"""
Architecture-aware Mach-O dependency graphs.

The regular :class:`macholib.MachOGraph.MachOGraph` collapses every fat slice
of a binary into a single node and a single, undifferentiated set of edges.
That hides information that matters when analysing a sample by architecture:

* which CPU type/subtype a dependency belongs to,
* whether the reference is a normal, weak, upward, re-export or prebound load,
* which raw load command produced the edge, and
* which references could not be resolved, and why.

This module builds one independent graph per architecture.  Recursive
dependencies are resolved by selecting a *compatible* slice of every candidate
file instead of silently using its first header.  Nothing in this module ever
loads or executes a dynamic library: files are only opened and parsed through
:class:`macholib.MachO.MachO`.
"""

import os
import sys

from macholib.MachO import MachO, _RELOCATABLE_NAMES
from macholib.mach_o import (
    CPU_TYPE_NAMES,
    LC_RPATH,
    get_cpu_subtype,
)
from macholib.ptypes import sizeof

__all__ = [
    "ArchKey",
    "DependencyEdge",
    "GraphNode",
    "MissingNode",
    "SearchPathResolver",
    "ArchDependencyGraph",
    "build_arch_graphs",
]

# Mask of the actual cpu_subtype value; the high nibble holds capability bits.
_SUBTYPE_MASK = 0x0FFFFFFF

# cpu_subtype value that means "any subtype of this cpu_type".
_SUBTYPE_ALL = 0


class ArchKey(object):
    """The identity of a fat slice: a CPU type/subtype pair."""

    __slots__ = ("cpu_type", "cpu_subtype")

    def __init__(self, cpu_type, cpu_subtype):
        self.cpu_type = int(cpu_type)
        self.cpu_subtype = int(cpu_subtype) & _SUBTYPE_MASK

    @classmethod
    def from_header(cls, header):
        return cls(header.header.cputype, header.header.cpusubtype)

    @property
    def type_name(self):
        return CPU_TYPE_NAMES.get(self.cpu_type, str(self.cpu_type))

    @property
    def subtype_name(self):
        return get_cpu_subtype(self.cpu_type, self.cpu_subtype)

    def label(self):
        return "%s/%s" % (self.type_name, self.subtype_name)

    def __eq__(self, other):
        return (
            isinstance(other, ArchKey)
            and self.cpu_type == other.cpu_type
            and self.cpu_subtype == other.cpu_subtype
        )

    def __hash__(self):
        return hash((self.cpu_type, self.cpu_subtype))

    def __repr__(self):
        return "ArchKey(cpu_type=0x%x, cpu_subtype=%d)" % (
            self.cpu_type,
            self.cpu_subtype,
        )


def arch_compatible(candidate, requested):
    """Return True when *candidate* can satisfy a *requested* architecture."""
    if candidate.cpu_type != requested.cpu_type:
        return False
    if candidate.cpu_subtype == requested.cpu_subtype:
        return True
    # An "ALL" subtype on either side is a wildcard within the same cpu_type.
    return (
        candidate.cpu_subtype == _SUBTYPE_ALL
        or requested.cpu_subtype == _SUBTYPE_ALL
    )


def _select_compatible_header(macho, arch):
    """
    Pick the best matching header of a parsed Mach-O for *arch*.

    An exact cpu_subtype match wins; otherwise an "ALL" wildcard slice is
    accepted.  Returns ``(header, index)`` or ``(None, None)``.  The first
    header is never returned merely because it is first.
    """
    wildcard = None
    for index, header in enumerate(macho.headers):
        candidate = ArchKey.from_header(header)
        if not arch_compatible(candidate, arch):
            continue
        if candidate.cpu_subtype == arch.cpu_subtype:
            return header, index
        if wildcard is None and candidate.cpu_subtype == _SUBTYPE_ALL:
            wildcard = (header, index)
    if wildcard is not None:
        return wildcard
    return None, None


def _lc_string(lc, cmd, data):
    """
    Extract the trailing ``lc_str`` of a dylib/rpath command.

    ``lc_str.name`` is an offset from the start of the load command; the fixed
    prefix is the load_command header plus the command body.  This mirrors
    :meth:`macholib.MachO.MachOHeader.walkRelocatables`.
    """
    offset = cmd.name - sizeof(lc.__class__) - sizeof(cmd.__class__)
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode(sys.getfilesystemencoding())


def _command_rpaths(header):
    rpaths = []
    for lc, cmd, data in header.commands:
        if lc.cmd == LC_RPATH:
            rpaths.append(_lc_string(lc, cmd, data))
    return rpaths


class DependencyEdge(object):
    """
    A single directed dependency between two nodes.

    Two references to the same library are kept as distinct edges whenever
    their semantics or their load-command provenance differ, so a weak load in
    one slice is never folded together with a normal load in another.
    """

    __slots__ = (
        "kind",
        "raw_command",
        "command_index",
        "install_name",
        "resolved_path",
        "target",
        "unresolved_reason",
    )

    def __init__(self, kind, raw_command, command_index, install_name):
        self.kind = kind
        self.raw_command = int(raw_command)
        self.command_index = command_index
        self.install_name = install_name
        self.resolved_path = None
        self.target = None
        self.unresolved_reason = None

    @property
    def resolved(self):
        return self.target is not None and isinstance(self.target, GraphNode)

    def __repr__(self):
        return (
            "DependencyEdge(kind=%r, install_name=%r, resolved=%r)"
            % (self.kind, self.install_name, self.resolved)
        )


class GraphNode(object):
    """A resolved Mach-O file viewed through a single architecture."""

    __slots__ = ("path", "arch", "slice_index", "edges", "rpaths", "filetype")

    def __init__(self, path, arch, slice_index, filetype, rpaths):
        self.path = path
        self.arch = arch
        self.slice_index = slice_index
        self.filetype = filetype
        self.rpaths = rpaths
        self.edges = []

    def __repr__(self):
        return "GraphNode(path=%r, arch=%r)" % (self.path, self.arch.label())


class MissingNode(object):
    """A dependency that could not be resolved to a compatible file."""

    __slots__ = ("install_name", "arch", "reason")

    def __init__(self, install_name, arch, reason):
        self.install_name = install_name
        self.arch = arch
        self.reason = reason

    @property
    def edges(self):
        return ()

    def __repr__(self):
        return "MissingNode(install_name=%r, reason=%r)" % (
            self.install_name,
            self.reason,
        )


class SearchPathResolver(object):
    """
    Resolve dylib install names to file paths without invoking dyld.

    Only files under the configured search roots (and the directories of the
    loader itself) are considered.  ``@executable_path``, ``@loader_path`` and
    ``@rpath`` are expanded purely as string operations; nothing is loaded or
    executed.
    """

    def __init__(self, search_paths=None, executable_path=None):
        self.search_paths = list(search_paths or [])
        self.executable_path = executable_path

    def _expand(self, install_name, loader_dir, rpaths):
        if install_name.startswith("@executable_path/"):
            base = self.executable_path or loader_dir
            rest = install_name[len("@executable_path/") :]
            return [os.path.normpath(os.path.join(base, rest))]
        if install_name.startswith("@loader_path/"):
            rest = install_name[len("@loader_path/") :]
            return [os.path.normpath(os.path.join(loader_dir, rest))]
        if install_name.startswith("@rpath/"):
            rest = install_name[len("@rpath/") :]
            roots = rpaths or self.search_paths
            return [os.path.normpath(os.path.join(root, rest)) for root in roots]
        if os.path.isabs(install_name):
            return [install_name]
        # A bare install name is looked up through every search root.
        return [
            os.path.normpath(os.path.join(root, install_name))
            for root in self.search_paths
        ]

    def resolve(self, install_name, loader_dir=None, rpaths=None):
        loader_dir = loader_dir or os.getcwd()
        for candidate in self._expand(install_name, loader_dir, rpaths):
            if os.path.isfile(candidate):
                return os.path.realpath(candidate)
        return None


class ArchDependencyGraph(object):
    """
    The dependency graph of one root Mach-O, separated per architecture.
    """

    def __init__(self, root_path, resolver=None):
        self.root_path = os.path.realpath(root_path)
        self.resolver = resolver or SearchPathResolver()
        # Keyed by (realpath, ArchKey) so the same file/slice is one node.
        self._node_cache = {}
        self.roots = {}
        self.unresolved = []
        self.cycles = []

    def build(self):
        root_macho = MachO(self.root_path)
        for index, header in enumerate(root_macho.headers):
            arch = ArchKey.from_header(header)
            node = self._node_for_header(
                self.root_path, arch, header, index, on_stack=set()
            )
            self.roots[arch] = node
        return self

    def architectures(self):
        return list(self.roots.keys())

    def _node_for_header(self, path, arch, header, slice_index, on_stack):
        key = (path, arch)
        existing = self._node_cache.get(key)
        if existing is not None:
            return existing

        rpaths = _command_rpaths(header)
        node = GraphNode(path, arch, slice_index, header.filetype, rpaths)
        self._node_cache[key] = node
        self._scan(node, header, on_stack | {key})
        return node

    def _scan(self, node, header, on_stack):
        loader_dir = os.path.dirname(node.path)
        for index, (lc, cmd, data) in enumerate(header.commands):
            kind = _RELOCATABLE_NAMES.get(lc.cmd)
            if kind is None:
                continue
            install_name = _lc_string(lc, cmd, data)
            edge = DependencyEdge(kind, lc.cmd, index, install_name)
            node.edges.append(edge)
            self._resolve_edge(node, edge, on_stack)

    def _resolve_edge(self, node, edge, on_stack):
        path = self.resolver.resolve(
            edge.install_name,
            loader_dir=os.path.dirname(node.path),
            rpaths=node.rpaths,
        )
        if path is None:
            missing = MissingNode(
                edge.install_name, node.arch, "no candidate file on search path"
            )
            edge.target = missing
            edge.unresolved_reason = missing.reason
            self.unresolved.append((node.arch, node.path, edge))
            return

        edge.resolved_path = path
        try:
            candidate = MachO(path)
        except (ValueError, OSError) as exc:
            missing = MissingNode(edge.install_name, node.arch, str(exc))
            edge.target = missing
            edge.unresolved_reason = missing.reason
            self.unresolved.append((node.arch, node.path, edge))
            return

        matched_header, matched_index = _select_compatible_header(candidate, node.arch)
        if matched_header is None:
            reason = "no compatible slice for %s" % (node.arch.label(),)
            missing = MissingNode(edge.install_name, node.arch, reason)
            edge.target = missing
            edge.unresolved_reason = reason
            self.unresolved.append((node.arch, node.path, edge))
            return

        key = (path, node.arch)
        if key in on_stack:
            # Back edge: the target already exists (or is being built) and this
            # closes a cycle. Record it without recursing again.
            target = self._node_cache.get(key)
            if target is None:
                target = GraphNode(
                    path,
                    node.arch,
                    matched_index,
                    matched_header.filetype,
                    _command_rpaths(matched_header),
                )
                self._node_cache[key] = target
            edge.target = target
            self.cycles.append((node.arch, node.path, path))
            return

        edge.target = self._node_for_header(
            path, node.arch, matched_header, matched_index, on_stack
        )

    def report(self):
        lines = []
        for arch, root in self.roots.items():
            lines.append("architecture %s" % arch.label())
            lines.append("  root: %s" % root.path)
            lines.append("  nodes:")
            for node in self._nodes_for(arch):
                lines.append(
                    "    - %s (slice %d, %s)"
                    % (node.path, node.slice_index, node.filetype)
                )
            lines.append("  edges:")
            for node in self._nodes_for(arch):
                for edge in node.edges:
                    target = edge.resolved_path or edge.install_name
                    lines.append(
                        "    %s --%s--> %s" % (node.path, edge.kind, target)
                    )
            unresolved = [item for item in self.unresolved if item[0] == arch]
            if unresolved:
                lines.append("  unresolved edges:")
                for _arch, source, edge in unresolved:
                    lines.append(
                        "    %s --%s--> %s (%s)"
                        % (
                            source,
                            edge.kind,
                            edge.install_name,
                            edge.unresolved_reason,
                        )
                    )
            else:
                lines.append("  unresolved edges: none")
            arch_cycles = [item for item in self.cycles if item[0] == arch]
            if arch_cycles:
                lines.append("  cycles:")
                for _arch, source, target in arch_cycles:
                    lines.append("    %s -> %s" % (source, target))
            else:
                lines.append("  cycles: none")
        return "\n".join(lines)

    def _nodes_for(self, arch):
        nodes = {}
        for (path, node_arch), node in self._node_cache.items():
            if node_arch == arch and isinstance(node, GraphNode):
                nodes[path] = node
        return list(nodes.values())


def build_arch_graphs(root_path, search_paths=None, executable_path=None):
    """Convenience wrapper returning a fully built :class:`ArchDependencyGraph`."""
    resolver = SearchPathResolver(
        search_paths=search_paths, executable_path=executable_path
    )
    return ArchDependencyGraph(root_path, resolver=resolver).build()
