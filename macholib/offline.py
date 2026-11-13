"""
Offline dyld-style dependency resolution.

This module resolves Mach-O install names (``@rpath``, ``@loader_path`` and
``@executable_path`` references) without consulting the analysis host:

* The caller supplies a :class:`LaunchContext` describing the *sample's*
  launch environment (main executable path and ``DYLD_*`` variables).
  The process environment (``os.environ``) of the analysis host is never
  used as a substitute.
* The caller supplies a file-existence probe, so candidates are checked
  against the sample's filesystem (a disk image, a fixture set, ...) and
  not against the host filesystem.

Every candidate path is reported together with the rule that produced it,
whether it depends on the deployment location of the bundle, and whether
it matched.  Run-path context is kept per load chain: the same install
name referenced by two different loaders is resolved (and cached)
separately, because dyld searches the run-path stack of the referencing
chain.
"""

import os

from macholib.framework import framework_info
from macholib.MachO import MachO

__all__ = [
    "Candidate",
    "Dependency",
    "LaunchContext",
    "OfflineResolver",
    "Resolution",
    "RPathEntry",
    "ScannedImage",
]

# Default fallback paths as per man dyld(1).  ``{home}`` is substituted
# with the sample's home directory from the launch context, never with
# the analysis host's home.
_DEFAULT_FRAMEWORK_FALLBACK = [
    "{home}/Library/Frameworks",
    "/Library/Frameworks",
    "/Network/Library/Frameworks",
    "/System/Library/Frameworks",
]

_DEFAULT_LIBRARY_FALLBACK = [
    "{home}/lib",
    "/usr/local/lib",
    "/lib",
    "/usr/lib",
]

_EXECUTABLE_TOKEN = "@executable_path/"
_LOADER_TOKEN = "@loader_path/"
_RPATH_TOKEN = "@rpath/"


class LaunchContext(object):
    """
    The launch environment of the *sample* under analysis.

    ``executable_path``
        Path of the main executable in the sample's filesystem.  Its
        directory is what ``@executable_path`` expands to.  May be None,
        in which case ``@executable_path`` cannot be expanded and the
        resolution report says so.

    ``env``
        Mapping with the sample's ``DYLD_*`` variables (for example
        ``DYLD_LIBRARY_PATH``).  Defaults to an empty environment; the
        host's ``os.environ`` is deliberately never consulted.

    ``home``
        The sample user's home directory, used for the default dyld
        fallback paths (``~/lib``, ``~/Library/Frameworks``).
    """

    def __init__(self, executable_path=None, env=None, home="/"):
        self.executable_path = executable_path
        self.env = dict(env) if env else {}
        self.home = home

    @property
    def executable_dir(self):
        if self.executable_path is None:
            return None
        return os.path.dirname(self.executable_path)

    def env_list(self, var):
        value = self.env.get(var)
        if not value:
            return []
        return [entry for entry in value.split(":") if entry]

    def __repr__(self):
        return "<LaunchContext executable_path=%r env=%r>" % (
            self.executable_path,
            self.env,
        )


class RPathEntry(object):
    """
    A single LC_RPATH entry after token expansion.

    ``declarer`` is the Mach-O file that contains the LC_RPATH command,
    ``raw`` the literal entry and ``expanded`` the result of substituting
    ``@executable_path``/``@loader_path``.  ``deployment_relative`` is
    true when the raw entry depends on where the bundle is deployed.
    """

    __slots__ = ("declarer", "raw", "expanded", "deployment_relative")

    def __init__(self, declarer, raw, expanded, deployment_relative):
        self.declarer = declarer
        self.raw = raw
        self.expanded = expanded
        self.deployment_relative = deployment_relative

    def __repr__(self):
        return "<RPathEntry %r (declared by %r)>" % (self.expanded, self.declarer)


class Candidate(object):
    """
    One concrete path tried while resolving an install name.

    ``rule`` describes which dyld rule produced the path (for example
    ``DYLD_LIBRARY_PATH[0]`` or ``run-path[1] declared by /a/Plug``).
    ``deployment_relative`` marks paths whose value changes with the
    deployment location of the bundle.  ``exists`` records the verdict
    of the caller-supplied probe (or of the shared-cache probe).
    """

    __slots__ = ("path", "rule", "deployment_relative", "exists", "via_shared_cache")

    def __init__(self, path, rule, deployment_relative):
        self.path = path
        self.rule = rule
        self.deployment_relative = deployment_relative
        self.exists = False
        self.via_shared_cache = False

    def __repr__(self):
        return "<Candidate %r via %s>" % (self.path, self.rule)


class Resolution(object):
    """
    The outcome of resolving one install name in one loader context.

    ``status`` is ``"resolved"`` or ``"missing"``.  ``resolved`` is the
    adopted path (or None) and ``rule`` the rule that produced it.
    ``notes`` lists rules that were applicable but could not produce a
    candidate (for example ``@executable_path`` without a known main
    executable), so the report explains the actual rules used.
    """

    def __init__(self, requested, loader_path):
        self.requested = requested
        self.loader_path = loader_path
        self.candidates = []
        self.notes = []
        self.status = "missing"
        self.resolved = None
        self.rule = None

    @property
    def deployment_relative(self):
        if not self.candidates:
            return False
        for candidate in self.candidates:
            if candidate.exists:
                return candidate.deployment_relative
        return False

    def __repr__(self):
        return "<Resolution %r -> %r (%s)>" % (self.requested, self.resolved, self.status)


class Dependency(object):
    """One referenced install name plus its resolution and child node."""

    def __init__(self, name, resolution, child=None, note=None):
        self.name = name
        self.resolution = resolution
        self.child = child
        self.note = note


class ScannedImage(object):
    """A parsed Mach-O file in the offline dependency graph."""

    def __init__(self, path):
        self.path = path
        self.rpath_entries = []
        self.dependencies = []
        self.parse_error = None

    def __repr__(self):
        return "<ScannedImage %r>" % (self.path,)


def _norm(path):
    return os.path.normpath(path)


class OfflineResolver(object):
    """
    Resolve Mach-O install names offline, dyld-style.

    ``file_probe`` is a callable ``path -> bool`` deciding whether a
    candidate path exists in the *sample's* filesystem.  It is required:
    offline resolution must never fall back to the host filesystem.

    ``shared_cache_probe`` is an optional callable ``path -> bool`` for
    paths contained in the sample's dyld shared cache.

    ``macho_factory`` builds :class:`macholib.MachO.MachO`-compatible
    objects from a path; override it to parse files from a disk image
    or another non-host store.
    """

    def __init__(
        self,
        launch_context=None,
        file_probe=None,
        shared_cache_probe=None,
        macho_factory=None,
    ):
        if file_probe is None:
            raise TypeError(
                "offline resolution requires an explicit file_probe; "
                "the host filesystem is never consulted implicitly"
            )
        self.launch_context = (
            launch_context if launch_context is not None else LaunchContext()
        )
        self.file_probe = file_probe
        self.shared_cache_probe = shared_cache_probe
        self.macho_factory = macho_factory if macho_factory is not None else MachO
        self._resolution_cache = {}
        self._scan_cache = {}
        self.cycles = []

    # -- candidate generation -------------------------------------------

    def _env_override_candidates(self, name):
        framework = framework_info(name)
        if framework is not None:
            for idx, path in enumerate(
                self.launch_context.env_list("DYLD_FRAMEWORK_PATH")
            ):
                yield (
                    _norm(os.path.join(path, framework["name"])),
                    "DYLD_FRAMEWORK_PATH[%d]" % (idx,),
                    False,
                )
        for idx, path in enumerate(self.launch_context.env_list("DYLD_LIBRARY_PATH")):
            yield (
                _norm(os.path.join(path, os.path.basename(name))),
                "DYLD_LIBRARY_PATH[%d]" % (idx,),
                False,
            )

    def _token_candidates(self, name, loader_path, run_path_context, notes):
        if name.startswith(_EXECUTABLE_TOKEN):
            rest = name[len(_EXECUTABLE_TOKEN) :]  # noqa: E203
            executable_dir = self.launch_context.executable_dir
            if executable_dir is None:
                notes.append(
                    "@executable_path expansion skipped: "
                    "no executable_path in launch context"
                )
            else:
                yield (
                    _norm(os.path.join(executable_dir, rest)),
                    "@executable_path expansion",
                    True,
                )

        elif name.startswith(_LOADER_TOKEN):
            rest = name[len(_LOADER_TOKEN) :]  # noqa: E203
            if loader_path is None:
                notes.append(
                    "@loader_path expansion skipped: no loader known for %r" % (name,)
                )
            else:
                yield (
                    _norm(os.path.join(loader_path, rest)),
                    "@loader_path expansion (loader dir %s)" % (loader_path,),
                    True,
                )

        elif name.startswith(_RPATH_TOKEN):
            rest = name[len(_RPATH_TOKEN) :]  # noqa: E203
            if not run_path_context:
                notes.append(
                    "@rpath expansion skipped: load chain has no LC_RPATH entries"
                )
            for idx, entry in enumerate(run_path_context):
                yield (
                    _norm(os.path.join(entry.expanded, rest)),
                    "run-path[%d] %r declared by %s"
                    % (idx, entry.raw, entry.declarer),
                    entry.deployment_relative,
                )

    def _fallback_candidates(self, name):
        framework = framework_info(name)
        leaf = os.path.basename(name)
        home = self.launch_context.home

        if framework is not None:
            fallback_framework = self.launch_context.env_list(
                "DYLD_FALLBACK_FRAMEWORK_PATH"
            )
            if fallback_framework:
                for idx, path in enumerate(fallback_framework):
                    yield (
                        _norm(os.path.join(path, framework["name"])),
                        "DYLD_FALLBACK_FRAMEWORK_PATH[%d]" % (idx,),
                        False,
                    )
            else:
                for path in _DEFAULT_FRAMEWORK_FALLBACK:
                    yield (
                        _norm(os.path.join(path.replace("{home}", home),
                                        framework["name"])),
                        "default framework fallback %s" % (path,),
                        False,
                    )

        fallback_library = self.launch_context.env_list("DYLD_FALLBACK_LIBRARY_PATH")
        if fallback_library:
            for idx, path in enumerate(fallback_library):
                yield (
                    _norm(os.path.join(path, leaf)),
                    "DYLD_FALLBACK_LIBRARY_PATH[%d]" % (idx,),
                    False,
                )
        else:
            for path in _DEFAULT_LIBRARY_FALLBACK:
                yield (
                    _norm(os.path.join(path.replace("{home}", home), leaf)),
                    "default library fallback %s" % (path,),
                    False,
                )

    def _iter_candidates(self, name, loader_path, run_path_context, notes):
        has_token = name.startswith(
            (_EXECUTABLE_TOKEN, _LOADER_TOKEN, _RPATH_TOKEN)
        )

        # 1. environment overrides apply to the leaf name, before any
        #    token expansion (dyld semantics).
        for candidate in self._env_override_candidates(name):
            yield candidate

        # 2. token expansion / literal name.
        if has_token:
            for candidate in self._token_candidates(
                name, loader_path, run_path_context, notes
            ):
                yield candidate
        else:
            yield (_norm(name), "literal install name", False)

        # 3. fallback paths (env override or dyld defaults).
        for candidate in self._fallback_candidates(name):
            yield candidate

    # -- resolution ------------------------------------------------------

    def resolve(self, name, loader_path=None, run_path_context=()):
        """
        Resolve *name* as referenced by the image at ``loader_path``
        (a directory) with the given run-path context (a sequence of
        :class:`RPathEntry`, nearest loader first).

        Results are cached per (name, loader, run-path context), so the
        same install name referenced by different loaders never reuses
        another loader's result.
        """
        context_key = tuple((entry.declarer, entry.raw) for entry in run_path_context)
        cache_key = (name, loader_path, context_key)
        cached = self._resolution_cache.get(cache_key)
        if cached is not None:
            return cached

        resolution = Resolution(name, loader_path)
        suffix = self.launch_context.env.get("DYLD_IMAGE_SUFFIX") or None

        for path, rule, deployment_relative in self._iter_candidates(
            name, loader_path, run_path_context, resolution.notes
        ):
            variants = [path]
            if suffix is not None:
                if path.endswith(".dylib"):
                    variants.insert(
                        0, path[: -len(".dylib")] + suffix + ".dylib"
                    )
                else:
                    variants.insert(0, path + suffix)
            for variant_idx, variant in enumerate(variants):
                variant_rule = rule
                if suffix is not None and variant_idx == 0:
                    variant_rule = rule + " (DYLD_IMAGE_SUFFIX variant)"
                candidate = Candidate(variant, variant_rule, deployment_relative)
                if self.shared_cache_probe is not None and self.shared_cache_probe(
                    variant
                ):
                    candidate.exists = True
                    candidate.via_shared_cache = True
                elif self.file_probe(variant):
                    candidate.exists = True
                resolution.candidates.append(candidate)
                if candidate.exists:
                    resolution.status = "resolved"
                    resolution.resolved = variant
                    resolution.rule = variant_rule
                    break
            if resolution.status == "resolved":
                break

        if resolution.status != "resolved":
            resolution.notes.append(
                "no candidate existed according to the file probe; "
                "dyld would abort with 'image not found'"
            )

        self._resolution_cache[cache_key] = resolution
        return resolution

    # -- run-path context -------------------------------------------------

    def expand_rpath_entry(self, raw, declarer):
        """
        Expand one LC_RPATH entry declared by *declarer* into an
        :class:`RPathEntry`.  Returns None (after recording nothing) when
        the entry cannot be expanded; callers report the note.
        """
        deployment_relative = False
        expanded = raw
        if expanded.startswith(_EXECUTABLE_TOKEN):
            executable_dir = self.launch_context.executable_dir
            if executable_dir is None:
                return None
            expanded = os.path.join(
                executable_dir, expanded[len(_EXECUTABLE_TOKEN) :]  # noqa: E203
            )
            deployment_relative = True
        elif expanded.startswith(_LOADER_TOKEN):
            expanded = os.path.join(
                os.path.dirname(declarer),
                expanded[len(_LOADER_TOKEN) :],  # noqa: E203
            )
            deployment_relative = True
        return RPathEntry(declarer, raw, _norm(expanded), deployment_relative)

    # -- dependency graph scan -------------------------------------------

    def scan(self, root_path):
        """
        Parse *root_path* and its dependency chain, resolving every
        referenced install name in its own run-path context.  Returns the
        root :class:`ScannedImage`.
        """
        self.cycles = []
        return self._scan_file(root_path, run_path_context=(), chain=())

    def _scan_file(self, path, run_path_context, chain):
        context_key = tuple(
            (entry.declarer, entry.raw) for entry in run_path_context
        )
        scan_key = (path, context_key)
        node = self._scan_cache.get(scan_key)
        if node is not None:
            return node

        node = ScannedImage(path)
        self._scan_cache[scan_key] = node

        try:
            macho = self.macho_factory(path)
        except Exception as exc:
            node.parse_error = "%s: %s" % (type(exc).__name__, exc)
            return node

        own_entries = []
        raws = []
        deps = []
        for header in macho.headers:
            for _idx, raw in header.walkRpaths():
                if raw not in raws:
                    raws.append(raw)
            for _idx, _cmd_name, filename in header.walkRelocatables():
                deps.append(filename)

        for raw in raws:
            entry = self.expand_rpath_entry(raw, path)
            if entry is None:
                entry = RPathEntry(path, raw, None, True)
            own_entries.append(entry)
        node.rpath_entries = own_entries

        expandable = [entry for entry in own_entries if entry.expanded is not None]
        child_context = tuple(expandable) + tuple(run_path_context)

        chain = chain + (path,)
        for name in deps:
            resolution = self.resolve(
                name,
                loader_path=os.path.dirname(path),
                run_path_context=child_context,
            )
            dependency = Dependency(name, resolution)
            if resolution.status == "resolved":
                resolved = resolution.resolved
                if resolved in chain:
                    dependency.note = (
                        "circular reference: %s is already being loaded; "
                        "dyld reuses the in-flight image" % (resolved,)
                    )
                    self.cycles.append((path, name, resolved))
                else:
                    dependency.child = self._scan_file(
                        resolved, child_context, chain
                    )
            node.dependencies.append(dependency)
        return node

    # -- reporting ---------------------------------------------------------

    def explain_resolution(self, resolution):
        """Human-readable search order for one resolution."""
        lines = ["resolve %r" % (resolution.requested,)]
        if resolution.loader_path is not None:
            lines.append("  loader dir: %s" % (resolution.loader_path,))
        for note in resolution.notes:
            lines.append("  note: %s" % (note,))
        for candidate in resolution.candidates:
            mark = "HIT " if candidate.exists else "miss"
            tags = []
            if candidate.deployment_relative:
                tags.append("deployment-relative")
            if candidate.via_shared_cache:
                tags.append("dyld shared cache")
            tag = " [%s]" % (", ".join(tags),) if tags else ""
            lines.append(
                "  %s %s%s" % (mark, candidate.path, tag)
            )
            lines.append("       rule: %s" % (candidate.rule,))
        if resolution.status == "resolved":
            lines.append(
                "  => %s via %s" % (resolution.resolved, resolution.rule)
            )
        else:
            lines.append("  => MISSING (image not found)")
        return lines

    def explain_scan(self, node=None):
        """Human-readable report for a scanned dependency graph."""
        lines = []
        seen = set()

        def walk(image, indent):
            prefix = "  " * indent
            lines.append("%s%s" % (prefix, image.path))
            if image.parse_error is not None:
                lines.append("%s  parse error: %s" % (prefix, image.parse_error))
                return
            for entry in image.rpath_entries:
                if entry.expanded is None:
                    lines.append(
                        "%s  LC_RPATH %r (not expandable in this launch context)"
                        % (prefix, entry.raw)
                    )
                else:
                    tag = " [deployment-relative]" if entry.deployment_relative else ""
                    lines.append(
                        "%s  LC_RPATH %r -> %s%s"
                        % (prefix, entry.raw, entry.expanded, tag)
                    )
            key = id(image)
            if key in seen:
                lines.append("%s  (already shown)" % (prefix,))
                return
            seen.add(key)
            for dependency in image.dependencies:
                resolution = dependency.resolution
                if resolution.status == "resolved":
                    tag = (
                        " [deployment-relative]"
                        if resolution.deployment_relative
                        else ""
                    )
                    lines.append(
                        "%s  %s -> %s%s"
                        % (prefix, dependency.name, resolution.resolved, tag)
                    )
                    lines.append("%s    rule: %s" % (prefix, resolution.rule))
                else:
                    lines.append(
                        "%s  %s -> MISSING (image not found)"
                        % (prefix, dependency.name)
                    )
                if dependency.note is not None:
                    lines.append("%s    note: %s" % (prefix, dependency.note))
                if dependency.child is not None:
                    walk(dependency.child, indent + 2)

        if node is None:
            raise TypeError("explain_scan() requires a scanned root node")
        walk(node, 0)
        return lines
