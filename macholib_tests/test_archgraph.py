"""
Tests for architecture-aware dependency graph construction.

The Mach-O binaries used here are synthesized in-process from raw structs.
No system dynamic library is ever opened, loaded or executed; the code under
test only parses bytes through :class:`macholib.MachO.MachO`.
"""

import os
import shutil
import struct
import tempfile
import unittest

from macholib import mach_o
from macholib.MachO import MachO
from macholib.archgraph import (
    ArchDependencyGraph,
    ArchKey,
    _select_compatible_header,
    build_arch_graphs,
)

ARM64 = mach_o._CPU_ARCH_ABI64 | 12  # 0x0100000C
X86_64 = mach_o._CPU_ARCH_ABI64 | 7  # 0x01000007
SUB_ALL = 0

# Dylib load-command kinds exercised by the fixture.
KIND_LOAD = "load_dylib"
KIND_WEAK = "load_weak_dylib"
KIND_REEXPORT = "reexport_dylib"
KIND_UPWARD = "load_upward_dylib"

_KIND_TO_LC = {
    KIND_LOAD: mach_o.LC_LOAD_DYLIB,
    KIND_WEAK: mach_o.LC_LOAD_WEAK_DYLIB,
    KIND_REEXPORT: mach_o.LC_REEXPORT_DYLIB,
    KIND_UPWARD: mach_o.LC_LOAD_UPWARD_DYLIB,
}


def dylib_command(lc_cmd, name):
    """Build one dylib load command (load_command + dylib + c-string)."""
    payload = name.encode("utf-8") + b"\x00"
    # lc_str offset = sizeof(load_command) + sizeof(dylib) == 8 + 16 == 24.
    cmdsize = 8 + 16 + len(payload)
    return struct.pack(
        "<IIIIII",
        lc_cmd,
        cmdsize,
        24,  # name offset from start of command
        0,  # timestamp
        0x10000,  # current version 1.0
        0x10000,  # compatibility version 1.0
    ) + payload


def make_slice(cpu_type, cpu_subtype, commands, filetype=mach_o.MH_DYLIB):
    """Build a single little-endian 64-bit Mach-O slice."""
    body = b"".join(commands)
    header = struct.pack(
        "<IIIIIIII",
        mach_o.MH_MAGIC_64,
        cpu_type,
        cpu_subtype,
        filetype,
        len(commands),
        len(body),
        0,
        0,
    )
    return header + body


def make_fat(slices, alignment=12):
    """
    Wrap little-endian slices in a big-endian fat (FAT_MAGIC) container.

    Each slice is placed at its own 2**alignment-aligned offset.
    """
    base = 2 ** alignment
    entries = []
    blobs = []
    offset = base
    for cpu_type, cpu_subtype, blob in slices:
        entries.append(
            struct.pack(
                ">IIIII",
                cpu_type,
                cpu_subtype,
                offset,
                len(blob),
                alignment,
            )
        )
        blobs.append(blob)
        offset += len(blob)
        # Keep every subsequent slice aligned as well.
        offset = (offset + base - 1) & ~(base - 1)

    fat_header = struct.pack(
        ">II", mach_o.FAT_MAGIC, len(slices)
    )
    out = bytearray(fat_header + b"".join(entries))
    if len(out) > base:
        raise AssertionError("fat header overlaps first slice")
    out.extend(b"\x00" * (base - len(out)))
    cursor = base
    for blob in blobs:
        if cursor != len(out):
            out.extend(b"\x00" * (cursor - len(out)))
        out.extend(blob)
        cursor += len(blob)
        cursor = (cursor + base - 1) & ~(base - 1)
    return bytes(out)


def fat_dylib(path, deps_by_arch, install_id=None):
    """
    Write a fat dylib with one arm64 and one x86_64 slice.

    *deps_by_arch* maps an architecture to a list of ``(kind, install_name)``.
    """
    slices = []
    for arch in (ARM64, X86_64):
        commands = []
        if install_id is not None:
            commands.append(dylib_command(mach_o.LC_ID_DYLIB, install_id))
        for kind, install_name in deps_by_arch.get(arch, []):
            commands.append(dylib_command(_KIND_TO_LC[kind], install_name))
        slices.append((arch, SUB_ALL, make_slice(arch, SUB_ALL, commands)))
    with open(path, "wb") as fp:
        fp.write(make_fat(slices))


class CyclicFixture(object):
    """
    Build the dual-architecture cyclic dependency graph used by the tests.

    Layout (same dylib name on both arches unless noted)::

        libA --reexport--> libB --load--> libA            (cycle)
        libA --weak(arm64)/load(x86_64)--> libC
        libB --upward--> libD
        libC --load--> libE   (arm64 thin only)
        libD --load--> libG   (libG is never created)
        libC --load--> libF
    """

    def __init__(self, root):
        self.root = root
        self.paths = {}

    def p(self, name):
        return os.path.realpath(os.path.join(self.root, name))

    def build(self):
        liba = "libA.dylib"
        libb = "libB.dylib"
        libc = "libC.dylib"
        libd = "libD.dylib"
        libe = "libE.dylib"
        libf = "libF.dylib"
        libg = "libG.dylib"

        fat_dylib(
            self.p(liba),
            {
                ARM64: [
                    (KIND_REEXPORT, libb),
                    (KIND_WEAK, libc),
                ],
                X86_64: [
                    (KIND_REEXPORT, libb),
                    (KIND_LOAD, libc),
                ],
            },
            install_id=liba,
        )
        fat_dylib(
            self.p(libb),
            {
                ARM64: [(KIND_LOAD, liba), (KIND_UPWARD, libd)],
                X86_64: [(KIND_LOAD, liba), (KIND_UPWARD, libd)],
            },
            install_id=libb,
        )
        fat_dylib(
            self.p(libc),
            {
                ARM64: [(KIND_LOAD, libe), (KIND_LOAD, libf)],
                X86_64: [(KIND_LOAD, libe), (KIND_LOAD, libf)],
            },
            install_id=libc,
        )
        fat_dylib(
            self.p(libd),
            {
                ARM64: [(KIND_LOAD, libg)],
                X86_64: [(KIND_LOAD, libg)],
            },
            install_id=libd,
        )
        # libE exists only as a thin arm64 slice: no x86_64-compatible header.
        with open(self.p(libe), "wb") as fp:
            fp.write(make_slice(ARM64, SUB_ALL, []))
        fat_dylib(
            self.p(libf),
            {ARM64: [], X86_64: []},
            install_id=libf,
        )
        # libG is deliberately not created.

        for name in (liba, libb, libc, libd, libe, libf, libg):
            self.paths[name] = self.p(name)
        return self


class ArchGraphTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.fixture = CyclicFixture(self.tmp).build()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def graph(self, name="libA.dylib"):
        return build_arch_graphs(
            self.fixture.p(name), search_paths=[self.tmp]
        )

    def edge_map(self, node):
        return {edge.install_name: edge for edge in node.edges}

    def test_builds_independent_graph_per_architecture(self):
        graph = self.graph()
        arm = ArchKey(ARM64, SUB_ALL)
        x86 = ArchKey(X86_64, SUB_ALL)
        self.assertEqual(
            sorted(arch.label() for arch in graph.architectures()),
            sorted([arm.label(), x86.label()]),
        )
        self.assertEqual(len(graph.roots), 2)
        arm_root = graph.roots[arm]
        x86_root = graph.roots[x86]
        self.assertIsNot(arm_root, x86_root)

    def test_cpu_type_subtype_and_slice_provenance_preserved(self):
        graph = self.graph()
        for arch, node in graph.roots.items():
            self.assertEqual(node.arch, arch)
            self.assertEqual(node.arch.cpu_type, arch.cpu_type)
        arm_node = graph.roots[ArchKey(ARM64, SUB_ALL)]
        self.assertEqual(arm_node.slice_index, 0)
        x86_node = graph.roots[ArchKey(X86_64, SUB_ALL)]
        self.assertEqual(x86_node.slice_index, 1)

    def test_same_library_weak_vs_normal_kept_distinct(self):
        graph = self.graph()
        arm_edges = self.edge_map(graph.roots[ArchKey(ARM64, SUB_ALL)])
        x86_edges = self.edge_map(graph.roots[ArchKey(X86_64, SUB_ALL)])
        self.assertEqual(arm_edges["libC.dylib"].kind, KIND_WEAK)
        self.assertEqual(
            arm_edges["libC.dylib"].raw_command, mach_o.LC_LOAD_WEAK_DYLIB
        )
        self.assertEqual(x86_edges["libC.dylib"].kind, KIND_LOAD)
        self.assertEqual(
            x86_edges["libC.dylib"].raw_command, mach_o.LC_LOAD_DYLIB
        )
        # The two references live on separate nodes/edges, never folded.
        self.assertIsNot(
            arm_edges["libC.dylib"], x86_edges["libC.dylib"]
        )

    def test_reexport_upward_and_command_index_preserved(self):
        graph = self.graph()
        arm_root = graph.roots[ArchKey(ARM64, SUB_ALL)]
        edges = self.edge_map(arm_root)
        reexport = edges["libB.dylib"]
        self.assertEqual(reexport.kind, KIND_REEXPORT)
        self.assertEqual(reexport.raw_command, mach_o.LC_REEXPORT_DYLIB)
        # LC_ID_DYLIB is index 0, reexport is the first relocatable command.
        self.assertEqual(reexport.command_index, 1)

        node_b = reexport.target
        upward = self.edge_map(node_b)["libD.dylib"]
        self.assertEqual(upward.kind, KIND_UPWARD)
        self.assertEqual(upward.raw_command, mach_o.LC_LOAD_UPWARD_DYLIB)

    def test_recursive_dependency_uses_compatible_slice(self):
        graph = self.graph()
        arm_root = graph.roots[ArchKey(ARM64, SUB_ALL)]
        libc = self.edge_map(arm_root)["libC.dylib"].target
        libe_arm = self.edge_map(libc)["libE.dylib"].target
        # arm64 can resolve the arm64-only thin file, using its single slice.
        self.assertTrue(
            os.path.samefile(libe_arm.path, self.fixture.paths["libE.dylib"])
        )
        self.assertEqual(libe_arm.arch, ArchKey(ARM64, SUB_ALL))
        self.assertEqual(libe_arm.slice_index, 0)

    def test_incompatible_architecture_is_unresolved_not_first_header(self):
        graph = self.graph()
        x86_root = graph.roots[ArchKey(X86_64, SUB_ALL)]
        libc = self.edge_map(x86_root)["libC.dylib"].target
        edge_to_e = self.edge_map(libc)["libE.dylib"]
        # The file exists but has no x86_64 slice: must not fall back to its
        # (first and only) arm64 header.
        self.assertFalse(edge_to_e.resolved)
        self.assertIn("no compatible slice", edge_to_e.unresolved_reason)

        reasons = [
            (edge.install_name, edge.unresolved_reason)
            for _arch, _src, edge in graph.unresolved
            if _arch == ArchKey(X86_64, SUB_ALL)
        ]
        self.assertIn(
            ("libE.dylib", edge_to_e.unresolved_reason), reasons
        )

    def test_selects_compatible_slice_even_when_not_first(self):
        # Build a fat dependency whose first slice is x86_64 and whose second
        # is arm64. An arm64 consumer must pick slice 1, never default to the
        # first header.
        reversed_path = os.path.join(self.tmp, "libReversed.dylib")
        slices = [
            (X86_64, SUB_ALL, make_slice(X86_64, SUB_ALL, [])),
            (ARM64, SUB_ALL, make_slice(ARM64, SUB_ALL, [])),
        ]
        with open(reversed_path, "wb") as fp:
            fp.write(make_fat(slices))

        graph = self.graph()
        arm_root = graph.roots[ArchKey(ARM64, SUB_ALL)]
        libc = self.edge_map(arm_root)["libC.dylib"].target
        # Resolve the reversed file directly via the slice-selection helper.
        header, index = _select_compatible_header(
            MachO(reversed_path), ArchKey(ARM64, SUB_ALL)
        )
        self.assertIsNotNone(header)
        self.assertEqual(index, 1)
        self.assertEqual(
            ArchKey.from_header(header), ArchKey(ARM64, SUB_ALL)
        )
        # And the reverse: an x86_64 request selects the leading slice.
        header_x86, index_x86 = _select_compatible_header(
            MachO(reversed_path), ArchKey(X86_64, SUB_ALL)
        )
        self.assertEqual(index_x86, 0)
        self.assertIsNotNone(libc)

    def test_missing_dependency_is_unresolved(self):
        graph = self.graph()
        unresolved_names = {
            edge.install_name
            for arch, _src, edge in graph.unresolved
            if arch == ArchKey(ARM64, SUB_ALL)
        }
        self.assertIn("libG.dylib", unresolved_names)
        # Every unresolved edge retains its originating semantics.
        libb = self.edge_map(graph.roots[ArchKey(ARM64, SUB_ALL)])[
            "libB.dylib"
        ].target
        libd = self.edge_map(libb)["libD.dylib"].target
        g_edge = self.edge_map(libd)["libG.dylib"]
        self.assertFalse(g_edge.resolved)
        self.assertEqual(g_edge.kind, KIND_LOAD)

    def test_cycle_is_detected_per_architecture(self):
        graph = self.graph()
        cycle_pairs = {(src, dst) for arch, src, dst in graph.cycles}
        self.assertIn(
            (self.fixture.paths["libB.dylib"], self.fixture.paths["libA.dylib"]),
            cycle_pairs,
        )
        # Both architectures independently close the A<->B loop.
        cycle_archs = {arch for arch, _src, _dst in graph.cycles}
        self.assertEqual(
            cycle_archs,
            {ArchKey(ARM64, SUB_ALL), ArchKey(X86_64, SUB_ALL)},
        )

    def test_nodes_are_separate_per_architecture(self):
        graph = self.graph()
        arm_nodes = {n.path for n in graph._nodes_for(ArchKey(ARM64, SUB_ALL))}
        x86_nodes = {n.path for n in graph._nodes_for(ArchKey(X86_64, SUB_ALL))}
        # The arm64-only libE is a resolved node only on arm64.
        self.assertIn(self.fixture.paths["libE.dylib"], arm_nodes)
        self.assertNotIn(self.fixture.paths["libE.dylib"], x86_nodes)

    def test_report_lists_unresolved_edges_per_architecture(self):
        graph = self.graph()
        report = graph.report()
        self.assertIn("architecture %s" % ArchKey(ARM64, SUB_ALL).label(), report)
        self.assertIn("architecture %s" % ArchKey(X86_64, SUB_ALL).label(), report)
        self.assertIn("libG.dylib", report)
        self.assertIn("unresolved edges", report)

    def test_graph_is_a_dependency_graph_instance(self):
        self.assertIsInstance(self.graph(), ArchDependencyGraph)


if __name__ == "__main__":
    unittest.main()
