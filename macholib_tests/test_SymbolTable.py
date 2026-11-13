import os
import struct
import sys
import tempfile

from macholib import SymbolTable
from macholib.MachO import MachO
from macholib.mach_o import INDIRECT_SYMBOL_ABS, INDIRECT_SYMBOL_LOCAL
from macholib_tests import stub_fixture as fx

if sys.version_info[:2] <= (2, 6):
    import unittest2 as unittest
else:
    import unittest


class FakeHeader(object):
    def __init__(self, endian="<", magic=fx.MH_MAGIC_64, size=4096):
        self.endian = endian
        self.MH_MAGIC = magic
        self.size = size
        self.offset = 0


def fake_table(nlists, endian="<"):
    table = SymbolTable.SymbolTable.__new__(SymbolTable.SymbolTable)
    table.macho_header = FakeHeader(endian=endian)
    table.nlists = nlists
    return table


class FixtureMixin(object):
    def make(self, bits, **kw):
        fd, path = tempfile.mkstemp(suffix=".dylib", dir=os.environ.get("TMPDIR"))
        os.close(fd)
        self.addCleanup(os.unlink, path)
        fx.write_sample(path, bits=bits, **kw)
        return path

    def make_fat(self, slices, **kw):
        fd, path = tempfile.mkstemp(suffix=".fat", dir=os.environ.get("TMPDIR"))
        os.close(fd)
        self.addCleanup(os.unlink, path)
        with open(path, "wb") as fh:
            fh.write(fx.build_fat([image for image, _ in slices], **kw))
        return path

    def assertStubs(self, table, expected):
        self.assertEqual(len(table.stubs), len(expected))
        for item, (name, kind) in zip(table.stubs, expected):
            self.assertEqual(item.kind, kind)
            if name is None:
                self.assertIsNone(item.symbol_index)
                self.assertIsNone(item.name)
            else:
                self.assertEqual(item.name, name.encode("utf-8"))
                self.assertEqual(
                    table.nlists[item.symbol_index][1], name.encode("utf-8")
                )


class TestSymbolTable(FixtureMixin, unittest.TestCase):
    def test_thin_stub_ownership_64(self):
        macho = MachO(self.make(64))
        table = SymbolTable.SymbolTable(macho)
        self.assertStubs(
            table,
            [("_malloc", "symbol"), (None, "local"), ("_rare_symbol", "symbol")],
        )
        self.assertEqual(
            [
                (p.section, p.item_index, p.kind, p.symbol_index)
                for p in table.symbol_pointers
            ],
            [
                ("__got", 0, "local-absolute", None),
                ("__got", 1, "symbol", 2),
                ("__la_symbol_ptr", 0, "symbol", 4),
            ],
        )

    def test_thin_stub_ownership_32(self):
        macho = MachO(self.make(32))
        table = SymbolTable.SymbolTable(macho)
        self.assertStubs(
            table,
            [("_malloc", "symbol"), (None, "local"), ("_rare_symbol", "symbol")],
        )
        self.assertEqual(table.localsyms[0][1], b"_local_data")
        self.assertEqual(table.extdefsyms[0][1], b"_exported_fn")
        self.assertEqual(len(table.undefsyms), 4)

    def test_marker_entries_never_named(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                table = SymbolTable.SymbolTable(MachO(self.make(bits)))
                marker = table.stubs[1]
                self.assertEqual(marker.entry, INDIRECT_SYMBOL_LOCAL)
                self.assertIsNone(marker.name)
                absolute = table.symbol_pointers[0]
                self.assertEqual(
                    absolute.entry, INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS
                )
                self.assertEqual(absolute.kind, "local-absolute")
                self.assertIsNone(absolute.name)
                for item in table.stubs + table.symbol_pointers:
                    if item.kind != "symbol":
                        self.assertIsNone(item.name)

    def test_fat_offsets_select_distinct_slices(self):
        slices = [
            fx.build_sample(64, tag="_slice0"),
            fx.build_sample(32, tag="_slice1"),
        ]
        path = self.make_fat(slices)
        macho = MachO(path)
        self.assertEqual(len(macho.headers), 2)
        expected = [
            (4096, "%#x" % (fx.MH_MAGIC_64,)),
            (8192, "%#x" % (fx.MH_MAGIC,)),
        ]
        for header, (offset, magic) in zip(macho.headers, expected):
            with self.subTest(offset=offset):
                self.assertEqual(header.offset, offset)
                table = SymbolTable.SymbolTable(macho, header=header)
                expected_name = b"_malloc_slice0" if offset == 4096 else b"_malloc_slice1"
                self.assertEqual(table.stubs[0].name, expected_name)
                self.assertEqual(len(table.stubs), 3)
                self.assertEqual(len(table.nlists), 7)

    def test_fat64_offsets(self):
        slices = [fx.build_sample(64, tag="_fat64")]
        path = self.make_fat(slices, fat64=True)
        macho = MachO(path)
        self.assertEqual(len(macho.headers), 1)
        self.assertEqual(macho.headers[0].offset, 4096)
        table = SymbolTable.SymbolTable(macho)
        self.assertEqual(table.stubs[0].name, b"_malloc_fat64")

    def test_nlist_64_width_uses_16_byte_records(self):
        fd, path = tempfile.mkstemp(suffix=".dylib", dir=os.environ.get("TMPDIR"))
        os.close(fd)
        self.addCleanup(os.unlink, path)
        fx.write_sample(path, bits=64)
        macho = MachO(path)
        raw = open(path, "rb").read()
        header = macho.headers[0]
        symtab = header.getSymbolTableCommand()
        first = raw[symtab.symoff : symtab.symoff + 16]
        second = raw[symtab.symoff + 16 : symtab.symoff + 32]
        self.assertEqual(struct.unpack("<I", first[:4])[0], 1)
        self.assertEqual(struct.unpack("<I", second[:4])[0], 13)
        table = SymbolTable.SymbolTable(macho)
        self.assertEqual(len(table.nlists), symtab.nsyms)
        self.assertEqual(table.nlists[6][0].n_value, 0)

    def test_mismatched_indirect_count_is_reported(self):
        path = self.make(64, nindirectsyms_override=5)
        table = SymbolTable.SymbolTable(MachO(path))
        report = table.diagnose()
        self.assertFalse(report["windows_in_bounds"])
        self.assertEqual(report["nindirectsyms"], 5)
        self.assertEqual(report["section_indirect_total"], 6)
        self.assertTrue(
            any("outside the 5 entry" in err for err in report["errors"])
        )

    def test_section_count_comes_from_reserved2_and_size(self):
        fd, path = tempfile.mkstemp(suffix=".dylib", dir=os.environ.get("TMPDIR"))
        os.close(fd)
        self.addCleanup(os.unlink, path)
        image, meta = fx.build_sample(
            64, stub_reserved2=6, stub_section_size=12, nindirectsyms_override=5
        )
        with open(path, "wb") as fh:
            fh.write(image)
        table = SymbolTable.SymbolTable(MachO(path))
        self.assertEqual(table.diagnose()["sections"][1]["count"], 2)
        self.assertEqual(len(table.stubs), 2)
        self.assertEqual([item.kind for item in table.stubs], ["symbol", "local"])
        self.assertEqual(table.stubs[0].name, b"_malloc")
        self.assertTrue(table.diagnose()["errors"])

    def test_zero_stub_size_is_an_error(self):
        path = self.make(64, stub_reserved2=0)
        with self.assertRaises(SymbolTable.SymbolTableError):
            SymbolTable.SymbolTable(MachO(path))

    def test_string_table_past_fat_slice_is_rejected(self):
        image, meta = fx.build_sample(64, tag="_clipped")
        clip = meta["stroff"] - 1
        path = self.make_fat([(image, meta)], arch_size_overrides={0: clip})
        with self.assertRaises(SymbolTable.SymbolTableError) as ctx:
            SymbolTable.SymbolTable(MachO(path))
        self.assertIn("exceeds", str(ctx.exception))
        self.assertIn("string table", str(ctx.exception))

    def test_string_index_out_of_range_is_not_empty(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                path = self.make(bits, strx_override={6: 0x10000})
                with self.assertRaises(SymbolTable.SymbolTableError) as ctx:
                    SymbolTable.SymbolTable(MachO(path))
                self.assertIn("outside", str(ctx.exception))

    def test_corrupt_string_index_above_signed_maximum(self):
        path = self.make(64, strx_override={6: 0x80000001})
        with self.assertRaises(SymbolTable.SymbolTableError) as ctx:
            SymbolTable.SymbolTable(MachO(path))
        self.assertIn("outside", str(ctx.exception))

    def test_missing_nul_is_an_error(self):
        path = self.make(64, missing_nul=True)
        with self.assertRaises(SymbolTable.SymbolTableError) as ctx:
            SymbolTable.SymbolTable(MachO(path))
        self.assertIn("terminating NUL", str(ctx.exception))

    def test_indirect_index_out_of_range_is_an_error(self):
        # Symbol index 6 is the last entry; force the third stub to point past it.
        fd, path = tempfile.mkstemp(suffix=".dylib", dir=os.environ.get("TMPDIR"))
        os.close(fd)
        self.addCleanup(os.unlink, path)
        image, meta = fx.build_sample(64)
        offset = meta["indirectsymoff"] + 2 * 4
        image = image[:offset] + struct.pack("<I", 7) + image[offset + 4 :]
        with open(path, "wb") as fh:
            fh.write(image)
        with self.assertRaises(SymbolTable.SymbolTableError) as ctx:
            SymbolTable.SymbolTable(MachO(path))
        self.assertIn("only 7 entries", str(ctx.exception))

    def test_big_endian_32_bit_tables(self):
        fd, path = tempfile.mkstemp(suffix=".dylib", dir=os.environ.get("TMPDIR"))
        os.close(fd)
        self.addCleanup(os.unlink, path)
        with open(path, "wb") as fh:
            fh.write(fx.build_be32())
        table = SymbolTable.SymbolTable(MachO(path))
        self.assertEqual([name for _nlist, name in table.nlists], [b"_be_local", b"_be_undef"])
        self.assertEqual(table.indirectsyms, [1, INDIRECT_SYMBOL_LOCAL])
        self.assertEqual(len(table.localsyms), 1)
        self.assertEqual(len(table.extdefsyms), 1)
        self.assertEqual(len(table.undefsyms), 0)
        self.assertEqual(
            table._resolveIndirectValue(table.indirectsyms[0], 0)[2], b"_be_undef"
        )
        self.assertEqual(
            table._resolveIndirectValue(table.indirectsyms[1], 1)[0], "local"
        )

    def test_dylib_reference_endianness(self):
        nlists = [(None, b"a"), (None, b"b")]
        for endian, raw in (
            ("<", 1 | (2 << 24)),
            (">", (1 << 8) | 2),
        ):
            with self.subTest(endian=endian):
                table = fake_table(nlists, endian)
                fd, path = tempfile.mkstemp(dir=os.environ.get("TMPDIR"))
                os.close(fd)
                self.addCleanup(os.unlink, path)
                with open(path, "wb") as fh:
                    fh.write(struct.pack(endian + "I", raw))
                with open(path, "rb") as fh:
                    refs = table.readsym(fh, 0, 1)
                self.assertEqual(refs[0][1], 2)
                self.assertEqual(refs[0][0][1], b"b")

    def test_repeated_headers_agree_on_layout(self):
        table = SymbolTable.SymbolTable(MachO(self.make(64)))
        self.assertEqual(table.diagnose()["section_indirect_total"], 6)
        self.assertEqual(len(table.stubs), 3)


if __name__ == "__main__":
    unittest.main()
