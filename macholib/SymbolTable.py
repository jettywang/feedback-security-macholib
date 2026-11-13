"""
Class to read the symbol table from a Mach-O header
"""

from __future__ import with_statement

from collections import namedtuple
import struct
import sys

from macholib.mach_o import (
    INDIRECT_SYMBOL_ABS,
    INDIRECT_SYMBOL_LOCAL,
    INDIRECT_SYMBOL_MASK,
    LC_SEGMENT,
    LC_SEGMENT_64,
    MH_CIGAM_64,
    MH_MAGIC_64,
    S_LAZY_DYLIB_SYMBOL_POINTERS,
    S_LAZY_SYMBOL_POINTERS,
    S_NON_LAZY_SYMBOL_POINTERS,
    S_SYMBOL_STUBS,
    S_THREAD_LOCAL_VARIABLE_POINTERS,
    dylib_module,
    dylib_module_64,
    dylib_reference,
    dylib_table_of_contents,
    nlist,
    nlist_64,
    relocation_info,
)

__all__ = ["SymbolTable", "StubEntry", "SymbolTableError", "INDIRECT_SECTION_TYPES"]

if sys.version_info[0] == 2:
    range = xrange  # noqa: F821


class SymbolTableError(ValueError):
    """Raised when a symbol or indirect table entry is malformed."""


StubEntry = namedtuple(
    "StubEntry",
    "segment section section_type section_index item_index indirect_index "
    "entry kind symbol_index name",
)

INDIRECT_SECTION_TYPES = frozenset(
    (
        S_NON_LAZY_SYMBOL_POINTERS,
        S_LAZY_SYMBOL_POINTERS,
        S_LAZY_DYLIB_SYMBOL_POINTERS,
        S_SYMBOL_STUBS,
        S_THREAD_LOCAL_VARIABLE_POINTERS,
    )
)

class SymbolTable(object):
    def __init__(self, macho, header=None, openfile=None):
        if openfile is None:
            openfile = open
        if header is None:
            header = macho.headers[0]
        self.macho_header = header
        self.macho = macho

        self.nlists = []
        self.localsyms = []
        self.extdefsyms = []
        self.undefsyms = []
        self.toc = None
        self.modtab = None
        self.indirectsyms = []
        self.stubs = []
        self.symbol_pointers = []
        self.errors = []

        with openfile(macho.filename, "rb") as fh:
            self.symtab = header.getSymbolTableCommand()
            self.dysymtab = header.getDynamicSymbolTableCommand()

            if self.symtab is not None:
                self.nlists = self.readSymbolTable(fh)

            if self.dysymtab is not None:
                self.readDynamicSymbolTable(fh)
                self.indirectsyms = self.readIndirectSymbolTable(fh)
                self.readIndirectSections()

    def _is_64_bit(self):
        return self.macho_header.MH_MAGIC in (MH_MAGIC_64, MH_CIGAM_64)

    def _nlist_class(self):
        return nlist_64 if self._is_64_bit() else nlist

    def _pointer_size(self):
        return 8 if self._is_64_bit() else 4

    def _check_window(self, offset, size, what):
        if offset < 0 or size < 0:
            raise SymbolTableError("%s has a negative offset or size" % (what,))
        if offset + size > self.macho_header.size:
            raise SymbolTableError(
                "%s at [%d, %d) exceeds the %d byte slice starting at %d"
                % (
                    what,
                    offset,
                    offset + size,
                    self.macho_header.size,
                    self.macho_header.offset,
                )
            )

    def _read_exact(self, fh, size, what):
        data = fh.read(size)
        if len(data) != size:
            raise SymbolTableError(
                "%s at offset %d is truncated: wanted %d bytes, got %d"
                % (what, fh.tell() - len(data), size, len(data))
            )
        return data

    def _symbol_name(self, strtab, n_strx, symbol_index):
        if n_strx == 0:
            return b""
        if n_strx >= len(strtab):
            raise SymbolTableError(
                "symbol %d has n_strx=%d outside the %d byte string table"
                % (symbol_index, n_strx, len(strtab))
            )
        end = strtab.find(b"\x00", n_strx)
        if end < 0:
            raise SymbolTableError(
                "symbol %d has n_strx=%d with no terminating NUL in the "
                "string table" % (symbol_index, n_strx)
            )
        return strtab[n_strx:end]

    def readSymbolTable(self, fh):
        cmd = self.symtab
        cls = self._nlist_class()
        nlist_size = struct.calcsize(cls._format_)
        self._check_window(int(cmd.stroff), int(cmd.strsize), "string table")
        self._check_window(
            int(cmd.symoff), int(cmd.nsyms) * nlist_size, "symbol table"
        )

        fh.seek(self.macho_header.offset + cmd.stroff)
        strtab = self._read_exact(fh, cmd.strsize, "string table")
        fh.seek(self.macho_header.offset + cmd.symoff)
        nlists = []

        endian = self.macho_header.endian
        for index in range(cmd.nsyms):
            entry = cls.from_fileobj(fh, _endian_=endian)
            name = self._symbol_name(strtab, int(entry.n_un), index)
            nlists.append((entry, name))
        return nlists

    def readDynamicSymbolTable(self, fh):
        cmd = self.dysymtab
        nlists = self.nlists
        nsyms = len(nlists)

        for label, start, count in (
            ("local", cmd.ilocalsym, cmd.nlocalsym),
            ("external defined", cmd.iextdefsym, cmd.nextdefsym),
            ("undefined", cmd.iundefsym, cmd.nundefsym),
        ):
            if int(start) + int(count) > nsyms:
                raise SymbolTableError(
                    "%s symbol range [%d, %d) exceeds the %d entry symbol table"
                    % (label, int(start), int(start) + int(count), nsyms)
                )

        self.localsyms = nlists[
            cmd.ilocalsym : cmd.ilocalsym + cmd.nlocalsym  # noqa: E203
        ]
        self.extdefsyms = nlists[
            cmd.iextdefsym : cmd.iextdefsym + cmd.nextdefsym  # noqa: E203
        ]
        self.undefsyms = nlists[
            cmd.iundefsym : cmd.iundefsym + cmd.nundefsym  # noqa: E203
        ]
        if cmd.tocoff == 0:
            self.toc = None
        else:
            self.toc = self.readtoc(fh, cmd.tocoff, cmd.ntoc)
        if cmd.modtaboff == 0:
            self.modtab = None
        else:
            self.modtab = self.readmodtab(fh, cmd.modtaboff, cmd.nmodtab)

    def readIndirectSymbolTable(self, fh):
        cmd = self.dysymtab
        if cmd is None:
            raise SymbolTableError("LC_DYSYMTAB is required for an indirect table")
        self._check_window(
            int(cmd.indirectsymoff), 4 * int(cmd.nindirectsyms), "indirect symbol table"
        )
        fh.seek(self.macho_header.offset + cmd.indirectsymoff)
        data = self._read_exact(fh, 4 * cmd.nindirectsyms, "indirect symbol table")
        count = int(cmd.nindirectsyms)
        if count == 0:
            return []
        fmt = self.macho_header.endian + "I" * count
        return [int(value) for value in struct.unpack(fmt, data)]

    def iterIndirectSections(self):
        """Yield (segment_name, section) for sections with indirect entries."""
        for lc, _cmd, data in self.macho_header.commands:
            if lc.cmd not in (LC_SEGMENT, LC_SEGMENT_64):
                continue
            for section in data:
                stype = int(section.flags) & 0xFF
                if stype in INDIRECT_SECTION_TYPES:
                    yield section.segname.rstrip(b"\x00"), section

    def indirectEntryCount(self, section):
        stype = int(section.flags) & 0xFF
        size = int(section.size)
        if stype == S_SYMBOL_STUBS:
            entry_size = int(section.reserved2)
            if entry_size == 0:
                raise SymbolTableError(
                    "stub section %s has reserved2=0, the symbol table cannot "
                    "derive its entry count"
                    % (section.sectname.rstrip(b"\x00").decode("utf-8", "replace"),)
                )
        else:
            entry_size = self._pointer_size()
        if entry_size <= 0 or size % entry_size:
            raise SymbolTableError(
                "section %s size %d is not a multiple of its %d byte indirect "
                "entry size"
                % (
                    section.sectname.rstrip(b"\x00").decode("utf-8", "replace"),
                    size,
                    entry_size,
                )
            )
        return size // entry_size

    def readIndirectSections(self):
        """Resolve every stub and symbol-pointer section.

        Ties each section entry to its nlist through section.reserved1 and
        section.size/reserved2 or the pointer width.  Special indirect values
        (INDIRECT_SYMBOL_LOCAL/ABS) are reported as such and never looked up
        as symbols.
        """
        if self.dysymtab is None:
            return
        self.stubs = []
        self.symbol_pointers = []
        total = len(self.indirectsyms)
        for segment, section in self.iterIndirectSections():
            stype = int(section.flags) & 0xFF
            count = self.indirectEntryCount(section)
            start = int(section.reserved1)
            end = start + count
            if start > total or end > total:
                self.errors.append(
                    "section %s references indirect entries [%d, %d) outside "
                    "the %d entry indirect table"
                    % (
                        section.sectname.rstrip(b"\x00").decode("utf-8", "replace"),
                        start,
                        end,
                        total,
                    )
                )
                count = max(0, min(count, total - start))
                if count == 0:
                    section.indirect_entries = []  # type: ignore[attr-defined]
                    continue
            entries = []
            for item_index in range(count):
                entry = self.indirectsyms[start + item_index]
                item = self._resolveIndirectEntry(
                    segment, section, stype, item_index, start + item_index, entry
                )
                if stype == S_SYMBOL_STUBS:
                    self.stubs.append(item)
                else:
                    self.symbol_pointers.append(item)
                entries.append(item)
            section.indirect_entries = entries  # type: ignore[attr-defined]

    def _resolveIndirectEntry(
        self, segment, section, stype, item_index, indirect_index, entry
    ):
        kind, symbol_index, name = self._resolveIndirectValue(entry, indirect_index)
        return StubEntry(
            segment=segment.rstrip(b"\x00").decode("utf-8", "replace"),
            section=section.sectname.rstrip(b"\x00").decode("utf-8", "replace"),
            section_type=stype,
            section_index=int(section.reserved1),
            item_index=item_index,
            indirect_index=indirect_index,
            entry=entry,
            kind=kind,
            symbol_index=symbol_index,
            name=name,
        )

    def _resolveIndirectValue(self, entry, indirect_index):
        marker = entry & INDIRECT_SYMBOL_MASK
        if marker:
            if marker == INDIRECT_SYMBOL_LOCAL:
                kind = "local"
            elif marker == INDIRECT_SYMBOL_ABS:
                kind = "absolute"
            elif marker == INDIRECT_SYMBOL_MASK:
                kind = "local-absolute"
            else:
                raise SymbolTableError(
                    "indirect entry %d has unsupported marker bits 0x%08x"
                    % (indirect_index, entry)
                )
            return kind, None, None

        if entry >= len(self.nlists):
            raise SymbolTableError(
                "indirect entry %d is symbol index %d, but the symbol table "
                "has only %d entries" % (indirect_index, entry, len(self.nlists))
            )
        return "symbol", entry, self.nlists[entry][1]

    def diagnose(self):
        """Explain symbol/stub counts structurally rather than by name.

        nindirectsyms is a table size, not a stub count.  Each section owns the
        window [reserved1, reserved1 + size/entry_size); those windows may
        overlap when a linker reuses entries (Go binaries do this for __got).
        """
        sections = []
        total = 0
        windows = []
        for segment, section in self.iterIndirectSections():
            count = self.indirectEntryCount(section)
            start = int(section.reserved1)
            total += count
            windows.append((start, start + count))
            sections.append(
                {
                    "segment": segment.rstrip(b"\x00").decode("utf-8", "replace"),
                    "section": section.sectname.rstrip(b"\x00").decode(
                        "utf-8", "replace"
                    ),
                    "type": int(section.flags) & 0xFF,
                    "reserved1": start,
                    "reserved2": int(section.reserved2),
                    "count": count,
                }
            )

        overlapping = any(
            windows[i][1] > windows[j][0]
            for i in range(len(windows))
            for j in range(i + 1, len(windows))
            if windows[i][0] < windows[j][1]
        )

        used = set()
        markers = 0
        for item in list(self.stubs) + list(self.symbol_pointers):
            if item.symbol_index is None:
                markers += 1
            else:
                used.add(item.symbol_index)

        return {
            "nsyms": len(self.nlists),
            "nindirectsyms": len(self.indirectsyms),
            "section_indirect_total": total,
            "windows_in_bounds": not any("outside" in err for err in self.errors),
            "windows_overlap": overlapping,
            "errors": list(self.errors),
            "sections": sections,
            "stubs": len(self.stubs),
            "symbol_pointers": len(self.symbol_pointers),
            "markers": markers,
            "referenced_symbol_indexes": sorted(used),
            "unreferenced_symbol_indexes": [
                index for index in range(len(self.nlists)) if index not in used
            ],
        }

    def readtoc(self, fh, off, n):
        self._check_window(int(off), 8 * int(n), "table of contents")
        fh.seek(self.macho_header.offset + off)
        return [
            dylib_table_of_contents.from_fileobj(fh, _endian_=self.macho_header.endian)
            for _i in range(n)
        ]

    def readmodtab(self, fh, off, n):
        cls = dylib_module_64 if self._is_64_bit() else dylib_module
        nlist_size = struct.calcsize(cls._format_)
        self._check_window(int(off), nlist_size * int(n), "module table")
        fh.seek(self.macho_header.offset + off)
        return [
            cls.from_fileobj(fh, _endian_=self.macho_header.endian) for _i in range(n)
        ]

    def readsym(self, fh, off, n):
        self._check_window(int(off), 4 * int(n), "dylib reference table")
        fh.seek(self.macho_header.offset + off)
        refs = []
        for _i in range(n):
            ref = dylib_reference.from_fileobj(fh, _endian_=self.macho_header.endian)
            raw = int(ref.isym_flags)
            if self.macho_header.endian == "<":
                isym, flags = raw & 0xFFFFFF, raw >> 24
            else:
                isym, flags = raw >> 8, raw & 0xFF
            if isym >= len(self.nlists):
                raise SymbolTableError(
                    "dylib reference at %d has symbol index %d outside the %d "
                    "entry symbol table" % (off, isym, len(self.nlists))
                )
            refs.append((self.nlists[isym], flags))
        return refs

    def readrel(self, fh, off, n):
        self._check_window(int(off), 8 * int(n), "relocation table")
        fh.seek(self.macho_header.offset + off)
        return [
            relocation_info.from_fileobj(fh, _endian_=self.macho_header.endian)
            for _i in range(n)
        ]
