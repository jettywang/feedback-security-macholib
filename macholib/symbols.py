"""Human-readable diagnostics for Mach-O symbol/stub association."""

from __future__ import print_function

import sys

from macholib.MachO import MachO
from macholib.SymbolTable import SymbolTable, SymbolTableError

_ARCH_NAMES = {
    0x0100000C: "arm64",
    0x01000007: "x86_64",
    7: "i386",
}

_TYPE_NAMES = {
    0x6: "S_NON_LAZY_SYMBOL_POINTERS",
    0x7: "S_LAZY_SYMBOL_POINTERS",
    0x8: "S_SYMBOL_STUBS",
    0x10: "S_LAZY_DYLIB_SYMBOL_POINTERS",
    0x14: "S_THREAD_LOCAL_VARIABLE_POINTERS",
}


def _safe_name(name):
    if name is None:
        return "-"
    if sys.version_info[0] == 2:
        return name
    return name.decode("utf-8", "backslashreplace")


def _text(value):
    if not isinstance(value, bytes):
        return value
    if sys.version_info[0] == 2:
        return value
    return value.decode("utf-8", "backslashreplace")


def format_table(table, out, path="<memory>", show_all=False):
    """Print section windows and a few representative indirect entries."""
    report = table.diagnose()
    print(
        "%s: nsyms=%d nindirectsyms=%d"
        % (path, report["nsyms"], report["nindirectsyms"]),
        file=out,
    )
    if report["windows_overlap"]:
        print(
            "  note: section windows overlap; nindirectsyms is a table "
            "size, not a stub count",
            file=out,
        )
    for section in report["sections"]:
        print(
            "  %s,%s type=%s reserved1=%d reserved2=%d entries=%d"
            % (
                _text(section["segment"]),
                _text(section["section"]),
                _TYPE_NAMES.get(section["type"], hex(section["type"])),
                section["reserved1"],
                section["reserved2"],
                section["count"],
            ),
            file=out,
        )

    items = list(table.stubs) + list(table.symbol_pointers)
    if not show_all:
        markers = [item for item in items if item.symbol_index is None]
        numbered = [item for item in items if item.symbol_index is not None]
        items = (markers + numbered)[:8]
    for item in items:
        label = "stub" if item.section_type == 0x8 else "ptr"
        print(
            "  %s %s[%d] indirect[%d] entry=0x%08x kind=%s symbol=%s name=%s"
            % (
                label,
                _text(item.section),
                item.item_index,
                item.indirect_index,
                item.entry,
                item.kind,
                "-" if item.symbol_index is None else item.symbol_index,
                _safe_name(item.name),
            ),
            file=out,
        )

    for error in report["errors"]:
        print("  ERROR: %s" % (error,), file=out)
    return bool(report["errors"])


def report_symbols(path, out, show_all=False):
    macho = MachO(path, allow_unknown_load_commands=True)
    failed = False
    for index, header in enumerate(macho.headers):
        arch = _ARCH_NAMES.get(
            int(header.header.cputype), str(header.header.cputype)
        )
        print(
            "slice %d: arch=%s offset=%d size=%d"
            % (index, arch, header.offset, header.size),
            file=out,
        )
        try:
            table = SymbolTable(macho, header=header)
        except SymbolTableError as exc:
            print("  ERROR: %s" % (exc,), file=out)
            failed = True
            continue
        if format_table(table, out, path, show_all):
            failed = True
    return failed
