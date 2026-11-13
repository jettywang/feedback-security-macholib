"""Static, non-decrypting analysis built directly on macholib's read path.

The analyzer reuses ``macholib.MachO`` for the only thing it trusts without
decryption: the mach header, load commands and the offsets/sizes they declare.
It never executes the image and never attempts to recover plaintext. Every
data region is classified against the declared encryption window so the report
distinguishes *declared encrypted*, *range conflict* and *actually readable
cleartext* bytes instead of guessing.

Both real files and in-memory byte strings are accepted.
"""

from __future__ import annotations

import io
import os

from macholib.MachO import MachO
from macholib.SymbolTable import SymbolTable
from macholib.mach_o import (
    LC_CODE_SIGNATURE,
    LC_DYLD_CHAINED_FIXUPS,
    LC_DYLD_EXPORTS_TRIE,
    LC_DYLD_INFO,
    LC_DYLD_INFO_ONLY,
    LC_ENCRYPTION_INFO,
    LC_ENCRYPTION_INFO_64,
    LC_MAIN,
    LC_SEGMENT_64,
    LC_UNIXTHREAD,
    MH_CIGAM_64,
    MH_FLAGS_NAMES,
    MH_MAGIC_64,
    S_ZEROFILL,
    get_cpu_subtype,
    nlist_64,
)
from macholib.ptypes import sizeof

import ranges

ENCRYPTION_CMDS = (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64)
# linkedit_data_command style (single dataoff/datasize pair)
LINKEDIT_DATA_CMDS = (
    LC_DYLD_EXPORTS_TRIE, LC_DYLD_CHAINED_FIXUPS, LC_CODE_SIGNATURE,
)
DYLD_INFO_CMDS = (LC_DYLD_INFO, LC_DYLD_INFO_ONLY)


class InMemoryMachO(MachO):
    """MachO variant that parses a byte string instead of opening a path."""

    def __init__(self, blob):
        self._blob = bytes(blob)
        self.graphident = "<in-memory>"
        self.filename = "<in-memory>"
        self.loader_path = ""
        self.fat = None
        self.headers = []
        self.allow_unknown_load_commands = False
        self.load(io.BytesIO(self._blob))


def _commands(header):
    for index, (lc, cmd, data) in enumerate(header.commands):
        yield index, lc, cmd, data


def _flag_names(raw_flags):
    return [name for bit, name in MH_FLAGS_NAMES.items() if raw_flags & bit]


def _readable_state(state):
    # With no active encryption command every on-disk byte is cleartext.
    return "fully-clear" if state == "no-encryption-command" else state


def _encryption_window(header, file_size):
    found = []
    for _idx, lc, cmd, _data in _commands(header):
        if lc.cmd in ENCRYPTION_CMDS:
            found.append((lc, int(cmd.cryptoff), int(cmd.cryptsize),
                          int(cmd.cryptid)))
    diagnostics = []
    if len(found) > 1:
        diagnostics.append("multiple encryption commands present")
    if not found:
        return None, diagnostics
    lc, cryptoff, cryptsize, cryptid = found[0]

    if cryptid != 0 and cryptsize == 0:
        diagnostics.append(
            "inconsistent declaration: cryptid=%d but cryptsize=0" % cryptid)
    if cryptid == 0 and cryptsize != 0:
        diagnostics.append(
            "dormant command: cryptid=0 (region stays cleartext on disk)")
    window_end = cryptoff + cryptsize
    if window_end > file_size:
        diagnostics.append(
            "declared window overruns file: end=0x%x filesize=0x%x"
            % (window_end, file_size))

    if cryptid == 0 or cryptsize == 0:
        return None, diagnostics
    return ranges.Interval(cryptoff, window_end, "crypt"), diagnostics


def _segment_records(header):
    out = []
    for _idx, lc, cmd, data in _commands(header):
        if lc.cmd != LC_SEGMENT_64:
            continue
        sections = [
            (sect.sectname.rstrip(b"\x00").decode(), int(sect.offset),
             int(sect.size), int(sect.flags))
            for sect in data
        ]
        out.append({
            "name": cmd.segname.rstrip(b"\x00").decode(),
            "file": ranges.Interval(int(cmd.fileoff),
                                    int(cmd.fileoff) + int(cmd.filesize)),
            "vmaddr": int(cmd.vmaddr), "vmsize": int(cmd.vmsize),
            "initprot": int(cmd.initprot), "maxprot": int(cmd.maxprot),
            "sections": sections,
        })
    return out


def _linkedit_regions(header):
    regions = []
    for _idx, lc, cmd, _data in _commands(header):
        if lc.cmd in LINKEDIT_DATA_CMDS:
            regions.append((lc.get_cmd_name(), int(cmd.dataoff),
                            int(cmd.datasize)))
        elif lc.cmd in DYLD_INFO_CMDS:
            for prefix in ("rebase", "bind", "weak_bind", "lazy_bind",
                           "export"):
                off = int(getattr(cmd, prefix + "_off"))
                size = int(getattr(cmd, prefix + "_size"))
                if size:
                    regions.append(("%s:%s" % (lc.get_cmd_name(), prefix),
                                    off, size))
    return regions


def analyze(blob):
    macho = InMemoryMachO(blob)
    return {"fat": macho.fat is not None,
            "architectures": [
                _analyze_header(macho, h, len(blob)) for h in macho.headers]}


def analyze_path(path):
    macho = MachO(path)
    file_size = os.path.getsize(path)
    with open(path, "rb") as fh:
        macho._blob = fh.read()
    return {"fat": macho.fat is not None,
            "architectures": [
                _analyze_header(macho, h, file_size) for h in macho.headers]}


def _analyze_header(macho, header, file_size):
    blob = macho._blob
    h = header.header
    crypto, diagnostics = _encryption_window(header, file_size)

    result = {
        "identity": {
            "width": "64-bit" if header.MH_MAGIC in (MH_MAGIC_64, MH_CIGAM_64)
            else "32-bit",
            "endian": header.endian,
            "cputype": h.cputype,
            "cpusubtype": get_cpu_subtype(h.cputype, h.cpusubtype),
            "filetype": header.filetype,
            "flags": _flag_names(int(h.flags)),
        },
        "encryption": _encryption_summary(header, crypto, diagnostics),
        "dependencies": _dependencies(header),
        "entry": _entry(header, crypto),
        "segments": [],
        "symbols": _symbols(macho, header, crypto),
        "linkedit": _linkedit(header, crypto),
        "confidence_notes": list(diagnostics),
    }

    for seg in _segment_records(header):
        coverage = ranges.classify_against(seg["file"], crypto)
        coverage_state = _readable_state(coverage["state"])
        sec_reports = []
        for name, off, size, flags in seg["sections"]:
            if flags & S_ZEROFILL or off == 0:
                # S_ZEROFILL sections occupy only virtual memory; there are no
                # on-disk bytes to read or encrypt, so they must not be counted
                # as either cleartext or ciphertext.
                sec_reports.append({"name": name,
                                    "state": "zerofill/no-file-bytes",
                                    "encrypted": 0, "clear": 0})
                continue
            sec_cov = ranges.classify_against(
                ranges.Interval(off, off + size), crypto)
            sec_reports.append({
                "name": name, "state": _readable_state(sec_cov["state"]),
                "encrypted": sec_cov["encrypted"], "clear": sec_cov["clear"],
                "entropy_bps": round(
                    ranges.shannon_entropy(blob[off:off + size]), 3),
            })
        result["segments"].append({
            "name": seg["name"],
            "file_range": (seg["file"].start, seg["file"].end),
            "vmaddr": seg["vmaddr"], "vmsize": seg["vmsize"],
            "initprot": seg["initprot"], "maxprot": seg["maxprot"],
            "coverage": coverage_state,
            "encrypted_bytes": coverage["encrypted"],
            "clear_bytes": coverage["clear"],
            "sections": sec_reports,
        })

    result["range_conflicts"] = _range_conflicts(result, crypto, file_size)
    return result


def _encryption_summary(header, crypto, diagnostics):
    raw = None
    for _idx, lc, cmd, _data in _commands(header):
        if lc.cmd in ENCRYPTION_CMDS:
            raw = {"command": lc.get_cmd_name(),
                   "cryptoff": int(cmd.cryptoff),
                   "cryptsize": int(cmd.cryptsize),
                   "cryptid": int(cmd.cryptid)}
    if raw is None:
        return {"declared": False, "active": False, "readable_window": None}
    summary = dict(raw)
    summary["declared"] = True
    summary["active"] = crypto is not None
    summary["readable_window"] = (None if crypto is None
                                  else (crypto.start, crypto.end))
    summary["diagnostics"] = diagnostics
    return summary


def _dependencies(header):
    # LC_LOAD_DYLIB strings live in the load-command area, which precedes the
    # encryption window; they are always readable and never "uncertain".
    return [{"kind": name, "path": path,
             "certainty": "declared-in-load-commands"}
            for _idx, name, path in header.walkRelocatables()]


def _entry(header, crypto):
    for _idx, lc, cmd, _data in _commands(header):
        if lc.cmd == LC_MAIN:
            entryoff = int(cmd.entryoff)
            point = ranges.Interval(entryoff, entryoff + 1)
            covered = crypto is not None and \
                ranges.intersect(point, crypto) is not None
            return {
                "source": "LC_MAIN", "entryoff": entryoff,
                "location_known": True,
                "instructions_readable": not covered,
                "certainty": "encrypted-bytes-unreadable" if covered
                else "cleartext",
            }
        if lc.cmd == LC_UNIXTHREAD:
            return {"source": "LC_UNIXTHREAD", "location_known": True,
                    "instructions_readable": crypto is None,
                    "certainty": "thread-state-entry"}
    return {"source": None, "location_known": False,
            "instructions_readable": False,
            "certainty": "no-entry-command-found"}


def _symbols(macho, header, crypto):
    sym = header.getSymbolTableCommand()
    if sym is None:
        return {"present": False,
                "certainty": "no-LC_SYMTAB (stripped or never emitted)"}

    nlist_bytes = int(sym.nsyms) * sizeof(nlist_64)
    sym_region = ranges.Interval(int(sym.symoff),
                                 int(sym.symoff) + nlist_bytes)
    str_region = ranges.Interval(int(sym.stroff),
                                 int(sym.stroff) + int(sym.strsize))
    sym_cov = ranges.classify_against(sym_region, crypto)
    str_cov = ranges.classify_against(str_region, crypto)
    readable = _readable_state(sym_cov["state"]) == "fully-clear" and \
        _readable_state(str_cov["state"]) == "fully-clear"

    out = {
        "present": True, "nsyms": int(sym.nsyms),
        "symtab_range": (sym_region.start, sym_region.end),
        "strtab_range": (str_region.start, str_region.end),
        "symtab_coverage": _readable_state(sym_cov["state"]),
        "strtab_coverage": _readable_state(str_cov["state"]),
        "names_resolvable": readable,
        "certainty": "fully-readable" if readable
        else "metadata-only: symbol/string bytes inside crypt window",
    }
    if readable:
        table = SymbolTable.__new__(SymbolTable)
        table.macho_header = header
        table.symtab = sym
        table.dysymtab = header.getDynamicSymbolTableCommand()
        nlists = table.readSymbolTable(io.BytesIO(macho._blob))
        out["sample_names"] = [
            name.decode("utf-8", "replace") for _nlist, name in nlists][:5]
    return out


def _linkedit(header, crypto):
    rows = []
    for name, off, size in _linkedit_regions(header):
        if size == 0:
            continue
        region = ranges.Interval(off, off + size)
        cov = ranges.classify_against(region, crypto)
        state = _readable_state(cov["state"])
        rows.append({"command": name, "range": (off, off + size),
                     "coverage": state,
                     "encrypted_bytes": cov["encrypted"],
                     "clear_bytes": cov["clear"],
                     "parseable": state == "fully-clear"})
    return rows


def _range_conflicts(result, crypto, file_size):
    conflicts = []
    if crypto is not None and crypto.end > file_size:
        conflicts.append("crypt window extends past end of file")
    for seg in result["segments"]:
        start, end = seg["file_range"]
        if end > file_size:
            conflicts.append("segment %s extends past end of file"
                             % seg["name"])
        if crypto is not None and seg["name"] == "__LINKEDIT":
            overlap = ranges.overlap_size(ranges.Interval(start, end), crypto)
            if overlap:
                conflicts.append(
                    "crypt window overlaps __LINKEDIT by %d bytes; dyld "
                    "metadata and signature would be unreadable on disk"
                    % overlap)
    for row in result["linkedit"]:
        start, end = row["range"]
        if end > file_size:
            conflicts.append("%s range past end of file" % row["command"])
    return conflicts
