"""End-to-end demo: build in-memory samples and report what static analysis
can establish without decrypting or executing them.

Run with the repository root on PYTHONPATH so the local macholib is used:

    python3 deliverable/demo/run_demo.py
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

import analyzer
import ranges
import sample_generator as gen

WIDTH = 60


def _bar(region_start, region_end, crypt, total):
    """Render one region's crypt coverage as an ASCII bar."""
    if total == 0:
        return ""
    marks = []
    for col in range(WIDTH):
        lo = total * col // WIDTH
        hi = total * (col + 1) // WIDTH
        sample = ranges.Interval(lo, max(hi, lo + 1))
        in_region = ranges.intersect(sample, ranges.Interval(region_start,
                                                             region_end))
        in_crypt = crypt is not None and ranges.intersect(sample, crypt)
        if not in_region:
            marks.append(".")
        elif in_crypt:
            marks.append("#")       # declared encrypted
        else:
            marks.append("-")       # readable cleartext
    return "".join(marks)


def _diagram(layout, crypto):
    total = layout["total_size"]
    lines = ["  legend: '-' cleartext/readable   '#' declared-encrypted   "
             "'.' outside region", ""]
    lines.append("  file 0x%06x .. 0x%06x (%d bytes); crypt window %s"
                 % (0, total, total,
                    ("0x%x-0x%x" % (crypto.start, crypto.end))
                    if crypto else "none/inactive"))
    lines.append("  +" + "-" * WIDTH + "+")
    # Each row is (label, start, size); layout tuples are (offset, size).
    rows = [("header+cmds", 0, layout["header_cmds_end"])]
    for name in ("__TEXT", "__DATA", "__LINKEDIT"):
        off, size = layout["segments"][name]
        rows.append((name, off, size))
    for name in ("__text", "__cstring", "__got", "__data"):
        off, size = layout["sections"][name]
        rows.append(("  ." + name, off, size))
    for label, key in (("symtab", "symtab"), ("strtab", "strtab"),
                       ("dyld_info", "dyld_info"),
                       ("code_signature", "code_signature")):
        off, size = layout[key]
        rows.append((label, off, size))
    rows.append(("LC_MAIN entryoff", layout["entryoff"], 1))
    for label, start, size in rows:
        end = start + size
        bar = _bar(start, end, crypto, total)
        lines.append("  |%s| %-18s 0x%05x-0x%05x" % (bar, label, start, end))
    lines.append("  +" + "-" * WIDTH + "+")
    return "\n".join(lines)


def _print_arch(arch):
    ident = arch["identity"]
    print("  identity     : %s %s endian=%s type=%s"
          % (ident["cputype"], ident["cpusubtype"], ident["endian"],
             ident["filetype"]))
    print("  header flags : %s" % ", ".join(ident["flags"]))
    enc = arch["encryption"]
    if not enc["declared"]:
        print("  encryption   : none")
    else:
        print("  encryption   : %s cryptoff=0x%x cryptsize=0x%x cryptid=%s "
              "active=%s" % (enc["command"], enc["cryptoff"], enc["cryptsize"],
                             enc["cryptid"], enc["active"]))
        for note in enc.get("diagnostics", []):
            print("                 ! %s" % note)
    print("  dependencies : %d (all in load commands, always readable)"
          % len(arch["dependencies"]))
    for dep in arch["dependencies"]:
        print("                 - %s  [%s]" % (dep["path"], dep["certainty"]))
    entry = arch["entry"]
    print("  entry        : %s %s instructions_readable=%s (%s)"
          % (entry["source"],
             ("entryoff=0x%x" % entry["entryoff"])
             if entry.get("entryoff") is not None else "",
             entry["instructions_readable"], entry["certainty"]))

    print("  segments/sections:")
    for seg in arch["segments"]:
        print("    %-10s file=0x%05x-0x%05x coverage=%-19s enc=%d clear=%d"
              % (seg["name"], seg["file_range"][0], seg["file_range"][1],
                 seg["coverage"], seg["encrypted_bytes"], seg["clear_bytes"]))
        for sect in seg["sections"]:
            extra = ("entropy=%.2fbps" % sect["entropy_bps"]) \
                if "entropy_bps" in sect else "no file bytes"
            print("      .%-10s %-19s enc=%-5d clear=%-5d %s"
                  % (sect["name"], sect["state"], sect["encrypted"],
                     sect["clear"], extra))

    sym = arch["symbols"]
    if sym["present"]:
        print("  symbols      : nsyms=%d names_resolvable=%s (%s)"
              % (sym["nsyms"], sym["names_resolvable"], sym["certainty"]))
        if "sample_names" in sym:
            print("                 names=%s" % sym["sample_names"])
    else:
        print("  symbols      : %s" % sym["certainty"])

    print("  linkedit data:")
    for row in arch["linkedit"]:
        print("    %-28s 0x%05x-0x%05x %-19s parseable=%s"
              % (row["command"], row["range"][0], row["range"][1],
                 row["coverage"], row["parseable"]))

    if arch["range_conflicts"]:
        print("  RANGE CONFLICTS:")
        for c in arch["range_conflicts"]:
            print("    !! %s" % c)
    else:
        print("  range conflicts: none")


def main():
    print("=" * 78)
    print("STATIC (NON-DECRYPTING) MACH-O ANALYSIS DEMO")
    print("All samples are synthesized in memory; nothing is executed or")
    print("decrypted. '#' marks bytes the header declares encrypted; the tool")
    print("only measures them, never interprets them as code.")
    print("=" * 78)

    for scenario in gen.SCENARIOS:
        blob, layout = gen.build_slice(scenario)
        crypto, _diag = analyzer._encryption_window(
            analyzer.InMemoryMachO(blob).headers[0], len(blob))
        print("\n### scenario=%s (single arm64 slice)" % scenario)
        print(_diagram(layout, crypto))
        report = analyzer.analyze(blob)
        _print_arch(report["architectures"][0])

    print("\n### scenario=fairplay wrapped in a fat (arm64 + x86_64)")
    fat_blob, fat_layout = gen.build_fat("fairplay")
    fat_report = analyzer.analyze(fat_blob)
    print("  fat=%s, %d slices" % (fat_report["fat"],
                                  len(fat_report["architectures"])))
    for arch in fat_report["architectures"]:
        print("  - %s %s active=%s entry_readable=%s"
              % (arch["identity"]["cputype"], arch["identity"]["cpusubtype"],
                 arch["encryption"]["active"],
                 arch["entry"]["instructions_readable"]))

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "sample_report.json")
    with open(out, "w") as fh:
        json.dump(analyzer.analyze(gen.build_slice("fairplay")[0]), fh,
                  indent=2, sort_keys=True)
    print("\nmachine-readable report written to %s" % out)


if __name__ == "__main__":
    main()
