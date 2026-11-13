#!/usr/bin/env python3
"""
Demonstrate what an embedded CodeDirectory digest does and does not protect.

The script builds a tiny signed Mach-O (or reuses one passed on the command
line) and mutates three distinct byte ranges:

1. a code page covered by a CodeDirectory page digest;
2. a stored digest inside the embedded signature (SuperBlob) area;
3. bytes appended after the signature, which no page digest covers.

For every mutation it prints whether the change is detected and, crucially,
why.  A digest match is never presented as certificate trust or permission to
execute: the CMS (PKCS#7) signature is reported as not verified.

Usage::

    python examples/integrity_demo.py [path-to-signed-macho]

With no argument the script compiles and ad-hoc signs a sample itself, which
requires ``clang`` and ``codesign`` (available on macOS).
"""

from __future__ import print_function

import os
import shutil
import struct
import subprocess
import sys
import tempfile

from macholib.code_signature import (CSMAGIC_EMBEDDED_SIGNATURE, analyze_macho,
                                     format_report)
from macholib.mach_o import LC_CODE_SIGNATURE
from macholib.MachO import MachO

HELLO_C = b"""
#include <stdio.h>
int main(void) {
    printf("integrity demo sample\\n");
    return 0;
}
"""


def build_sample(workdir):
    source = os.path.join(workdir, "hello.c")
    binary = os.path.join(workdir, "hello")
    with open(source, "wb") as fp:
        fp.write(HELLO_C)
    subprocess.check_call(["clang", "-arch", "arm64", "-o", binary, source])
    # An ad-hoc signature embeds a CodeDirectory with no usable CMS identity.
    subprocess.check_call(["codesign", "--force", "-s", "-", binary])
    return binary


def signature_layout(path):
    """Return (slice_offset, sig_dataoff, sig_datasize) for every slice."""
    macho = MachO(path)
    layout = []
    for header in macho.headers:
        for load, command, _data in header.commands:
            if load.cmd == LC_CODE_SIGNATURE:
                layout.append(
                    (
                        header.offset,
                        int(command.dataoff),
                        int(command.datasize),
                    )
                )
    return layout


def first_code_slot_file_offset(path):
    """
    Locate the first ordinary code slot of the primary CodeDirectory as an
    absolute file offset, so the demo can mutate a *stored* digest.
    """
    slice_offset, sig_off, _sig_size = signature_layout(path)[0]
    with open(path, "rb") as fp:
        data = fp.read()
    superblob = data[slice_offset + sig_off:]
    if struct.unpack(">I", superblob[:4])[0] != CSMAGIC_EMBEDDED_SIGNATURE:
        raise ValueError("not an embedded signature SuperBlob")
    count = struct.unpack(">I", superblob[8:12])[0]
    cd_blob_offset = None
    for index in range(count):
        pos = 12 + index * 8
        slot_type, blob_offset = struct.unpack(
            ">II", superblob[pos:pos + 8]
        )
        if slot_type == 0:
            cd_blob_offset = blob_offset
            break
    if cd_blob_offset is None:
        raise ValueError("primary CodeDirectory not found")
    hash_offset = struct.unpack(
        ">I", superblob[cd_blob_offset + 16:cd_blob_offset + 20]
    )[0]
    return slice_offset + sig_off + cd_blob_offset + hash_offset


def summarize(path, label):
    report = analyze_macho(path)
    print("\n--- %s ---" % label)
    for slice_report in report.slices:
        if not slice_report.has_signature:
            print("  slice %d: no signature" % slice_report.slice_index)
            continue
        if slice_report.errors:
            print(
                "  slice %d: signature structure unparseable: %s"
                % (slice_report.slice_index, "; ".join(slice_report.errors))
            )
        for cd in slice_report.code_directories:
            if cd.structural_error:
                print(
                    "  slice %d CodeDirectory slot 0x%x (%s): structural "
                    "error: %s"
                    % (
                        slice_report.slice_index,
                        cd.slot_type,
                        cd.hash_type_name,
                        cd.structural_error,
                    )
                )
                continue
            mismatched_pages = [m["page"] for m in cd.page_mismatches]
            print(
                "  slice %d CodeDirectory slot 0x%x (%s): %d page(s) "
                "checked, digest match=%s, mismatched pages=%s"
                % (
                    slice_report.slice_index,
                    cd.slot_type,
                    cd.hash_type_name,
                    cd.pages_checked,
                    cd.page_hashes_match,
                    mismatched_pages,
                )
            )
        if slice_report.cms_blob is not None:
            print(
                "  slice %d: CMS signature present but NOT verified (no "
                "trust or execution decision)" % slice_report.slice_index
            )
        for region in slice_report.uncovered_regions:
            print(
                "  slice %d: uncovered %s of %d byte(s) at slice offset %d"
                % (
                    slice_report.slice_index,
                    region["kind"],
                    region["length"],
                    region["offset"],
                )
            )
    return report


def mutate_copy(source, destination, mutate):
    shutil.copyfile(source, destination)
    with open(destination, "r+b") as fp:
        mutate(fp)


def main(argv):
    workdir = tempfile.mkdtemp(prefix="macho-integrity-")
    try:
        if len(argv) > 1:
            original = argv[1]
            if not os.path.exists(original):
                print("sample not found: %s" % original, file=sys.stderr)
                return 1
        else:
            original = build_sample(workdir)
        print("using sample: %s" % original)
        print(format_report(analyze_macho(original)))

        covered_path = os.path.join(workdir, "mut_covered")
        signature_path = os.path.join(workdir, "mut_signature")
        tail_path = os.path.join(workdir, "mut_tail")

        # Pick a byte inside the first slice's first sealed page.  In a fat
        # file the slice starts at a non-zero offset, so a plain offset of 100
        # would land in the fat header and be invisible to every slice.
        first_slice_offset, _sig_off, _sig_size = signature_layout(
            original
        )[0]
        covered_offset = first_slice_offset + 100

        # 1. Flip a byte inside the first sealed code page.
        def mutate_covered(fp):
            fp.seek(covered_offset)
            byte = fp.read(1)
            fp.seek(covered_offset)
            fp.write(bytes([byte[0] ^ 0xFF]))

        # 2. Flip one byte of a stored page digest inside the SuperBlob.
        slot_offset = first_code_slot_file_offset(original)

        def mutate_signature(fp):
            fp.seek(slot_offset)
            byte = fp.read(1)
            fp.seek(slot_offset)
            fp.write(bytes([byte[0] ^ 0xFF]))

        # 3. Append bytes that lie beyond every sealed range.
        def mutate_tail(fp):
            fp.seek(0, os.SEEK_END)
            fp.write(b"UNSEALED-TAIL-BYTES")

        mutate_copy(original, covered_path, mutate_covered)
        mutate_copy(original, signature_path, mutate_signature)
        mutate_copy(original, tail_path, mutate_tail)

        summarize(original, "baseline (unmodified)")
        summarize(
            covered_path,
            "mutation 1: covered code page byte at file offset %d"
            % covered_offset,
        )
        summarize(
            signature_path,
            "mutation 2: stored digest byte at file offset %d "
            "(inside signature area)" % slot_offset,
        )
        summarize(
            tail_path,
            "mutation 3: bytes appended after the signature (uncovered tail)",
        )

        print(
            "\nInterpretation:\n"
            "  mutation 1 changes a sealed page, so its recomputed digest no "
            "longer\n"
            "    matches the stored digest and is detected.\n"
            "  mutation 2 changes a stored digest, so the unchanged page no "
            "longer\n"
            "    matches it and is detected (corrupting SuperBlob metadata "
            "instead\n"
            "    yields a structural error).\n"
            "  mutation 3 is outside codeLimit and the signature area, so no "
            "page\n"
            "    digest covers it and the sealed content still verifies.\n"
            "  None of these outcomes proves certificate trust or execution "
            "approval;\n"
            "  CMS verification is intentionally not performed."
        )
        return 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
