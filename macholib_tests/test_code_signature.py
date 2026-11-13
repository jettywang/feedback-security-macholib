"""
Tests for the read-only embedded code signature analyzer.

The samples are built at runtime with clang/codesign so the repository does
not need to ship binaries.  When the toolchain is unavailable the sample
builds are skipped; the pure-Python malformed-input tests still run.
"""

import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from macholib import code_signature
from macholib.code_signature import (CSMAGIC_BLOBWRAPPER,
                                     CSMAGIC_CODEDIRECTORY,
                                     CSMAGIC_EMBEDDED_SIGNATURE,
                                     CSSLOT_ALTERNATE_CODEDIRECTORIES,
                                     CSSLOT_CODEDIRECTORY,
                                     CSSLOT_SIGNATURESLOT, analyze_macho)
from macholib.mach_o import LC_CODE_SIGNATURE
from macholib.MachO import MachO

HELLO_C = b"""
#include <stdio.h>
int main(void) {
    printf("code signature analyzer sample\\n");
    return 0;
}
"""


def _toolchain_available():
    return (
        shutil.which("clang") is not None
        and shutil.which("codesign") is not None
        and shutil.which("lipo") is not None
        and sys.platform == "darwin"
    )


SKIP_WITHOUT_TOOLCHAIN = unittest.skipUnless(
    _toolchain_available(),
    "clang/codesign/lipo toolchain required for signed sample tests",
)


class SampleBuilder(object):
    def __init__(self):
        self.tmpdir = tempfile.mkdtemp(prefix="macholib-cs-test-")
        self.source = os.path.join(self.tmpdir, "hello.c")
        with open(self.source, "wb") as fp:
            fp.write(HELLO_C)

    def cleanup(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def build(self, name, archs, dual_digest=False, signed=True):
        path = os.path.join(self.tmpdir, name)
        cmd = ["clang"]
        for arch in archs:
            cmd.extend(["-arch", arch])
        cmd.extend(["-o", path, self.source])
        subprocess.check_call(cmd)
        if not signed:
            # Recent clang toolchains embed an ad-hoc signature by default;
            # strip it so the sample genuinely has no LC_CODE_SIGNATURE.
            subprocess.check_call(["codesign", "--remove-signature", path])
            return path
        sign = ["codesign", "--force", "-s", "-"]
        if dual_digest:
            sign.append("--digest-algorithm=sha1,sha256")
        sign.append(path)
        subprocess.check_call(sign)
        return path

    def fat(self, name, thin_paths):
        path = os.path.join(self.tmpdir, name)
        subprocess.check_call(["lipo", "-create"] + thin_paths + ["-output", path])
        return path


def signature_location(path, slice_index=0):
    macho = MachO(path)
    header = macho.headers[slice_index]
    for load, command, _data in header.commands:
        if load.cmd == LC_CODE_SIGNATURE:
            return (
                header.offset,
                int(command.dataoff),
                int(command.datasize),
            )
    raise AssertionError("no LC_CODE_SIGNATURE in sample")


def first_code_slot_offset(path):
    """Absolute file offset of the primary CD's first code slot digest."""
    slice_offset, sig_off, _sig_size = signature_location(path)
    with open(path, "rb") as fp:
        data = fp.read()
    superblob = data[slice_offset + sig_off:]
    count = struct.unpack(">I", superblob[8:12])[0]
    cd_blob_offset = None
    for index in range(count):
        pos = 12 + index * 8
        slot_type, blob_offset = struct.unpack(
            ">II", superblob[pos:pos + 8]
        )
        if slot_type == CSSLOT_CODEDIRECTORY:
            cd_blob_offset = blob_offset
            break
    hash_offset = struct.unpack(
        ">I", superblob[cd_blob_offset + 16:cd_blob_offset + 20]
    )[0]
    return slice_offset + sig_off + cd_blob_offset + hash_offset


def flip_byte(path, offset):
    with open(path, "r+b") as fp:
        fp.seek(offset)
        byte = fp.read(1)
        fp.seek(offset)
        fp.write(bytes([byte[0] ^ 0xFF]))


def _find_load_command_offset(path, slice_offset):
    """Absolute file offset of the LC_CODE_SIGNATURE load command."""
    with open(path, "rb") as fp:
        fp.seek(slice_offset)
        magic = struct.unpack(">I", fp.read(4))[0]
    little_endian = magic in (0xCEFAEDFE, 0xCFFAEDFE)
    is_64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
    endian = "<" if little_endian else ">"
    cursor = slice_offset + (32 if is_64 else 28)
    with open(path, "rb") as fp:
        while True:
            fp.seek(cursor)
            cmd, cmdsize = struct.unpack(endian + "II", fp.read(8))
            if cmd == LC_CODE_SIGNATURE:
                return cursor
            cursor += cmdsize


def copy_mutate(builder, source, name, offset):
    destination = os.path.join(builder.tmpdir, name)
    shutil.copyfile(source, destination)
    flip_byte(destination, offset)
    return destination


class SignedSampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _toolchain_available():
            raise cls.skipTest("no Mach-O toolchain")
        cls.builder = SampleBuilder()
        cls.thin = cls.builder.build("thin", ["arm64"])
        cls.dual = cls.builder.build(
            "dual", ["arm64"], dual_digest=True
        )
        arm64 = cls.builder.build("arm64", ["arm64"])
        x86 = cls.builder.build("x86_64", ["x86_64"])
        cls.fat = cls.builder.fat("fat", [x86, arm64])

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "builder"):
            cls.builder.cleanup()

    def test_clean_thin_sample_verifies(self):
        report = analyze_macho(self.thin)
        self.assertFalse(report.is_fat)
        self.assertEqual(len(report.slices), 1)
        self.assertTrue(report.has_any_signature)
        self.assertTrue(report.all_page_hashes_match)
        slc = report.slices[0]
        self.assertEqual(slc.errors, [])
        self.assertEqual(len(slc.code_directories), 1)
        cd = slc.code_directories[0]
        self.assertEqual(cd.slot_type, CSSLOT_CODEDIRECTORY)
        self.assertEqual(cd.hash_type_name, "sha256")
        self.assertEqual(cd.hash_size, 32)
        self.assertGreater(cd.page_size, 0)
        self.assertEqual(
            cd.expected_code_slots, cd.n_code_slots
        )
        self.assertEqual(cd.pages_checked, cd.n_code_slots)
        self.assertEqual(cd.page_mismatches, [])
        self.assertTrue(cd.page_hashes_match)
        self.assertTrue(cd.valid)
        self.assertEqual(len(cd.cdhash), 64)
        # The ad-hoc CMS wrapper is located but never verified.
        self.assertIsNotNone(slc.cms_blob)
        self.assertEqual(slc.cms_blob.magic, CSMAGIC_BLOBWRAPPER)
        self.assertFalse(slc.cms_verified)

    def test_superblob_sub_blob_ranges(self):
        report = analyze_macho(self.thin)
        slc = report.slices[0]
        self.assertGreaterEqual(len(slc.blobs), 3)
        end = slc.superblob_length
        for blob in slc.blobs:
            self.assertGreaterEqual(blob.offset, 12 + slc.superblob_count * 8)
            self.assertGreater(blob.length, 0)
            self.assertLessEqual(blob.offset + blob.length, end)
        magics = {blob.slot_type: blob.magic for blob in slc.blobs}
        self.assertEqual(magics[CSSLOT_CODEDIRECTORY], CSMAGIC_CODEDIRECTORY)
        self.assertEqual(magics[CSSLOT_SIGNATURESLOT], CSMAGIC_BLOBWRAPPER)

    def test_multiple_code_directories_reported_separately(self):
        report = analyze_macho(self.dual)
        slc = report.slices[0]
        cds = slc.code_directories
        self.assertEqual(len(cds), 2)
        slots = sorted(cd.slot_type for cd in cds)
        self.assertEqual(
            slots,
            [CSSLOT_CODEDIRECTORY, CSSLOT_ALTERNATE_CODEDIRECTORIES],
        )
        hash_types = sorted(cd.hash_type_name for cd in cds)
        self.assertEqual(hash_types, ["sha1", "sha256"])
        for cd in cds:
            self.assertIsNone(cd.structural_error)
            self.assertTrue(cd.slot_count_consistent)
            self.assertTrue(cd.page_hashes_match)
        # Each CodeDirectory keeps its own page mismatches.
        self.assertIsNot(cds[0].page_mismatches, cds[1].page_mismatches)
        self.assertTrue(report.all_page_hashes_match)

    def test_covered_page_mutation_is_detected(self):
        mutated = copy_mutate(self.builder, self.thin, "page_mut", 100)
        report = analyze_macho(mutated)
        slc = report.slices[0]
        self.assertEqual(slc.errors, [])
        cd = slc.code_directories[0]
        self.assertFalse(cd.page_hashes_match)
        self.assertFalse(slc.all_code_directories_match)
        self.assertEqual(cd.page_mismatches[0]["page"], 0)
        self.assertEqual(cd.page_mismatches[0]["file_offset"], 0)

    def test_signature_area_mutation_is_detected(self):
        slot_offset = first_code_slot_offset(self.thin)
        mutated = copy_mutate(
            self.builder, self.thin, "sig_mut", slot_offset
        )
        report = analyze_macho(mutated)
        slc = report.slices[0]
        # The blob still parses; the stored digest no longer matches the page.
        self.assertEqual(slc.errors, [])
        cd = slc.code_directories[0]
        self.assertFalse(cd.page_hashes_match)
        self.assertEqual(cd.page_mismatches[0]["page"], 0)

    def test_superblob_metadata_mutation_is_structural_error(self):
        slice_offset, sig_off, _size = signature_location(self.thin)
        # Corrupt the SuperBlob magic itself.
        mutated = copy_mutate(
            self.builder,
            self.thin,
            "magic_mut",
            slice_offset + sig_off,
        )
        report = analyze_macho(mutated)
        slc = report.slices[0]
        self.assertTrue(slc.errors)
        self.assertIn("magic", slc.errors[0])

    def test_uncovered_tail_mutation_is_not_detected(self):
        tail = os.path.join(self.builder.tmpdir, "tail_mut")
        with open(self.thin, "rb") as src, open(tail, "wb") as dst:
            dst.write(src.read())
            dst.write(b"extra bytes beyond every sealed range")
        report = analyze_macho(tail)
        slc = report.slices[0]
        self.assertTrue(slc.all_code_directories_match)
        self.assertTrue(
            any(region["kind"] == "tail" for region in slc.uncovered_regions)
        )

    def test_fat_slices_use_their_own_offsets(self):
        report = analyze_macho(self.fat)
        self.assertTrue(report.is_fat)
        self.assertEqual(len(report.slices), 2)
        slice_offsets = [slc.slice_offset for slc in report.slices]
        self.assertEqual(len(set(slice_offsets)), 2)
        # In a fat file every slice starts at a non-zero, page-aligned offset
        # and all signature offsets are relative to that slice start.
        self.assertTrue(all(offset > 0 for offset in slice_offsets))
        for slc in report.slices:
            self.assertTrue(slc.all_code_directories_match)
            self.assertEqual(slc.errors, [])
            self.assertLessEqual(
                slc.signature_offset + slc.signature_length,
                slc.slice_size,
            )

    def test_fat_mutation_isolated_to_one_slice(self):
        slice_offset, sig_off, _size = signature_location(self.fat, 0)
        mutated = copy_mutate(
            self.builder, self.fat, "fat_mut", slice_offset + 100
        )
        report = analyze_macho(mutated)
        self.assertFalse(report.slices[0].all_code_directories_match)
        self.assertTrue(report.slices[1].all_code_directories_match)

    def test_fat_signature_mutation_isolated_to_one_slice(self):
        slice_offset, sig_off, _size = signature_location(self.fat, 0)
        mutated = copy_mutate(
            self.builder,
            self.fat,
            "fat_sig_mut",
            slice_offset + sig_off + 40,
        )
        report = analyze_macho(mutated)
        self.assertFalse(report.slices[0].structurally_valid)
        self.assertTrue(report.slices[1].all_code_directories_match)

    def test_cms_is_reported_but_not_verified(self):
        report = analyze_macho(self.thin)
        slc = report.slices[0]
        self.assertIsNotNone(slc.cms_blob)
        self.assertTrue(slc.cms_blob.is_cms_signature)
        self.assertFalse(slc.cms_verified)
        text = code_signature.format_report(report)
        self.assertIn("NOT verified", text)
        self.assertIn("trust", text)


class UnsignedAndMalformedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _toolchain_available():
            raise cls.skipTest("no Mach-O toolchain")
        cls.builder = SampleBuilder()
        cls.signed = cls.builder.build("signed", ["arm64"])
        cls.unsigned = cls.builder.build(
            "unsigned", ["arm64"], signed=False
        )

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "builder"):
            cls.builder.cleanup()

    def _copy(self, source, name):
        destination = os.path.join(self.builder.tmpdir, name)
        shutil.copyfile(source, destination)
        return destination

    def test_unsigned_macho_reports_no_signature(self):
        report = analyze_macho(self.unsigned)
        self.assertFalse(report.has_any_signature)
        self.assertFalse(report.all_page_hashes_match)
        slc = report.slices[0]
        self.assertFalse(slc.has_signature)
        self.assertEqual(slc.code_directories, [])
        self.assertEqual(slc.blobs, [])

    def test_truncated_signature_area_is_error(self):
        # Rewrite LC_CODE_SIGNATURE.datasize to a value smaller than the
        # SuperBlob header; the analyzer must flag it rather than crash.
        path = self._copy(self.signed, "truncated")
        slice_offset, _sig_off, original_size = signature_location(path)
        lc_offset = _find_load_command_offset(path, slice_offset)
        with open(path, "rb") as fp:
            fp.seek(slice_offset)
            magic = struct.unpack(">I", fp.read(4))[0]
        endian = "<" if magic in (0xCEFAEDFE, 0xCFFAEDFE) else ">"
        with open(path, "r+b") as fp:
            fp.seek(lc_offset + 8 + 4)  # past cmd/cmdsize and dataoff
            fp.write(struct.pack(endian + "I", 4))
        self.assertGreater(original_size, 4)
        report = analyze_macho(path)
        slc = report.slices[0]
        self.assertTrue(slc.errors)

    def test_corrupt_superblob_length_is_error(self):
        path = self._copy(self.signed, "bad_length")
        slice_offset, sig_off, _size = signature_location(path)
        with open(path, "r+b") as fp:
            # SuperBlob.length lives 4 bytes into the signature area.
            fp.seek(slice_offset + sig_off + 4)
            fp.write(struct.pack(">I", 0xFFFFFFFF))
        report = analyze_macho(path)
        slc = report.slices[0]
        self.assertTrue(slc.errors)
        self.assertIn("length", slc.errors[0])

    def test_corrupt_blob_index_offset_is_error(self):
        path = self._copy(self.signed, "bad_index")
        slice_offset, sig_off, _size = signature_location(path)
        with open(path, "r+b") as fp:
            # First CS_BlobIndex entry starts at SuperBlob offset 12; its
            # blob offset is the second uint32.
            fp.seek(slice_offset + sig_off + 12 + 4)
            fp.write(struct.pack(">I", 0xFFFFFFF0))
        report = analyze_macho(path)
        slc = report.slices[0]
        self.assertTrue(slc.errors)
        self.assertIn("out of range", slc.errors[0])

    def test_corrupt_code_limit_is_structural_error(self):
        path = self._copy(self.signed, "bad_codelimit")
        slice_offset, sig_off, _size = signature_location(path)
        with open(path, "rb") as fp:
            data = fp.read()
        superblob = data[slice_offset + sig_off:]
        count = struct.unpack(">I", superblob[8:12])[0]
        cd_blob_offset = None
        for index in range(count):
            slot_type, blob_offset = struct.unpack(
                ">II", superblob[12 + index * 8:20 + index * 8]
            )
            if slot_type == CSSLOT_CODEDIRECTORY:
                cd_blob_offset = blob_offset
                break
        # codeLimit is the uint32 at CodeDirectory offset 32.
        target = (
            slice_offset + sig_off + cd_blob_offset + 32
        )
        with open(path, "r+b") as fp:
            fp.seek(target)
            fp.write(struct.pack(">I", 0x7FFFFFFF))
        report = analyze_macho(path)
        slc = report.slices[0]
        cd = slc.code_directories[0]
        self.assertIsNotNone(cd.structural_error)
        self.assertIn("codeLimit", cd.structural_error)

    def test_constants_match_kernel_header_values(self):
        self.assertEqual(CSMAGIC_EMBEDDED_SIGNATURE, 0xFADE0CC0)
        self.assertEqual(CSMAGIC_CODEDIRECTORY, 0xFADE0C02)
        self.assertEqual(CSMAGIC_BLOBWRAPPER, 0xFADE0B01)
        self.assertEqual(CSSLOT_SIGNATURESLOT, 0x10000)
        self.assertEqual(CSSLOT_ALTERNATE_CODEDIRECTORIES, 0x1000)


def _build_synthetic_signed_macho(hash_type, hash_size, page_log2=12):
    """
    Construct a minimal little-endian 64-bit Mach-O whose only load command is
    LC_CODE_SIGNATURE, plus a hand-built SuperBlob with one CodeDirectory.

    This lets the tests exercise hash algorithms that the host codesign tool
    does not emit (notably CS_HASHTYPE_SHA256_TRUNCATED) without needing the
    platform toolchain.
    """
    page_size = 1 << page_log2
    mach_header = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,  # MH_MAGIC_64 (little endian)
        0x100000C,  # CPU_TYPE_ARM64
        0,
        2,  # MH_EXECUTE
        1,  # ncmds
        16,  # sizeofcmds
        0,
        0,
    )
    # The sealed region spans one whole page: the Mach-O header, the load
    # command, and the code content, padded out to the page size.
    content = b"SYNTHETIC-MACHO-CONTENT-PAGE-ONE"
    padding = page_size - len(mach_header) - 16 - len(content)
    code_limit = page_size

    # Build the CodeDirectory to match the SDK offsets exactly:
    # uint32 magic, length, version, flags (offsets 0..15);
    # uint32 hashOffset, identOffset, nSpecialSlots, nCodeSlots, codeLimit
    # (offsets 16..35); then uint8 hashSize/hashType/platform/pageSize (36..39)
    # and uint32 spare2 (40..43).
    placeholder_cd = struct.pack(
        ">IIII",
        CSMAGIC_CODEDIRECTORY,
        0,  # length, patched below
        0x20100,  # version: fixture only carries the 44-byte base header
        0,  # flags
    ) + struct.pack(
        ">IIIII",
        44,  # hashOffset (no identifier, no special slots)
        0,  # identOffset
        0,  # nSpecialSlots
        1,  # nCodeSlots
        code_limit,  # codeLimit
    ) + struct.pack(
        ">BBBB", hash_size, hash_type, 0, page_log2
    ) + struct.pack(">I", 0)  # spare2
    assert len(placeholder_cd) == 44
    assert struct.unpack(">I", placeholder_cd[16:20])[0] == 44
    assert struct.unpack(">I", placeholder_cd[32:36])[0] == code_limit
    algorithm = "sha1" if hash_type == 1 else "sha256"
    if hash_type == 4:
        algorithm = "sha384"

    def make_cd(page_digest):
        cd = placeholder_cd + page_digest
        # Replace the 4-byte length field (bytes 4..7) without changing the
        # total size: magic, new length, then everything from offset 8.
        return cd[:4] + struct.pack(">I", len(cd)) + cd[8:]

    # The CodeDirectory size is fixed by its header plus the one page digest;
    # the digest content does not affect its length.
    cd_blob = make_cd(
        hashlib.new(algorithm, b"").digest()[:hash_size]
    )
    cd_length = len(cd_blob)
    cd_blob_offset = 20  # 12-byte SuperBlob header + one 8-byte index
    superblob_length = cd_blob_offset + cd_length

    lc = struct.pack(
        "<IIII",
        LC_CODE_SIGNATURE,
        16,
        code_limit,  # dataoff: signature starts on the page boundary
        superblob_length,
    )
    sealed_region = mach_header + lc + content + b"\x00" * padding
    assert len(sealed_region) == code_limit

    # Recompute the digest over the final, unchanging sealed bytes.
    page_digest = hashlib.new(
        algorithm, sealed_region
    ).digest()[:hash_size]
    cd_blob = make_cd(page_digest)
    assert len(cd_blob) == cd_length
    superblob = (
        struct.pack(">III", CSMAGIC_EMBEDDED_SIGNATURE, 0, 1)
        + struct.pack(">II", CSSLOT_CODEDIRECTORY, cd_blob_offset)
        + cd_blob
    )
    # Patch only the length field (bytes 4..7); the count at bytes 8..11
    # must remain 1.
    superblob = (
        superblob[:4]
        + struct.pack(">I", superblob_length)
        + superblob[8:]
    )
    return sealed_region + superblob


class SyntheticSignatureTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="macholib-cs-synth-")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write(self, name, data):
        path = os.path.join(self.tmpdir, name)
        with open(path, "wb") as fp:
            fp.write(data)
        return path

    def test_truncated_sha256_code_directory(self):
        # CS_HASHTYPE_SHA256_TRUNCATED = 3, 20-byte truncated digests.
        data = _build_synthetic_signed_macho(hash_type=3, hash_size=20)
        report = analyze_macho(self._write("trunc", data))
        slc = report.slices[0]
        self.assertEqual(slc.errors, [])
        cd = slc.code_directories[0]
        self.assertEqual(cd.hash_type_name, "sha256_truncated")
        self.assertEqual(cd.hash_size, 20)
        self.assertTrue(cd.slot_count_consistent)
        self.assertTrue(cd.page_hashes_match)
        self.assertTrue(cd.valid)

    def test_synthetic_sha1_and_sha384(self):
        for hash_type, hash_size, name in (
            (1, 20, "sha1"),
            (4, 48, "sha384"),
        ):
            data = _build_synthetic_signed_macho(hash_type, hash_size)
            report = analyze_macho(self._write(name, data))
            cd = report.slices[0].code_directories[0]
            self.assertEqual(cd.hash_type_name, name)
            self.assertTrue(cd.page_hashes_match, name)

    def test_synthetic_page_tamper_detected(self):
        data = bytearray(
            _build_synthetic_signed_macho(hash_type=2, hash_size=32)
        )
        # Flip a byte inside the sealed page (after the 32-byte header and
        # 16-byte load command).
        data[48 + 5] ^= 0xFF
        report = analyze_macho(self._write("tampered", bytes(data)))
        cd = report.slices[0].code_directories[0]
        self.assertFalse(cd.page_hashes_match)
        self.assertEqual(cd.page_mismatches[0]["page"], 0)

    def test_synthetic_tail_not_covered(self):
        data = _build_synthetic_signed_macho(hash_type=2, hash_size=32)
        report = analyze_macho(self._write("clean", data))
        slc = report.slices[0]
        self.assertTrue(slc.all_code_directories_match)
        # Appending beyond the signature leaves every sealed digest intact.
        appended = self._write("appended", data + b"tail-bytes")
        report2 = analyze_macho(appended)
        self.assertTrue(report2.slices[0].all_code_directories_match)

    def test_unsupported_hash_type_is_structural_error(self):
        # Build a valid-looking blob but claim an unknown hash type (99).
        data = bytearray(
            _build_synthetic_signed_macho(hash_type=2, hash_size=32)
        )
        # The signature starts at dataoff (the page boundary); the sole CD
        # blob begins 20 bytes into the SuperBlob and hashType is CD byte 37.
        sig_off = struct.unpack("<I", data[40:44])[0]
        cd_blob_offset = 20
        data[sig_off + cd_blob_offset + 37] = 99
        report = analyze_macho(self._write("badhash", bytes(data)))
        cd = report.slices[0].code_directories[0]
        self.assertIsNotNone(cd.structural_error)
        self.assertIn("unsupported hash type", cd.structural_error)


if __name__ == "__main__":
    unittest.main()
