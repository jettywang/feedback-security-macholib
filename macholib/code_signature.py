"""
Read-only analysis of the embedded code signature of Mach-O files.

This module answers one narrow question on behalf of an integrity checker:
which bytes of a Mach-O file are covered by the digest stored in an embedded
CodeDirectory, and do the bytes currently on disk still match that digest?

The parsing is deliberately read-only and uses :mod:`macholib` to locate the
``LC_CODE_SIGNATURE`` load command.  The SuperBlob (``CS_SuperBlob``) and the
CodeDirectory blobs (``CS_CodeDirectory``) it points at are then parsed from
raw bytes using the layout documented in the macOS kernel header
``kern/cs_blobs.h``.

Trust boundary
--------------
A matching page digest only proves that the sealed part of the file was not
modified after the CodeDirectory was created.  It does **not** establish that
the signature is trustworthy, that any certificate chain is valid, or that the
operating system will allow the binary to execute.  The CMS (PKCS#7) signature
blob is located and reported but never verified here; CMS verification is
explicitly left to a component that can evaluate certificate trust.
"""

import hashlib
import struct

from macholib.mach_o import LC_CODE_SIGNATURE
from macholib.MachO import MachO

# CS_CodeDirectory / CS_SuperBlob magic numbers (kern/cs_blobs.h).
CSMAGIC_REQUIREMENT = 0xFADE0C00
CSMAGIC_REQUIREMENTS = 0xFADE0C01
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_SIGNATURE_OLD = 0xFADE0B02
CSMAGIC_DETACHED_SIGNATURE = 0xFADE0CC1
CSMAGIC_BLOBWRAPPER = 0xFADE0B01
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172
CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT = 0xFADE8181

# SuperBlob slot indices.
CSSLOT_CODEDIRECTORY = 0
CSSLOT_INFOSLOT = 1
CSSLOT_REQUIREMENTS = 2
CSSLOT_RESOURCEDIR = 3
CSSLOT_APPLICATION = 4
CSSLOT_ENTITLEMENTS = 5
CSSLOT_DER_ENTITLEMENTS = 7
CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000
CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT = 0x1005
CSSLOT_SIGNATURESLOT = 0x10000
CSSLOT_IDENTIFICATIONSLOT = 0x10001
CSSLOT_TICKETSLOT = 0x10002

# Digest algorithms referenced by CS_CodeDirectory.hashType.  Each entry maps
# the type id to (display name, algorithm used with hashlib, digest size).
# SHA-256 truncated stores only the first 20 bytes of a full SHA-256 digest.
CS_HASHTYPE_SHA1 = 1
CS_HASHTYPE_SHA256 = 2
CS_HASHTYPE_SHA256_TRUNCATED = 3
CS_HASHTYPE_SHA384 = 4

HASH_TYPES = {
    CS_HASHTYPE_SHA1: ("sha1", "sha1", 20),
    CS_HASHTYPE_SHA256: ("sha256", "sha256", 32),
    CS_HASHTYPE_SHA256_TRUNCATED: ("sha256_truncated", "sha256", 20),
    CS_HASHTYPE_SHA384: ("sha384", "sha384", 48),
}

# CS_CodeDirectory flags.
CS_ADHOC = 0x00000002

# Field offsets inside a CS_CodeDirectory (all multi-byte fields are big endian
# and naturally aligned; see the __CodeDirectory typedef in cs_blobs.h).
CD_MAGIC = 0
CD_LENGTH = 4
CD_VERSION = 8
CD_FLAGS = 12
CD_HASHOFFSET = 16
CD_IDENTOFFSET = 20
CD_NSPECIALSLOTS = 24
CD_NCODESLOTS = 28
CD_CODELIMIT = 32
CD_HASHSIZE = 36
CD_HASHTYPE = 37
CD_PLATFORM = 38
CD_PAGESIZE = 39
# Version 0x20300 and newer.
CD_CODELIMIT64 = 48

SUPERBLOB_HEADER_SIZE = 12
BLOB_INDEX_SIZE = 8
BLOB_HEADER_SIZE = 8


class CodeSignatureError(ValueError):
    """Raised when an embedded signature is malformed or out of range."""


def _u32(buf, offset):
    return struct.unpack(">I", buf[offset:offset + 4])[0]


def _slot_name(slot_type):
    names = {
        CSSLOT_CODEDIRECTORY: "code directory",
        CSSLOT_INFOSLOT: "Info.plist",
        CSSLOT_REQUIREMENTS: "requirements",
        CSSLOT_RESOURCEDIR: "resource directory",
        CSSLOT_APPLICATION: "application",
        CSSLOT_ENTITLEMENTS: "entitlements",
        CSSLOT_DER_ENTITLEMENTS: "DER entitlements",
        CSSLOT_SIGNATURESLOT: "CMS signature",
        CSSLOT_IDENTIFICATIONSLOT: "identification",
        CSSLOT_TICKETSLOT: "notarization ticket",
    }
    if slot_type in names:
        return names[slot_type]
    if CSSLOT_ALTERNATE_CODEDIRECTORIES <= slot_type < (
        CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT
    ):
        return "alternate code directory %d" % (
            slot_type - CSSLOT_ALTERNATE_CODEDIRECTORIES
        )
    return "unknown slot 0x%x" % slot_type


def _is_code_directory_slot(slot_type):
    if slot_type == CSSLOT_CODEDIRECTORY:
        return True
    return (
        CSSLOT_ALTERNATE_CODEDIRECTORIES
        <= slot_type
        < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT
    )


def _effective_code_limit(cd, blob_length):
    """
    Return codeLimit, widened to codeLimit64 for version 0x20300+ blobs.

    A v20300 CodeDirectory extends the fixed header with spare3 and the
    64-bit codeLimit, so the codeLimit64 field only exists when the blob is
    actually long enough to contain it.  Merely having trailing hash bytes is
    not sufficient.
    """
    code_limit = _u32(cd, CD_CODELIMIT)
    version = _u32(cd, CD_VERSION)
    if (
        version >= 0x20300
        and blob_length >= CD_CODELIMIT64 + 8
    ):
        high = struct.unpack(">Q", cd[CD_CODELIMIT64:CD_CODELIMIT64 + 8])[0]
        if high:
            return (high << 32) | code_limit
    return code_limit


def _read_c_string(buf, offset):
    if offset <= 0 or offset >= len(buf):
        return None
    end = buf.find(b"\x00", offset)
    if end < 0:
        end = len(buf)
    try:
        return buf[offset:end].decode("utf-8")
    except UnicodeDecodeError:
        return buf[offset:end].decode("utf-8", "replace")


class BlobInfo(object):
    """A single sub-blob referenced by a SuperBlob index entry."""

    def __init__(self, slot_type, offset, length, magic):
        self.slot_type = slot_type
        self.slot_name = _slot_name(slot_type)
        self.offset = offset
        self.length = length
        self.magic = magic
        self.is_code_directory = magic == CSMAGIC_CODEDIRECTORY
        self.is_cms_signature = slot_type == CSSLOT_SIGNATURESLOT

    def __repr__(self):
        return (
            "<BlobInfo slot=0x%x magic=0x%08x offset=%d length=%d>"
            % (self.slot_type, self.magic, self.offset, self.length)
        )


class CodeDirectoryReport(object):
    """
    Parsed and verified state of one CodeDirectory blob.

    A SuperBlob may contain several CodeDirectories (a primary one plus
    alternate CodeDirectories for other digest algorithms); each one gets its
    own report so that results are never conflated.
    """

    def __init__(self, slot_type, blob_offset):
        self.slot_type = slot_type
        self.slot_name = _slot_name(slot_type)
        self.blob_offset = blob_offset
        self.blob_length = None
        self.version = None
        self.flags = None
        self.identifier = None
        self.hash_type = None
        self.hash_type_name = None
        self.hash_size = None
        self.page_size = None
        self.code_limit = None
        self.n_code_slots = None
        self.n_special_slots = None
        self.hash_offset = None
        self.code_slots_offset = None
        self.cdhash = None
        self.structural_error = None
        self.expected_code_slots = None
        self.slot_count_consistent = None
        self.page_mismatches = []
        self.pages_checked = 0
        self.page_hashes_match = None

    @property
    def is_adhoc(self):
        return self.flags is not None and bool(self.flags & CS_ADHOC)

    @property
    def valid(self):
        return (
            self.structural_error is None
            and self.slot_count_consistent
            and not self.page_mismatches
        )

    def __repr__(self):
        return (
            "<CodeDirectoryReport slot=0x%x %s hash=%s valid=%s>"
            % (
                self.slot_type,
                self.hash_type_name,
                self.identifier,
                self.valid,
            )
        )


class SliceReport(object):
    """Signature analysis for one architecture slice of a Mach-O file."""

    def __init__(self, slice_index, cpu_type, slice_offset, slice_size):
        self.slice_index = slice_index
        self.cpu_type = cpu_type
        self.slice_offset = slice_offset
        self.slice_size = slice_size
        self.has_signature_load_command = False
        self.signature_offset = None
        self.signature_length = None
        self.superblob_length = None
        self.superblob_count = None
        self.blobs = []
        self.code_directories = []
        self.cms_blob = None
        self.cms_verified = False
        self.errors = []
        # Bytes inside the slice but outside the sealed code range.
        self.uncovered_regions = []

    @property
    def has_signature(self):
        return self.has_signature_load_command

    @property
    def structurally_valid(self):
        return not self.errors

    @property
    def all_code_directories_match(self):
        if not self.code_directories:
            return False
        return all(cd.valid for cd in self.code_directories)

    def __repr__(self):
        return (
            "<SliceReport slice=%d cputype=0x%x code_directories=%d valid=%s>"
            % (
                self.slice_index,
                self.cpu_type,
                len(self.code_directories),
                self.all_code_directories_match,
            )
        )


class IntegrityReport(object):
    """Aggregate report for every slice (one slice for thin files, many for fat)."""

    def __init__(self, path, is_fat):
        self.path = path
        self.is_fat = is_fat
        self.slices = []

    @property
    def has_any_signature(self):
        return any(s.has_signature for s in self.slices)

    @property
    def all_page_hashes_match(self):
        if not self.has_any_signature:
            return False
        return all(s.all_code_directories_match for s in self.slices)

    def __repr__(self):
        return "<IntegrityReport %r fat=%s slices=%d>" % (
            self.path,
            self.is_fat,
            len(self.slices),
        )


def _analyze_code_directory(superblob, blob, slice_data, digest_cache):
    report = CodeDirectoryReport(blob.slot_type, blob.offset)
    report.blob_length = blob.length
    cd = superblob[blob.offset:blob.offset + blob.length]
    try:
        report.version = _u32(cd, CD_VERSION)
        report.flags = _u32(cd, CD_FLAGS)
        report.hash_offset = _u32(cd, CD_HASHOFFSET)
        report.n_special_slots = _u32(cd, CD_NSPECIALSLOTS)
        report.n_code_slots = _u32(cd, CD_NCODESLOTS)
        report.code_limit = _effective_code_limit(cd, blob.length)
        report.hash_size = cd[CD_HASHSIZE]
        report.hash_type = cd[CD_HASHTYPE]
        report.page_log2 = cd[CD_PAGESIZE]
        report.identifier = _read_c_string(cd, _u32(cd, CD_IDENTOFFSET))
    except struct.error as exc:
        report.structural_error = "truncated CodeDirectory header: %s" % exc
        return report

    if report.hash_type not in HASH_TYPES:
        report.structural_error = (
            "unsupported hash type %d (known types: %s)"
            % (report.hash_type, sorted(HASH_TYPES))
        )
        return report
    hash_name, algorithm_name, expected_hash_size = HASH_TYPES[
        report.hash_type
    ]
    report.hash_type_name = hash_name
    if report.hash_size != expected_hash_size:
        report.structural_error = (
            "hash size %d does not match hash type %s (expected %d bytes)"
            % (report.hash_size, hash_name, expected_hash_size)
        )
        return report

    # pageSize 0 means the whole codeLimit is sealed as a single page.
    if report.page_log2 == 0:
        report.page_size = report.code_limit
    else:
        report.page_size = 1 << report.page_log2

    # Special slots use negative indices and occupy the nSpecialSlots entries
    # immediately before hashOffset; the ordinary code slots start at
    # hashOffset and run for nCodeSlots entries.
    report.code_slots_offset = report.hash_offset
    special_area_start = (
        report.hash_offset - report.n_special_slots * report.hash_size
    )
    code_area_end = (
        report.hash_offset + report.n_code_slots * report.hash_size
    )
    if report.hash_offset < 0 or special_area_start < 0:
        report.structural_error = (
            "hashOffset %d cannot fit %d special slot(s) of %d bytes"
            % (
                report.hash_offset,
                report.n_special_slots,
                report.hash_size,
            )
        )
        return report
    if code_area_end > blob.length:
        report.structural_error = (
            "code hash area (offset %d, %d slot(s) of %d bytes) overruns "
            "CodeDirectory of %d bytes"
            % (
                report.hash_offset,
                report.n_code_slots,
                report.hash_size,
                blob.length,
            )
        )
        return report
    if report.code_limit > len(slice_data):
        report.structural_error = (
            "codeLimit %d exceeds slice size %d"
            % (report.code_limit, len(slice_data))
        )
        return report

    expected_slots = 0
    if report.page_size > 0:
        expected_slots = (
            report.code_limit + report.page_size - 1
        ) // report.page_size
    report.expected_code_slots = expected_slots
    report.slot_count_consistent = expected_slots == report.n_code_slots
    if not report.slot_count_consistent:
        report.structural_error = (
            "code slot count %d does not match codeLimit %d at page size %d "
            "(expected %d slots)"
            % (
                report.n_code_slots,
                report.code_limit,
                report.page_size,
                expected_slots,
            )
        )
        return report

    if algorithm_name not in digest_cache:
        digest_cache[algorithm_name] = hashlib.new(algorithm_name)
    digest = digest_cache[algorithm_name]

    for index in range(report.n_code_slots):
        start = index * report.page_size
        end = min(start + report.page_size, report.code_limit)
        page = slice_data[start:end]
        actual = digest.copy()
        actual.update(page)
        # Truncated variants store a prefix of the full digest.
        actual_digest = actual.digest()[: report.hash_size]
        slot_start = report.code_slots_offset + index * report.hash_size
        stored = cd[slot_start:slot_start + report.hash_size]
        report.pages_checked += 1
        if actual_digest != stored:
            report.page_mismatches.append(
                {
                    "page": index,
                    "file_offset": start,
                    "length": len(page),
                    "stored": stored,
                    "actual": actual_digest,
                }
            )
    report.page_hashes_match = not report.page_mismatches

    # The CDHash seals the CodeDirectory itself; it is useful for correlation
    # with tooling output but is not a trust decision.
    cd_digest = hashlib.sha256()
    cd_digest.update(cd[:blob.length])
    report.cdhash = cd_digest.hexdigest()
    return report


def _parse_superblob(signature_data, slice_data, slice_report):
    if len(signature_data) < SUPERBLOB_HEADER_SIZE:
        raise CodeSignatureError(
            "signature area of %d bytes is too small for a SuperBlob header"
            % len(signature_data)
        )
    magic = _u32(signature_data, 0)
    if magic not in (CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_EMBEDDED_SIGNATURE_OLD):
        raise CodeSignatureError(
            "bad SuperBlob magic 0x%08x (expected 0x%08x)"
            % (magic, CSMAGIC_EMBEDDED_SIGNATURE)
        )
    superblob_length = _u32(signature_data, 4)
    count = _u32(signature_data, 8)
    slice_report.superblob_length = superblob_length
    slice_report.superblob_count = count

    if superblob_length > len(signature_data):
        raise CodeSignatureError(
            "SuperBlob length %d exceeds LC_CODE_SIGNATURE data size %d"
            % (superblob_length, len(signature_data))
        )
    index_end = SUPERBLOB_HEADER_SIZE + count * BLOB_INDEX_SIZE
    if index_end > superblob_length:
        raise CodeSignatureError(
            "%d BlobIndex entries do not fit in SuperBlob of %d bytes"
            % (count, superblob_length)
        )

    digest_cache = {}
    for i in range(count):
        entry_pos = SUPERBLOB_HEADER_SIZE + i * BLOB_INDEX_SIZE
        # CS_BlobIndex is { uint32 type; uint32 offset; }.
        slot_type, blob_offset = struct.unpack(
            ">II",
            signature_data[entry_pos:entry_pos + BLOB_INDEX_SIZE],
        )
        if blob_offset < index_end or (
            blob_offset + BLOB_HEADER_SIZE > superblob_length
        ):
            raise CodeSignatureError(
                "slot 0x%x blob offset %d is out of range "
                "(index area ends at %d, SuperBlob ends at %d)"
                % (slot_type, blob_offset, index_end, superblob_length)
            )
        blob_magic = _u32(signature_data, blob_offset)
        blob_length = _u32(signature_data, blob_offset + 4)
        if blob_length < BLOB_HEADER_SIZE:
            raise CodeSignatureError(
                "slot 0x%x declares implausible blob length %d"
                % (slot_type, blob_length)
            )
        if blob_offset + blob_length > superblob_length:
            raise CodeSignatureError(
                "slot 0x%x blob (offset %d, length %d) overruns SuperBlob "
                "of %d bytes" % (slot_type, blob_offset, blob_length,
                                 superblob_length)
            )
        blob = BlobInfo(slot_type, blob_offset, blob_length, blob_magic)
        slice_report.blobs.append(blob)

        if slot_type == CSSLOT_SIGNATURESLOT:
            if blob_magic != CSMAGIC_BLOBWRAPPER:
                raise CodeSignatureError(
                    "CMS slot has unexpected magic 0x%08x" % blob_magic
                )
            slice_report.cms_blob = blob
            continue

        if _is_code_directory_slot(slot_type):
            if blob_magic != CSMAGIC_CODEDIRECTORY:
                raise CodeSignatureError(
                    "code directory slot 0x%x has wrong magic 0x%08x"
                    % (slot_type, blob_magic)
                )
            cd_report = _analyze_code_directory(
                signature_data, blob, slice_data, digest_cache
            )
            slice_report.code_directories.append(cd_report)
            if cd_report.structural_error:
                slice_report.errors.append(
                    "CodeDirectory at slot 0x%x: %s"
                    % (slot_type, cd_report.structural_error)
                )

    # The primary CodeDirectory is mandatory for a usable embedded signature.
    if not any(
        cd.slot_type == CSSLOT_CODEDIRECTORY
        for cd in slice_report.code_directories
    ):
        raise CodeSignatureError("SuperBlob contains no primary CodeDirectory")


def analyze_macho(path):
    """
    Analyze the embedded code signature of ``path`` without modifying it.

    Returns an :class:`IntegrityReport` containing one :class:`SliceReport`
    per architecture.  Malformed signature data is reported on the affected
    slice (and via :class:`CodeSignatureError` for an unparseable SuperBlob);
    callers never need to treat a digest mismatch as an exception.
    """
    macho = MachO(path)
    report = IntegrityReport(path, macho.fat is not None)
    with open(path, "rb") as fp:
        file_data = fp.read()

    for index, header in enumerate(macho.headers):
        slice_offset = header.offset
        slice_size = header.size
        slice_report = SliceReport(
            index, int(header.header.cputype), slice_offset, slice_size
        )
        # Every offset in a fat file is relative to the start of its own slice.
        slice_data = file_data[slice_offset:slice_offset + slice_size]

        load_commands = [
            (cmd, data)
            for lc, cmd, data in header.commands
            if lc.cmd == LC_CODE_SIGNATURE
        ]
        if not load_commands:
            report.slices.append(slice_report)
            continue
        if len(load_commands) > 1:
            slice_report.errors.append(
                "slice has %d LC_CODE_SIGNATURE load commands; expected 1"
                % len(load_commands)
            )
        linkedit = load_commands[0][0]
        data_off = int(linkedit.dataoff)
        data_size = int(linkedit.datasize)
        slice_report.has_signature_load_command = True
        slice_report.signature_offset = data_off
        slice_report.signature_length = data_size

        if data_off < 0 or data_size <= 0:
            slice_report.errors.append(
                "LC_CODE_SIGNATURE has invalid offset/size (%d, %d)"
                % (data_off, data_size)
            )
            report.slices.append(slice_report)
            continue
        if data_off + data_size > slice_size:
            slice_report.errors.append(
                "LC_CODE_SIGNATURE range (%d + %d) overruns slice of %d bytes"
                % (data_off, data_size, slice_size)
            )
            report.slices.append(slice_report)
            continue

        signature_data = slice_data[data_off:data_off + data_size]
        try:
            _parse_superblob(signature_data, slice_data, slice_report)
        except CodeSignatureError as exc:
            slice_report.errors.append(str(exc))

        # Describe what the primary CodeDirectory does and does not seal.
        primary = next(
            (
                cd
                for cd in slice_report.code_directories
                if cd.slot_type == CSSLOT_CODEDIRECTORY
            ),
            None,
        )
        if primary is not None and primary.structural_error is None:
            code_limit = primary.code_limit
            if code_limit < data_off:
                # Gap between the sealed bytes and the signature area.
                slice_report.uncovered_regions.append(
                    {
                        "kind": "gap",
                        "offset": code_limit,
                        "length": data_off - code_limit,
                    }
                )
        # Bytes after the signature area (and, for fat files, anything after
        # the slice) are not covered by any page digest.
        sig_end = data_off + data_size
        if sig_end < slice_size:
            slice_report.uncovered_regions.append(
                {
                    "kind": "tail",
                    "offset": sig_end,
                    "length": slice_size - sig_end,
                }
            )
        report.slices.append(slice_report)
    return report


def format_report(report):
    """Render an :class:`IntegrityReport` as a human-readable text report."""
    lines = []
    lines.append("Mach-O integrity analysis: %s" % report.path)
    lines.append(
        "container: %s"
        % (
            "fat/universal binary"
            if report.is_fat
            else "thin Mach-O"
        )
    )
    if not report.has_any_signature:
        lines.append("no LC_CODE_SIGNATURE load command found")
        return "\n".join(lines)

    for slc in report.slices:
        lines.append("")
        lines.append(
            "slice %d (cpu_type=0x%x, file offset %d, size %d)"
            % (slc.slice_index, slc.cpu_type, slc.slice_offset, slc.slice_size)
        )
        if not slc.has_signature:
            lines.append("  no embedded signature")
            continue
        lines.append(
            "  LC_CODE_SIGNATURE: slice-relative offset %d, length %d"
            % (slc.signature_offset, slc.signature_length)
        )
        lines.append(
            "  SuperBlob: %d sub-blob(s), declared length %d"
            % (slc.superblob_count, slc.superblob_length)
        )
        for blob in slc.blobs:
            lines.append(
                "    - slot 0x%-6x %-26s magic=0x%08x length=%d"
                % (blob.slot_type, blob.slot_name, blob.magic, blob.length)
            )
        for region in slc.uncovered_regions:
            lines.append(
                "  uncovered %s: %d byte(s) at slice offset %d "
                "(not covered by any page digest)"
                % (region["kind"], region["length"], region["offset"])
            )
        for cd in slc.code_directories:
            lines.append("")
            lines.append(
                "  CodeDirectory slot 0x%x (%s):"
                % (cd.slot_type, cd.slot_name)
            )
            lines.append(
                "    version=0x%x flags=0x%x adhoc=%s identifier=%r"
                % (cd.version or 0, cd.flags or 0, cd.is_adhoc,
                   cd.identifier)
            )
            if cd.structural_error:
                lines.append("    structural error: %s" % cd.structural_error)
                continue
            lines.append(
                "    hash=%s (%d bytes) page_size=%d code_limit=%d "
                "code_slots=%d special_slots=%d"
                % (
                    cd.hash_type_name,
                    cd.hash_size,
                    cd.page_size,
                    cd.code_limit,
                    cd.n_code_slots,
                    cd.n_special_slots,
                )
            )
            lines.append(
                "    expected code slots from code_limit/page_size: %d "
                "(consistent: %s)"
                % (cd.expected_code_slots, cd.slot_count_consistent)
            )
            lines.append(
                "    page digests recomputed: %d, mismatches: %d"
                % (cd.pages_checked, len(cd.page_mismatches))
            )
            if cd.page_mismatches:
                first = cd.page_mismatches[0]
                lines.append(
                    "    first mismatch: page %d at file offset %d"
                    % (first["page"], first["file_offset"])
                )
            lines.append(
                "    page digest match: %s"
                % ("yes" if cd.page_hashes_match else "NO")
            )
            lines.append("    CDHash (sha256 of CodeDirectory): %s" % cd.cdhash)
        if slc.cms_blob is not None:
            payload = slc.cms_blob.length - BLOB_HEADER_SIZE
            lines.append("")
            lines.append(
                "  CMS (PKCS#7) signature blob present (%d payload byte(s)): "
                "NOT verified" % payload
            )
            lines.append(
                "    certificate trust and execution approval are outside "
                "the scope of this check"
            )
        else:
            lines.append("")
            lines.append("  CMS signature: absent (typical for ad-hoc signing)")
        if slc.errors:
            lines.append("  errors:")
            for error in slc.errors:
                lines.append("    * %s" % error)
    return "\n".join(lines)
