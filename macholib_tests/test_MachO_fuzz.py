import contextlib
import hashlib
import os
import struct
import sys
import tempfile
import time
import uuid

from macholib import MachO, mach_o
from macholib.ptypes import sizeof

if sys.version_info[:2] <= (2, 6):
    import unittest2 as unittest
else:
    import unittest


UNKNOWN_CMD = 0x707A11ED
UNKNOWN_PAYLOAD = b"ABCDEFGH"
FUZZ_UUID = uuid.UUID("6894C0AE-C8B7-4E0B-A529-30BBEBA3703B")
CPU_TYPE_ARM64 = 0x100000C
MH_EXECUTE = 0x2
THIN_HEADER_SIZE = sizeof(mach_o.mach_header_64)
LOAD_COMMAND_SIZE = sizeof(mach_o.load_command)


@contextlib.contextmanager
def temporary_file(data):
    with tempfile.NamedTemporaryFile(delete=False) as fileobj:
        fileobj.write(data)
        fileobj.close()
        try:
            yield fileobj.name
        finally:
            os.unlink(fileobj.name)


class ReadRecord(object):
    """File object that records every read as an absolute file interval."""

    def __init__(self, fileobj, records):
        self._fileobj = fileobj
        self._records = records

    def read(self, size=-1):
        start = self._fileobj.tell()
        data = self._fileobj.read(size)
        self._records.append((start, start + len(data), size))
        return data

    def seek(self, offset, whence=0):
        return self._fileobj.seek(offset, whence)

    def tell(self):
        return self._fileobj.tell()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def close(self):
        self._fileobj.close()


class ParseOutcome(object):
    def __init__(self, macho, error, reads, file_size, data):
        self.macho = macho
        self.error = error
        self.reads = reads
        self.file_size = file_size
        self.data = data

    def intervals(self):
        return [(start, end) for start, end, _size in self.reads]


class Sample(object):
    """A named deterministic sample that can be written and reproduced."""

    def __init__(self, group, name, data):
        self.group = group
        self.name = name
        self.data = data

    @property
    def digest(self):
        return hashlib.sha256(self.data).hexdigest()

    def label(self):
        return "%s/%s sha256=%s" % (self.group, self.name, self.digest)

    def write(self, filename):
        with open(filename, "wb") as fileobj:
            fileobj.write(self.data)


def parse_bytes(data, allow_unknown):
    """Parse data from a fresh file while recording every read interval."""
    reads = []
    real_open = open

    def recording_open(filename, mode="rb", *args, **kwargs):
        fileobj = real_open(filename, mode, *args, **kwargs)
        if mode == "rb":
            return ReadRecord(fileobj, reads)
        return fileobj

    with temporary_file(data) as filename:
        macho_module = sys.modules[MachO.MachO.__module__]
        missing = object()
        previous_open = macho_module.__dict__.get("open", missing)
        macho_module.open = recording_open
        error = None
        macho = None
        try:
            try:
                macho = MachO.MachO(filename, allow_unknown_load_commands=allow_unknown)
            except Exception as exc:  # noqa: B902 - classified by assertions
                error = exc
            file_size = os.path.getsize(filename)
        finally:
            if previous_open is missing:
                del macho_module.open
            else:
                macho_module.open = previous_open
    return ParseOutcome(macho, error, reads, file_size, data)


def lc_bytes(cmd, body=b"", cmdsize=None):
    if cmdsize is None:
        cmdsize = LOAD_COMMAND_SIZE + len(body)
    return struct.pack(">II", cmd, cmdsize) + body


def lc_uuid_bytes():
    return lc_bytes(mach_o.LC_UUID, FUZZ_UUID.bytes)


def lc_main_bytes():
    return lc_bytes(mach_o.LC_MAIN, struct.pack(">QQ", 0, 0))


def lc_unknown_bytes(payload=UNKNOWN_PAYLOAD, cmd=UNKNOWN_CMD, cmdsize=None):
    return lc_bytes(cmd, payload, cmdsize)


def lc_dylib_bytes(name_offset, name=b"/tmp/libx.dylib\x00"):
    body = (
        struct.pack(">I", name_offset)
        + b"\x00" * (sizeof(mach_o.dylib_command) - 4)
        + name
    )
    return lc_bytes(mach_o.LC_LOAD_DYLIB, body)


def build_thin(commands, ncmds=None, sizeofcmds=None, trailer=b"", magic=None):
    """Serialize a synthetic thin Mach-O with optional malformed counters."""
    if magic is None:
        magic = mach_o.MH_MAGIC_64
    if ncmds is None:
        ncmds = len(commands)
    if sizeofcmds is None:
        sizeofcmds = sum(len(command) for command in commands)
    if magic == mach_o.MH_MAGIC_64:
        header = struct.pack(
            ">IIIIIIII",
            magic,
            CPU_TYPE_ARM64,
            0,
            MH_EXECUTE,
            ncmds,
            sizeofcmds,
            0,
            0,
        )
    else:
        header = struct.pack(
            ">IIIIIII",
            magic,
            CPU_TYPE_ARM64,
            0,
            MH_EXECUTE,
            ncmds,
            sizeofcmds,
            0,
        )
    return header + b"".join(commands) + trailer


def build_fat(slices, is64=False):
    """Serialize a synthetic universal binary containing complete slices."""
    arch_cls = mach_o.fat_arch64 if is64 else mach_o.fat_arch
    magic = mach_o.FAT_MAGIC_64 if is64 else mach_o.FAT_MAGIC
    header = mach_o.fat_header(magic=magic, nfat_arch=len(slices)).to_str()
    table_size = len(header) + sizeof(arch_cls) * len(slices)
    alignment = 1 << 12
    offset = (table_size + alignment - 1) & ~(alignment - 1)
    arch_entries = []
    payload = b""
    for slice_data in slices:
        arch = arch_cls(
            cputype=CPU_TYPE_ARM64,
            cpusubtype=0,
            offset=offset,
            size=len(slice_data),
            align=12,
        )
        if is64:
            arch.reserved = 0
        arch_entries.append(arch.to_str())
        padding = offset - table_size - len(payload)
        payload += b"\x00" * padding + slice_data
        offset += len(slice_data)
    return header + b"".join(arch_entries) + payload


def control_commands():
    """A valid unknown command framed by two known commands."""
    return [lc_uuid_bytes(), lc_unknown_bytes(), lc_main_bytes()]


def control_thin():
    return build_thin(control_commands())


def control_fat(is64=False):
    slice_data = control_thin()
    return build_fat([slice_data, slice_data], is64=is64)


def malformed_length_samples():
    """
    Structurally broken samples: command lengths or header counters do not
    match the actual byte layout. Both modes must reject these.
    """
    uid = lc_uuid_bytes()
    main = lc_main_bytes()
    return [
        Sample(
            "malformed-length",
            "unknown-cmdsize-zero",
            build_thin([struct.pack(">II", UNKNOWN_CMD, 0) + UNKNOWN_PAYLOAD, main]),
        ),
        Sample(
            "malformed-length",
            "unknown-cmdsize-below-header",
            build_thin([struct.pack(">II", UNKNOWN_CMD, 4) + UNKNOWN_PAYLOAD, main]),
        ),
        Sample(
            "malformed-length",
            "unknown-cmdsize-short",
            build_thin([struct.pack(">II", UNKNOWN_CMD, 7) + UNKNOWN_PAYLOAD, main]),
        ),
        Sample(
            "malformed-length",
            "unknown-cmdsize-inflated",
            build_thin([lc_unknown_bytes(cmdsize=0x100), main], sizeofcmds=0x100),
        ),
        Sample(
            "malformed-length",
            "unknown-cmdsize-overflow",
            build_thin(
                [lc_unknown_bytes(cmdsize=0x7FFFFFFF), main],
                sizeofcmds=0xFFFFFFFF,
            ),
        ),
        Sample(
            "malformed-length",
            "unknown-cmdsize-past-file",
            build_thin([lc_unknown_bytes(cmdsize=0x100), uid, main]),
        ),
        Sample(
            "malformed-length",
            "known-cmdsize-short",
            build_thin([struct.pack(">II", mach_o.LC_UUID, 8) + FUZZ_UUID.bytes, main]),
        ),
        Sample(
            "malformed-length",
            "known-cmdsize-overflow",
            build_thin([struct.pack(">II", mach_o.LC_MAIN, 0xFFFFFFFF) + b"\x00" * 16]),
        ),
        Sample("malformed-length", "ncmds-zero", build_thin([uid, main], ncmds=0)),
        Sample("malformed-length", "ncmds-too-small", build_thin([uid, main], ncmds=1)),
        Sample("malformed-length", "ncmds-too-large", build_thin([uid, main], ncmds=3)),
        Sample(
            "malformed-length", "ncmds-past-file", build_thin([uid, main], ncmds=50)
        ),
        Sample(
            "malformed-length", "sizeofcmds-zero", build_thin([uid, main], sizeofcmds=0)
        ),
        Sample(
            "malformed-length",
            "sizeofcmds-short",
            build_thin([uid, main], sizeofcmds=THIN_HEADER_SIZE),
        ),
        Sample(
            "malformed-length",
            "sizeofcmds-long",
            build_thin([uid, main], sizeofcmds=THIN_HEADER_SIZE + 0x100),
        ),
        Sample(
            "malformed-length",
            "command-area-truncated",
            build_thin([uid], sizeofcmds=0x100),
        ),
    ]


def ordinary_unknown_samples():
    """
    Well-formed samples exercising unknown commands and LC_REQ_DYLD.
    Strict mode rejects them; lenient mode preserves every boundary and
    the raw payload.
    """
    uid = lc_uuid_bytes()
    main = lc_main_bytes()
    return [
        Sample("ordinary-unknown", "unknown-only", build_thin([lc_unknown_bytes()])),
        Sample(
            "ordinary-unknown",
            "unknown-then-uuid",
            build_thin([lc_unknown_bytes(), uid]),
        ),
        Sample(
            "ordinary-unknown", "control-interleaved", build_thin(control_commands())
        ),
        Sample(
            "ordinary-unknown",
            "unknown-with-req-dyld",
            build_thin([lc_unknown_bytes(cmd=UNKNOWN_CMD | mach_o.LC_REQ_DYLD), main]),
        ),
        Sample(
            "ordinary-unknown",
            "uuid-with-req-dyld",
            build_thin(
                [lc_bytes(mach_o.LC_UUID | mach_o.LC_REQ_DYLD, FUZZ_UUID.bytes), main]
            ),
        ),
        Sample(
            "ordinary-unknown",
            "main-with-req-dyld-cleared",
            build_thin(
                [
                    lc_bytes(
                        mach_o.LC_MAIN & ~mach_o.LC_REQ_DYLD,
                        struct.pack(">QQ", 0, 0),
                    ),
                    uid,
                ]
            ),
        ),
        Sample(
            "ordinary-unknown",
            "unknown-empty-body",
            build_thin([lc_unknown_bytes(b""), main]),
        ),
        Sample(
            "ordinary-unknown",
            "two-unknowns",
            build_thin(
                [
                    lc_unknown_bytes(b"x", cmd=UNKNOWN_CMD),
                    main,
                    lc_unknown_bytes(b"y", cmd=UNKNOWN_CMD + 1),
                    uid,
                ]
            ),
        ),
        Sample(
            "ordinary-unknown",
            "unknown-at-end",
            build_thin([uid, main, lc_unknown_bytes(b"tail")]),
        ),
    ]


def string_offset_samples():
    """LC_LOAD_DYLIB name offsets at and past the end of the string area."""
    return [
        Sample(
            "string-offset",
            "dylib-name-offset-%d" % (offset,),
            build_thin([lc_uuid_bytes(), lc_dylib_bytes(offset), lc_main_bytes()]),
        )
        for offset in (0, 4, 8, 16, 24, 32, 39, 40, 0xFFFFFFFF)
    ]


def boundary_shift_samples():
    """
    Inflated unknown cmdsize values whose declared end lands inside a
    following command. Must be rejected in both modes rather than
    reinterpreting the remainder from the shifted boundary.
    """
    return [
        Sample(
            "boundary-shift",
            "unknown-end-inside-uuid",
            build_thin(
                [
                    struct.pack(">II", UNKNOWN_CMD, LOAD_COMMAND_SIZE + 24),
                    lc_uuid_bytes(),
                    lc_main_bytes(),
                ],
                ncmds=3,
                sizeofcmds=LOAD_COMMAND_SIZE + 24,
                trailer=b"PADDING!",
            ),
        ),
        Sample(
            "boundary-shift",
            "unknown-end-inside-main",
            build_thin(
                [
                    struct.pack(">II", UNKNOWN_CMD, LOAD_COMMAND_SIZE + 8),
                    lc_main_bytes(),
                    lc_uuid_bytes(),
                ],
                ncmds=3,
                sizeofcmds=LOAD_COMMAND_SIZE + 8,
            ),
        ),
    ]


def fat_samples():
    """Valid universal binaries plus malformed fat table entries."""
    slice_data = control_thin()
    header = mach_o.fat_header(magic=mach_o.FAT_MAGIC, nfat_arch=1).to_str()
    pad = b"\x00" * ((1 << 12) - len(header) - sizeof(mach_o.fat_arch))
    return [
        Sample("fat", "valid-fat32", control_fat()),
        Sample("fat", "valid-fat64", control_fat(is64=True)),
        Sample(
            "fat",
            "nfat-arch-exceeds-table",
            struct.pack(">II", mach_o.FAT_MAGIC, 2)
            + mach_o.fat_arch(
                cputype=CPU_TYPE_ARM64,
                cpusubtype=0,
                offset=1 << 12,
                size=len(slice_data),
                align=12,
            ).to_str()
            + pad
            + slice_data,
        ),
        Sample(
            "fat",
            "slice-overlaps-arch-table",
            header
            + struct.pack(">IIIII", CPU_TYPE_ARM64, 0, 0, len(slice_data), 12)
            + slice_data,
        ),
        Sample(
            "fat",
            "slice-past-eof",
            header
            + struct.pack(">IIIII", CPU_TYPE_ARM64, 0, 1 << 12, 0x10000000, 12)
            + pad
            + slice_data,
        ),
        Sample(
            "fat",
            "slice-too-small",
            header
            + struct.pack(">IIIII", CPU_TYPE_ARM64, 0, 1 << 12, LOAD_COMMAND_SIZE, 12)
            + pad
            + slice_data,
        ),
        Sample(
            "fat",
            "overlapping-slices",
            struct.pack(">II", mach_o.FAT_MAGIC, 2)
            + struct.pack(">IIIII", CPU_TYPE_ARM64, 0, 1 << 12, len(slice_data), 12)
            + struct.pack(
                ">IIIII", CPU_TYPE_ARM64, 0, (1 << 12) + 4, len(slice_data), 12
            )
            + b"\x00"
            * ((1 << 12) - sizeof(mach_o.fat_header) - 2 * sizeof(mach_o.fat_arch))
            + slice_data,
        ),
    ]


def all_samples():
    return (
        malformed_length_samples()
        + ordinary_unknown_samples()
        + string_offset_samples()
        + boundary_shift_samples()
        + fat_samples()
    )


class TestStructuralFuzz(unittest.TestCase):
    """Structural fuzz tests for thin and fat Mach-O inputs."""

    if not hasattr(unittest.TestCase, "subTest"):

        def subTest(self, *args, **kwargs):
            class SubTest(object):
                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    return False

            return SubTest()

    def assert_reads_within_file(self, result):
        self.assertGreater(result.file_size, 0)
        for start, end, _size in result.reads:
            self.assertGreaterEqual(start, 0)
            self.assertGreaterEqual(end, start)
            self.assertLessEqual(start, result.file_size)
            self.assertLessEqual(end, result.file_size)

    def assert_reads_within_commands(self, result, header):
        """
        Reads must stay inside the slice's load-command area, aside from
        the mach header at the start of the slice.
        """
        slice_start = header.offset
        slice_end = header.offset + header.size
        command_start = slice_start + THIN_HEADER_SIZE
        command_end = command_start + header.header.sizeofcmds
        self.assertLessEqual(command_end, slice_end)
        for start, end, _size in result.reads:
            if start < command_start:
                self.assertEqual(start, slice_start)
                self.assertLessEqual(end, command_start)
                continue
            self.assertGreaterEqual(start, command_start)
            self.assertLessEqual(end, command_end)

    def assert_reads_within_slices(self, result, headers, container_end):
        slices = [(header.offset, header.offset + header.size) for header in headers]
        for start, end, _size in result.reads:
            if start < container_end:
                self.assertLessEqual(end, container_end)
                continue
            contained = any(
                slice_start <= start <= end <= slice_end
                for slice_start, slice_end in slices
            )
            self.assertTrue(
                contained, "read [%d, %d) escaped slices %r" % (start, end, slices)
            )

    def assert_control_commands(self, header):
        commands = header.commands
        self.assertEqual(
            [command[0].cmd for command in commands],
            [mach_o.LC_UUID, UNKNOWN_CMD, mach_o.LC_MAIN],
        )
        load_command, command, payload = commands[1]
        self.assertIsInstance(load_command, mach_o.load_command)
        self.assertIs(command, load_command)
        self.assertEqual(load_command.cmdsize, LOAD_COMMAND_SIZE + len(UNKNOWN_PAYLOAD))
        self.assertEqual(payload, UNKNOWN_PAYLOAD)
        self.assertEqual(uuid.UUID(bytes=commands[0][1].uuid), FUZZ_UUID)
        self.assertEqual(commands[2][1].entryoff, 0)
        self.assertEqual(commands[2][1].stacksize, 0)

    def assert_commands_walk_layout(self, data, header):
        cursor = header.offset + THIN_HEADER_SIZE
        declared_end = cursor + header.header.sizeofcmds
        self.assertEqual(declared_end, header.offset + len(data))
        for load_command, _specific, payload in header.commands:
            self.assertGreaterEqual(load_command.cmdsize, LOAD_COMMAND_SIZE)
            self.assertLessEqual(cursor + load_command.cmdsize, declared_end)
            if isinstance(payload, bytes):
                expected = load_command.cmdsize - LOAD_COMMAND_SIZE
                if load_command.cmd in mach_o.LC_REGISTRY:
                    expected -= sizeof(mach_o.LC_REGISTRY[load_command.cmd])
                self.assertEqual(len(payload), expected)
            cursor += load_command.cmdsize
        self.assertEqual(cursor, declared_end)

    def test_small_thin_control_interleaved(self):
        result = parse_bytes(control_thin(), allow_unknown=True)
        self.assertIsNone(result.error, result.error)
        header = result.macho.headers[0]
        self.assert_control_commands(header)
        self.assert_reads_within_file(result)
        self.assertEqual(header.offset, 0)
        self.assertEqual(
            header.total_size,
            THIN_HEADER_SIZE + sum(len(lc) for lc in control_commands()),
        )

    def test_small_fat_control_interleaved(self):
        for is64 in (False, True):
            data = control_fat(is64=is64)
            result = parse_bytes(data, allow_unknown=True)
            self.assertIsNone(result.error, result.error)
            self.assertEqual(len(result.macho.headers), 2)
            container_end = sizeof(mach_o.fat_header) + 2 * sizeof(
                mach_o.fat_arch64 if is64 else mach_o.fat_arch
            )
            for header in result.macho.headers:
                self.assert_control_commands(header)
            self.assert_reads_within_slices(result, result.macho.headers, container_end)
            self.assert_reads_within_file(result)

    def test_control_rejected_in_strict_mode(self):
        for data in (control_thin(), control_fat()):
            result = parse_bytes(data, allow_unknown=False)
            self.assertIsInstance(result.error, ValueError)
            self.assertIn("Unknown load command", str(result.error))
            self.assert_reads_within_file(result)

    def test_malformed_lengths_rejected_in_both_modes(self):
        for sample in malformed_length_samples():
            for allow_unknown in (False, True):
                with self.subTest(sample.label(), allow_unknown=allow_unknown):
                    result = parse_bytes(sample.data, allow_unknown)
                    self.assertIsInstance(
                        result.error,
                        ValueError,
                        "%s accepted with allow_unknown=%r"
                        % (sample.label(), allow_unknown),
                    )
                    self.assert_reads_within_file(result)

    def test_ordinary_unknowns_lenient_preserves_boundaries(self):
        for sample in ordinary_unknown_samples():
            with self.subTest(sample.label()):
                result = parse_bytes(sample.data, allow_unknown=True)
                self.assertIsNone(result.error, result.error)
                header = result.macho.headers[0]
                self.assert_commands_walk_layout(sample.data, header)
                self.assert_reads_within_commands(result, header)

    def test_ordinary_unknowns_keep_raw_payload(self):
        sample = Sample(
            "ordinary-unknown",
            "raw-payload-check",
            build_thin([lc_uuid_bytes(), lc_unknown_bytes(), lc_main_bytes()]),
        )
        result = parse_bytes(sample.data, allow_unknown=True)
        self.assertIsNone(result.error, result.error)
        header = result.macho.headers[0]
        command_start = THIN_HEADER_SIZE + len(lc_uuid_bytes())
        load_command, command, payload = header.commands[1]
        declared = sample.data[
            command_start : command_start + load_command.cmdsize  # noqa: E203
        ]
        self.assertEqual(declared, lc_unknown_bytes())
        self.assertEqual(payload, UNKNOWN_PAYLOAD)
        self.assertIs(command, load_command)

    def test_ordinary_unknowns_strict_rejects(self):
        for sample in ordinary_unknown_samples():
            with self.subTest(sample.label()):
                result = parse_bytes(sample.data, allow_unknown=False)
                self.assertIsInstance(result.error, ValueError)
                self.assert_reads_within_file(result)

    def test_string_offsets_bounded(self):
        for sample in string_offset_samples():
            with self.subTest(sample.label()):
                result = parse_bytes(sample.data, allow_unknown=True)
                self.assertIsNone(result.error, result.error)
                header = result.macho.headers[0]
                load_command, specific, payload = header.commands[1]
                self.assertEqual(load_command.cmd, mach_o.LC_LOAD_DYLIB)
                offset = struct.unpack(">I", specific.to_str()[:4])[0]
                relative = offset - LOAD_COMMAND_SIZE - sizeof(mach_o.dylib_command)
                names = [value for _idx, _name, value in header.walkRelocatables()]
                self.assertEqual(len(names), 1)
                if 0 <= relative <= len(payload):
                    self.assertIn(names[0], payload.decode("ascii", "replace"))
                else:
                    self.assertEqual(names[0], "")
                self.assert_reads_within_commands(result, header)

    def test_boundary_shifts_rejected(self):
        samples = boundary_shift_samples()
        self.assertEqual(len(samples), 2)
        for sample in samples:
            for allow_unknown in (False, True):
                with self.subTest(sample.label(), allow_unknown=allow_unknown):
                    result = parse_bytes(sample.data, allow_unknown)
                    self.assertIsInstance(result.error, ValueError)
                    self.assert_reads_within_file(result)
                    if result.error is not None:
                        self.assertNotIsInstance(
                            result.error,
                            UnicodeDecodeError,
                            "boundary shift should be a length error",
                        )

    def test_fat_valid_and_invalid_slices(self):
        for sample in fat_samples():
            for allow_unknown in (False, True):
                with self.subTest(sample.label(), allow_unknown=allow_unknown):
                    result = parse_bytes(sample.data, allow_unknown)
                    self.assert_reads_within_file(result)
                    if sample.name.startswith("valid") and allow_unknown:
                        self.assertIsNone(result.error, result.error)
                        self.assertEqual(len(result.macho.headers), 2)
                        container_end = sizeof(mach_o.fat_header) + 2 * sizeof(
                            mach_o.fat_arch64
                            if sample.name == "valid-fat64"
                            else mach_o.fat_arch
                        )
                        for header in result.macho.headers:
                            self.assertEqual(header.size, len(control_thin()))
                        self.assert_reads_within_slices(
                            result, result.macho.headers, container_end
                        )
                    else:
                        self.assertIsInstance(result.error, ValueError)

    def test_each_sample_reproduces_individually(self):
        for sample in all_samples():
            with self.subTest(sample.label()):
                first = parse_bytes(sample.data, allow_unknown=True)
                second = parse_bytes(sample.data, allow_unknown=True)
                self.assertEqual(first.error is None, second.error is None)
                if first.error is not None:
                    self.assertEqual(type(first.error), type(second.error))
                    self.assertEqual(str(first.error), str(second.error))
                self.assertEqual(first.intervals(), second.intervals())
                with tempfile.NamedTemporaryFile(delete=False) as fileobj:
                    sample.write(fileobj.name)
                    readable = fileobj.name
                try:
                    with open(readable, "rb") as fileobj:
                        self.assertEqual(fileobj.read(), sample.data)
                finally:
                    os.unlink(readable)

    def test_samples_are_deterministic(self):
        samples = all_samples()
        digests = [sample.digest for sample in samples]
        self.assertEqual(len(digests), len(set(digests)))
        self.assertEqual([sample.digest for sample in all_samples()], digests)
        self.assertLessEqual(len(samples), 50)
        self.assertEqual(
            {sample.group for sample in malformed_length_samples()},
            {"malformed-length"},
        )
        self.assertEqual(
            {sample.group for sample in ordinary_unknown_samples()},
            {"ordinary-unknown"},
        )

    def test_corpus_runs_quickly(self):
        started = time.time()
        for sample in all_samples():
            parse_bytes(sample.data, allow_unknown=True)
        for sample in all_samples():
            parse_bytes(sample.data, allow_unknown=False)
        self.assertLess(time.time() - started, 2.0)


if __name__ == "__main__":
    unittest.main()
