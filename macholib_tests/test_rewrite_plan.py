import contextlib
import os
import struct
import sys
import tempfile

from macholib import MachO, mach_o
from macholib.MachO import InsufficientHeaderSpaceError

if sys.version_info[:2] <= (2, 6):
    import unittest2 as unittest
else:
    import unittest


HEADER_64_SIZE = 32
LOAD_COMMAND_SIZE = 8
SEGMENT_64_BODY_SIZE = 64
DYLIB_BODY_SIZE = 16
LINKEDIT_BODY_SIZE = 8
FAT_ARCH_SIZE = 20

CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_X86_64 = 0x01000007
CPU_SUBTYPE_ALL = 0
MH_FILETYPE_EXECUTE = 0x2


def _maybe_swap(value, endian):
    # struct applies the byte order itself, so the numeric constant
    # stays the same for either endianness
    return value


def _aligned_string(value, alignment=8):
    padding = alignment - (len(value) % alignment)
    return value + (b"\x00" * padding)


def lc_segment_64(fileoff, filesize=1, segname=b"__LINKEDIT", endian=">"):
    cmdsize = LOAD_COMMAND_SIZE + SEGMENT_64_BODY_SIZE
    return struct.pack(
        endian + "II16sQQQQiiII",
        _maybe_swap(mach_o.LC_SEGMENT_64, endian),
        cmdsize,
        segname,
        fileoff,  # vmaddr
        filesize,  # vmsize
        fileoff,
        filesize,
        7,  # maxprot
        5,  # initprot
        0,  # nsects
        0,  # flags
    )


def lc_load_dylib(path, endian=">"):
    string = _aligned_string(path)
    cmdsize = LOAD_COMMAND_SIZE + DYLIB_BODY_SIZE + len(string)
    payload = struct.pack(
        endian + "IIII",
        LOAD_COMMAND_SIZE
        + DYLIB_BODY_SIZE,  # lc_str name offset (from command start)
        2,  # timestamp
        0x10000,  # current version
        0x10000,  # compatibility version
    )
    return (
        struct.pack(
            endian + "II",
            _maybe_swap(mach_o.LC_LOAD_DYLIB, endian),
            cmdsize,
        )
        + payload
        + string
    )


def lc_code_signature(dataoff, datasize, endian=">"):
    cmdsize = LOAD_COMMAND_SIZE + LINKEDIT_BODY_SIZE
    return struct.pack(
        endian + "IIII",
        _maybe_swap(mach_o.LC_CODE_SIGNATURE, endian),
        cmdsize,
        dataoff,
        datasize,
    )


def build_slice(cputype, cpusubtype, load_commands, first_data_offset):
    ncmds = len(load_commands)
    sizeofcmds = sum(len(command) for command in load_commands)
    header = struct.pack(
        ">IIIIIIII",
        mach_o.MH_MAGIC_64,
        cputype,
        cpusubtype,
        MH_FILETYPE_EXECUTE,
        ncmds,
        sizeofcmds,
        0,
        0,
    )
    body = header + b"".join(load_commands)
    if len(body) < first_data_offset:
        body += b"\x00" * (first_data_offset - len(body))
    return body


def build_little_endian_slice(load_commands, first_data_offset):
    ncmds = len(load_commands)
    sizeofcmds = sum(len(command) for command in load_commands)
    header = struct.pack(
        "<IIIIIIII",
        struct.unpack("<I", struct.pack(">I", mach_o.MH_CIGAM_64))[0],
        CPU_TYPE_X86_64,
        CPU_SUBTYPE_ALL,
        MH_FILETYPE_EXECUTE,
        ncmds,
        sizeofcmds,
        0,
        0,
    )
    body = header + b"".join(load_commands)
    if len(body) < first_data_offset:
        body += b"\x00" * (first_data_offset - len(body))
    return body


@contextlib.contextmanager
def temporary_file(data):
    temporary = tempfile.NamedTemporaryFile(delete=False)
    try:
        temporary.write(data)
        temporary.close()
        yield temporary.name
    finally:
        if os.path.exists(temporary.name):
            os.unlink(temporary.name)


def build_fat_file(slices):
    """slices: list of (cputype, cpusubtype, slice_bytes)"""
    header_size = 8 + FAT_ARCH_SIZE * len(slices)
    offset = header_size
    arch_entries = []
    bodies = []
    for cputype, cpusubtype, body in slices:
        arch_entries.append(
            struct.pack(
                ">iiIII",
                cputype,
                cpusubtype,
                offset,
                len(body),
                2,  # align as 2**2 == 4 byte alignment
            )
        )
        bodies.append(body)
        offset += len(body)
    fat_header = struct.pack(
        ">II", mach_o.FAT_MAGIC, len(slices)
    )
    return fat_header + b"".join(arch_entries) + b"".join(bodies)


def make_two_slice_file(arm_path, x86_path, arm_slack, x86_slack):
    arm_commands = [
        lc_segment_64(0),
        lc_load_dylib(arm_path),
        lc_code_signature(0x4000, 256),
    ]
    arm_first_data = (
        HEADER_64_SIZE + sum(len(c) for c in arm_commands) + arm_slack
    )
    arm_commands[0] = lc_segment_64(arm_first_data)
    arm_slice = build_slice(
        CPU_TYPE_ARM64, CPU_SUBTYPE_ALL, arm_commands, arm_first_data
    )

    x86_commands = [
        lc_segment_64(0),
        lc_load_dylib(x86_path),
        lc_code_signature(0x4000, 256),
    ]
    x86_first_data = (
        HEADER_64_SIZE + sum(len(c) for c in x86_commands) + x86_slack
    )
    x86_commands[0] = lc_segment_64(x86_first_data)
    x86_slice = build_slice(
        CPU_TYPE_X86_64, CPU_SUBTYPE_ALL, x86_commands, x86_first_data
    )
    return build_fat_file(
        [
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ALL, arm_slice),
            (CPU_TYPE_X86_64, CPU_SUBTYPE_ALL, x86_slice),
        ]
    )


class TestRewritePlan(unittest.TestCase):
    def test_preflight_is_read_only_and_reports_ranges(self):
        old_path = b"/old/path/libfoo.dylib"
        new_path = b"/very/long/new/path/to/libfoo.dylib"
        data = make_two_slice_file(old_path, b"/other/libbar.dylib", 64, 64)
        with temporary_file(data) as filename:
            original_bytes = open(filename, "rb").read()
            macho = MachO.MachO(filename)

            def changefunc(path):
                if path == old_path.decode("utf-8"):
                    return new_path.decode("utf-8")
                return None

            plan = macho.preflight_rewrite(changefunc)

            self.assertTrue(plan.feasible)
            self.assertEqual(plan.errors(), [])
            # preflight must not touch the file or the parsed commands
            self.assertEqual(open(filename, "rb").read(), original_bytes)
            arm_plan = plan.slice_plans[0]
            self.assertEqual(len(arm_plan.changes), 1)
            change = arm_plan.changes[0]
            self.assertEqual(change.old_path, old_path.decode("utf-8"))
            self.assertEqual(change.new_path, new_path.decode("utf-8"))
            self.assertEqual(change.command_name, "load_dylib")
            expected_growth = (
                len(_aligned_string(new_path))
                - len(_aligned_string(old_path))
            )
            self.assertEqual(change.size_delta, expected_growth)
            self.assertEqual(arm_plan.size_delta, expected_growth)
            segment_command_size = LOAD_COMMAND_SIZE + SEGMENT_64_BODY_SIZE
            # range covers the whole original load command, which sits
            # right after the mach header and the segment command
            self.assertEqual(
                change.file_offset,
                arm_plan.file_offset
                + HEADER_64_SIZE
                + segment_command_size,
            )
            self.assertEqual(
                change.file_offset + change.old_size,
                arm_plan.file_offset
                + HEADER_64_SIZE
                + segment_command_size
                + change.old_size,
            )
            self.assertEqual(
                change.string_offset,
                change.file_offset
                + LOAD_COMMAND_SIZE
                + DYLIB_BODY_SIZE,
            )
            # untouched slice has no changes
            self.assertEqual(plan.slice_plans[1].changes, [])
            self.assertEqual(plan.changed_slices, [arm_plan])

    def test_signature_state_is_reported_and_never_removed(self):
        old_path = b"/old/lib.dylib"
        data = make_two_slice_file(old_path, old_path, 64, 64)
        with temporary_file(data) as filename:
            macho = MachO.MachO(filename)

            def changefunc(path):
                if path == old_path.decode("utf-8"):
                    return b"/new/lib.dylib".decode("utf-8")
                return None

            plan = macho.preflight_rewrite(changefunc)
            self.assertEqual(len(plan.resigned_slices), 2)
            for slice_plan in plan.slice_plans:
                self.assertTrue(slice_plan.has_code_signature)
                self.assertTrue(slice_plan.needs_resign)
                self.assertIsNotNone(slice_plan.code_signature_offset)
                self.assertEqual(slice_plan.code_signature_size, 256)

            self.assertTrue(plan.feasible)
            with open(filename, "rb+") as fileobj:
                macho.apply_plan(plan, fileobj)

            rewritten = MachO.MachO(filename)
            for header in rewritten.headers:
                signature_commands = [
                    lc
                    for lc, _cmd, _data in header.commands
                    if lc.cmd == mach_o.LC_CODE_SIGNATURE
                ]
                self.assertEqual(len(signature_commands), 1)

    def test_infeasible_slice_rejects_whole_file_without_writes(self):
        old_arm = b"/old/arm/lib.dylib"
        old_x86 = b"/old/x86/lib.dylib"
        new_arm = b"/writable/arm/lib.dylib"
        new_x86 = (
            b"/an/enormously/longer/x86/path/that/definitely/does/not/fit/"
            b"in/the/handful/of/slack/bytes/lib.dylib"
        )
        data = make_two_slice_file(old_arm, old_x86, 64, 0)
        with temporary_file(data) as filename:
            original_bytes = open(filename, "rb").read()
            macho = MachO.MachO(filename)

            def changefunc(path):
                if path == old_arm.decode("utf-8"):
                    return new_arm.decode("utf-8")
                if path == old_x86.decode("utf-8"):
                    return new_x86.decode("utf-8")
                return None

            plan = macho.preflight_rewrite(changefunc)
            self.assertFalse(plan.feasible)
            self.assertTrue(plan.slice_plans[0].feasible)
            self.assertFalse(plan.slice_plans[1].feasible)
            self.assertEqual(len(plan.errors()), 1)
            self.assertEqual(plan.errors()[0][0], 1)
            self.assertIn("only 0", plan.slice_plans[1].error)
            self.assertGreater(plan.slice_plans[1].size_delta, 0)

            with self.assertRaises(InsufficientHeaderSpaceError):
                with open(filename, "rb+") as fileobj:
                    macho.apply_plan(plan, fileobj)

            # not a single byte may change, in either slice
            self.assertEqual(open(filename, "rb").read(), original_bytes)

            macho_again = MachO.MachO(filename)
            arm_paths = [
                value
                for _idx, _name, value in macho_again.headers[
                    0
                ].walkRelocatables()
            ]
            x86_paths = [
                value
                for _idx, _name, value in macho_again.headers[
                    1
                ].walkRelocatables()
            ]
            self.assertEqual(arm_paths, [old_arm.decode("utf-8")])
            self.assertEqual(x86_paths, [old_x86.decode("utf-8")])

    def test_successful_plan_identifies_slice_and_commands(self):
        old_path = b"/old/libfoo.dylib"
        new_path = b"@executable_path/Frameworks/libfoo.dylib"
        data = make_two_slice_file(old_path, old_path, 128, 128)
        with temporary_file(data) as filename:
            macho = MachO.MachO(filename)

            def changefunc(path):
                if path == old_path.decode("utf-8"):
                    return new_path.decode("utf-8")
                return None

            plan = macho.preflight_rewrite(changefunc)
            self.assertTrue(plan.feasible)
            self.assertEqual(len(plan.changed_slices), 2)
            self.assertEqual(len(plan.resigned_slices), 2)
            for slice_plan in plan.slice_plans:
                self.assertEqual(slice_plan.changed_command_indices, [1])
                change = slice_plan.changes[0]
                self.assertEqual(change.cmd, mach_o.LC_LOAD_DYLIB)
                self.assertEqual(
                    change.old_path, old_path.decode("utf-8")
                )
                self.assertEqual(
                    change.new_path, new_path.decode("utf-8")
                )

            with open(filename, "rb+") as fileobj:
                macho.apply_plan(plan, fileobj)

            rewritten = MachO.MachO(filename)
            for header in rewritten.headers:
                paths = [
                    value
                    for _idx, _name, value in header.walkRelocatables()
                ]
                self.assertEqual(paths, [new_path.decode("utf-8")])

    def test_stale_plan_is_rejected(self):
        old_path = b"/old/libfoo.dylib"
        new_path = b"/new/libfoo.dylib"
        data = make_two_slice_file(old_path, old_path, 64, 64)
        with temporary_file(data) as filename:
            macho = MachO.MachO(filename)

            def changefunc(path):
                if path == old_path.decode("utf-8"):
                    return new_path.decode("utf-8")
                return None

            plan = macho.preflight_rewrite(changefunc)
            # mutate the planned dylib command behind the plan's back
            macho.headers[0].commands[1][0].cmdsize += 8
            with self.assertRaises(ValueError):
                with open(filename, "rb+") as fileobj:
                    macho.apply_plan(plan, fileobj)
            original = make_two_slice_file(old_path, old_path, 64, 64)
            self.assertEqual(open(filename, "rb").read(), original)

    def test_unsigned_changed_slice_does_not_need_resign(self):
        old_path = b"/old/libfoo.dylib"
        new_path = b"/new/libfoo.dylib"
        commands = [
            lc_segment_64(0),
            lc_load_dylib(old_path),
        ]
        first_data = HEADER_64_SIZE + sum(len(c) for c in commands) + 64
        commands[0] = lc_segment_64(first_data)
        slice_bytes = build_slice(
            CPU_TYPE_ARM64, CPU_SUBTYPE_ALL, commands, first_data
        )
        with temporary_file(slice_bytes) as filename:
            macho = MachO.MachO(filename)
            plan = macho.preflight_rewrite(
                lambda path: new_path.decode("utf-8")
                if path == old_path.decode("utf-8")
                else None
            )
            slice_plan = plan.slice_plans[0]
            self.assertTrue(plan.feasible)
            self.assertEqual(len(slice_plan.changes), 1)
            self.assertFalse(slice_plan.has_code_signature)
            self.assertFalse(slice_plan.needs_resign)
            self.assertEqual(plan.resigned_slices, [])

            original_bytes = open(filename, "rb").read()
            with open(filename, "rb+") as fileobj:
                macho.apply_plan(plan, fileobj)
            rewritten = MachO.MachO(filename)
            paths = [
                value
                for _idx, _name, value in rewritten.headers[
                    0
                ].walkRelocatables()
            ]
            self.assertEqual(paths, [new_path.decode("utf-8")])
            self.assertNotEqual(
                open(filename, "rb").read(), original_bytes
            )

    def test_little_endian_slice_is_handled(self):
        old_path = b"/old/libfoo.dylib"
        new_path = b"@rpath/libfoo.dylib"
        endian = "<"
        commands = [
            lc_segment_64(0, endian=endian),
            lc_load_dylib(old_path, endian=endian),
            lc_code_signature(0x4000, 256, endian=endian),
        ]
        first_data = HEADER_64_SIZE + sum(len(c) for c in commands) + 64
        commands[0] = lc_segment_64(first_data, endian=endian)
        slice_bytes = build_little_endian_slice(commands, first_data)
        with temporary_file(slice_bytes) as filename:
            macho = MachO.MachO(filename)
            self.assertEqual(macho.headers[0].endian, "<")
            plan = macho.preflight_rewrite(
                lambda path: new_path.decode("utf-8")
                if path == old_path.decode("utf-8")
                else None
            )
            slice_plan = plan.slice_plans[0]
            self.assertTrue(plan.feasible)
            self.assertEqual(
                slice_plan.changes[0].old_path, old_path.decode("utf-8")
            )
            self.assertTrue(slice_plan.needs_resign)
            with open(filename, "rb+") as fileobj:
                macho.apply_plan(plan, fileobj)
            rewritten = MachO.MachO(filename)
            paths = [
                value
                for _idx, _name, value in rewritten.headers[
                    0
                ].walkRelocatables()
            ]
            self.assertEqual(paths, [new_path.decode("utf-8")])

    def test_no_matching_paths_produces_empty_plan(self):
        old_path = b"/old/libfoo.dylib"
        data = make_two_slice_file(old_path, old_path, 64, 64)
        with temporary_file(data) as filename:
            original_bytes = open(filename, "rb").read()
            macho = MachO.MachO(filename)
            plan = macho.preflight_rewrite(lambda path: None)
            self.assertTrue(plan.feasible)
            self.assertEqual(plan.changed_slices, [])
            self.assertEqual(plan.resigned_slices, [])
            for slice_plan in plan.slice_plans:
                self.assertTrue(slice_plan.has_code_signature)
                self.assertFalse(slice_plan.needs_resign)
                self.assertEqual(slice_plan.changes, [])
                self.assertEqual(slice_plan.size_delta, 0)
            with open(filename, "rb+") as fileobj:
                macho.apply_plan(plan, fileobj)
            self.assertEqual(open(filename, "rb").read(), original_bytes)


if __name__ == "__main__":
    unittest.main()
