import contextlib
import io
import os
import struct
import tempfile

from macholib import macho_dump
from macholib.MachO import MachO
from macholib.thread_state import (
    CPU_TYPE_ARM,
    CPU_TYPE_ARM64,
    CPU_TYPE_I386,
    CPU_TYPE_X86_64,
    ThreadStateError,
    parse_thread_states,
    thread_state_layout,
)

if __import__("sys").version_info[:2] <= (2, 6):
    import unittest2 as unittest
else:
    import unittest

CPU_SUBTYPE_X86_64_ALL = 3
CPU_SUBTYPE_ARM64_ALL = 0
MH_EXECUTE = 2
LC_THREAD = 0x4
LC_UNIXTHREAD = 0x5


def thread_command_bytes(payload, endian="<", cmd=LC_UNIXTHREAD):
    return struct.pack(endian + "II", cmd, 8 + len(payload)) + payload


def state_bytes(flavor, count, data, endian="<"):
    return struct.pack(endian + "II", flavor, count) + data


def x86_thread_state64(values):
    """
    Assemble an x86_THREAD_STATE64 record by hand.

    *values* maps register names to values; every field is 8 bytes wide.
    """
    order = (
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rdi",
        "rsi",
        "rbp",
        "rsp",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "rip",
        "rflags",
        "cs",
        "fs",
        "gs",
    )
    return b"".join(struct.pack("<Q", values.get(name, 0)) for name in order)


def arm_thread_state64(values):
    """
    Assemble an arm_thread_state64_t record by hand.

    x0-x28 are 8 bytes each, followed by fp, lr, sp, pc, cpsr and pad.
    """
    words = b"".join(
        struct.pack("<Q", values.get("x%d" % index, 0)) for index in range(29)
    )
    words += b"".join(
        struct.pack("<Q", values.get(name, 0)) for name in ("fp", "lr", "sp", "pc")
    )
    return words + struct.pack("<II", values.get("cpsr", 0), values.get("pad", 0))


@contextlib.contextmanager
def temporary_macho_file(cputype, load_commands, endian="<", size=64):
    """
    Write a one-architecture Mach-O file containing *load_commands*.

    The magic is always the value for a 64-bit Mach-O; when the file is
    written big-endian it is serialized as ``MH_CIGAM_64`` so that the
    existing reader selects ``">"``-decoding.
    """
    subtype = {
        CPU_TYPE_X86_64: CPU_SUBTYPE_X86_64_ALL,
        CPU_TYPE_ARM64: CPU_SUBTYPE_ARM64_ALL,
    }.get(cputype, 0)
    if size == 64:
        header = struct.pack(
            endian + "IIIIIIII",
            0xFEEDFACF,
            cputype,
            subtype,
            MH_EXECUTE,
            len(load_commands),
            sum(len(command) for command in load_commands),
            0,
            0,
        )
    else:
        header = struct.pack(
            endian + "IIIIIII",
            0xFEEDFACE,
            cputype,
            subtype,
            MH_EXECUTE,
            len(load_commands),
            sum(len(command) for command in load_commands),
            0,
        )
    fd, path = tempfile.mkstemp(suffix=".macho")
    try:
        with os.fdopen(fd, "wb") as macho_file:
            macho_file.write(header)

            for command in load_commands:
                macho_file.write(command)
        yield path
    finally:
        os.unlink(path)


def x86_thread_state32(values):
    """
    Assemble an i386/x86_THREAD_STATE32 record by hand.
    """
    order = (
        "eax",
        "ebx",
        "ecx",
        "edx",
        "edi",
        "esi",
        "ebp",
        "esp",
        "ss",
        "eflags",
        "eip",
        "cs",
        "ds",
        "es",
        "fs",
        "gs",
    )
    return b"".join(struct.pack("<I", values.get(name, 0)) for name in order)


def first_thread_command(path):
    macho = MachO(path)
    header = macho.headers[0]
    for lc, command, _data in header.commands:
        if lc.cmd in (LC_THREAD, LC_UNIXTHREAD):
            return header, lc, command
    raise AssertionError("no thread command in sample")


class TestThreadStateDecoding(unittest.TestCase):
    def test_x86_64_registers_and_field_sources(self):
        registers = {
            "rsp": 0x7FFEE0A0C000,
            "rbp": 0x7FFEE0A0C010,
            "r12": 0xABCDEF0012345678,
            "rip": 0x0000000100003F90,
            "rflags": 0x246,
            "cs": 0x2B,
        }
        payload = state_bytes(4, 42, x86_thread_state64(registers), "<")
        with temporary_macho_file(
            CPU_TYPE_X86_64, [thread_command_bytes(payload)]
        ) as path:
            header, lc, command = first_thread_command(path)
            command = command.thread_states
            self.assertEqual(header.header.cputype, CPU_TYPE_X86_64)
            self.assertEqual(lc.cmd, LC_UNIXTHREAD)
            self.assertEqual(command.endian, "<")
            self.assertEqual(len(command.states), 1)
            state = command.states[0]
            self.assertTrue(state.supported)
            self.assertEqual(state.count, 42)
            self.assertEqual(state.size, 168)
            self.assertEqual(state.registers["r12"], 0xABCDEF0012345678)
            self.assertEqual(state.registers["rip"], 0x0000000100003F90)
            self.assertEqual(command.pc, 0x0000000100003F90)
            self.assertEqual(command.sp, 0x7FFEE0A0C000)
            source = command.pc_source
            self.assertEqual(source.flavor, 4)
            self.assertEqual(source.flavor_name, "x86_THREAD_STATE64")
            self.assertEqual(source.field, "rip")
            self.assertEqual(source.state_offset, 0)
            self.assertEqual(source.field_offset, 128)
            self.assertEqual(source.offset, 8 + 128)
            sp_source = command.sp_source
            self.assertEqual(sp_source.field, "rsp")
            self.assertEqual(sp_source.field_offset, 56)
            self.assertEqual(sp_source.offset, 8 + 56)
            described = command.describe()
            self.assertTrue(described["pc"]["available"])
            self.assertEqual(described["pc"]["source"]["offset"], 136)
            self.assertEqual(described["states"][0]["count"], 42)

    def test_arm64_registers_and_field_sources(self):
        registers = {
            "x0": 0x1,
            "x28": 0x2828282828282828,
            "fp": 0x16FD0000B000,
            "lr": 0x000000018000ABCD,
            "sp": 0x16FD0000B000,
            "pc": 0x0000000100002A40,
            "cpsr": 0x80000000,
        }
        payload = state_bytes(6, 68, arm_thread_state64(registers), "<")
        with temporary_macho_file(
            CPU_TYPE_ARM64, [thread_command_bytes(payload)]
        ) as path:
            header, lc, command = first_thread_command(path)
            command = command.thread_states
            self.assertEqual(header.header.cputype, CPU_TYPE_ARM64)
            self.assertEqual(command.cputype_name, "ARM64")
            self.assertEqual(len(command.states), 1)
            state = command.states[0]
            self.assertEqual(state.flavor_name, "ARM_THREAD_STATE64")
            self.assertEqual(state.count, 68)
            self.assertEqual(state.size, 272)
            self.assertEqual(state.registers["x28"], 0x2828282828282828)
            self.assertEqual(command.pc, 0x0000000100002A40)
            self.assertEqual(command.sp, 0x16FD0000B000)
            source = command.pc_source
            self.assertEqual(source.flavor, 6)
            self.assertEqual(source.field, "pc")
            self.assertEqual(source.state_offset, 0)
            self.assertEqual(source.field_offset, 256)
            self.assertEqual(source.offset, 8 + 256)
            self.assertTrue(command.describe()["sp"]["available"])

    def test_multiple_states_align_after_previous_count(self):
        unknown_state = b"\xAA\xBB\xCC\xDD" * 3
        registers = {"rip": 0x0000000100001000, "rsp": 0x7FFFFFFF0000}
        payload = state_bytes(4, 42, x86_thread_state64(registers), "<")
        payload += state_bytes(0x1BAD, 3, unknown_state, "<")
        with temporary_macho_file(
            CPU_TYPE_X86_64, [thread_command_bytes(payload)]
        ) as path:
            _header, _lc, command = first_thread_command(path)
            command = command.thread_states
            self.assertEqual(len(command.states), 2)
            first, second = command.states
            self.assertEqual(first.supported, True)
            self.assertEqual(second.state_index, 1)
            self.assertEqual(second.offset, 8 + 168)
            self.assertEqual(second.data_offset, 16 + 168)
            self.assertEqual(second.flavor, 0x1BAD)
            self.assertIsNone(second.flavor_name)
            self.assertFalse(second.supported)
            self.assertIsNone(second.registers)
            self.assertEqual(second.raw, unknown_state)
            self.assertEqual(second.size, 12)
            described = second.describe()
            self.assertFalse(described["pc"]["available"])
            self.assertFalse(described["sp"]["available"])
            self.assertEqual(
                described["raw_hex"], "aabbccddaabbccddaabbccdd"
            )
            self.assertEqual(command.pc_source.field, "rip")

    def test_unknown_flavor_only_keeps_raw_bytes(self):
        payload = state_bytes(0xDEAD, 2, b"\x11\x22\x33\x44\x55\x66\x77\x88", "<")
        with temporary_macho_file(
            CPU_TYPE_ARM64, [thread_command_bytes(payload)]
        ) as path:
            _header, _lc, command = first_thread_command(path)
            command = command.thread_states
            empty = parse_thread_states(b"", CPU_TYPE_ARM64, "<")
            self.assertEqual(empty.states, [])
            self.assertFalse(empty.pc_available)
            self.assertFalse(empty.sp_available)
            state = command.states[0]
            self.assertEqual(state.flavor, 0xDEAD)
            self.assertIsNone(state.flavor_name)
            self.assertFalse(state.supported)
            self.assertEqual(
                state.raw, b"\x11\x22\x33\x44\x55\x66\x77\x88"
            )
            self.assertIsNone(state.pc)
            self.assertIsNone(state.sp)
            self.assertFalse(command.pc_available)
            self.assertFalse(command.sp_available)

    def test_x86_layout_is_not_applied_to_arm64(self):
        x86_looking = x86_thread_state64({"rip": 0x1234, "rsp": 0x5678})
        self.assertTrue(thread_state_layout(CPU_TYPE_X86_64, 4))
        self.assertEqual(thread_state_layout(CPU_TYPE_ARM64, 4), None)
        payload = state_bytes(4, 42, x86_looking, "<")
        with temporary_macho_file(
            CPU_TYPE_ARM64, [thread_command_bytes(payload)]
        ) as path:
            _header, _lc, command = first_thread_command(path)
            state = command.thread_states.states[0]
            self.assertEqual(state.flavor, 4)
            self.assertFalse(state.supported)
            self.assertIsNone(state.registers)
            self.assertIsNone(state.pc)
            self.assertFalse(command.thread_states.pc_available)
            self.assertFalse(command.thread_states.sp_available)

    def test_arm64_layout_is_not_applied_to_x86(self):
        self.assertTrue(thread_state_layout(CPU_TYPE_ARM64, 6))
        self.assertEqual(
            thread_state_layout(CPU_TYPE_X86_64, 6), "x86_EXCEPTION_STATE64"
        )
        # x86 flavor 6 is the exception state; an arm64 thread state must
        # not be decoded as it even when the counts happen to overlap.
        payload = state_bytes(6, 6, b"\x00" * 24, "<")
        with temporary_macho_file(
            CPU_TYPE_X86_64, [thread_command_bytes(payload)]
        ) as path:
            _header, _lc, command = first_thread_command(path)
            state = command.thread_states.states[0]
            self.assertTrue(state.supported)
            self.assertEqual(state.flavor_name, "x86_EXCEPTION_STATE64")
            self.assertIsNone(state.pc)
            self.assertIsNone(state.sp)
            self.assertFalse(command.thread_states.pc_available)

    def test_count_is_in_32_bit_words(self):
        # 21 64-bit words are 168 bytes when mistaken for 8-byte words, but
        # ``count`` counts 32-bit words, so 21 means 84 bytes: too short for
        # x86_THREAD_STATE64 and it must be rejected rather than zero-filled.
        payload = state_bytes(4, 21, x86_thread_state64({}), "<")
        with self.assertRaises(ThreadStateError) as context:
            parse_thread_states(payload, CPU_TYPE_X86_64, "<")
        error = context.exception
        self.assertEqual(error.offset, 0)
        self.assertEqual(error.data_offset, 8)
        self.assertEqual(error.flavor, 4)
        self.assertEqual(error.count, 21)
        self.assertEqual(error.needed, 168)
        self.assertEqual(error.available, 84)
        self.assertIn("too short", str(error))

    def test_truncated_state_reports_exact_offset(self):
        payload = state_bytes(6, 68, arm_thread_state64({})[:-1], "<")
        with self.assertRaises(ThreadStateError) as context:
            parse_thread_states(payload, CPU_TYPE_ARM64, "<")
        error = context.exception
        self.assertEqual(error.offset, 0)
        self.assertEqual(error.data_offset, 8)
        self.assertEqual(error.flavor, 6)
        self.assertEqual(error.count, 68)
        self.assertEqual(error.needed, 272)
        self.assertEqual(error.available, 271)
        self.assertIn("truncated", str(error))

    def test_truncated_second_pair_reports_its_offset(self):
        first = state_bytes(4, 42, x86_thread_state64({"rip": 1}), "<")
        payload = first + b"\x03\x00"
        with self.assertRaises(ThreadStateError) as context:
            parse_thread_states(payload, CPU_TYPE_X86_64, "<")
        error = context.exception
        self.assertEqual(error.offset, 176)
        self.assertEqual(error.needed, 8)
        self.assertEqual(error.available, 2)

    def test_truncated_second_state_after_aligned_first(self):
        first = state_bytes(4, 42, x86_thread_state64({"rip": 1}), "<")
        second = state_bytes(0xFEED, 4, b"\x01\x02\x03\x04" * 3, "<")
        payload = first + second
        with self.assertRaises(ThreadStateError) as context:
            parse_thread_states(payload, CPU_TYPE_X86_64, "<")
        error = context.exception
        self.assertEqual(error.offset, 176)
        self.assertEqual(error.data_offset, 184)
        self.assertEqual(error.flavor, 0xFEED)
        self.assertEqual(error.count, 4)
        self.assertEqual(error.needed, 16)
        self.assertEqual(error.available, 12)
        self.assertIsNone(error.command_index)

    def test_big_endian_file_decodes_big_endian_state(self):
        registers = {"rip": 0x0000000100001000, "rsp": 0x7FFFFFFF0000}
        words = struct.unpack("<21Q", x86_thread_state64(registers))
        state = b"".join(struct.pack(">Q", value) for value in words)
        payload = state_bytes(4, 42, state, ">")
        command = thread_command_bytes(payload, ">")
        with temporary_macho_file(
            CPU_TYPE_X86_64, [command], endian=">"
        ) as path:
            header, _lc, parsed = first_thread_command(path)
            self.assertEqual(header.endian, ">")
            parsed = parsed.thread_states
            self.assertEqual(parsed.endian, ">")
            self.assertEqual(parsed.states[0].registers["rip"], 0x0000000100001000)
            self.assertEqual(parsed.states[0].registers["rsp"], 0x7FFFFFFF0000)
            self.assertEqual(parsed.pc_source.offset, 136)
            self.assertEqual(
                parsed.states[0].raw, state
            )

    def test_mixed_endian_flavor_pair_is_rejected_by_length(self):
        # Flavor/count read with the wrong byte order would see count 42 as
        # little-endian value; make sure the decoder follows the file order
        # and rejects a pair whose words run past the payload.
        payload = struct.pack("<II", 4, 42) + x86_thread_state64({})
        with self.assertRaises(ThreadStateError):
            parse_thread_states(payload, CPU_TYPE_X86_64, ">")


class TestMoreThreadStateCases(unittest.TestCase):
    def test_i386_thread_state32(self):
        registers = {"eip": 0x00004000, "esp": 0xBFFFF000, "eax": 0x12345678}
        state = x86_thread_state32(registers)
        payload = state_bytes(1, 16, state, "<")
        with temporary_macho_file(
            CPU_TYPE_I386, [thread_command_bytes(payload, cmd=LC_THREAD)], size=32
        ) as path:
            header, lc, command = first_thread_command(path)
            command = command.thread_states
            self.assertEqual(header.header.cputype, CPU_TYPE_I386)
            self.assertEqual(lc.cmd, LC_THREAD)
            self.assertEqual(command.states[0].flavor_name, "x86_THREAD_STATE32")
            self.assertEqual(command.states[0].count, 16)
            self.assertEqual(command.states[0].size, 64)
            self.assertEqual(command.states[0].registers["eax"], 0x12345678)
            self.assertEqual(command.pc, 0x00004000)
            self.assertEqual(command.sp, 0xBFFFF000)
            self.assertEqual(command.pc_source.field, "eip")
            self.assertEqual(command.pc_source.field_offset, 40)
            self.assertEqual(command.pc_source.offset, 8 + 40)

    def test_x86_32_flavor_is_not_64_bit(self):
        payload = state_bytes(1, 16, x86_thread_state32({"eip": 0x1}), "<")
        command = parse_thread_states(payload, CPU_TYPE_X86_64, "<")
        self.assertEqual(command.states[0].flavor_name, "x86_THREAD_STATE32")
        self.assertEqual(command.pc, 0x1)
        self.assertEqual(command.pc_source.offset, 8 + 40)

    def test_i386_64_bit_flavor_is_unknown(self):
        payload = state_bytes(4, 42, x86_thread_state64({"rip": 0x1234}), "<")
        command = parse_thread_states(payload, CPU_TYPE_I386, "<")
        self.assertFalse(command.states[0].supported)
        self.assertFalse(command.pc_available)

    def test_arm_thread_state32(self):
        state = b"".join(struct.pack("<I", value) for value in range(17))
        payload = state_bytes(1, 17, state, "<")
        command = parse_thread_states(payload, CPU_TYPE_ARM, "<")
        state_description = command.states[0]
        self.assertEqual(state_description.flavor_name, "ARM_THREAD_STATE")
        self.assertEqual(state_description.count, 17)
        self.assertEqual(state_description.registers["r12"], 12)
        self.assertEqual(state_description.registers["sp"], 13)
        self.assertEqual(state_description.registers["pc"], 15)
        self.assertEqual(command.pc, 15)
        self.assertEqual(command.sp, 13)
        self.assertEqual(command.pc_source.field, "pc")
        self.assertEqual(command.pc_source.field_offset, 60)

    def test_arm_exception_state_has_no_pc_or_sp(self):
        payload = state_bytes(3, 3, b"\x01\x02\x03\x04" * 3, "<")
        command = parse_thread_states(payload, CPU_TYPE_ARM, "<")
        state_description = command.states[0]
        self.assertTrue(state_description.supported)
        self.assertEqual(state_description.flavor_name, "ARM_EXCEPTION_STATE")
        self.assertFalse(state_description.pc_available)
        self.assertFalse(state_description.sp_available)
        self.assertFalse(command.pc_available)
        self.assertFalse(command.sp_available)

    def test_arm_unified_flavor_is_raw(self):
        payload = state_bytes(1, 68, b"\x00" * 272, "<")
        command = parse_thread_states(payload, CPU_TYPE_ARM64, "<")
        self.assertEqual(command.states[0].flavor, 1)
        self.assertEqual(command.states[0].flavor_name, "ARM_UNIFIED_THREAD_STATE")
        self.assertFalse(command.states[0].supported)
        self.assertEqual(command.states[0].size, 272)

    def test_large_count_is_rejected_without_padding(self):
        payload = state_bytes(4, 0x10000001, b"\x00" * 168, "<")
        with self.assertRaises(ThreadStateError) as context:
            parse_thread_states(payload, CPU_TYPE_X86_64, "<")
        self.assertEqual(context.exception.count, 0x10000001)
        self.assertEqual(context.exception.needed, 0x10000001 * 4)

    def test_overlong_known_state_keeps_extra_bytes(self):
        registers = {"rip": 0x1000, "rsp": 0x2000}
        extra = b"\xAA" * 16
        payload = state_bytes(4, 46, x86_thread_state64(registers) + extra, "<")
        command = parse_thread_states(payload, CPU_TYPE_X86_64, "<")
        state_description = command.states[0]
        self.assertTrue(state_description.supported)
        self.assertEqual(state_description.size, 184)
        self.assertEqual(state_description.extra, extra)
        self.assertEqual(command.pc, 0x1000)
        self.assertEqual(command.sp, 0x2000)
        described = state_description.describe()
        self.assertEqual(described["extra_size"], 16)
        self.assertEqual(described["extra_hex"], "aa" * 16)
        self.assertEqual(len(described["raw_hex"]), 2 * 184)

    def test_unknown_state_follows_overlong_known_state(self):
        registers = {"rip": 0x1}
        first = state_bytes(4, 44, x86_thread_state64(registers) + b"\xAA" * 8, "<")
        second = state_bytes(0xBEEF, 2, b"\x01" * 8, "<")
        payload = first + second
        command = parse_thread_states(payload, CPU_TYPE_X86_64, "<")
        self.assertEqual(command.states[1].offset, 8 + 176)
        self.assertEqual(command.states[1].flavor, 0xBEEF)
        self.assertEqual(command.states[1].raw, b"\x01" * 8)
        self.assertEqual(command.pc, 0x1)


class TestThreadCommandFileErrors(unittest.TestCase):
    def test_command_larger_than_file_is_rejected(self):
        payload = state_bytes(4, 42, x86_thread_state64({"rip": 0x1234}), "<")
        command = thread_command_bytes(payload)
        # Trim two bytes from the file while leaving cmdsize untouched.
        command = command[:-2]
        with temporary_macho_file(CPU_TYPE_X86_64, [command]) as path:
            with self.assertRaises(ThreadStateError) as context:
                MachO(path)
        error = context.exception
        self.assertEqual(error.needed, 168)
        self.assertEqual(error.available, 166)
        self.assertEqual(error.command_index, 0)

    def test_cmdsize_too_small_for_flavor_pair(self):
        command = struct.pack("<II", LC_UNIXTHREAD, 8)
        with temporary_macho_file(CPU_TYPE_X86_64, [command]) as path:
            with self.assertRaises(ThreadStateError) as context:
                MachO(path)
            error = context.exception
            self.assertEqual(error.needed, 8)
            self.assertEqual(error.available, 0)
            self.assertEqual(error.command_index, 0)

    def test_state_larger_than_cmdsize_is_rejected(self):
        registers = x86_thread_state64({"rip": 0x1234})
        payload = state_bytes(4, 45, registers, "<")
        with temporary_macho_file(
            CPU_TYPE_X86_64, [thread_command_bytes(payload)]
        ) as path:
            with self.assertRaises(ThreadStateError) as context:
                MachO(path)
            error = context.exception
            self.assertEqual(error.offset, 0)
            self.assertEqual(error.flavor, 4)
            self.assertEqual(error.count, 45)
            self.assertEqual(error.needed, 180)
            self.assertEqual(error.available, 168)

    def test_dump_output_reports_unknown_state_raw(self):
        payload = state_bytes(0xDEAD, 2, b"\x11" * 8, "<")
        with temporary_macho_file(
            CPU_TYPE_X86_64, [thread_command_bytes(payload)]
        ) as path:
            output = io.StringIO()
            macho_dump.print_file(output, path)
        text = output.getvalue()
        self.assertIn("flavor=57005 (unknown) count=2 bytes=8", text)
        self.assertIn("raw=1111111111111111", text)
        self.assertEqual(text.count("unavailable"), 2)

    def test_thread_command_describe_includes_states(self):
        payload = state_bytes(4, 42, x86_thread_state64({"rip": 0x40}), "<")
        with temporary_macho_file(
            CPU_TYPE_X86_64, [thread_command_bytes(payload)]
        ) as path:
            _header, _lc, command = first_thread_command(path)
        described = command.describe()
        self.assertEqual(described["flavor"], 4)
        self.assertEqual(described["count"], 42)
        self.assertEqual(described["thread_states"]["pc"]["value"], 0x40)
        self.assertEqual(len(described["thread_states"]["states"]), 1)

    def test_parse_does_not_pad_or_invent_registers(self):
        payload = state_bytes(6, 68, arm_thread_state64({"pc": 0x1000})[:-8], "<")
        try:
            parse_thread_states(payload, CPU_TYPE_ARM64, "<")
        except ThreadStateError as error:
            self.assertEqual(error.available, 264)
        else:
            self.fail("a truncated known state must not decode")


if __name__ == "__main__":
    unittest.main()
