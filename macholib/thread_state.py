"""
Read-only decoding of the thread states stored in ``LC_THREAD`` and
``LC_UNIXTHREAD`` load commands.

A thread command stores one or more ``(flavor, count)`` pairs.  The
``count`` field is a number of 32-bit words, also for 64-bit register
layouts (it is a ``mach_msg_type_number_t``), and both the pair header
and the register values use the byte order of the containing Mach-O
header.

Only well-known CPU/flavor combinations are decoded into registers.
Everything else is preserved as raw bytes.  Truncated or otherwise
inconsistent states are rejected with :class:`ThreadStateError`; this
module never pads a short state with zeroes, and it never restores or
runs a thread.
"""

import binascii
import struct

LC_THREAD = 0x4
LC_UNIXTHREAD = 0x5

THREAD_COMMAND_NAMES = {
    LC_THREAD: "LC_THREAD",
    LC_UNIXTHREAD: "LC_UNIXTHREAD",
}

CPU_TYPE_I386 = 7
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM = 12
CPU_TYPE_ARM64 = 0x0100000C

CPU_TYPE_NAMES = {
    CPU_TYPE_I386: "i386",
    CPU_TYPE_X86_64: "x86_64",
    CPU_TYPE_ARM: "ARM",
    CPU_TYPE_ARM64: "ARM64",
}

_FIELD_FORMATS = {2: "H", 4: "I", 8: "Q"}


class ThreadStateError(ValueError):
    """
    Raised when a thread command cannot be decoded without inventing data.

    Offsets are relative to the start of the thread command payload, that
    is the byte containing the first ``flavor`` value.  ``offset`` locates
    the ``(flavor, count)`` pair, ``data_offset`` locates its state data
    and ``available`` is the number of bytes actually present from
    ``data_offset`` onwards.
    """

    def __init__(
        self,
        message,
        offset=None,
        data_offset=None,
        flavor=None,
        count=None,
        needed=None,
        available=None,
        command_index=None,
    ):
        ValueError.__init__(self, message)
        self.offset = offset
        self.data_offset = data_offset
        self.flavor = flavor
        self.count = count
        self.needed = needed
        self.available = available
        self.command_index = command_index


class RegisterReference(object):
    """
    Where a register value came from in the original command payload.

    ``offset`` is the absolute payload offset of the register value,
    ``state_offset`` the payload offset of the ``(flavor, count)`` pair
    and ``field_offset`` the offset of the field inside the state data.
    """

    __slots__ = (
        "state_index",
        "flavor",
        "flavor_name",
        "field",
        "value",
        "state_offset",
        "field_offset",
        "offset",
        "size",
    )

    def __init__(
        self,
        state_index,
        flavor,
        flavor_name,
        field,
        value,
        state_offset,
        field_offset,
        offset,
        size,
    ):
        self.state_index = state_index
        self.flavor = flavor
        self.flavor_name = flavor_name
        self.field = field
        self.value = value
        self.state_offset = state_offset
        self.field_offset = field_offset
        self.offset = offset
        self.size = size

    def __repr__(self):
        return "<%s %r=%#x at %d>" % (
            type(self).__name__,
            str(self),
            self.value,
            self.offset,
        )

    def __str__(self):
        return "%s.%s" % (self.flavor_name, self.field)

    def describe(self):
        return {
            "flavor": self.flavor,
            "flavor_name": self.flavor_name,
            "field": self.field,
            "state_index": self.state_index,
            "state_offset": self.state_offset,
            "field_offset": self.field_offset,
            "offset": self.offset,
            "size": self.size,
        }


class _Layout(object):
    __slots__ = ("name", "fields", "offsets", "pc", "sp", "size", "format")

    def __init__(self, name, fields, pc=None, sp=None):
        self.name = name
        self.fields = fields
        self.pc = pc
        self.sp = sp
        offsets = []
        current = 0
        format_chars = []
        for _field_name, field_size in fields:
            offsets.append((current, field_size))
            format_chars.append(_FIELD_FORMATS[field_size])
            current += field_size
        self.offsets = dict(
            (field_name, offsets[index])
            for index, (field_name, _field_size) in enumerate(fields)
        )
        self.size = current
        self.format = "".join(format_chars)

    @property
    def count(self):
        """The expected ``count`` value, in 32-bit words."""
        return self.size // 4


def _fields(names, size):
    return [(name, size) for name in names]


_X86_THREAD_STATE32 = _Layout(
    "x86_THREAD_STATE32",
    _fields(
        (
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
        ),
        4,
    ),
    pc="eip",
    sp="esp",
)

_X86_EXCEPTION_STATE32 = _Layout(
    "x86_EXCEPTION_STATE32",
    [("trapno", 2), ("cpu", 2), ("err", 4), ("faultvaddr", 4)],
)

_X86_THREAD_STATE64 = _Layout(
    "x86_THREAD_STATE64",
    _fields(
        (
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
        ),
        8,
    ),
    pc="rip",
    sp="rsp",
)

_X86_EXCEPTION_STATE64 = _Layout(
    "x86_EXCEPTION_STATE64",
    [("trapno", 2), ("cpu", 2), ("err", 4), ("faultvaddr", 8)],
)

_X86_THREAD_FULL_STATE64 = _Layout(
    "x86_THREAD_FULL_STATE64",
    _fields(
        (
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
            "ds",
            "es",
            "ss",
            "gsbase",
        ),
        8,
    ),
    pc="rip",
    sp="rsp",
)

_ARM_THREAD_STATE = _Layout(
    "ARM_THREAD_STATE",
    _fields(tuple("r%d" % index for index in range(13)), 4)
    + [("sp", 4), ("lr", 4), ("pc", 4), ("cpsr", 4)],
    pc="pc",
    sp="sp",
)

_ARM_EXCEPTION_STATE = _Layout(
    "ARM_EXCEPTION_STATE",
    [("exception", 4), ("fsr", 4), ("far", 4)],
)

_ARM_THREAD_STATE64 = _Layout(
    "ARM_THREAD_STATE64",
    _fields(tuple("x%d" % index for index in range(29)), 8)
    + [("fp", 8), ("lr", 8), ("sp", 8), ("pc", 8), ("cpsr", 4), ("pad", 4)],
    pc="pc",
    sp="sp",
)

_ARM_EXCEPTION_STATE64 = _Layout(
    "ARM_EXCEPTION_STATE64",
    [("far", 8), ("esr", 4), ("exception", 4)],
)

_ARM_EXCEPTION_STATE64_V2 = _Layout(
    "ARM_EXCEPTION_STATE64_V2",
    [("far", 8), ("esr", 8)],
)

_CPU_FLAVORS = {
    CPU_TYPE_I386: {
        1: _X86_THREAD_STATE32,
        2: None,
        3: _X86_EXCEPTION_STATE32,
        7: None,
    },
    CPU_TYPE_X86_64: {
        1: _X86_THREAD_STATE32,
        2: None,
        3: _X86_EXCEPTION_STATE32,
        4: _X86_THREAD_STATE64,
        5: None,
        6: _X86_EXCEPTION_STATE64,
        7: None,
        8: None,
        9: None,
        23: _X86_THREAD_FULL_STATE64,
        24: None,
        25: None,
    },
    CPU_TYPE_ARM: {
        1: _ARM_THREAD_STATE,
        2: None,
        3: _ARM_EXCEPTION_STATE,
        4: None,
        5: None,
    },
    CPU_TYPE_ARM64: {
        1: None,
        2: None,
        3: None,
        6: _ARM_THREAD_STATE64,
        7: _ARM_EXCEPTION_STATE64,
        9: None,
        10: _ARM_EXCEPTION_STATE64_V2,
    },
}

_FLAVOR_NAMES = {
    CPU_TYPE_I386: {
        1: "x86_THREAD_STATE32",
        2: "x86_FLOAT_STATE32",
        3: "x86_EXCEPTION_STATE32",
        7: "x86_THREAD_STATE",
    },
    CPU_TYPE_X86_64: {
        1: "x86_THREAD_STATE32",
        2: "x86_FLOAT_STATE32",
        3: "x86_EXCEPTION_STATE32",
        4: "x86_THREAD_STATE64",
        5: "x86_FLOAT_STATE64",
        6: "x86_EXCEPTION_STATE64",
        7: "x86_THREAD_STATE",
        8: "x86_FLOAT_STATE",
        9: "x86_EXCEPTION_STATE",
        23: "x86_THREAD_FULL_STATE64",
        24: "x86_INSTRUCTION_STATE",
        25: "x86_LAST_BRANCH_STATE",
    },
    CPU_TYPE_ARM: {
        1: "ARM_THREAD_STATE",
        2: "ARM_VFP_STATE",
        3: "ARM_EXCEPTION_STATE",
        4: "ARM_DEBUG_STATE",
        5: "THREAD_STATE_NONE",
    },
    CPU_TYPE_ARM64: {
        1: "ARM_UNIFIED_THREAD_STATE",
        2: "ARM_VFP_STATE",
        3: "ARM_EXCEPTION_STATE",
        4: "ARM_DEBUG_STATE",
        5: "THREAD_STATE_NONE",
        6: "ARM_THREAD_STATE64",
        7: "ARM_EXCEPTION_STATE64",
        9: "ARM_THREAD_STATE32",
        10: "ARM_EXCEPTION_STATE64_V2",
    },
}


def thread_state_flavor_name(cputype, flavor):
    """
    Return the documented name for a CPU/flavor pair, or ``None``.
    """
    return _FLAVOR_NAMES.get(int(cputype), {}).get(int(flavor))


def thread_state_layout(cputype, flavor):
    """
    Return the layout name for a decoded CPU/flavor pair, or ``None``.
    """
    layout = _CPU_FLAVORS.get(int(cputype), {}).get(int(flavor))
    if layout is None:
        return None
    return layout.name


def supported_cpu_types():
    """
    Return the CPU types for which at least one flavor is decoded.
    """
    return tuple(sorted(_CPU_FLAVORS))


def _endian_name(endian):
    return "little" if endian == "<" else "big"


class _RegisterAvailability(object):
    """
    Shared description of a ``pc``/``sp`` slot: availability, value and
    provenance.  A missing register is never represented as ``0``.
    """

    __slots__ = ()

    def _describe_register(self, available, value, source):
        return {
            "available": available,
            "value": value,
            "source": None if source is None else source.describe(),
        }


class ThreadState(_RegisterAvailability):
    """
    One ``(flavor, count)`` record from a thread command.

    ``raw`` always contains exactly ``count * 4`` bytes from the command.
    ``registers`` is ``None`` when the CPU/flavor combination is not
    decoded; the raw state is kept instead.  States whose declared count
    is larger than the known layout keep the trailing bytes in
    ``extra``; states whose count is smaller are rejected earlier and
    never zero-filled.
    """

    __slots__ = (
        "cputype",
        "endian",
        "state_index",
        "offset",
        "data_offset",
        "flavor",
        "flavor_name",
        "count",
        "size",
        "supported",
        "layout_size",
        "registers",
        "extra",
        "raw",
        "pc",
        "sp",
        "pc_source",
        "sp_source",
        "_field_offsets",
    )

    def __init__(
        self,
        cputype,
        endian,
        state_index,
        offset,
        flavor,
        count,
        raw,
        layout,
    ):
        self.cputype = cputype
        self.endian = endian
        self.state_index = state_index
        self.offset = offset
        self.data_offset = offset + 8
        self.flavor = flavor
        self.flavor_name = thread_state_flavor_name(cputype, flavor)
        self.count = count
        self.size = len(raw)
        self.raw = raw
        self.supported = layout is not None
        self.registers = None
        self.extra = None
        self._field_offsets = {}
        self.pc = None
        self.sp = None
        self.pc_source = None
        self.sp_source = None

        if layout is None:
            self.layout_size = None
            return

        self.layout_size = layout.size
        values = struct.unpack(endian + layout.format, raw[: layout.size])
        self.registers = dict(
            (layout.fields[index][0], values[index])
            for index in range(len(layout.fields))
        )
        self._field_offsets = layout.offsets
        if len(raw) > layout.size:
            self.extra = raw[layout.size :]  # noqa: E203

        if layout.pc is not None:
            self.pc = self.registers[layout.pc]
            self.pc_source = self.register_source(layout.pc)
        if layout.sp is not None:
            self.sp = self.registers[layout.sp]
            self.sp_source = self.register_source(layout.sp)
    @property
    def pc_available(self):
        return self.pc_source is not None

    @property
    def sp_available(self):
        return self.sp_source is not None

    def register_source(self, name):
        """
        Return a :class:`RegisterReference` for a decoded register, or
        ``None`` when the register is not available.
        """
        if not self.supported or name not in self._field_offsets:
            return None
        field_offset, field_size = self._field_offsets[name]
        return RegisterReference(
            state_index=self.state_index,
            flavor=self.flavor,
            flavor_name=self.flavor_name,
            field=name,
            value=self.registers[name],
            state_offset=self.offset,
            field_offset=field_offset,
            offset=self.data_offset + field_offset,
            size=field_size,
        )

    def describe(self):
        return {
            "state_index": self.state_index,
            "offset": self.offset,
            "data_offset": self.data_offset,
            "flavor": self.flavor,
            "flavor_name": self.flavor_name,
            "count": self.count,
            "size": self.size,
            "layout_size": self.layout_size,
            "supported": self.supported,
            "raw_hex": binascii.hexlify(self.raw).decode("ascii"),
            "registers": self.registers,
            "extra_size": 0 if self.extra is None else len(self.extra),
            "extra_hex": (
                None
                if self.extra is None
                else binascii.hexlify(self.extra).decode("ascii")
            ),
            "pc": self._describe_register(
                self.pc_available, self.pc, self.pc_source
            ),
            "sp": self._describe_register(
                self.sp_available, self.sp, self.sp_source
            ),
        }


class ThreadStateCommand(_RegisterAvailability):
    """
    All states found in one ``LC_THREAD``/``LC_UNIXTHREAD`` command.

    ``cmd`` is the load command number, ``payload`` the exact bytes of
    the command after its ``load_command`` header and ``states`` the
    decoded records in file order.  ``pc``/``sp`` and their sources
    come from the first state in the command that provides them.
    """

    __slots__ = (
        "cmd",
        "cmd_name",
        "cputype",
        "cputype_name",
        "endian",
        "states",
        "payload",
        "pc",
        "pc_source",
        "sp",
        "sp_source",
    )

    def __init__(self, cmd, cputype, endian, states, payload):
        self.cmd = cmd
        self.cmd_name = THREAD_COMMAND_NAMES.get(cmd)
        self.cputype = cputype
        self.cputype_name = CPU_TYPE_NAMES.get(cputype)
        self.endian = endian
        self.states = states
        self.payload = payload
        self.pc = None
        self.pc_source = None
        self.sp = None
        self.sp_source = None
        for state in states:
            if self.pc_source is None and state.pc_source is not None:
                self.pc = state.pc
                self.pc_source = state.pc_source
            if self.sp_source is None and state.sp_source is not None:
                self.sp = state.sp
                self.sp_source = state.sp_source

    @property
    def pc_available(self):
        return self.pc_source is not None

    @property
    def sp_available(self):
        return self.sp_source is not None

    @property
    def has_unsupported_states(self):
        return any(not state.supported for state in self.states)

    def describe(self):
        return {
            "cmd": self.cmd,
            "cmd_name": self.cmd_name,
            "cputype": self.cputype,
            "cputype_name": self.cputype_name,
            "endian": _endian_name(self.endian),
            "pc": self._describe_register(
                self.pc_available, self.pc, self.pc_source
            ),
            "sp": self._describe_register(
                self.sp_available, self.sp, self.sp_source
            ),
            "states": [state.describe() for state in self.states],
        }


def parse_thread_states(payload, cputype, endian="<", cmd=LC_THREAD):
    """
    Decode the payload of a thread command.

    *payload* starts at the first ``flavor`` field (everything after the
    load command's 8-byte ``cmd``/``cmdsize`` header).  *endian* must be
    ``"<"`` or ``">"`` and must match the containing Mach-O header.  A
    command may contain several ``(flavor, count)`` pairs; each record is
    consumed as ``8 + count * 4`` bytes, where ``count`` is a number of
    32-bit words.

    Unknown CPU/flavor combinations are returned with their raw bytes.
    Truncated or inconsistent records raise :class:`ThreadStateError`
    with the exact payload offset of the rejected record.
    """
    cputype = int(cputype)
    if endian not in ("<", ">"):
        raise ValueError("endian must be '<' or '>': %r" % (endian,))
    if not isinstance(payload, bytes):
        raise TypeError("thread state payload must be bytes")

    states = []
    offset = 0
    length = len(payload)
    layouts = _CPU_FLAVORS.get(cputype, {})

    while offset < length:
        remaining = length - offset
        if remaining < 8:
            raise ThreadStateError(
                "thread command has %d trailing byte(s) at offset %d; "
                "a flavor/count pair needs 8 bytes"
                % (remaining, offset),
                offset=offset,
                needed=8,
                available=remaining,
            )
        flavor, count = struct.unpack_from(endian + "II", payload, offset)
        data_offset = offset + 8
        declared_size = count * 4
        available = length - data_offset
        if declared_size > available:
            raise ThreadStateError(
                "truncated thread state at offset %d: flavor %d declares "
                "%d bytes (%d 32-bit words) but only %d byte(s) are present"
                % (offset, flavor, declared_size, count, available),
                offset=offset,
                data_offset=data_offset,
                flavor=flavor,
                count=count,
                needed=declared_size,
                available=available,
            )

        layout = layouts.get(flavor)
        expected_size = None if layout is None else layout.size
        if layout is not None and declared_size < expected_size:
            raise ThreadStateError(
                "thread state at offset %d is too short for %s: flavor %d "
                "declares %d 32-bit words (%d bytes), the layout needs %d "
                "words (%d bytes)"
                % (
                    offset,
                    layout.name,
                    flavor,
                    count,
                    declared_size,
                    layout.count,
                    expected_size,
                ),
                offset=offset,
                data_offset=data_offset,
                flavor=flavor,
                count=count,
                needed=expected_size,
                available=declared_size,
            )

        raw = payload[data_offset : data_offset + declared_size]  # noqa: E203
        state = ThreadState(
            cputype=cputype,
            endian=endian,
            state_index=len(states),
            offset=offset,
            flavor=flavor,
            count=count,
            raw=raw,
            layout=layout,
        )
        states.append(state)
        offset = data_offset + declared_size

    return ThreadStateCommand(cmd, cputype, endian, states, payload)


parse_thread_command = parse_thread_states
