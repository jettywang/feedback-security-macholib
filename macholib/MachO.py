"""
Utilities for reading and writing Mach-O headers
"""

from __future__ import print_function

import os
import struct
import sys

from macholib.util import fileview

from .mach_o import (
    FAT_MAGIC,
    FAT_MAGIC_64,
    LC_CODE_SIGNATURE,
    LC_DYSYMTAB,
    LC_ID_DYLIB,
    LC_LOAD_DYLIB,
    LC_LOAD_UPWARD_DYLIB,
    LC_LOAD_WEAK_DYLIB,
    LC_PREBOUND_DYLIB,
    LC_REEXPORT_DYLIB,
    LC_REGISTRY,
    LC_SEGMENT,
    LC_SEGMENT_64,
    LC_SYMTAB,
    MH_CIGAM,
    MH_CIGAM_64,
    MH_FILETYPE_SHORTNAMES,
    MH_MAGIC,
    MH_MAGIC_64,
    S_ZEROFILL,
    fat_arch,
    fat_arch64,
    fat_header,
    load_command,
    mach_header,
    mach_header_64,
    section,
    section_64,
)
from .ptypes import sizeof

try:
    from macholib.compat import bytes
except ImportError:
    pass

try:
    unicode
except NameError:
    unicode = str

if sys.version_info[0] == 2:
    range = xrange  # noqa: F821

__all__ = [
    "MachO",
    "RewritePlan",
    "SlicePlan",
    "CommandChange",
    "InsufficientHeaderSpaceError",
]

_RELOCATABLE = {
    # relocatable commands that should be used for dependency walking
    LC_LOAD_DYLIB,
    LC_LOAD_UPWARD_DYLIB,
    LC_LOAD_WEAK_DYLIB,
    LC_PREBOUND_DYLIB,
    LC_REEXPORT_DYLIB,
}

_RELOCATABLE_NAMES = {
    LC_LOAD_DYLIB: "load_dylib",
    LC_LOAD_UPWARD_DYLIB: "load_upward_dylib",
    LC_LOAD_WEAK_DYLIB: "load_weak_dylib",
    LC_PREBOUND_DYLIB: "prebound_dylib",
    LC_REEXPORT_DYLIB: "reexport_dylib",
}


def _shouldRelocateCommand(cmd):
    """
    Should this command id be investigated for relocation?
    """
    return cmd in _RELOCATABLE


class InsufficientHeaderSpaceError(ValueError):
    """
    Raised when a planned rewrite cannot fit in the free space of a
    Mach-O header. Nothing is written when this is raised.
    """


class CommandChange(object):
    """
    A single planned modification of one string-bearing load command.

    All offsets are absolute file offsets. ``old_size``/``new_size`` are
    the full load command sizes (load_command + command body + string).
    """

    def __init__(
        self,
        command_index,
        cmd,
        command_name,
        old_path,
        new_path,
        file_offset,
        old_size,
        new_size,
        size_delta,
        string_offset,
        string_old_size,
        string_new_size,
    ):
        self.command_index = command_index
        self.cmd = cmd
        self.command_name = command_name
        self.old_path = old_path
        self.new_path = new_path
        self.file_offset = file_offset
        self.old_size = old_size
        self.new_size = new_size
        self.size_delta = size_delta
        self.string_offset = string_offset
        self.string_old_size = string_old_size
        self.string_new_size = string_new_size

    def __repr__(self):
        return (
            "<CommandChange index=%r name=%r old_path=%r new_path=%r "
            "offset=%d old_size=%d new_size=%d>"
            % (
                self.command_index,
                self.command_name,
                self.old_path,
                self.new_path,
                self.file_offset,
                self.old_size,
                self.new_size,
            )
        )

    def __eq__(self, other):
        if not isinstance(other, CommandChange):
            return NotImplemented
        return self.__dict__ == other.__dict__


class SlicePlan(object):
    """
    Read-only preflight result for one slice (architecture) of a Mach-O,
    possibly the sole slice of a thin file.

    ``changes`` lists every load command that would be rewritten with the
    exact byte range (``file_offset`` .. ``file_offset + old_size``) it
    currently occupies and the size it needs afterwards. The signature
    information explains why an existing LC_CODE_SIGNATURE stops being
    valid once any byte of the slice changes; the signature is never
    removed automatically.
    """

    def __init__(
        self,
        header,
        slice_index,
        cpu_type,
        cpu_subtype,
        file_offset,
        changes,
        header_size,
        max_header_size,
        free_space,
        size_delta,
        has_code_signature,
        code_signature_offset,
        code_signature_size,
        feasible,
        error,
    ):
        self.header = header
        self.slice_index = slice_index
        self.cpu_type = cpu_type
        self.cpu_subtype = cpu_subtype
        self.file_offset = file_offset
        self.changes = changes
        self.header_size = header_size
        self.max_header_size = max_header_size
        self.free_space = free_space
        self.size_delta = size_delta
        self.has_code_signature = has_code_signature
        self.code_signature_offset = code_signature_offset
        self.code_signature_size = code_signature_size
        self.feasible = feasible
        self.error = error

    @property
    def needs_resign(self):
        """True when this slice changes bytes and carries a signature."""
        return bool(self.changes) and self.has_code_signature

    @property
    def changed_command_indices(self):
        return [change.command_index for change in self.changes]

    def __repr__(self):
        return (
            "<SlicePlan slice_index=%d cpu_type=0x%x changes=%d feasible=%r "
            "needs_resign=%r>"
            % (
                self.slice_index,
                self.cpu_type,
                len(self.changes),
                self.feasible,
                self.needs_resign,
            )
        )


class RewritePlan(object):
    """
    Read-only preflight result for a whole (possibly fat) Mach-O file.

    The plan is the single source of truth shared between the preflight
    check and the actual write: ``MachO.apply_plan`` refuses to write when
    the on-disk headers no longer match this plan, and refuses outright
    when any slice is infeasible, so a file can never be half rewritten.
    """

    def __init__(self, filename, slice_plans):
        self.filename = filename
        self.slice_plans = slice_plans

    @property
    def feasible(self):
        return all(slice_plan.feasible for slice_plan in self.slice_plans)

    @property
    def changed_slices(self):
        return [
            slice_plan
            for slice_plan in self.slice_plans
            if slice_plan.changes
        ]

    @property
    def resigned_slices(self):
        return [
            slice_plan
            for slice_plan in self.slice_plans
            if slice_plan.needs_resign
        ]

    def errors(self):
        return [
            (slice_plan.slice_index, slice_plan.error)
            for slice_plan in self.slice_plans
            if not slice_plan.feasible
        ]

    def __repr__(self):
        return "<RewritePlan filename=%r feasible=%r slices=%d>" % (
            self.filename,
            self.feasible,
            len(self.slice_plans),
        )


def lc_str_value(offset, cmd_info):
    """
    Fetch the actual value of a field of type "lc_str"
    """
    cmd_load, cmd_cmd, cmd_data = cmd_info

    offset -= sizeof(cmd_load) + sizeof(cmd_cmd)
    return cmd_data[offset:].strip(b"\x00")


class MachO(object):
    """
    Provides reading/writing the Mach-O header of a specific existing file.

    If allow_unknown_load_commands is True, allows unknown load commands.
    Otherwise, raises ValueError if the file contains an unknown load command.
    """

    #   filename   - the original filename of this mach-o
    #   sizediff   - the current deviation from the initial mach-o size
    #   header     - the mach-o header
    #   commands   - a list of (load_command, somecommand, data)
    #                data is either a str, or a list of segment structures
    #   total_size - the current mach-o header size (including header)
    #   low_offset - essentially, the maximum mach-o header size
    #   id_cmd     - the index of my id command, or None

    def __init__(self, filename, allow_unknown_load_commands=False):
        # supports the ObjectGraph protocol
        self.graphident = filename
        self.filename = filename
        self.loader_path = os.path.dirname(filename)

        # initialized by load
        self.fat = None
        self.headers = []
        self.allow_unknown_load_commands = allow_unknown_load_commands
        with open(filename, "rb") as fp:
            self.load(fp)

    def __repr__(self):
        return "<MachO filename=%r>" % (self.filename,)

    def load(self, fh):
        assert fh.tell() == 0
        header = struct.unpack(">I", fh.read(4))[0]
        fh.seek(0)
        if header in (FAT_MAGIC, FAT_MAGIC_64):
            self.load_fat(fh)
        else:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(0)
            self.load_header(fh, 0, size)

    def load_fat(self, fh):
        self.fat = fat_header.from_fileobj(fh)
        if self.fat.magic == FAT_MAGIC:
            archs = [fat_arch.from_fileobj(fh) for i in range(self.fat.nfat_arch)]
        elif self.fat.magic == FAT_MAGIC_64:
            archs = [fat_arch64.from_fileobj(fh) for i in range(self.fat.nfat_arch)]
        else:
            raise ValueError("Unknown fat header magic: %r" % (self.fat.magic))

        for arch in archs:
            self.load_header(fh, arch.offset, arch.size)

    def rewriteLoadCommands(self, *args, **kw):
        changed = False
        for header in self.headers:
            if header.rewriteLoadCommands(*args, **kw):
                changed = True
        return changed

    def preflight_rewrite(self, changefunc):
        """
        Build a :class:`RewritePlan` describing what *changefunc* would do
        to every slice, without modifying the parsed headers or the file.

        The returned plan records the exact byte ranges of the load
        commands that would change, the header free space available, the
        size delta per slice and the LC_CODE_SIGNATURE state so callers
        know which slices must be re-signed. When a slice cannot fit the
        growth its plan is marked infeasible (with an explanatory error)
        and :meth:`apply_plan` will reject the whole file.
        """
        slice_plans = [
            header.plan_rewrite(index, changefunc)
            for index, header in enumerate(self.headers)
        ]
        return RewritePlan(self.filename, slice_plans)

    def apply_plan(self, plan, fileobj):
        """
        Apply a previously computed :class:`RewritePlan` to *fileobj*.

        The headers are re-checked against the plan first: the same file
        must still expose the same commands at the same offsets with the
        same sizes and old paths. When the plan is infeasible, or the
        headers drifted since the preflight, no byte is written and an
        exception is raised. Existing code signatures are preserved in
        place; the plan reports the slices that must be re-signed rather
        than stripping the signature to hide the modification.
        """
        if not isinstance(plan, RewritePlan):
            raise TypeError("expected a RewritePlan, got %r" % (type(plan),))
        if plan.filename != self.filename:
            raise ValueError(
                "plan was built for %r, cannot apply it to %r"
                % (plan.filename, self.filename)
            )
        if len(plan.slice_plans) != len(self.headers):
            raise ValueError(
                "plan covers %d slices, file now has %d"
                % (len(plan.slice_plans), len(self.headers))
            )
        if not plan.feasible:
            raise InsufficientHeaderSpaceError(
                "refusing to rewrite %r: %s"
                % (self.filename, plan.errors())
            )
        for header, slice_plan in zip(self.headers, plan.slice_plans):
            header.verify_plan(slice_plan)
        for header, slice_plan in zip(self.headers, plan.slice_plans):
            header.write_with_plan(slice_plan, fileobj)

    def load_header(self, fh, offset, size):
        fh.seek(offset)
        header = struct.unpack(">I", fh.read(4))[0]
        fh.seek(offset)
        if header == MH_MAGIC:
            magic, hdr, endian = MH_MAGIC, mach_header, ">"
        elif header == MH_CIGAM:
            magic, hdr, endian = MH_CIGAM, mach_header, "<"
        elif header == MH_MAGIC_64:
            magic, hdr, endian = MH_MAGIC_64, mach_header_64, ">"
        elif header == MH_CIGAM_64:
            magic, hdr, endian = MH_CIGAM_64, mach_header_64, "<"
        else:
            raise ValueError("Unknown Mach-O header: 0x%08x in %r" % (header, fh))
        hdr = MachOHeader(
            self, fh, offset, size, magic, hdr, endian, self.allow_unknown_load_commands
        )
        self.headers.append(hdr)

    def write(self, f):
        for header in self.headers:
            header.write(f)


class MachOHeader(object):
    """
    Provides reading/writing the Mach-O header of a specific existing file.

    If allow_unknown_load_commands is True, allows unknown load commands.
    Otherwise, raises ValueError if the file contains an unknown load command.
    """

    #   filename   - the original filename of this mach-o
    #   sizediff   - the current deviation from the initial mach-o size
    #   header     - the mach-o header
    #   commands   - a list of (load_command, somecommand, data)
    #                data is either a str, or a list of segment structures
    #   total_size - the current mach-o header size (including header)
    #   low_offset - essentially, the maximum mach-o header size
    #   id_cmd     - the index of my id command, or None

    def __init__(
        self,
        parent,
        fh,
        offset,
        size,
        magic,
        hdr,
        endian,
        allow_unknown_load_commands=False,
    ):
        self.MH_MAGIC = magic
        self.mach_header = hdr

        # These are all initialized by self.load()
        self.parent = parent
        self.offset = offset
        self.size = size

        self.endian = endian
        self.header = None
        self.commands = None
        self.id_cmd = None
        self.sizediff = None
        self.total_size = None
        self.low_offset = None
        self.filetype = None
        self.headers = []

        self.allow_unknown_load_commands = allow_unknown_load_commands

        self.load(fh)

    def __repr__(self):
        return "<%s filename=%r offset=%d size=%d endian=%r>" % (
            type(self).__name__,
            self.parent.filename,
            self.offset,
            self.size,
            self.endian,
        )

    def load(self, fh):
        fh = fileview(fh, self.offset, self.size)
        fh.seek(0)

        self.sizediff = 0
        kw = {"_endian_": self.endian}
        header = self.mach_header.from_fileobj(fh, **kw)
        self.header = header
        # if header.magic != self.MH_MAGIC:
        #    raise ValueError("header has magic %08x, expecting %08x" % (
        #        header.magic, self.MH_MAGIC))

        cmd = self.commands = []

        self.filetype = self.get_filetype_shortname(header.filetype)

        read_bytes = 0
        low_offset = sys.maxsize
        for i in range(header.ncmds):
            # read the load command
            cmd_load = load_command.from_fileobj(fh, **kw)

            # read the specific command
            klass = LC_REGISTRY.get(cmd_load.cmd, None)
            if klass is None:
                if not self.allow_unknown_load_commands:
                    raise ValueError("Unknown load command: %d" % (cmd_load.cmd,))
                # No load command in the registry, so append the load command itself
                # instead of trying to deserialize the data after the header.
                data_size = cmd_load.cmdsize - sizeof(load_command)
                cmd_data = fh.read(data_size)
                cmd.append((cmd_load, cmd_load, cmd_data))
                read_bytes += cmd_load.cmdsize
                continue

            cmd_cmd = klass.from_fileobj(fh, **kw)

            if cmd_load.cmd == LC_ID_DYLIB:
                # remember where this command was
                if self.id_cmd is not None:
                    raise ValueError("This dylib already has an id")
                self.id_cmd = i

            if cmd_load.cmd in (LC_SEGMENT, LC_SEGMENT_64):
                # for segment commands, read the list of segments
                segs = []
                # assert that the size makes sense
                if cmd_load.cmd == LC_SEGMENT:
                    section_cls = section
                else:  # LC_SEGMENT_64
                    section_cls = section_64

                expected_size = (
                    sizeof(klass)
                    + sizeof(load_command)
                    + (sizeof(section_cls) * cmd_cmd.nsects)
                )
                if cmd_load.cmdsize != expected_size:
                    raise ValueError("Segment size mismatch")
                # this is a zero block or something
                # so the beginning is wherever the fileoff of this command is
                if cmd_cmd.nsects == 0:
                    if cmd_cmd.filesize != 0:
                        low_offset = min(low_offset, cmd_cmd.fileoff)
                else:
                    # this one has multiple segments
                    for _j in range(cmd_cmd.nsects):
                        # read the segment
                        seg = section_cls.from_fileobj(fh, **kw)
                        # if the segment has a size and is not zero filled
                        # then its beginning is the offset of this segment
                        not_zerofill = (seg.flags & S_ZEROFILL) != S_ZEROFILL
                        if seg.offset > 0 and seg.size > 0 and not_zerofill:
                            low_offset = min(low_offset, seg.offset)
                        if not_zerofill:
                            c = fh.tell()
                            fh.seek(seg.offset)
                            sd = fh.read(seg.size)
                            seg.add_section_data(sd)
                            fh.seek(c)
                        segs.append(seg)
                # data is a list of segments
                cmd_data = segs

            # These are disabled for now because writing back doesn't work
            # elif cmd_load.cmd == LC_CODE_SIGNATURE:
            #    c = fh.tell()
            #    fh.seek(cmd_cmd.dataoff)
            #    cmd_data = fh.read(cmd_cmd.datasize)
            #    fh.seek(c)
            # elif cmd_load.cmd == LC_SYMTAB:
            #    c = fh.tell()
            #    fh.seek(cmd_cmd.stroff)
            #    cmd_data = fh.read(cmd_cmd.strsize)
            #    fh.seek(c)

            else:
                # data is a raw str
                data_size = cmd_load.cmdsize - sizeof(klass) - sizeof(load_command)
                cmd_data = fh.read(data_size)
            cmd.append((cmd_load, cmd_cmd, cmd_data))
            read_bytes += cmd_load.cmdsize

        # make sure the header made sense
        if read_bytes != header.sizeofcmds:
            raise ValueError(
                "Read %d bytes, header reports %d bytes"
                % (read_bytes, header.sizeofcmds)
            )
        self.total_size = sizeof(self.mach_header) + read_bytes
        self.low_offset = low_offset

    def walkRelocatables(self, shouldRelocateCommand=_shouldRelocateCommand):
        """
        for all relocatable commands
        yield (command_index, command_name, filename)
        """
        for idx, (lc, cmd, data) in enumerate(self.commands):
            if shouldRelocateCommand(lc.cmd):
                name = _RELOCATABLE_NAMES[lc.cmd]
                ofs = cmd.name - sizeof(lc.__class__) - sizeof(cmd.__class__)
                yield idx, name, data[
                    ofs : data.find(b"\x00", ofs)  # noqa: E203
                ].decode(sys.getfilesystemencoding())

    def rewriteInstallNameCommand(self, loadcmd):
        """Rewrite the load command of this dylib"""
        if self.id_cmd is not None:
            self.rewriteDataForCommand(self.id_cmd, loadcmd)
            return True
        return False

    def changedHeaderSizeBy(self, bytes):
        self.sizediff += bytes
        if (self.total_size + self.sizediff) > self.low_offset:
            print(
                "WARNING: Mach-O header in %r may be too large to relocate"
                % (self.parent.filename,)
            )

    def rewriteLoadCommands(self, changefunc):
        """
        Rewrite the load commands based upon a change dictionary
        """
        data = changefunc(self.parent.filename)
        changed = False
        if data is not None:
            if self.rewriteInstallNameCommand(data.encode(sys.getfilesystemencoding())):
                changed = True
        for idx, _name, filename in self.walkRelocatables():
            data = changefunc(filename)
            if data is not None:
                if self.rewriteDataForCommand(
                    idx, data.encode(sys.getfilesystemencoding())
                ):
                    changed = True
        return changed

    def rewriteDataForCommand(self, idx, data):
        lc, cmd, old_data = self.commands[idx]
        hdrsize = sizeof(lc.__class__) + sizeof(cmd.__class__)
        align = struct.calcsize("Q")
        data = data + (b"\x00" * (align - (len(data) % align)))
        newsize = hdrsize + len(data)
        self.commands[idx] = (lc, cmd, data)
        self.changedHeaderSizeBy(newsize - lc.cmdsize)
        lc.cmdsize, cmd.name = newsize, hdrsize
        return True

    def _command_file_offset(self, idx):
        """
        Absolute file offset of load command *idx*, computed from the
        header layout rather than trusting any mutable state.
        """
        offset = self.offset + sizeof(self.mach_header)
        for current in range(idx):
            offset += self.commands[current][0].cmdsize
        return offset

    def _code_signature_info(self):
        """
        Return ``(present, dataoff, datasize)`` for LC_CODE_SIGNATURE.

        The offsets stored in the linkedit_data_command are slice
        relative and are converted to absolute file offsets.
        """
        for lc, cmd, _data in self.commands:
            if lc.cmd == LC_CODE_SIGNATURE:
                return True, self.offset + int(cmd.dataoff), int(cmd.datasize)
        return False, None, None

    def _relocation_requests(self, changefunc):
        """
        Resolve *changefunc* against the install name (if any) and every
        relocatable command, yielding the command index, old path and
        replacement path for commands that actually need rewriting.
        """
        requests = []
        install_name = changefunc(self.parent.filename)
        if install_name is not None and self.id_cmd is not None:
            requests.append(
                (self.id_cmd, install_name.encode(sys.getfilesystemencoding()))
            )
        for idx, _name, old_path in self.walkRelocatables():
            new_path = changefunc(old_path)
            if new_path is not None:
                requests.append(
                    (idx, new_path.encode(sys.getfilesystemencoding()))
                )
        return requests

    def plan_rewrite(self, slice_index, changefunc):
        """
        Build a :class:`SlicePlan` for this slice without mutating the
        parsed header or the underlying file.
        """
        align = struct.calcsize("Q")
        changes = []
        size_delta = 0
        for idx, new_string in self._relocation_requests(changefunc):
            lc, cmd, old_data = self.commands[idx]
            hdrsize = sizeof(lc.__class__) + sizeof(cmd.__class__)
            string_offset_in_data = int(cmd.name) - hdrsize
            old_string = old_data[
                string_offset_in_data : old_data.find(  # noqa: E203
                    b"\x00", string_offset_in_data
                )
            ]
            if new_string == old_string:
                continue
            padded_length = len(new_string) + (
                align - (len(new_string) % align)
            )
            new_size = hdrsize + padded_length
            delta = new_size - int(lc.cmdsize)
            string_file_offset = (
                self._command_file_offset(idx) + int(cmd.name)
            )
            changes.append(
                CommandChange(
                    command_index=idx,
                    cmd=int(lc.cmd),
                    command_name=_RELOCATABLE_NAMES.get(
                        int(lc.cmd),
                        "id_dylib" if idx == self.id_cmd else "unknown",
                    ),
                    old_path=old_string.decode(
                        sys.getfilesystemencoding(), "surrogateescape"
                    ),
                    new_path=new_string.decode(
                        sys.getfilesystemencoding(), "surrogateescape"
                    ),
                    file_offset=self._command_file_offset(idx),
                    old_size=int(lc.cmdsize),
                    new_size=new_size,
                    size_delta=delta,
                    string_offset=string_file_offset,
                    string_old_size=len(old_string),
                    string_new_size=len(new_string),
                )
            )
            size_delta += delta

        has_sig, sig_offset, sig_size = self._code_signature_info()
        free_space = self.low_offset - self.total_size
        feasible = True
        error = None
        if size_delta > free_space:
            feasible = False
            error = (
                "header needs %d additional byte(s) but only %d are "
                "available before the first section (header size %d, "
                "limit %d)"
                % (
                    size_delta,
                    free_space,
                    self.total_size,
                    self.low_offset,
                )
            )
        return SlicePlan(
            header=self,
            slice_index=slice_index,
            cpu_type=int(self.header.cputype),
            cpu_subtype=int(self.header.cpusubtype),
            file_offset=self.offset,
            changes=changes,
            header_size=self.total_size,
            max_header_size=self.low_offset,
            free_space=free_space,
            size_delta=size_delta,
            has_code_signature=has_sig,
            code_signature_offset=sig_offset,
            code_signature_size=sig_size,
            feasible=feasible,
            error=error,
        )

    def verify_plan(self, slice_plan):
        """
        Confirm that the on-disk-parsed header still matches the plan:
        same slice position, same commands, same offsets, sizes and old
        paths. Raises ValueError on any drift; never writes anything.
        """
        if slice_plan.header is not self:
            raise ValueError(
                "plan slice %d does not match the current header of %r"
                % (slice_plan.slice_index, self.parent.filename)
            )
        if slice_plan.file_offset != self.offset:
            raise ValueError(
                "slice %d moved from offset %d to %d since preflight"
                % (
                    slice_plan.slice_index,
                    slice_plan.file_offset,
                    self.offset,
                )
            )
        for change in slice_plan.changes:
            idx = change.command_index
            if idx >= len(self.commands):
                raise ValueError(
                    "planned command index %d no longer exists in slice %d"
                    % (idx, slice_plan.slice_index)
                )
            lc, cmd, data = self.commands[idx]
            if int(lc.cmd) != change.cmd:
                raise ValueError(
                    "command %d in slice %d changed type since preflight"
                    % (idx, slice_plan.slice_index)
                )
            if int(lc.cmdsize) != change.old_size:
                raise ValueError(
                    "command %d in slice %d changed size since preflight"
                    % (idx, slice_plan.slice_index)
                )
            if self._command_file_offset(idx) != change.file_offset:
                raise ValueError(
                    "command %d in slice %d moved since preflight"
                    % (idx, slice_plan.slice_index)
                )
            hdrsize = sizeof(lc.__class__) + sizeof(cmd.__class__)
            string_offset_in_data = int(cmd.name) - hdrsize
            current_path = data[
                string_offset_in_data : data.find(  # noqa: E203
                    b"\x00", string_offset_in_data
                )
            ]
            if current_path.decode(
                sys.getfilesystemencoding(), "surrogateescape"
            ) != change.old_path:
                raise ValueError(
                    "command %d in slice %d no longer holds the planned "
                    "old path %r"
                    % (idx, slice_plan.slice_index, change.old_path)
                )

    def write_with_plan(self, slice_plan, fileobj):
        """
        Rewrite exactly the commands described by *slice_plan* and nothing
        else, then zero the now-unused header tail. Callers must have run
        :meth:`verify_plan` and established feasibility beforehand.
        """
        if not slice_plan.feasible:
            raise InsufficientHeaderSpaceError(
                "slice %d of %r cannot be rewritten: %s"
                % (
                    slice_plan.slice_index,
                    self.parent.filename,
                    slice_plan.error,
                )
            )
        if slice_plan.size_delta > self.low_offset - self.total_size:
            raise InsufficientHeaderSpaceError(
                "header free space of slice %d changed since preflight"
                % (slice_plan.slice_index,)
            )

        replacements = dict(
            (change.command_index, change) for change in slice_plan.changes
        )
        view = fileview(fileobj, self.offset, self.size)
        view.seek(0)

        self.sizediff = slice_plan.size_delta
        self.synchronize_size()

        self.header.to_fileobj(view)
        for idx, (lc, cmd, data) in enumerate(self.commands):
            change = replacements.get(idx)
            if change is not None:
                align = struct.calcsize("Q")
                new_string = change.new_path.encode(
                    sys.getfilesystemencoding(), "surrogateescape"
                )
                padded = new_string + (
                    b"\x00" * (align - (len(new_string) % align))
                )
                hdrsize = sizeof(lc.__class__) + sizeof(cmd.__class__)
                new_size = hdrsize + len(padded)
                lc.cmdsize = new_size
                cmd.name = hdrsize
                data = padded
            lc.to_fileobj(view)
            cmd.to_fileobj(view)
            if isinstance(data, bytes):
                view.write(data)
            else:
                for obj in data:
                    obj.to_fileobj(view)

        # zero out the unused space between the last command and the
        # first section, matching the regular write() behaviour
        view.write(b"\x00" * (self.low_offset - view.tell()))

    def synchronize_size(self):
        if (self.total_size + self.sizediff) > self.low_offset:
            raise ValueError(
                (
                    "New Mach-O header is too large to relocate in %r "
                    "(new size=%r, max size=%r, delta=%r)"
                )
                % (
                    self.parent.filename,
                    self.total_size + self.sizediff,
                    self.low_offset,
                    self.sizediff,
                )
            )
        self.header.sizeofcmds += self.sizediff
        self.total_size = sizeof(self.mach_header) + self.header.sizeofcmds
        self.sizediff = 0

    def write(self, fileobj):
        fileobj = fileview(fileobj, self.offset, self.size)
        fileobj.seek(0)

        # serialize all the mach-o commands
        self.synchronize_size()

        self.header.to_fileobj(fileobj)
        for lc, cmd, data in self.commands:
            lc.to_fileobj(fileobj)
            cmd.to_fileobj(fileobj)

            if sys.version_info[0] == 2:
                if isinstance(data, unicode):
                    fileobj.write(data.encode(sys.getfilesystemencoding()))

                elif isinstance(data, (bytes, str)):
                    fileobj.write(data)
                else:
                    # segments..
                    for obj in data:
                        obj.to_fileobj(fileobj)
            else:
                if isinstance(data, str):
                    fileobj.write(data.encode(sys.getfilesystemencoding()))

                elif isinstance(data, bytes):
                    fileobj.write(data)

                else:
                    # segments..
                    for obj in data:
                        obj.to_fileobj(fileobj)

        # zero out the unused space, doubt this is strictly necessary
        # and is generally probably already the case
        fileobj.write(b"\x00" * (self.low_offset - fileobj.tell()))

    def getSymbolTableCommand(self):
        for lc, cmd, _data in self.commands:
            if lc.cmd == LC_SYMTAB:
                return cmd
        return None

    def getDynamicSymbolTableCommand(self):
        for lc, cmd, _data in self.commands:
            if lc.cmd == LC_DYSYMTAB:
                return cmd
        return None

    def get_filetype_shortname(self, filetype):
        if filetype in MH_FILETYPE_SHORTNAMES:
            return MH_FILETYPE_SHORTNAMES[filetype]
        else:
            return "unknown"


def main(fn):
    m = MachO(fn)
    seen = set()
    for header in m.headers:
        for _idx, name, other in header.walkRelocatables():
            if other not in seen:
                seen.add(other)
                print("\t" + name + ": " + other)


if __name__ == "__main__":
    import sys

    files = sys.argv[1:] or ["/bin/ls"]
    for fn in files:
        print(fn)
        main(fn)
