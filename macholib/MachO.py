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

__all__ = ["MachO"]

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


def lc_str_value(offset, cmd_info):
    """
    Fetch the actual value of a field of type "lc_str"
    """
    cmd_load, cmd_cmd, cmd_data = cmd_info

    offset -= sizeof(cmd_load) + sizeof(cmd_cmd)
    if offset < 0 or offset > len(cmd_data):
        return b""
    return cmd_data[offset:].strip(b"\x00")


def _read_command_data(fh, size, description):
    """
    Read exactly *size* bytes for a load command, raising ValueError when
    the command or file ends before the requested data is available.
    """
    if size < 0:
        raise ValueError("%s has a negative size: %d" % (description, size))
    data = fh.read(size)
    if len(data) != size:
        raise ValueError(
            "%s is truncated: expected %d bytes, got %d"
            % (description, size, len(data))
        )
    return data


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
        fh.seek(0, 2)
        size = fh.tell()
        fh.seek(0)
        if size < 4:
            raise ValueError(
                "File is too small to be a Mach-O file: %d bytes" % (size,)
            )
        header = struct.unpack(">I", fh.read(4))[0]
        fh.seek(0)
        if header in (FAT_MAGIC, FAT_MAGIC_64):
            self.load_fat(fh)
        else:
            self.load_header(fh, 0, size)

    def load_fat(self, fh):
        fh.seek(0, 2)
        file_size = fh.tell()
        if file_size < sizeof(fat_header):
            raise ValueError("Fat header is truncated: file size %d" % (file_size,))
        fh.seek(0)
        self.fat = fat_header.from_fileobj(fh)
        if self.fat.magic == FAT_MAGIC:
            arch_cls = fat_arch
        elif self.fat.magic == FAT_MAGIC_64:
            arch_cls = fat_arch64
        else:
            raise ValueError("Unknown fat header magic: %r" % (self.fat.magic,))

        available_archs = (file_size - sizeof(fat_header)) // sizeof(arch_cls)
        if self.fat.nfat_arch < 1:
            raise ValueError("Fat header reports no architectures")
        if self.fat.nfat_arch > available_archs:
            raise ValueError(
                "Fat header is truncated: reports %d architectures, only %d "
                "fit in the file" % (self.fat.nfat_arch, available_archs)
            )

        archs = [arch_cls.from_fileobj(fh) for i in range(self.fat.nfat_arch)]
        table_end = sizeof(fat_header) + len(archs) * sizeof(arch_cls)

        for index, arch in enumerate(archs):
            if arch.offset < table_end:
                raise ValueError(
                    "Fat architecture %d overlaps the fat header: offset %d, "
                    "header ends at %d" % (index, arch.offset, table_end)
                )
            if arch.size < sizeof(mach_header):
                raise ValueError(
                    "Fat architecture %d is too small: %d bytes" % (index, arch.size)
                )
            if arch.offset + arch.size > file_size:
                raise ValueError(
                    "Fat architecture %d extends past the end of the file: "
                    "slice [%d, %d), file size %d"
                    % (index, arch.offset, arch.offset + arch.size, file_size)
                )

        ranges = sorted((arch.offset, arch.offset + arch.size) for arch in archs)
        previous_end = table_end
        for start, end in ranges:
            if start < previous_end:
                raise ValueError(
                    "Fat slices overlap: slice [%d, %d) starts before previous "
                    "end %d" % (start, end, previous_end)
                )
            previous_end = end

        for arch in archs:
            self.load_header(fh, arch.offset, arch.size)

    def rewriteLoadCommands(self, *args, **kw):
        changed = False
        for header in self.headers:
            if header.rewriteLoadCommands(*args, **kw):
                changed = True
        return changed

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
        if self.size < sizeof(self.mach_header):
            raise ValueError(
                "Mach-O header is truncated: slice size %d, header requires %d"
                % (self.size, sizeof(self.mach_header))
            )
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

        header_size = sizeof(self.mach_header)
        command_area = max(0, self.size - header_size)
        if header.sizeofcmds > command_area:
            raise ValueError(
                "Load command area is truncated: header reports %d bytes, "
                "only %d available" % (header.sizeofcmds, command_area)
            )

        read_bytes = 0
        low_offset = sys.maxsize
        for i in range(header.ncmds):
            remaining = header.sizeofcmds - read_bytes
            if remaining < sizeof(load_command):
                raise ValueError(
                    "Load command %d is truncated: %d bytes remain in the "
                    "command area" % (i, remaining)
                )

            # read the load command
            cmd_load = load_command.from_fileobj(fh, **kw)
            if cmd_load.cmdsize < sizeof(load_command):
                raise ValueError(
                    "Load command %d has invalid cmdsize %d" % (i, cmd_load.cmdsize)
                )
            if cmd_load.cmdsize > remaining:
                raise ValueError(
                    "Load command %d has cmdsize %d, only %d bytes remain in "
                    "the command area" % (i, cmd_load.cmdsize, remaining)
                )

            # read the specific command
            klass = LC_REGISTRY.get(cmd_load.cmd, None)
            if klass is None:
                if not self.allow_unknown_load_commands:
                    raise ValueError("Unknown load command: %d" % (cmd_load.cmd,))
                # No load command in the registry, so append the load command itself
                # instead of trying to deserialize the data after the header.
                data_size = cmd_load.cmdsize - sizeof(load_command)
                cmd_data = _read_command_data(
                    fh, data_size, "Unknown load command %d" % (cmd_load.cmd,)
                )
                cmd.append((cmd_load, cmd_load, cmd_data))
                read_bytes += cmd_load.cmdsize
                continue

            min_size = sizeof(load_command) + sizeof(klass)
            if cmd_load.cmdsize < min_size:
                raise ValueError(
                    "Load command %d (0x%x) has cmdsize %d, smaller than its "
                    "structure size %d" % (i, cmd_load.cmd, cmd_load.cmdsize, min_size)
                )

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
                if ofs < 0 or ofs > len(data):
                    value = b""
                else:
                    end = data.find(b"\x00", ofs)
                    if end == -1:
                        end = len(data)
                    value = data[ofs:end]
                yield idx, name, value.decode(sys.getfilesystemencoding())

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
