"""Build tiny deterministic Mach-O images with a stub section.

The fixture is intentionally small enough to verify by hand:

    symbol table (7 entries)
        0 local       _local_data
        1 local       _local_anchor
        2 external def _exported_fn
        3 undefined   _malloc
        4 undefined   _puts
        5 undefined   _free
        6 undefined   _rare_symbol

    indirect table (6 entries)
        0 -> 3                  __stubs[0]
        1 -> INDIRECT_SYMBOL_LOCAL
        2 -> 6                  __stubs[2]
        3 -> LOCAL|ABS
        4 -> 2                  __got[1]
        5 -> 4                  __la_symbol_ptr[0]

Both the 64-bit and 32-bit builders use the same logical content; only the
header, section, nlist and pointer widths change.
"""

from __future__ import print_function

import argparse
import os
import struct
import sys
import tempfile

MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF

LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB

S_REGULAR = 0x0
S_NON_LAZY_SYMBOL_POINTERS = 0x6
S_LAZY_SYMBOL_POINTERS = 0x7
S_SYMBOL_STUBS = 0x8

N_UNDF = 0x0
N_SECT = 0xE
N_EXT = 0x01

MH_DYLIB = 0x6

INDIRECT_SYMBOL_LOCAL = 0x80000000
INDIRECT_SYMBOL_ABS = 0x40000000

CPU_TYPE_I386 = 7
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_I386_ALL = 3
CPU_SUBTYPE_ARM64_ALL = 0

STUB_SIZE = 6
DEFAULT_STUB_ENTRIES = [3, INDIRECT_SYMBOL_LOCAL, 6]
DEFAULT_GOT_ENTRIES = [INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS, 2]
DEFAULT_LAZY_ENTRIES = [4]


def _align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def _p16(name):
    raw = name.encode("utf-8")
    if len(raw) > 16:
        raise ValueError("name too long for a 16-byte Mach-O field: %r" % (name,))
    return raw + (b"\x00" * (16 - len(raw)))


def _make_strtab(names):
    strtab = bytearray(b"\x00")
    offsets = {}
    for name in names:
        offsets[name] = len(strtab)
        strtab.extend(name.encode("utf-8"))
        strtab.append(0)
    return bytes(strtab), offsets


def _load_command(cmd, payload):
    return struct.pack("<II", cmd, 8 + len(payload)) + payload


def _be_load_command(cmd, payload):
    return struct.pack(">II", cmd, 8 + len(payload)) + payload


def _segment_64(name, vmaddr, fileoff, filesize, sections):
    payload = struct.pack(
        "<16sQQQQiiII",
        _p16(name),
        vmaddr,
        0x1000,
        fileoff,
        filesize,
        7,
        5,
        len(sections),
        0,
    )
    for sect in sections:
        payload += struct.pack(
            "<16s16sQQIIIIIIII",
            _p16(sect["sectname"]),
            _p16(sect["segname"]),
            sect["addr"],
            sect["size"],
            sect["offset"],
            0,
            0,
            0,
            sect["flags"],
            sect["reserved1"],
            sect["reserved2"],
            sect["reserved3"],
        )
    return _load_command(LC_SEGMENT_64, payload)


def _segment_32(name, vmaddr, fileoff, filesize, sections):
    payload = struct.pack(
        "<16sIIIIiiII",
        _p16(name),
        vmaddr,
        0x1000,
        fileoff,
        filesize,
        7,
        5,
        len(sections),
        0,
    )
    for sect in sections:
        payload += struct.pack(
            "<16s16sIIIIIIIII",
            _p16(sect["sectname"]),
            _p16(sect["segname"]),
            sect["addr"],
            sect["size"],
            sect["offset"],
            0,
            0,
            0,
            sect["flags"],
            sect["reserved1"],
            sect["reserved2"],
        )
    return _load_command(LC_SEGMENT, payload)


def _symbol_record(bits, strx, n_type, n_sect, n_value):
    if bits == 64:
        return struct.pack("<IBBHQ", strx, n_type, n_sect, 0, n_value)
    return struct.pack("<IBBHI", strx, n_type, n_sect, 0, n_value)


def build_sample(
    bits=64,
    strx_override=None,
    missing_nul=False,
    tag="",
    stub_reserved1=0,
    stub_reserved2=STUB_SIZE,
    got_reserved1=None,
    nindirectsyms_override=None,
    stub_section_size=None,
):
    """Return (image_bytes, metadata).

    ``strx_override`` maps a symbol index to a deliberately corrupt n_strx.
    ``missing_nul`` drops the terminating NUL of the last string table name.
    ``tag`` is appended to every symbol name so fat slices stay distinguishable.
    """
    if bits not in (32, 64):
        raise ValueError(bits)
    if strx_override is None:
        strx_override = {}

    local_names = ["_local_data" + tag, "_local_anchor" + tag]
    extdef_name = "_exported_fn" + tag
    undef_names = ["_malloc" + tag, "_puts" + tag, "_free" + tag, "_rare_symbol" + tag]
    names = local_names + [extdef_name] + undef_names
    strtab, strx = _make_strtab(names)
    if missing_nul:
        strtab = strtab[:-1]

    header_size = 32 if bits == 64 else 28
    text_offset = 0x400
    text_size = 16
    stubs_offset = text_offset + text_size
    stubs_size = stub_reserved2 * len(DEFAULT_STUB_ENTRIES)
    if stub_section_size is not None:
        stubs_size = stub_section_size
        text_size = stub_section_size
    got_offset = _align(stubs_offset + stubs_size, 8)
    pointer_size = 8 if bits == 64 else 4
    got_size = pointer_size * len(DEFAULT_GOT_ENTRIES)
    lazy_offset = _align(got_offset + got_size, 8)
    lazy_size = pointer_size * len(DEFAULT_LAZY_ENTRIES)

    base = 0x100000000 if bits == 64 else 0x1000
    text = [
        {
            "sectname": "__text",
            "segname": "__TEXT",
            "addr": base,
            "size": text_size,
            "offset": text_offset,
            "flags": S_REGULAR,
            "reserved1": 0,
            "reserved2": 0,
            "reserved3": 0,
        },
        {
            "sectname": "__stubs",
            "segname": "__TEXT",
            "addr": base + text_size,
            "size": stubs_size,
            "offset": stubs_offset,
            "flags": S_SYMBOL_STUBS,
            "reserved1": stub_reserved1,
            "reserved2": stub_reserved2,
            "reserved3": 0,
        },
    ]
    data_size = _align(lazy_offset + lazy_size, 8)
    data = [
        {
            "sectname": "__got",
            "segname": "__DATA",
            "addr": base + 0x1000,
            "size": got_size,
            "offset": got_offset,
            "flags": S_NON_LAZY_SYMBOL_POINTERS,
            "reserved1": (
                len(DEFAULT_STUB_ENTRIES)
                if got_reserved1 is None
                else got_reserved1
            ),
            "reserved2": 0,
            "reserved3": 0,
        },
        {
            "sectname": "__la_symbol_ptr",
            "segname": "__DATA",
            "addr": base + 0x1000 + got_size,
            "size": lazy_size,
            "offset": lazy_offset,
            "flags": S_LAZY_SYMBOL_POINTERS,
            "reserved1": len(DEFAULT_STUB_ENTRIES) + len(DEFAULT_GOT_ENTRIES),
            "reserved2": 0,
            "reserved3": 0,
        },
    ]

    indirect = DEFAULT_STUB_ENTRIES + DEFAULT_GOT_ENTRIES + DEFAULT_LAZY_ENTRIES
    nsyms = len(names)

    symoff = _align(data_size, 8)
    nlist_size = 16 if bits == 64 else 12
    stroff = symoff + nsyms * nlist_size
    indirectsymoff = _align(stroff + len(strtab), 4)
    tocoff = indirectsymoff + 4 * len(indirect)
    modtaboff = tocoff + 8
    extrefsymoff = modtaboff + (56 if bits == 64 else 52)
    file_size = extrefsymoff + 2 * 4

    symbol_values = [
        base + 0x40,
        base + 0x48,
        base + 0x10,
        0,
        0,
        0,
        0,
    ]
    symbol_types = [
        N_SECT,
        N_SECT,
        N_SECT | N_EXT,
        N_UNDF | N_EXT,
        N_UNDF | N_EXT,
        N_UNDF | N_EXT,
        N_UNDF | N_EXT,
    ]
    symbol_sects = [1, 1, 1, 0, 0, 0, 0]
    nlists = []
    for idx, name in enumerate(names):
        x = strx_override.get(idx, strx[name])
        nlists.append(
            _symbol_record(bits, x, symbol_types[idx], symbol_sects[idx], symbol_values[idx])
        )
    symtab_payload = struct.pack(
        "<IIIIII", symoff, nsyms, stroff, len(strtab), 0, 0
    )
    symtab_cmd = _load_command(LC_SYMTAB, symtab_payload)

    toc = struct.pack("<II", 2, 0)
    if bits == 64:
        module = struct.pack(
            "<IIIIIIIIIIIIQ",
            strx[extdef_name],
            2,
            1,
            0,
            2,
            0,
            2,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    else:
        module = struct.pack(
            "<IIIIIIIIIIIII",
            strx[extdef_name],
            2,
            1,
            0,
            2,
            0,
            2,
            0,
            0,
            0,
            0,
            0,
            0,
        )
    refs = struct.pack("<II", 2 | (2 << 24), 3)
    bytables = toc + module + refs
    assert len(bytables) == 8 + (56 if bits == 64 else 52) + 8

    dysymtab_payload = struct.pack(
        "<18I",
        0,
        2,
        2,
        1,
        3,
        4,
        tocoff,
        1,
        modtaboff,
        1,
        extrefsymoff,
        2,
        indirectsymoff,
        (
            len(indirect)
            if nindirectsyms_override is None
            else nindirectsyms_override
        ),
        0,
        0,
        0,
        0,
    )
    dysymtab_cmd = _load_command(LC_DYSYMTAB, dysymtab_payload)

    if bits == 64:
        header = struct.pack(
            "<IIIIIIII", MH_MAGIC_64, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, MH_DYLIB, 4, 0, 0x85, 0
        )
        seg_text = _segment_64("__TEXT", base, 0, data_size, text)
        seg_data = _segment_64(
            "__DATA", base + 0x1000, got_offset, lazy_offset + lazy_size - got_offset, data
        )
    else:
        header = struct.pack(
            "<IIIIIII", MH_MAGIC, CPU_TYPE_I386, CPU_SUBTYPE_I386_ALL, MH_DYLIB, 4, 0, 0x85
        )
        seg_text = _segment_32("__TEXT", base, 0, data_size, text)
        seg_data = _segment_32(
            "__DATA", base + 0x1000, got_offset, lazy_offset + lazy_size - got_offset, data
        )

    cmds = seg_text + seg_data + symtab_cmd + dysymtab_cmd
    header = bytearray(header)
    header[16:20] = struct.pack("<I", 4)
    header[20:24] = struct.pack("<I", len(cmds))
    header = bytes(header)
    assert len(header) + len(cmds) <= text_offset

    image = bytearray(file_size)
    image[0 : len(header)] = header
    image[header_size : header_size + len(cmds)] = cmds
    image[text_offset : text_offset + text_size] = b"\x90" * text_size
    image[stubs_offset : stubs_offset + stubs_size] = b"\x00" * stubs_size
    image[got_offset : got_offset + got_size] = b"\x00" * got_size
    image[lazy_offset : lazy_offset + lazy_size] = b"\x00" * lazy_size
    image[symoff : symoff + len(nlists) * nlist_size] = b"".join(nlists)
    image[stroff : stroff + len(strtab)] = strtab
    image[indirectsymoff : indirectsymoff + 4 * len(indirect)] = struct.pack(
        "<%dI" % len(indirect), *indirect
    )
    image[tocoff : tocoff + len(toc)] = toc
    image[modtaboff : modtaboff + len(module)] = module
    image[extrefsymoff:file_size] = refs

    metadata = {
        "bits": bits,
        "path": None,
        "file_size": file_size,
        "nsyms": nsyms,
        "names": names,
        "strx": dict(strx),
        "strtab": strtab,
        "symoff": symoff,
        "stroff": stroff,
        "stubs_offset": stubs_offset,
        "stubs_size": stubs_size,
        "stub_size": STUB_SIZE,
        "stub_reserved1": stub_reserved1,
        "stub_reserved2": stub_reserved2,
        "nindirectsyms": (
            len(indirect)
            if nindirectsyms_override is None
            else nindirectsyms_override
        ),
        "stub_entries": list(DEFAULT_STUB_ENTRIES),
        "got_entries": list(DEFAULT_GOT_ENTRIES),
        "lazy_entries": list(DEFAULT_LAZY_ENTRIES),
        "indirect": list(indirect),
        "indirectsymoff": indirectsymoff,
        "tocoff": tocoff,
        "modtaboff": modtaboff,
        "extrefsymoff": extrefsymoff,
        "sections": text + data,
        "base": base,
    }
    return bytes(image), metadata


def build_be32():
    """Build a minimal big-endian 32-bit image with symbol and indirect tables.

    No segments are included, so this exercises only endian handling for
    LC_SYMTAB/LC_DYSYMTAB and the indirect table:

        nlist[0] = _be_local   (local, N_SECT)
        nlist[1] = _be_undef   (undefined, N_EXT)
        indirect = [1, INDIRECT_SYMBOL_LOCAL]
    """
    names = ["_be_local", "_be_undef"]
    strtab, strx = _make_strtab(names)
    header_size = 28
    nsyms = 2
    symoff = _align(header_size + 16 + 72, 4)
    stroff = symoff + nsyms * 12
    indirectsymoff = _align(stroff + len(strtab), 4)
    file_size = indirectsymoff + 8

    nlists = struct.pack(">IBBHI", strx["_be_local"], N_SECT, 1, 0, 0x1000)
    nlists += struct.pack(">IBBHI", strx["_be_undef"], N_UNDF | N_EXT, 0, 0, 0)
    cmds = _be_load_command(
        LC_SYMTAB, struct.pack(">IIII", symoff, nsyms, stroff, len(strtab))
    )
    cmds += _be_load_command(
        LC_DYSYMTAB,
        struct.pack(
            ">18I",
            0,
            1,
            1,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            indirectsymoff,
            2,
            0,
            0,
            0,
            0,
        ),
    )
    header = struct.pack(
        ">IIIIIII",
        MH_MAGIC,
        CPU_TYPE_I386,
        CPU_SUBTYPE_I386_ALL,
        MH_DYLIB,
        2,
        len(cmds),
        0x85,
    )
    image = bytearray(file_size)
    image[0 : len(header)] = header
    image[header_size : header_size + len(cmds)] = cmds
    image[symoff : symoff + len(nlists)] = nlists
    image[stroff : stroff + len(strtab)] = strtab
    image[indirectsymoff : indirectsymoff + 8] = struct.pack(
        ">II", 1, INDIRECT_SYMBOL_LOCAL
    )
    return bytes(image)


def build_fat(images, fat64=False, arch_size_overrides=None):
    """Wrap already-built thin images in a fat file.

    The first slice is labelled arm64 and later slices i386; this fixture only
    uses the CPU fields to make the slices distinguishable.
    """
    if len(images) > 2:
        raise ValueError("this fixture only needs one or two slices")
    if arch_size_overrides is None:
        arch_size_overrides = {}
    arch_size = 32 if fat64 else 20
    header_size = 8 + len(images) * arch_size
    offsets = []
    cursor = _align(header_size, 0x1000)
    for image in images:
        offsets.append(cursor)
        cursor = _align(cursor + len(image), 0x1000)
    magic = 0xCAFEBABF if fat64 else 0xCAFEBABE
    out = bytearray(cursor)
    out[0:8] = struct.pack(">II", magic, len(images))
    for idx, image in enumerate(images):
        cputype, cpusubtype = (
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL)
            if idx == 0
            else (CPU_TYPE_I386, CPU_SUBTYPE_I386_ALL)
        )
        size = arch_size_overrides.get(idx, len(image))
        off = offsets[idx]
        begin = 8 + idx * arch_size
        end = begin + arch_size
        if fat64:
            out[begin:end] = struct.pack(">IIQQII", cputype, cpusubtype, off, size, 12, 0)
        else:
            out[begin:end] = struct.pack(">IIIII", cputype, cpusubtype, off, size, 12)
        out[off : off + len(image)] = image
    return bytes(out)


def build_fat_64(images, **kw):
    return build_fat(images, fat64=True, **kw)


def write_sample(path, bits=64, **kw):
    image, metadata = build_sample(bits=bits, **kw)
    with open(path, "wb") as fh:
        fh.write(image)
    metadata["path"] = path
    return metadata


def main(argv=None):
    parser = argparse.ArgumentParser(description="build a stub fixture")
    parser.add_argument("output", nargs="?")
    parser.add_argument("--bits", type=int, choices=(32, 64), default=64)
    args = parser.parse_args(argv)
    if args.output is None:
        fd, path = tempfile.mkstemp(suffix=".dylib", dir=os.environ.get("TMPDIR"))
        os.close(fd)
    else:
        path = args.output
    metadata = write_sample(path, bits=args.bits)
    print(path)
    print("nsyms=%d indirect=%d stubs=%d" % (
        metadata["nsyms"], len(metadata["indirect"]),
        len(metadata["stub_entries"]),
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
