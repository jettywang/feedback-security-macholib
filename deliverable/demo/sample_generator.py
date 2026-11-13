"""Generate synthetic, in-memory Mach-O images for the static-analysis demo.

Nothing here is a real FairPlay-encrypted App Store binary. The images are
hand-built with macholib's own ``Structure`` classes so that the very same
classes used for analysis can parse them back. A *simulated* ciphertext region
is produced with a deterministic PRNG purely so that byte-level coverage and
entropy can be demonstrated.

Scenarios (all single-slice arm64 unless wrapped in a fat container):

* ``fairplay``   - crypt window covers __TEXT's payload, linkedit stays clear
                   (the normal on-disk shape of an App Store executable);
* ``conflict``   - declared crypt window overruns into __DATA/__LINKEDIT,
                   producing range conflicts worth flagging;
* ``unencrypted``- command present but ``cryptid == 0`` (declared, not active);
* ``malformed``  - ``cryptid != 0`` with ``cryptsize == 0`` (inconsistent).
"""

from __future__ import annotations

from macholib.mach_o import (
    CPU_TYPE_NAMES,
    MH_EXECUTE,
    MH_MAGIC_64,
    MH_NO_HEAP_EXECUTION,
    MH_PIE,
    N_EXT,
    N_SECT,
    N_UNDF,
    S_REGULAR,
    S_ZEROFILL,
    build_tool_version,
    build_version_command,
    dysymtab_command,
    dylib,
    dylib_command,
    entry_point_command,
    encryption_info_command_64,
    fat_arch,
    fat_header,
    linkedit_data_command,
    load_command,
    mach_header_64,
    nlist_64,
    n_un,
    section_64,
    segment_command_64,
    symtab_command,
    uuid_command,
)
from macholib.ptypes import sizeof

ENDIAN = "<"
PAGE = 0x4000
BASE = 0x100000000

# vm_prot_t bit values (macholib exposes the type, not these named constants)
VM_PROT_READ = 1
VM_PROT_WRITE = 2
VM_PROT_EXECUTE = 4

LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_LOAD_DYLIB = 0x0C
LC_CODE_SIGNATURE = 0x1D
LC_DYLD_INFO_ONLY = 0x22 | 0x80000000
LC_MAIN = 0x28 | 0x80000000
LC_ENCRYPTION_INFO_64 = 0x2C
LC_BUILD_VERSION = 0x32
LC_SYMTAB = 0x02
LC_DYSYMTAB = 0x0B

CPU_ARM64 = 0x01000000 | 12
CPU_SUBTYPE_ARM64_ALL = 0
PLATFORM_IOS = 2
TOOL_CLANG = 1

FAT_MAGIC = 0xCAFEBABE


def lc(cmd, cmdsize):
    return load_command(cmd, cmdsize, _endian_=ENDIAN)


def _prng(seed, length):
    """Deterministic LCGB-style bytes standing in for opaque ciphertext."""
    state = seed & 0xFFFFFFFF
    out = bytearray()
    while len(out) < length:
        state = (1103515245 * state + 12345) & 0xFFFFFFFF
        out.append((state >> 16) & 0xFF)
    return bytes(out[:length])


def _place(buf, offset, structure):
    raw = structure.to_str()
    buf[offset : offset + len(raw)] = raw
    return offset + len(raw)


def _cstr(buf, offset, text):
    raw = text.encode("utf-8") + b"\x00"
    buf[offset : offset + len(raw)] = raw
    return offset + len(raw)


SCENARIOS = {
    # name: (cryptid, cryptoff, cryptsize)
    "fairplay": (1, PAGE, PAGE),            # 0x4000 .. 0x8000
    "conflict": (1, PAGE, 9 * PAGE),        # 0x4000 .. 0x28000 (overruns)
    "unencrypted": (0, PAGE, PAGE),         # declared but inactive
    "malformed": (1, PAGE, 0),              # active id, zero window
}


def build_slice(scenario="fairplay", cputype=CPU_ARM64, cpusubtype=0):
    """Return ``(blob, layout)`` for one Mach-O slice."""
    if scenario not in SCENARIOS:
        raise KeyError("unknown scenario %r" % scenario)
    cryptid, cryptoff, cryptsize = SCENARIOS[scenario]

    # --- file layout (all offsets chosen up-front, page aligned) ----------
    text_off, text_size = PAGE, 0x200
    cstr_off, cstr_size = 0x4200, 0x200
    text_seg_fileoff, text_seg_filesize = 0, 2 * PAGE          # __TEXT
    data_seg_off, data_seg_size = 2 * PAGE, PAGE               # __DATA
    got_off, got_size = 0x8000, 0x80
    data_off, data_size = 0x8080, 0x40
    bss_size = 0x100
    linkedit_off, linkedit_size = 3 * PAGE, PAGE              # __LINKEDIT
    symoff, nsyms, symsize = 0xC000, 3, 3 * sizeof(nlist_64)
    stroff, strsize = 0xC100, 0x80
    dyld_off, dyld_size = 0xC200, 0x100
    sig_off, sig_size = 0xC300, 0x200
    total = linkedit_off + linkedit_size

    blob = bytearray(b"\x00" * total)
    layout = {"scenario": scenario, "total_size": total,
              "cputype": cputype, "cpusubtype": cpusubtype}

    # --- segment payloads (plaintext bytes) --------------------------------
    nop = b"\x1F\x20\x03\xD5"
    blob[text_off : text_off + text_size] = nop * (text_size // 4)
    _cstr(blob, cstr_off, "demo synthetic marker %s" % scenario)
    blob[got_off : got_off + got_size] = b"\x00" * got_size
    blob[data_off : data_off + data_size] = b"DATA" * (data_size // 4)
    blob[dyld_off : dyld_off + dyld_size] = b"DYLD" * (dyld_size // 4)
    blob[sig_off : sig_off + sig_size] = b"SIG!" + b"\x00" * (sig_size - 4)

    # string table: index 0 reserved, one NUL-terminated name per symbol
    strtab = bytearray(b"\x00" * strsize)
    name_entry = b"_demo_entry\x00"
    name_local = b"_demo_local_cstring\x00"
    name_undef = b"_demo_undefined\x00"
    p_entry = 1
    p_local = p_entry + len(name_entry)
    p_undef = p_local + len(name_local)
    strtab[p_entry:p_entry + len(name_entry)] = name_entry
    strtab[p_local:p_local + len(name_local)] = name_local
    strtab[p_undef:p_undef + len(name_undef)] = name_undef
    blob[stroff : stroff + strsize] = bytes(strtab)

    # symbol table: defined text symbol, local cstring symbol, undefined
    n1 = nlist_64(n_un(p_entry, _endian_=ENDIAN), N_EXT | N_SECT, 1, 0,
                  BASE + text_off, _endian_=ENDIAN)
    n2 = nlist_64(n_un(p_local, _endian_=ENDIAN), N_SECT, 2, 0,
                  BASE + cstr_off, _endian_=ENDIAN)
    n3 = nlist_64(n_un(p_undef, _endian_=ENDIAN), N_EXT | N_UNDF, 0, 0, 0,
                  _endian_=ENDIAN)
    _place(blob, symoff, n1)
    _place(blob, symoff + sizeof(nlist_64), n2)
    _place(blob, symoff + 2 * sizeof(nlist_64), n3)

    # --- build load commands in a temporary buffer -------------------------
    lcbuf = bytearray()
    ncmds = 0

    def emit(structures):
        # First element is always the load_command header; one emit call ==
        # one load command on the wire (header + body + any variable data).
        nonlocal ncmds
        ncmds += 1
        for st in structures:
            lcbuf.extend(st.to_str())

    text_sect = section_64(
        b"__text\x00".ljust(16, b"\x00"), b"__TEXT\x00".ljust(16, b"\x00"),
        BASE + text_off, text_size, text_off, 2, 0, 0, S_REGULAR, 0, 0, 0,
        _endian_=ENDIAN)
    cstr_sect = section_64(
        b"__cstring\x00".ljust(16, b"\x00"), b"__TEXT\x00".ljust(16, b"\x00"),
        BASE + cstr_off, cstr_size, cstr_off, 0, 0, 0, S_REGULAR, 0, 0, 0,
        _endian_=ENDIAN)
    text_seg_cmdsize = sizeof(load_command) + sizeof(segment_command_64) + \
        2 * sizeof(section_64)
    text_seg = segment_command_64(
        b"__TEXT\x00".ljust(16, b"\x00"), BASE, text_seg_filesize,
        text_seg_fileoff, text_seg_filesize,
        VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE,
        2, 0, _endian_=ENDIAN)
    emit([lc(LC_SEGMENT_64, text_seg_cmdsize), text_seg, text_sect, cstr_sect])

    got_sect = section_64(
        b"__got\x00".ljust(16, b"\x00"), b"__DATA\x00".ljust(16, b"\x00"),
        BASE + got_off, got_size, got_off, 3, 0, 0, S_REGULAR, 0, 0, 0,
        _endian_=ENDIAN)
    data_sect = section_64(
        b"__data\x00".ljust(16, b"\x00"), b"__DATA\x00".ljust(16, b"\x00"),
        BASE + data_off, data_size, data_off, 0, 0, 0, S_REGULAR, 0, 0, 0,
        _endian_=ENDIAN)
    bss_sect = section_64(
        b"__bss\x00".ljust(16, b"\x00"), b"__DATA\x00".ljust(16, b"\x00"),
        BASE + data_off + data_size, bss_size, 0, 0, 0, 0, S_ZEROFILL, 0, 0, 0,
        _endian_=ENDIAN)
    data_seg_cmdsize = sizeof(load_command) + sizeof(segment_command_64) + \
        3 * sizeof(section_64)
    data_vmsize = data_seg_size + bss_size
    data_seg = segment_command_64(
        b"__DATA\x00".ljust(16, b"\x00"), BASE + data_seg_off, data_vmsize,
        data_seg_off, data_seg_size,
        VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE,
        3, 0, _endian_=ENDIAN)
    emit([lc(LC_SEGMENT_64, data_seg_cmdsize), data_seg,
          got_sect, data_sect, bss_sect])

    link_seg = segment_command_64(
        b"__LINKEDIT\x00".ljust(16, b"\x00"), BASE + linkedit_off,
        linkedit_size, linkedit_off, linkedit_size, VM_PROT_READ,
        VM_PROT_READ, 0, 0, _endian_=ENDIAN)
    emit([lc(LC_SEGMENT_64, sizeof(load_command) + sizeof(segment_command_64)),
          link_seg])

    uuid_bytes = (b"\x01\x23\x45\x67\x89\xAB\xCD\xEF"
                  b"\x01\x23\x45\x67\x89\xAB\xCD\xEF")
    uuid_cmd = uuid_command(uuid_bytes, _endian_=ENDIAN)
    emit([lc(LC_UUID, sizeof(load_command) + sizeof(uuid_command)), uuid_cmd])

    dep = b"/usr/lib/libSystem.B.dylib\x00"
    dylib_cmdsize = sizeof(load_command) + sizeof(dylib_command) + len(dep)
    name_lc_str = sizeof(load_command) + sizeof(dylib_command)
    dep_cmd = dylib_command(
        name_lc_str, 2, 0x10000, 0x10000, _endian_=ENDIAN)
    emit([lc(LC_LOAD_DYLIB, dylib_cmdsize), dep_cmd])
    lcbuf.extend(dep)

    bv = build_version_command(PLATFORM_IOS, 0x000E0000, 0x000E0000, 1,
                               _endian_=ENDIAN)
    tool = build_tool_version(TOOL_CLANG, 0x000E0000, _endian_=ENDIAN)
    emit([lc(LC_BUILD_VERSION,
             sizeof(load_command) + sizeof(build_version_command) +
             sizeof(tool)), bv, tool])

    main_cmd = entry_point_command(text_off, 0, _endian_=ENDIAN)
    emit([lc(LC_MAIN, sizeof(load_command) + sizeof(entry_point_command)),
          main_cmd])

    enc = encryption_info_command_64(cryptoff, cryptsize, cryptid, 0,
                                     _endian_=ENDIAN)
    emit([lc(LC_ENCRYPTION_INFO_64,
             sizeof(load_command) + sizeof(encryption_info_command_64)), enc])

    sym_cmd = symtab_command(symoff, nsyms, stroff, strsize, _endian_=ENDIAN)
    emit([lc(LC_SYMTAB, sizeof(load_command) + sizeof(symtab_command)),
          sym_cmd])

    dys_values = (0, 2, 2, 1, 3, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0)
    dys = dysymtab_command(*dys_values, _endian_=ENDIAN)
    emit([lc(LC_DYSYMTAB,
             sizeof(load_command) + sizeof(dysymtab_command)), dys])

    from macholib.mach_o import dyld_info_command
    dyld_cmd = dyld_info_command(
        0, 0, dyld_off, dyld_size, 0, 0, 0, 0, dyld_off, dyld_size,
        _endian_=ENDIAN)
    emit([lc(LC_DYLD_INFO_ONLY,
             sizeof(load_command) + sizeof(dyld_info_command)), dyld_cmd])

    sig_cmd = linkedit_data_command(sig_off, sig_size, _endian_=ENDIAN)
    emit([lc(LC_CODE_SIGNATURE,
             sizeof(load_command) + sizeof(linkedit_data_command)), sig_cmd])

    sizeofcmds = len(lcbuf)
    header = mach_header_64(
        MH_MAGIC_64, cputype, cpusubtype, MH_EXECUTE,
        ncmds, sizeofcmds, MH_PIE | MH_NO_HEAP_EXECUTION, 0,
        _endian_=ENDIAN)
    blob[0:sizeof(header)] = header.to_str()
    blob[sizeof(header) : sizeof(header) + sizeofcmds] = bytes(lcbuf)

    # --- simulate the on-disk ciphertext inside the declared window --------
    if cryptid != 0 and cryptsize > 0:
        window_end = min(cryptoff + cryptsize, total)
        blob[cryptoff:window_end] = _prng(0xC0FFEE, window_end - cryptoff)

    layout.update({
        "arch_name": CPU_TYPE_NAMES.get(cputype, cputype),
        "segments": {
            "__TEXT": (text_seg_fileoff, text_seg_filesize),
            "__DATA": (data_seg_off, data_seg_size),
            "__LINKEDIT": (linkedit_off, linkedit_size),
        },
        "sections": {
            "__text": (text_off, text_size),
            "__cstring": (cstr_off, cstr_size),
            "__got": (got_off, got_size),
            "__data": (data_off, data_size),
            "__bss": (0, 0),
        },
        "entryoff": text_off,
        "symtab": (symoff, symsize),
        "strtab": (stroff, strsize),
        "dyld_info": (dyld_off, dyld_size),
        "code_signature": (sig_off, sig_size),
        "crypt": (cryptoff, cryptsize, cryptid),
        "header_cmds_end": sizeof(header) + sizeofcmds,
    })
    return bytes(blob), layout


def build_fat(scenario="fairplay"):
    """Wrap an arm64 and an x86_64 slice in a big-endian fat container."""
    arm_blob, arm_layout = build_slice(scenario, CPU_ARM64, 0)
    x86_cpu = 0x01000000 | 7
    x86_blob, x86_layout = build_slice(scenario, x86_cpu, 3)

    align_shift = 14  # 2^14 = 0x4000
    first_off = PAGE
    second_off = (first_off + len(arm_blob) + PAGE - 1) & ~(PAGE - 1)
    total = second_off + len(x86_blob)
    fat = bytearray(b"\x00" * total)

    fh = fat_header(FAT_MAGIC, 2, _endian_=">")
    a1 = fat_arch(CPU_ARM64, 0, first_off, len(arm_blob), align_shift,
                  _endian_=">")
    a2 = fat_arch(x86_cpu, 3, second_off, len(x86_blob), align_shift,
                  _endian_=">")
    pos = 0
    for st in (fh, a1, a2):
        raw = st.to_str()
        fat[pos : pos + len(raw)] = raw
        pos += len(raw)
    fat[first_off : first_off + len(arm_blob)] = arm_blob
    fat[second_off : second_off + len(x86_blob)] = x86_blob
    layout = {"scenario": scenario, "slices": [arm_layout, x86_layout],
              "offsets": [first_off, second_off]}
    return bytes(fat), layout
