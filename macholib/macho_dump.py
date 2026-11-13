#!/usr/bin/env python

from __future__ import print_function

import sys

from macholib._cmdline import main as _main
from macholib.mach_o import (
    CPU_TYPE_NAMES,
    LC_THREAD,
    LC_UNIXTHREAD,
    MH_CIGAM_64,
    MH_MAGIC_64,
    get_cpu_subtype,
)
from macholib.MachO import MachO

ARCH_MAP = {
    ("<", "64-bit"): "x86_64",
    ("<", "32-bit"): "i386",
    (">", "64-bit"): "ppc64",
    (">", "32-bit"): "ppc",
}


def _format_register(register):
    if not register["available"]:
        return "unavailable"
    source = register["source"]
    return "%#x (%s, state[%d], +%d)" % (
        register["value"],
        source["flavor_name"],
        source["state_index"],
        source["field_offset"],
    )


def print_thread_states(fp, states):
    """
    Write the forensic summary of a thread command.  Only values read
    from the file are reported; nothing is padded to fill a truncated
    state.
    """
    print(
        "\tthread %s cputype=%s endian=%s states=%d"
        % (
            states.cmd_name,
            states.cputype_name,
            states.endian,
            len(states.states),
        ),
        file=fp,
    )
    described = states.describe()
    print("\t\tpc: %s" % (_format_register(described["pc"]),), file=fp)
    print("\t\tsp: %s" % (_format_register(described["sp"]),), file=fp)
    for state in states.states:
        state_description = state.describe()
        print(
            "\t\tstate[%d] flavor=%d (%s) count=%d bytes=%d supported=%s"
            % (
                state_description["state_index"],
                state_description["flavor"],
                state_description["flavor_name"] or "unknown",
                state_description["count"],
                state_description["size"],
                state_description["supported"],
            ),
            file=fp,
        )
        if state_description["pc"]["available"]:
            print(
                "\t\t\tpc=%#x" % (state_description["pc"]["value"],), file=fp
            )
        if state_description["sp"]["available"]:
            print(
                "\t\t\tsp=%#x" % (state_description["sp"]["value"],), file=fp
            )
        if not state_description["supported"]:
            print(
                "\t\t\traw=%s" % (state_description["raw_hex"],), file=fp
            )


def print_file(fp, path):
    print(path, file=fp)
    m = MachO(path)
    for header in m.headers:
        seen = set()

        if header.MH_MAGIC == MH_MAGIC_64 or header.MH_MAGIC == MH_CIGAM_64:
            sz = "64-bit"
        else:
            sz = "32-bit"

        arch = CPU_TYPE_NAMES.get(header.header.cputype, header.header.cputype)

        subarch = get_cpu_subtype(header.header.cputype, header.header.cpusubtype)

        print(
            "    [%s endian=%r size=%r arch=%r subarch=%r]"
            % (header.__class__.__name__, header.endian, sz, arch, subarch),
            file=fp,
        )
        for _idx, _name, other in header.walkRelocatables():
            if other not in seen:
                seen.add(other)
                print("\t" + other, file=fp)

        for _lc, command, _data in header.commands:
            states = getattr(command, "thread_states", None)
            if states is None or _lc.cmd not in (LC_THREAD, LC_UNIXTHREAD):
                continue
            print_thread_states(fp, states)
    print("", file=fp)


def main():
    print(
        "WARNING: 'macho_dump' is deprecated, use 'python -mmacholib dump' " "instead"
    )
    _main(print_file)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
