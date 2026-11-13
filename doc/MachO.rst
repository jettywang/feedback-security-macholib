:mod:`macholib.MachO` --- Utilities for reading and writing Mach-O headers
==========================================================================

.. module:: macholib.MachO
   :synopsis: Utilities for reading and writing Mach-O headers

This module defines a class :class:`Macho`, which enables reading
and writing the Mach-O header of an executable file or dynamic
library on MacOS X.

.. function:: lc_str_value(offset, cmd_info)

   Returns the bytes for an ``lc_str`` value, given the *offset*
   of type ``lc_str`` and the ``cmd_info`` that contains the
   structure that contains the ``lc_str`` value. ``cmd_info`` is
   and item in the ``commands`` attribute of a MachOHeader instance.


.. class:: MachO(filename, allow_unknown_load_commands=False)

   Creates a MachO object by reading the Mach-O headers from
   *filename*.

   The *filename* should refer to an existing file in Mach-O
   format, and can refer to fat (universal) binaries.

   When *allow_unknown_load_commands* is false the instance will
   raise an error when the specified file contains unknown
   load commands.

   .. versionchanged: 1.16

      Added the *allow_unknown_load_commands* argument.

.. note:: more information will be added later

Thread states
-------------

``LC_THREAD`` and ``LC_UNIXTHREAD`` commands may contain several
``(flavor, count)`` pairs.  ``MachOHeader`` decodes them read-only and
attaches a :class:`macholib.thread_state.ThreadStateCommand` to the
``thread_states`` attribute of the ``thread_command`` instance in
``commands``.  ``count`` is a number of 32-bit words, also for 64-bit
register layouts, and both the pair headers and the register values use
the byte order of the Mach-O header.

Only documented CPU/flavor combinations are decoded (x86 and x86-64
thread/exception states, 32-bit and 64-bit ARM thread and exception
states).  Other states are kept as raw bytes.  A truncated state, a
count that is too small for a known layout, or a trailing partial
``(flavor, count)`` pair raises :class:`macholib.thread_state.ThreadStateError`
with the payload offset of the rejected record; no register value is
ever invented by padding.

Use :meth:`ThreadStateCommand.describe` for a JSON-friendly summary.
It records ``pc`` and ``sp`` availability together with the flavor,
state index and field offset each value came from.
