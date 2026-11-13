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

   .. method:: preflight_rewrite(changefunc)

      Read-only counterpart of :meth:`rewriteLoadCommands`. Applies
      *changefunc* to the install name and every relocatable load command
      of every slice without mutating the parsed headers or the file, and
      returns a :class:`RewritePlan` describing the outcome.

      The plan records, per slice, the exact byte ranges of the load
      commands that would change, the header free space available, the
      total size delta and the ``LC_CODE_SIGNATURE`` state. A slice whose
      commands cannot grow into the free header space is marked
      infeasible; :meth:`apply_plan` then refuses the whole file.

   .. method:: apply_plan(plan, fileobj)

      Writes the changes described by a :class:`RewritePlan` previously
      returned by :meth:`preflight_rewrite` to *fileobj*. The parsed
      headers are re-checked against the plan first, so any drift since
      the preflight (moved or resized commands, changed paths) raises
      ``ValueError`` before anything is written. An infeasible plan
      raises :class:`InsufficientHeaderSpaceError` without touching the
      file. Existing code signatures are never removed; slices that
      change bytes while carrying an ``LC_CODE_SIGNATURE`` are reported
      by the plan and must be re-signed afterwards.

.. class:: RewritePlan(filename, slice_plans)

   Read-only preflight result for a whole, possibly fat, Mach-O file.

   .. attribute:: filename

      The file the plan was built for.

   .. attribute:: slice_plans

      A list of :class:`SlicePlan` objects, one per architecture.

   .. attribute:: feasible

      True only when every slice has enough header free space.

   .. attribute:: changed_slices

      The :class:`SlicePlan` objects containing at least one change.

   .. attribute:: resigned_slices

      The :class:`SlicePlan` objects that change bytes and carry an
      ``LC_CODE_SIGNATURE``, and therefore have to be re-signed.

   .. method:: errors()

      A list of ``(slice_index, error_message)`` pairs for infeasible
      slices.

.. class:: SlicePlan(...)

   Read-only preflight result for one slice. Notable attributes:

   ``slice_index``, ``cpu_type`` and ``cpu_subtype`` identify the
   architecture; ``file_offset`` is the slice offset in the file.
   ``changes`` is a list of :class:`CommandChange` objects.
   ``header_size``, ``max_header_size``, ``free_space`` and
   ``size_delta`` describe the space accounting.
   ``has_code_signature``, ``code_signature_offset`` and
   ``code_signature_size`` describe the signature, and
   ``needs_resign`` is true when the slice changes and is signed.
   ``feasible`` is false with an explanatory ``error`` when the
   commands do not fit.

.. class:: CommandChange(...)

   Describes one load command rewrite. Notable attributes:

   ``command_index`` and ``cmd``/``command_name`` identify the command,
   ``old_path`` and ``new_path`` the string replacement, ``file_offset``
   and ``old_size`` the exact byte range currently occupied,
   ``new_size`` and ``size_delta`` the resulting size, and
   ``string_offset``, ``string_old_size`` and ``string_new_size`` the
   location and sizes of the path string itself.

.. exception:: InsufficientHeaderSpaceError

   Subclass of ``ValueError`` raised when a planned rewrite cannot fit
   in the free space of a Mach-O header. Raised before any byte is
   written, so the original file is preserved byte for byte.

.. note:: more information will be added later
