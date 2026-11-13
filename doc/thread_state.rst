:mod:`macholib.thread_state` --- Thread state decoding
=======================================================

.. module:: macholib.thread_state
   :synopsis: Read-only decoding of LC_THREAD/LC_UNIXTHREAD states

This module decodes the thread states stored in ``LC_THREAD`` and
``LC_UNIXTHREAD`` load commands.  It only reads the register values;
macholib never restores or executes a thread.

All offsets reported by this module are relative to the thread command
payload, that is the byte containing the first ``flavor`` value
(everything after the load command's 8-byte ``cmd``/``cmdsize`` header).

.. class:: ThreadStateCommand

   The states of one thread command.  ``cmd`` is the load command number,
   ``cputype`` the CPU type of the containing Mach-O header, ``endian``
   either ``"<"`` or ``">"``, ``payload`` the exact command bytes and
   ``states`` the decoded records in file order.

   ``pc`` and ``sp`` contain the values from the first state that
   provides them; ``pc_source`` and ``sp_source`` describe where they
   were read from.  Use the ``pc_available`` and ``sp_available``
   properties to distinguish "not present in this state" from a value of
   zero.

   ``has_unsupported_states`` is true when at least one record kept its
   raw bytes instead of being decoded.

   .. method:: describe()

      Return a JSON-friendly dictionary with the command metadata,
      ``pc``/``sp`` availability and provenance, plus one entry per state
      with its flavor, count, raw bytes and decoded registers.

.. class:: ThreadState

   One ``(flavor, count)`` record.  ``raw`` holds exactly ``count * 4``
   bytes from the command.  ``registers`` is ``None`` for unsupported
   CPU/flavor combinations, which are kept as raw bytes only.  States
   with a count larger than the known layout keep the trailing bytes in
   ``extra``; smaller counts are rejected.

   .. method:: describe()

      Return a JSON-friendly dictionary for this state.  ``supported``
      tells whether registers were decoded, and ``pc``/``sp`` each report
      ``available``, ``value`` and the source field offset.

.. class:: ThreadStateError

   Subclass of :class:`ValueError` raised for truncated or inconsistent
   thread commands.  ``offset`` is the payload offset of the rejected
   ``(flavor, count)`` pair, ``data_offset`` the offset of its state data,
   ``flavor`` and ``count`` the rejected pair, ``needed`` and ``available``
   the size in bytes that was required and present, and ``command_index``
   the index of the load command when the error came from a Mach-O file.

.. function:: supported_cpu_types()

   Return the CPU type numbers for which at least one flavor is decoded.
   All other CPU types and flavors keep their raw bytes.

.. function:: thread_state_layout(cputype, flavor)

   Return the layout name used for a CPU/flavor pair, or ``None`` when
   the state is preserved as raw bytes.

.. function:: parse_thread_states(payload, cputype, endian="<", cmd=LC_THREAD)

   Decode *payload*, which starts at the first ``flavor`` field, using
   *cputype* and the byte order of the containing header.  Each record
   consumes ``8 + count * 4`` bytes.  This is the function used by
   :class:`macholib.MachO.MachO`; it is also usable on data recovered
   from another source.
