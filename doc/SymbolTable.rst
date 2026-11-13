:mod:`macholib.SymbolTable` --- Class to read the symbol table from a Mach-O header
===================================================================================

.. module:: macholib.SymbolTable
   :synopsis: Class to read the symbol table from a Mach-O header

.. class:: SymbolTable(macho[, header][, openfile])

   Reads the symbol table for the given Mach-O object.  *header* selects a
   slice of a fat file and defaults to the first slice.  *openfile* defaults
   to the builtin :func:`open`.

   The reader supports both 32-bit and 64-bit nlist records and uses the
   slice's own endianness for the symbol table and all auxiliary tables.

   ``nlists`` is a list of ``(nlist, name)`` pairs in symbol-index order.
   ``localsyms``, ``extdefsyms`` and ``undefsyms`` are slices defined by
   ``LC_DYSYMTAB``; a range outside ``nsyms`` raises :exc:`SymbolTableError`
   instead of silently shrinking.

   Malformed string references are errors, not empty names: an ``n_strx``
   outside the string table or a string without a terminating NUL raises
   :exc:`SymbolTableError`.  ``n_strx == 0`` is the documented null name.

.. method:: diagnose()

   Returns a dictionary describing how stub counts relate to symbols.  The
   important distinction is:

   * ``nindirectsyms`` is the number of 32-bit entries in the indirect table,
     not the number of stubs.
   * Each symbol-pointer or stub section owns the window
     ``[reserved1, reserved1 + size/entry_size)`` of that table.  For
     ``S_SYMBOL_STUBS`` the entry size is ``reserved2``; for pointer sections
     it is 4 bytes in 32-bit slices and 8 bytes in 64-bit slices.
   * Windows may overlap.  Go binaries, for example, make ``__got`` reuse the
     stub window.  Overlap is reported as ``windows_overlap``.
   * Values with ``INDIRECT_SYMBOL_LOCAL`` and/or ``INDIRECT_SYMBOL_ABS`` set
     are markers, not symbol indexes.  ``stubs`` and ``symbol_pointers``
     expose them as ``StubEntry`` records with ``kind`` set to ``"local"``,
     ``"absolute"`` or ``"local-absolute"`` and ``name`` set to ``None``.

   ``windows_in_bounds`` is false when a window runs past ``nindirectsyms``;
   ``errors`` contains those out-of-bounds windows and truncated tables;
   ``referenced_symbol_indexes`` and ``unreferenced_symbol_indexes`` show
   which nlists are actually reachable through the indirect table.

Command line
------------

``python -m macholib symbols FILE ...`` prints each slice, its section
windows, a sample of indirect entries and any structural errors.
