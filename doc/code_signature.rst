:mod:`macholib.code_signature` --- Read-only embedded signature analysis
========================================================================

.. module:: macholib.code_signature
   :synopsis: Read-only analysis of Mach-O embedded code signatures

This module parses the embedded code signature pointed to by the
``LC_CODE_SIGNATURE`` load command without modifying the file.  It locates
the ``CS_SuperBlob`` and every CodeDirectory (``CS_CodeDirectory``) it
contains, validates the blob ranges and CodeDirectory metadata, and
recomputes the per-page digests to decide which bytes of the file are still
consistent with the sealed CodeDirectory.

Trust boundary
--------------

A matching page digest only proves that the sealed bytes were not changed
after the CodeDirectory was created.  It does **not** establish that the
signature is trustworthy, that a certificate chain validates, or that the
operating system will allow the binary to execute.  The CMS (PKCS#7)
signature blob is located and reported but never verified; CMS verification
is explicitly left to a component that can evaluate certificate trust.

Fat (universal) binaries are handled per architecture: every offset stored
in a slice is relative to the start of that slice, so a change inside one
slice can never be attributed to another.

.. function:: analyze_macho(path)

   Analyze the embedded signature of *path* and return an
   :class:`IntegrityReport`.  Malformed signature data is recorded on the
   affected slice report rather than raised; digest mismatches are never
   raised as exceptions.

.. function:: format_report(report)

   Render an :class:`IntegrityReport` as human-readable text, including the
   explicit "CMS not verified" note.

.. class:: IntegrityReport

   Aggregate result with one :class:`SliceReport` per architecture.

   .. attribute:: is_fat

      ``True`` for a fat/universal container.

   .. attribute:: slices

      List of :class:`SliceReport` objects.

   .. attribute:: all_page_hashes_match

      ``True`` only when every CodeDirectory of every signed slice
      recomputes without a page-digest mismatch.

.. class:: SliceReport

   Signature state for one architecture slice.

   .. attribute:: slice_offset

      File offset where the slice begins; zero for a thin Mach-O.

   .. attribute:: blobs

      :class:`BlobInfo` for every sub-blob referenced by the SuperBlob.

   .. attribute:: code_directories

      One :class:`CodeDirectoryReport` per CodeDirectory, including
      alternate CodeDirectories selected for other digest algorithms.

   .. attribute:: cms_blob

      The CMS signature :class:`BlobInfo`, or ``None``.  CMS verification is
      never performed.

   .. attribute:: uncovered_regions

      Byte ranges inside the slice that no page digest covers (gaps between
      ``codeLimit`` and the signature area, and any tail after it).

.. class:: CodeDirectoryReport

   Parsed and verified state of a single CodeDirectory.

   .. attribute:: hash_type_name

      Digest algorithm name (``sha1``, ``sha256``, ``sha256_truncated`` or
      ``sha384``).

   .. attribute:: page_size

      Page size in bytes derived from the ``pageSize`` log2 field.

   .. attribute:: code_limit

      Number of sealed bytes from the start of the slice.

   .. attribute:: n_code_slots

      Number of ordinary page-digest slots, cross-checked against
      ``codeLimit`` and the page size.

   .. attribute:: page_mismatches

      A list of dictionaries describing each page whose recomputed digest
      differs from the stored digest.  Empty when the sealed content is
      intact.

   .. attribute:: structural_error

      Populated when the CodeDirectory metadata is malformed or out of
      range, otherwise ``None``.

A runnable demonstration that mutates a covered page, the signature area and
an uncovered tail is provided in ``examples/integrity_demo.py``.
