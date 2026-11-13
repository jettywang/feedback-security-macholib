Offline dependency resolution
=============================

.. module:: macholib.offline
   :synopsis: Offline dyld-style resolution of Mach-O install names

The :mod:`macholib.offline` module resolves Mach-O install names
(``@rpath``, ``@loader_path`` and ``@executable_path`` references)
*offline*: nothing about the analysis host leaks into the result.

* The caller supplies a :class:`LaunchContext` with the *sample's* launch
  environment: the main executable path and its ``DYLD_*`` variables.
  The host's ``os.environ`` is never consulted.
* The caller supplies a file-existence probe, so candidate paths are
  checked against the sample's filesystem (a mounted disk image, a
  fixture set, ...) instead of the host filesystem.

Every candidate path is reported with the rule that produced it, a flag
marking results that depend on the deployment location of the bundle,
and the probe verdict.  Run-path context is kept per load chain: the
same install name referenced by two different loaders is resolved and
cached separately, because dyld searches the run-path stack of the
referencing chain.

Example
-------

.. sourcecode:: python

    from macholib.offline import LaunchContext, OfflineResolver

    launch = LaunchContext(
        executable_path="/samples/MyApp.app/Contents/MacOS/MyApp",
        env={"DYLD_LIBRARY_PATH": "/payload/lib"},
    )
    resolver = OfflineResolver(
        launch_context=launch,
        file_probe=lambda path: path in sample_files,
    )
    root = resolver.scan("/samples/MyApp.app/Contents/MacOS/MyApp")
    for line in resolver.explain_scan(root):
        print(line)

Launch environment
------------------

.. class:: LaunchContext(executable_path=None, env=None, home="/")

   The launch environment of the sample under analysis.

   .. attribute:: executable_path

      Path of the main executable in the sample's filesystem; its
      directory is what ``@executable_path`` expands to.  When None,
      ``@executable_path`` cannot be expanded and the resolution notes
      say so.

   .. attribute:: env

      Mapping with the sample's ``DYLD_*`` variables.  Defaults to an
      empty environment.

   .. attribute:: home

      The sample user's home directory, used for dyld's default
      fallback paths (``~/lib``, ``~/Library/Frameworks``).

Resolving and scanning
----------------------

.. class:: OfflineResolver(launch_context=None, file_probe=None, \
                           shared_cache_probe=None, macho_factory=None)

   .. method:: resolve(name, loader_path=None, run_path_context=())

      Resolve one install *name* as referenced by the image in
      *loader_path* with the given run-path context (nearest loader
      first).  Returns a :class:`Resolution`.  Results are cached per
      (name, loader, run-path context), so results are never reused
      across different loader contexts.

   .. method:: scan(root_path)

      Parse *root_path* and its dependency chain, resolving every
      referenced install name in its own run-path context.  Circular
      references are reported on the dependency edge (dyld reuses the
      in-flight image) and collected in ``resolver.cycles``.

   .. method:: explain_resolution(resolution)

      Return the full search order for one resolution as text lines:
      every candidate, the rule that produced it, and whether it hit.

   .. method:: explain_scan(node)

      Return a text report for a scanned dependency graph, marking
      deployment-relative results and missing libraries.

   ``file_probe`` is required and decides whether a candidate path
   exists in the sample's filesystem.  ``macho_factory`` can be
   overridden to parse Mach-O files from a non-host store (by default
   :class:`macholib.MachO.MachO` is used, which reads host paths).

Result objects
--------------

.. class:: Resolution

   .. attribute:: requested

      The install name as referenced.

   .. attribute:: status

      ``"resolved"`` or ``"missing"``.

   .. attribute:: resolved

      The adopted path, or None when missing.

   .. attribute:: rule

      The rule that produced the adopted path, for example
      ``DYLD_LIBRARY_PATH[0]`` or
      ``run-path[0] '@loader_path/SharedA' declared by /a/PlugA.dylib``.

   .. attribute:: candidates

      List of :class:`Candidate` objects in search order.

   .. attribute:: notes

      Rules that were applicable but produced no candidate (for example
      ``@executable_path`` without a known main executable), and the
      reason a library is reported missing.

   .. attribute:: deployment_relative

      True when the adopted path depends on where the bundle is
      deployed (it was reached through ``@executable_path``,
      ``@loader_path`` or a run-path entry using those tokens).

.. class:: Candidate

   One concrete path tried while resolving: ``path``, ``rule``,
   ``deployment_relative``, ``exists`` and ``via_shared_cache``.

.. class:: RPathEntry

   One LC_RPATH entry after token expansion: ``declarer``, ``raw``,
   ``expanded`` and ``deployment_relative``.
