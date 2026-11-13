"""
Tests for macholib.offline: offline dyld-style resolution.

The fixture builds real (minimal) Mach-O files so parsing is exercised
end to end, while file existence is decided by a caller-supplied probe
over a virtual filesystem -- the analysis host's filesystem and
environment are never consulted.
"""

import os
import shutil
import struct
import tempfile
import unittest

from macholib.MachO import MachO
from macholib.mach_o import (
    LC_ID_DYLIB,
    LC_LOAD_DYLIB,
    LC_RPATH,
    MH_DYLIB,
    MH_EXECUTE,
    MH_MAGIC_64,
)
from macholib.offline import LaunchContext, OfflineResolver


def _dylib_command(cmd_id, path):
    raw = path.encode("utf-8") + b"\x00"
    header_size = 8 + 16  # load_command + dylib_command
    cmdsize = (header_size + len(raw) + 7) & ~7
    return (
        struct.pack("<II", cmd_id, cmdsize)
        + struct.pack("<IIII", 24, 0, 0, 0)
        + raw.ljust(cmdsize - header_size, b"\x00")
    )


def _rpath_command(path):
    raw = path.encode("utf-8") + b"\x00"
    header_size = 8 + 4  # load_command + rpath_command
    cmdsize = (header_size + len(raw) + 7) & ~7
    return (
        struct.pack("<II", LC_RPATH, cmdsize)
        + struct.pack("<I", 12)
        + raw.ljust(cmdsize - header_size, b"\x00")
    )


def make_macho(filetype=MH_DYLIB, rpaths=(), dylibs=(), ident=None):
    """Build a minimal 64-bit little-endian Mach-O image."""
    commands = b""
    ncmds = 0
    if ident is not None:
        commands += _dylib_command(LC_ID_DYLIB, ident)
        ncmds += 1
    for name in dylibs:
        commands += _dylib_command(LC_LOAD_DYLIB, name)
        ncmds += 1
    for path in rpaths:
        commands += _rpath_command(path)
        ncmds += 1
    header = struct.pack(
        "<8I",
        MH_MAGIC_64,
        0x0100000C,  # CPU_TYPE_X86_64
        3,  # CPU_SUBTYPE_X86_64_ALL
        filetype,
        ncmds,
        len(commands),
        0,
        0,
    )
    return header + commands


class VirtualFS(object):
    """
    Caller-supplied file-existence probe over a virtual file set.

    Bundle files are registered under their real (host) path so the
    parser can read them.  ``sample_root`` additionally lets the probe
    translate sample-absolute paths (such as ``/usr/lib/...``) into the
    host directory that mirrors the sample's filesystem.
    """

    def __init__(self, sample_root=None):
        self.files = set()
        self.sample_root = sample_root

    def add(self, path, content):
        path = os.path.normpath(path)
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "wb") as fp:
            fp.write(content)
        self.files.add(path)
        return path

    def probe(self, path):
        path = os.path.normpath(path)
        if path in self.files:
            return True
        if self.sample_root is not None and path.startswith("/"):
            mirrored = os.path.normpath(
                os.path.join(self.sample_root, path.lstrip("/"))
            )
            return mirrored in self.files
        return False


class BundleFixture(object):
    """
    The example bundle from the task description: two plug-ins link the
    same ``@rpath/libUtils.dylib`` name but resolve to different files
    because each contributes its own LC_RPATH to the load chain.

        Contents/MacOS/MyApp            rpath: @executable_path/../Frameworks
        Contents/Frameworks/PlugA.dylib rpath: @loader_path/SharedA
        Contents/Frameworks/PlugB.dylib rpath: @loader_path/SharedB
        Contents/Frameworks/SharedA/libUtils.dylib
        Contents/Frameworks/SharedB/libUtils.dylib
    """

    def __init__(self, root):
        self.sample_root = os.path.join(root, "sample_root")
        self.vfs = VirtualFS(sample_root=self.sample_root)
        contents = os.path.join(root, "Deploy", "MyApp.app", "Contents")
        frameworks = os.path.join(contents, "Frameworks")

        self.exe = self.vfs.add(
            os.path.join(contents, "MacOS", "MyApp"),
            make_macho(
                MH_EXECUTE,
                rpaths=["@executable_path/../Frameworks"],
                dylibs=["@rpath/PlugA.dylib", "@rpath/PlugB.dylib"],
            ),
        )
        self.plug_a = self.vfs.add(
            os.path.join(frameworks, "PlugA.dylib"),
            make_macho(
                MH_DYLIB,
                ident="@rpath/PlugA.dylib",
                rpaths=["@loader_path/SharedA"],
                dylibs=["@rpath/libUtils.dylib", "/usr/lib/libSystem.B.dylib"],
            ),
        )
        self.plug_b = self.vfs.add(
            os.path.join(frameworks, "PlugB.dylib"),
            make_macho(
                MH_DYLIB,
                ident="@rpath/PlugB.dylib",
                rpaths=["@loader_path/SharedB"],
                dylibs=["@rpath/libUtils.dylib", "@rpath/libMissing.dylib"],
            ),
        )
        self.utils_a = self.vfs.add(
            os.path.join(frameworks, "SharedA", "libUtils.dylib"),
            make_macho(
                MH_DYLIB,
                ident="@rpath/libUtils.dylib",
                dylibs=["@rpath/PlugA.dylib"],  # circular reference
            ),
        )
        self.utils_b = self.vfs.add(
            os.path.join(frameworks, "SharedB", "libUtils.dylib"),
            make_macho(MH_DYLIB, ident="@rpath/libUtils.dylib"),
        )
        # Registered under the sample's absolute path: the probe maps
        # "/usr/lib/..." into the mirror of the sample's filesystem.
        self.libsystem = "/usr/lib/libSystem.B.dylib"
        self.vfs.add(
            os.path.join(self.sample_root, "usr", "lib", "libSystem.B.dylib"),
            make_macho(MH_DYLIB, ident=self.libsystem),
        )

    def resolver(self, **env):
        launch = LaunchContext(executable_path=self.exe, env=env)
        return OfflineResolver(launch_context=launch, file_probe=self.vfs.probe)


class TestOffline(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="macholib-offline-")
        self.addCleanup(shutil.rmtree, self.tmpdir, True)
        self.bundle = BundleFixture(self.tmpdir)

    def test_walk_rpaths(self):
        macho = MachO(self.bundle.plug_a)
        rpaths = []
        for header in macho.headers:
            rpaths.extend(raw for _idx, raw in header.walkRpaths())
        self.assertEqual(rpaths, ["@loader_path/SharedA"])

    def test_same_rpath_name_resolves_per_loader(self):
        resolver = self.bundle.resolver()
        root = resolver.scan(self.bundle.exe)

        dep_a = root.dependencies[0].child.dependencies[0]
        dep_b = root.dependencies[1].child.dependencies[0]

        # Both plug-ins reference the very same install name...
        self.assertEqual(dep_a.name, "@rpath/libUtils.dylib")
        self.assertEqual(dep_b.name, "@rpath/libUtils.dylib")

        # ...but resolve to different files, because the run-path stack
        # of each load chain differs.
        self.assertEqual(dep_a.resolution.resolved, self.bundle.utils_a)
        self.assertEqual(dep_b.resolution.resolved, self.bundle.utils_b)

        # The cache must not confuse the two contexts: resolving the same
        # name through each loader's run-path context returns the
        # loader-specific result, and identical contexts share the cache.
        exe_entry = resolver.expand_rpath_entry(
            "@executable_path/../Frameworks", self.bundle.exe
        )
        entry_a = resolver.expand_rpath_entry(
            "@loader_path/SharedA", self.bundle.plug_a
        )
        entry_b = resolver.expand_rpath_entry(
            "@loader_path/SharedB", self.bundle.plug_b
        )
        context_a = (entry_a, exe_entry)
        context_b = (entry_b, exe_entry)

        res_a = resolver.resolve(
            "@rpath/libUtils.dylib",
            loader_path=os.path.dirname(self.bundle.plug_a),
            run_path_context=context_a,
        )
        res_b = resolver.resolve(
            "@rpath/libUtils.dylib",
            loader_path=os.path.dirname(self.bundle.plug_b),
            run_path_context=context_b,
        )
        self.assertIsNot(res_a, res_b)
        self.assertEqual(res_a.resolved, self.bundle.utils_a)
        self.assertEqual(res_b.resolved, self.bundle.utils_b)
        self.assertIs(
            res_a,
            resolver.resolve(
                "@rpath/libUtils.dylib",
                loader_path=os.path.dirname(self.bundle.plug_a),
                run_path_context=context_a,
            ),
        )

    def test_missing_library_reports_search_order(self):
        resolver = self.bundle.resolver()
        root = resolver.scan(self.bundle.exe)
        plug_b = root.dependencies[1].child
        missing = plug_b.dependencies[1]

        self.assertEqual(missing.name, "@rpath/libMissing.dylib")
        self.assertEqual(missing.resolution.status, "missing")
        self.assertIsNone(missing.resolution.resolved)

        searched = [c.path for c in missing.resolution.candidates]
        frameworks = os.path.dirname(self.bundle.plug_b)
        self.assertEqual(
            searched[0],
            os.path.normpath(os.path.join(frameworks, "SharedB", "libMissing.dylib")),
        )
        self.assertEqual(
            searched[1],
            os.path.normpath(os.path.join(frameworks, "libMissing.dylib")),
        )
        # dyld default fallbacks are tried last, using the sample's home.
        self.assertIn(
            os.path.join("/usr", "lib", "libMissing.dylib"), searched
        )

    def test_circular_reference_reported(self):
        resolver = self.bundle.resolver()
        root = resolver.scan(self.bundle.exe)
        utils_a = root.dependencies[0].child.dependencies[0].child
        back = utils_a.dependencies[0]

        self.assertEqual(back.name, "@rpath/PlugA.dylib")
        self.assertEqual(back.resolution.status, "resolved")
        self.assertIsNone(back.child)
        self.assertIn("circular reference", back.note)
        self.assertEqual(len(resolver.cycles), 1)

    def test_env_override_comes_from_launch_context(self):
        override = self.bundle.vfs.add(
            os.path.join(self.tmpdir, "override", "libUtils.dylib"),
            make_macho(MH_DYLIB, ident="@rpath/libUtils.dylib"),
        )
        resolver = self.bundle.resolver(
            DYLD_LIBRARY_PATH=os.path.join(self.tmpdir, "override")
        )
        root = resolver.scan(self.bundle.exe)
        dep_a = root.dependencies[0].child.dependencies[0]

        self.assertEqual(dep_a.resolution.resolved, override)
        self.assertTrue(
            dep_a.resolution.rule.startswith("DYLD_LIBRARY_PATH[0]"),
            dep_a.resolution.rule,
        )
        self.assertFalse(dep_a.resolution.deployment_relative)

    def test_host_environment_is_ignored(self):
        saved = os.environ.get("DYLD_LIBRARY_PATH")
        os.environ["DYLD_LIBRARY_PATH"] = os.path.join(self.tmpdir, "bogus")
        try:
            resolver = self.bundle.resolver()
            root = resolver.scan(self.bundle.exe)
            dep_a = root.dependencies[0].child.dependencies[0]
            # The host's DYLD_LIBRARY_PATH must not leak into resolution.
            self.assertEqual(dep_a.resolution.resolved, self.bundle.utils_a)
            for candidate in dep_a.resolution.candidates:
                self.assertNotIn("bogus", candidate.path)
        finally:
            if saved is None:
                del os.environ["DYLD_LIBRARY_PATH"]
            else:
                os.environ["DYLD_LIBRARY_PATH"] = saved

    def test_deployment_relative_flag(self):
        resolver = self.bundle.resolver()
        root = resolver.scan(self.bundle.exe)

        # @rpath hits via @loader_path/@executable_path entries depend on
        # where the bundle is deployed.
        plug_a_dep = root.dependencies[0]
        self.assertTrue(plug_a_dep.resolution.deployment_relative)
        utils_dep = plug_a_dep.child.dependencies[0]
        self.assertTrue(utils_dep.resolution.deployment_relative)

        # An absolute install name does not.
        libsystem_dep = plug_a_dep.child.dependencies[1]
        self.assertEqual(libsystem_dep.name, "/usr/lib/libSystem.B.dylib")
        self.assertEqual(libsystem_dep.resolution.resolved, self.bundle.libsystem)
        self.assertFalse(libsystem_dep.resolution.deployment_relative)

    def test_no_executable_path_is_reported(self):
        launch = LaunchContext(executable_path=None)
        resolver = OfflineResolver(launch_context=launch, file_probe=self.bundle.vfs.probe)
        resolution = resolver.resolve("@executable_path/../Frameworks/x.dylib")
        self.assertEqual(resolution.status, "missing")
        self.assertTrue(
            any("no executable_path" in note for note in resolution.notes),
            resolution.notes,
        )

    def test_requires_explicit_probe(self):
        self.assertRaises(TypeError, OfflineResolver)

    def test_explain_output(self):
        resolver = self.bundle.resolver()
        root = resolver.scan(self.bundle.exe)
        report = "\n".join(resolver.explain_scan(root))
        self.assertIn("LC_RPATH '@loader_path/SharedA'", report)
        self.assertIn("[deployment-relative]", report)
        self.assertIn("MISSING", report)
        self.assertIn("circular reference", report)

        dep_a = root.dependencies[0].child.dependencies[0]
        explanation = "\n".join(resolver.explain_resolution(dep_a.resolution))
        self.assertIn("HIT", explanation)
        self.assertIn("run-path[0]", explanation)


if __name__ == "__main__":
    unittest.main()
