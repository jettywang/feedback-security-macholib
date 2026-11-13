import os
import sys
import tempfile

try:
    from io import StringIO
except ImportError:
    from StringIO import StringIO

from macholib import symbols
from macholib_tests import stub_fixture as fx


if sys.version_info[:2] <= (2, 6):
    import unittest2 as unittest
else:
    import unittest


class TestSymbolsReport(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".dylib", dir=os.environ.get("TMPDIR"))
        os.close(fd)
        self.addCleanup(os.unlink, self.path)
        fx.write_sample(self.path, bits=64)

    def test_report_lists_structural_windows(self):
        out = StringIO()
        failed = symbols.report_symbols(self.path, out, show_all=True)
        text = out.getvalue()
        self.assertFalse(failed)
        self.assertIn("nindirectsyms=6", text)
        self.assertIn(
            "__TEXT,__stubs type=S_SYMBOL_STUBS reserved1=0 reserved2=6 entries=3",
            text,
        )
        self.assertIn("entry=0x80000000 kind=local", text)
        self.assertIn("entry=0xc0000000 kind=local-absolute", text)
        self.assertIn("name=_rare_symbol", text)

    def test_report_flags_out_of_bounds(self):
        with open(self.path, "wb") as fh:
            image, _meta = fx.build_sample(64, nindirectsyms_override=5)
            fh.write(image)
        out = StringIO()
        failed = symbols.report_symbols(self.path, out)
        self.assertTrue(failed)
        self.assertIn("ERROR", out.getvalue())


if __name__ == "__main__":
    unittest.main()
