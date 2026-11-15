import contextlib
import io
import subprocess
import sys
import unittest
from unittest import mock

from secretpulse.reporting import ReportGenerator


class PdfCommandSafetyTests(unittest.TestCase):
    def test_pdf_paths_are_passed_as_arguments_not_code(self):
        html_path = "report'; import os; os.system('touch /tmp/pwned'); #.html"
        pdf_path = "out'); import os; os.system('touch /tmp/pwned2'); #.pdf"
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0)

        with mock.patch('secretpulse.reporting.subprocess.run', side_effect=fake_run), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(ReportGenerator.generate_pdf(html_path, pdf_path))

        convert = calls[1]
        self.assertEqual(convert[0], sys.executable)
        self.assertEqual(convert[-2:], [html_path, pdf_path])
        self.assertNotIn(html_path, convert[2])
        self.assertNotIn(pdf_path, convert[2])


if __name__ == '__main__':
    unittest.main()
