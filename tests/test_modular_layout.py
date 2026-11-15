"""Ensure the modular source and generated single-file distribution stay in sync."""

import unittest
from pathlib import Path

import build_secretpulse


ROOT = Path(__file__).resolve().parents[1]


class ModularLayoutTests(unittest.TestCase):
    def test_generated_bundle_is_current(self):
        expected = build_secretpulse.render()
        actual = (ROOT / 'SecretPulse.py').read_text()
        self.assertEqual(actual, expected)
        self.assertEqual(actual, build_secretpulse.render())

    def test_bundle_is_standalone(self):
        source = (ROOT / 'SecretPulse.py').read_text()
        self.assertNotIn('from .', source)
        self.assertNotIn('from secretpulse', source)
        self.assertNotIn('import secretpulse', source)

    def test_package_exposes_core_components(self):
        from secretpulse import __version__
        from secretpulse.analysis import AccuracyEngine, FalsePositiveFilter
        from secretpulse.cli import main
        from secretpulse.scanner import SecretScanner
        from secretpulse.verification import ActiveVerifierV2

        self.assertEqual(__version__, '5.6.0')
        self.assertTrue(callable(main))
        for component in (AccuracyEngine, FalsePositiveFilter,
                          SecretScanner, ActiveVerifierV2):
            self.assertTrue(isinstance(component, type), component)


if __name__ == '__main__':
    unittest.main()
