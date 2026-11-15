import contextlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from secretpulse.analysis import FalsePositiveFilter
from secretpulse.scanner import SecretScanner


ROOT = Path(__file__).resolve().parents[1]
GITHUB_TOKEN = 'ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'
JWT_SECRET = '8f4b2c9a7d1e6f30b5a2c8d4e9f17263'


def _run_git(repo, *args):
    subprocess.run(
        ['git', '-C', str(repo), *args],
        check=True, capture_output=True, text=True)


@unittest.skipUnless(shutil.which('git'), 'git is required')
class StagedScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / 'repo'
        self.repo.mkdir()
        _run_git(self.repo, 'init', '-q')
        _run_git(self.repo, 'config', 'user.email', 'test@example.com')
        _run_git(self.repo, 'config', 'user.name', 'Test')
        (self.repo / 'README.md').write_text('# fixture\n')
        _run_git(self.repo, 'add', 'README.md')
        _run_git(self.repo, 'commit', '-qm', 'base')

    def tearDown(self):
        self.tmp.cleanup()

    def _stage(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        _run_git(self.repo, 'add', name)
        return path

    def test_reads_index_not_working_tree(self):
        path = self._stage(
            'src/app.js',
            f'const config = {{}};\nconst token = "{GITHUB_TOKEN}";\n')
        path.write_text('const config = {};\n')

        scanner = SecretScanner(show_progress=False, max_retries=0)
        with contextlib.redirect_stdout(io.StringIO()):
            scanned = scanner.scan_staged_changes(self.repo)

        self.assertEqual(scanned, 1)
        github = [f for f in scanner.found_secrets if f['type'] == 'GitHub Token']
        self.assertEqual(len(github), 1)
        self.assertEqual(github[0]['line'], 2)
        self.assertEqual(github[0]['value'], GITHUB_TOKEN)
        self.assertTrue(github[0]['source'].endswith('src/app.js'))
        self.assertTrue(github[0]['source'].startswith('git-staged://'))

    def test_deleted_files_and_clean_staging_are_ignored(self):
        self._stage('removed.js', f'const token = "{GITHUB_TOKEN}";\n')
        _run_git(self.repo, 'rm', '-q', '-f', 'removed.js')
        self._stage('clean.js', 'const value = 1;\n')

        scanner = SecretScanner(show_progress=False, max_retries=0)
        with contextlib.redirect_stdout(io.StringIO()):
            scanned = scanner.scan_staged_changes(self.repo)

        self.assertEqual(scanned, 1)
        self.assertEqual(scanner.found_secrets, [])

    def test_non_repository_returns_failure(self):
        outside = Path(self.tmp.name) / 'outside'
        outside.mkdir()
        scanner = SecretScanner(show_progress=False, max_retries=0)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(scanner.scan_staged_changes(outside), -1)

    def test_cli_staged_gate_fails_and_does_not_echo_secret(self):
        self._stage('app.js', f'const token = "{GITHUB_TOKEN}";\n')
        result = subprocess.run(
            [sys.executable, '-m', 'secretpulse', '--staged', str(self.repo),
             '--fail-on', 'high'],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
        )
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 1, combined[-1000:])
        self.assertIn('GitHub Token', result.stdout)
        self.assertNotIn(GITHUB_TOKEN, combined)


class NotebookScanTests(unittest.TestCase):
    def test_cell_sources_and_text_outputs_are_scanned(self):
        notebook = {
            'cells': [
                {'cell_type': 'markdown', 'source': ['password = "changeme"\n']},
                {'cell_type': 'code', 'source': [
                    'import os\n',
                    f'GITHUB_TOKEN = "{GITHUB_TOKEN}"\n',
                    f'JWT_SECRET = "{JWT_SECRET}"\n',
                    'SESSION_SECRET = "supersecretsupersecret"\n',
                ], 'outputs': [{
                    'output_type': 'stream',
                    'text': ['ready\n', 'slack=xoxb-abcdefghijklmnopqrstuvwx\n'],
                }]},
            ],
        }
        scanner = SecretScanner(show_progress=False, max_retries=0)
        with contextlib.redirect_stdout(io.StringIO()):
            result = scanner.scan_notebook_data(
                notebook, 'file:///fixtures/client.ipynb')

        self.assertEqual(result, {'cells_total': 2, 'texts_scanned': 3})
        by_type = {}
        for finding in scanner.found_secrets:
            by_type.setdefault(finding['type'], []).append(finding)
        self.assertEqual(by_type['GitHub Token'][0]['line'], 2)
        self.assertEqual(by_type['Slack Token'][0]['line'], 2)
        self.assertTrue(by_type['GitHub Token'][0]['source'].endswith(
            '[cell 2 code]'))
        self.assertTrue(by_type['Slack Token'][0]['source'].endswith(
            '[cell 2 output 1]'))
        signing = [f for f in by_type['Hardcoded Password']
                   if f['value'] == JWT_SECRET]
        self.assertEqual(signing[0]['line'], 3)
        self.assertTrue(signing[0]['source'].endswith('[cell 2 code]'))

        kept, removed = FalsePositiveFilter.filter_findings(scanner.found_secrets)
        self.assertFalse(any(
            f.get('value') == 'supersecretsupersecret' for f in kept))
        self.assertTrue(any(
            f.get('value') == 'supersecretsupersecret' for f in removed))

    def test_malformed_notebook_falls_back_to_raw_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'broken.ipynb'
            path.write_text('{"cells": [}\n')
            scanner = SecretScanner(show_progress=False, max_retries=0)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(scanner.scan_local_path(path), 1)


if __name__ == '__main__':
    unittest.main()
