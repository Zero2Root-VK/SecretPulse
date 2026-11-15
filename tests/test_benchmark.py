import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'sp_bench', ROOT / 'benchmarks' / 'run_benchmark.py')
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)


class MatchingTests(unittest.TestCase):
    def test_match_counts_and_evidence_accuracy(self):
        labels = [
            {'types': ['GitHub Token'], 'line': 2,
             'category': 'secret', 'severity': 'CRITICAL'},
            {'types': ['Stripe Publishable Key'], 'line': 4,
             'category': 'public_identifier', 'severity': 'LOW'},
        ]
        findings = [
            {'type': 'GitHub Token', 'line': 2, 'category': 'secret',
             'severity': 'CRITICAL', 'source': 'file:///app.js'},
            {'type': 'Stripe Publishable Key', 'line': 4,
             'category': 'public_identifier', 'severity': 'LOW',
             'source': 'file:///app.js'},
            {'type': 'High-Entropy Secret', 'line': 9, 'category': 'secret',
             'severity': 'LOW', 'source': 'file:///app.js'},
        ]
        match = bench._match_case(labels, findings)
        self.assertEqual(len(match['pairs']), 2)
        self.assertEqual(len(match['false_positives']), 1)
        self.assertEqual(match['misses'], [])
        self.assertEqual(match['line_correct'], 2)
        self.assertEqual(match['category_correct'], 2)
        self.assertEqual(match['severity_correct'], 2)

    def test_wrong_line_is_a_miss_and_false_positive(self):
        labels = [{'types': ['GitHub Token'], 'line': 2,
                   'category': 'secret', 'severity': 'CRITICAL'}]
        findings = [{'type': 'GitHub Token', 'line': 3, 'category': 'secret',
                     'severity': 'CRITICAL', 'source': 'file:///app.js'}]
        match = bench._match_case(labels, findings)
        self.assertEqual(match['pairs'], [])
        self.assertEqual(len(match['misses']), 1)
        self.assertEqual(len(match['false_positives']), 1)

    def test_source_map_label_matches_embedded_source(self):
        label = {'types': ['GitHub Token'], 'line': 2,
                 'source': 'webpack://app/src/api.ts',
                 'category': 'secret'}
        finding = {'type': 'GitHub Token', 'line': 2, 'category': 'secret',
                   'source': 'file:///app.js.map → webpack://app/src/api.ts'}
        self.assertTrue(bench._label_matches(label, finding))
        finding['source'] = 'file:///app.js.map → webpack://app/src/other.ts'
        self.assertFalse(bench._label_matches(label, finding))


class CorpusValidationTests(unittest.TestCase):
    def _write_corpus(self, root, manifest, files):
        root.mkdir(parents=True, exist_ok=True)
        (root / 'manifest.json').write_text(json.dumps(manifest))
        for name, content in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)

    def test_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'corpus'
            self._write_corpus(root, {
                'schema': 1,
                'cases': [{'id': 'escape', 'kind': 'file',
                           'path': '../outside.js', 'labels': []}],
            }, {})
            with self.assertRaises(bench.BenchmarkError):
                bench._load_manifest(root)

    def test_rejects_duplicate_ids_and_invalid_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'corpus'
            self._write_corpus(root, {
                'schema': 1,
                'cases': [
                    {'id': 'same', 'kind': 'file', 'path': 'a.js', 'labels': []},
                    {'id': 'same', 'kind': 'file', 'path': 'a.js', 'labels': []},
                ],
            }, {'a.js': 'const a = 1;\n'})
            with self.assertRaises(bench.BenchmarkError):
                bench._load_manifest(root)

            self._write_corpus(root, {
                'schema': 1,
                'cases': [{
                    'id': 'bad-label', 'kind': 'file', 'path': 'a.js',
                    'labels': [{'types': [], 'category': 'secret'}],
                }],
            }, {'a.js': 'const a = 1;\n'})
            with self.assertRaises(bench.BenchmarkError):
                bench._load_manifest(root)

            self._write_corpus(root, {
                'schema': 1,
                'cases': [{
                    'id': 'typo-label', 'kind': 'file', 'path': 'a.js',
                    'labels': [{'types': ['Github Token'], 'category': 'secret'}],
                }],
            }, {'a.js': 'const a = 1;\n'})
            with self.assertRaisesRegex(bench.BenchmarkError, 'unknown detection type'):
                bench._load_manifest(root)


class BenchmarkRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.args = bench._parse_args([])
        cls.payload = bench.run_benchmark(ROOT / 'benchmarks' / 'corpus', cls.args)

    def test_builtin_corpus_has_no_misses_or_false_positives(self):
        summary = self.payload['summary']
        self.assertTrue(self.payload['passed'])
        self.assertEqual(summary['fn'], 0)
        self.assertEqual(summary['fp'], 0)
        self.assertGreaterEqual(summary['expected'], 20)
        self.assertEqual(summary['precision'], 1.0)
        self.assertEqual(summary['recall'], 1.0)
        self.assertEqual(summary['line_accuracy'], 1.0)
        self.assertEqual(summary['category_accuracy'], 1.0)
        self.assertEqual(summary['severity_accuracy'], 1.0)

    def test_clean_cases_stay_clean_after_filtering(self):
        cases = {case['id']: case for case in self.payload['cases']}
        for case_id in (
                'clean-vendor-bundle', 'clean-package-lock',
                'clean-public-config', 'clean-documentation-placeholders'):
            self.assertEqual(cases[case_id]['fp'], 0, case_id)
            self.assertEqual(cases[case_id]['detected'], 0, case_id)
        self.assertGreater(cases['clean-documentation-placeholders']
                           ['filtered_candidates'], 0)

    def test_notebook_case_scans_cells_and_outputs(self):
        case = next(c for c in self.payload['cases']
                    if c['id'] == 'notebook-cell-and-output')
        self.assertEqual(case['tp'], 3)
        self.assertEqual(case['fp'], 0)
        self.assertEqual(case['line_accuracy'], 1.0)
        self.assertTrue(any(
            label['types'] == ['Hardcoded Password']
            for label in case['matched_labels']))

    def test_source_map_case_scans_embedded_sources(self):
        case = next(c for c in self.payload['cases']
                    if c['id'] == 'source-map-original-sources')
        self.assertEqual(case['tp'], 3)
        self.assertEqual(case['line_accuracy'], 1.0)
        self.assertEqual(case['severity_accuracy'], 1.0)

    def test_baseline_comparison_detects_regression(self):
        baseline = json.loads(json.dumps(self.payload))
        baseline['summary']['recall'] = 1.01
        regressions = bench._compare_baseline(
            self.payload['summary'], baseline, 0.0)
        self.assertTrue(any('recall regressed' in item for item in regressions))

    def test_threshold_failures_are_reported(self):
        summary = dict(self.payload['summary'])
        summary['precision'] = 0.5
        summary['clean_noise_cases'] = 1
        args = bench._parse_args(['--min-precision', '0.9', '--max-clean-noise', '0'])
        failures = bench._threshold_failures(summary, args)
        self.assertTrue(any('precision' in item for item in failures))
        self.assertTrue(any('clean noise' in item for item in failures))

    def test_finding_summary_redacts_secret_value(self):
        secret = 'ghp_' + 'A' * 36
        summary = bench._finding_summary({
            'type': 'GitHub Token', 'category': 'secret', 'line': 3,
            'value': secret, 'snippet': f'token = "{secret}"',
        })
        self.assertNotIn(secret, summary['snippet'])
        self.assertIn('***', summary['snippet'])

    def test_invalid_settings_and_baselines_are_rejected(self):
        args = bench._parse_args(['--min-recall', '-0.1'])
        with self.assertRaisesRegex(bench.BenchmarkError, '--min-recall'):
            bench.run_benchmark(ROOT / 'benchmarks' / 'corpus', args)
        with self.assertRaisesRegex(bench.BenchmarkError, 'not an integer'):
            bench._compare_baseline(
                self.payload['summary'], {'summary': {'tp': '24'}}, 0.0)

    def test_cli_writes_json_and_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_path = Path(tmp) / 'bench.json'
            md_path = Path(tmp) / 'bench.md'
            with contextlib.redirect_stdout(io.StringIO()):
                code = bench.main([
                    '--corpus', str(ROOT / 'benchmarks' / 'corpus'),
                    '--json', str(json_path), '--markdown', str(md_path),
                ])
            self.assertEqual(code, 0)
            data = json.loads(json_path.read_text())
            self.assertTrue(data['passed'])
            self.assertIn('SecretPulse Detection Benchmark', md_path.read_text())
            self.assertEqual(data['summary']['tp'], data['summary']['expected'])


class SourceMapScannerTests(unittest.TestCase):
    def test_scan_sourcemap_data_reports_embedded_file_and_line(self):
        value = 'ghp_' + 'Q' * 36
        payload = {
            'version': 3,
            'sources': ['webpack://demo/src/client.ts'],
            'sourcesContent': [
                'const client = createClient();\n'
                f'const token = "{value}";\n'
            ],
        }
        scanner = bench.sp.SecretScanner(show_progress=False)
        with contextlib.redirect_stdout(io.StringIO()):
            result = scanner.scan_sourcemap_data(payload, 'file:///app.js.map')
        self.assertEqual(result['sources_scanned'], 1)
        self.assertTrue(any(
            finding['type'] == 'GitHub Token'
            and finding['line'] == 2
            and finding['source'].endswith('webpack://demo/src/client.ts')
            for finding in scanner.found_secrets
        ))


if __name__ == '__main__':
    unittest.main()
