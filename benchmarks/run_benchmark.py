#!/usr/bin/env python3
"""Precision/recall benchmark for SecretPulse's production detection pipeline."""

import argparse
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('secretpulse', ROOT / 'SecretPulse.py')
sp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sp)

CATEGORIES = ('secret', 'public_identifier')
SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
KINDS = ('file', 'sourcemap', 'notebook')
EXTRA_DETECTION_TYPES = {
    'High-Entropy Secret',
    'Base64-Encoded Secret',
    'Base64-Encoded Secret (atob)',
    'URL-Encoded Secret',
    'Obfuscated Secret',
}


class BenchmarkError(Exception):
    """Raised when the corpus or baseline is malformed."""


def _metric(numerator, denominator, empty=1.0):
    return empty if denominator == 0 else numerator / denominator


def _f1(precision, recall):
    return 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)


def _known_detection_types():
    scanner = sp.SecretScanner(show_progress=False, max_retries=0)
    return set(scanner.patterns) | EXTRA_DETECTION_TYPES


def _load_manifest(corpus_root):
    manifest_path = corpus_root / 'manifest.json'
    if not manifest_path.is_file():
        raise BenchmarkError(f'Manifest not found: {manifest_path}')
    try:
        data = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as exc:
        raise BenchmarkError(f'Invalid manifest JSON: {exc}') from exc
    if not isinstance(data, dict) or data.get('schema') != 1:
        raise BenchmarkError('Manifest schema must be version 1')
    cases = data.get('cases')
    if not isinstance(cases, list) or not cases:
        raise BenchmarkError('Manifest must contain at least one case')

    root = corpus_root.resolve()
    seen_ids = set()
    known_types = None
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise BenchmarkError(f'Case #{index} must be an object')
        case_id = case.get('id')
        if not isinstance(case_id, str) or not case_id.strip():
            raise BenchmarkError(f'Case #{index} has no valid id')
        if case_id in seen_ids:
            raise BenchmarkError(f'Duplicate case id: {case_id}')
        seen_ids.add(case_id)
        if case.get('kind') not in KINDS:
            raise BenchmarkError(f'{case_id}: kind must be one of {KINDS}')
        rel_path = case.get('path')
        if not isinstance(rel_path, str) or not rel_path:
            raise BenchmarkError(f'{case_id}: path is required')
        target = (corpus_root / rel_path).resolve()
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise BenchmarkError(f'{case_id}: path escapes the corpus root') from exc
        if not target.is_file():
            raise BenchmarkError(f'{case_id}: fixture not found: {rel_path}')
        labels = case.get('labels')
        if not isinstance(labels, list):
            raise BenchmarkError(f'{case_id}: labels must be a list')
        if labels and known_types is None:
            known_types = _known_detection_types()
        for label_index, label in enumerate(labels):
            _validate_label(case_id, label_index, label, known_types)
    return data


def _validate_label(case_id, index, label, known_types):
    where = f'{case_id} label #{index}'
    if not isinstance(label, dict):
        raise BenchmarkError(f'{where} must be an object')
    types = label.get('types')
    if (not isinstance(types, list) or not types
            or any(not isinstance(item, str) or not item for item in types)):
        raise BenchmarkError(f'{where}: types must be a non-empty string list')
    for type_name in types:
        if type_name not in known_types and not type_name.startswith('Obfuscated Secret ('):
            raise BenchmarkError(f'{where}: unknown detection type: {type_name}')
    if label.get('category') not in CATEGORIES:
        raise BenchmarkError(f'{where}: category must be one of {CATEGORIES}')
    if 'line' in label and (not isinstance(label['line'], int) or label['line'] < 1):
        raise BenchmarkError(f'{where}: line must be a positive integer')
    if 'severity' in label and label['severity'] not in SEVERITIES:
        raise BenchmarkError(f'{where}: invalid severity')
    if 'source' in label and not isinstance(label['source'], str):
        raise BenchmarkError(f'{where}: source must be a string')


def _new_scanner(calibration_dir):
    scanner = sp.SecretScanner(show_progress=False, max_retries=0)
    engine = scanner.accuracy_engine
    engine.calibration_file = str(calibration_dir / 'calibration.json')
    engine.known_secrets_db = str(calibration_dir / 'known_secrets.json')
    engine.cross_repo_db = str(calibration_dir / 'cross_repo.json')
    engine.trust_decay_enabled = False
    return scanner


def _scan_case(case, corpus_root, calibration_dir):
    scanner = _new_scanner(calibration_dir)
    path = corpus_root / case['path']
    source = path.as_uri()
    started = time.perf_counter()
    with contextlib.redirect_stdout(io.StringIO()):
        if case['kind'] == 'sourcemap':
            try:
                map_data = json.loads(path.read_text())
            except json.JSONDecodeError as exc:
                raise BenchmarkError(f"{case['id']}: invalid source map JSON: {exc}") from exc
            if not isinstance(map_data, dict):
                raise BenchmarkError(f"{case['id']}: source map must be a JSON object")
            scanner.scan_sourcemap_data(map_data, source)
        elif case['kind'] == 'notebook':
            try:
                notebook = json.loads(path.read_text())
            except json.JSONDecodeError as exc:
                raise BenchmarkError(f"{case['id']}: invalid notebook JSON: {exc}") from exc
            try:
                scanner.scan_notebook_data(notebook, source)
            except ValueError as exc:
                raise BenchmarkError(f"{case['id']}: {exc}") from exc
        else:
            scanner.scan_content(path.read_text(), source)

        raw_count = len(scanner.found_secrets)
        kept, removed = sp.FalsePositiveFilter.filter_findings(scanner.found_secrets)
        scanner.fp_removed = removed
        scanner.found_secrets = kept
        scanner.stats['fp_filtered'] = len(removed)
        if kept:
            scanner.found_secrets = scanner.accuracy_engine.process_findings(
                kept, scanner.content_cache)
        unified = scanner.collect_findings()
    elapsed_ms = (time.perf_counter() - started) * 1000
    findings = [f for f in unified if f.get('category') in CATEGORIES]
    return {
        'findings': findings,
        'raw_count': raw_count,
        'filtered_count': len(removed),
        'filter_reasons': sorted({r.get('fp_reason', 'unknown') for r in removed}),
        'duration_ms': round(elapsed_ms, 2),
    }


def _source_matches(label, finding):
    expected = label.get('source')
    if not expected:
        return True
    actual = str(finding.get('source', ''))
    return (actual == expected or actual.endswith('→ ' + expected)
            or actual.endswith(' ' + expected))


def _label_matches(label, finding):
    if finding.get('type') not in label['types']:
        return False
    if not _source_matches(label, finding):
        return False
    if 'line' in label and finding.get('line') != label['line']:
        return False
    return True


def _match_case(labels, findings):
    matched_labels = set()
    matched_findings = set()
    pairs = []
    for label_index, label in enumerate(labels):
        for finding_index, finding in enumerate(findings):
            if finding_index in matched_findings:
                continue
            if _label_matches(label, finding):
                matched_labels.add(label_index)
                matched_findings.add(finding_index)
                pairs.append((label, finding))
                break

    misses = [label for index, label in enumerate(labels)
              if index not in matched_labels]
    false_positives = [finding for index, finding in enumerate(findings)
                       if index not in matched_findings]

    line_pairs = [(label, finding) for label, finding in pairs if 'line' in label]
    severity_pairs = [(label, finding) for label, finding in pairs if 'severity' in label]
    return {
        'pairs': pairs,
        'misses': misses,
        'false_positives': false_positives,
        'line_correct': sum(
            1 for label, finding in line_pairs
            if label['line'] == finding.get('line')),
        'line_total': len(line_pairs),
        'category_correct': sum(
            1 for label, finding in pairs
            if label['category'] == finding.get('category')),
        'severity_correct': sum(
            1 for label, finding in severity_pairs
            if label['severity'] == finding.get('severity')),
        'severity_total': len(severity_pairs),
    }


def _label_summary(label):
    item = {
        'types': label['types'],
        'category': label.get('category'),
    }
    if 'line' in label:
        item['line'] = label['line']
    if 'source' in label:
        item['source'] = label['source']
    return item


def _safe_snippet(finding):
    snippet = str(finding.get('snippet') or finding.get('context') or '')
    secret = str(finding.get('value') or '')
    if secret and secret in snippet:
        snippet = snippet.replace(secret, sp.mask_secret(secret))
    return snippet[:160]


def _finding_summary(finding):
    return {
        'type': finding.get('type'),
        'category': finding.get('category'),
        'severity': finding.get('severity'),
        'status': finding.get('status'),
        'line': finding.get('line'),
        'source': finding.get('source'),
        'snippet': _safe_snippet(finding),
    }


def _case_result(case, scan):
    match = _match_case(case['labels'], scan['findings'])
    tp = len(match['pairs'])
    fp = len(match['false_positives'])
    fn = len(match['misses'])
    precision = _metric(tp, tp + fp)
    recall = _metric(tp, tp + fn)
    severity_mismatches = [
        {
            'types': label['types'],
            'expected': label['severity'],
            'actual': finding.get('severity'),
            'line': finding.get('line'),
        }
        for label, finding in match['pairs']
        if 'severity' in label and label['severity'] != finding.get('severity')
    ]
    return {
        'id': case['id'],
        'kind': case['kind'],
        'path': case['path'],
        'expected': len(case['labels']),
        'detected': len(scan['findings']),
        'tp': tp,
        'fp': fp,
        'fn': fn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(_f1(precision, recall), 4),
        'line_correct': match['line_correct'],
        'line_total': match['line_total'],
        'line_accuracy': round(
            _metric(match['line_correct'], match['line_total']), 4),
        'category_correct': match['category_correct'],
        'category_accuracy': round(_metric(match['category_correct'], tp), 4),
        'severity_correct': match['severity_correct'],
        'severity_total': match['severity_total'],
        'severity_accuracy': round(
            _metric(match['severity_correct'], match['severity_total']), 4),
        'severity_mismatches': severity_mismatches,
        'raw_candidates': scan['raw_count'],
        'filtered_candidates': scan['filtered_count'],
        'filter_reasons': scan['filter_reasons'],
        'duration_ms': scan['duration_ms'],
        'matched_labels': [_label_summary(label) for label, _ in match['pairs']],
        'misses': [_label_summary(label) for label in match['misses']],
        'false_positives': [
            _finding_summary(finding) for finding in match['false_positives']],
    }


def _aggregate(case_results):
    tp = sum(case['tp'] for case in case_results)
    fp = sum(case['fp'] for case in case_results)
    fn = sum(case['fn'] for case in case_results)
    line_correct = sum(case['line_correct'] for case in case_results)
    line_total = sum(case['line_total'] for case in case_results)
    category_correct = sum(case['category_correct'] for case in case_results)
    severity_correct = sum(case['severity_correct'] for case in case_results)
    severity_total = sum(case['severity_total'] for case in case_results)
    clean_cases = [case for case in case_results if case['expected'] == 0]
    clean_noise = sum(1 for case in clean_cases if case['fp'] > 0)
    precision = _metric(tp, tp + fp)
    recall = _metric(tp, tp + fn)
    return {
        'cases': len(case_results),
        'expected': tp + fn,
        'detected': tp + fp,
        'tp': tp,
        'fp': fp,
        'fn': fn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(_f1(precision, recall), 4),
        'line_accuracy': round(_metric(line_correct, line_total), 4),
        'line_correct': line_correct,
        'line_total': line_total,
        'category_accuracy': round(_metric(category_correct, tp), 4),
        'category_correct': category_correct,
        'severity_accuracy': round(_metric(severity_correct, severity_total), 4),
        'severity_correct': severity_correct,
        'severity_total': severity_total,
        'clean_cases': len(clean_cases),
        'clean_noise_cases': clean_noise,
        'raw_candidates': sum(case['raw_candidates'] for case in case_results),
        'filtered_candidates': sum(case['filtered_candidates'] for case in case_results),
        'duration_ms': round(sum(case['duration_ms'] for case in case_results), 2),
    }


def _build_type_rows(case_results):
    expected = {}
    matched = {}
    missed = {}
    fp_by_type = {}
    for case in case_results:
        for label in case['matched_labels']:
            primary = label['types'][0]
            expected[primary] = expected.get(primary, 0) + 1
            matched[primary] = matched.get(primary, 0) + 1
        for label in case['misses']:
            primary = label['types'][0]
            expected[primary] = expected.get(primary, 0) + 1
            missed[primary] = missed.get(primary, 0) + 1
        for fp in case['false_positives']:
            actual = fp['type']
            fp_by_type[actual] = fp_by_type.get(actual, 0) + 1

    names = sorted(set(expected) | set(matched) | set(missed) | set(fp_by_type))
    rows = []
    for name in names:
        exp = expected.get(name, 0)
        hit = matched.get(name, 0)
        fp = fp_by_type.get(name, 0)
        rows.append({
            'type': name,
            'expected': exp,
            'matched': hit,
            'missed': missed.get(name, 0),
            'false_positives': fp,
            'recall': round(_metric(hit, exp), 4),
            'precision': round(_metric(hit, hit + fp), 4),
        })
    return rows


def _threshold_failures(summary, args):
    failures = []
    checks = (
        ('precision', args.min_precision),
        ('recall', args.min_recall),
        ('line_accuracy', args.min_line_accuracy),
        ('category_accuracy', args.min_category_accuracy),
        ('severity_accuracy', args.min_severity_accuracy),
    )
    for metric, minimum in checks:
        if summary[metric] < minimum:
            failures.append(
                f'{metric} {summary[metric]:.4f} < required {minimum:.4f}')
    if summary['clean_noise_cases'] > args.max_clean_noise:
        failures.append(
            f"clean noise cases {summary['clean_noise_cases']} > "
            f"allowed {args.max_clean_noise}")
    return failures


def _validate_args(args):
    for flag, value in (
            ('--min-precision', args.min_precision),
            ('--min-recall', args.min_recall),
            ('--min-line-accuracy', args.min_line_accuracy),
            ('--min-category-accuracy', args.min_category_accuracy),
            ('--min-severity-accuracy', args.min_severity_accuracy),
            ('--max-regression', args.max_regression)):
        if not 0 <= value <= 1:
            raise BenchmarkError(f'{flag} must be between 0 and 1')
    if args.max_clean_noise < 0:
        raise BenchmarkError('--max-clean-noise must be zero or greater')


def _compare_baseline(summary, baseline, max_regression):
    if not isinstance(baseline, dict) or not isinstance(baseline.get('summary'), dict):
        raise BenchmarkError('Baseline must be a benchmark JSON file with a summary')
    previous = baseline['summary']
    regressions = []
    for metric in ('precision', 'recall', 'f1', 'line_accuracy',
                   'category_accuracy', 'severity_accuracy'):
        if metric not in previous:
            continue
        if not isinstance(previous[metric], (int, float)):
            raise BenchmarkError(f'Baseline metric {metric} is not numeric')
        delta = round(summary[metric] - previous[metric], 4)
        if delta < -max_regression:
            regressions.append(
                f"{metric} regressed {previous[metric]:.4f} -> "
                f"{summary[metric]:.4f} ({delta:+.4f})")
    for metric, label in (
            ('tp', 'true positives'), ('fp', 'false positives'),
            ('fn', 'false negatives')):
        if metric not in previous:
            continue
        if not isinstance(previous[metric], int) or isinstance(previous[metric], bool):
            raise BenchmarkError(f'Baseline count {metric} is not an integer')
        delta = summary[metric] - previous[metric]
        bad = delta < 0 if metric == 'tp' else delta > 0
        if bad and abs(delta) > 0:
            regressions.append(
                f'{label} {previous[metric]} -> {summary[metric]} ({delta:+d})')
    return regressions


def _print_report(payload, args):
    summary = payload['summary']
    print('SecretPulse Detection Benchmark')
    print('=' * 72)
    print(f"Corpus:   {payload['benchmark']['name']} "
          f"({summary['cases']} cases, {summary['expected']} labeled findings)")
    print(f"Scanner:  v{payload['benchmark']['scanner_version']}")
    print(f"Runtime:  {summary['duration_ms']:.1f} ms")
    print()
    rows = (
        ('Precision', 'precision', args.min_precision),
        ('Recall', 'recall', args.min_recall),
        ('F1', 'f1', None),
        ('Line accuracy', 'line_accuracy', args.min_line_accuracy),
        ('Category accuracy', 'category_accuracy', args.min_category_accuracy),
        ('Severity accuracy', 'severity_accuracy', args.min_severity_accuracy),
    )
    for label, key, minimum in rows:
        suffix = '' if minimum is None else f'  (min {minimum:.2f})'
        print(f"  {label:<20} {summary[key]:.4f}{suffix}")
    print(f"  {'TP / FP / FN':<20} {summary['tp']} / {summary['fp']} / {summary['fn']}")
    print(f"  {'Clean noise':<20} {summary['clean_noise_cases']} of "
          f"{summary['clean_cases']} clean cases")
    print(f"  {'Filtered candidates':<20} {summary['filtered_candidates']} "
          f"of {summary['raw_candidates']} raw")
    print()

    type_rows = payload['by_type']
    if type_rows:
        print('By type')
        print(f"  {'Type':<34} {'Expected':>8} {'Matched':>8} {'FP':>4} "
              f"{'Recall':>8} {'Precision':>10}")
        for row in type_rows:
            print(f"  {row['type'][:34]:<34} {row['expected']:>8} "
                  f"{row['matched']:>8} {row['false_positives']:>4} "
                  f"{row['recall']:>8.3f} {row['precision']:>10.3f}")
        print()

    failures = []
    for case in payload['cases']:
        if case['misses'] or case['false_positives']:
            failures.append(case)
    if failures:
        print('Case failures')
        for case in failures:
            print(f"  [{case['id']}] TP={case['tp']} FP={case['fp']} FN={case['fn']}")
            for miss in case['misses']:
                print(f"    MISS  {', '.join(miss['types'])}"
                      f"{' line ' + str(miss['line']) if 'line' in miss else ''}"
                      f"{' in ' + miss['source'] if 'source' in miss else ''}")
            for fp in case['false_positives']:
                print(f"    FP    {fp['type']} [{fp['severity']}] "
                      f"line {fp['line']}: {fp['snippet'][:100]}")
        print()

    severity_issues = [
        case for case in payload['cases'] if case.get('severity_mismatches')]
    if severity_issues:
        print('Severity mismatches')
        for case in severity_issues:
            for mismatch in case['severity_mismatches']:
                print(f"  [{case['id']}] {', '.join(mismatch['types'])} "
                      f"line {mismatch['line']}: expected {mismatch['expected']}, "
                      f"got {mismatch['actual']}")
        print()

    if args.verbose:
        print('Cases')
        for case in payload['cases']:
            print(f"  {case['id']:<32} TP={case['tp']:<3} FP={case['fp']:<3} "
                  f"FN={case['fn']:<3} P={case['precision']:.3f} "
                  f"R={case['recall']:.3f} {case['duration_ms']:.1f} ms")
        print()

    if payload.get('baseline'):
        baseline = payload['baseline']
        print(f"Baseline: {baseline['path']}")
        if baseline['regressions']:
            for regression in baseline['regressions']:
                print(f"  REGRESSION  {regression}")
        else:
            print('  No regressions detected.')
        print()

    if payload['failures']:
        print('FAILED')
        for failure in payload['failures']:
            print(f"  - {failure}")
    else:
        print('PASS')


def _markdown_report(payload):
    summary = payload['summary']
    lines = [
        f"# SecretPulse Detection Benchmark — {payload['benchmark']['name']}",
        '',
        f"Scanner: `v{payload['benchmark']['scanner_version']}` · "
        f"Cases: {summary['cases']} · Runtime: {summary['duration_ms']:.1f} ms",
        '',
        '| Metric | Value |',
        '|--------|-------|',
        f"| Precision | {summary['precision']:.4f} |",
        f"| Recall | {summary['recall']:.4f} |",
        f"| F1 | {summary['f1']:.4f} |",
        f"| Line accuracy | {summary['line_accuracy']:.4f} |",
        f"| Category accuracy | {summary['category_accuracy']:.4f} |",
        f"| Severity accuracy | {summary['severity_accuracy']:.4f} |",
        f"| TP / FP / FN | {summary['tp']} / {summary['fp']} / {summary['fn']} |",
        f"| Clean noise | {summary['clean_noise_cases']} / {summary['clean_cases']} |",
        '',
        '## Per type',
        '',
        '| Type | Expected | Matched | Missed | FP | Recall | Precision |',
        '|------|----------|---------|--------|----|--------|-----------|',
    ]
    for row in payload['by_type']:
        lines.append(
            f"| {row['type']} | {row['expected']} | {row['matched']} | "
            f"{row['missed']} | {row['false_positives']} | "
            f"{row['recall']:.3f} | {row['precision']:.3f} |")
    lines.extend(['', '## Cases', '',
                  '| Case | TP | FP | FN | Precision | Recall |',
                  '|------|----|----|----|-----------|--------|'])
    for case in payload['cases']:
        lines.append(
            f"| {case['id']} | {case['tp']} | {case['fp']} | {case['fn']} | "
            f"{case['precision']:.3f} | {case['recall']:.3f} |")
    lines.append('')
    lines.append(f"Result: **{'PASS' if payload['passed'] else 'FAIL'}**")
    return '\n'.join(lines) + '\n'


def run_benchmark(corpus_root, args, baseline=None):
    _validate_args(args)
    corpus_root = Path(corpus_root).expanduser().resolve()
    manifest = _load_manifest(corpus_root)
    case_results = []
    with tempfile.TemporaryDirectory(prefix='secretpulse-bench-') as temp_dir:
        calibration_dir = Path(temp_dir)
        for manifest_case in manifest['cases']:
            try:
                scan = _scan_case(manifest_case, corpus_root, calibration_dir)
            except (OSError, UnicodeDecodeError) as exc:
                raise BenchmarkError(f"{manifest_case['id']}: {exc}") from exc
            result = _case_result(manifest_case, scan)
            case_results.append(result)

    summary = _aggregate(case_results)
    type_rows = _build_type_rows(case_results)
    failures = _threshold_failures(summary, args)
    baseline_info = None
    if baseline:
        regressions = _compare_baseline(summary, baseline, args.max_regression)
        baseline_info = {
            'path': str(args.baseline),
            'regressions': regressions,
        }
        failures.extend(regressions)
    payload = {
        'benchmark': {
            'name': manifest.get('name', corpus_root.name),
            'corpus': str(corpus_root),
            'schema_version': manifest['schema'],
            'scanner_version': sp.__version__,
        },
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'summary': summary,
        'thresholds': {
            'min_precision': args.min_precision,
            'min_recall': args.min_recall,
            'min_line_accuracy': args.min_line_accuracy,
            'min_category_accuracy': args.min_category_accuracy,
            'min_severity_accuracy': args.min_severity_accuracy,
            'max_clean_noise': args.max_clean_noise,
            'max_regression': args.max_regression,
        },
        'by_type': type_rows,
        'cases': case_results,
        'baseline': baseline_info,
        'failures': failures,
        'passed': not failures,
    }
    return payload


def _parse_args(argv):
    parser = argparse.ArgumentParser(
        description='Measure SecretPulse precision, recall, and evidence quality '
                    'against a labeled corpus.')
    parser.add_argument(
        '--corpus', default=str(ROOT / 'benchmarks' / 'corpus'),
        help='Corpus directory containing manifest.json')
    parser.add_argument('--json', help='Write full results as JSON')
    parser.add_argument('--markdown', help='Write a Markdown report')
    parser.add_argument('--baseline', help='Previous benchmark JSON to compare')
    parser.add_argument('--min-precision', type=float, default=0.95)
    parser.add_argument('--min-recall', type=float, default=0.95)
    parser.add_argument('--min-line-accuracy', type=float, default=0.90)
    parser.add_argument('--min-category-accuracy', type=float, default=0.95)
    parser.add_argument('--min-severity-accuracy', type=float, default=0.90)
    parser.add_argument('--max-clean-noise', type=int, default=0,
                        help='Allowed clean cases with any false positive')
    parser.add_argument('--max-regression', type=float, default=0.0,
                        help='Allowed metric drop versus --baseline')
    parser.add_argument('-v', '--verbose', action='store_true')
    return parser.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv)
    baseline = None
    try:
        if args.baseline:
            try:
                baseline = json.loads(Path(args.baseline).read_text())
            except (OSError, json.JSONDecodeError) as exc:
                raise BenchmarkError(f'Cannot read baseline: {exc}') from exc
        payload = run_benchmark(args.corpus, args, baseline=baseline)
    except BenchmarkError as exc:
        print(f'Benchmark error: {exc}', file=sys.stderr)
        return 2

    _print_report(payload, args)
    try:
        if args.json:
            Path(args.json).write_text(json.dumps(payload, indent=2) + '\n')
            print(f"\nJSON: {args.json}")
        if args.markdown:
            Path(args.markdown).write_text(_markdown_report(payload))
            print(f"Markdown: {args.markdown}")
    except OSError as exc:
        print(f'Artifact write failed: {exc}', file=sys.stderr)
        return 2
    return 0 if payload['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
