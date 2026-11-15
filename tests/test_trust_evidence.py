import contextlib
import importlib.util
import io
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('secretpulse', ROOT / 'SecretPulse.py')
sp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sp)


class RecordingVerifier:
    def __init__(self, live=False):
        self.calls = []
        self.live = live

    def verify(self, secret_type, value):
        self.calls.append((secret_type, value))
        return {'live': self.live, 'detail': 'checked'}


class PublicIdentifierTests(unittest.TestCase):
    def setUp(self):
        self.scanner = sp.SecretScanner(show_progress=False)

    def test_stripe_publishable_is_a_low_lead_with_evidence(self):
        content = (
            'const pk = "pk_live_' + 'A' * 30 + '";\n'
            'const sk = "sk_live_' + 'B' * 30 + '";\n'
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.scanner.scan_content(content, 'file:///tmp/app.js')

        by_type = {f['type']: f for f in self.scanner.found_secrets}
        public = by_type['Stripe Publishable Key']
        secret = by_type['Stripe API Key']
        self.assertTrue(public['public_identifier'])
        self.assertEqual(public['severity'], 'LOW')
        self.assertEqual(public['line'], 1)
        self.assertIn('pk_live_', public['snippet'])
        self.assertNotIn('public_identifier', secret)
        self.assertEqual(secret['severity'], 'CRITICAL')
        self.assertEqual(secret['line'], 2)

        unified = {f['type']: f for f in self.scanner.collect_findings()}
        self.assertEqual(unified['Stripe Publishable Key']['status'], 'lead')
        self.assertEqual(unified['Stripe Publishable Key']['category'], 'public_identifier')
        self.assertEqual(unified['Stripe Publishable Key']['severity'], 'LOW')
        self.assertEqual(unified['Stripe API Key']['status'], 'potential')
        self.assertIn('sed -n', unified['Stripe API Key']['repro'])
        self.assertIn('sed -n', unified['Stripe Publishable Key']['repro'])

    def test_public_identifiers_skip_verification(self):
        verifier = RecordingVerifier(live=True)
        self.scanner.verifier = verifier
        content = (
            'const pk = "pk_live_' + 'C' * 30 + '";\n'
            'const sk = "sk_live_' + 'D' * 30 + '";\n'
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.scanner.scan_content(content, 'file:///tmp/app.js')
        self.assertEqual([c[0] for c in verifier.calls], ['Stripe API Key'])
        public = next(f for f in self.scanner.found_secrets
                      if f['type'] == 'Stripe Publishable Key')
        self.assertEqual(public['severity'], 'LOW')
        self.assertNotIn('verified_live', public)

    def test_public_leads_do_not_fail_a_ci_gate(self):
        self.scanner.found_secrets = [{
            'type': 'Mapbox Token', 'value': 'pk.' + 'E' * 80,
            'source': 'https://app.example/app.js', 'severity': 'LOW',
            'confidence': 'HIGH', 'entropy': 4.0, 'line': 4,
            'snippet': 'mapboxgl.accessToken = "pk..."',
            'public_identifier': True, 'public_identifier_reason': 'public',
        }]
        findings = self.scanner.collect_findings()
        self.assertEqual(findings[0]['status'], 'lead')
        self.assertEqual(findings[0]['severity'], 'LOW')
        self.assertEqual(self.scanner.compute_exit_code('low', findings), 0)

    def test_export_json_has_one_unified_schema(self):
        self.scanner.found_secrets = [
            {
                'type': 'GitHub Token', 'value': 'ghp_' + 'F' * 36,
                'source': 'file:///tmp/a.js', 'severity': 'CRITICAL',
                'confidence': 'HIGH', 'entropy': 4.2, 'line': 8,
                'snippet': 'token = "ghp_..."', 'verified_live': False,
            },
            {
                'type': 'Sentry DSN',
                'value': 'https://' + 'a' * 32 + '@example.ingest.sentry.io/1',
                'source': 'file:///tmp/a.js', 'severity': 'LOW',
                'confidence': 'HIGH', 'entropy': 4.1, 'line': 9,
                'snippet': 'dsn: "https://..."',
                'public_identifier': True,
                'public_identifier_reason': 'Public ingestion endpoint',
            },
        ]
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as fh:
            path = fh.name
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                self.scanner.export_json(path)
            with open(path) as fh:
                data = json.load(fh)
            self.assertEqual(len(data['findings']), 2)
            self.assertEqual(data['findings'], data['unified_findings'])
            self.assertEqual(data['public_identifiers_total'], 1)
            self.assertEqual(data['secrets_total'], 1)
            self.assertTrue(all('category' in f for f in data['findings']))
            self.assertEqual(len(data['secret_candidates']), 2)
            public = next(f for f in data['findings']
                          if f['category'] == 'public_identifier')
            self.assertEqual(public['line'], 9)
            self.assertIn('https://', public['snippet'])
        finally:
            Path(path).unlink()

    def test_sarif_exports_line_and_snippet(self):
        value = 'ghp_' + 'G' * 36
        finding = self.scanner._mk_finding(
            'secret', 'GitHub Token', 'CRITICAL', 'HIGH', 'potential',
            'file:///tmp/app.js', value,
            evidence={'line': 7, 'snippet': f'const token = "{value}"'},
        )
        with tempfile.NamedTemporaryFile('w', suffix='.sarif', delete=False) as fh:
            path = fh.name
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                sp.export_sarif([finding], self.scanner.stats, path)
            with open(path) as fh:
                sarif = json.load(fh)
            location = sarif['runs'][0]['results'][0]['locations'][0]['physicalLocation']
            self.assertEqual(location['region']['startLine'], 7)
            snippet = location['region']['snippet']['text']
            self.assertIn('ghp_', snippet)
            self.assertNotIn(value, snippet)
        finally:
            Path(path).unlink()


class SeverityTests(unittest.TestCase):
    def test_exact_provider_format_keeps_declared_severity(self):
        value = 'sk_live_' + '1ed3e028f07deabf430d4dd58f154142'
        source = 'file:///tmp/app.js'
        content = f'const stripeSecret = "{value}";\n'
        engine = sp.AccuracyEngine()
        engine.calibration_save = lambda: None
        engine.trust_decay_apply = lambda finding: 1.0
        findings = [{
            'type': 'Stripe API Key', 'value': value, 'source': source,
            'severity': 'CRITICAL', 'validated': False, 'confidence': 'HIGH',
            'entropy': sp.shannon_entropy(value), 'line': 1,
            'snippet': content.strip(),
        }]
        result = engine.process_findings(findings, {source: content})
        self.assertEqual(result[0]['severity'], 'CRITICAL')
        self.assertTrue(result[0]['severity_pinned'])
        self.assertEqual(result[0]['severity_pin_reason'], 'exact provider format')
        self.assertNotIn('severity_downgraded', result[0])

        scanner = sp.SecretScanner(show_progress=False)
        scanner.found_secrets = result
        unified = scanner.collect_findings()[0]
        self.assertEqual(unified['severity'], 'CRITICAL')
        self.assertTrue(unified['evidence']['severity_pinned'])
        self.assertEqual(unified['evidence']['severity_pin_reason'],
                         'exact provider format')


class VerifierSafetyTests(unittest.TestCase):
    def test_public_types_allowlist_and_webhook_gate(self):
        class Session:
            def __init__(self):
                self.calls = []

            def get(self, url, **kwargs):
                self.calls.append(('GET', url, kwargs))

                class R:
                    status_code = 200
                    text = '{}'
                    headers = {'content-type': 'application/json'}

                    def json(self):
                        return {'data': []}
                return R()

            def post(self, url, **kwargs):
                self.calls.append(('POST', url, kwargs))
                return R()

        session = Session()
        verifier = sp.ActiveVerifierV2(session, provider_allowlist=['github'])
        result = verifier.verify('Stripe Publishable Key', 'pk_live_' + 'H' * 30)
        self.assertIsNone(result['live'])
        self.assertEqual(session.calls, [])

        self.assertIsNone(verifier.verify('Stripe API Key', 'sk_live_' + 'I' * 30))
        self.assertEqual(session.calls, [])

        webhook_verifier = sp.ActiveVerifierV2(session)
        result = webhook_verifier.verify(
            'Slack Webhook',
            'https://hooks.slack.com/services/T00000000/B00000000/' + 'J' * 24,
        )
        self.assertIsNone(result['live'])
        self.assertEqual(session.calls, [])

        verifier.verify('GitHub Token', 'ghp_' + 'K' * 36)
        self.assertEqual(session.calls[0][0], 'GET')
        self.assertIn('api.github.com', session.calls[0][1])


class HttpSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(BaseHTTPRequestHandler):
            seen = []

            def do_GET(self):
                type(self).seen.append({
                    'path': self.path,
                    'x-test': self.headers.get('X-Test'),
                    'cookie': self.headers.get('Cookie'),
                })
                if self.path == '/redirect':
                    self.send_response(302)
                    self.send_header('Location', '/body')
                    self.end_headers()
                    return
                body = b'x' * (200 * 1024)
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.scanner = sp.SecretScanner(
            show_progress=False, max_retries=0,
            scope_domains=['127.0.0.1'],
            max_response_bytes=64 * 1024,
            request_timeout=3,
            custom_headers={'X-Test': 'yes'},
            cookies='session=abc123',
        )

    def test_caps_response_and_applies_auth_headers(self):
        with contextlib.redirect_stdout(io.StringIO()):
            resp = self.scanner._resilient_get(
                f'http://127.0.0.1:{self.port}/body')
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.content), 64 * 1024)
        self.assertTrue(resp._secretpulse_truncated)
        seen = self.server.RequestHandlerClass.seen[-1]
        self.assertEqual(seen['x-test'], 'yes')
        self.assertEqual(seen['cookie'], 'session=abc123')

    def test_follows_in_scope_redirect_and_blocks_out_of_scope(self):
        with contextlib.redirect_stdout(io.StringIO()):
            resp = self.scanner._resilient_get(
                f'http://127.0.0.1:{self.port}/redirect')
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status_code, 200)

        with contextlib.redirect_stdout(io.StringIO()):
            blocked = self.scanner._resilient_get(
                f'http://localhost:{self.port}/body')
        self.assertIsNone(blocked)
        self.assertEqual(self.scanner.stats['scope_blocked'], 1)

    def test_concurrent_fetches_use_isolated_sessions(self):
        results = []

        def fetch():
            with contextlib.redirect_stdout(io.StringIO()):
                responses = [
                    self.scanner._resilient_get(f'http://127.0.0.1:{self.port}/body')
                    for _ in range(3)
                ]
            results.extend(r is not None and r.status_code == 200 for r in responses)

        threads = [threading.Thread(target=fetch) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(results), 18)
        self.assertTrue(all(results))


class ConfigTests(unittest.TestCase):
    def test_json_and_toml_config_loading(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_path = Path(tmp) / 'scan.json'
            json_path.write_text(json.dumps({
                'http': {'headers': {'X-API-Key': 'abc'}, 'timeout': 9},
                'verify': {'providers': ['stripe'], 'allow_webhooks': True},
            }))
            cfg = sp.load_scan_config(str(json_path))
            self.assertEqual(cfg['http']['headers']['X-API-Key'], 'abc')
            self.assertEqual(cfg['http']['timeout'], 9)
            self.assertTrue(cfg['verify']['allow_webhooks'])

            toml_path = Path(tmp) / 'scan.toml'
            toml_path.write_text(
                '[http]\ntimeout = 11\nheaders = ["X-Test: yes"]\n'
                '[verify]\nproviders = ["github"]\n'
            )
            try:
                cfg = sp.load_scan_config(str(toml_path))
            except ValueError as exc:
                self.assertIn('TOML config requires', str(exc))
            else:
                self.assertEqual(cfg['http']['timeout'], 11)
                self.assertEqual(cfg['http']['headers'], ['X-Test: yes'])
                self.assertEqual(cfg['verify']['providers'], ['github'])

    def test_invalid_header_is_rejected(self):
        with self.assertRaises(ValueError):
            sp.parse_header_lines(['MissingColon'])


if __name__ == '__main__':
    unittest.main()
