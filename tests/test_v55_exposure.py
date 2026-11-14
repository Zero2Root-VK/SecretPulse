import contextlib
import importlib.util
import io
import json
import os
import tempfile
import time
import unittest
from types import SimpleNamespace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('secretpulse', ROOT / 'SecretPulse.py')
sp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sp)


class FakeResponse:
    def __init__(self, payload=None, status=200, text='', content_type='application/json'):
        self._payload = payload if payload is not None else {}
        self.status_code = status
        self.text = text
        self.headers = {'Content-Type': content_type}

    def json(self):
        return self._payload

    def close(self):
        pass


class DohSession:
    def __init__(self, answer=None):
        self.answer = answer
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if 'dns.google' in url:
            if self.answer is None:
                return FakeResponse({'Status': 3})
            return FakeResponse({'Status': 0, 'Answer': [{'type': 5, 'data': self.answer}]})
        return FakeResponse(status=200, text='<html>welcome</html>', content_type='text/html')


class ExposureTests(unittest.TestCase):
    def setUp(self):
        self.scanner = sp.SecretScanner(show_progress=False)

    def test_finding_has_cwe_owasp_remediation_and_repro(self):
        finding = self.scanner._mk_finding(
            'cors', 'CORS Misconfiguration', 'HIGH', 'HIGH', 'confirmed',
            'https://app.example/api', 'reflected origin',
            evidence={'origin_sent': 'https://evil.example'},
        )
        self.assertEqual(finding['cwe'], 'CWE-942')
        self.assertIn('A05:2021', finding['owasp'])
        self.assertIn('Allowlist', finding['remediation'])
        self.assertIn("Origin: https://evil.example", finding['repro'])

    def test_collect_findings_includes_exposure_modules(self):
        self.scanner.env_files_found = [{
            'url': 'https://app.example/.env', 'lines': 3,
            'sample_keys': ['DB_HOST', 'DB_USER', 'DB_PASS'],
        }]
        self.scanner.sensitive_files_found = [{
            'url': 'https://app.example/.git/config', 'path': '/.git/config',
            'type': 'Exposed Git Config', 'severity': 'HIGH', 'status_code': 200,
        }]
        self.scanner.graphql_endpoints = [{'url': 'https://app.example/graphql', 'types_count': 9}]
        self.scanner.api_discovery.graphql_schemas = [{
            'url': 'https://app.example/graphql', 'types': 11,
            'mutations': ['deleteUser'], 'has_mutations': True,
        }]
        self.scanner.api_discovery.swagger_specs = [{
            'url': 'https://app.example/openapi.json', 'title': 'Internal API',
            'version': '1.0', 'endpoints': 42, 'paths_sample': ['/users'],
        }]
        self.scanner.subtko.findings = [{
            'domain': 'old.example.com', 'cname': 'old.github.io',
            'service': 'GitHub Pages', 'signature': "There isn't a GitHub Pages site here",
            'severity': 'CRITICAL', 'status': 'potential', 'confidence': 'HIGH',
            'status_code': 404,
        }]

        findings = {f['category']: f for f in self.scanner.collect_findings()}
        self.assertEqual(findings['env']['status'], 'confirmed')
        self.assertEqual(findings['env']['severity'], 'CRITICAL')
        self.assertEqual(findings['sensitive_file']['status'], 'confirmed')
        self.assertEqual(findings['graphql']['severity'], 'HIGH')
        self.assertIn('1 mutations', findings['graphql']['value'])
        self.assertEqual(findings['swagger']['severity'], 'MEDIUM')
        self.assertEqual(findings['takeover']['status'], 'potential')
        self.assertEqual(findings['takeover']['severity'], 'CRITICAL')
        self.assertIn('curl', findings['env']['repro'])
        self.assertIn('__schema', findings['graphql']['repro'])

    def test_sensitive_probe_requires_content_signature(self):
        responses = {
            'https://app.example/.git/config': (
                SimpleNamespace(status_code=200, headers={'Content-Type': 'text/plain'}),
                b'[core]\nrepositoryformatversion = 0\n',
            ),
            'https://app.example/.git/HEAD': (
                SimpleNamespace(status_code=200, headers={'Content-Type': 'text/plain'}),
                b'ref: refs/heads/main\n',
            ),
            'https://app.example/backup.zip': (
                SimpleNamespace(status_code=200, headers={'Content-Type': 'application/zip'}),
                b'PK\x03\x04' + b'A' * 64,
            ),
            'https://app.example/phpinfo.php': (
                SimpleNamespace(status_code=200, headers={'Content-Type': 'text/html'}),
                b'<html>PHP Version 8.2.1</html>',
            ),
            # SPA soft-404 must not be reported as appsettings.json
            'https://app.example/appsettings.json': (
                SimpleNamespace(status_code=200, headers={'Content-Type': 'text/html'}),
                b'<html>not found</html>',
            ),
        }
        self.scanner._sensitive_probe_get = lambda url, limit=16384: responses.get(url, (None, b''))
        self.scanner.scan_content = lambda *args, **kwargs: None
        with contextlib.redirect_stdout(io.StringIO()):
            self.scanner.probe_sensitive_files('https://app.example/')

        types = {f['type'] for f in self.scanner.sensitive_files_found}
        self.assertEqual(types, {
            'Exposed Git Config', 'Exposed Git HEAD',
            'Exposed Backup Archive', 'Exposed PHP Info',
        })
        self.assertEqual(self.scanner.stats['sensitive_files_found'], 4)

    def test_takeover_requires_cname_and_fingerprint(self):
        session = DohSession(answer='old.github.io.')
        checker = sp.SubdomainTakeoverChecker(session)
        with contextlib.redirect_stdout(io.StringIO()):
            checker.check_cname('old.example.com')
        self.assertEqual(len(checker.findings), 1)
        finding = checker.findings[0]
        self.assertEqual(finding['cname'], 'old.github.io')
        self.assertEqual(finding['status'], 'lead')
        self.assertEqual(finding['severity'], 'LOW')

        safe = sp.SubdomainTakeoverChecker(DohSession(answer='app.example.net.'))
        self.assertFalse(safe.check_cname('safe.example.com'))
        self.assertEqual(safe.findings, [])

        nxdomain = sp.SubdomainTakeoverChecker(DohSession(answer=None))
        self.assertFalse(nxdomain.check_cname('gone.example.com'))
        self.assertEqual(nxdomain.findings, [])

    def test_takeover_signature_promotes_to_potential(self):
        class SignatureSession(DohSession):
            def get(self, url, **kwargs):
                if 'dns.google' in url:
                    return FakeResponse({'Status': 0, 'Answer': [
                        {'type': 5, 'data': 'old.github.io.'}]})
                return FakeResponse(
                    status=404,
                    text="There isn't a GitHub Pages site here",
                    content_type='text/html',
                )

        checker = sp.SubdomainTakeoverChecker(SignatureSession())
        with contextlib.redirect_stdout(io.StringIO()):
            checker.check_cname('old.example.com')
        self.assertEqual(checker.findings[0]['status'], 'potential')
        self.assertEqual(checker.findings[0]['confidence'], 'HIGH')

    def test_waf_recovery_restores_paused_probes(self):
        self.scanner.probe_env = True
        self.scanner.probe_graphql = True
        self.scanner.probe_swagger = True
        self.scanner.probe_sensitive = True
        self.scanner.enable_subtko = True
        self.scanner._waf_original_workers = 5
        self.scanner.rate_limiter.rps = 0
        self.scanner._waf_hits_window = [time.time()] * 8
        with contextlib.redirect_stdout(io.StringIO()):
            self.scanner._adapt_to_waf()
        self.assertTrue(self.scanner._waf_stealth_mode)
        self.assertFalse(self.scanner.probe_env)
        self.assertFalse(self.scanner.probe_sensitive)

        self.scanner._waf_hits_window = []
        self.scanner._waf_stealth_activated_at = time.time() - 120
        with contextlib.redirect_stdout(io.StringIO()):
            self.scanner._adapt_to_waf()
        self.assertFalse(self.scanner._waf_stealth_mode)
        self.assertTrue(self.scanner.probe_env)
        self.assertTrue(self.scanner.probe_sensitive)
        self.assertTrue(self.scanner.enable_subtko)

    def test_sarif_includes_cwe_repro_and_fingerprint(self):
        finding = self.scanner._mk_finding(
            'env', 'Exposed .env File', 'CRITICAL', 'HIGH', 'confirmed',
            'https://app.example/.env', '3 vars', evidence={'lines': 3},
        )
        with tempfile.NamedTemporaryFile('w', suffix='.sarif', delete=False) as fh:
            path = fh.name
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                sp.export_sarif([finding], self.scanner.stats, path)
            with open(path) as fh:
                sarif = json.load(fh)
            rule = sarif['runs'][0]['tool']['driver']['rules'][0]
            result = sarif['runs'][0]['results'][0]
            self.assertEqual(rule['properties']['cwe'], 'CWE-538')
            self.assertIn('cwe.mitre.org', rule['helpUri'])
            self.assertIn('cwe.mitre.org', rule['properties']['helpUri'])
            self.assertIn('curl', result['properties']['repro'])
            self.assertEqual(result['partialFingerprints']['secretPulse/v1'], finding['id'])
        finally:
            os.unlink(path)

    def test_smart_plan_uses_real_probe_modules(self):
        with contextlib.redirect_stdout(io.StringIO()):
            plan = sp.SmartRouter.plan(
                [{'subdomain': 'api.example.com', 'risk_score': 70}], 'example.com'
            )
        modules = set(plan[0]['smart_modules'])
        self.assertIn('sensitive_files', modules)
        self.assertIn('takeover', modules)
        self.assertNotIn('verify', modules)

    def test_unknown_target_gets_exposure_discovery(self):
        classification = sp.SmartRouter.classify('www.example.com', 'example.com')
        modules = set(classification['modules'])
        self.assertEqual(classification['type'], 'web_app')
        self.assertTrue({
            'probe_env', 'cors_check', 'open_redirect',
            'probe_graphql', 'probe_swagger', 'sensitive_files', 'takeover',
        }.issubset(modules))


if __name__ == '__main__':
    unittest.main()
