import contextlib
import hashlib
import importlib.util
import io
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('secretpulse', ROOT / 'SecretPulse.py')
sp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sp)


def material(label, length, alphabet=None):
    chunk = ''
    i = 0
    while len(chunk) < length:
        chunk += hashlib.sha256(f'{label}:{i}'.encode()).hexdigest()
        i += 1
    chunk = chunk[:length]
    if alphabet:
        chunk = ''.join(alphabet[int(c, 16) % len(alphabet)] for c in chunk)
    return chunk


def uuid(label):
    digest = hashlib.sha256(label.encode()).hexdigest()
    return f'{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}'


ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
LOWER = 'abcdefghijklmnopqrstuvwxyz0123456789'
AGE = 'QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L'


def provider_fixture():
    return {
        'OpenRouter API Key': f'sk-or-v1-{material("or", 64)}',
        'Groq API Key': f'gsk_{material("groq", 48, ALNUM)}',
        'xAI API Key': f'xai-{material("xai", 80, ALNUM)}',
        'Perplexity API Key': f'pplx-{material("pplx", 48, ALNUM)}',
        'Mistral API Key': f'MISTRAL_API_KEY={material("mistral", 32, ALNUM)}',
        'DeepSeek API Key': f'DEEPSEEK_API_KEY=sk-{material("deepseek", 32)}',
        'Together API Key': f'TOGETHER_API_KEY={material("together", 64)}',
        'Supabase Secret Key': f'sb_secret_{material("supabase", 40, ALNUM)}',
        'Resend API Key': f'RESEND_API_KEY=re_{material("resend", 40, ALNUM)}',
        'Postman API Key': f'PMAK-{material("pm1", 24)}-{material("pm2", 34)}',
        'Pulumi Access Token': f'pul-{material("pulumi", 40)}',
        'Sentry User Token': f'sntryu_{material("sentry", 64)}',
        'Sentry Org Token': (
            'sntrys_eyJpYXQiO' + 'A' * 20 + 'LCJyZWdpb25fdXJs' + 'B' * 20
            + '_' + 'C' * 43
        ),
        'Datadog API Key': f'DD_API_KEY={material("datadog", 32)}',
        'Databricks API Token': f'dapi{material("databricks", 32)}-1',
        'Doppler API Token': f'dp.pt.{material("doppler", 43, LOWER)}',
        'Fly.io Access Token': f'fo1_{material("fly", 43, ALNUM)}',
        'Slack App Token': (
            f'xapp-1-A{int(material("slack", 9), 16)}-'
            f'{int(material("slack2", 6), 16)}-{material("slack3", 16, LOWER)}'
        ),
        'Telegram Bot Token': (
            f'TELEGRAM_BOT_TOKEN={int(material("tg", 8), 16) % 90000000 + 10000000}:'
            f'{material("tg2", 34, ALNUM)}'
        ),
        'Discord Webhook': (
            f'https://discord.com/api/webhooks/9{material("dc", 17, "0123456789")}'
            f'/{material("dc2", 68, ALNUM)}'
        ),
        'Microsoft Teams Webhook': (
            f'https://acme.webhook.office.com/webhookb2/{uuid("t1")}@{uuid("t2")}'
            f'/IncomingWebhook/{material("t3", 32)}/{uuid("t4")}'
        ),
        'Atlassian API Token': f'ATATT3{material("atlassian", 186, ALNUM)}',
        'Mailchimp API Key': f'{material("mailchimp", 32)}-us12',
        '1Password Service Account Token': f'ops_eyJ{material("op", 260, ALNUM)}',
        'Age Secret Key': (
            'AGE-SECRET-KEY-1'
            + ''.join(AGE[int(c, 16) % 32] for c in material('age', 58))
        ),
        'AWS Bedrock API Key': f'ABSK{material("bedrock", 120, ALNUM)}',
        'AWS Secret Access Key': f'AWS_SECRET_ACCESS_KEY={material("aws", 40, ALNUM)}',
        'Google OAuth Client Secret': f'GOCSPX-{material("google", 28, ALNUM)}',
        'Azure AD Client Secret': (
            f'AZURE_CLIENT_SECRET={material("az1", 3, ALNUM)}'
            f'{int(material("az2", 1), 16) % 10}Q~{material("az3", 34, ALNUM)}'
        ),
        'Azure Storage Account Key': (
            'DefaultEndpointsProtocol=https;AccountName=acme;AccountKey='
            f'{material("azure", 80, ALNUM)}=;EndpointSuffix=core.windows.net'
        ),
    }


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.scanner = sp.SecretScanner(show_progress=False)

    def test_all_2026_provider_types_detect(self):
        fixture = provider_fixture()
        with contextlib.redirect_stdout(io.StringIO()):
            self.scanner.scan_content('\n'.join(fixture.values()), 'file:///tmp/2026.env')
        found = {finding['type'] for finding in self.scanner.found_secrets}
        self.assertEqual(found, set(fixture))

    def test_placeholders_do_not_match(self):
        text = '\n'.join([
            'OPENROUTER_API_KEY=your_key_here',
            'MISTRAL_API_KEY=changeme',
            'XAI_API_KEY=REPLACE_ME',
            'SENTRY_TOKEN=sntryu_short',
            'AWS_SECRET_ACCESS_KEY=placeholder',
        ])
        with contextlib.redirect_stdout(io.StringIO()):
            self.scanner.scan_content(text, 'file:///tmp/placeholders.env')
        self.assertEqual(self.scanner.found_secrets, [])

    def test_new_patterns_are_not_duplicated(self):
        names = list(self.scanner.patterns)
        self.assertEqual(len(names), len(set(names)))
        for name, config in self.scanner.patterns.items():
            compiled = [re.compile(p) for p in config['patterns']]
            self.assertEqual(len(compiled), len(config['patterns']), name)


class FakeResponse:
    headers = {'content-type': 'application/json'}

    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if 'openrouter.ai/api/v1/key' in url:
            return FakeResponse({'data': {'label': 'test', 'usage': 0}})
        if 'api.telegram.org' in url:
            return FakeResponse({'ok': True, 'result': {'username': 'testbot'}})
        if 'discord.com/api/webhooks' in url:
            return FakeResponse({'name': 'test-hook'})
        if 'api.mailchimp.com' in url:
            return FakeResponse({})
        if 'api.resend.com' in url:
            return FakeResponse({'data': [{'id': 'one'}]})
        return FakeResponse({'data': [{'id': 'model'}]})


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.session = FakeSession()
        self.verifier = sp.ActiveVerifierV2(self.session)

    def test_new_verifiers_use_read_only_get(self):
        checks = [
            ('OpenRouter API Key', 'sk-or-v1-' + material('or', 64)),
            ('Groq API Key', 'gsk_' + material('groq', 48, ALNUM)),
            ('xAI API Key', 'xai-' + material('xai', 80, ALNUM)),
            ('Mistral API Key', material('mistral', 32, ALNUM)),
            ('DeepSeek API Key', 'sk-' + material('deepseek', 32)),
            ('Together API Key', material('together', 64)),
            ('Resend API Key', 're_' + material('resend', 40, ALNUM)),
            ('Postman API Key', 'PMAK-' + material('pm1', 24) + '-' + material('pm2', 34)),
            ('Pulumi Access Token', 'pul-' + material('pulumi', 40)),
            ('Sentry User Token', 'sntryu_' + material('sentry', 64)),
            ('Datadog API Key', material('datadog', 32)),
            ('Telegram Bot Token', '123456789:' + material('tg2', 34, ALNUM)),
            ('Discord Webhook', 'https://discord.com/api/webhooks/123456789012345678/'
             + material('dc2', 68, ALNUM)),
            ('Mailchimp API Key', material('mailchimp', 32) + '-us12'),
        ]
        for secret_type, value in checks:
            with self.subTest(secret_type=secret_type):
                result = self.verifier.verify(secret_type, value)
                self.assertIsNotNone(result, secret_type)
                self.assertTrue(result.get('live'), secret_type)
        self.assertEqual(len(self.session.calls), len(checks))
        self.assertTrue(all('timeout' in kwargs for _, kwargs in self.session.calls))

    def test_provider_auth_headers(self):
        postman_key = 'PMAK-' + material('pm1', 24) + '-' + material('pm2', 34)
        self.verifier.verify('Postman API Key', postman_key)
        self.assertEqual(self.session.calls[-1][1]['headers']['X-Api-Key'], postman_key)

        pulumi_key = 'pul-' + material('pulumi', 40)
        self.verifier.verify('Pulumi Access Token', pulumi_key)
        self.assertEqual(
            self.session.calls[-1][1]['headers']['Authorization'],
            f'token {pulumi_key}',
        )


if __name__ == '__main__':
    unittest.main()
