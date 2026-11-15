"""Version metadata, detection constants, and probe tables."""
from ._imports import *

__version__ = '5.6.0'
__author__  = 'Vinod Kumar Bontha'
__lines__   = '12,000+'

UA_POOL = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 '
    '(KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) '
    'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
]

CDN_WAF_PATH_PATTERNS = [
    '/akam/', '/akamai/', '/_bm/', '/cdn-cgi/', '/cf-challenge',
    '/__cf_chl_', '/fingerprint/', '/captcha/', '/perimeterx/',
    '/px/', '/datadome/', '/kasada/', '/imperva/', '/_Incapsula_',
    '/distil/', '/bot-detect/',
]

# Client-side identifiers that are expected to be public. They remain useful
# inventory signal, but must never be promoted to a credential finding unless
# a provider-specific privilege check proves otherwise.
PUBLIC_IDENTIFIER_TYPES = {
    'Stripe Publishable Key': {
        'reason': 'Stripe publishable keys are designed for browser code; they cannot create charges alone.',
        'skip_verification': True,
    },
    'Google API Key': {
        'reason': 'Google API keys are client identifiers; risk depends on API restrictions, referrer rules, and quotas.',
        'skip_verification': False,
    },
    'Firebase Config': {
        'reason': 'Firebase web configuration is shipped to browsers; risk depends on security rules and key restrictions.',
        'skip_verification': False,
    },
    'Sentry DSN': {
        'reason': 'Sentry DSNs are public ingestion endpoints and cannot read project data.',
        'skip_verification': True,
    },
    'Datadog RUM Token': {
        'reason': 'Datadog RUM client tokens are browser-side identifiers with ingestion-only scope.',
        'skip_verification': True,
    },
    'Mapbox Token': {
        'reason': 'Mapbox public tokens (pk.*) are designed for client-side use; secret tokens use the sk.* prefix.',
        'skip_verification': True,
    },
    'Mixpanel Project Token': {
        'reason': 'Mixpanel project tokens are embedded in client code and only allow event ingestion.',
        'skip_verification': True,
    },
    'Amplitude API Key': {
        'reason': 'Amplitude project API keys are shipped to clients for event ingestion.',
        'skip_verification': True,
    },
    'LogRocket App ID': {
        'reason': 'LogRocket app IDs are public client configuration identifiers.',
        'skip_verification': True,
    },
    'Auth0 Client ID': {
        'reason': 'Auth0 client IDs are public OAuth application identifiers, not client secrets.',
        'skip_verification': True,
    },
    'Recaptcha Site Key': {
        'reason': 'reCAPTCHA site keys are intentionally embedded in web pages.',
        'skip_verification': True,
    },
    'FullStory Org ID': {
        'reason': 'FullStory organization IDs are public browser configuration values.',
        'skip_verification': True,
    },
    'Intercom App ID': {
        'reason': 'Intercom app IDs are public widget configuration values; access tokens are separate.',
        'skip_verification': True,
    },
    'HubSpot Portal ID': {
        'reason': 'HubSpot portal IDs are public tracking identifiers; API keys and tokens are separate.',
        'skip_verification': True,
    },
}

KNOWN_TEST_KEYS = {
    'AIzaSyA-example-key-that-is-not-real',
    'AIzaSyBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    'sk_live_EXAMPLE_KEY_DO_NOT_USE_1',
    'pk_live_EXAMPLE_KEY_DO_NOT_USE_2',
    'sk_test_EXAMPLE_KEY_DO_NOT_USE_3',
    'pk_test_EXAMPLE_KEY_DO_NOT_USE_4',
    'YOUR_WRITE_KEY',
    'SG.xxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    'AKIAIOSFODNN7EXAMPLE',
    'xoxb-not-a-real-token-this-will-not-work',
    'AC00000000000000000000000000000000',
    'SK00000000000000000000000000000000',
    'examplePublicKey',
    'EXAMPLE-HUB-SPOT-KEY',
}

ENV_FILE_PATHS = [
    '/.env', '/.env.local', '/.env.production', '/.env.staging',
    '/.env.development', '/.env.backup', '/.env.old', '/.env.save',
    '/.env.bak', '/.env.example', '/.env.dev', '/.env.prod',
    '/.env.test', '/env', '/env.json', '/config.json',
    '/config/env.js', '/.config', '/app-config.json',
]

GRAPHQL_PATHS = [
    '/graphql', '/api/graphql', '/graphql/console', '/gql',
    '/query', '/api/query', '/graphiql', '/playground',
    '/v1/graphql', '/api/v1/graphql',
]

# v5.5: high-signal sensitive paths. Every probe is validated against
# content, so SPA soft-404s returning 200 HTML do not become findings.
SENSITIVE_FILE_PROBES = [
    {
        'path': '/.git/config', 'type': 'Exposed Git Config', 'severity': 'HIGH',
        'markers': ('[core]', 'repositoryformatversion'), 'scan': True,
    },
    {
        'path': '/.git/HEAD', 'type': 'Exposed Git HEAD', 'severity': 'MEDIUM',
        'regex': r'(?m)^(ref:\s+refs/|[0-9a-f]{40}\s*$)',
    },
    {
        'path': '/.svn/entries', 'type': 'Exposed SVN Metadata', 'severity': 'MEDIUM',
        'markers': ('svn', 'dir'),
    },
    {
        'path': '/.hg/requires', 'type': 'Exposed Mercurial Metadata', 'severity': 'MEDIUM',
        'markers': ('revlogv1',),
    },
    {
        'path': '/.DS_Store', 'type': 'Exposed .DS_Store', 'severity': 'LOW',
        'binary_marker': b'Bud1',
    },
    {
        'path': '/.ssh/id_rsa', 'type': 'Exposed SSH Private Key', 'severity': 'CRITICAL',
        'markers': ('PRIVATE KEY',), 'scan': True,
    },
    {
        'path': '/id_rsa', 'type': 'Exposed SSH Private Key', 'severity': 'CRITICAL',
        'markers': ('PRIVATE KEY',), 'scan': True,
    },
    {
        'path': '/backup.zip', 'type': 'Exposed Backup Archive', 'severity': 'HIGH',
        'magic': b'PK', 'content_types': ('application/zip', 'application/x-zip-compressed',
                                         'application/octet-stream'),
    },
    {
        'path': '/backup.sql', 'type': 'Exposed SQL Backup', 'severity': 'HIGH',
        'markers': ('CREATE TABLE', 'INSERT INTO'), 'scan': True,
    },
    {
        'path': '/dump.sql', 'type': 'Exposed SQL Dump', 'severity': 'HIGH',
        'markers': ('CREATE TABLE', 'INSERT INTO'), 'scan': True,
    },
    {
        'path': '/config.php.bak', 'type': 'Exposed PHP Config Backup', 'severity': 'HIGH',
        'markers': ('<?php', 'password', 'DB_'), 'scan': True,
    },
    {
        'path': '/web.config', 'type': 'Exposed IIS Config', 'severity': 'MEDIUM',
        'markers': ('<configuration', 'connectionString'), 'scan': True,
    },
    {
        'path': '/appsettings.json', 'type': 'Exposed App Settings', 'severity': 'MEDIUM',
        'markers': ('ConnectionStrings', 'Logging'), 'scan': True,
    },
    {
        'path': '/actuator/env', 'type': 'Exposed Spring Actuator Env', 'severity': 'HIGH',
        'markers': ('propertySources', 'activeProfiles'), 'scan': True,
    },
    {
        'path': '/server-status', 'type': 'Exposed Apache Server Status', 'severity': 'MEDIUM',
        'markers': ('Apache Server Status',), 'allow_html': True,
    },
    {
        'path': '/phpinfo.php', 'type': 'Exposed PHP Info', 'severity': 'MEDIUM',
        'markers': ('PHP Version', 'phpinfo()'), 'allow_html': True,
    },
    {
        'path': '/terraform.tfstate', 'type': 'Exposed Terraform State', 'severity': 'CRITICAL',
        'markers': ('terraform_version', 'resources'), 'scan': True,
    },
    {
        'path': '/docker-compose.yml', 'type': 'Exposed Docker Compose', 'severity': 'MEDIUM',
        'markers': ('services:', 'version:'), 'scan': True,
    },
]


# ═══════════════════════════════════════════════════════════════════
#  Source Map Intelligence Analyzer — v2.9
