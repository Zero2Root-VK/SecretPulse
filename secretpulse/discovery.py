"""API discovery, cloud, CI/CD, exposure, and recon support modules."""
from ._imports import *
from .constants import __version__
from .utils import Colors

class APIDiscoveryV2:
    """
    OpenAPI/Swagger harvesting, GraphQL schema attacks,
    gRPC/protobuf detection, REST path discovery.
    """

    SWAGGER_PATHS = [
        '/swagger.json', '/swagger/v1/swagger.json', '/swagger.yaml',
        '/api-docs', '/api-docs.json', '/api/swagger.json',
        '/v1/swagger.json', '/v2/swagger.json', '/v3/swagger.json',
        '/openapi.json', '/openapi.yaml', '/openapi/v3/api-docs',
        '/api/openapi.json', '/.well-known/openapi',
    ]

    GRAPHQL_MUTATION_PROBE = '{"query":"{ __schema { mutationType { name fields { name args { name type { name } } } } } }"}'
    GRAPHQL_FULL_SCHEMA = '{"query":"{ __schema { types { name kind fields { name type { name kind ofType { name } } } } } }"}'

    GRPC_INDICATORS = [
        r'\.proto(?:buf)?(?:\.js)?["\']',
        r'grpc[_\-]?(?:web|gateway)',
        r'application/grpc',
        r'google\.protobuf\.',
        r'\.pb\.(?:js|go|py)',
    ]

    def __init__(self, session, rate_limiter, verbose=False):
        self.session = session
        self.rate_limiter = rate_limiter
        self.verbose = verbose
        self.swagger_specs: List[Dict] = []
        self.graphql_schemas: List[Dict] = []
        self.grpc_endpoints: List[Dict] = []

    def probe_swagger(self, base_url, get_fn):
        """Probe for OpenAPI/Swagger spec files."""
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if self.verbose:
            print(f"{Colors.OKCYAN}  [*] Probing {len(self.SWAGGER_PATHS)} "
                  f"Swagger/OpenAPI paths...{Colors.ENDC}")
        for path in self.SWAGGER_PATHS:
            url = origin + path
            try:
                resp = get_fn(url, timeout=8)
                if resp and resp.status_code == 200:
                    ct = resp.headers.get('Content-Type', '')
                    if 'json' in ct or 'yaml' in ct or resp.text.strip().startswith('{'):
                        try:
                            spec = resp.json()
                            info = spec.get('info', {})
                            paths = spec.get('paths', {})
                            self.swagger_specs.append({
                                'url': url,
                                'title': info.get('title', 'N/A'),
                                'version': info.get('version', 'N/A'),
                                'endpoints': len(paths),
                                'paths_sample': list(paths.keys())[:20],
                            })
                            print(f"{Colors.FAIL}[CRITICAL]{Colors.ENDC} "
                                  f"[conf:HIGH] Swagger/OpenAPI: {url} "
                                  f"({len(paths)} endpoints)")
                        except (json.JSONDecodeError, ValueError):
                            pass
            except Exception:
                pass

    def probe_graphql_schema(self, base_url, get_fn):
        """Enhanced GraphQL: extract full schema + mutations."""
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        gql_paths = [
            '/graphql', '/api/graphql', '/graphql/console', '/gql',
            '/query', '/api/query', '/graphiql', '/playground',
            '/v1/graphql', '/api/v1/graphql',
        ]
        for path in gql_paths:
            url = origin + path
            try:
                self.rate_limiter.wait()
                headers = {'Content-Type': 'application/json'}
                resp = self.session.post(url, data=self.GRAPHQL_FULL_SCHEMA,
                                          headers=headers, timeout=8)
                if resp.status_code == 200:
                    data = resp.json()
                    schema = (data.get('data') or {}).get('__schema', {})
                    if schema:
                        types = schema.get('types', [])
                        user_types = [t for t in types
                                      if not t.get('name', '').startswith('__')]
                        mutations = []
                        # Try mutation probe
                        try:
                            resp2 = self.session.post(url, data=self.GRAPHQL_MUTATION_PROBE,
                                                       headers=headers, timeout=8)
                            if resp2.status_code == 200:
                                mdata = resp2.json()
                                mt = ((mdata.get('data') or {}).get('__schema') or {}).get('mutationType')
                                if mt:
                                    mutations = [f.get('name', '?') for f in mt.get('fields', [])]
                        except Exception:
                            pass
                        self.graphql_schemas.append({
                            'url': url, 'types': len(user_types),
                            'type_names': [t['name'] for t in user_types[:20]],
                            'mutations': mutations[:20],
                            'has_mutations': len(mutations) > 0,
                        })
                        if mutations:
                            print(f"{Colors.FAIL}[CRITICAL]{Colors.ENDC} "
                                  f"GraphQL mutations exposed: {url} "
                                  f"({len(mutations)} mutations)")
            except Exception:
                pass

    def scan_grpc(self, content: str, source: str):
        """Detect gRPC/protobuf indicators in content."""
        for pattern in self.GRPC_INDICATORS:
            for m in re.finditer(pattern, content, re.I):
                val = m.group(0)
                h = f"gRPC:{val}:{source}"
                if not any(e.get('indicator') == val and e.get('source') == source
                           for e in self.grpc_endpoints):
                    self.grpc_endpoints.append({
                        'indicator': val, 'source': source,
                    })

    def get_summary(self) -> Dict:
        return {
            'swagger_specs': self.swagger_specs,
            'graphql_schemas': self.graphql_schemas,
            'grpc_endpoints': self.grpc_endpoints,
        }


# ═══════════════════════════════════════════════════════════════════
#  WAF Bypass v4.0 — v3.0
# ═══════════════════════════════════════════════════════════════════

class WAFBypassV4:
    """
    Advanced WAF evasion: path normalization, encoding tricks,
    method override, header smuggling.
    """

    @staticmethod
    def generate_bypass_urls(url: str) -> List[str]:
        """Generate multiple bypass variants for a blocked URL."""
        parsed = urlparse(url)
        path = parsed.path
        base = f"{parsed.scheme}://{parsed.netloc}"
        variants = [url]  # Original

        # Path normalization tricks
        if path and path != '/':
            variants.extend([
                base + path + '/',              # Trailing slash
                base + path + '/.',             # Dot trailing
                base + path + '%20',            # Space suffix
                base + path + '%09',            # Tab suffix
                base + path + '?',              # Empty query
                base + path + '#',              # Fragment
                base + '//' + path.lstrip('/'), # Double slash prefix
                base + path.replace('/', '/./'),  # Dot segments
            ])

            # Double URL encoding
            encoded_path = quote(path, safe='')
            variants.append(base + encoded_path)

            # Case variation (for case-insensitive servers)
            if any(c.isalpha() for c in path):
                swapped = ''.join(c.swapcase() if c.isalpha() else c for c in path)
                variants.append(base + swapped)

        return variants[:10]  # Cap at 10

    @staticmethod
    def get_bypass_headers() -> List[Dict]:
        """Return header sets for WAF bypass."""
        return [
            {},  # No extra headers
            {'X-Original-URL': '/', 'X-Rewrite-URL': '/'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'Content-Type': 'application/x-www-form-urlencoded'},
            {'Transfer-Encoding': 'chunked'},
            {'X-HTTP-Method-Override': 'GET'},
        ]


# ═══════════════════════════════════════════════════════════════════
#  Cloud Native Scanner — v3.0
# ═══════════════════════════════════════════════════════════════════

class CloudNativeScanner:
    """
    Detect cloud-native misconfigurations: IAM policies, K8s RBAC,
    serverless configs, Terraform/CloudFormation credential exposure.
    """

    PATTERNS = {
        'AWS IAM Policy': {
            'patterns': [
                r'"Effect"\s*:\s*"Allow"[^}]*"Action"\s*:\s*"\*"',
                r'"Effect"\s*:\s*"Allow"[^}]*"Resource"\s*:\s*"\*"',
                r'arn:aws:iam::\d{12}:(?:role|user|policy)/[A-Za-z0-9+=,.@_-]+',
            ],
            'severity': 'CRITICAL',
        },
        'AWS Lambda Config': {
            'patterns': [
                r'arn:aws:lambda:[a-z0-9-]+:\d{12}:function:[A-Za-z0-9_-]+',
                r'LAMBDA_TASK_ROOT|AWS_LAMBDA_FUNCTION_NAME',
            ],
            'severity': 'MEDIUM',
        },
        'Kubernetes Secret': {
            'patterns': [
                r'kind:\s*Secret\s+metadata:',
                r'kubectl\s+(?:create|apply|get)\s+secret',
                r'kubernetes\.io/service-account-token',
            ],
            'severity': 'CRITICAL',
        },
        'Kubernetes RBAC': {
            'patterns': [
                r'kind:\s*(?:Cluster)?RoleBinding',
                r'kind:\s*(?:Cluster)?Role[^B]',
                r'apiGroups:\s*\["\*"\]',
            ],
            'severity': 'HIGH',
        },
        'Terraform Credential': {
            'patterns': [
                r'(?:access_key|secret_key|password)\s*=\s*"[^"]{8,}"',
                r'provider\s*"(?:aws|azurerm|google)"\s*\{[^}]*(?:token|key)\s*=',
            ],
            'severity': 'CRITICAL',
        },
        'CloudFormation Secret': {
            'patterns': [
                r'AWSTemplateFormatVersion',
                r'Type:\s*AWS::(?:IAM|SecretsManager|KMS)',
            ],
            'severity': 'MEDIUM',
        },
        'GCP Service Account': {
            'patterns': [
                r'"type"\s*:\s*"service_account"',
                r'"private_key_id"\s*:\s*"[a-f0-9]{40}"',
                r'[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com',
            ],
            'severity': 'CRITICAL',
        },
        'Azure Connection String': {
            'patterns': [
                r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}',
                r'Server=tcp:[^;]+;.*Password=[^;]+',
            ],
            'severity': 'CRITICAL',
        },
    }

    def __init__(self):
        self.findings: List[Dict] = []

    def scan(self, content: str, source: str):
        """Scan content for cloud-native misconfigurations."""
        for finding_type, config in self.PATTERNS.items():
            for pattern in config['patterns']:
                for m in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                    val = m.group(0)[:200]
                    h = f"Cloud:{finding_type}:{val[:50]}"
                    if not any(f.get('_hash') == h for f in self.findings):
                        self.findings.append({
                            'type': finding_type, 'value': val,
                            'source': source, 'severity': config['severity'],
                            '_hash': h,
                        })


# ═══════════════════════════════════════════════════════════════════
#  CI/CD Integration — v3.0
# ═══════════════════════════════════════════════════════════════════

class CICDIntegration:
    """Generate CI/CD configs and baseline diff."""

    @staticmethod
    def generate_github_action(filename='secret-scan.yml'):
        """Generate GitHub Actions workflow YAML."""
        action = """name: Secret Scan
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install requests pyyaml

      - name: Run Secret Scanner
        run: |
          python SecretPulse.py --path . --fail-on high \\
            --sarif results.sarif \\
            -o results.json --html report.html

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Upload artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: scan-results
          path: |
            results.json
            report.html
"""
        with open(filename, 'w') as f:
            f.write(action)
        print(f"{Colors.OKGREEN}[+] GitHub Action: {filename}{Colors.ENDC}")
        return filename

    @staticmethod
    def generate_gitlab_ci(filename='.gitlab-ci-scan.yml'):
        """Generate GitLab CI pipeline YAML."""
        ci = """secret-scan:
  stage: test
  image: python:3.11-slim
  script:
    - pip install requests pyyaml
    - python SecretPulse.py --path . --fail-on high --sarif gl-secret-detection-report.json -o results.json
  artifacts:
    reports:
      sast: gl-secret-detection-report.json
    paths:
      - results.json
    when: always
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
    - if: $CI_PIPELINE_SOURCE == "schedule"
"""
        with open(filename, 'w') as f:
            f.write(ci)
        print(f"{Colors.OKGREEN}[+] GitLab CI: {filename}{Colors.ENDC}")
        return filename

    @staticmethod
    def generate_pre_commit_hook(filename='pre-commit-scan.sh'):
        """Generate pre-commit hook script."""
        hook = """#!/bin/bash
# SecretPulse pre-commit hook
# Install: cp pre-commit-scan.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit

echo "[*] Running secret scan on staged files..."

STAGED=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\.(js|ts|jsx|tsx|json|env|yml|yaml|py|rb|go|java)$')

if [ -z "$STAGED" ]; then
    echo "[*] No relevant files staged, skipping scan."
    exit 0
fi

# Check for common secret patterns in staged files
FOUND=0
for FILE in $STAGED; do
    # Check for hardcoded secrets
    if grep -nP '(AKIA[0-9A-Z]{16}|sk_live_|ghp_[0-9a-zA-Z]{36}|-----BEGIN.*PRIVATE KEY)' "$FILE" 2>/dev/null; then
        echo "[!] Potential secret found in $FILE"
        FOUND=1
    fi
done

if [ $FOUND -eq 1 ]; then
    echo ""
    echo "[!] BLOCKED: Potential secrets detected in staged files."
    echo "[!] Review findings above and remove secrets before committing."
    echo "[!] To bypass (NOT recommended): git commit --no-verify"
    exit 1
fi

echo "[+] No secrets detected. Commit OK."
exit 0
"""
        with open(filename, 'w') as f:
            f.write(hook)
        print(f"{Colors.OKGREEN}[+] Pre-commit hook: {filename}{Colors.ENDC}")
        return filename

    @staticmethod
    def diff_baseline(current_findings: List[Dict], baseline_path: str) -> Tuple[List[Dict], List[Dict]]:
        """Compare current scan against baseline, return (new, resolved)."""
        try:
            with open(baseline_path) as f:
                baseline = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"{Colors.FAIL}[!] Baseline error: {e}{Colors.ENDC}")
            return current_findings, []

        prev = baseline.get('unified_findings') or baseline.get('findings', [])
        prev_keys = {f"{f.get('type', '')}:{f.get('value', '')}" for f in prev}
        curr_keys = {f"{f.get('type', '')}:{f.get('value', '')}" for f in current_findings}

        new_findings = [f for f in current_findings
                        if f"{f.get('type', '')}:{f.get('value', '')}" not in prev_keys]
        resolved = [f for f in prev
                    if f"{f.get('type', '')}:{f.get('value', '')}" not in curr_keys]

        return new_findings, resolved


# ═══════════════════════════════════════════════════════════════════
#  Team Collaboration — v3.0 (Webhook Notifications)
# ═══════════════════════════════════════════════════════════════════

class TeamNotifier:
    """Push scan results to Slack/Teams/Discord/generic webhooks."""

    def __init__(self, webhook_url: str, session: requests.Session):
        self.webhook_url = webhook_url
        self.session = session
        self._detect_platform()

    def _detect_platform(self):
        url_l = self.webhook_url.lower()
        if 'hooks.slack.com' in url_l:
            self.platform = 'slack'
        elif 'discord.com/api/webhooks' in url_l or 'discordapp.com' in url_l:
            self.platform = 'discord'
        elif 'webhook.office.com' in url_l or 'outlook.office.com' in url_l:
            self.platform = 'teams'
        else:
            self.platform = 'generic'

    def send_alert(self, findings: List[Dict], stats: Dict, target: str):
        """Send scan summary to webhook."""
        critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
        high = sum(1 for f in findings if f['severity'] == 'HIGH')
        live = sum(1 for f in findings if f.get('verified_live') is True)

        if self.platform == 'slack':
            self._send_slack(findings, stats, target, critical, high, live)
        elif self.platform == 'discord':
            self._send_discord(findings, stats, target, critical, high, live)
        elif self.platform == 'teams':
            self._send_teams(findings, stats, target, critical, high, live)
        else:
            self._send_generic(findings, stats, target, critical, high, live)

    def _send_slack(self, findings, stats, target, critical, high, live):
        emoji = '🚨' if critical > 0 else ('⚠️' if high > 0 else '✅')
        blocks = [{
            'type': 'section',
            'text': {'type': 'mrkdwn', 'text':
                     f'{emoji} *Secret Scanner v{__version__}*\n'
                     f'*Target:* `{target}`\n'
                     f'*Findings:* {len(findings)} total · '
                     f'{critical} CRITICAL · {high} HIGH · {live} verified live\n'
                     f'*URLs scanned:* {stats.get("requests_made", 0)}'}
        }]
        if critical > 0:
            crit_list = [f for f in findings if f['severity'] == 'CRITICAL'][:5]
            text = '\n'.join(f"• `{f['type']}` in {f['source'][:50]}"
                             for f in crit_list)
            blocks.append({
                'type': 'section',
                'text': {'type': 'mrkdwn', 'text': f'*Critical Findings:*\n{text}'}
            })
        try:
            self.session.post(self.webhook_url, json={'blocks': blocks}, timeout=10)
            print(f"{Colors.OKGREEN}[+] Slack notification sent{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] Slack notification failed: {e}{Colors.ENDC}")

    def _send_discord(self, findings, stats, target, critical, high, live):
        color = 0xFF0000 if critical > 0 else (0xFF8C00 if high > 0 else 0x00FF00)
        embed = {
            'title': f'🔍 Secret Scanner v{__version__}',
            'description': f'**Target:** `{target}`',
            'color': color,
            'fields': [
                {'name': 'Findings', 'value': str(len(findings)), 'inline': True},
                {'name': 'Critical', 'value': str(critical), 'inline': True},
                {'name': 'Verified Live', 'value': str(live), 'inline': True},
            ],
        }
        try:
            self.session.post(self.webhook_url, json={'embeds': [embed]}, timeout=10)
            print(f"{Colors.OKGREEN}[+] Discord notification sent{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] Discord notification failed: {e}{Colors.ENDC}")

    def _send_teams(self, findings, stats, target, critical, high, live):
        card = {
            '@type': 'MessageCard', '@context': 'https://schema.org/extensions',
            'summary': f'Secret Scan: {len(findings)} findings',
            'themeColor': 'FF0000' if critical > 0 else '00FF00',
            'title': f'🔍 Secret Scanner v{__version__}',
            'sections': [{'facts': [
                {'name': 'Target', 'value': target},
                {'name': 'Findings', 'value': f'{len(findings)} ({critical} CRITICAL, {high} HIGH)'},
                {'name': 'Verified Live', 'value': str(live)},
            ]}],
        }
        try:
            self.session.post(self.webhook_url, json=card, timeout=10)
            print(f"{Colors.OKGREEN}[+] Teams notification sent{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] Teams notification failed: {e}{Colors.ENDC}")

    def _send_generic(self, findings, stats, target, critical, high, live):
        payload = {
            'tool': f'SecretPulse v{__version__}',
            'target': target, 'total_findings': len(findings),
            'critical': critical, 'high': high, 'verified_live': live,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'top_findings': [
                {'type': f['type'], 'severity': f['severity'],
                 'source': f['source'][:100]}
                for f in sorted(findings, key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}.get(x['severity'],4))[:10]
            ],
        }
        try:
            self.session.post(self.webhook_url, json=payload, timeout=10)
            print(f"{Colors.OKGREEN}[+] Webhook notification sent{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] Webhook notification failed: {e}{Colors.ENDC}")



# ═══════════════════════════════════════════════════════════════════
#  OFFENSIVE RECON: Wayback Machine Historical Miner — v4.0
# ═══════════════════════════════════════════════════════════════════

class WaybackMiner:
    """Mine archived JS/HTML from Wayback Machine for historical secrets."""

    WAYBACK_CDX = 'https://web.archive.org/cdx/search/cdx'

    # Domains that should NEVER be scanned — they're infrastructure, not targets
    EXCLUDED_DOMAINS = {
        'web.archive.org', 'archive.org', 'cloudflare.com', 'cdnjs.cloudflare.com',
        'cdn.cloudflare.com', 'ajax.cloudflare.com', 'ruffle.rs',
        'cdn.jsdelivr.net', 'unpkg.com', 'cdnjs.com', 'fonts.googleapis.com',
        'fonts.gstatic.com', 'google-analytics.com', 'googletagmanager.com',
        'www.googletagmanager.com', 'connect.facebook.net', 'platform.twitter.com',
        'cdn.segment.com', 'js.stripe.com', 'cdn.shopify.com',
        'static.cloudflareinsights.com', 'challenges.cloudflare.com',
        'www.google.com', 'apis.google.com', 'maps.googleapis.com',
    }

    def __init__(self, session, rate_limiter, verbose=False):
        self.session = session
        self.rate_limiter = rate_limiter
        self.verbose = verbose
        self.archived_urls: List[Dict] = []
        self.filtered_count = 0  # track how many off-scope URLs were dropped

    def _is_in_scope(self, url: str, target_domain: str) -> bool:
        """Check if URL belongs to the target domain (strict scope)."""
        try:
            parsed = urlparse(url)
            url_domain = parsed.netloc.lower().lstrip('www.')
            target_clean = target_domain.lower().lstrip('www.')

            # Reject known infrastructure domains
            for excluded in self.EXCLUDED_DOMAINS:
                if url_domain == excluded or url_domain.endswith('.' + excluded):
                    return False

            # Must match target domain or be a subdomain of it
            if url_domain == target_clean:
                return True
            if url_domain.endswith('.' + target_clean):
                return True

            return False
        except Exception:
            return False

    def mine(self, domain: str, max_results: int = 100) -> List[str]:
        """Fetch archived JS/HTML URLs from Wayback Machine (target-scoped, deduplicated)."""
        urls = []
        seen_paths = set()  # Dedup by base path (strip query params)
        self.filtered_count = 0
        self.dedup_count = 0
        target_domain = domain.lower().lstrip('www.')

        for mime in ['application/javascript', 'text/html']:
            try:
                self.rate_limiter.wait()
                params = {
                    'url': f'{domain}/*', 'output': 'json',
                    'filter': f'mimetype:{mime}',
                    'fl': 'timestamp,original,statuscode',
                    'limit': str(max_results // 2),
                    'collapse': 'urlkey',
                }
                resp = self.session.get(self.WAYBACK_CDX, params=params, timeout=30)
                if resp.status_code == 200:
                    rows = resp.json()
                    for row in rows[1:]:  # Skip header
                        if len(row) >= 3 and row[2] == '200':
                            original_url = row[1]
                            # STRICT SCOPE: only accept URLs on the target domain
                            if not self._is_in_scope(original_url, target_domain):
                                self.filtered_count += 1
                                if self.verbose:
                                    print(f"{Colors.DIM}  Wayback skip (off-scope): "
                                          f"{urlparse(original_url).netloc}{Colors.ENDC}")
                                continue
                            # Dedup: strip query params to avoid scanning same file 20x
                            base_path = urlparse(original_url).path.lower()
                            if base_path in seen_paths:
                                self.dedup_count += 1
                                continue
                            seen_paths.add(base_path)
                            wb_url = f"https://web.archive.org/web/{row[0]}if_/{row[1]}"
                            urls.append(wb_url)
                            self.archived_urls.append({
                                'timestamp': row[0], 'original': original_url,
                                'wayback_url': wb_url, 'type': mime,
                            })
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.DIM}  Wayback error: {e}{Colors.ENDC}")
        dedup_msg = f", {self.dedup_count} duplicates removed" if self.dedup_count else ""
        if self.verbose or self.filtered_count > 0:
            print(f"{Colors.OKCYAN}  [*] Wayback: {len(urls)} unique in-scope URLs "
                  f"({self.filtered_count} off-scope filtered{dedup_msg}){Colors.ENDC}")
        return urls


# ═══════════════════════════════════════════════════════════════════
#  OFFENSIVE RECON: Subdomain Takeover / Dangling CNAME — v4.0
# ═══════════════════════════════════════════════════════════════════

class SubdomainTakeoverChecker:
    """Check for dangling CNAMEs and subdomain takeover conditions."""

    VULNERABLE_CNAMES = {
        'herokuapp.com': 'Heroku', 'herokudns.com': 'Heroku',
        'github.io': 'GitHub Pages', 'azurewebsites.net': 'Azure',
        'cloudapp.net': 'Azure', 'cloudapp.azure.com': 'Azure',
        'trafficmanager.net': 'Azure Traffic Manager',
        's3.amazonaws.com': 'AWS S3', 's3-website': 'AWS S3 Website',
        'elasticbeanstalk.com': 'AWS EB', 'cloudfront.net': 'AWS CloudFront',
        'shopify.com': 'Shopify', 'myshopify.com': 'Shopify',
        'zendesk.com': 'Zendesk', 'readme.io': 'ReadMe', 'ghost.io': 'Ghost',
        'netlify.app': 'Netlify', 'pantheon.io': 'Pantheon',
        'surge.sh': 'Surge', 'bitbucket.io': 'Bitbucket',
        'wordpress.com': 'WordPress', 'tumblr.com': 'Tumblr',
        'statuspage.io': 'Statuspage', 'fastly.net': 'Fastly',
        'unbounce.com': 'Unbounce', 'uservoice.com': 'UserVoice',
        'webflow.io': 'Webflow', 'cargo.site': 'Cargo', 'tilda.ws': 'Tilda',
    }

    TAKEOVER_SIGNATURES = [
        "There isn't a GitHub Pages site here",
        "NoSuchBucket", "The specified bucket does not exist",
        "No such app", "Heroku | No such app",
        "404 Blog is not found", "is not a registered InCloud",
        "Domain is not configured", "project not found",
        "Sorry, this shop is currently unavailable",
        "Do you want to register", "Fastly error: unknown domain",
        "404 Web Site not found", "This site is not configured",
        "Repository not found", "no such app",
    ]

    def __init__(self, session, verbose=False):
        self.session = session
        self.verbose = verbose
        self.findings: List[Dict] = []
        self._checked: Set[str] = set()

    def _doh_cname(self, domain):
        """Resolve a CNAME through DNS-over-HTTPS without extra dependencies."""
        try:
            resp = self.session.get(
                'https://dns.google/resolve',
                params={'name': domain, 'type': 'CNAME'},
                headers={'Accept': 'application/dns-json'},
                timeout=8,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            for answer in data.get('Answer', []):
                if answer.get('type') == 5 and answer.get('data'):
                    return str(answer['data']).rstrip('.').lower()
        except Exception:
            return None
        return None

    def _service_for_target(self, target):
        for suffix, service in self.VULNERABLE_CNAMES.items():
            if target == suffix or target.endswith('.' + suffix):
                return service
            if suffix == 's3-website' and suffix in target:
                return service
        return None

    def check_cname(self, domain: str):
        """Check a real CNAME chain and fingerprint the destination page.

        NXDOMAIN and TLS failures are not takeover evidence by themselves, so
        they are intentionally not reported. A finding requires a CNAME to a
        known claimable service plus a matching takeover page or a failed
        destination fetch.
        """
        domain = (domain or '').strip().lower().rstrip('.')
        if not domain or domain in self._checked:
            return False
        self._checked.add(domain)

        try:
            ipaddress.ip_address(domain)
            return False
        except ValueError:
            pass
        if '.' not in domain or not re.fullmatch(r'[a-z0-9.-]+', domain):
            return False

        cname = self._doh_cname(domain)
        if not cname:
            return False
        service = self._service_for_target(cname)
        if not service:
            return False

        status_code = 0
        try:
            resp = self.session.get(f'https://{domain}', timeout=10, allow_redirects=True)
            status_code = resp.status_code
            body = resp.text[:200000].lower()
            for sig in self.TAKEOVER_SIGNATURES:
                if sig.lower() in body:
                    self.findings.append({
                        'domain': domain, 'cname': cname, 'service': service,
                        'signature': sig, 'severity': 'CRITICAL',
                        'status': 'potential', 'confidence': 'HIGH',
                        'status_code': status_code,
                    })
                    return True
            self.findings.append({
                'domain': domain, 'cname': cname, 'service': service,
                'signature': f'CNAME points to {service}; verify claimability',
                'severity': 'LOW', 'status': 'lead', 'confidence': 'MEDIUM',
                'status_code': status_code,
            })
            return True
        except Exception:
            self.findings.append({
                'domain': domain, 'cname': cname, 'service': service,
                'signature': f'{service} destination is unreachable; verify claimability',
                'severity': 'MEDIUM', 'status': 'lead', 'confidence': 'MEDIUM',
                'status_code': status_code,
            })
            return True


# ═══════════════════════════════════════════════════════════════════
#  OFFENSIVE RECON: SSRF Cloud Metadata Prober — v4.0
# ═══════════════════════════════════════════════════════════════════

class SSRFProber:
    """Detect SSRF vectors and cloud metadata exposure."""

    METADATA_URLS = {
        'AWS': 'http://169.254.169.254/latest/meta-data/',
        'GCP': 'http://metadata.google.internal/computeMetadata/v1/',
        'Azure': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
        'DigitalOcean': 'http://169.254.169.254/metadata/v1/',
    }

    SSRF_INDICATORS = [
        r'(?:url|uri|path|dest|redirect|next|data|load|fetch|proxy|img|src)\s*=\s*["\']?(https?://)',
        r'urllib\.request\.urlopen|requests\.get|http\.get|fetch\(',
        r'file:///|gopher://|dict://|ldap://|tftp://',
    ]

    def __init__(self):
        self.vectors: List[Dict] = []

    def scan_for_ssrf(self, content: str, source: str):
        """Detect potential SSRF vectors in source code."""
        for pattern in self.SSRF_INDICATORS:
            for m in re.finditer(pattern, content, re.I):
                h = f"ssrf:{m.group()[:30]}:{source}"
                if not any(v.get('_hash') == h for v in self.vectors):
                    ctx = content[max(0, m.start()-50):m.end()+50]
                    self.vectors.append({
                        'indicator': m.group()[:100], 'source': source,
                        'context': ctx[:200], 'severity': 'MEDIUM', '_hash': h,
                    })

    def check_metadata_leaks(self, content: str, source: str):
        """Check if content references cloud metadata endpoints."""
        for cloud, url in self.METADATA_URLS.items():
            if url in content or '169.254.169.254' in content:
                h = f"meta:{cloud}:{source}"
                if not any(v.get('_hash') == h for v in self.vectors):
                    self.vectors.append({
                        'indicator': f'Cloud metadata reference ({cloud})',
                        'source': source, 'context': url,
                        'severity': 'CRITICAL', '_hash': h,
                    })


# ═══════════════════════════════════════════════════════════════════
#  OFFENSIVE RECON: Auth Bypass / IDOR / BOLA Fuzzer — v4.0
# ═══════════════════════════════════════════════════════════════════

class IDORFuzzer:
    """Automated IDOR/BOLA detection via ID enumeration."""

    ID_PATTERNS = [
        r'/(?:api/)?(?:v\d+/)?(?:users?|accounts?|profiles?|orders?|invoices?|'
        r'documents?|files?|projects?|teams?|organizations?)/(\d{1,10})(?:/|$|\?)',
        r'/(?:api/)?(?:v\d+/)?(?:users?|accounts?)/([a-f0-9]{24})(?:/|$|\?)',
        r'[?&](?:user_?id|account_?id|order_?id|doc_?id|file_?id)=(\d{1,10})',
        r'[?&](?:id|uid|oid)=([a-f0-9\-]{20,})',
    ]

    def __init__(self, session, rate_limiter, verbose=False):
        self.session = session
        self.rate_limiter = rate_limiter
        self.verbose = verbose
        self.idor_candidates: List[Dict] = []

    def find_candidates(self, content: str, base_url: str):
        """Find potential IDOR-vulnerable endpoints in content."""
        for pattern in self.ID_PATTERNS:
            for m in re.finditer(pattern, content, re.I):
                self.idor_candidates.append({
                    'url_pattern': m.group(0), 'id_value': m.group(1),
                    'base_url': base_url, 'severity': 'HIGH',
                })

# ═══════════════════════════════════════════════════════════════════
#  OFFENSIVE RECON: Internal API Enumeration — v4.0
# ═══════════════════════════════════════════════════════════════════

class InternalAPIEnumerator:
    """Extract internal API routes from source maps and JS bundles."""

    ROUTE_PATTERNS = [
        r'(?:path|route|url)\s*:\s*["\'](/api/[^\s"\']{3,})["\']',
        r'(?:get|post|put|delete|patch)\s*\(\s*["\'](/[^\s"\']{3,})["\']',
        r'fetch\s*\(\s*[`"\']([^`"\']*?/api/[^`"\']*?)[`"\']',
        r'axios\.\w+\s*\(\s*[`"\']([^`"\']*?/api/[^`"\']*?)[`"\']',
        r'(?:BASE_URL|API_URL|API_BASE|ENDPOINT)["\']?\s*[+\=]\s*["\']([^\s"\']+)["\']',
        r'router\.\w+\s*\(\s*["\']([^\s"\']+)["\']',
    ]

    def __init__(self):
        self.routes: List[Dict] = []
        self._seen: Set[str] = set()

    def extract_routes(self, content: str, source: str):
        """Extract API routes from content."""
        for pattern in self.ROUTE_PATTERNS:
            for m in re.finditer(pattern, content, re.I):
                route = m.group(1)
                if route not in self._seen and len(route) > 3:
                    self._seen.add(route)
                    sev = 'LOW'
                    low = route.lower()
                    if any(k in low for k in ['admin', 'internal', 'debug', 'manage']):
                        sev = 'CRITICAL'
                    elif any(k in low for k in ['user', 'auth', 'token', 'session', 'password']):
                        sev = 'HIGH'
                    elif any(k in low for k in ['config', 'setting', 'private', 'secret']):
                        sev = 'HIGH'
                    self.routes.append({'route': route, 'source': source, 'severity': sev})

    def extract_from_sourcemap(self, sourcemap_data: Dict, source: str):
        """Deep-mine API routes from source map contents."""
        sources = sourcemap_data.get('sources', [])
        for i, content in enumerate(sourcemap_data.get('sourcesContent', []) or []):
            if content:
                src_name = sources[i] if i < len(sources) else '?'
                self.extract_routes(content, f"{source}:{src_name}")

class AttackChainBuilder:
    """Map secrets into attack chains with exploitability scoring and bounty estimates."""

    BOUNTY_TIERS = {
        'CRITICAL': {'label': 'P1 — Critical Exploitability'},
        'HIGH':     {'label': 'P2 — High Exploitability'},
        'MEDIUM':   {'label': 'P3 — Moderate Exploitability'},
        'LOW':      {'label': 'P4 — Low Exploitability'},
    }

    ESCALATION_PATHS = {
        'AWS Access Key': [
            'STS:GetCallerIdentity -> identify account',
            'IAM:ListUsers -> enumerate users',
            'IAM:ListRoles -> find assumable roles',
            'S3:ListBuckets -> access all storage',
            'Lambda:ListFunctions -> extract code/secrets',
            'SecretsManager:ListSecrets -> vault access',
        ],
        'OpenAI API Key': [
            'models/list -> enumerate models',
            'chat/completions -> data exfiltration via prompts',
            'files/list -> access training data',
            'fine-tuning/jobs -> model manipulation',
        ],
        'Anthropic API Key': [
            'models/list -> enumerate models',
            'messages/create -> prompt injection / data exfil',
            'billing -> financial impact',
        ],
        'GitHub Token': [
            'user -> identify account + orgs',
            'repos -> access private repositories',
            'actions/secrets -> extract CI/CD secrets',
            'admin/org -> organization takeover',
        ],
        'GitLab Token': [
            'user -> identify account',
            'projects -> access private repos',
            'pipelines/variables -> CI/CD secret extraction',
        ],
        'Stripe API Key': [
            'customers/list -> PII exposure',
            'charges/list -> financial data',
            'payouts/create -> financial theft',
        ],
        'Slack Token': [
            'auth.test -> identify workspace',
            'conversations.list -> enumerate channels',
            'conversations.history -> read messages',
        ],
        'Discord Bot Token': [
            'users/@me -> bot identity',
            'guilds -> server access',
            'channels/messages -> read all messages',
        ],
        'Google API Key': [
            'Service enumeration (Maps/Drive/Calendar)',
            'Unrestricted key -> billing abuse',
        ],
        'Firebase Config': [
            'Firestore -> data access',
            'Auth users -> PII exposure',
            'Storage -> file access',
        ],
        'Database Connection String': [
            'Connect -> full database access',
            'Enumerate tables -> data mapping',
            'Extract credentials -> chain further',
        ],
        'OAuth Refresh Token': [
            'Token refresh -> persistent access',
            'Scope enumeration -> permission mapping',
        ],
        'Cloudflare API Token': [
            'zones/list -> domain enumeration',
            'dns_records -> DNS manipulation',
            'firewall/rules -> WAF bypass',
        ],
        'DigitalOcean Token': [
            'droplets -> infrastructure access',
            'databases -> data access',
            'domains -> DNS takeover',
        ],
        'Terraform Cloud Token': [
            'workspaces -> infrastructure state',
            'variables -> secret extraction',
            'runs -> infrastructure manipulation',
        ],
    }

    @staticmethod
    def build_chains(findings: List[Dict]) -> List[Dict]:
        """Build attack chains from findings."""
        chains = []
        for f in findings:
            chain = {
                'secret_type': f['type'], 'severity': f['severity'],
                'source': f['source'], 'value_preview': f['value'][:20] + '...',
                'escalation_paths': AttackChainBuilder.ESCALATION_PATHS.get(f['type'], []),
                'verified_live': f.get('verified_live', False),
                'exploitability_score': 0, 'bounty_tier': '', 'chain_steps': [],
            }
            score = {'CRITICAL': 40, 'HIGH': 25, 'MEDIUM': 15, 'LOW': 5}.get(f['severity'], 0)
            if f.get('verified_live'): score += 30
            if chain['escalation_paths']: score += 15
            if f.get('confidence') == 'HIGH': score += 10
            if f.get('entropy', 0) > 4.0: score += 5
            chain['exploitability_score'] = min(score, 100)

            if chain['exploitability_score'] >= 70:
                chain['bounty_tier'] = AttackChainBuilder.BOUNTY_TIERS['CRITICAL']['label']
            elif chain['exploitability_score'] >= 50:
                chain['bounty_tier'] = AttackChainBuilder.BOUNTY_TIERS['HIGH']['label']
            elif chain['exploitability_score'] >= 30:
                chain['bounty_tier'] = AttackChainBuilder.BOUNTY_TIERS['MEDIUM']['label']
            else:
                chain['bounty_tier'] = AttackChainBuilder.BOUNTY_TIERS['LOW']['label']

            steps = [f"1. FOUND: {f['type']} in {f['source'][:50]}"]
            if f.get('verified_live'):
                steps.append("2. VERIFIED: Key is active")
            if chain['escalation_paths']:
                steps.append(f"3. ESCALATE: {chain['escalation_paths'][0]}")
                if len(chain['escalation_paths']) > 1:
                    steps.append(f"4. PIVOT: {chain['escalation_paths'][1]}")
            chain['chain_steps'] = steps
            chains.append(chain)
        chains.sort(key=lambda x: x['exploitability_score'], reverse=True)
        return chains

    @staticmethod
    def print_chains(chains: List[Dict]):
        """Display attack chains."""
        if not chains: return
        print(f"\n{Colors.BOLD}{'=' * 60}")
        print(f"  ATTACK CHAIN ANALYSIS -- {len(chains)} chain(s)")
        print(f"{'=' * 60}{Colors.ENDC}")
        for i, c in enumerate(chains[:15], 1):
            color = Colors.FAIL if c['exploitability_score'] >= 70 else (
                Colors.WARNING if c['exploitability_score'] >= 50 else Colors.OKCYAN)
            live_tag = f" {Colors.FAIL}* LIVE{Colors.ENDC}" if c['verified_live'] else ""
            print(f"\n{color}Chain #{i}: {c['secret_type']} "
                  f"[Score: {c['exploitability_score']}/100] [{c['bounty_tier']}]{Colors.ENDC}{live_tag}")
            for step in c['chain_steps']:
                print(f"  {step}")
            if c['escalation_paths']:
                print(f"  Escalation ({len(c['escalation_paths'])} paths):")
                for ep in c['escalation_paths'][:3]:
                    print(f"    -> {ep}")


# ═══════════════════════════════════════════════════════════════════
#  PRIVILEGE ESCALATION SIMULATOR — v4.0
# ═══════════════════════════════════════════════════════════════════

class PrivilegeEscalationSimulator:
    """Simulate privilege escalation paths (safe read-only operations)."""

    def __init__(self, session):
        self.session = session
        self.results: List[Dict] = []

    def simulate_aws(self, access_key: str, finding: Dict):
        """Document AWS privilege escalation paths."""
        if access_key.startswith('AKIA'):
            result = {
                'provider': 'AWS', 'key_type': 'IAM Access Key',
                'potential_paths': [
                    'sts:GetCallerIdentity -> Account + ARN',
                    'iam:ListUsers -> User enumeration',
                    'iam:ListAttachedUserPolicies -> Policy mapping',
                    's3:ListBuckets -> Storage enumeration',
                    'ec2:DescribeInstances -> Infrastructure mapping',
                    'lambda:ListFunctions -> Serverless code access',
                    'secretsmanager:ListSecrets -> Secret vault access',
                ],
                'risk_level': 'CRITICAL',
            }
            self.results.append(result)
            return result
        return None

    def simulate_gcp(self, key_data: str, finding: Dict):
        """Document GCP privilege escalation paths."""
        result = {
            'provider': 'GCP', 'key_type': 'Service Account',
            'potential_paths': [
                'iam.serviceAccounts.list -> SA enumeration',
                'storage.buckets.list -> Bucket enumeration',
                'compute.instances.list -> VM enumeration',
                'cloudfunctions.functions.list -> Function code access',
            ],
            'risk_level': 'CRITICAL',
        }
        self.results.append(result)
        return result

    def simulate_jwt(self, jwt_analysis: Dict, finding: Dict):
        """Simulate JWT privilege escalation."""
        vulns = jwt_analysis.get('vulnerabilities', [])
        paths = []
        if 'ALG_NONE' in vulns:
            paths.append('Algorithm:none -> Forge any JWT claim')
        if 'WEAK_ALG' in vulns:
            paths.append('HS256 weak key -> Brute-force secret')
        if jwt_analysis.get('sensitive_permissions'):
            paths.append(f'Admin perms: {jwt_analysis["sensitive_permissions"][:3]} -> Admin access')
        if 'NO_EXPIRY' in vulns:
            paths.append('No expiration -> Persistent access token')
        result = {
            'provider': 'JWT', 'key_type': 'Token',
            'potential_paths': paths or ['Standard JWT -- limited escalation'],
            'risk_level': jwt_analysis.get('risk_grade', 'MEDIUM'),
        }
        self.results.append(result)
        return result


# ═══════════════════════════════════════════════════════════════════
#  v5.0: CVE Auto-Lookup from Source Map Packages
# ═══════════════════════════════════════════════════════════════════

class CVELookup:
    """
    Cross-reference npm packages discovered via Source Map Intelligence
    against known vulnerability databases (OSV.dev + local DB).
    """

    # Expanded local CVE database for offline/fast lookup
    LOCAL_CVE_DB = {
        'lodash': [
            {'version_below': '4.17.21', 'cve': 'CVE-2021-23337', 'severity': 'HIGH',
             'detail': 'Prototype pollution via set/setWith functions'},
            {'version_below': '4.17.12', 'cve': 'CVE-2019-10744', 'severity': 'CRITICAL',
             'detail': 'Prototype pollution via defaultsDeep'},
        ],
        'axios': [
            {'version_below': '1.6.0', 'cve': 'CVE-2023-45857', 'severity': 'HIGH',
             'detail': 'CSRF/SSRF bypass via proxy configuration'},
            {'version_below': '0.21.1', 'cve': 'CVE-2021-3749', 'severity': 'MEDIUM',
             'detail': 'ReDoS in content-type parsing'},
        ],
        'express': [
            {'version_below': '4.17.3', 'cve': 'CVE-2022-24999', 'severity': 'MEDIUM',
             'detail': 'Open redirect via qs prototype pollution'},
        ],
        'jquery': [
            {'version_below': '3.5.0', 'cve': 'CVE-2020-11022', 'severity': 'MEDIUM',
             'detail': 'XSS via htmlPrefilter regex'},
            {'version_below': '3.0.0', 'cve': 'CVE-2015-9251', 'severity': 'HIGH',
             'detail': 'Selector XSS via cross-site scripting'},
        ],
        'minimist': [
            {'version_below': '1.2.6', 'cve': 'CVE-2021-44906', 'severity': 'CRITICAL',
             'detail': 'Prototype pollution via constructor/proto'},
        ],
        'node-fetch': [
            {'version_below': '2.6.7', 'cve': 'CVE-2022-0235', 'severity': 'HIGH',
             'detail': 'SSRF bypass via redirect handling'},
        ],
        'ua-parser-js': [
            {'version_below': '0.7.31', 'cve': 'CVE-2021-44906', 'severity': 'CRITICAL',
             'detail': 'Supply chain attack — malicious code injection'},
        ],
        'ejs': [
            {'version_below': '3.1.7', 'cve': 'CVE-2022-29078', 'severity': 'CRITICAL',
             'detail': 'RCE via template injection'},
        ],
        'handlebars': [
            {'version_below': '4.7.7', 'cve': 'CVE-2021-23369', 'severity': 'HIGH',
             'detail': 'Prototype pollution via template compilation'},
        ],
        'marked': [
            {'version_below': '4.0.10', 'cve': 'CVE-2022-21680', 'severity': 'HIGH',
             'detail': 'ReDoS via crafted markdown input'},
        ],
        'dompurify': [
            {'version_below': '3.0.6', 'cve': 'CVE-2023-48219', 'severity': 'HIGH',
             'detail': 'mXSS bypass via nested forms'},
        ],
        'next': [
            {'version_below': '13.4.6', 'cve': 'CVE-2023-46298', 'severity': 'HIGH',
             'detail': 'SSRF via Server Actions'},
        ],
        'socket.io': [
            {'version_below': '4.6.2', 'cve': 'CVE-2023-32695', 'severity': 'MEDIUM',
             'detail': 'DoS via malformed packet'},
        ],
        'json5': [
            {'version_below': '2.2.2', 'cve': 'CVE-2022-46175', 'severity': 'MEDIUM',
             'detail': 'Prototype pollution via parse()'},
        ],
        'sanitize-html': [
            {'version_below': '2.3.2', 'cve': 'CVE-2021-26539', 'severity': 'HIGH',
             'detail': 'XSS bypass via crafted attributes'},
        ],
        'tinymce': [
            {'version_below': '5.10.0', 'cve': 'CVE-2022-23494', 'severity': 'HIGH',
             'detail': 'Stored XSS via crafted content'},
        ],
        'terser': [
            {'version_below': '5.14.2', 'cve': 'CVE-2022-25858', 'severity': 'MEDIUM',
             'detail': 'ReDoS via crafted input'},
        ],
        'glob-parent': [
            {'version_below': '5.1.2', 'cve': 'CVE-2020-28469', 'severity': 'HIGH',
             'detail': 'ReDoS via crafted glob pattern'},
        ],
        'underscore': [
            {'version_below': '1.13.6', 'cve': 'CVE-2021-23358', 'severity': 'MEDIUM',
             'detail': 'Code injection via template()'},
        ],
        'moment': [
            {'version_below': '2.29.4', 'cve': 'CVE-2022-31129', 'severity': 'MEDIUM',
             'detail': 'ReDoS via crafted date string'},
        ],
        'semver': [
            {'version_below': '7.5.2', 'cve': 'CVE-2022-25883', 'severity': 'MEDIUM',
             'detail': 'ReDoS via crafted version string'},
        ],
        'tough-cookie': [
            {'version_below': '4.1.3', 'cve': 'CVE-2023-26136', 'severity': 'MEDIUM',
             'detail': 'Prototype pollution via cookie parsing'},
        ],
        'word-wrap': [
            {'version_below': '1.2.4', 'cve': 'CVE-2023-26115', 'severity': 'MEDIUM',
             'detail': 'ReDoS via crafted input'},
        ],
        'xml2js': [
            {'version_below': '0.5.0', 'cve': 'CVE-2023-0842', 'severity': 'MEDIUM',
             'detail': 'Prototype pollution via XML parsing'},
        ],
        'postcss': [
            {'version_below': '8.4.31', 'cve': 'CVE-2023-44270', 'severity': 'MEDIUM',
             'detail': 'Line return parsing error'},
        ],
        'undici': [
            {'version_below': '5.26.2', 'cve': 'CVE-2023-45143', 'severity': 'HIGH',
             'detail': 'Cookie header leak via cross-origin redirect'},
        ],
        '@babel/traverse': [
            {'version_below': '7.23.2', 'cve': 'CVE-2023-45133', 'severity': 'CRITICAL',
             'detail': 'Arbitrary code execution via crafted AST'},
        ],
        'crypto-js': [
            {'version_below': '4.2.0', 'cve': 'CVE-2023-46233', 'severity': 'CRITICAL',
             'detail': 'Weak default PRNG in encrypt functions'},
        ],
    }

    def __init__(self, session=None, verbose=False):
        self.session = session
        self.verbose = verbose
        self.results: List[Dict] = []
        self._cache: Dict[str, List[Dict]] = {}

    def lookup_packages(self, packages: List[str], source_map_intel: List[Dict]) -> List[Dict]:
        """
        Cross-reference npm packages against CVE databases.
        Uses source map intel to attempt version detection.
        """
        # Build package -> version map from source map paths
        pkg_versions = self._extract_versions_from_sourcemaps(source_map_intel)

        for pkg in packages:
            pkg_lower = pkg.lower().strip()
            if not pkg_lower or pkg_lower.startswith('.'):
                continue

            version = pkg_versions.get(pkg_lower)

            # Check local DB first
            local_hits = self._check_local_db(pkg_lower, version)
            if local_hits:
                self.results.extend(local_hits)

            # Try OSV.dev API for packages not in local DB
            if not local_hits and self.session and version:
                osv_hits = self._query_osv(pkg_lower, version)
                if osv_hits:
                    self.results.extend(osv_hits)

        return self.results

    def _extract_versions_from_sourcemaps(self, source_map_intel: List[Dict]) -> Dict[str, str]:
        """Extract package versions from source map file paths."""
        versions = {}
        for sm in source_map_intel:
            for path in sm.get('file_tree', []):
                # node_modules/pkg@version or node_modules/pkg/package.json
                m = re.search(r'node_modules/(@?[^/]+(?:/[^/]+)?)/.*?(\d+\.\d+\.\d+)', path)
                if m:
                    pkg_name = m.group(1).lower()
                    pkg_ver = m.group(2)
                    versions[pkg_name] = pkg_ver
        return versions

    def _check_local_db(self, package: str, version: Optional[str]) -> List[Dict]:
        """Check package against local CVE database."""
        hits = []
        entries = self.LOCAL_CVE_DB.get(package, [])
        if not entries:
            return hits

        for entry in entries:
            result = {
                'package': package,
                'version': version or 'unknown',
                'cve': entry['cve'],
                'severity': entry['severity'],
                'detail': entry['detail'],
                'version_below': entry['version_below'],
                'source': 'local_db',
                'vulnerable': None,
            }

            if version:
                result['vulnerable'] = self._version_lt(version, entry['version_below'])
                if result['vulnerable']:
                    hits.append(result)
            else:
                # No version info — flag as potential
                result['vulnerable'] = None
                result['note'] = 'Version unknown — manual check required'
                hits.append(result)

        return hits

    def _query_osv(self, package: str, version: str) -> List[Dict]:
        """Query OSV.dev API for known vulnerabilities."""
        cache_key = f"{package}@{version}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        hits = []
        try:
            resp = self.session.post(
                'https://api.osv.dev/v1/query',
                json={'package': {'name': package, 'ecosystem': 'npm'}, 'version': version},
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get('vulns', []):
                    severity = 'MEDIUM'
                    for sev_item in vuln.get('severity', []):
                        score = sev_item.get('score', '')
                        if isinstance(score, str) and ':' in score:
                            try:
                                base = float(score.split('/')[0].split(':')[-1])
                                if base >= 9.0: severity = 'CRITICAL'
                                elif base >= 7.0: severity = 'HIGH'
                                elif base >= 4.0: severity = 'MEDIUM'
                                else: severity = 'LOW'
                            except (ValueError, IndexError):
                                pass

                    aliases = vuln.get('aliases', [])
                    cve = next((a for a in aliases if a.startswith('CVE-')), vuln.get('id', '?'))

                    hits.append({
                        'package': package,
                        'version': version,
                        'cve': cve,
                        'severity': severity,
                        'detail': vuln.get('summary', vuln.get('details', 'N/A'))[:200],
                        'source': 'osv.dev',
                        'vulnerable': True,
                    })
        except Exception as e:
            if self.verbose:
                print(f"{Colors.DIM}  OSV.dev error for {package}: {e}{Colors.ENDC}")

        self._cache[cache_key] = hits
        return hits

    @staticmethod
    def _version_lt(a: str, b: str) -> bool:
        """Compare version strings: return True if a < b."""
        try:
            def _parts(v):
                return [int(x) for x in re.findall(r'\d+', v)][:4]
            pa, pb = _parts(a), _parts(b)
            while len(pa) < len(pb): pa.append(0)
            while len(pb) < len(pa): pb.append(0)
            return pa < pb
        except (ValueError, IndexError):
            return False

    def print_results(self):
        """Display CVE lookup results."""
        if not self.results:
            return
        confirmed = [r for r in self.results if r.get('vulnerable') is True]
        potential = [r for r in self.results if r.get('vulnerable') is None]

        print(f"\n{Colors.BOLD}📦 Source Map CVE Analysis:{Colors.ENDC}")
        if confirmed:
            print(f"  {Colors.FAIL}Confirmed vulnerable: {len(confirmed)}{Colors.ENDC}")
            seen = set()
            for r in confirmed:
                key = f"{r['package']}@{r['version']}:{r['cve']}"
                if key in seen:
                    continue
                seen.add(key)
                sc = {'CRITICAL': Colors.FAIL, 'HIGH': Colors.WARNING,
                      'MEDIUM': Colors.OKCYAN, 'LOW': Colors.OKBLUE}.get(r['severity'], Colors.ENDC)
                print(f"    {sc}[{r['severity']}]{Colors.ENDC} "
                      f"{r['package']}@{r['version']} — {r['cve']} — {r['detail'][:80]}")
        if potential:
            print(f"  {Colors.WARNING}Potential (version unknown): {len(potential)}{Colors.ENDC}")
            seen = set()
            for r in potential[:10]:
                key = f"{r['package']}:{r['cve']}"
                if key in seen:
                    continue
                seen.add(key)
                print(f"    {r['package']} — {r['cve']} (check manually: vuln below {r.get('version_below','')})")

    def get_summary(self) -> Dict:
        """Return CVE analysis summary."""
        return {
            'total_cves': len(self.results),
            'confirmed_vulnerable': sum(1 for r in self.results if r.get('vulnerable') is True),
            'potential': sum(1 for r in self.results if r.get('vulnerable') is None),
            'by_severity': {
                'CRITICAL': sum(1 for r in self.results if r['severity'] == 'CRITICAL'),
                'HIGH': sum(1 for r in self.results if r['severity'] == 'HIGH'),
                'MEDIUM': sum(1 for r in self.results if r['severity'] == 'MEDIUM'),
                'LOW': sum(1 for r in self.results if r['severity'] == 'LOW'),
            },
            'findings': self.results,
        }


# ═══════════════════════════════════════════════════════════════════
#  v5.0: API Rate Abuse Tester
# ═══════════════════════════════════════════════════════════════════

class RateAbuseTester:
    """
    Test verified API keys for rate limiting and quota enforcement.
    Estimates real-world cost exposure for billable APIs.

    SAFE MODE (default): Max 3 requests per key, extrapolate mathematically.
    No brute forcing. No billing damage. Ethical by default.
    """

    # Cost per request estimates for billable APIs
    API_COST_TABLE = {
        'Google Maps Geocoding': {'cost_per_req': 0.005, 'free_tier': 200, 'unit': 'req'},
        'Google Maps Directions': {'cost_per_req': 0.005, 'free_tier': 200, 'unit': 'req'},
        'Google Maps Places': {'cost_per_req': 0.017, 'free_tier': 100, 'unit': 'req'},
        'Google Maps Static': {'cost_per_req': 0.002, 'free_tier': 200, 'unit': 'req'},
        'YouTube Data': {'cost_per_req': 0.0001, 'free_tier': 10000, 'unit': 'unit'},
        'OpenAI GPT-4': {'cost_per_req': 0.03, 'free_tier': 0, 'unit': '1K tokens'},
        'OpenAI GPT-3.5': {'cost_per_req': 0.002, 'free_tier': 0, 'unit': '1K tokens'},
        'Anthropic Claude': {'cost_per_req': 0.015, 'free_tier': 0, 'unit': '1K tokens'},
        'SendGrid': {'cost_per_req': 0.001, 'free_tier': 100, 'unit': 'email'},
        'Twilio SMS': {'cost_per_req': 0.0075, 'free_tier': 0, 'unit': 'SMS'},
        'Stripe': {'cost_per_req': 0.0, 'free_tier': 0, 'unit': 'req (data access)'},
        'Mapbox': {'cost_per_req': 0.0005, 'free_tier': 50000, 'unit': 'req'},
    }

    PROBE_ENDPOINTS = {
        'Google API Key': {
            'url': 'https://maps.googleapis.com/maps/api/geocode/json',
            'params_fn': lambda key: {'address': 'test', 'key': key},
            'api_name': 'Google Maps Geocoding',
        },
        'OpenAI API Key': {
            'url': 'https://api.openai.com/v1/models',
            'headers_fn': lambda key: {'Authorization': f'Bearer {key}'},
            'api_name': 'OpenAI',
        },
        'Mapbox Token': {
            'url': 'https://api.mapbox.com/geocoding/v5/mapbox.places/test.json',
            'params_fn': lambda key: {'access_token': key},
            'api_name': 'Mapbox',
        },
        'SendGrid API Key': {
            'url': 'https://api.sendgrid.com/v3/scopes',
            'headers_fn': lambda key: {'Authorization': f'Bearer {key}'},
            'api_name': 'SendGrid',
        },
    }

    # Max probes in safe mode — enough to detect headers, not enough to cause damage
    SAFE_MODE_MAX_PROBES = 3

    def __init__(self, session, verbose=False):
        self.session = session
        self.verbose = verbose
        self.results: List[Dict] = []

    def test_key(self, secret_type: str, key: str, max_probes: int = None) -> Optional[Dict]:
        """
        Probe a verified live key for rate limits.
        SAFE MODE: Max 3 requests, then extrapolate mathematically.
        No brute forcing. No billing damage.
        """
        probe_config = self.PROBE_ENDPOINTS.get(secret_type)
        if not probe_config:
            return None

        # SAFE MODE: enforce max probe limit
        if max_probes is None:
            max_probes = self.SAFE_MODE_MAX_PROBES

        api_name = probe_config['api_name']
        url = probe_config['url']
        params = probe_config.get('params_fn', lambda k: {})(key)
        headers = probe_config.get('headers_fn', lambda k: {})(key)

        results = []
        rate_limited = False
        rate_limit_header = None

        for i in range(max_probes):
            try:
                start_t = time.time()
                resp = self.session.get(url, params=params, headers=headers, timeout=8)
                elapsed = time.time() - start_t

                result = {
                    'probe': i + 1,
                    'status': resp.status_code,
                    'latency_ms': round(elapsed * 1000),
                }

                # Check for rate limit headers
                for hdr in ['X-RateLimit-Limit', 'X-RateLimit-Remaining',
                            'X-Rate-Limit-Limit', 'RateLimit-Limit',
                            'Retry-After', 'X-RateLimit-Reset']:
                    val = resp.headers.get(hdr)
                    if val:
                        result[hdr] = val
                        rate_limit_header = {hdr: val}

                if resp.status_code == 429:
                    rate_limited = True
                    result['rate_limited'] = True
                    break

                results.append(result)
                time.sleep(0.3)  # Conservative delay between probes

            except Exception as e:
                results.append({'probe': i + 1, 'error': str(e)})

        # Analyze results — MATHEMATICAL EXTRAPOLATION, not brute force
        analysis = {
            'api_name': api_name,
            'secret_type': secret_type,
            'probes_sent': len(results),
            'safe_mode': True,
            'rate_limited': rate_limited,
            'rate_limit_headers': rate_limit_header,
            'avg_latency_ms': 0,
            'cost_estimate': {},
        }

        if results:
            latencies = [r['latency_ms'] for r in results if 'latency_ms' in r]
            if latencies:
                analysis['avg_latency_ms'] = round(sum(latencies) / len(latencies))

        # Extract rate limit info from headers
        rate_limit_value = None
        remaining_value = None
        for r in results:
            for hdr in ['X-RateLimit-Limit', 'X-Rate-Limit-Limit', 'RateLimit-Limit']:
                if hdr in r:
                    try:
                        rate_limit_value = int(r[hdr])
                    except (ValueError, TypeError):
                        pass
            for hdr in ['X-RateLimit-Remaining', 'X-Rate-Limit-Remaining']:
                if hdr in r:
                    try:
                        remaining_value = int(r[hdr])
                    except (ValueError, TypeError):
                        pass

        if rate_limited:
            analysis['rate_limit_status'] = 'RATE LIMITED (good — API protected)'
            analysis['exploitability_boost'] = 5
            analysis['risk_level'] = 'LOW'
        elif rate_limit_value:
            analysis['rate_limit_status'] = f'{rate_limit_value} req/window (has limits)'
            analysis['exploitability_boost'] = 10
            analysis['risk_level'] = 'MEDIUM'
            if remaining_value is not None:
                analysis['quota_remaining'] = remaining_value
        else:
            analysis['rate_limit_status'] = 'NO RATE LIMIT DETECTED'
            analysis['exploitability_boost'] = 25
            analysis['risk_level'] = 'HIGH'

        # Cost exposure — ESTIMATED mathematically, not tested
        cost_info = self.API_COST_TABLE.get(api_name)
        if cost_info:
            if not rate_limited and not rate_limit_value:
                # No protection detected — estimate theoretical max exposure
                reqs_per_day = 86400  # theoretical 1 req/sec
                daily_cost = reqs_per_day * cost_info['cost_per_req']
                analysis['cost_estimate'] = {
                    'method': 'mathematical_extrapolation',
                    'note': 'Estimated from headers, NOT from actual abuse',
                    'cost_per_request': cost_info['cost_per_req'],
                    'theoretical_reqs_per_day': reqs_per_day,
                    'theoretical_daily_cost': round(daily_cost, 2),
                    'theoretical_monthly_cost': round(daily_cost * 30, 2),
                    'free_tier': cost_info['free_tier'],
                    'unit': cost_info['unit'],
                }
            elif rate_limit_value:
                daily_cost = rate_limit_value * cost_info['cost_per_req']
                analysis['cost_estimate'] = {
                    'method': 'header_based_extrapolation',
                    'cost_per_request': cost_info['cost_per_req'],
                    'rate_limit': rate_limit_value,
                    'estimated_daily_cost': round(daily_cost, 2),
                    'unit': cost_info['unit'],
                }

        self.results.append(analysis)
        return analysis

    def test_findings(self, findings: List[Dict]):
        """Test all verified live findings for rate abuse (safe mode)."""
        live_findings = [f for f in findings if f.get('verified_live') is True]
        tested = set()  # Don't test same key type twice
        for f in live_findings:
            if f['type'] in tested:
                continue
            tested.add(f['type'])
            result = self.test_key(f['type'], f['value'])
            if result and self.verbose:
                print(f"{Colors.OKCYAN}  Rate test ({result['probes_sent']} probes, safe mode): "
                      f"{result['api_name']} — {result['rate_limit_status']}{Colors.ENDC}")

    def print_results(self):
        """Display rate abuse analysis."""
        if not self.results:
            return
        print(f"\n{Colors.BOLD}💰 API Rate Abuse Analysis (Safe Mode — {self.SAFE_MODE_MAX_PROBES} probes max):{Colors.ENDC}")
        for r in self.results:
            risk = r.get('risk_level', 'UNKNOWN')
            if risk == 'HIGH':
                status_color = Colors.FAIL
            elif risk == 'MEDIUM':
                status_color = Colors.WARNING
            else:
                status_color = Colors.OKGREEN
            print(f"\n  {Colors.BOLD}{r['api_name']}{Colors.ENDC}")
            print(f"    Rate limit: {status_color}{r['rate_limit_status']}{Colors.ENDC}")
            print(f"    Risk level: {status_color}{risk}{Colors.ENDC}")
            if r.get('avg_latency_ms'):
                print(f"    Avg latency: {r['avg_latency_ms']}ms")
            if r.get('quota_remaining') is not None:
                print(f"    Quota remaining: {r['quota_remaining']}")
            cost = r.get('cost_estimate', {})
            if cost:
                method = cost.get('method', 'unknown')
                if cost.get('theoretical_daily_cost'):
                    daily = cost['theoretical_daily_cost']
                    monthly = cost.get('theoretical_monthly_cost', daily * 30)
                    print(f"    {Colors.WARNING}Theoretical cost exposure: "
                          f"${daily}/day (${monthly}/month){Colors.ENDC}")
                    print(f"    {Colors.DIM}(Extrapolated from headers, not from actual requests){Colors.ENDC}")
                elif cost.get('estimated_daily_cost'):
                    print(f"    Estimated max cost: ${cost['estimated_daily_cost']}/day "
                          f"(rate limit: {cost.get('rate_limit', '?')})")
                if cost.get('free_tier'):
                    print(f"    Free tier: {cost['free_tier']} {cost.get('unit', 'req')}/day")
            print(f"    Exploitability boost: +{r.get('exploitability_boost', 0)} points")

    def get_summary(self) -> Dict:
        return {
            'apis_tested': len(self.results),
            'safe_mode': True,
            'max_probes_per_key': self.SAFE_MODE_MAX_PROBES,
            'unrestricted': sum(1 for r in self.results if 'NO RATE LIMIT' in r.get('rate_limit_status', '')),
            'rate_limited': sum(1 for r in self.results if r.get('rate_limited')),
            'results': self.results,
        }


# ═══════════════════════════════════════════════════════════════════
#  v5.0: Multi-Target Batch Scanner
# ═══════════════════════════════════════════════════════════════════

class BatchScanner:
    """
    Scan multiple targets from file or stdin with unified summary.
    Supports per-target output and parallel target processing.
    """

    def __init__(self):
        self.target_results: List[Dict] = []

    @staticmethod
    def load_targets(source: str) -> List[str]:
        """Load targets from file or stdin."""
        targets = []
        if source == '-':
            # Read from stdin
            import select
            if select.select([sys.stdin], [], [], 0.0)[0]:
                for line in sys.stdin:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if not line.startswith(('http://', 'https://')):
                            line = 'https://' + line
                        targets.append(line)
        else:
            try:
                with open(source) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if not line.startswith(('http://', 'https://')):
                                line = 'https://' + line
                            targets.append(line)
            except FileNotFoundError:
                print(f"{Colors.FAIL}[!] Target file not found: {source}{Colors.ENDC}")
        return targets

    def add_result(self, target: str, findings_count: int, duration: float,
                   findings: List[Dict]):
        """Record per-target results."""
        self.target_results.append({
            'target': target,
            'findings': findings_count,
            'duration': round(duration, 1),
            'critical': sum(1 for f in findings if f['severity'] == 'CRITICAL'),
            'high': sum(1 for f in findings if f['severity'] == 'HIGH'),
            'live': sum(1 for f in findings if f.get('verified_live') is True),
        })

    def print_batch_summary(self):
        """Print unified summary across all targets."""
        if not self.target_results:
            return
        print(f"\n{'=' * 70}")
        print(f"{Colors.BOLD}BATCH SCAN SUMMARY — {len(self.target_results)} targets{Colors.ENDC}")
        print(f"{'=' * 70}")

        total_findings = sum(r['findings'] for r in self.target_results)
        total_critical = sum(r['critical'] for r in self.target_results)
        total_high = sum(r['high'] for r in self.target_results)
        total_live = sum(r['live'] for r in self.target_results)
        total_time = sum(r['duration'] for r in self.target_results)

        print(f"\n  Targets scanned: {len(self.target_results)}")
        print(f"  Total findings:  {total_findings}")
        if total_critical:
            print(f"  {Colors.FAIL}Critical: {total_critical}{Colors.ENDC}")
        if total_high:
            print(f"  {Colors.WARNING}High: {total_high}{Colors.ENDC}")
        if total_live:
            print(f"  {Colors.FAIL}Verified live: {total_live}{Colors.ENDC}")
        print(f"  Total time: {total_time:.1f}s")

        print(f"\n  Per-target breakdown:")
        for r in sorted(self.target_results, key=lambda x: x['findings'], reverse=True):
            indicator = '🔴' if r['critical'] > 0 else ('🟡' if r['high'] > 0 else '🟢')
            live_tag = f" (⚡{r['live']} live)" if r['live'] > 0 else ''
            print(f"    {indicator} {r['target'][:50]:<50s} "
                  f"{r['findings']:>3d} findings  {r['duration']:>6.1f}s{live_tag}")
