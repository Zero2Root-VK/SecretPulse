"""CORS, redirect, cloud permission, DOM, dependency, and JWT exploit probes."""
from ._imports import *
from .jwt import JWTAnalyzer
from .utils import Colors

class CORSDetector:
    """
    Test for CORS misconfigurations: reflected origins, null origin,
    subdomain wildcards, credential leakage.
    """

    def __init__(self, session, rate_limiter, verbose=False):
        self.session = session
        self.rate_limiter = rate_limiter
        self.verbose = verbose
        self.findings: List[Dict] = []

    def test_url(self, url: str, target_domain: str):
        """Run all CORS tests against a URL."""
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        tests = [
            # (origin_to_send, test_name, severity_if_reflected)
            ("https://evil.com", "arbitrary_origin", "CRITICAL"),
            ("null", "null_origin", "HIGH"),
            (f"https://{target_domain}.evil.com", "subdomain_suffix", "HIGH"),
            (f"https://evil-{target_domain}", "prefix_bypass", "HIGH"),
            (f"https://sub.{target_domain}", "subdomain_match", "MEDIUM"),
            (origin.replace("https://", "http://"), "http_downgrade", "MEDIUM"),
        ]

        for test_origin, test_name, severity in tests:
            try:
                self.rate_limiter.wait()
                headers = {'Origin': test_origin}
                resp = self.session.get(url, headers=headers, timeout=8, allow_redirects=False)
                if resp is None:
                    continue

                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '').lower()

                if not acao:
                    continue

                vuln = False
                detail = ""
                wildcard_credentials = False

                if acao == '*' and acac == 'true':
                    vuln = True
                    wildcard_credentials = True
                    severity = "MEDIUM"
                    detail = ("Wildcard ACAO with credentials — invalid combination; "
                              "browsers reject credentialed requests")
                elif acao == test_origin and test_name in ('arbitrary_origin', 'subdomain_suffix', 'prefix_bypass'):
                    vuln = True
                    cred_note = " WITH credentials" if acac == 'true' else ""
                    detail = f"Origin '{test_origin}' reflected{cred_note} ({test_name})"
                    if acac == 'true':
                        severity = "CRITICAL"
                elif acao == 'null' and test_name == 'null_origin':
                    vuln = True
                    detail = "null origin accepted — sandbox/iframe CORS bypass"
                    if acac == 'true':
                        severity = "CRITICAL"

                if vuln:
                    finding = {
                        'type': 'CORS Misconfiguration',
                        'url': url,
                        'test': test_name,
                        'severity': severity,
                        'origin_sent': test_origin,
                        'acao': acao,
                        'credentials': acac == 'true',
                        'wildcard_credentials': wildcard_credentials,
                        'detail': detail,
                    }
                    self.findings.append(finding)
                    if self.verbose:
                        sev_color = {'CRITICAL': Colors.FAIL, 'HIGH': Colors.WARNING}.get(severity, Colors.OKCYAN)
                        print(f"{sev_color}  [CORS] [{severity}] {detail}{Colors.ENDC}")
                    break  # One finding per URL is enough

            except Exception:
                continue

    def get_summary(self) -> dict:
        critical = sum(1 for f in self.findings if f['severity'] == 'CRITICAL')
        return {
            'total': len(self.findings),
            'critical': critical,
            'findings': self.findings,
        }


# ═══════════════════════════════════════════════════════════════════
#  v6.0: Open Redirect Detector
# ═══════════════════════════════════════════════════════════════════

class OpenRedirectDetector:
    """
    Detect open redirect vulnerabilities by testing URL parameters
    with external redirect targets.
    """

    REDIRECT_PARAMS = [
        'redirect', 'redirect_uri', 'redirect_url', 'redir',
        'next', 'url', 'return', 'return_to', 'returnTo',
        'goto', 'dest', 'destination', 'continue', 'forward',
        'rurl', 'target', 'link', 'out', 'view', 'ref',
        'callback', 'cb', 'jump', 'to', 'path',
    ]

    PAYLOADS = [
        'https://evil.com',
        '//evil.com',
        '/\\evil.com',
        'https:evil.com',
        '////evil.com',
        'https://evil.com%00.target.com',
        'https://evil.com%23.target.com',
    ]

    def __init__(self, session, rate_limiter, verbose=False):
        self.session = session
        self.rate_limiter = rate_limiter
        self.verbose = verbose
        self.findings: List[Dict] = []
        self._tested = set()

    def scan_url(self, url: str):
        """Test URL parameters for open redirect."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Test existing redirect-like parameters
        for param in params:
            if param.lower() in self.REDIRECT_PARAMS:
                self._test_param(url, param)

        # Also probe common redirect params if not present
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        for param in self.REDIRECT_PARAMS[:8]:  # Top 8 most common
            test_key = f"{base_url}:{param}"
            if test_key not in self._tested:
                self._tested.add(test_key)
                test_url = f"{base_url}?{param}=https://evil.com"
                self._test_redirect(test_url, param, "https://evil.com")

    def _test_param(self, url: str, param: str):
        """Test a specific parameter with multiple payloads."""
        parsed = urlparse(url)
        for payload in self.PAYLOADS[:3]:  # Limit to 3 payloads per param
            key = f"{parsed.netloc}{parsed.path}:{param}:{payload}"
            if key in self._tested:
                continue
            self._tested.add(key)

            # Replace the param value
            params = parse_qs(parsed.query)
            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            self._test_redirect(test_url, param, payload)

    def _test_redirect(self, url: str, param: str, payload: str):
        """Send request and check if redirect goes to our target."""
        try:
            self.rate_limiter.wait()
            resp = self.session.get(url, timeout=8, allow_redirects=False)
            if resp is None:
                return

            location = resp.headers.get('Location', '')
            status = resp.status_code

            is_redirect = status in (301, 302, 303, 307, 308)
            redirects_external = False
            verified_by = None

            if is_redirect and location:
                loc_parsed = urlparse(location)
                if loc_parsed.netloc and 'evil.com' in loc_parsed.netloc:
                    redirects_external = True
                elif location.startswith('//evil.com') or location.startswith('/\\evil.com'):
                    redirects_external = True
                if redirects_external:
                    verified_by = 'location'

            # Client-side redirects are weaker evidence and require manual confirmation.
            if not is_redirect and status == 200:
                body = resp.text[:2000].lower()
                meta_refresh = bool(re.search(
                    r'<meta[^>]+http-equiv=["\']?refresh', body))
                js_redirect = bool(re.search(
                    r'window\.location(?:\.href)?\s*=\s*["\'][^"\']*evil\.com', body))
                if 'evil.com' in body and (meta_refresh or js_redirect):
                    redirects_external = True
                    verified_by = 'body'

            if redirects_external:
                severity = "HIGH" if 'oauth' in url.lower() or 'auth' in url.lower() else "MEDIUM"
                finding = {
                    'type': 'Open Redirect',
                    'url': url,
                    'param': param,
                    'payload': payload,
                    'severity': severity,
                    'status_code': status,
                    'location': location[:200],
                    'verified_by': verified_by,
                    'detail': f"Parameter '{param}' redirects to external domain",
                }
                self.findings.append(finding)
                if self.verbose:
                    print(f"{Colors.WARNING}  [REDIRECT] [{severity}] "
                          f"?{param}= redirects to evil.com (HTTP {status}){Colors.ENDC}")
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════
#  v6.0: Cloud Permission Tester
# ═══════════════════════════════════════════════════════════════════

class CloudPermissionTester:
    """
    Test discovered cloud resources for read-only misconfigurations:
    - S3 bucket listing
    - GCS bucket access
    - Firebase open read
    - Azure blob public access

    Never writes to or deletes from a discovered bucket.
    """

    def __init__(self, session, rate_limiter, verbose=False):
        self.session = session
        self.rate_limiter = rate_limiter
        self.verbose = verbose
        self.findings: List[Dict] = []

    def test_s3_bucket(self, bucket_name: str):
        """Test S3 bucket for public listing without modifying it."""
        bucket_name = bucket_name.strip().strip('/')
        urls_to_try = [
            f"https://{bucket_name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket_name}",
        ]

        for base_url in urls_to_try:
            try:
                # Test LIST
                self.rate_limiter.wait()
                resp = self.session.get(base_url, timeout=10)
                if resp and resp.status_code == 200:
                    body = resp.text[:5000]
                    if '<ListBucketResult' in body or '<Contents>' in body:
                        # Count objects
                        import re as _re
                        keys = _re.findall(r'<Key>([^<]+)</Key>', body)
                        self.findings.append({
                            'type': 'S3 Bucket Public Listing',
                            'severity': 'HIGH',
                            'bucket': bucket_name,
                            'url': base_url,
                            'objects_visible': len(keys),
                            'sample_keys': keys[:5],
                            'detail': f"S3 bucket '{bucket_name}' allows public listing ({len(keys)} objects visible)",
                        })
                        if self.verbose:
                            print(f"{Colors.FAIL}  [S3] [HIGH] Public listing: {bucket_name} "
                                  f"({len(keys)} objects){Colors.ENDC}")
                        return  # Found listing, no need to try other URL format
                elif resp and resp.status_code == 403:
                    # Bucket exists but not listable — that's OK
                    pass
                elif resp and resp.status_code == 404:
                    pass  # Bucket doesn't exist
            except Exception:
                continue

    def test_gcs_bucket(self, bucket_url: str):
        """Test GCS bucket/object for public access."""
        try:
            self.rate_limiter.wait()
            resp = self.session.get(bucket_url, timeout=10)
            if resp and resp.status_code == 200:
                # Check if it's a directory listing
                ct = resp.headers.get('Content-Type', '')
                if 'xml' in ct and '<ListBucketResult' in resp.text[:1000]:
                    self.findings.append({
                        'type': 'GCS Bucket Public Listing',
                        'severity': 'HIGH',
                        'url': bucket_url,
                        'detail': f"GCS bucket allows public listing",
                    })
                    if self.verbose:
                        print(f"{Colors.FAIL}  [GCS] [HIGH] Public listing: {bucket_url}{Colors.ENDC}")
        except Exception:
            pass

    def test_firebase(self, firebase_url: str):
        """Test Firebase for open read access."""
        # Firebase DBs expose data at /.json
        base = firebase_url.rstrip('/')
        if not base.endswith('.json'):
            test_url = base + '/.json'
        else:
            test_url = base

        try:
            self.rate_limiter.wait()
            resp = self.session.get(test_url, timeout=10)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if data and data != 'null' and isinstance(data, dict):
                        keys = list(data.keys())[:10]
                        self.findings.append({
                            'type': 'Firebase Open Read',
                            'severity': 'CRITICAL',
                            'url': test_url,
                            'collections': keys,
                            'detail': f"Firebase database is publicly readable ({len(keys)} top-level collections)",
                        })
                        if self.verbose:
                            print(f"{Colors.FAIL}  [FIREBASE] [CRITICAL] Open read: {test_url} "
                                  f"({', '.join(keys[:5])}){Colors.ENDC}")
                except Exception:
                    pass
        except Exception:
            pass

    def test_azure_blob(self, container_url: str):
        """Test Azure blob container for public listing."""
        test_url = container_url.rstrip('/') + '?restype=container&comp=list'
        try:
            self.rate_limiter.wait()
            resp = self.session.get(test_url, timeout=10)
            if resp and resp.status_code == 200 and '<EnumerationResults' in resp.text[:1000]:
                self.findings.append({
                    'type': 'Azure Blob Public Listing',
                    'severity': 'HIGH',
                    'url': container_url,
                    'detail': "Azure blob container allows public listing",
                })
                if self.verbose:
                    print(f"{Colors.FAIL}  [AZURE] [HIGH] Public listing: {container_url}{Colors.ENDC}")
        except Exception:
            pass

    def test_from_findings(self, findings: List[Dict]):
        """Auto-test cloud resources found by the secret scanner."""
        for f in findings:
            ftype = f.get('type', '')
            value = f.get('value', '')

            if ftype == 'AWS S3 Bucket' or ('s3.amazonaws.com' in value and 'amazonaws' in value):
                # Extract bucket name
                if 's3.amazonaws.com/' in value:
                    bucket = value.split('s3.amazonaws.com/')[-1].split('/')[0]
                elif '.s3.' in value:
                    bucket = urlparse(value).netloc.split('.s3.')[0]
                else:
                    bucket = value
                if bucket:
                    self.test_s3_bucket(bucket)

            elif ftype == 'GCS Bucket' or 'storage.googleapis.com' in value:
                self.test_gcs_bucket(value)

            elif 'firebaseio.com' in value or 'firebase' in value.lower():
                self.test_firebase(value)

            elif '.blob.core.windows.net' in value:
                self.test_azure_blob(value)


# ═══════════════════════════════════════════════════════════════════
#  v6.0: DOM XSS Sink/Source Mapper
# ═══════════════════════════════════════════════════════════════════

class DOMXSSMapper:
    """
    Static analysis of JavaScript to map DOM XSS sources → sinks.
    Identifies potential DOM XSS attack vectors without active exploitation.
    """

    SOURCES = {
        'location.hash': 'URL fragment',
        'location.search': 'URL query string',
        'location.href': 'Full URL',
        'location.pathname': 'URL path',
        'document.referrer': 'Referrer header',
        'document.URL': 'Document URL',
        'document.documentURI': 'Document URI',
        'window.name': 'Window name (cross-origin writable)',
        'document.cookie': 'Cookie values',
        'window.location': 'Window location',
        'postMessage': 'Cross-origin message',
        'addEventListener\\s*\\(\\s*[\'"]message': 'postMessage listener',
        'URLSearchParams': 'URL parameter parser',
        'url\\.searchParams': 'URL search params',
    }

    SINKS = {
        'innerHTML': 'HTML injection — HIGH risk',
        'outerHTML': 'HTML injection — HIGH risk',
        'document\\.write': 'Document write — HIGH risk',
        'document\\.writeln': 'Document writeln — HIGH risk',
        'eval\\s*\\(': 'Code execution — CRITICAL risk',
        'setTimeout\\s*\\(\\s*["\']': 'String-based setTimeout — HIGH risk',
        'setTimeout\\s*\\(\\s*[^,)]+\\+': 'Concatenated setTimeout — MEDIUM risk',
        'setInterval\\s*\\(\\s*["\']': 'String-based setInterval — HIGH risk',
        'Function\\s*\\(': 'Dynamic Function — CRITICAL risk',
        '\\.html\\s*\\(': 'jQuery .html() — HIGH risk',
        'insertAdjacentHTML': 'Adjacent HTML injection — HIGH risk',
        'createContextualFragment': 'Fragment injection — HIGH risk',
        'srcdoc\\s*=': 'iframe srcdoc — HIGH risk',
        'v-html': 'Vue v-html directive — HIGH risk',
        'dangerouslySetInnerHTML': 'React dangerous HTML — HIGH risk',
        '\\$sce\\.trustAsHtml': 'Angular trust HTML — HIGH risk',
        'bypassSecurityTrust': 'Angular security bypass — CRITICAL risk',
    }

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.findings: List[Dict] = []
        self._compiled_sources = {k: re.compile(k, re.IGNORECASE) for k in self.SOURCES}
        self._compiled_sinks = {k: re.compile(k, re.IGNORECASE) for k in self.SINKS}

    def analyze(self, js_content: str, source_url: str):
        """Analyze JS content for DOM XSS source → sink flows."""
        if not js_content or len(js_content) < 50:
            return

        found_sources = []
        found_sinks = []

        # Scan for sources
        for pattern, desc in self.SOURCES.items():
            regex = self._compiled_sources[pattern]
            matches = regex.finditer(js_content)
            for m in matches:
                # Get line number approximation
                line_no = js_content[:m.start()].count('\n') + 1
                found_sources.append({
                    'pattern': pattern.replace('\\s*', ' ').replace('\\(', '('),
                    'description': desc,
                    'line': line_no,
                    'context': js_content[max(0, m.start()-30):m.end()+30].strip(),
                })

        # Scan for sinks
        for pattern, desc in self.SINKS.items():
            regex = self._compiled_sinks[pattern]
            matches = regex.finditer(js_content)
            for m in matches:
                line_no = js_content[:m.start()].count('\n') + 1
                found_sinks.append({
                    'pattern': pattern.replace('\\s*', ' ').replace('\\(', '('),
                    'description': desc,
                    'line': line_no,
                    'context': js_content[max(0, m.start()-30):m.end()+30].strip(),
                })

        if found_sources and found_sinks:
            # Determine severity based on sink types
            has_critical = any('CRITICAL' in s['description'] for s in found_sinks)
            has_high = any('HIGH' in s['description'] for s in found_sinks)
            severity = 'CRITICAL' if has_critical else ('HIGH' if has_high else 'MEDIUM')

            finding = {
                'type': 'DOM XSS Vector',
                'severity': severity,
                'url': source_url,
                'sources': found_sources[:10],
                'sinks': found_sinks[:10],
                'source_count': len(found_sources),
                'sink_count': len(found_sinks),
                'detail': (f"{len(found_sources)} source(s) + {len(found_sinks)} sink(s) "
                           f"in {source_url.split('/')[-1][:40]}"),
            }
            self.findings.append(finding)

            if self.verbose:
                sc = Colors.FAIL if severity == 'CRITICAL' else Colors.WARNING
                print(f"{sc}  [DOM-XSS] [{severity}] {len(found_sources)} sources → "
                      f"{len(found_sinks)} sinks in {source_url.split('/')[-1][:50]}{Colors.ENDC}")
                for src in found_sources[:3]:
                    print(f"{Colors.DIM}    Source: {src['pattern']} (line ~{src['line']}){Colors.ENDC}")
                for snk in found_sinks[:3]:
                    print(f"{Colors.DIM}    Sink: {snk['pattern']} — {snk['description']}{Colors.ENDC}")

        elif found_sinks and not found_sources:
            # Sinks without visible sources — still worth noting
            if len(found_sinks) >= 3:
                self.findings.append({
                    'type': 'DOM XSS Sinks (no source mapped)',
                    'severity': 'LOW',
                    'url': source_url,
                    'sinks': found_sinks[:10],
                    'sink_count': len(found_sinks),
                    'detail': f"{len(found_sinks)} dangerous sink(s), sources may be in other files",
                })


# ═══════════════════════════════════════════════════════════════════
#  v6.0: Dependency Confusion Scanner
# ═══════════════════════════════════════════════════════════════════

class DependencyConfusionScanner:
    """
    From source maps, detect internal/scoped npm packages that
    may not exist on public registries → dependency confusion attack.
    """

    def __init__(self, session, rate_limiter, verbose=False):
        self.session = session
        self.rate_limiter = rate_limiter
        self.verbose = verbose
        self.findings: List[Dict] = []
        self._checked = set()

    def check_packages(self, packages: List[str], target_domain: str = ""):
        """Check if scoped/internal packages exist on public npm."""
        for pkg in packages:
            pkg = pkg.strip()
            if not pkg or pkg in self._checked:
                continue
            self._checked.add(pkg)

            # Only check scoped packages (@company/xxx) or unusual names
            is_scoped = pkg.startswith('@')
            is_internal_looking = any(kw in pkg.lower() for kw in [
                'internal', 'private', 'core', 'shared', 'common',
                'utils', 'helpers', 'config', 'auth', 'lib',
            ])

            # Also check if package name contains the target domain
            domain_parts = target_domain.replace('.com', '').replace('.my', '').replace('.io', '').split('.')
            has_domain = any(part in pkg.lower() for part in domain_parts if len(part) > 3)

            if not (is_scoped or is_internal_looking or has_domain):
                continue

            # Check npm registry
            try:
                self.rate_limiter.wait()
                npm_url = f"https://registry.npmjs.org/{pkg}"
                resp = self.session.get(npm_url, timeout=8)

                if resp and resp.status_code == 404:
                    # Package doesn't exist on public npm — potential confusion!
                    severity = "CRITICAL" if is_scoped else "HIGH"
                    finding = {
                        'type': 'Dependency Confusion',
                        'severity': severity,
                        'package': pkg,
                        'detail': (f"Package '{pkg}' used in source but NOT on public npm — "
                                   f"dependency confusion attack possible"),
                        'is_scoped': is_scoped,
                    }
                    self.findings.append(finding)
                    if self.verbose:
                        print(f"{Colors.FAIL}  [DEP-CONFUSION] [{severity}] '{pkg}' "
                              f"NOT on public npm!{Colors.ENDC}")

                elif resp and resp.status_code == 200:
                    # Exists — check if it might be a squatter
                    try:
                        data = resp.json()
                        latest = data.get('dist-tags', {}).get('latest', '')
                        created = data.get('time', {}).get('created', '')[:10]
                        weekly = data.get('downloads', 0) if 'downloads' in data else 'unknown'

                        # Suspicious if very low downloads or very recent
                        if has_domain and created:
                            self.findings.append({
                                'type': 'Dependency Confusion (potential squatter)',
                                'severity': 'MEDIUM',
                                'package': pkg,
                                'npm_version': latest,
                                'npm_created': created,
                                'detail': (f"Package '{pkg}' exists on npm (v{latest}, created {created}) — "
                                           f"verify this is the intended package"),
                            })
                    except Exception:
                        pass

            except Exception:
                continue

    def check_from_source_maps(self, source_map_intel: List[Dict], target_domain: str = ""):
        """Extract packages from source map data and check them."""
        all_packages = set()
        for sm in source_map_intel:
            if sm.get('npm_packages'):
                all_packages.update(sm['npm_packages'])

        if all_packages:
            if self.verbose:
                print(f"{Colors.OKCYAN}  [*] Checking {len(all_packages)} packages for "
                      f"dependency confusion...{Colors.ENDC}")
            self.check_packages(list(all_packages), target_domain)


# ═══════════════════════════════════════════════════════════════════
#  v6.0: JWT Deep Exploitation Tester
# ═══════════════════════════════════════════════════════════════════

class JWTExploitTester:
    """
    Extends JWTAnalyzer with active exploitation tests:
    - alg:none bypass
    - HS256 weak secret brute-force
    - RS256→HS256 algorithm confusion
    - Expired token acceptance
    """

    COMMON_SECRETS = [
        'secret', 'password', 'key', '123456', 'admin',
        'jwt_secret', 'changeme', 'default', 'test',
        'supersecret', 'mysecret', 'your-256-bit-secret',
        'shhhhh', 'keyboard cat', 'secretkey',
    ]

    def __init__(self, session, rate_limiter, verbose=False):
        self.session = session
        self.rate_limiter = rate_limiter
        self.verbose = verbose
        self.findings: List[Dict] = []

    def test_token(self, token: str, source_url: str):
        """Run all JWT exploitation tests."""
        analysis = JWTAnalyzer.analyze(token)
        if not analysis:
            return

        header = analysis['header']
        payload = analysis['payload']

        # ── Test 1: alg:none bypass ──
        self._test_alg_none(header, payload, token, source_url)

        # ── Test 2: Weak secret brute-force (HS256 only) ──
        alg = header.get('alg', '').upper()
        if alg.startswith('HS'):
            self._test_weak_secrets(token, alg, source_url)

        # ── Test 3: Expired token still accepted? ──
        if analysis['analysis'].get('expired'):
            self._test_expired_acceptance(token, source_url)

    def _test_alg_none(self, header: dict, payload: dict, original_token: str, source_url: str):
        """Forge token with alg:none and test if accepted."""
        for alg in ['none', 'None', 'NONE', 'nOnE']:
            forged_header = {**header, 'alg': alg}
            try:
                h_b64 = base64.urlsafe_b64encode(
                    json.dumps(forged_header, separators=(',', ':')).encode()
                ).rstrip(b'=').decode()
                p_b64 = base64.urlsafe_b64encode(
                    json.dumps(payload, separators=(',', ':')).encode()
                ).rstrip(b'=').decode()
                forged = f"{h_b64}.{p_b64}."

                self.findings.append({
                    'type': 'JWT alg:none Forge',
                    'severity': 'HIGH',
                    'source': source_url,
                    'original_alg': header.get('alg', '?'),
                    'forged_token': forged[:60] + '...',
                    'detail': f"Forged JWT with alg:{alg} — test against API endpoints for auth bypass",
                    'needs_manual_test': True,
                })
                if self.verbose:
                    print(f"{Colors.WARNING}  [JWT] [HIGH] alg:none token forged — "
                          f"needs manual testing against API{Colors.ENDC}")
                break  # One forge attempt is enough
            except Exception:
                continue

    def _test_weak_secrets(self, token: str, alg: str, source_url: str):
        """Try common secrets to sign the JWT."""
        import hmac as _hmac
        import hashlib as _hashlib

        parts = token.split('.')
        if len(parts) < 3:
            return

        signing_input = f"{parts[0]}.{parts[1]}".encode()
        original_sig = parts[2]

        hash_func = {
            'HS256': _hashlib.sha256,
            'HS384': _hashlib.sha384,
            'HS512': _hashlib.sha512,
        }.get(alg, _hashlib.sha256)

        for secret in self.COMMON_SECRETS:
            sig = base64.urlsafe_b64encode(
                _hmac.new(secret.encode(), signing_input, hash_func).digest()
            ).rstrip(b'=').decode()

            if sig == original_sig:
                self.findings.append({
                    'type': 'JWT Weak Secret',
                    'severity': 'CRITICAL',
                    'source': source_url,
                    'algorithm': alg,
                    'secret': secret,
                    'detail': f"JWT signed with weak secret '{secret}' — full token forgery possible",
                })
                if self.verbose:
                    print(f"{Colors.FAIL}  [JWT] [CRITICAL] Weak secret found: '{secret}'{Colors.ENDC}")
                return  # Found it

    def _test_expired_acceptance(self, token: str, source_url: str):
        """Note that an expired token was found — may still be accepted."""
        self.findings.append({
            'type': 'JWT Expired Token',
            'severity': 'MEDIUM',
            'source': source_url,
            'detail': "Expired JWT found in source — test if API still accepts it (session fixation)",
            'needs_manual_test': True,
        })
