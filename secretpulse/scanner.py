"""Core scan orchestration, detection pipeline, and unified finding assembly."""
from ._imports import *
from .constants import (CDN_WAF_PATH_PATTERNS, ENV_FILE_PATHS, GRAPHQL_PATHS, KNOWN_TEST_KEYS, PUBLIC_IDENTIFIER_TYPES, SENSITIVE_FILE_PROBES, UA_POOL, __author__, __version__)
from .utils import Colors, ProgressBar, RateLimiter, line_context, mask_secret, shannon_entropy
from .jwt import decode_jwt
from .verification import ActiveVerifierV2
from .analysis import AccuracyEngine, SecurityHeadersAuditor, SourceMapAnalyzer, SupplyChainMapper
from .discovery import (APIDiscoveryV2, BatchScanner, CVELookup, CloudNativeScanner, IDORFuzzer, InternalAPIEnumerator, PrivilegeEscalationSimulator, RateAbuseTester, SSRFProber, SubdomainTakeoverChecker, TeamNotifier, WaybackMiner)
from .exposure import CORSDetector, CloudPermissionTester, OpenRedirectDetector

class SecretScanner:
    def __init__(self, verbose=False, max_workers=5, crawl_depth=0,
                 no_validate=False, max_retries=3, ua_rotate=False,
                 probe_env=False, probe_graphql=False,
                 show_progress=True, verify_live=False,
                 rate_limit=0, scope_domains=None, custom_rules=None,
                 notify_url=None, baseline_path=None,
                 probe_swagger=False, scan_cloud=False,
                 wayback=False, subtko=False, ssrf_probe=False,
                 fuzz_idor=False, cors_check=False, open_redirect=False,
                 dep_confusion=False, jwt_exploit=False,
                 cloud_perms=False, request_timeout=15.0,
                 max_response_bytes=10 * 1024 * 1024,
                 custom_headers=None, cookies=None, proxy=None,
                 verify_providers=None, allow_webhook_checks=False):
        self.verbose = verbose
        self.max_workers = max_workers
        self.crawl_depth = crawl_depth
        self.no_validate = no_validate
        self.max_retries = max_retries
        self.request_timeout = max(1.0, float(request_timeout))
        self.max_response_bytes = max(64 * 1024, int(max_response_bytes))
        self.custom_headers = dict(custom_headers or {})
        self.custom_cookies = cookies or ''
        self.proxy = proxy or ''
        self.verify_providers = list(verify_providers or [])
        self.allow_webhook_checks = bool(allow_webhook_checks)
        self._session_local = threading.local()
        self.ua_rotate = ua_rotate
        self.probe_env = probe_env
        self.probe_graphql = probe_graphql
        self.probe_swagger = probe_swagger
        self.probe_sensitive = False
        self.scan_cloud = scan_cloud
        self.enable_wayback = wayback
        self.enable_subtko = subtko
        self.enable_ssrf = ssrf_probe
        self.enable_fuzz_idor = fuzz_idor
        self.enable_cors = cors_check
        self.enable_redirect = open_redirect
        self.enable_dep_confusion = dep_confusion
        self.enable_jwt_exploit = jwt_exploit
        self.enable_cloud_perms = cloud_perms
        self.verify_live = verify_live
        self.scope_domains = scope_domains or []
        self.baseline_path = baseline_path
        self.found_secrets: List[Dict] = []
        self.jwt_findings: List[Dict] = []
        self.dep_confusion_findings: List[Dict] = []
        self.smart_selected_modules: Set[str] = set()
        self.exit_findings: Optional[List[Dict]] = None
        self.local_files_scanned = 0
        self.git_commits_scanned = 0
        self.seen_secrets: Set[str] = set()
        self.gitleaks_allowlisted_values: Set[str] = set()
        self.scanned_urls: Set[str] = set()
        self.url_status: Dict[str, int] = {}
        self.blocked_urls: Set[str] = set()
        self.discovered_endpoints: List[Dict] = []
        self.discovered_internal_urls: List[Dict] = []
        self.graphql_endpoints: List[Dict] = []
        self.env_files_found: List[Dict] = []
        self.sensitive_files_found: List[Dict] = []
        self._sensitive_probed_origins: Set[str] = set()
        self.google_scope_results: List[Dict] = []
        self.source_map_intel: List[Dict] = []
        self.supply_chain = SupplyChainMapper()
        self.headers_auditor = SecurityHeadersAuditor()
        self.cloud_scanner = CloudNativeScanner() if scan_cloud else None
        self.fp_removed: List[Dict] = []
        self.progress = ProgressBar(enabled=show_progress and not verbose)
        self.rate_limiter = RateLimiter(rate_limit)
        self.accuracy_engine = AccuracyEngine()
        self.content_cache: Dict[str, str] = {}  # source_url -> content (for context analysis)

        self.stats = {
            'requests_made': 0, 'requests_failed': 0,
            'retries_used': 0, 'waf_blocked': 0,
            'source_maps_found': 0, 'chunks_discovered': 0,
            'env_files_found': 0, 'graphql_found': 0,
            'sensitive_files_found': 0,
            'endpoints_discovered': 0, 'internal_ips_found': 0,
            'private_keys_found': 0, 'buckets_found': 0,
            'secrets_verified_live': 0, 'db_strings_found': 0,
            'high_entropy_found': 0, 'passwords_found': 0,
            'sourcemap_files_found': 0, 'supply_chain_vulns': 0,
            'sri_missing': 0, 'jwt_critical': 0,
            'cloud_findings': 0, 'swagger_specs': 0,
            'header_issues': 0, 'fp_filtered': 0,
            'wayback_urls': 0, 'subtko_findings': 0,
            'ssrf_vectors': 0, 'idor_candidates': 0,
            'internal_routes': 0, 'attack_chains': 0,
            'cve_confirmed': 0, 'cve_potential': 0,
            'rate_abuse_unrestricted': 0, 'responses_truncated': 0,
            'scope_blocked': 0,
        }

        # Session
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries, backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=['GET', 'HEAD', 'POST'],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount('https://', adapter)
        self.session.mount('http://', adapter)
        self.session.headers.update({
            'User-Agent': UA_POOL[0],
            'Accept': 'text/html,application/xhtml+xml,application/xml;'
                      'q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        })
        if self.custom_headers:
            self.session.headers.update(self.custom_headers)
        if self.custom_cookies:
            self.session.headers['Cookie'] = self.custom_cookies
        if self.proxy:
            self.session.proxies.update({'http': self.proxy, 'https': self.proxy})
        self._retry_strategy = retry_strategy

        # Active verifier — v5.4: 66 read-only verification routes
        self.verifier = (ActiveVerifierV2(
            self.session,
            provider_allowlist=self.verify_providers,
            allow_webhooks=self.allow_webhook_checks,
        ) if verify_live else None)

        # v3.0: API Discovery, Notifier
        self.api_discovery = APIDiscoveryV2(self.session, self.rate_limiter, verbose)
        self.notifier = TeamNotifier(notify_url, self.session) if notify_url else None

        # v4.0: Offensive Recon modules
        self.wayback = WaybackMiner(self.session, self.rate_limiter, verbose)
        self.subtko = SubdomainTakeoverChecker(self.session, verbose)
        self.ssrf_prober = SSRFProber()
        self.idor_fuzzer = IDORFuzzer(self.session, self.rate_limiter, verbose)
        self.internal_api_enum = InternalAPIEnumerator()
        self.priv_esc = PrivilegeEscalationSimulator(self.session)
        self.attack_chains: List[Dict] = []

        # v5.0: New modules
        self.cve_lookup = CVELookup(self.session, verbose)
        self.rate_tester = RateAbuseTester(self.session, verbose) if verify_live else None
        self.batch_scanner = BatchScanner()

        # v6.0: Exposure detection modules (always declare, conditionally init)
        self.cors_detector = CORSDetector(self.session, self.rate_limiter, verbose) if cors_check else None
        self.redirect_detector = OpenRedirectDetector(self.session, self.rate_limiter, verbose) if open_redirect else None
        self.cloud_perm_tester = CloudPermissionTester(self.session, self.rate_limiter, verbose) if cloud_perms else None

        self.skip_libraries = [
            'jquery', 'bootstrap', 'angular.min', 'react.production',
            'vue.min', 'lodash', 'moment', 'axios', 'polyfill',
        ]

        self.patterns = self._build_patterns()

        # Output dedup tracking
        self._seen_source_maps = set()    # Don't print same map twice
        self._seen_scan_urls = set()      # Track scanned URLs for progress

        # v5.1.1: WAF adaptive intelligence (v5.1.2: oscillation fix)
        self._waf_hits_window = []        # Timestamps of recent WAF blocks
        self._waf_stealth_mode = False    # Whether stealth mode is active
        self._waf_original_workers = max_workers
        self._waf_original_rps = rate_limit
        self._waf_stealth_activated_at = 0  # Timestamp when stealth was last activated
        self._waf_cooldown_secs = 90        # Minimum seconds before recovery attempt
        self._waf_escalation = 0            # 0=normal, 1=stealth, 2=deep stealth
        self._waf_total_blocks = 0          # Lifetime WAF blocks for this scan
        self._waf_paused_probes = None      # Probe flags paused by stealth mode

        # Merge custom rules
        if custom_rules:
            self.patterns.update(custom_rules)

    # ─────────────────────────────────────────────────────────────
    #  HTTP helpers
    # ─────────────────────────────────────────────────────────────

    def _get_headers(self):
        h = {}
        if self.ua_rotate:
            h['User-Agent'] = random.choice(UA_POOL)
        return h

    def _get_thread_session(self):
        """requests.Session is not thread-safe; isolate target fetches per worker."""
        session = getattr(self._session_local, 'session', None)
        if session is None:
            session = requests.Session()
            adapter = HTTPAdapter(max_retries=self._retry_strategy)
            session.mount('https://', adapter)
            session.mount('http://', adapter)
            session.headers.update(self.session.headers)
            session.cookies.update(self.session.cookies)
            session.proxies.update(self.session.proxies)
            session.verify = self.session.verify
            session.auth = self.session.auth
            session.trust_env = self.session.trust_env
            self._session_local.session = session
        return session

    def _cap_response(self, resp):
        """Read at most max_response_bytes and keep the response usable."""
        if resp is None:
            return None
        chunks, total = [], 0
        try:
            for chunk in resp.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                remaining = self.max_response_bytes - total
                if remaining <= 0:
                    resp._secretpulse_truncated = True
                    break
                chunks.append(chunk[:remaining])
                total += min(len(chunk), remaining)
                if total >= self.max_response_bytes:
                    resp._secretpulse_truncated = True
                    break
        except Exception:
            resp._secretpulse_truncated = True
        finally:
            try:
                resp.close()
            except Exception:
                pass
        resp._content = b''.join(chunks)
        resp._content_consumed = True
        if getattr(resp, '_secretpulse_truncated', False):
            self.stats['responses_truncated'] = self.stats.get('responses_truncated', 0) + 1
        return resp

    def _adapt_to_waf(self):
        """Detect WAF pressure and switch to stealth mode with cooldown."""
        now = time.time()
        # Keep only WAF hits from the last 30 seconds
        self._waf_hits_window = [t for t in self._waf_hits_window if now - t < 30]
        waf_rate = len(self._waf_hits_window)
        self._waf_total_blocks += 1

        if waf_rate >= 8 and not self._waf_stealth_mode:
            # Enter stealth mode
            self._waf_stealth_mode = True
            self._waf_stealth_activated_at = now
            self._waf_escalation = 1
            self.max_workers = max(2, self._waf_original_workers // 4)
            if self.rate_limiter.rps > 0:
                self.rate_limiter.rps = max(1.0, self.rate_limiter.rps / 3)
            else:
                self.rate_limiter.rps = 2.0
            self._waf_paused_probes = {
                name: getattr(self, name, False) for name in
                ('probe_env', 'probe_graphql', 'probe_swagger',
                 'probe_sensitive', 'enable_subtko')
            }
            self.probe_env = False
            self.probe_graphql = False
            self.probe_swagger = False
            self.probe_sensitive = False
            self.enable_subtko = False
            print(f"\n{Colors.WARNING}  [SMART] WAF pressure detected ({waf_rate} blocks/30s) "
                  f"→ Stealth mode: {self.max_workers} workers, "
                  f"{self.rate_limiter.rps:.1f} req/s, noisy probes disabled{Colors.ENDC}")

        elif waf_rate >= 12 and self._waf_stealth_mode and self._waf_escalation < 2:
            # Escalate to deep stealth — WAF is still blocking even in stealth
            self._waf_escalation = 2
            self._waf_stealth_activated_at = now  # Reset cooldown
            self.max_workers = 1
            self.rate_limiter.rps = max(0.5, self.rate_limiter.rps / 2)
            print(f"\n{Colors.FAIL}  [SMART] WAF still blocking in stealth → Deep stealth: "
                  f"1 worker, {self.rate_limiter.rps:.1f} req/s{Colors.ENDC}")

        elif waf_rate <= 2 and self._waf_stealth_mode:
            # Check cooldown before recovering — prevent oscillation
            elapsed_stealth = now - self._waf_stealth_activated_at
            if elapsed_stealth < self._waf_cooldown_secs:
                return  # Too soon — stay in stealth

            # Restore probes paused on entry; WAF pressure has eased.
            if self._waf_paused_probes:
                for name, value in self._waf_paused_probes.items():
                    setattr(self, name, value)
                self._waf_paused_probes = None

            # Gradual recovery based on total WAF pressure seen
            self._waf_stealth_mode = False
            if self._waf_total_blocks > 50:
                # Heavy WAF target — recover conservatively
                self.max_workers = max(2, self._waf_original_workers // 3)
                if self._waf_original_rps > 0:
                    self.rate_limiter.rps = max(2.0, self._waf_original_rps * 0.5)
                else:
                    self.rate_limiter.rps = 3.0
                print(f"\n{Colors.OKCYAN}  [SMART] WAF pressure eased → Cautious recovery: "
                      f"{self.max_workers} workers, {self.rate_limiter.rps:.1f} req/s "
                      f"(heavy WAF target){Colors.ENDC}")
            else:
                # Light WAF — recover to 75%
                self.max_workers = max(self.max_workers, int(self._waf_original_workers * 0.75))
                if self._waf_original_rps > 0:
                    self.rate_limiter.rps = self._waf_original_rps
                else:
                    self.rate_limiter.rps = 0
                print(f"\n{Colors.OKCYAN}  [SMART] WAF pressure eased → Resuming: "
                      f"{self.max_workers} workers{Colors.ENDC}")
            self._waf_escalation = 0

    def _resilient_get(self, url, timeout=None, is_page=False):
        timeout = self.request_timeout if timeout is None else timeout
        if not self._is_in_scope(url):
            self.stats['scope_blocked'] += 1
            self.stats['requests_failed'] += 1
            return None
        self.rate_limiter.wait()
        self.stats['requests_made'] += 1

        # Skip URLs from domains already heavily blocked
        domain = urlparse(url).netloc
        blocked_count = sum(1 for bu in self.blocked_urls if domain in bu)
        if blocked_count >= 5:
            self.stats['requests_failed'] += 1
            return None

        # Reduce retries in stealth mode to avoid hammering WAF
        effective_retries = 1 if self._waf_stealth_mode else self.max_retries
        session = self._get_thread_session()

        for attempt in range(effective_retries + 1):
            try:
                headers = self._get_headers()
                if is_page:
                    headers.update({'Sec-Fetch-Dest': 'document', 'Sec-Fetch-Mode': 'navigate'})
                else:
                    headers.update({
                        'Sec-Fetch-Dest': 'script', 'Sec-Fetch-Mode': 'no-cors',
                        'Referer': url.rsplit('/', 1)[0] + '/',
                    })
                resp = None
                current = url
                for _ in range(6):
                    resp = session.get(
                        current, timeout=timeout, allow_redirects=False,
                        headers=headers, stream=True,
                    )
                    location = resp.headers.get('Location')
                    if resp.status_code in (301, 302, 303, 307, 308) and location:
                        next_url = urljoin(current, location)
                        resp.close()
                        if not self._is_in_scope(next_url):
                            self.stats['scope_blocked'] += 1
                            self.stats['requests_failed'] += 1
                            return None
                        current = next_url
                        continue
                    break
                if resp is None:
                    self.stats['requests_failed'] += 1
                    return None
                resp = self._cap_response(resp)
                if resp.status_code in (301, 302, 303, 307, 308):
                    self.stats['requests_failed'] += 1
                    return None
                if resp.status_code == 403:
                    self.stats['waf_blocked'] += 1
                    self.progress.increment('waf_blocked')
                    self._waf_hits_window.append(time.time())
                    self._adapt_to_waf()
                    if attempt < effective_retries:
                        self.stats['retries_used'] += 1
                        self.progress.increment('retries_used')
                        ua = random.choice(UA_POOL)
                        self.session.headers['User-Agent'] = ua
                        session.headers['User-Agent'] = ua
                        # Stealth: longer backoff with jitter
                        if self._waf_stealth_mode:
                            time.sleep((3 ** attempt) + random.uniform(2.0, 5.0))
                        else:
                            time.sleep((2 ** attempt) + random.uniform(0.5, 1.5))
                        continue
                    self.blocked_urls.add(url)
                    return None
                if 400 <= resp.status_code < 500 and resp.status_code != 429:
                    # Other 4xx are final decisions — retrying only creates a storm.
                    self.stats['requests_failed'] += 1
                    return resp
                resp.raise_for_status()
                return resp
            except requests.exceptions.RequestException:
                self.stats['requests_failed'] += 1
                if attempt < effective_retries:
                    self.stats['retries_used'] += 1
                    self.progress.increment('retries_used')
                    time.sleep((2 ** attempt) + random.uniform(0.3, 1.0))
                    continue
        return None

    def _is_cdn_waf_source(self, url):
        path = urlparse(url).path.lower()
        return any(pat in path for pat in CDN_WAF_PATH_PATTERNS)

    def _is_in_scope(self, url):
        """Check if URL is within authorized scope domains."""
        if not self.scope_domains:
            return True
        parsed = urlparse(url)
        host = (parsed.hostname or '').lower()
        return any(host == d or host.endswith('.' + d) for d in self.scope_domains)

    # ─────────────────────────────────────────────────────────────
    #  Pattern definitions
    # ─────────────────────────────────────────────────────────────

    def _build_patterns(self):
        return {
            # ── Analytics ───────────────────────────────────────────
            'Segment Write Key': {
                'patterns': [
                    r'segment["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{32})["\']',
                    r'SEGMENT_WRITE_KEY["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{32})["\']',
                    r'writeKey["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{32})["\']',
                ],
                'severity': 'MEDIUM', 'validate': self.validate_segment,
            },
            'Sentry DSN': {
                'patterns': [
                    r'https://([a-f0-9]{32})@([a-z0-9\-]+)\.ingest\.sentry\.io/([0-9]+)',
                ],
                'severity': 'MEDIUM', 'validate': self.validate_sentry,
            },
            'Split.io API Key': {
                'patterns': [r'split["\']?\s*[:\=]\s*["\']([a-z0-9]{30,45})["\']'],
                'severity': 'HIGH', 'validate': self.validate_split,
            },
            'Datadog RUM Token': {
                'patterns': [r'(pub[a-f0-9]{32})'],
                'severity': 'HIGH', 'validate': self.validate_datadog,
            },
            'Mixpanel Project Token': {
                'patterns': [
                    r'MIXPANEL_TOKEN["\']?\s*[:\=]\s*["\']([a-f0-9]{32})["\']',
                    r'mixpanel\.init\s*\(\s*["\']([a-f0-9]{32})["\']',
                ],
                'severity': 'MEDIUM', 'validate': self.validate_hex32,
                'context_required': True,
            },
            'Amplitude API Key': {
                'patterns': [
                    r'AMPLITUDE_API_KEY["\']?\s*[:\=]\s*["\']([a-f0-9]{32})["\']',
                    r'amplitude\.init\s*\(\s*["\']([a-f0-9]{32})["\']',
                ],
                'severity': 'MEDIUM', 'validate': self.validate_hex32,
            },
            'LogRocket App ID': {
                'patterns': [r'LogRocket\.init\s*\(\s*["\']([a-z0-9]+/[a-z0-9\-]+)["\']'],
                'severity': 'MEDIUM', 'validate': self.validate_logrocket,
            },
            'FullStory Org ID': {
                'patterns': [r'FULLSTORY_ORG_ID["\']?\s*[:\=]\s*["\']([A-Z0-9]{5,10})["\']'],
                'severity': 'MEDIUM', 'validate': None,
            },

            # ── Auth & Cloud ────────────────────────────────────────
            'Google API Key': {
                'patterns': [r'(AIza[0-9A-Za-z\-_]{35})'],
                'severity': 'HIGH', 'validate': self.validate_google_api,
                'case_sensitive': True,
            },
            'Firebase Config': {
                'patterns': [r'apiKey["\']?\s*:\s*["\'](AIza[0-9A-Za-z\-_]{35})["\']'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'AWS Access Key': {
                'patterns': [r'(AKIA[0-9A-Z]{16})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Auth0 Client ID': {
                'patterns': [r'AUTH0_CLIENT_ID["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{32})["\']'],
                'severity': 'LOW', 'validate': None,
            },
            'Recaptcha Site Key': {
                'patterns': [r'(6L[a-zA-Z0-9_-]{38})'],
                'severity': 'LOW', 'validate': None,
            },

            # ── Communication ───────────────────────────────────────
            'Slack Token': {
                'patterns': [r'(xox[baprs]-[0-9a-zA-Z]{10,48})'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'Slack Webhook': {
                'patterns': [
                    r'(https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24})',
                    r'(https://hooks\.slack\.com/triggers/[A-Za-z0-9/_\-]+)',
                ],
                'severity': 'HIGH', 'validate': self.validate_slack_webhook,
            },
            'Intercom Token': {
                'patterns': [
                    r'INTERCOM_ACCESS_TOKEN["\']?\s*[:\=]\s*["\']([A-Za-z0-9=_\-]{20,})["\']',
                ],
                'severity': 'HIGH', 'validate': self.validate_intercom,
            },
            'Intercom App ID': {
                'patterns': [
                    r'intercomSettings\s*=\s*\{[^}]*app_id\s*:\s*["\']([a-z0-9]{8})["\']',
                ],
                'severity': 'LOW', 'validate': None, 'preserve_severity': True,
            },
            'Zendesk Token': {
                'patterns': [
                    r'ZENDESK_API_TOKEN["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{40})["\']',
                    r'ZENDESK_TOKEN["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{40})["\']',
                ],
                'severity': 'HIGH', 'validate': self.validate_zendesk,
            },
            'HubSpot API Key': {
                'patterns': [
                    r'HUBSPOT_API_KEY["\']?\s*[:\=]\s*["\']([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']',
                    r'(pat-[a-z]{2}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
                ],
                'severity': 'HIGH', 'validate': self.validate_hubspot,
            },
            'HubSpot Portal ID': {
                'patterns': [r'//js\.hs-scripts\.com/([0-9]{6,9})\.js'],
                'severity': 'LOW', 'validate': None, 'preserve_severity': True,
            },

            # ── Dev Keys ────────────────────────────────────────────
            'Notion API Key': {
                'patterns': [r'(secret_[A-Za-z0-9]{43})', r'(ntn_[A-Za-z0-9]{44,})'],
                'severity': 'CRITICAL', 'validate': self.validate_notion,
                'case_sensitive': True,
            },
            'Linear API Key': {
                'patterns': [r'(lin_api_[A-Za-z0-9]{40,})'],
                'severity': 'CRITICAL', 'validate': self.validate_linear,
                'case_sensitive': True,
            },
            'GitHub Token': {
                'patterns': [
                    r'(ghp_[0-9a-zA-Z]{36})', r'(github_pat_[0-9a-zA-Z_]{82})',
                    r'(gho_[0-9a-zA-Z]{36})', r'(ghu_[0-9a-zA-Z]{36})',
                    r'(ghs_[0-9a-zA-Z]{36})',
                ],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Stripe API Key': {
                'patterns': [
                    r'(sk_live_[0-9a-zA-Z]{24,})', r'(rk_live_[0-9a-zA-Z]{24,})',
                ],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Stripe Publishable Key': {
                'patterns': [r'(pk_live_[0-9a-zA-Z]{24,})'],
                'severity': 'LOW', 'validate': None, 'case_sensitive': True,
                'preserve_severity': True,
            },

            # ── Email & Messaging ───────────────────────────────────
            'SendGrid API Key': {
                'patterns': [r'(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})'],
                'severity': 'CRITICAL', 'validate': self.validate_sendgrid,
                'case_sensitive': True,
            },
            'Twilio Credentials': {
                'patterns': [
                    r'(AC[a-f0-9]{32})', r'(SK[a-f0-9]{32})',
                    r'TWILIO_AUTH_TOKEN["\']?\s*[:\=]\s*["\']([a-f0-9]{32})["\']',
                    r'TWILIO_ACCOUNT_SID["\']?\s*[:\=]\s*["\'](AC[a-f0-9]{32})["\']',
                ],
                'severity': 'CRITICAL', 'validate': self.validate_twilio,
                'case_sensitive': True,
            },
            'Mailgun API Key': {
                'patterns': [r'(key-[0-9a-zA-Z]{32})'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },

            # ── Misc ────────────────────────────────────────────────
            'Mapbox Token': {
                'patterns': [r'(pk\.[a-zA-Z0-9_-]{60,})'],
                'severity': 'LOW', 'validate': None, 'preserve_severity': True,
            },
            'Mapbox Secret Token': {
                'patterns': [r'(sk\.[a-zA-Z0-9_-]{60,})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'JWT Token': {
                'patterns': [r'(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'Algolia API Key': {
                'patterns': [r'[0-9a-f]{32}'],
                'severity': 'MEDIUM', 'validate': None, 'context_required': True,
            },

            # ── Private Keys ────────────────────────────────────────
            'Private Key': {
                'patterns': [
                    r'(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)',
                    r'(-----BEGIN CERTIFICATE-----)',
                ],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },

            # ── Cloud Buckets ───────────────────────────────────────
            'AWS S3 Bucket': {
                'patterns': [
                    r'(https?://[a-z0-9][a-z0-9\.\-]{1,61}[a-z0-9]\.s3[a-z0-9\-]*\.amazonaws\.com)',
                    r'(https?://s3[a-z0-9\-]*\.amazonaws\.com/[a-z0-9][a-z0-9\.\-]{1,61}[a-z0-9])',
                    r'arn:aws:s3:::([a-z0-9][a-z0-9\.\-]{1,61}[a-z0-9])',
                ],
                'severity': 'HIGH', 'validate': None,
            },
            'GCS Bucket': {
                'patterns': [
                    r'(https?://storage\.googleapis\.com/[a-z0-9][a-z0-9\.\-_]{1,61}[a-z0-9])',
                    r'(gs://[a-z0-9][a-z0-9\.\-_]{1,61}[a-z0-9])',
                ],
                'severity': 'HIGH', 'validate': None,
            },
            'Azure Blob': {
                'patterns': [
                    r'(https?://[a-z0-9]{3,24}\.blob\.core\.windows\.net/[a-z0-9][a-z0-9\-]{1,62})',
                ],
                'severity': 'HIGH', 'validate': None,
            },

            # ── NEW v2.8: Password & DB Connection Strings ──────────
            'Database Connection String': {
                'patterns': [
                    r'((?:postgres|postgresql|mysql|mariadb|mssql)://[^\s"\'<>]{10,200})',
                    r'(mongodb(?:\+srv)?://[^\s"\'<>]{10,200})',
                    r'(redis://[^\s"\'<>]{10,200})',
                    r'(amqp://[^\s"\'<>]{10,200})',
                    r'DATABASE_URL["\']?\s*[:\=]\s*["\']((?:postgres|mysql|mongodb|redis|mariadb)[^\s"\'<>]{10,200})["\']',
                    r'DB_CONNECTION["\']?\s*[:\=]\s*["\']((?:postgres|mysql|mongodb|redis)[^\s"\'<>]{10,200})["\']',
                ],
                'severity': 'CRITICAL', 'validate': self.validate_db_string,
                'require_validation': True,
            },
            'Hardcoded Password': {
                'patterns': [
                    r'(?:password|passwd|pass|pwd)["\']?\s*[:\=]\s*["\']((?!\{\{)[^\s"\']{8,128})["\']',
                    r'(?:PASSWORD|PASSWD|DB_PASS|DB_PASSWORD|ADMIN_PASS|ROOT_PASS|USER_PASS)["\']?\s*[:\=]\s*["\']([^\s"\']{8,128})["\']',
                    r'(?:secret_?key|auth_?secret|api_?secret)["\']?\s*[:\=]\s*["\']([^\s"\']{12,128})["\']',
                    # Signing/session material is a credential even without "password".
                    r'(?:jwt|session|cookie|csrf|signing|encryption|hmac|app|oauth|refresh)'
                    r'[_\-]?(?:secret|signing[_\-]?key|secret[_\-]?key)'
                    r'["\']?\s*[:\=]\s*["\']([^\s"\']{16,128})["\']',
                ],
                'severity': 'HIGH', 'validate': self.validate_password,
                'require_validation': True,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: AI / ML Platform API Keys
            # ═══════════════════════════════════════════════════════
            'OpenAI API Key': {
                'patterns': [
                    r'(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})',
                    r'(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,})',
                ],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Anthropic API Key': {
                'patterns': [r'(sk-ant-[A-Za-z0-9\-_]{80,})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'HuggingFace Token': {
                'patterns': [r'(hf_[A-Za-z0-9]{34,})'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'Pinecone API Key': {
                'patterns': [r'PINECONE_API_KEY["\']?\s*[:\=]\s*["\']([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']'],
                'severity': 'HIGH', 'validate': None,
            },
            'Cohere API Key': {
                'patterns': [r'(co-[A-Za-z0-9]{40,})'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'Replicate API Token': {
                'patterns': [r'(r8_[A-Za-z0-9]{40,})'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: Cloud Providers (expanded)
            # ═══════════════════════════════════════════════════════
            'Cloudflare API Token': {
                'patterns': [r'CF_API_TOKEN["\']?\s*[:\=]\s*["\']([A-Za-z0-9_\-]{40})["\']',
                             r'(v1\.0-[a-f0-9]{24}-[a-f0-9]{64})'],
                'severity': 'CRITICAL', 'validate': None,
            },
            'Cloudflare Global API Key': {
                'patterns': [r'CF_API_KEY["\']?\s*[:\=]\s*["\']([a-f0-9]{37})["\']'],
                'severity': 'CRITICAL', 'validate': None,
            },
            'Vercel Token': {
                'patterns': [r'VERCEL_TOKEN["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{24})["\']',
                             r'(Bearer\s+[A-Za-z0-9]{24})'],
                'severity': 'HIGH', 'validate': None,
            },
            'Netlify Token': {
                'patterns': [r'NETLIFY_AUTH_TOKEN["\']?\s*[:\=]\s*["\']([A-Za-z0-9\-_]{40,})["\']'],
                'severity': 'HIGH', 'validate': None,
            },
            'DigitalOcean Token': {
                'patterns': [r'(dop_v1_[a-f0-9]{64})', r'DIGITALOCEAN_TOKEN["\']?\s*[:\=]\s*["\']([a-f0-9]{64})["\']'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Heroku API Key': {
                'patterns': [r'HEROKU_API_KEY["\']?\s*[:\=]\s*["\']([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']'],
                'severity': 'CRITICAL', 'validate': None,
            },
            'Supabase Key': {
                'patterns': [r'(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]{30,})',
                             r'SUPABASE_(?:ANON|SERVICE_ROLE)_KEY["\']?\s*[:\=]\s*["\']([A-Za-z0-9_\-\.]{100,})["\']'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'Terraform Cloud Token': {
                'patterns': [r'(atlasv1-[A-Za-z0-9\-_]{60,})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'HashiCorp Vault Token': {
                'patterns': [r'(hvs\.[A-Za-z0-9\-_]{24,})', r'VAULT_TOKEN["\']?\s*[:\=]\s*["\']([^\s"\']{10,})["\']'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: Payment / E-commerce
            # ═══════════════════════════════════════════════════════
            'PayPal Client Secret': {
                'patterns': [r'PAYPAL_(?:CLIENT_SECRET|SECRET)["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{30,})["\']'],
                'severity': 'CRITICAL', 'validate': None,
            },
            'Shopify API Key': {
                'patterns': [r'(shpat_[a-f0-9]{32})', r'(shpca_[a-f0-9]{32})',
                             r'(shppa_[a-f0-9]{32})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Square Access Token': {
                'patterns': [r'(sq0atp-[A-Za-z0-9\-_]{22})', r'(EAAA[A-Za-z0-9]{60})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: CI/CD & DevOps
            # ═══════════════════════════════════════════════════════
            'GitLab Token': {
                'patterns': [
                    r'(glpat-[A-Za-z0-9\-_]{20,})',
                    r'(glcbt-[0-9A-Za-z]{1,5}_[0-9A-Za-z_-]{20})',
                    r'(gldt-[0-9A-Za-z_-]{20})',
                    r'(glrt-[0-9A-Za-z_-]{20})',
                ],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Bitbucket App Password': {
                'patterns': [r'BITBUCKET_APP_PASSWORD["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{18,})["\']'],
                'severity': 'HIGH', 'validate': None,
            },
            'CircleCI Token': {
                'patterns': [r'CIRCLECI_TOKEN["\']?\s*[:\=]\s*["\']([a-f0-9]{40})["\']'],
                'severity': 'CRITICAL', 'validate': None,
            },
            'Travis CI Token': {
                'patterns': [r'TRAVIS_TOKEN["\']?\s*[:\=]\s*["\']([A-Za-z0-9\-_]{20,})["\']'],
                'severity': 'HIGH', 'validate': None,
            },
            'npm Token': {
                'patterns': [r'(npm_[A-Za-z0-9]{36})', r'//registry\.npmjs\.org/:_authToken=([A-Za-z0-9\-_]{36,})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'PyPI Token': {
                'patterns': [r'(pypi-[A-Za-z0-9\-_]{100,})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'NuGet API Key': {
                'patterns': [r'(oy2[A-Za-z0-9]{43})'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'Docker Hub Token': {
                'patterns': [r'DOCKER_(?:PASSWORD|TOKEN|HUB_TOKEN)["\']?\s*[:\=]\s*["\']([A-Za-z0-9\-_]{30,})["\']'],
                'severity': 'CRITICAL', 'validate': None,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: Monitoring / Analytics (expanded)
            # ═══════════════════════════════════════════════════════
            'New Relic API Key': {
                'patterns': [r'(NRAK-[A-Z0-9]{27})', r'NEW_RELIC_(?:LICENSE_KEY|API_KEY)["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{40})["\']'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'Grafana API Key': {
                'patterns': [r'(eyJrIjoi[A-Za-z0-9+/=]{30,})', r'(glsa_[A-Za-z0-9]{32}_[a-f0-9]{8})'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'Elastic API Key': {
                'patterns': [r'ELASTIC_(?:API_KEY|CLOUD_AUTH)["\']?\s*[:\=]\s*["\']([A-Za-z0-9_\-:]{20,})["\']'],
                'severity': 'HIGH', 'validate': None,
            },
            'PagerDuty API Key': {
                'patterns': [r'PAGERDUTY_(?:API_KEY|TOKEN)["\']?\s*[:\=]\s*["\']([A-Za-z0-9+_\-]{20})["\']'],
                'severity': 'HIGH', 'validate': None,
            },
            'PostHog API Key': {
                'patterns': [r'(phc_[A-Za-z0-9]{30,})', r'POSTHOG_API_KEY["\']?\s*[:\=]\s*["\']([A-Za-z0-9_\-]{30,})["\']'],
                'severity': 'MEDIUM', 'validate': None, 'case_sensitive': True,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: Identity / Auth (expanded)
            # ═══════════════════════════════════════════════════════
            'Okta API Token': {
                'patterns': [r'OKTA_(?:API_TOKEN|TOKEN)["\']?\s*[:\=]\s*["\']([A-Za-z0-9\-_]{42})["\']',
                             r'(?:okta|OKTA)["\']?\s*[:\=]\s*["\']?(00[A-Za-z0-9\-_]{40})["\']?'],
                'severity': 'CRITICAL', 'validate': None,
                'context_required': True,
            },
            'Firebase Auth': {
                'patterns': [r'FIREBASE_(?:AUTH_TOKEN|TOKEN|ADMIN_SDK)["\']?\s*[:\=]\s*["\']([A-Za-z0-9_\-\.]{50,})["\']'],
                'severity': 'CRITICAL', 'validate': None,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: Database
            # ═══════════════════════════════════════════════════════
            'PlanetScale Password': {
                'patterns': [r'(pscale_pw_[A-Za-z0-9\-_]{32,})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'CockroachDB Connection': {
                'patterns': [r'(cockroachdb://[^\s"\'<>]{10,200})', r'COCKROACH_URL["\']?\s*[:\=]\s*["\']([^\s"\'<>]{10,200})["\']'],
                'severity': 'CRITICAL', 'validate': None,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: Collaboration / Productivity
            # ═══════════════════════════════════════════════════════
            'Airtable API Key': {
                'patterns': [r'(key[A-Za-z0-9]{14})', r'(pat[A-Za-z0-9]{14,}\.[a-f0-9]{64})'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
                'context_required': True,
            },
            'Contentful Token': {
                'patterns': [r'CONTENTFUL_(?:ACCESS_TOKEN|DELIVERY_TOKEN|MANAGEMENT_TOKEN)["\']?\s*[:\=]\s*["\']([A-Za-z0-9\-_]{40,})["\']'],
                'severity': 'HIGH', 'validate': None,
            },
            'Discord Bot Token': {
                'patterns': [r'((?:MTA|MTE|MTI|OD|OT|Nj|Nz|ND|NT)[A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: Media / Social
            # ═══════════════════════════════════════════════════════
            'Twitch API Token': {
                'patterns': [r'TWITCH_(?:CLIENT_SECRET|API_TOKEN)["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{30})["\']'],
                'severity': 'HIGH', 'validate': None,
            },
            'Spotify Client Secret': {
                'patterns': [r'SPOTIFY_(?:CLIENT_SECRET|SECRET)["\']?\s*[:\=]\s*["\']([a-f0-9]{32})["\']'],
                'severity': 'HIGH', 'validate': None,
            },
            'Twitter API Key': {
                'patterns': [r'TWITTER_(?:API_KEY|API_SECRET|BEARER_TOKEN)["\']?\s*[:\=]\s*["\']([A-Za-z0-9\-_]{25,})["\']'],
                'severity': 'HIGH', 'validate': None,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: OAuth / Generic Tokens
            # ═══════════════════════════════════════════════════════
            'OAuth Access Token': {
                'patterns': [r'access_token["\']?\s*[:\=]\s*["\']([A-Za-z0-9\-_\.]{30,})["\']'],
                'severity': 'HIGH', 'validate': None, 'context_required': True,
            },
            'OAuth Refresh Token': {
                'patterns': [r'refresh_token["\']?\s*[:\=]\s*["\']([A-Za-z0-9\-_\.]{30,})["\']'],
                'severity': 'CRITICAL', 'validate': None, 'context_required': True,
            },
            'Generic Bearer Token': {
                'patterns': [r'Bearer\s+([A-Za-z0-9\-_\.]{40,200})'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
                'context_required': True,
            },

            # ═══════════════════════════════════════════════════════
            #  v5.4: 2026 AI / inference providers
            # ═══════════════════════════════════════════════════════
            'OpenRouter API Key': {
                'patterns': [r'\b(sk-or-v1-[a-f0-9]{64})\b'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Groq API Key': {
                'patterns': [r'\b(gsk_[A-Za-z0-9]{48})\b'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'xAI API Key': {
                'patterns': [r'\b(xai-[A-Za-z0-9]{80})\b'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Perplexity API Key': {
                'patterns': [r'\b(pplx-[A-Za-z0-9]{48})\b'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Mistral API Key': {
                'patterns': [
                    r'(?i)(?:MISTRAL_API_KEY|MISTRAL_KEY|mistral[_-]?api[_-]?key)'
                    r'["\']?\s*[:\=]\s*["\']?([A-Za-z0-9]{32})["\']?',
                ],
                'severity': 'HIGH', 'validate': None,
            },
            'DeepSeek API Key': {
                'patterns': [
                    r'(?i)(?:DEEPSEEK_API_KEY|deepseek[_-]?api[_-]?key)'
                    r'["\']?\s*[:\=]\s*["\']?(sk-[a-f0-9]{32})["\']?',
                ],
                'severity': 'CRITICAL', 'validate': None,
            },
            'Together API Key': {
                'patterns': [
                    r'(?i)(?:TOGETHER_API_KEY|TOGETHER_KEY|together[_-]?api[_-]?key)'
                    r'["\']?\s*[:\=]\s*["\']?([a-f0-9]{64})["\']?',
                ],
                'severity': 'CRITICAL', 'validate': None,
            },

            # ═══════════════════════════════════════════════════════
            #  v5.4: 2026 developer / data platforms
            # ═══════════════════════════════════════════════════════
            'Supabase Secret Key': {
                'patterns': [r'\b(sb_secret_[A-Za-z0-9_-]{20,})\b'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Resend API Key': {
                'patterns': [r'\b(re_[A-Za-z0-9]{24,})\b'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
                'context_required': True,
            },
            'Postman API Key': {
                'patterns': [r'\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Pulumi Access Token': {
                'patterns': [r'\b(pul-[a-f0-9]{40})\b'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Sentry User Token': {
                'patterns': [r'\b(sntryu_[a-f0-9]{64})\b'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'Sentry Org Token': {
                'patterns': [
                    r'\b(sntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}'
                    r'(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)'
                    r'[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43})',
                ],
                'severity': 'HIGH', 'validate': None,
            },
            'Datadog API Key': {
                'patterns': [
                    r'(?i)(?:DATADOG_API_KEY|DD_API_KEY|DD_APP_KEY)'
                    r'["\']?\s*[:\=]\s*["\']?([a-f0-9]{32})["\']?',
                ],
                'severity': 'HIGH', 'validate': None,
            },
            'Databricks API Token': {
                'patterns': [r'\b(dapi[a-f0-9]{32}(?:-\d)?)\b'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Doppler API Token': {
                'patterns': [r'\b(dp\.pt\.[A-Za-z0-9]{43})\b'],
                'severity': 'CRITICAL', 'validate': None,
            },
            'Fly.io Access Token': {
                'patterns': [r'\b(fo1_[\w-]{43})\b'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },

            # ═══════════════════════════════════════════════════════
            #  v5.4: CI/CD, collaboration, and webhooks
            # ═══════════════════════════════════════════════════════
            'Slack App Token': {
                'patterns': [r'\b(xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+)\b'],
                'severity': 'HIGH', 'validate': None,
            },
            'Telegram Bot Token': {
                'patterns': [
                    r'(?i)(?:TELEGRAM_BOT_TOKEN|BOT_TOKEN|telegram)'
                    r'["\']?\s*[:\=]\s*["\']?([0-9]{5,16}:[A-Za-z0-9_-]{34})["\']?',
                    r'\b([0-9]{8,10}:[A-Za-z0-9_-]{35})\b',
                ],
                'severity': 'HIGH', 'validate': None,
            },
            'Discord Webhook': {
                'patterns': [
                    r'(https://(?:discord|discordapp)\.com/api/webhooks/'
                    r'[0-9]{17,20}/[A-Za-z0-9_-]{60,})',
                ],
                'severity': 'HIGH', 'validate': None,
            },
            'Microsoft Teams Webhook': {
                'patterns': [
                    r'(https://[a-z0-9]+\.webhook\.office\.com/webhookb2/'
                    r'[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}@'
                    r'[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}/'
                    r'IncomingWebhook/[a-z0-9]{32}/'
                    r'[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12})',
                ],
                'severity': 'HIGH', 'validate': None,
            },
            'Atlassian API Token': {
                'patterns': [
                    r'\b(ATATT3[A-Za-z0-9_\-=]{186})\b',
                    r'(?i)(?:atlassian|confluence|jira)(?:[ \t\w.-]{0,20})'
                    r'[\s\'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60\'"\s=]{0,5}'
                    r'([a-z0-9]{20}[a-f0-9]{4})(?:[\x60\'"\s;]|\\[nr]|$)',
                ],
                'severity': 'CRITICAL', 'validate': None,
            },
            'Mailchimp API Key': {
                'patterns': [
                    r'\b([a-f0-9]{32}-us\d{1,2})\b',
                    r'(?i)(?:mailchimp|MAILCHIMP_API_KEY)(?:[ \t\w.-]{0,20})'
                    r'["\']?\s*[:\=]\s*["\']?([a-f0-9]{32}-us\d{1,2})["\']?',
                ],
                'severity': 'HIGH', 'validate': None,
            },

            # ═══════════════════════════════════════════════════════
            #  v5.4: infrastructure and long-lived credentials
            # ═══════════════════════════════════════════════════════
            '1Password Service Account Token': {
                'patterns': [r'\b(ops_eyJ[A-Za-z0-9+/]{250,}={0,3})'],
                'severity': 'CRITICAL', 'validate': None,
            },
            'Age Secret Key': {
                'patterns': [
                    r'\b(AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})\b',
                ],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'AWS Bedrock API Key': {
                'patterns': [r'\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'AWS Secret Access Key': {
                'patterns': [
                    r'(?i)(?:AWS_SECRET_ACCESS_KEY|AWS_SECRET_KEY|aws_secret_access_key)'
                    r'["\']?\s*[:\=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
                ],
                'severity': 'CRITICAL', 'validate': None,
            },
            'Google OAuth Client Secret': {
                'patterns': [r'\b(GOCSPX-[A-Za-z0-9_-]{28})\b'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'Azure AD Client Secret': {
                'patterns': [
                    r"""(?:^|[\\'"\x60\s>=:(,])"""
                    r"""([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})"""
                    r"""(?:$|[\\'"\x60\s<),])""",
                ],
                'severity': 'CRITICAL', 'validate': None,
            },
            'Azure Storage Account Key': {
                'patterns': [
                    r'(?i)AccountKey=([A-Za-z0-9+/=]{60,})',
                ],
                'severity': 'CRITICAL', 'validate': None,
            },
        }

    # ═════════════════════════════════════════════════════════════
    #  Validators
    # ═════════════════════════════════════════════════════════════

    def validate_segment(self, k): return len(k) == 32 and k.isalnum()
    def validate_hex32(self, k): return len(k) == 32 and all(c in '0123456789abcdef' for c in k)
    def validate_sentry(self, dsn):
        return bool(re.match(r'https://([a-f0-9]{32})@([a-z0-9\-]+)\.ingest\.sentry\.io/([0-9]+)', dsn))
    def validate_split(self, k): return 30 <= len(k) <= 45 and k.isalnum() and k.islower()
    def validate_datadog(self, t):
        return t.startswith('pub') and len(t[3:]) == 32 and all(c in '0123456789abcdef' for c in t[3:])
    def validate_google_api(self, k): return k.startswith('AIza') and len(k) == 39
    def validate_logrocket(self, a):
        parts = a.split('/'); return len(parts) == 2 and all(p.replace('-', '').isalnum() for p in parts)
    def validate_notion(self, k):
        if k.startswith('secret_'): return len(k) == 50 and k[7:].isalnum()
        if k.startswith('ntn_'): return len(k) >= 48 and k[4:].isalnum()
        return False
    def validate_intercom(self, t):
        if len(t) == 8 and t.islower() and t.isalnum(): return True
        return len(t) >= 20 and t.replace('=', '').replace('-', '').replace('_', '').isalnum()
    def validate_zendesk(self, t): return (len(t) == 40 and t.isalnum()) or len(t) >= 20
    def validate_hubspot(self, v):
        if v.startswith('pat-'): return bool(re.match(r'^pat-[a-z]{2}-[a-f0-9\-]+$', v))
        if re.match(r'^[a-f0-9]{8}-', v): return True
        return v.isdigit() and 6 <= len(v) <= 9
    def validate_linear(self, k): return k.startswith('lin_api_') and len(k) >= 48
    def validate_slack_webhook(self, u): return u.startswith('https://hooks.slack.com/')
    def validate_twilio(self, v):
        if v.startswith('AC') and len(v) == 34: return all(c in '0123456789abcdef' for c in v[2:])
        if v.startswith('SK') and len(v) == 34: return all(c in '0123456789abcdef' for c in v[2:])
        return len(v) == 32 and v.isalnum()
    def validate_sendgrid(self, k):
        return bool(re.match(r'^SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}$', k))

    def validate_db_string(self, val):
        """Validate DB connection string has user:pass@host pattern."""
        return bool(re.match(r'^\w+(?:\+\w+)?://\S+:\S+@\S+', val))

    def validate_password(self, val):
        """Filter out template/placeholder passwords."""
        skip = {'password', 'changeme', 'example', 'xxxxxxxx', '********',
                'your_password', 'YOUR_PASSWORD', 'undefined', 'null', 'true', 'false',
                'process.env', '${', '{{', 'env(', '<password>', '[password]'}
        vl = val.lower().strip()
        if any(s in vl for s in skip):
            return False
        if len(set(val)) <= 2:
            return False
        return len(val) >= 8

    # ═════════════════════════════════════════════════════════════
    #  Entropy-enhanced confidence scoring
    # ═════════════════════════════════════════════════════════════

    def _score_confidence(self, secret_type, value, context):
        ctx_lower = context.lower()
        type_keywords = {
            'Segment Write Key': ['segment', 'writekey'],
            'Sentry DSN': ['sentry', 'dsn'],
            'Split.io API Key': ['split'],
            'Datadog RUM Token': ['datadog', 'rum'],
            'Mixpanel Project Token': ['mixpanel'],
            'Amplitude API Key': ['amplitude'],
            'LogRocket App ID': ['logrocket'],
            'FullStory Org ID': ['fullstory'],
            'Google API Key': ['google', 'firebase', 'apikey'],
            'AWS Access Key': ['aws', 'akia'],
            'Slack Token': ['slack', 'xox'],
            'Slack Webhook': ['slack', 'webhook'],
            'Intercom Token': ['intercom'],
            'Intercom App ID': ['intercom'],
            'Zendesk Token': ['zendesk'],
            'HubSpot API Key': ['hubspot', 'hs-scripts'],
            'HubSpot Portal ID': ['hubspot', 'hs-scripts'],
            'Notion API Key': ['notion'],
            'Linear API Key': ['linear'],
            'GitHub Token': ['github'],
            'Stripe API Key': ['stripe'],
            'Stripe Publishable Key': ['stripe'],
            'SendGrid API Key': ['sendgrid'],
            'Twilio Credentials': ['twilio'],
            'Mailgun API Key': ['mailgun'],
            'Mapbox Token': ['mapbox'],
            'Mapbox Secret Token': ['mapbox'],
            'JWT Token': ['jwt', 'bearer', 'authorization', 'token'],
            'Algolia API Key': ['algolia'],
            'Recaptcha Site Key': ['recaptcha', 'captcha'],
            'Auth0 Client ID': ['auth0'],
            'Private Key': ['key', 'private', 'cert'],
            'AWS S3 Bucket': ['s3', 'aws', 'bucket'],
            'GCS Bucket': ['gcs', 'google', 'storage'],
            'Azure Blob': ['azure', 'blob'],
            'Database Connection String': ['database', 'db_', 'postgres', 'mysql', 'mongo', 'redis'],
            'Hardcoded Password': ['password', 'passwd', 'secret', 'auth'],
            'High-Entropy Secret': ['key', 'secret', 'token', 'auth'],
            'OpenRouter API Key': ['openrouter'],
            'Groq API Key': ['groq'],
            'xAI API Key': ['xai', 'grok'],
            'Perplexity API Key': ['perplexity', 'pplx'],
            'Mistral API Key': ['mistral'],
            'DeepSeek API Key': ['deepseek'],
            'Together API Key': ['together'],
            'Supabase Secret Key': ['supabase'],
            'Resend API Key': ['resend'],
            'Postman API Key': ['postman'],
            'Pulumi Access Token': ['pulumi'],
            'Sentry User Token': ['sentry'],
            'Sentry Org Token': ['sentry'],
            'Datadog API Key': ['datadog'],
            'Databricks API Token': ['databricks'],
            'Doppler API Token': ['doppler'],
            'Fly.io Access Token': ['fly'],
            'Slack App Token': ['slack', 'xapp'],
            'Telegram Bot Token': ['telegram', 'bot_token'],
            'Discord Webhook': ['discord', 'webhook'],
            'Microsoft Teams Webhook': ['teams', 'webhook'],
            'Atlassian API Token': ['atlassian', 'confluence', 'jira'],
            'Mailchimp API Key': ['mailchimp'],
            '1Password Service Account Token': ['1password', 'onepassword'],
            'AWS Bedrock API Key': ['bedrock', 'aws'],
            'AWS Secret Access Key': ['aws', 'secret_access_key'],
            'Google OAuth Client Secret': ['oauth', 'client_secret', 'google'],
            'Azure AD Client Secret': ['azure', 'client_secret'],
            'Azure Storage Account Key': ['azure', 'accountkey', 'storage'],
        }
        keywords = type_keywords.get(secret_type, [])
        keyword_match = any(kw in ctx_lower for kw in keywords)

        entropy = shannon_entropy(value)

        # Strong format-validated types — HIGH confidence regardless
        strong = {
            'AWS Access Key', 'GitHub Token', 'Stripe API Key',
            'SendGrid API Key', 'Notion API Key', 'Linear API Key',
            'Slack Webhook', 'Private Key', 'Database Connection String',
            'OpenRouter API Key', 'Groq API Key', 'xAI API Key',
            'Perplexity API Key', 'Postman API Key', 'Pulumi Access Token',
            'Sentry User Token', 'Databricks API Token', 'Doppler API Token',
            'Fly.io Access Token', '1Password Service Account Token',
            'Age Secret Key', 'AWS Bedrock API Key', 'AWS Secret Access Key',
            'Google OAuth Client Secret', 'Azure AD Client Secret',
            'Azure Storage Account Key', 'Supabase Secret Key',
            'Mapbox Secret Token',
        }
        if secret_type in strong:
            return 'HIGH'

        # Keyword match + good entropy = HIGH
        if keyword_match and entropy > 3.5:
            return 'HIGH'

        # Good entropy alone = MEDIUM
        if entropy > 4.0:
            return 'MEDIUM'

        # Keyword match but low entropy = still LOW (likely false positive)
        if keyword_match and entropy < 3.0:
            return 'LOW'

        # Env var assignment pattern
        env_match = re.search(
            r'(?:NEXT_PUBLIC_|REACT_APP_|VUE_APP_)?[A-Z_]{3,}(?:_KEY|_TOKEN|_SECRET|_DSN)',
            context
        )
        if env_match and entropy > 3.0:
            return 'MEDIUM'

        # Low entropy = LOW confidence (covers "Hardcoded Password entropy 2.5" case)
        if entropy < 3.0:
            return 'LOW'
        return 'LOW'

    # ═════════════════════════════════════════════════════════════
    #  Dedup
    # ═════════════════════════════════════════════════════════════

    def _is_submatch(self, new_type, new_value):
        for existing in self.found_secrets:
            if existing['type'] == new_type:
                continue
            if new_value in existing['value']:
                return True
        return False

    def should_skip_file(self, url):
        return any(lib in url.lower() for lib in self.skip_libraries)

    # ═════════════════════════════════════════════════════════════
    #  JS / asset extraction
    # ═════════════════════════════════════════════════════════════

    def extract_js_urls(self, html, base_url):
        js_urls = []
        for url in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            full = urljoin(base_url, url)
            if not self.should_skip_file(full):
                js_urls.append(full)
        return js_urls

    def extract_webpack_chunks(self, content, base_url):
        chunks = []
        for path in re.findall(r'["\']([a-zA-Z0-9/_\-]+\.chunk\.js)["\']', content):
            full = urljoin(base_url, path)
            if full not in chunks:
                chunks.append(full)
        for ref in re.findall(r'["\'](?:static/js/|_next/static/chunks/)([a-zA-Z0-9._\-]+\.js)["\']', content):
            p = urlparse(base_url)
            for pfx in ['static/js/', '_next/static/chunks/']:
                full = f"{p.scheme}://{p.netloc}/{pfx}{ref}"
                if full not in chunks:
                    chunks.append(full)
        return chunks

    def extract_same_domain_links(self, html, base_url):
        links = []
        pb = urlparse(base_url)
        for href in re.findall(r'<a[^>]+href=["\']([^"\'#]+)["\']', html, re.I):
            full = urljoin(base_url, href)
            p = urlparse(full)
            if p.netloc == pb.netloc:
                clean = f"{p.scheme}://{p.netloc}{p.path}"
                if clean not in self.scanned_urls and clean not in links:
                    if self._is_in_scope(clean):
                        links.append(clean)
            elif p.netloc and p.scheme in ('http', 'https'):
                # v5.1.1: Track external domains for scope warning
                if not hasattr(self, '_external_domains'):
                    self._external_domains = set()
                self._external_domains.add(p.netloc)
        return links

    # ═════════════════════════════════════════════════════════════
    #  __NEXT_DATA__ / window.__ENV__
    # ═════════════════════════════════════════════════════════════

    def extract_embedded_configs(self, html, source):
        targets = []
        nd = re.search(r'<script\s+id="__NEXT_DATA__"[^>]*>(.*?)</script>', html, re.DOTALL | re.I)
        if nd:
            targets.append(('__NEXT_DATA__', nd.group(1)))
        for var in ['__ENV__', '__CONFIG__', '__APP_CONFIG__', '__RUNTIME_CONFIG__', 'env']:
            m = re.search(r'window\.' + re.escape(var) + r'\s*=\s*(\{.+?\});', html, re.DOTALL)
            if m:
                targets.append((var, m.group(1)))
        for label, raw in targets:
            try:
                data = json.loads(raw)
                flat = self._flatten_json(data)
                synth = '\n'.join(f'{k} = "{v}"' for k, v in flat.items() if isinstance(v, str) and len(v) >= 8)
                if synth:
                    if self.verbose:
                        print(f"{Colors.OKCYAN}  [*] Scanning {label}{Colors.ENDC}")
                    self.scan_content(synth, f"{source} ({label})")
            except (json.JSONDecodeError, TypeError):
                self.scan_content(raw, f"{source} ({label})")

    @staticmethod
    def _flatten_json(obj, prefix=''):
        items = {}
        if isinstance(obj, dict):
            for k, v in obj.items():
                items.update(SecretScanner._flatten_json(v, f"{prefix}.{k}" if prefix else k))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                items.update(SecretScanner._flatten_json(v, f"{prefix}[{i}]"))
        else:
            items[prefix] = str(obj)
        return items

    # ═════════════════════════════════════════════════════════════
    #  HTTP Header Inspection
    # ═════════════════════════════════════════════════════════════

    HEADER_PATTERNS = [
        ('x-api-key', 'API Key in Header'),
        ('authorization', 'Auth Header Leak'),
        ('x-auth-token', 'Auth Token in Header'),
        ('x-access-token', 'Access Token in Header'),
        ('x-amz-security', 'AWS Security Token in Header'),
    ]

    def inspect_headers(self, response, source):
        for hdr_name, hdr_value in response.headers.items():
            hdr_lower = hdr_name.lower()
            for pat_name, label in self.HEADER_PATTERNS:
                if pat_name in hdr_lower:
                    val = hdr_value.strip()
                    if len(val) >= 8 and '<' not in val:
                        h = f"Header:{label}:{val}"
                        if h not in self.seen_secrets:
                            self.seen_secrets.add(h)
                            self.found_secrets.append({
                                'type': label, 'value': val,
                                'source': f"{source} (header: {hdr_name})",
                                'severity': 'HIGH', 'validated': False,
                                'confidence': 'HIGH', 'entropy': shannon_entropy(val),
                            })
                            print(f"{Colors.WARNING}[HIGH]{Colors.ENDC} "
                                  f"Found {label} in {source} header")

    # ═════════════════════════════════════════════════════════════
    #  Internal IP / URL leak detection
    # ═════════════════════════════════════════════════════════════

    INTERNAL_PATTERNS = [
        (r'(?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/\S*)?', 'RFC1918 (10.x)'),
        (r'(?:https?://)?(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/\S*)?', 'RFC1918 (172.16-31)'),
        (r'(?:https?://)?(?:192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/\S*)?', 'RFC1918 (192.168)'),
        (r'(?:https?://)?localhost(?::\d+)(?:/\S*)?', 'Localhost'),
        (r'(?:https?://)?127\.0\.0\.1(?::\d+)?(?:/\S*)?', 'Loopback'),
        (r'https?://[a-z0-9\-]+\.(?:internal|local|corp|lan|intranet)(?::\d+)?(?:/\S*)?', 'Internal hostname'),
    ]

    def scan_internal_urls(self, content, source):
        for pattern, label in self.INTERNAL_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                val = match.group(0)
                h = f"Internal:{val}"
                if h not in self.seen_secrets:
                    self.seen_secrets.add(h)
                    self.stats['internal_ips_found'] += 1
                    self.discovered_internal_urls.append({'type': label, 'value': val, 'source': source})
                    if self.verbose:
                        print(f"{Colors.OKCYAN}[INFO]{Colors.ENDC} Internal URL ({label}): {val}")

    # ═════════════════════════════════════════════════════════════
    #  API endpoint discovery
    # ═════════════════════════════════════════════════════════════

    API_ENDPOINT_PATTERNS = [
        r'fetch\s*\(\s*["\'](/api/[^"\']+)["\']',
        r'axios\.\w+\s*\(\s*["\'](/api/[^"\']+)["\']',
        r'\.get\s*\(\s*["\'](https?://[^"\']*api[^"\']*)["\']',
        r'\.post\s*\(\s*["\'](https?://[^"\']*api[^"\']*)["\']',
        r'["\'](/api/v\d+/[^"\']+)["\']',
        r'endpoint["\']?\s*[:\=]\s*["\'](https?://[^"\']+)["\']',
        r'baseURL["\']?\s*[:\=]\s*["\'](https?://[^"\']+)["\']',
    ]

    def scan_api_endpoints(self, content, source):
        for pattern in self.API_ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                ep = match.group(1)
                h = f"Endpoint:{ep}"
                if h not in self.seen_secrets:
                    self.seen_secrets.add(h)
                    self.stats['endpoints_discovered'] += 1
                    self.discovered_endpoints.append({'endpoint': ep, 'source': source})

    # ═════════════════════════════════════════════════════════════
    #  NEW v2.8: Generic high-entropy string detection
    # ═════════════════════════════════════════════════════════════

    HIGH_ENTROPY_KEYWORDS = [
        'key', 'secret', 'token', 'auth', 'password', 'passwd', 'credential',
        'api_key', 'apikey', 'access_key', 'private_key', 'client_secret',
        'app_secret', 'signing_key', 'encryption_key', 'bearer',
    ]

    def scan_high_entropy(self, content, source):
        """Catch unknown secrets: high-entropy strings near security keywords."""
        # Match KEY = "value" or KEY: "value" patterns
        pattern = re.compile(
            r'(?:' + '|'.join(self.HIGH_ENTROPY_KEYWORDS) + r')'
            r'["\']?\s*[:\=]\s*["\']([A-Za-z0-9\-_/+\.=]{20,128})["\']',
            re.IGNORECASE
        )

        for match in pattern.finditer(content):
            val = match.group(1)
            if val in self.gitleaks_allowlisted_values:
                continue
            h = f"HighEntropy:{val}"
            if h in self.seen_secrets:
                continue

            # Calculate entropy
            ent = shannon_entropy(val)
            if ent < 4.0:
                continue  # Not random enough

            # Skip if already matched by a known pattern
            known_hash = None
            for st in self.found_secrets:
                if val in st['value'] or st['value'] in val:
                    known_hash = True
                    break
            if known_hash:
                continue

            # Skip placeholders
            vl = val.lower()
            if any(s in vl for s in ['example', 'placeholder', 'xxxxx', 'your_',
                                      'changeme', 'undefined', 'null', 'process.env']):
                continue

            self.seen_secrets.add(h)
            self.stats['high_entropy_found'] += 1

            ctx_s = max(0, match.start() - 100)
            ctx_e = min(len(content), match.end() + 100)
            context = content[ctx_s:ctx_e]

            # Identify the keyword
            keyword = 'unknown'
            for kw in self.HIGH_ENTROPY_KEYWORDS:
                if kw in context.lower():
                    keyword = kw
                    break

            line_no, snippet = line_context(content, match.start(), match.end())
            finding = {
                'type': 'High-Entropy Secret',
                'value': val, 'source': source,
                'severity': 'MEDIUM', 'validated': False,
                'confidence': 'MEDIUM', 'entropy': ent,
                'keyword_hint': keyword, 'line': line_no, 'snippet': snippet,
            }
            self.found_secrets.append(finding)
            self.progress.increment('secrets_found')
            print(f"{Colors.OKCYAN}[MEDIUM secret candidate]{Colors.ENDC} "
                  f"[entropy:{ent}] High-entropy string near '{keyword}' "
                  f"at {source}:{line_no}")

    # ═════════════════════════════════════════════════════════════
    #  .env probing
    # ═════════════════════════════════════════════════════════════

    def probe_env_files(self, base_url):
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if self.verbose:
            print(f"{Colors.OKCYAN}  [*] Probing {len(ENV_FILE_PATHS)} env paths...{Colors.ENDC}")
        for path in ENV_FILE_PATHS:
            url = origin + path
            try:
                resp = self._resilient_get(url, timeout=8)
                if resp is None:
                    continue
                ct = resp.headers.get('Content-Type', '')
                if resp.status_code == 200 and 'html' not in ct.lower():
                    text = resp.text[:5000]
                    env_lines = re.findall(r'^[A-Z_]{2,}=.+', text, re.MULTILINE)
                    if len(env_lines) >= 2:
                        self.stats['env_files_found'] += 1
                        self.env_files_found.append({
                            'url': url, 'lines': len(env_lines),
                            'sample_keys': [l.split('=')[0] for l in env_lines[:5]],
                        })
                        print(f"{Colors.FAIL}[CRITICAL]{Colors.ENDC} "
                              f"[conf:HIGH] Exposed .env file: {url} ({len(env_lines)} vars)")
                        self.scan_content(text, f"{url} (.env)")
            except Exception:
                pass

    # ═════════════════════════════════════════════════════════════
    #  Sensitive file discovery
    # ═════════════════════════════════════════════════════════════

    def _sensitive_probe_get(self, url, limit=16384):
        """Fetch only a prefix of a sensitive path; avoids downloading dumps."""
        if not self._is_in_scope(url):
            self.stats['scope_blocked'] += 1
            return None, b''
        self.rate_limiter.wait()
        self.stats['requests_made'] += 1
        try:
            headers = self._get_headers()
            headers['Accept'] = '*/*'
            resp = self._get_thread_session().get(
                url, timeout=self.request_timeout, allow_redirects=False,
                stream=True, headers=headers,
            )
            if resp.status_code == 403:
                self.stats['waf_blocked'] += 1
                self.progress.increment('waf_blocked')
                self._waf_hits_window.append(time.time())
                self._adapt_to_waf()
                resp.close()
                return resp, b''
            chunks, total = [], 0
            for chunk in resp.iter_content(chunk_size=2048):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= limit:
                    break
            prefix = b''.join(chunks)
            resp.close()
            return resp, prefix
        except Exception:
            self.stats['requests_failed'] += 1
            return None, b''

    @staticmethod
    def _sensitive_matches(probe, prefix, content_type):
        ct = (content_type or '').lower()
        if probe.get('content_types') and not any(t in ct for t in probe['content_types']):
            return False
        if not probe.get('allow_html') and 'html' in ct:
            return False
        if probe.get('magic') and not prefix.startswith(probe['magic']):
            return False
        if probe.get('binary_marker') and probe['binary_marker'] not in prefix:
            return False
        text = prefix.decode('utf-8', 'ignore')
        markers = probe.get('markers') or ()
        if markers and not any(m.lower() in text.lower() for m in markers):
            return False
        regex = probe.get('regex')
        if regex and not re.search(regex, text, re.I):
            return False
        return True

    def probe_sensitive_files(self, base_url):
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin in self._sensitive_probed_origins:
            return
        self._sensitive_probed_origins.add(origin)
        if self.verbose:
            print(f"{Colors.OKCYAN}  [*] Probing {len(SENSITIVE_FILE_PROBES)} "
                  f"sensitive paths...{Colors.ENDC}")
        for probe in SENSITIVE_FILE_PROBES:
            url = origin + probe['path']
            resp, prefix = self._sensitive_probe_get(url)
            if resp is None or resp.status_code != 200 or not prefix:
                continue
            content_type = resp.headers.get('Content-Type', '')
            if not self._sensitive_matches(probe, prefix, content_type):
                continue
            text = prefix.decode('utf-8', 'ignore')
            record = {
                'url': url, 'path': probe['path'], 'type': probe['type'],
                'severity': probe['severity'], 'status_code': resp.status_code,
                'content_type': content_type.split(';')[0].strip(),
                'bytes_inspected': len(prefix),
            }
            self.stats['sensitive_files_found'] += 1
            self.sensitive_files_found.append(record)
            color = Colors.FAIL if probe['severity'] in ('CRITICAL', 'HIGH') else Colors.WARNING
            print(f"{color}[{probe['severity']}]{Colors.ENDC} [conf:HIGH] "
                  f"{probe['type']}: {url}")
            if probe.get('scan') and text:
                self.scan_content(text, f"{url} (sensitive file)")

    # ═════════════════════════════════════════════════════════════
    #  robots.txt / sitemap
    # ═════════════════════════════════════════════════════════════

    def parse_robots_sitemap(self, base_url):
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        extra = []
        try:
            resp = self._resilient_get(f"{origin}/robots.txt", timeout=8)
            if resp and resp.status_code == 200:
                for line in resp.text.splitlines():
                    m = re.match(r'^(?:Dis)?allow:\s*(\S+)', line, re.I)
                    if m:
                        path = m.group(1)
                        if path != '/' and '*' not in path:
                            full = origin + path
                            if full not in self.scanned_urls and self._is_in_scope(full):
                                extra.append(full)
                    m = re.match(r'^Sitemap:\s*(\S+)', line, re.I)
                    if m:
                        extra.extend(self._parse_sitemap(m.group(1)))
        except Exception:
            pass
        if not any('sitemap' in u.lower() for u in extra):
            extra.extend(self._parse_sitemap(f"{origin}/sitemap.xml"))
        return extra[:50]

    def _parse_sitemap(self, url):
        urls = []
        try:
            resp = self._resilient_get(url, timeout=8)
            if resp and resp.status_code == 200:
                urls = re.findall(r'<loc>\s*(.*?)\s*</loc>', resp.text, re.I)[:30]
        except Exception:
            pass
        return urls

    # ═════════════════════════════════════════════════════════════
    #  GraphQL introspection
    # ═════════════════════════════════════════════════════════════

    INTROSPECTION_QUERY = '{"query":"{ __schema { types { name } } }"}'

    def probe_graphql_endpoints(self, base_url):
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if self.verbose:
            print(f"{Colors.OKCYAN}  [*] Probing GraphQL endpoints...{Colors.ENDC}")
        for path in GRAPHQL_PATHS:
            url = origin + path
            try:
                headers = self._get_headers()
                headers['Content-Type'] = 'application/json'
                self.rate_limiter.wait()
                resp = self.session.post(url, data=self.INTROSPECTION_QUERY,
                                         headers=headers, timeout=8)
                self.stats['requests_made'] += 1
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if 'data' in data and '__schema' in (data.get('data') or {}):
                            types = data['data']['__schema'].get('types', [])
                            self.stats['graphql_found'] += 1
                            self.graphql_endpoints.append({'url': url, 'types_count': len(types)})
                            print(f"{Colors.FAIL}[CRITICAL]{Colors.ENDC} "
                                  f"[conf:HIGH] GraphQL introspection: {url}")
                    except (json.JSONDecodeError, TypeError):
                        pass
            except Exception:
                pass

    # ═════════════════════════════════════════════════════════════
    #  Core scanning
    # ═════════════════════════════════════════════════════════════

    @staticmethod
    def _gitleaks_allowlisted(config, value, content, source, match):
        allowlists = config.get('allowlists') or []
        if not allowlists:
            return False
        for allowlist in allowlists:
            regexes = allowlist.get('regexes') or []
            paths = allowlist.get('paths') or []
            stopwords = allowlist.get('stopwords') or []
            if not (regexes or paths or stopwords):
                continue

            target = value
            regex_target = str(allowlist.get('regexTarget', 'secret')).lower()
            if regex_target == 'match':
                target = match.group(0)
            elif regex_target == 'line':
                line_start = content.rfind('\n', 0, match.start()) + 1
                line_end = content.find('\n', match.end())
                target = content[line_start:line_end if line_end != -1 else len(content)]

            checks = []
            if regexes:
                checks.append(any(re.search(p, target, re.IGNORECASE) for p in regexes))
            if paths:
                checks.append(any(re.search(p, source, re.IGNORECASE) for p in paths))
            if stopwords:
                checks.append(any(w.lower() in value.lower() for w in stopwords))

            condition = str(allowlist.get('condition', 'OR')).upper()
            if (all(checks) if condition == 'AND' else any(checks)):
                return True
        return False

    def scan_content(self, content, source):
        if self._is_cdn_waf_source(source):
            return

        # ── AccuracyEngine: Cache content for context analysis ──
        self.content_cache[source] = content

        # ── AccuracyEngine: Pre-scan for encoded/obfuscated secrets [6][7] ──
        _, extra_findings = self.accuracy_engine.pre_scan_content(content, source)
        for ef in extra_findings:
            h = f"{ef['type']}:{ef['value']}"
            if h not in self.seen_secrets:
                self.seen_secrets.add(h)
                self.found_secrets.append(ef)
                self.progress.increment('secrets_found')
                sc = Colors.WARNING if ef['severity'] == 'HIGH' else Colors.OKCYAN
                print(f"{sc}[{ef['severity']} secret candidate]{Colors.ENDC}"
                      f" [encoded] {ef['type']} in {source}")

        for secret_type, config in self.patterns.items():
            flags = re.MULTILINE if config.get('case_sensitive') else re.IGNORECASE | re.MULTILINE
            for pattern in config['patterns']:
                for match in re.finditer(pattern, content, flags):
                    group_idx = config.get('secret_group')
                    if group_idx is not None:
                        try:
                            val = match.group(group_idx)
                        except (IndexError, re.error):
                            val = match.group(0)
                        if not val:
                            continue
                    elif match.lastindex:
                        if match.lastindex == 1:
                            val = match.group(1)
                        elif match.lastindex == 3 and 'sentry' in secret_type.lower():
                            val = f"https://{match.group(1)}@{match.group(2)}.ingest.sentry.io/{match.group(3)}"
                        else:
                            val = match.group(1) if match.lastindex >= 1 else match.group(0)
                    else:
                        val = match.group(0)

                    if val in KNOWN_TEST_KEYS:
                        continue
                    if config.get('keywords'):
                        window = content[max(0, match.start() - 200):match.end() + 200].lower()
                        if not any(k.lower() in window for k in config['keywords']):
                            continue
                    if self._gitleaks_allowlisted(config, val, content, source, match):
                        self.gitleaks_allowlisted_values.add(val)
                        continue
                    h = f"{secret_type}:{val}"
                    if h in self.seen_secrets:
                        continue
                    self.seen_secrets.add(h)

                    # v4.0: Per-source cap — max 3 findings of same type per URL
                    source_type_key = f"{secret_type}@{source}"
                    source_type_count = sum(1 for f in self.found_secrets
                                            if f['type'] == secret_type and f['source'] == source)
                    if source_type_count >= 3:
                        continue

                    if self._is_submatch(secret_type, val):
                        continue

                    ctx_s = max(0, match.start() - 200)
                    ctx_e = min(len(content), match.end() + 200)
                    context = content[ctx_s:ctx_e]

                    if config.get('context_required'):
                        kw_map = {
                            'Algolia API Key': ['algolia'],
                            'Mixpanel Project Token': ['mixpanel'],
                            'Amplitude API Key': ['amplitude'],
                            'Okta API Token': ['okta'],
                            'Airtable API Key': ['airtable'],
                            'OAuth Access Token': ['oauth', 'access_token', 'bearer', 'authorization'],
                            'OAuth Refresh Token': ['oauth', 'refresh_token', 'refresh'],
                            'Generic Bearer Token': ['bearer', 'authorization', 'auth'],
                        }
                        kws = kw_map.get(secret_type, [secret_type.split()[0].lower()])
                        if not any(k in context.lower() for k in kws):
                            continue

                    confidence = self._score_confidence(secret_type, val, context)
                    entropy = shannon_entropy(val)
                    public_meta = PUBLIC_IDENTIFIER_TYPES.get(secret_type)

                    line_no, snippet = line_context(
                        content, match.start(), match.end())

                    validated = False
                    if (not public_meta and config.get('validate')
                            and not self.no_validate):
                        try:
                            validated = config['validate'](val)
                        except Exception:
                            pass
                        # If validation is required and failed, skip
                        if config.get('require_validation') and not validated:
                            self.seen_secrets.discard(h)
                            continue

                    # JWT decode + security scoring (v2.9 enhanced)
                    jwt_info = None
                    if secret_type == 'JWT Token':
                        jwt_info = decode_jwt(val)
                        if jwt_info:
                            a = jwt_info.get('analysis', {})
                            vulns = a.get('vulnerabilities', [])
                            risk_grade = a.get('risk_grade', 'LOW')
                            if vulns or risk_grade in ('CRITICAL', 'HIGH'):
                                confidence = 'HIGH'
                                self.stats['jwt_critical'] += 1
                            if a.get('expired'):
                                confidence = 'MEDIUM' if confidence == 'HIGH' else confidence

                    finding = {
                        'type': secret_type, 'value': val,
                        'source': source, 'severity': config['severity'],
                        'validated': validated, 'confidence': confidence,
                        'entropy': entropy, 'line': line_no, 'snippet': snippet,
                    }
                    if config.get('preserve_severity'):
                        finding['severity_pinned'] = True
                    if public_meta:
                        finding['public_identifier'] = True
                        finding['public_identifier_reason'] = public_meta['reason']
                        finding['severity'] = 'LOW'
                        finding['severity_pinned'] = True
                    if jwt_info:
                        finding['jwt_decoded'] = jwt_info

                    # ── Active verification — v5.4 (66 read-only routes) ──
                    verify_public = bool(public_meta and not public_meta.get('skip_verification'))
                    if self.verifier and (not public_meta or verify_public):
                        vresult = self.verifier.verify(secret_type, val)
                        if vresult:
                            detail = str(vresult.get('detail', ''))
                            if val and val in detail:
                                detail = detail.replace(val, mask_secret(val))
                            finding['verified_live'] = vresult.get('live')
                            finding['verification_detail'] = detail
                            if vresult.get('live') is True:
                                self.stats['secrets_verified_live'] += 1
                                self.progress.increment('verified')
                                # Public identifiers stay LOW even when the key works.
                                if not public_meta and config['severity'] != 'CRITICAL':
                                    finding['severity'] = 'CRITICAL'
                                    finding['severity_escalated'] = True
                                if not public_meta:
                                    confidence = 'HIGH'
                                    finding['confidence'] = 'HIGH'
                                print(f"{Colors.FAIL}  ⚡ VERIFIED LIVE: "
                                      f"{detail}{Colors.ENDC}")

                                # Google API scope check
                                if secret_type in ('Google API Key', 'Firebase Config'):
                                    scope = self.verifier.verify_google_scope(val)
                                    finding['google_api_scopes'] = scope
                                    self.google_scope_results.append({
                                        'key': val[:12] + '...', 'scopes': scope,
                                    })
                                    active_apis = [k for k, v in scope.items() if 'ACTIVE' in v]
                                    if active_apis:
                                        print(f"{Colors.FAIL}  🔓 Unrestricted APIs: "
                                              f"{', '.join(active_apis)}{Colors.ENDC}")
                            elif vresult.get('live') is False:
                                if self.verbose:
                                    print(f"{Colors.DIM}  ✗ Not live: "
                                          f"{detail}{Colors.ENDC}")

                    # Source map escalation
                    if '.map' in source and confidence == 'MEDIUM':
                        confidence = 'HIGH'
                        finding['confidence'] = 'HIGH'
                        finding['escalation_reason'] = 'Found in source map (not intended to be public)'

                    self.found_secrets.append(finding)
                    self.progress.increment('secrets_found')

                    sc = {
                        'CRITICAL': Colors.FAIL, 'HIGH': Colors.WARNING,
                        'MEDIUM': Colors.OKCYAN, 'LOW': Colors.OKBLUE,
                    }.get(finding['severity'], Colors.ENDC)
                    kind = 'public identifier' if public_meta else 'secret candidate'
                    print(f"{sc}[{finding['severity']} {kind}]{Colors.ENDC}"
                          f" [conf:{confidence}] [entropy:{entropy}] "
                          f"{secret_type} at {source}:{line_no}")

        # Additional scans
        self.scan_internal_urls(content, source)
        self.scan_api_endpoints(content, source)
        self.scan_high_entropy(content, source)

    # ═════════════════════════════════════════════════════════════
    #  Source-map harvesting
    # ═════════════════════════════════════════════════════════════

    def scan_sourcemap_data(self, sm_data, map_url):
        """Analyze a parsed source map and scan every embedded source file.

        Returns the analyzer intel plus the number of source files scanned.
        Shared by live source-map harvesting and the offline benchmark so
        both exercise the same extraction path.
        """
        if not isinstance(sm_data, dict):
            raise ValueError('Source map must be a JSON object')
        intel = SourceMapAnalyzer.analyze(sm_data, map_url)
        self.source_map_intel.append(intel)
        self.stats['sourcemap_files_found'] += intel['total_files']

        if intel['npm_packages']:
            self.supply_chain.add_npm_packages(intel['npm_packages'])

        if self.verbose and intel['frameworks']:
            print(f"{Colors.OKCYAN}    Frameworks: "
                  f"{', '.join(intel['frameworks'])}{Colors.ENDC}")
        if self.verbose and intel['npm_packages']:
            print(f"{Colors.OKCYAN}    npm packages: "
                  f"{len(intel['npm_packages'])} found{Colors.ENDC}")

        for comment in intel.get('comments', []):
            if comment['type'] == 'Secret Comment':
                print(f"{Colors.WARNING}[HIGH]{Colors.ENDC} "
                      f"Secret comment in source map: "
                      f"{comment['file']} → {comment['text'][:60]}")

        sources = sm_data.get('sources', [])
        scanned = 0
        for i, src in enumerate(sm_data.get('sourcesContent', []) or []):
            if src and len(src) > 20:
                fname = sources[i] if i < len(sources) else 'unknown'
                self.scan_content(src, f"{map_url} → {fname}")
                scanned += 1
        return {'intel': intel, 'sources_scanned': scanned}

    def try_source_map(self, js_url, js_content):
        sm = re.search(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', js_content)
        if not sm:
            map_url = js_url + '.map'
        else:
            ref = sm.group(1)
            if ref.startswith('data:'):
                return
            map_url = urljoin(js_url, ref)
        if map_url in self._seen_source_maps:
            return  # Already processed this source map
        try:
            resp = self._resilient_get(map_url, timeout=8)
            if resp is None or resp.status_code != 200:
                return
            if len(resp.text) > 10_000_000:
                return
            self._seen_source_maps.add(map_url)
            self.stats['source_maps_found'] += 1
            if self.verbose:
                print(f"{Colors.OKCYAN}  [+] Source map: {map_url}{Colors.ENDC}")
            try:
                self.scan_sourcemap_data(resp.json(), map_url)
            except (json.JSONDecodeError, ValueError):
                self.scan_content(resp.text, f"{map_url} (raw)")
        except Exception:
            pass

    def _fetch_js(self, js_url):
        resp = self._resilient_get(js_url, timeout=10)
        if resp is None:
            return None
        self.progress.increment('js_scanned')
        return (js_url, resp.text)

    # ═════════════════════════════════════════════════════════════
    #  Local sources: filesystem + git history
    # ═════════════════════════════════════════════════════════════

    @staticmethod
    def _notebook_text(value):
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            return ''.join(
                part for part in value if isinstance(part, str))
        return ''

    def scan_notebook_data(self, notebook, source):
        """Scan Jupyter cell sources and text outputs with cell-aware sources."""
        if not isinstance(notebook, dict):
            raise ValueError('Notebook must be a JSON object')
        cells = notebook.get('cells')
        if not isinstance(cells, list):
            raise ValueError('Notebook must contain a cells array')

        texts_scanned = 0
        for cell_index, cell in enumerate(cells, 1):
            if not isinstance(cell, dict):
                continue
            cell_type = str(cell.get('cell_type', 'unknown'))
            cell_source = self._notebook_text(cell.get('source'))
            if cell_source.strip():
                self.scan_content(
                    cell_source, f"{source} [cell {cell_index} {cell_type}]")
                texts_scanned += 1

            outputs = cell.get('outputs')
            if not isinstance(outputs, list):
                continue
            for output_index, output in enumerate(outputs, 1):
                if not isinstance(output, dict):
                    continue
                parts = [self._notebook_text(output.get('text'))]
                data = output.get('data')
                if isinstance(data, dict):
                    for mime in ('text/plain', 'text/html', 'text/markdown',
                                 'application/json', 'application/javascript',
                                 'text/latex'):
                        parts.append(self._notebook_text(data.get(mime)))
                parts.extend(self._notebook_text(line)
                             for line in (output.get('traceback') or []))
                text = '\n'.join(part for part in parts if part)
                if text.strip():
                    self.scan_content(
                        text,
                        f"{source} [cell {cell_index} output {output_index}]")
                    texts_scanned += 1
        return {'cells_total': len(cells), 'texts_scanned': texts_scanned}

    @staticmethod
    def _read_notebook(raw_text):
        data = json.loads(raw_text)
        if not isinstance(data, dict):
            raise ValueError('Notebook must be a JSON object')
        return data

    def _scan_staged_blob(self, root, rel_path, data, max_file_bytes):
        if len(data) > max_file_bytes:
            return False
        if b'\x00' in data[:8192]:
            return False
        text = data.decode('utf-8', errors='replace')
        source = f"git-staged://{root}:{rel_path}"
        if rel_path.lower().endswith('.ipynb'):
            try:
                self.scan_notebook_data(self._read_notebook(text), source)
                return True
            except (json.JSONDecodeError, ValueError):
                pass
        self.scan_content(text, source)
        return True

    def scan_staged_changes(self, repo='.', max_file_bytes=2 * 1024 * 1024):
        """Scan the staged git index, not the working tree.

        Returns the number of staged files scanned, or -1 when the path is not
        a usable git work tree. Content is read from the index so pre-commit
        hooks and CI agree even when the working tree has newer edits.
        """
        root = Path(repo).expanduser()
        if not root.exists():
            print(f"{Colors.FAIL}[!] Repository path not found: {repo}{Colors.ENDC}")
            return -1
        try:
            top = subprocess.run(
                ['git', '-C', str(root), 'rev-parse', '--show-toplevel'],
                capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"{Colors.FAIL}[!] git executable not available: "
                  f"{exc}{Colors.ENDC}")
            return -1
        if top.returncode != 0:
            detail = top.stderr.strip()[:200] or 'not a git work tree'
            print(f"{Colors.FAIL}[!] Staged scan failed: {detail}{Colors.ENDC}")
            return -1
        repo_root = Path(top.stdout.strip())

        try:
            staged = subprocess.run(
                ['git', '-C', str(repo_root), 'diff', '--cached',
                 '--name-only', '-z', '--diff-filter=ACMR'],
                capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"{Colors.FAIL}[!] Could not list staged files: "
                  f"{exc}{Colors.ENDC}")
            return -1
        if staged.returncode != 0:
            detail = staged.stderr.strip()[:200]
            print(f"{Colors.FAIL}[!] Could not list staged files: "
                  f"{detail}{Colors.ENDC}")
            return -1

        paths = [item for item in staged.stdout.split('\0') if item]
        scanned = 0
        skipped = 0
        for rel_path in paths:
            try:
                size = subprocess.run(
                    ['git', '-C', str(repo_root), 'cat-file', '-s',
                     f':{rel_path}'],
                    capture_output=True, text=True, timeout=30)
                if size.returncode != 0:
                    skipped += 1
                    continue
                try:
                    blob_size = int(size.stdout.strip())
                except ValueError:
                    skipped += 1
                    continue
                if blob_size > max_file_bytes:
                    skipped += 1
                    continue
                blob = subprocess.run(
                    ['git', '-C', str(repo_root), 'show', f':{rel_path}'],
                    capture_output=True, timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                skipped += 1
                continue
            if blob.returncode != 0:
                skipped += 1
                continue
            if not self._scan_staged_blob(
                    repo_root, rel_path, blob.stdout, max_file_bytes):
                skipped += 1
                continue
            scanned += 1
            self.local_files_scanned += 1

        extra = f", {skipped} skipped" if skipped else ""
        print(f"[*] Staged changes: {scanned} files scanned{extra}")
        return scanned

    def scan_local_path(self, path, max_file_bytes=2 * 1024 * 1024):
        """Scan a local file or directory tree for secrets (no network)."""
        root = Path(path).expanduser()
        if not root.exists():
            print(f"{Colors.FAIL}[!] Path not found: {path}{Colors.ENDC}")
            return 0
        skip_dirs = {'.git', '.hg', '.svn', 'node_modules', 'vendor', 'dist',
                     'build', '.venv', 'venv', '__pycache__', '.tox',
                     '.mypy_cache', '.pytest_cache'}
        if root.is_file():
            files = [root]
        else:
            files = []
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in skip_dirs]
                for name in filenames:
                    files.append(Path(dirpath) / name)

        scanned = 0
        skipped = 0
        for f in files:
            try:
                if not f.is_file() or f.stat().st_size > max_file_bytes:
                    skipped += 1
                    continue
                data = f.read_bytes()
            except OSError:
                skipped += 1
                continue
            if b'\x00' in data[:8192]:
                skipped += 1
                continue
            text = data.decode('utf-8', errors='replace')
            source = f"file://{f.resolve()}"
            if f.suffix.lower() == '.ipynb':
                try:
                    self.scan_notebook_data(self._read_notebook(text), source)
                    scanned += 1
                    self.local_files_scanned += 1
                    continue
                except (json.JSONDecodeError, ValueError):
                    pass
            self.scan_content(text, source)
            scanned += 1
            self.local_files_scanned += 1

        extra = f", {skipped} skipped" if skipped else ""
        print(f"[*] Local path: {scanned} files scanned{extra}")
        return scanned

    def scan_git_history(self, repo, max_commits=500):
        """Scan added lines across a local git repository's history."""
        root = Path(repo).expanduser()
        if not root.exists():
            print(f"{Colors.FAIL}[!] Repository path not found: {repo}{Colors.ENDC}")
            return 0
        cmd = ['git', '-C', str(root), 'log', '--all', '--no-color',
               '--no-ext-diff', '--unified=0', '--format=commit %H', '-p']
        if max_commits and max_commits > 0:
            cmd += ['--max-count', str(max_commits)]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True,
                                    errors='replace')
        except OSError:
            print(f"{Colors.FAIL}[!] git executable not available{Colors.ENDC}")
            return 0

        commits = 0
        current_sha = None
        current_file = None
        added: List[str] = []

        def flush():
            if added and current_file and current_sha:
                self.scan_content(
                    '\n'.join(added),
                    f"git://{root.resolve()}@{current_sha[:12]}:{current_file}",
                )
            added.clear()

        try:
            for line in proc.stdout:
                if line.startswith('commit '):
                    flush()
                    current_sha = line.split(None, 1)[1].strip()
                    commits += 1
                    current_file = None
                elif line.startswith('+++ '):
                    flush()
                    target = line[4:].strip()
                    if target == '/dev/null':
                        current_file = None
                    elif target.startswith('b/'):
                        current_file = target[2:]
                    else:
                        current_file = target
                elif line.startswith('+') and current_file is not None:
                    added.append(line[1:])
                elif line.startswith('@@') or line.startswith('diff --git'):
                    flush()
            flush()
        finally:
            proc.stdout.close()
            err = proc.stderr.read()
            proc.stderr.close()
            proc.wait()

        if proc.returncode != 0:
            print(f"{Colors.FAIL}[!] Git history scan failed: "
                  f"{err.strip()[:200]}{Colors.ENDC}")
            return 0
        self.git_commits_scanned = commits
        print(f"[*] Git history: {commits} commits scanned")
        return commits

    # ═════════════════════════════════════════════════════════════
    #  Scan URL
    # ═════════════════════════════════════════════════════════════

    def scan_url(self, url, depth=0):
        if url in self.scanned_urls:
            return
        if not self._is_in_scope(url):
            if self.verbose:
                print(f"{Colors.DIM}  [~] Out of scope: {url}{Colors.ENDC}")
            return
        self.scanned_urls.add(url)
        is_archive_url = 'web.archive.org' in url or 'archive.org' in url

        # v5.5: check CNAME takeover before fetching, so dead hosts still count
        if depth == 0 and self.enable_subtko and not is_archive_url:
            hostname = urlparse(url).hostname
            if hostname:
                self.subtko.check_cname(hostname)

        try:
            if self.verbose:
                print(f"{Colors.OKBLUE}{'  '*depth}[*] Scanning: {url}{Colors.ENDC}")

            response = self._resilient_get(url, timeout=12, is_page=True)
            if response is None:
                print(f"{Colors.FAIL}[!] Could not fetch {url}{Colors.ENDC}")
                return

            self.url_status[url] = response.status_code
            html_content = response.text
            self.inspect_headers(response, url)

            # v3.0: Security headers audit
            if depth == 0:
                self.headers_auditor.audit(dict(response.headers), url)

            # v2.9: Supply chain analysis
            self.supply_chain.analyze_script_tags(html_content, url)

            for script in re.findall(r'<script[^>]*>(.*?)</script>', html_content, re.DOTALL | re.I):
                if len(script.strip()) > 10:
                    self.scan_content(script, f"{url} (inline)")

            self.extract_embedded_configs(html_content, url)
            self.scan_content(html_content, url)

            # v3.0: Cloud native scanning
            if self.cloud_scanner:
                self.cloud_scanner.scan(html_content, url)

            # v5.2: Exposure modules were previously constructed but never run.
            if depth == 0 and not is_archive_url:
                if self.enable_cors and getattr(self, 'cors_detector', None):
                    self.cors_detector.test_url(url, urlparse(url).netloc)
                if self.enable_redirect and getattr(self, 'redirect_detector', None):
                    self.redirect_detector.scan_url(url)

            if depth == 0 and not is_archive_url:
                self.parse_robots_sitemap(url)
            if depth == 0 and self.probe_env and not is_archive_url:
                self.probe_env_files(url)
            if depth == 0 and self.probe_sensitive and not is_archive_url:
                self.probe_sensitive_files(url)
            if depth == 0 and self.probe_graphql and not is_archive_url:
                self.probe_graphql_endpoints(url)
            # v3.0: Swagger/OpenAPI probing
            if depth == 0 and self.probe_swagger and not is_archive_url:
                self.api_discovery.probe_swagger(url, self._resilient_get)
            # v3.0: Enhanced GraphQL schema extraction
            if depth == 0 and self.probe_graphql and not is_archive_url:
                self.api_discovery.probe_graphql_schema(url, self._resilient_get)

            js_urls = self.extract_js_urls(html_content, url)
            if self.verbose:
                print(f"{Colors.OKBLUE}  [*] {len(js_urls)} external JS files{Colors.ENDC}")

            all_chunks = []
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                futures = {pool.submit(self._fetch_js, u): u for u in js_urls}
                for future in as_completed(futures):
                    result = future.result()
                    if result is None:
                        continue
                    js_url, js_text = result
                    self.scan_content(js_text, js_url)
                    self.try_source_map(js_url, js_text)
                    self.supply_chain.analyze_js_content(js_text, js_url)
                    self.api_discovery.scan_grpc(js_text, js_url)
                    if self.cloud_scanner:
                        self.cloud_scanner.scan(js_text, js_url)
                    # v4.0: Offensive recon on JS
                    if self.enable_ssrf:
                        self.ssrf_prober.scan_for_ssrf(js_text, js_url)
                        self.ssrf_prober.check_metadata_leaks(js_text, js_url)
                    self.internal_api_enum.extract_routes(js_text, js_url)
                    if self.enable_fuzz_idor:
                        self.idor_fuzzer.find_candidates(js_text, js_url)
                    all_chunks.extend(self.extract_webpack_chunks(js_text, js_url))

            unique_chunks = list(set(all_chunks) - set(js_urls) - self.scanned_urls)
            if unique_chunks:
                self.stats['chunks_discovered'] += len(unique_chunks)
                for cu in unique_chunks[:30]:
                    r = self._fetch_js(cu)
                    if r:
                        self.scan_content(r[1], cu)
                        self.try_source_map(cu, r[1])

            if depth < self.crawl_depth:
                # v5.1.1: Early exit — detect low-value targets
                if self._should_reduce_crawl(url, html_content):
                    if self.verbose:
                        print(f"{Colors.WARNING}  [SMART] Low-value content detected — "
                              f"crawl depth reduced for {url}{Colors.ENDC}")
                else:
                    children = self.extract_same_domain_links(html_content, url)
                    for link in children[:20]:
                        self.scan_url(link, depth + 1)

            self.progress.update(urls_done=len(self.scanned_urls))

        except Exception as e:
            print(f"{Colors.FAIL}[!] Error scanning {url}: {e}{Colors.ENDC}")

    # ═════════════════════════════════════════════════════════════
    #  v5.1.1: Exploit Path Suggestion Engine + Exploitability Probability
    # ═════════════════════════════════════════════════════════════

    # Maps finding types to exploit suggestions and base probability
    EXPLOIT_PLAYBOOK = {
        'Google Maps API Key': {
            'prob': 40, 'steps': [
                'Check billing status via Places/Geocoding API calls',
                'Test DirectionsAPI for route enumeration',
                'Check if key has admin/owner scope restrictions',
            ]
        },
        'AWS Access Key': {
            'prob': 75, 'steps': [
                'Run: aws sts get-caller-identity --access-key-id <key>',
                'Enumerate IAM permissions with enumerate-iam.py',
                'Check S3 bucket access and EC2 describe-instances',
                'Look for privilege escalation paths (iam:PassRole)',
            ]
        },
        'Stripe Secret Key': {
            'prob': 85, 'steps': [
                'List customers: curl -u sk_live_xxx: https://api.stripe.com/v1/customers',
                'Check payment intents and charges',
                'Verify scope (restricted vs full)',
            ]
        },
        'GitHub Token': {
            'prob': 70, 'steps': [
                'Check token scopes: curl -H "Authorization: token xxx" https://api.github.com',
                'List private repos and org memberships',
                'Check for write access to repos (code injection risk)',
            ]
        },
        'Database URI': {
            'prob': 65, 'steps': [
                'Test connectivity from external network',
                'Check for default credentials or weak passwords',
                'Enumerate databases, tables, and user privileges',
            ]
        },
        'Private Key': {
            'prob': 60, 'steps': [
                'Identify key type (RSA, EC, Ed25519) and purpose (SSH, TLS, signing)',
                'Check for associated certificate or known_hosts',
                'Test authentication against discovered endpoints',
            ]
        },
        'JSON Web Token': {
            'prob': 55, 'steps': [
                'Test alg:none bypass (remove signature, set alg to none)',
                'Brute-force HMAC secret with jwt-cracker or hashcat',
                'Check for expired token reuse (session fixation)',
                'Modify claims (role/admin escalation)',
            ]
        },
        'Slack Token': {
            'prob': 65, 'steps': [
                'Test: curl -H "Authorization: Bearer xoxb-xxx" https://slack.com/api/auth.test',
                'List channels and message history',
                'Check for file access and admin permissions',
            ]
        },
        'Firebase Config': {
            'prob': 50, 'steps': [
                'Test Firestore rules: curl https://<project>.firebaseio.com/.json',
                'Check Firebase Auth user enumeration',
                'Test Cloud Functions for unauthenticated access',
            ]
        },
        'OpenAI API Key': {
            'prob': 60, 'steps': [
                'Check billing and usage: curl with Authorization header',
                'Test model access (GPT-4, DALL-E)',
                'Estimate financial exposure from rate limits',
            ]
        },
    }

    # Generic patterns for types not in the playbook
    GENERIC_EXPLOIT_PATTERNS = {
        'api': {'prob': 50, 'steps': ['Test API key scopes and permissions', 'Check rate limits and billing', 'Enumerate accessible endpoints']},
        'token': {'prob': 55, 'steps': ['Verify token validity and expiration', 'Test scope of access', 'Check for refresh token flow']},
        'password': {'prob': 60, 'steps': ['Test credential against login endpoints', 'Check for password reuse across services', 'Verify account access level']},
        'key': {'prob': 45, 'steps': ['Identify the service this key belongs to', 'Test key against known API endpoints', 'Check for rate limiting or billing']},
        'secret': {'prob': 55, 'steps': ['Identify the associated service', 'Test secret against auth endpoints', 'Check scope and permissions']},
        'bucket': {'prob': 65, 'steps': ['Test public read: aws s3 ls s3://<bucket>', 'Review bucket policy/ACL for public write (read-only)', 'Check for sensitive files (backups, configs)']},
    }

    def _get_exploit_suggestions(self, finding):
        """Generate exploit path suggestions and exploitability probability for a finding."""
        ftype = finding.get('type', '')
        sev = finding.get('severity', 'LOW')
        verified = finding.get('verified_live', False)
        confidence = finding.get('confidence_score', 50)

        # Check exact match in playbook
        result = None
        for key, playbook in self.EXPLOIT_PLAYBOOK.items():
            if key.lower() in ftype.lower():
                result = {'probability': playbook['prob'], 'next_steps': list(playbook['steps'])}
                break

        # Fall back to generic pattern matching
        if not result:
            ftype_lower = ftype.lower()
            for pattern, generic in self.GENERIC_EXPLOIT_PATTERNS.items():
                if pattern in ftype_lower:
                    result = {'probability': generic['prob'], 'next_steps': list(generic['steps'])}
                    break

        if not result:
            result = {'probability': 20, 'next_steps': ['Investigate the context and identify the associated service']}

        # Modifiers: adjust probability based on finding properties
        if verified is True:
            result['probability'] = min(99, result['probability'] + 25)
            result['next_steps'].insert(0, 'KEY IS LIVE — immediate exploitation possible')
        elif verified is False:
            result['probability'] = max(5, result['probability'] - 20)

        if confidence >= 85:
            result['probability'] = min(99, result['probability'] + 10)
        elif confidence < 40:
            result['probability'] = max(5, result['probability'] - 15)

        if sev == 'CRITICAL':
            result['probability'] = min(99, result['probability'] + 10)
        elif sev in ('LOW', 'INFO'):
            result['probability'] = max(5, result['probability'] - 10)

        # Context-specific boosts
        source = finding.get('source', '')
        if '.env' in source or 'config' in source.lower():
            result['probability'] = min(99, result['probability'] + 5)
        if 'staging' in source or 'dev' in source or 'test' in source:
            result['probability'] = min(99, result['probability'] + 5)

        return result

    # ═════════════════════════════════════════════════════════════
    #  v5.1.1: Early Exit Intelligence
    # ═════════════════════════════════════════════════════════════

    def _should_reduce_crawl(self, url, html_content):
        """Detect low-value targets and recommend reducing crawl depth.
        Returns True if this target is likely static/marketing content."""
        # Only evaluate after scanning enough pages
        if len(self.scanned_urls) < 8:
            return False

        # Check: no secrets found so far AND mostly static content
        if self.found_secrets:
            return False  # We're finding things, keep going

        # Indicators of low-value (static/marketing) content
        low_value_signals = 0
        content_lower = html_content.lower()

        # Marketing page indicators
        marketing_patterns = ['request a demo', 'get started', 'pricing',
                              'contact us', 'sign up free', 'schedule a call',
                              'trusted by', 'customer stories', 'read more']
        marketing_hits = sum(1 for p in marketing_patterns if p in content_lower)
        if marketing_hits >= 3:
            low_value_signals += 2

        # Very few JS files (static site)
        js_count = len(re.findall(r'<script[^>]*src=', html_content, re.I))
        if js_count <= 2:
            low_value_signals += 1

        # No inline scripts with meaningful code
        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html_content, re.DOTALL | re.I)
        meaningful_inline = sum(1 for s in inline_scripts if len(s.strip()) > 200)
        if meaningful_inline == 0:
            low_value_signals += 1

        # High WAF block rate (> 50% of requests blocked)
        total_req = self.stats['requests_made']
        if total_req > 20 and self.stats['waf_blocked'] / total_req > 0.4:
            low_value_signals += 1

        # Low entropy across scanned content
        if len(self.scanned_urls) >= 10 and self.stats.get('high_entropy_found', 0) == 0:
            low_value_signals += 1

        return low_value_signals >= 3

    # ═════════════════════════════════════════════════════════════
    #  Output — Terminal
    # ═════════════════════════════════════════════════════════════

    def print_details(self):
        for i, s in enumerate(self.found_secrets, 1):
            print("=" * 70)
            sev = s.get('severity', 'LOW')
            sc = {'CRITICAL': Colors.FAIL, 'HIGH': Colors.WARNING,
                  'MEDIUM': Colors.OKCYAN, 'LOW': Colors.OKBLUE,
                  'INFO': Colors.DIM}.get(sev, Colors.ENDC)
            conf_score = s.get('confidence_score', '?')
            risk_score = s.get('risk_score', '?')
            print(f"{sc}[{sev}]{Colors.ENDC} {s['type']}")
            print(f"  Confidence: {conf_score}/100  |  "
                  f"Risk: {risk_score}/100  |  "
                  f"Entropy: {s.get('entropy',0):.1f}")

            print(f"  Value: {mask_secret(s['value'])}")
            print(f"  Source: {s['source']}")

            # v2 Factor breakdown
            factors = s.get('score_factors')
            if factors:
                print(f"{Colors.DIM}  Factors: "
                      f"FMT:{factors.get('format_validity','-')} "
                      f"CTX:{factors.get('context_strength','-')} "
                      f"OWN:{factors.get('domain_ownership','-')} "
                      f"FILE:{factors.get('file_risk_weight','-')} "
                      f"ENT:{factors.get('entropy_range_fit','-')} "
                      f"LIVE:{factors.get('live_validation','-')}"
                      f"{Colors.ENDC}")

            if s.get('validated'):
                print(f"{Colors.OKGREEN}  + Format validated{Colors.ENDC}")
            if s.get('verified_live') is True:
                print(f"{Colors.FAIL}  ! VERIFIED LIVE: {s.get('verification_detail','')}{Colors.ENDC}")
            elif s.get('verified_live') is False:
                print(f"{Colors.DIM}  x Not live: {s.get('verification_detail','')}{Colors.ENDC}")
            if s.get('severity_downgraded'):
                print(f"{Colors.DIM}  v Severity downgraded by confidence score{Colors.ENDC}")
            if s.get('severity_escalated'):
                print(f"{Colors.WARNING}  ^ Severity escalated (verified live){Colors.ENDC}")
            if s.get('escalation_reason'):
                print(f"{Colors.WARNING}  ^ {s['escalation_reason']}{Colors.ENDC}")
            if s.get('keyword_hint'):
                print(f"  Keyword hint: {s['keyword_hint']}")
            if s.get('encoding'):
                print(f"  Encoding: {s['encoding']}")
            if s.get('multi_file'):
                src_count = len(s.get('all_sources', []))
                print(f"  Multi-file: found in {src_count} sources")
            if s.get('duplicate_count'):
                print(f"  Deduplicated: {s['duplicate_count']} duplicate(s) merged")
            if s.get('cross_repo'):
                cr = s['cross_repo']
                if cr.get('repo_count', 0) > 1:
                    print(f"{Colors.FAIL}  CROSS-REPO: found across {cr['repo_count']} targets "
                          f"(x{cr['boost_multiplier']:.1f} boost){Colors.ENDC}")
                    if cr.get('is_leaked_widely'):
                        print(f"{Colors.FAIL}  >> WIDELY LEAKED <<{Colors.ENDC}")
            if s.get('accuracy_notes'):
                for note in s['accuracy_notes']:
                    print(f"{Colors.DIM}  [{note}]{Colors.ENDC}")

            # Google scope
            if s.get('google_api_scopes'):
                print(f"{Colors.OKCYAN}  Google API Scopes:{Colors.ENDC}")
                for api, status in s['google_api_scopes'].items():
                    icon = '🔓' if 'ACTIVE' in status else '🔒'
                    print(f"    {icon} {api}: {status}")

            # JWT security analysis (v2.9 enhanced)
            jwt_info = s.get('jwt_decoded')
            if jwt_info:
                a = jwt_info.get('analysis', {})
                score = a.get('risk_score', 0)
                grade = a.get('risk_grade', '?')
                gc = {'CRITICAL': Colors.FAIL, 'HIGH': Colors.WARNING,
                      'MEDIUM': Colors.OKCYAN, 'LOW': Colors.OKGREEN}.get(grade, Colors.ENDC)
                print(f"{Colors.OKCYAN}  JWT Security Analysis:{Colors.ENDC}")
                print(f"    Algorithm: {a.get('algorithm')} "
                      f"({a.get('algorithm_rating','?')})")
                print(f"    {gc}Risk: {grade} (score: {score}/100){Colors.ENDC}")
                if a.get('missing_claims'):
                    print(f"    Missing claims: {', '.join(a['missing_claims'])}")
                if a.get('lifetime_days'):
                    print(f"    Lifetime: {a['lifetime_days']} days")
                if a.get('permissions'):
                    print(f"    Permissions: {', '.join(a['permissions'][:8])}")
                if a.get('pii_claims'):
                    for k, v in a['pii_claims'].items():
                        print(f"    {k}: {v}")
                for vuln in a.get('vulnerabilities', []):
                    print(f"{Colors.FAIL}    ⚠ {vuln}{Colors.ENDC}")
                if a.get('expired'):
                    print(f"{Colors.DIM}    Token expired since: "
                          f"{a.get('expired_since','?')}{Colors.ENDC}")

            # v5.1.1: Exploit path suggestions + exploitability probability
            suggestions = self._get_exploit_suggestions(s)
            if suggestions:
                prob = suggestions.get('probability', 0)
                prob_color = Colors.FAIL if prob >= 70 else (Colors.WARNING if prob >= 40 else Colors.OKCYAN)
                print(f"{prob_color}  ⚡ Exploit Probability: {prob}%{Colors.ENDC}")
                if suggestions.get('next_steps'):
                    print(f"{Colors.DIM}  Suggested Next Steps:{Colors.ENDC}")
                    for step in suggestions['next_steps'][:4]:
                        print(f"{Colors.DIM}    → {step}{Colors.ENDC}")
            print()

    def print_summary(self):
        self.progress.finish()
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}SCAN SUMMARY — v{__version__} by {__author__}{Colors.ENDC}")
        print("=" * 70)

        public_identifiers = [s for s in self.found_secrets if s.get('public_identifier')]
        secret_candidates = [s for s in self.found_secrets if not s.get('public_identifier')]
        if not secret_candidates and not public_identifiers:
            print(f"{Colors.OKGREEN}No high-confidence secrets detected.{Colors.ENDC}")
            print(f"{Colors.DIM}  Target appears hardened against passive secret exposure.{Colors.ENDC}")
            # Provide intelligent guidance based on what WAS found
            surface_hints = []
            if self.stats.get('header_issues', 0) > 0:
                surface_hints.append("Security header misconfigurations (CSP, CORS)")
            if self.stats.get('sri_missing', 0) > 0:
                surface_hints.append("Supply chain integrity (missing SRI)")
            if self.stats.get('swagger_specs', 0) > 0:
                surface_hints.append("Exposed API documentation (Swagger/OpenAPI)")
            if self.stats.get('waf_blocked', 0) > 10:
                surface_hints.append("WAF-protected endpoints (may hide deeper issues)")
            if not surface_hints:
                surface_hints = ["Application logic", "Auth flows", "Business logic vulnerabilities"]
            print(f"{Colors.DIM}  Primary attack surface likely:{Colors.ENDC}")
            for hint in surface_hints[:5]:
                print(f"{Colors.DIM}    → {hint}{Colors.ENDC}")
        else:
            print(f"Credential candidates: {len(secret_candidates)} · "
                  f"Public identifiers: {len(public_identifiers)}")
            by_sev = defaultdict(int)
            for s in secret_candidates:
                by_sev[s['severity']] += 1
            if by_sev:
                print("\nBy Severity (credentials only):")
                for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    if sev in by_sev:
                        c = {'CRITICAL': Colors.FAIL, 'HIGH': Colors.WARNING,
                             'MEDIUM': Colors.OKCYAN, 'LOW': Colors.OKBLUE}.get(sev, '')
                        print(f"  {c}{sev}: {by_sev[sev]}{Colors.ENDC}")

            # Verified live count
            live_count = sum(1 for s in secret_candidates if s.get('verified_live') is True)
            if live_count:
                print(f"\n{Colors.FAIL}⚡ VERIFIED LIVE: {live_count} secret(s){Colors.ENDC}")

            print("\nBy Type:")
            by_type = defaultdict(int)
            for s in secret_candidates:
                by_type[s['type']] += 1
            for t, c in sorted(by_type.items()):
                print(f"  {t}: {c}")
            if public_identifiers:
                print(f"\n{Colors.OKBLUE}Public identifiers (not credentials):{Colors.ENDC}")
                for s in public_identifiers[:10]:
                    loc = s.get('source', '')
                    if s.get('line'):
                        loc += f":{s['line']}"
                    print(f"  {s.get('type')}: {loc}")

        if self.discovered_endpoints:
            print(f"\n{Colors.BOLD}API Endpoints: {len(self.discovered_endpoints)}{Colors.ENDC}")
            for ep in self.discovered_endpoints[:10]:
                print(f"  {ep['endpoint']}")
        if self.discovered_internal_urls:
            print(f"\n{Colors.BOLD}Internal URLs: {len(self.discovered_internal_urls)}{Colors.ENDC}")
            for iu in self.discovered_internal_urls[:10]:
                print(f"  [{iu['type']}] {iu['value']}")
        if self.env_files_found:
            print(f"\n{Colors.FAIL}⚠ .env Files: {len(self.env_files_found)}{Colors.ENDC}")
            for ef in self.env_files_found:
                print(f"  {ef['url']} ({ef['lines']} vars)")
        if self.sensitive_files_found:
            print(f"\n{Colors.FAIL}⚠ Sensitive Files: {len(self.sensitive_files_found)}{Colors.ENDC}")
            for sf in self.sensitive_files_found:
                print(f"  [{sf['severity']}] {sf['type']}: {sf['url']}")
        if self.graphql_endpoints:
            print(f"\n{Colors.FAIL}⚠ GraphQL: {len(self.graphql_endpoints)}{Colors.ENDC}")
            for gql in self.graphql_endpoints:
                print(f"  {gql['url']}")
        if self.api_discovery.swagger_specs:
            print(f"\n{Colors.FAIL}⚠ OpenAPI Schemas: {len(self.api_discovery.swagger_specs)}{Colors.ENDC}")
            for spec in self.api_discovery.swagger_specs:
                print(f"  {spec['url']} ({spec['endpoints']} endpoints)")
        if self.subtko.findings:
            print(f"\n{Colors.FAIL}⚠ Takeover Leads: {len(self.subtko.findings)}{Colors.ENDC}")
            for tf in self.subtko.findings:
                print(f"  [{tf.get('severity')}] {tf.get('domain')} -> {tf.get('cname')}")
        if self.google_scope_results:
            print(f"\n{Colors.FAIL}⚠ Google API Scopes:{Colors.ENDC}")
            for gs in self.google_scope_results:
                active = [k for k, v in gs['scopes'].items() if 'ACTIVE' in v]
                if active:
                    print(f"  Key {gs['key']}: {', '.join(active)}")

        print(f"\n{Colors.DIM}Network Stats:{Colors.ENDC}")
        for k, v in self.stats.items():
            if v > 0:
                print(f"  {k.replace('_', ' ').title()}: {v}")
        print(f"  URLs Scanned: {len(self.scanned_urls)}")

        # WAF intelligence summary
        waf_blocks = self.stats.get('waf_blocked', 0)
        total_req = self.stats.get('requests_made', 0)
        retries = self.stats.get('retries_used', 0)
        if waf_blocks > 5 and total_req > 0:
            block_rate = waf_blocks / total_req * 100
            wasted = retries + self.stats.get('requests_failed', 0)
            print(f"\n{Colors.DIM}  WAF Intelligence:{Colors.ENDC}")
            print(f"    Block rate: {block_rate:.0f}% ({waf_blocks}/{total_req} requests)")
            if wasted > 0:
                efficiency = max(0, (total_req - wasted) / total_req * 100)
                print(f"    Scan efficiency: {efficiency:.0f}% ({wasted} wasted requests)")
            if self._waf_total_blocks > 50:
                print(f"    {Colors.WARNING}→ Heavy WAF target. Consider: -w 3 -r 3 --ua-rotate{Colors.ENDC}")
            elif self._waf_total_blocks > 20:
                print(f"    {Colors.DIM}→ Moderate WAF. Adaptive stealth handled it.{Colors.ENDC}")

        # v5.1.1: Auto-scope warning — show external domains discovered but not scanned
        ext_domains = getattr(self, '_external_domains', set())
        if ext_domains:
            # Filter out common CDN/tracking/social that aren't interesting
            noise = {'facebook.com', 'twitter.com', 'linkedin.com', 'youtube.com',
                     'google.com', 'googleapis.com', 'gstatic.com', 'cloudflare.com',
                     'fonts.googleapis.com', 'www.w3.org', 'schema.org', 'cdn.jsdelivr.net',
                     'cdnjs.cloudflare.com', 'unpkg.com', 'maxcdn.bootstrapcdn.com'}
            interesting = sorted([d for d in ext_domains
                                  if not any(d.endswith(n) or d == n for n in noise)])[:8]
            if interesting:
                print(f"\n{Colors.WARNING}  ⚠ External domains discovered (not scanned):{Colors.ENDC}")
                for d in interesting:
                    print(f"{Colors.DIM}    → {d}{Colors.ENDC}")
                if self.scope_domains:
                    print(f"{Colors.DIM}    (scope restricted to: {', '.join(self.scope_domains[:5])}){Colors.ENDC}")
                else:
                    print(f"{Colors.DIM}    Tip: use --smart for subdomain recon or add targets manually{Colors.ENDC}")

        # ── v2.9: Source Map Intelligence ──
        if self.source_map_intel:
            print(f"\n{Colors.BOLD}📂 Source Map Intelligence:{Colors.ENDC}")
            for sm in self.source_map_intel:
                print(f"  {sm['url']}")
                print(f"    Files: {sm['total_files']} · Lines: {sm['total_lines']:,}")
                if sm['frameworks']:
                    print(f"    Frameworks: {', '.join(sm['frameworks'])}")
                if sm['npm_packages']:
                    print(f"    npm packages: {len(sm['npm_packages'])} "
                          f"({', '.join(sm['npm_packages'][:8])})")
                if sm['comments']:
                    print(f"    Dev comments: {len(sm['comments'])} "
                          f"(TODO/FIXME/secrets)")

        # ── v2.9: Supply Chain ──
        sc_summary = self.supply_chain.get_summary()
        if sc_summary['total_scripts'] > 0:
            print(f"\n{Colors.BOLD}🔗 Supply Chain Analysis:{Colors.ENDC}")
            print(f"  Total scripts: {sc_summary['total_scripts']} "
                  f"({sc_summary['external_scripts']} external)")
            if sc_summary['cdn_origins']:
                print(f"  CDN origins: {', '.join(sc_summary['cdn_origins'][:8])}")
            print(f"  Libraries detected: {sc_summary['libraries_detected']}")
            if sc_summary['npm_packages_from_sourcemaps']:
                print(f"  npm packages (from source maps): "
                      f"{len(sc_summary['npm_packages_from_sourcemaps'])}")

            if sc_summary['vulnerable_libraries'] > 0:
                print(f"\n{Colors.FAIL}  ⚠ VULNERABLE LIBRARIES: "
                      f"{sc_summary['vulnerable_libraries']}{Colors.ENDC}")
                seen = set()
                for v in sc_summary['vulnerabilities']:
                    key = f"{v['library']}@{v['version']}"
                    if key not in seen:
                        seen.add(key)
                        sc_color = {'CRITICAL': Colors.FAIL, 'HIGH': Colors.WARNING,
                                    'MEDIUM': Colors.OKCYAN}.get(v['severity'], Colors.ENDC)
                        print(f"    {sc_color}[{v['severity']}]{Colors.ENDC} "
                              f"{v['library']}@{v['version']} — {v['detail']}")

            if sc_summary['sri_missing'] > 0:
                print(f"\n{Colors.WARNING}  ⚠ Missing SRI: "
                      f"{sc_summary['sri_missing']} external script(s){Colors.ENDC}")
                for sri in sc_summary['sri_issues'][:5]:
                    print(f"    {sri['host']}: {sri['url'][:80]}")

        # ── v3.0: Security Headers (deduplicated) ──
        if self.headers_auditor.findings:
            # Deduplicate: group by (severity, header, issue)
            seen_headers = {}
            for f in self.headers_auditor.findings:
                key = (f['severity'], f['header'], f['issue'])
                if key not in seen_headers:
                    seen_headers[key] = {'count': 1, 'detail': f['detail']}
                else:
                    seen_headers[key]['count'] += 1
            total_unique = len(seen_headers)
            total_raw = len(self.headers_auditor.findings)
            print(f"\n{Colors.BOLD}🛡 Security Headers: "
                  f"{total_unique} unique issue(s) (from {total_raw} checks){Colors.ENDC}")
            for (sev, header, issue), info in sorted(
                seen_headers.items(), key=lambda x: {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}.get(x[0][0], 3)
            ):
                sc = {'HIGH': Colors.WARNING, 'MEDIUM': Colors.OKCYAN,
                      'LOW': Colors.OKBLUE}.get(sev, Colors.ENDC)
                count_str = f" (x{info['count']})" if info['count'] > 1 else ""
                print(f"  {sc}[{sev}]{Colors.ENDC} {header}: "
                      f"{issue} — {info['detail']}{count_str}")

        # ── v3.0: API Discovery ──
        api_sum = self.api_discovery.get_summary()
        if api_sum['swagger_specs']:
            print(f"\n{Colors.FAIL}⚠ Swagger/OpenAPI Specs: "
                  f"{len(api_sum['swagger_specs'])}{Colors.ENDC}")
            for s in api_sum['swagger_specs']:
                print(f"  {s['url']} — {s['title']} v{s['version']} "
                      f"({s['endpoints']} endpoints)")
        if api_sum['graphql_schemas']:
            print(f"\n{Colors.FAIL}⚠ GraphQL Schemas: "
                  f"{len(api_sum['graphql_schemas'])}{Colors.ENDC}")
            for s in api_sum['graphql_schemas']:
                mut = f" · {len(s['mutations'])} mutations" if s['mutations'] else ''
                print(f"  {s['url']} — {s['types']} types{mut}")
        if api_sum['grpc_endpoints']:
            print(f"\n{Colors.OKCYAN}gRPC/Protobuf: "
                  f"{len(api_sum['grpc_endpoints'])}{Colors.ENDC}")

        # ── v3.0: Cloud Native ──
        if self.cloud_scanner and self.cloud_scanner.findings:
            print(f"\n{Colors.FAIL}☁ Cloud Native Findings: "
                  f"{len(self.cloud_scanner.findings)}{Colors.ENDC}")
            for cf in self.cloud_scanner.findings[:10]:
                sc = {'CRITICAL': Colors.FAIL, 'HIGH': Colors.WARNING}.get(
                    cf['severity'], Colors.OKCYAN)
                print(f"  {sc}[{cf['severity']}]{Colors.ENDC} {cf['type']} "
                      f"in {cf['source'][:60]}")

        # ── v3.0: FP filtering stats ──
        if self.fp_removed:
            print(f"\n{Colors.DIM}False positives filtered: "
                  f"{len(self.fp_removed)}{Colors.ENDC}")

        # ── v5.0: CVE Analysis ──
        self.cve_lookup.print_results()

        # ── v5.0: Rate Abuse Analysis ──
        if self.rate_tester:
            self.rate_tester.print_results()

    # ═════════════════════════════════════════════════════════════
    #  v5.2: Unified findings model
    # ═════════════════════════════════════════════════════════════

    SEVERITY_RANK = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    BLOCKING_STATUSES = {'confirmed', 'potential'}

    FINDING_META = {
        'secret': {
            'cwe': 'CWE-798', 'owasp': 'A07:2021 Identification and Authentication Failures',
            'remediation': 'Revoke and rotate the credential, remove it from source, and load it from a managed secret store.',
        },
        'public_identifier': {
            'cwe': 'CWE-200', 'owasp': 'A05:2021 Security Misconfiguration',
            'remediation': 'Confirm the identifier is domain/referrer restricted, quota-limited, and cannot grant privileged access.',
        },
        'cors': {
            'cwe': 'CWE-942', 'owasp': 'A05:2021 Security Misconfiguration',
            'remediation': 'Allowlist exact trusted origins and never combine credentialed requests with reflected or wildcard origins.',
        },
        'redirect': {
            'cwe': 'CWE-601', 'owasp': 'A01:2021 Broken Access Control',
            'remediation': 'Allowlist redirect destinations and reject absolute or protocol-relative URLs outside that list.',
        },
        'env': {
            'cwe': 'CWE-538', 'owasp': 'A05:2021 Security Misconfiguration',
            'remediation': 'Remove environment files from the web root, block dotfiles at the edge, and rotate every exposed value.',
        },
        'sensitive_file': {
            'cwe': 'CWE-538', 'owasp': 'A05:2021 Security Misconfiguration',
            'remediation': 'Remove the file from the public root or deny access at the edge, then rotate any exposed credentials.',
        },
        'graphql': {
            'cwe': 'CWE-200', 'owasp': 'A05:2021 Security Misconfiguration',
            'remediation': 'Disable introspection in production and require authorization on the GraphQL endpoint.',
        },
        'swagger': {
            'cwe': 'CWE-200', 'owasp': 'A05:2021 Security Misconfiguration',
            'remediation': 'Restrict API documentation to authenticated or internal users.',
        },
        'cloud': {
            'cwe': 'CWE-200', 'owasp': 'A05:2021 Security Misconfiguration',
            'remediation': 'Remove embedded cloud configuration from client content and apply least privilege.',
        },
        'cloud_permissions': {
            'cwe': 'CWE-284', 'owasp': 'A01:2021 Broken Access Control',
            'remediation': 'Enable public access blocking and scope bucket or storage permissions to intended principals.',
        },
        'jwt': {
            'cwe': 'CWE-347', 'owasp': 'A07:2021 Identification and Authentication Failures',
            'remediation': 'Verify signatures with pinned algorithms, reject alg=none, and replace weak signing secrets.',
        },
        'dependency': {
            'cwe': 'CWE-427', 'owasp': 'A08:2021 Software and Data Integrity Failures',
            'remediation': 'Use a scoped private registry, reserve internal package names, and pin verified dependency sources.',
        },
        'takeover': {
            'cwe': 'CWE-284', 'owasp': 'A05:2021 Security Misconfiguration',
            'remediation': 'Remove the dangling DNS record or reclaim the third-party resource before attackers do.',
        },
        'header': {
            'cwe': 'CWE-693', 'owasp': 'A05:2021 Security Misconfiguration',
            'remediation': 'Set the missing security header at the application or reverse proxy.',
        },
        'ssrf': {
            'cwe': 'CWE-918', 'owasp': 'A10:2021 Server-Side Request Forgery',
            'remediation': 'Validate outbound destinations against an allowlist and block metadata and internal address ranges.',
        },
        'idor': {
            'cwe': 'CWE-639', 'owasp': 'A01:2021 Broken Access Control',
            'remediation': 'Enforce object-level authorization on every request and use unguessable identifiers.',
        },
        'grpc': {
            'cwe': 'CWE-200', 'owasp': 'A05:2021 Security Misconfiguration',
            'remediation': 'Require authentication and transport security for exposed gRPC services.',
        },
    }

    def _mk_finding(self, category, ftype, severity, confidence, status,
                    source, value='', evidence=None, verification=None,
                    cwe=None, owasp=None, remediation=None, repro=None):
        meta = self.FINDING_META.get(category, {})
        evidence = evidence or {}
        value_str = value if isinstance(value, str) else str(value)
        key = f"{category}|{ftype}|{source}|{value_str}"
        return {
            'id': hashlib.sha256(key.encode('utf-8', 'ignore')).hexdigest()[:16],
            'category': category,
            'type': ftype or 'Unknown',
            'severity': (severity or 'INFO').upper(),
            'confidence': confidence or 'LOW',
            'status': status if status in ('confirmed', 'potential', 'lead') else 'potential',
            'source': source or '',
            'line': evidence.get('line'),
            'snippet': (evidence.get('snippet') or '')[:500],
            'value': value_str[:500],
            'evidence': evidence,
            'verification': verification or {},
            'cwe': cwe or meta.get('cwe', ''),
            'owasp': owasp or meta.get('owasp', ''),
            'remediation': remediation or meta.get('remediation', ''),
            'repro': (repro if repro is not None
                      else self._build_repro(category, source, evidence, value_str)),
            'tool': 'SecretPulse',
            'version': __version__,
        }

    @staticmethod
    def _shell_quote(value):
        return "'" + str(value).replace("'", "'\\''") + "'"

    def _build_repro(self, category, source, evidence, value=''):
        """Build a safe, copy-ready request that reproduces the observation."""
        source = source or ''
        ev = evidence or {}
        q = self._shell_quote
        if category in ('secret', 'public_identifier'):
            if not source or not value:
                return ''
            if source.startswith('file://'):
                path = source[len('file://'):]
                if ev.get('line'):
                    return f"sed -n '{int(ev['line'])}p' {q(path)}"
                return f"grep -nF -- {q(value)} {q(path)}"
            if source.startswith(('http://', 'https://')):
                if ev.get('line'):
                    return f"curl -sS {q(source)} | sed -n '{int(ev['line'])}p'"
                return f"curl -sS {q(source)} | grep -nF -- {q(value)}"
            return ''
        if category == 'cors':
            origin = ev.get('origin_sent') or 'https://evil.example'
            return f"curl -sS -D - -o /dev/null -H {q('Origin: ' + origin)} {q(source)}"
        if category == 'redirect':
            param, payload = ev.get('param'), ev.get('payload')
            if param and payload and source:
                sep = '&' if '?' in source else '?'
                target = f"{source}{sep}{urlencode({param: payload})}"
                return f"curl -sS -D - -o /dev/null {q(target)}"
            return f"curl -sS -D - -o /dev/null {q(source)}"
        if category == 'graphql':
            body = '{"query":"{__schema{types{name}}}"}'
            return (f"curl -sS -X POST -H 'Content-Type: application/json' "
                    f"--data {q(body)} {q(source)}")
        if category == 'takeover':
            target = source if source.startswith(('http://', 'https://')) else f"https://{source}"
            return f"curl -sS -D - {q(target)}"
        if category in ('env', 'sensitive_file', 'swagger'):
            return f"curl -sS {q(source)}"
        if category in ('cloud_permissions', 'header'):
            return f"curl -sS -D - -o /dev/null {q(source)}"
        return ''

    def collect_findings(self):
        """Single source of truth for every module's findings.

        Each entry carries a status tier so unverified signal (IDOR/SSRF
        presence checks) is reported as a *lead* instead of a finding.
        """
        out = []
        seen = set()

        def add(f):
            if f['id'] in seen:
                return
            seen.add(f['id'])
            out.append(f)

        # Secrets — verified-live is confirmed, public identifiers stay leads.
        for s in self.found_secrets:
            public = bool(s.get('public_identifier'))
            evidence = {
                'entropy': s.get('entropy', 0),
                'validated': s.get('validated', False),
                'verified_live': s.get('verified_live'),
                'line': s.get('line'),
                'snippet': s.get('snippet', ''),
                'public_by_design': public,
                'confidence_score': s.get('confidence_score'),
                'risk_score': s.get('risk_score'),
                'severity_pinned': bool(s.get('severity_pinned')),
            }
            for key in ('severity_pin_reason', 'severity_downgraded'):
                if s.get(key):
                    evidence[key] = s[key]
            if public:
                evidence['reason'] = s.get('public_identifier_reason', '')
            add(self._mk_finding(
                'public_identifier' if public else 'secret',
                s.get('type'), 'LOW' if public else s.get('severity'),
                s.get('confidence'),
                'lead' if public else (
                    'confirmed' if s.get('verified_live') is True else 'potential'),
                s.get('source', ''), s.get('value', ''), evidence=evidence,
                verification={'detail': s.get('verification_detail', '')},
            ))

        # CORS — wildcard+credentials is an invalid browser combination
        for f in (getattr(getattr(self, 'cors_detector', None), 'findings', None) or []):
            cors_confirmed = bool(f.get('credentials')) and not f.get('wildcard_credentials')
            add(self._mk_finding(
                'cors', f.get('type', 'CORS Misconfiguration'), f.get('severity'),
                'HIGH', 'confirmed' if cors_confirmed else 'potential',
                f.get('url', ''), f.get('detail', ''),
                evidence={'origin_sent': f.get('origin_sent'),
                          'acao': f.get('acao'),
                          'credentials': f.get('credentials'),
                          'wildcard_credentials': f.get('wildcard_credentials', False)},
            ))

        # Open redirect — only a 3xx Location response is confirmed
        for f in (getattr(getattr(self, 'redirect_detector', None), 'findings', None) or []):
            add(self._mk_finding(
                'redirect', f.get('type', 'Open Redirect'), f.get('severity'),
                'HIGH', 'confirmed' if f.get('verified_by') == 'location' else 'potential',
                f.get('url', ''), f.get('detail', ''),
                evidence={'param': f.get('param'), 'payload': f.get('payload'),
                          'status_code': f.get('status_code'),
                          'location': f.get('location'),
                          'verified_by': f.get('verified_by')},
            ))

        # .env and sensitive-file exposure — validated HTTP 200 content
        for ef in (getattr(self, 'env_files_found', None) or []):
            keys = ', '.join(ef.get('sample_keys', [])[:5])
            add(self._mk_finding(
                'env', 'Exposed .env File', 'CRITICAL', 'HIGH', 'confirmed',
                ef.get('url', ''), f"{ef.get('lines', 0)} vars: {keys}".strip(': '),
                evidence=ef,
            ))
        for sf in (getattr(self, 'sensitive_files_found', None) or []):
            add(self._mk_finding(
                'sensitive_file', sf.get('type', 'Exposed Sensitive File'),
                sf.get('severity', 'MEDIUM'), 'HIGH', 'confirmed',
                sf.get('url', ''), sf.get('path', ''), evidence=sf,
            ))

        # GraphQL — merge the lightweight and full-schema probes by URL
        gql_map = {}
        for g in (getattr(self, 'graphql_endpoints', None) or []):
            entry = gql_map.setdefault(g.get('url', ''), {'types': 0, 'mutations': []})
            entry['types'] = max(entry['types'], g.get('types_count', 0))
        for s in (getattr(getattr(self, 'api_discovery', None), 'graphql_schemas', None) or []):
            entry = gql_map.setdefault(s.get('url', ''), {'types': 0, 'mutations': []})
            entry['types'] = max(entry['types'], s.get('types', 0))
            entry['mutations'] = s.get('mutations') or entry['mutations']
            entry.update({k: v for k, v in s.items() if k not in ('url', 'types', 'mutations')})
        for url, info in gql_map.items():
            mutations = info.get('mutations') or []
            add(self._mk_finding(
                'graphql', 'GraphQL Introspection Enabled',
                'HIGH' if mutations else 'MEDIUM', 'HIGH', 'confirmed',
                url, f"{info.get('types', 0)} types, {len(mutations)} mutations",
                evidence=info,
                verification={'detail': 'Introspection response returned schema data'},
            ))

        # Swagger/OpenAPI specs — public schema exposure
        for spec in (getattr(getattr(self, 'api_discovery', None), 'swagger_specs', None) or []):
            add(self._mk_finding(
                'swagger', 'Exposed OpenAPI Schema', 'MEDIUM', 'HIGH', 'confirmed',
                spec.get('url', ''),
                f"{spec.get('title', 'N/A')} ({spec.get('endpoints', 0)} endpoints)",
                evidence=spec,
                verification={'detail': 'Valid OpenAPI document returned over HTTP'},
            ))

        # gRPC indicators extracted from client bundles are unverified leads
        for g in (getattr(getattr(self, 'api_discovery', None), 'grpc_endpoints', None) or []):
            add(self._mk_finding(
                'grpc', 'gRPC Service Indicator', 'INFO', 'LOW', 'lead',
                g.get('source', ''), g.get('indicator', ''), evidence=g,
            ))

        # Cloud-native findings are regex indicators, not confirmed exposure
        cloud_findings = getattr(getattr(self, 'cloud_scanner', None), 'findings', None) or []
        for f in cloud_findings:
            add(self._mk_finding(
                'cloud', f.get('type'), f.get('severity'), 'MEDIUM',
                'lead', f.get('source', ''), f.get('detail', ''), evidence=f,
            ))

        # Cloud permission findings are read-only HTTP observations
        cloud_perm_findings = getattr(
            getattr(self, 'cloud_perm_tester', None), 'findings', None) or []
        for f in cloud_perm_findings:
            add(self._mk_finding(
                'cloud_permissions', f.get('type'), f.get('severity'), 'HIGH',
                'confirmed', f.get('url') or f.get('bucket', ''), f.get('detail', ''),
                evidence=f,
            ))

        # JWT findings — weak signing keys are provable offline
        for f in (getattr(self, 'jwt_findings', None) or []):
            ftype = f.get('type', 'JWT Finding')
            jwt_confirmed = ftype == 'JWT Weak Secret'
            value = f.get('secret') or f.get('forged_token') or f.get('detail', '')
            add(self._mk_finding(
                'jwt', ftype, f.get('severity'), 'HIGH' if jwt_confirmed else 'MEDIUM',
                'confirmed' if jwt_confirmed else 'lead',
                f.get('source', ''), value, evidence=f,
                verification={'detail': f.get('detail', '')},
            ))

        # Dependency confusion — absence from npm is verified, exploitation is not
        for f in (getattr(self, 'dep_confusion_findings', None) or []):
            pkg = f.get('package', '')
            add(self._mk_finding(
                'dependency', f.get('type', 'Dependency Confusion'), f.get('severity'),
                'MEDIUM', 'potential', f"npm:{pkg}", pkg, evidence=f,
            ))

        # Subdomain takeover — CNAME to a claimable service plus fingerprint
        for f in (getattr(getattr(self, 'subtko', None), 'findings', None) or []):
            status = f.get('status', 'lead')
            value = f"{f.get('service', '')} via {f.get('cname', '')}".strip(' via')
            value = value or f.get('signature', 'Dangling subdomain')
            add(self._mk_finding(
                'takeover',
                'Subdomain Takeover' if status != 'lead' else 'Subdomain Takeover Lead',
                f.get('severity', 'INFO'), f.get('confidence', 'MEDIUM'), status,
                f.get('domain', ''), value, evidence=f,
                verification={'detail': f.get('signature', '')},
            ))

        # Security header findings
        for f in (getattr(self.headers_auditor, 'findings', None) or []):
            label = f"{f.get('header', '')}: {f.get('issue', '')}".strip(': ')
            add(self._mk_finding(
                'header', label or 'Security Header Issue', f.get('severity'),
                'MEDIUM', 'lead', f.get('url', ''),
                f.get('detail', ''), evidence=f,
            ))

        # Unverified signals — reported as leads, never as findings
        for v in (getattr(getattr(self, 'ssrf_prober', None), 'vectors', None) or []):
            add(self._mk_finding(
                'ssrf', 'SSRF Indicator (unconfirmed)', v.get('severity', 'INFO'),
                'LOW', 'lead', v.get('source', ''), v.get('indicator', ''), evidence=v,
            ))
        for c in (getattr(getattr(self, 'idor_fuzzer', None), 'idor_candidates', None) or []):
            add(self._mk_finding(
                'idor', 'IDOR/BOLA Candidate (unverified)', 'INFO',
                'LOW', 'lead', c.get('base_url', ''), c.get('url_pattern', ''), evidence=c,
            ))
        for ch in (getattr(self, 'attack_chains', None) or []):
            if not isinstance(ch, dict):
                continue
            add(self._mk_finding(
                'attack_chain', ch.get('type', ch.get('name', 'Attack Chain')),
                ch.get('severity', 'INFO'), 'LOW', 'lead',
                ch.get('source', ch.get('url', '')),
                ch.get('detail', ch.get('description', '')), evidence=ch,
            ))

        return out

    def get_finding_summary(self):
        findings = self.collect_findings()
        by_status, by_sev = defaultdict(int), defaultdict(int)
        for f in findings:
            by_status[f['status']] += 1
            by_sev[f['severity']] += 1
        return {
            'total': len(findings),
            'by_status': dict(by_status),
            'by_severity': dict(by_sev),
            'blocking': sum(1 for f in findings if f['status'] in self.BLOCKING_STATUSES),
        }

    def compute_exit_code(self, fail_on, findings=None):
        """CI gate: 1 if confirmed/potential findings meet the severity threshold.

        Leads are intentionally excluded so unverified heuristics never fail a build.
        """
        if not fail_on or str(fail_on).lower() == 'none':
            return 0
        limit = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'any': 4}.get(
            str(fail_on).lower())
        if limit is None:
            return 0
        if findings is None:
            findings = self.collect_findings()
        blocking = [f for f in findings
                    if f['status'] in self.BLOCKING_STATUSES]
        if not blocking:
            return 0
        worst = min(self.SEVERITY_RANK.get(f['severity'], 4) for f in blocking)
        return 1 if worst <= limit else 0

    # ═════════════════════════════════════════════════════════════
    #  Output — JSON
    # ═════════════════════════════════════════════════════════════

    def export_json(self, filename):
        unified = self.collect_findings()
        public_count = sum(1 for s in self.found_secrets if s.get('public_identifier'))
        output = {
            'tool': f'SecretPulse v{__version__}',
            'author': __author__,
            'scan_time': datetime.now(timezone.utc).isoformat(),
            'urls_scanned': len(self.scanned_urls),
            'total_findings': len(unified),
            'secrets_total': len(self.found_secrets) - public_count,
            'public_identifiers_total': public_count,
            'secret_candidates_total': len(self.found_secrets),
            'scan_config': {
                'request_timeout': self.request_timeout,
                'max_response_bytes': self.max_response_bytes,
                'custom_headers': sorted(self.custom_headers),
                'cookie_auth': bool(self.custom_cookies),
                'proxy': bool(self.proxy),
                'verify_providers': self.verify_providers,
                'allow_webhook_checks': self.allow_webhook_checks,
            },
            'network_stats': self.stats,
            'findings': unified,
            'secret_candidates': self.found_secrets,
            'api_endpoints': self.discovered_endpoints,
            'internal_urls': self.discovered_internal_urls,
            'env_files': self.env_files_found,
            'sensitive_files': self.sensitive_files_found,
            'graphql_endpoints': self.graphql_endpoints,
            'google_scope_results': self.google_scope_results,
            'source_map_intel': self.source_map_intel,
            'supply_chain': self.supply_chain.get_summary(),
            'security_headers': self.headers_auditor.findings,
            'api_discovery': self.api_discovery.get_summary(),
            'cloud_findings': self.cloud_scanner.findings if self.cloud_scanner else [],
            'false_positives_removed': len(self.fp_removed),
            'attack_chains': self.attack_chains,
            'ssrf_vectors': self.ssrf_prober.vectors,
            'idor_candidates': self.idor_fuzzer.idor_candidates,
            'internal_routes': self.internal_api_enum.routes,
            'subtko_findings': self.subtko.findings,
            'wayback_urls': self.wayback.archived_urls,
            'privilege_escalation': self.priv_esc.results,
            'cve_analysis': self.cve_lookup.get_summary(),
            'rate_abuse': self.rate_tester.get_summary() if self.rate_tester else {},
            'accuracy_engine': self.accuracy_engine.get_stats(),
            'unified_findings': unified,
            'finding_summary': self.get_finding_summary(),
        }
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2, default=str)
        print(f"{Colors.OKGREEN}[+] JSON: {filename}{Colors.ENDC}")

    # ═════════════════════════════════════════════════════════════
    #  Output — HTML
    # ═════════════════════════════════════════════════════════════

    def export_html(self, filename):
        sev_c = {'CRITICAL': '#dc3545', 'HIGH': '#fd7e14', 'MEDIUM': '#0dcaf0', 'LOW': '#0d6efd', 'INFO': '#adb5bd'}
        conf_c = {'HIGH': '#198754', 'MEDIUM': '#ffc107', 'LOW': '#6c757d'}

        rows = []
        # v5.1.1: Deduplicate findings by value in HTML report
        seen_values = {}  # value -> index in found_secrets (first occurrence)
        dedup_sources = {}  # value -> list of additional sources
        for i, s in enumerate(self.found_secrets):
            val_key = f"{s.get('type','')}:{s.get('value','')}"
            if val_key in seen_values:
                if val_key not in dedup_sources:
                    dedup_sources[val_key] = []
                dedup_sources[val_key].append(s.get('source', ''))
                continue
            seen_values[val_key] = i

        row_num = 0
        for i, s in enumerate(self.found_secrets, 0):
            val_key = f"{s.get('type','')}:{s.get('value','')}"
            if val_key in seen_values and seen_values[val_key] != i:
                continue  # Skip duplicates, already handled by first occurrence
            row_num += 1
            val = html_lib.escape(s['value'])
            if len(val) > 80:
                val = val[:77] + "..."
            src = html_lib.escape(s['source'])
            if s.get('line'):
                src += f":{s['line']}"
            sev = s['severity']
            conf = s.get('confidence', '?')
            conf_score = s.get('confidence_score', '?')
            risk_score = s.get('risk_score', '?')
            ent = s.get('entropy', 0)
            v_fmt = '+' if s.get('validated') else ''
            v_live = ''
            if s.get('public_identifier'):
                v_live = '<br><small>public</small>'
            elif s.get('verified_live') is True:
                v_live = '<br><span style="color:#dc3545;font-weight:bold">! LIVE</span>'
            elif s.get('verified_live') is False:
                v_live = '<br><span style="color:#6c757d">x Dead</span>'
            extra = ''
            if s.get('public_identifier'):
                extra += (f"<br><small style='color:#0d6efd'>Public by design: "
                          f"{html_lib.escape(s.get('public_identifier_reason', ''))}</small>")
            if s.get('snippet'):
                extra += (f"<br><pre style='white-space:pre-wrap;font-size:11px;"
                          f"margin:2px 0'>{html_lib.escape(s['snippet'])}</pre>")
            # v2 Factor breakdown
            factors = s.get('score_factors', {})
            if factors:
                extra += (f"<br><small style='color:#555'>FMT:{factors.get('format_validity','-')} "
                          f"CTX:{factors.get('context_strength','-')} "
                          f"OWN:{factors.get('domain_ownership','-')} "
                          f"FILE:{factors.get('file_risk_weight','-')} "
                          f"ENT:{factors.get('entropy_range_fit','-')} "
                          f"LIVE:{factors.get('live_validation','-')}</small>")
            if s.get('severity_downgraded'):
                extra += '<br><small style="color:#6c757d">v severity downgraded by confidence</small>'
            if s.get('jwt_decoded'):
                a = s['jwt_decoded'].get('analysis', {})
                grade = a.get('risk_grade', '?')
                score = a.get('risk_score', 0)
                gc = {'CRITICAL':'#dc3545','HIGH':'#fd7e14','MEDIUM':'#0dcaf0','LOW':'#198754'}.get(grade,'#6c757d')
                extra += (f"<br><small>JWT: {a.get('algorithm','?')} - "
                          f"<span style='color:{gc}'>{grade} ({score}/100)</span></small>")
                vulns = a.get('vulnerabilities', [])
                if vulns:
                    extra += f"<br><small style='color:#dc3545'>! {vulns[0][:60]}</small>"
                if a.get('permissions'):
                    extra += f"<br><small>perms: {', '.join(a['permissions'][:4])}</small>"
            if s.get('keyword_hint'):
                extra += f"<br><small>hint: {s['keyword_hint']}</small>"
            if s.get('accuracy_notes'):
                for note in s['accuracy_notes'][:3]:
                    extra += f"<br><small style='color:#6c757d'>[{html_lib.escape(note)}]</small>"
            if s.get('multi_file'):
                extra += f"<br><small>Multi-file: {len(s.get('all_sources', []))} sources</small>"
            # v5.1.1: Exploit suggestions in HTML
            suggestions = None if s.get('public_identifier') else self._get_exploit_suggestions(s)
            if suggestions:
                prob = suggestions.get('probability', 0)
                pc = '#dc3545' if prob >= 70 else ('#fd7e14' if prob >= 40 else '#0dcaf0')
                extra += f"<br><small style='color:{pc}'>⚡ Exploit probability: {prob}%</small>"
                if suggestions.get('next_steps'):
                    extra += "<br><small style='color:#8b949e'>→ " + \
                             "</small><br><small style='color:#8b949e'>→ ".join(
                                 html_lib.escape(step) for step in suggestions['next_steps'][:3]) + "</small>"
            # v5.1.1: Show additional sources for deduped findings
            additional_sources = dedup_sources.get(val_key, [])
            if additional_sources:
                extra += f"<br><small style='color:#0dcaf0'>Also found in {len(additional_sources)} other source(s):</small>"
                for asrc in additional_sources[:3]:
                    extra += f"<br><small style='color:#6c757d'>  + {html_lib.escape(asrc[:60])}</small>"
                if len(additional_sources) > 3:
                    extra += f"<br><small style='color:#6c757d'>  + {len(additional_sources)-3} more...</small>"
            rows.append(f"""<tr>
                <td>{row_num}</td>
                <td><span class="badge" style="background:{sev_c.get(sev,'#6c757d')}">{sev}</span></td>
                <td><span class="badge" style="background:{conf_c.get(conf,'#6c757d')}">{conf_score}</span><br><small>risk:{risk_score}</small></td>
                <td>{html_lib.escape(s['type'])}{extra}</td>
                <td class="mono">{val}</td>
                <td>{ent:.1f}</td>
                <td class="src">{src}</td>
                <td style="text-align:center">{v_fmt}{v_live}</td>
            </tr>""")

        by_sev = defaultdict(int)
        for s in self.found_secrets:
            by_sev[s['severity']] += 1
        badges = ' '.join(
            f'<span class="badge" style="background:{sev_c.get(k,"#6c757d")}">{k}: {v}</span>'
            for k in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] if (v := by_sev.get(k))
        )
        live_count = sum(1 for s in self.found_secrets if s.get('verified_live') is True)
        if live_count:
            badges += f' <span class="badge" style="background:#dc3545">⚡ LIVE: {live_count}</span>'

        disc_html = ''
        if self.env_files_found:
            disc_html += '<h2 style="color:#dc3545">⚠ Exposed .env Files</h2><ul>'
            for ef in self.env_files_found:
                disc_html += f'<li><code>{html_lib.escape(ef["url"])}</code> — {ef["lines"]} vars</li>'
            disc_html += '</ul>'
        if self.graphql_endpoints:
            disc_html += '<h2 style="color:#dc3545">⚠ GraphQL Introspection</h2><ul>'
            for gql in self.graphql_endpoints:
                disc_html += f'<li><code>{html_lib.escape(gql["url"])}</code></li>'
            disc_html += '</ul>'
        if self.google_scope_results:
            disc_html += '<h2 style="color:#dc3545">⚠ Google API Key Scopes</h2>'
            for gs in self.google_scope_results:
                disc_html += f'<p>Key: <code>{html_lib.escape(gs["key"])}</code></p><ul>'
                for api, status in gs['scopes'].items():
                    icon = '🔓' if 'ACTIVE' in status else '🔒'
                    disc_html += f'<li>{icon} {html_lib.escape(api)}: {html_lib.escape(status)}</li>'
                disc_html += '</ul>'
        if self.discovered_internal_urls:
            disc_html += f'<h2>Internal URLs ({len(self.discovered_internal_urls)})</h2><ul>'
            for iu in self.discovered_internal_urls[:15]:
                disc_html += f'<li>[{html_lib.escape(iu["type"])}] <code>{html_lib.escape(iu["value"])}</code></li>'
            disc_html += '</ul>'
        if self.discovered_endpoints:
            disc_html += f'<h2>API Endpoints ({len(self.discovered_endpoints)})</h2><ul>'
            for ep in self.discovered_endpoints[:15]:
                disc_html += f'<li><code>{html_lib.escape(ep["endpoint"])}</code></li>'
            disc_html += '</ul>'

        # ── v2.9: Source Map Intelligence ──
        if self.source_map_intel:
            disc_html += '<h2>📂 Source Map Intelligence</h2>'
            for sm in self.source_map_intel:
                disc_html += (f'<p><code>{html_lib.escape(sm["url"])}</code> — '
                              f'{sm["total_files"]} files · {sm["total_lines"]:,} lines</p>')
                if sm['frameworks']:
                    disc_html += f'<p>Frameworks: <strong>{", ".join(sm["frameworks"])}</strong></p>'
                if sm['npm_packages']:
                    disc_html += f'<p>npm: {", ".join(sm["npm_packages"][:15])}</p>'

        # ── v2.9: Supply Chain ──
        sc_summary = self.supply_chain.get_summary()
        if sc_summary['total_scripts'] > 0:
            disc_html += f'<h2>🔗 Supply Chain ({sc_summary["total_scripts"]} scripts)</h2>'
            # Script inventory table
            ext_count = sc_summary['external_scripts']
            int_count = sc_summary['total_scripts'] - ext_count
            libs_count = sc_summary['libraries_detected']
            disc_html += (f'<p>Total: {sc_summary["total_scripts"]} scripts '
                          f'({ext_count} external, {int_count} internal) · '
                          f'Libraries detected: {libs_count}</p>')
            if sc_summary['inventory']:
                disc_html += ('<table style="width:100%;border-collapse:collapse;margin:8px 0">'
                              '<tr style="background:#1a1a2e;color:#8b949e;font-size:12px">'
                              '<th style="padding:6px 8px;text-align:left">Script URL</th>'
                              '<th style="padding:6px 8px;text-align:center">Type</th>'
                              '<th style="padding:6px 8px;text-align:center">Library</th>'
                              '<th style="padding:6px 8px;text-align:center">SRI</th></tr>')
                for script in sc_summary['inventory']:
                    s_url = html_lib.escape(script['url'])
                    # Truncate long URLs for display
                    s_url_display = html_lib.escape(script['url'][:80] + ('...' if len(script['url']) > 80 else ''))
                    s_type = '<span style="color:#f59e0b">external</span>' if script['is_external'] else '<span style="color:#64748b">internal</span>'
                    s_lib = html_lib.escape(f"{script['library']}@{script['version']}") if script.get('library') else '<span style="color:#334155">—</span>'
                    s_sri = '<span style="color:#10b981">✓</span>' if script.get('has_sri') else ('<span style="color:#ef4444">✗</span>' if script['is_external'] else '<span style="color:#334155">—</span>')
                    disc_html += (f'<tr style="border-bottom:1px solid #1e293b;font-size:11px">'
                                  f'<td style="padding:4px 8px"><code style="font-size:11px">{s_url_display}</code></td>'
                                  f'<td style="padding:4px 8px;text-align:center">{s_type}</td>'
                                  f'<td style="padding:4px 8px;text-align:center">{s_lib}</td>'
                                  f'<td style="padding:4px 8px;text-align:center">{s_sri}</td></tr>')
                disc_html += '</table>'
            if sc_summary['vulnerable_libraries'] > 0:
                disc_html += '<h3 style="color:#dc3545">⚠ Vulnerable Libraries</h3><ul>'
                seen = set()
                for v in sc_summary['vulnerabilities']:
                    key = f"{v['library']}@{v['version']}"
                    if key not in seen:
                        seen.add(key)
                        vc = {'CRITICAL':'#dc3545','HIGH':'#fd7e14','MEDIUM':'#0dcaf0'}.get(v['severity'],'#6c757d')
                        disc_html += (f'<li><span class="badge" style="background:{vc}">'
                                      f'{v["severity"]}</span> '
                                      f'<strong>{html_lib.escape(v["library"])}@{html_lib.escape(v["version"])}'
                                      f'</strong> — {html_lib.escape(v["detail"])}</li>')
                disc_html += '</ul>'
            if sc_summary['sri_missing'] > 0:
                disc_html += (f'<p style="color:#fd7e14">⚠ {sc_summary["sri_missing"]} '
                              f'external scripts missing SRI integrity attribute</p>')
            if sc_summary['cdn_origins']:
                disc_html += f'<p>CDN origins: {", ".join(html_lib.escape(o) for o in sc_summary["cdn_origins"][:10])}</p>'

        # v3.0: Security Headers (deduplicated)
        if self.headers_auditor.findings:
            seen_hdr = {}
            for f in self.headers_auditor.findings:
                key = (f['severity'], f['header'], f['issue'])
                if key not in seen_hdr:
                    seen_hdr[key] = {'count': 1, 'detail': f['detail']}
                else:
                    seen_hdr[key]['count'] += 1
            disc_html += f'<h2>🛡 Security Headers ({len(seen_hdr)} unique issues)</h2><ul>'
            for (sev, header, issue), info in sorted(
                seen_hdr.items(), key=lambda x: {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}.get(x[0][0], 3)
            ):
                hc = {'HIGH':'#fd7e14','MEDIUM':'#0dcaf0','LOW':'#0d6efd'}.get(sev,'#6c757d')
                count_str = f" (x{info['count']})" if info['count'] > 1 else ""
                disc_html += (f'<li><span class="badge" style="background:{hc}">{sev}</span> '
                              f'<strong>{html_lib.escape(header)}</strong>: '
                              f'{html_lib.escape(issue)} — {html_lib.escape(info["detail"])}{count_str}</li>')
            disc_html += '</ul>'

        # v3.0: API Discovery
        api_sum = self.api_discovery.get_summary()
        if api_sum['swagger_specs']:
            disc_html += '<h2 style="color:#dc3545">⚠ Swagger/OpenAPI Specs</h2><ul>'
            for s in api_sum['swagger_specs']:
                disc_html += (f'<li><code>{html_lib.escape(s["url"])}</code> — '
                              f'{html_lib.escape(s["title"])} ({s["endpoints"]} endpoints)</li>')
            disc_html += '</ul>'
        if api_sum['graphql_schemas']:
            disc_html += '<h2 style="color:#dc3545">⚠ GraphQL Schemas</h2><ul>'
            for s in api_sum['graphql_schemas']:
                mut = f' · {len(s["mutations"])} mutations' if s['mutations'] else ''
                disc_html += f'<li><code>{html_lib.escape(s["url"])}</code> — {s["types"]} types{mut}</li>'
            disc_html += '</ul>'

        # v3.0: Cloud Native
        if self.cloud_scanner and self.cloud_scanner.findings:
            disc_html += f'<h2 style="color:#dc3545">☁ Cloud Native ({len(self.cloud_scanner.findings)})</h2><ul>'
            for cf in self.cloud_scanner.findings[:10]:
                cc = {'CRITICAL':'#dc3545','HIGH':'#fd7e14'}.get(cf['severity'],'#0dcaf0')
                disc_html += (f'<li><span class="badge" style="background:{cc}">{cf["severity"]}</span> '
                              f'{html_lib.escape(cf["type"])} in <code>{html_lib.escape(cf["source"][:60])}</code></li>')
            disc_html += '</ul>'

        # v5.2: Unified exposure findings — module results now reach the report
        unified = self.collect_findings()
        module_findings = [f for f in unified if f['category'] != 'secret']
        if module_findings:
            stat_c = {'confirmed': '#dc3545', 'potential': '#fd7e14', 'lead': '#6c757d'}
            disc_html += (f'<h2>Exposure Findings ({len(module_findings)})</h2>'
                          '<table><tr><th>Severity</th><th>Status</th><th>Category</th>'
                          '<th>Type / CWE</th><th>Source</th><th>Evidence</th><th>Repro</th></tr>')
            for f in sorted(module_findings,
                            key=lambda x: self.SEVERITY_RANK.get(x['severity'], 4)):
                sc = stat_c.get(f['status'], '#6c757d')
                ev_items = []
                for k, val in (f.get('evidence') or {}).items():
                    if val in (None, '', [], {}, False):
                        continue
                    if any(marker in k.lower() for marker in
                           ('secret', 'token', 'password', 'authorization')):
                        val = '[redacted]'
                    elif isinstance(val, (dict, list)):
                        val = json.dumps(val, default=str)
                    ev_items.append(f'{k}={val}')
                ev_text = '; '.join(ev_items)[:240]
                repro = f.get('repro') or ''
                cwe = f.get('cwe') or ''
                owasp = f.get('owasp') or ''
                remediation = f.get('remediation') or ''
                display_value = ('weak HMAC secret confirmed'
                                 if f['category'] == 'jwt' and f['status'] == 'confirmed'
                                 else f['value'])
                fix_html = (f'<br><small style="color:#6c757d">fix: '
                            f'{html_lib.escape(remediation)}</small>') if remediation else ''
                ev_html = (f'<br><small style="color:#6c757d">'
                           f'{html_lib.escape(ev_text)}</small>') if ev_text else ''
                repro_html = (f'<code style="white-space:pre-wrap">'
                              f'{html_lib.escape(repro)}</code>') if repro else ''
                disc_html += (
                    f'<tr><td><span class="badge" style="background:'
                    f'{sev_c.get(f["severity"], "#6c757d")}">{html_lib.escape(f["severity"])}</span></td>'
                    f'<td><span class="badge" style="background:{sc}">'
                    f'{html_lib.escape(f["status"])}</span></td>'
                    f'<td>{html_lib.escape(f["category"])}</td>'
                    f'<td>{html_lib.escape(f["type"])}'
                    f'<br><small style="color:#8b949e">{html_lib.escape(cwe)}'
                    f'{(" · " + html_lib.escape(owasp)) if owasp else ""}</small>'
                    f'{fix_html}</td>'
                    f'<td class="src">{html_lib.escape(f["source"][:100])}</td>'
                    f'<td>{html_lib.escape(display_value[:160])}{ev_html}</td>'
                    f'<td>{repro_html}</td></tr>')
            disc_html += '</table>'

        now = datetime.now(timezone.utc)
        html_out = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Secret Scanner v{__version__} Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d1117;color:#c9d1d9;padding:24px}}
h1{{color:#58a6ff;margin-bottom:4px;font-size:1.6rem}}
h2{{color:#58a6ff;margin:16px 0 8px;font-size:1.1rem}}
.author{{color:#f0883e;font-size:0.85rem;margin-bottom:4px}}
.subtitle{{color:#8b949e;margin-bottom:20px;font-size:0.9rem}}
.badge{{display:inline-block;padding:3px 10px;border-radius:12px;color:#fff;font-size:0.75rem;font-weight:600;margin-right:6px}}
table{{width:100%;border-collapse:collapse;font-size:0.85rem}}
th{{background:#161b22;color:#58a6ff;padding:10px 8px;text-align:left;border-bottom:2px solid #30363d;position:sticky;top:0}}
td{{padding:8px;border-bottom:1px solid #21262d;vertical-align:top}}
tr:hover td{{background:#161b22}}
.mono{{font-family:'SF Mono','Fira Code',monospace;font-size:0.8rem;word-break:break-all;color:#f0883e}}
.src{{font-size:0.78rem;color:#8b949e;word-break:break-all}}
ul{{margin:8px 0 16px 24px;font-size:0.85rem}}
li{{margin-bottom:4px}}
code{{background:#161b22;padding:2px 6px;border-radius:4px;font-size:0.82rem}}
.net{{background:#161b22;border-radius:8px;padding:16px;margin-bottom:20px;font-size:0.82rem}}
.net span{{margin-right:18px}}
.footer{{margin-top:24px;color:#484f58;font-size:0.75rem;text-align:center}}
</style></head><body>
<h1>🔍 SecretPulse v{__version__} — Report</h1>
<div class="author">by {__author__}</div>
<div class="subtitle">Generated: {now.strftime('%Y-%m-%d %H:%M:%S UTC')} · URLs: {len(self.scanned_urls)} · Findings: {len(self.found_secrets)}</div>
<div class="net"><strong>Network:</strong>
<span>Requests: {self.stats['requests_made']}</span>
<span>Failed: {self.stats['requests_failed']}</span>
<span>WAF blocked: {self.stats['waf_blocked']}</span>
<span>Source maps: {self.stats['source_maps_found']}</span>
<span>Verified live: {self.stats['secrets_verified_live']}</span>
<span>Supply chain vulns: {self.stats['supply_chain_vulns']}</span>
<span>SRI missing: {self.stats['sri_missing']}</span></div>
<div style="margin-bottom:16px">{badges}</div>
{disc_html}
<table><thead><tr><th>#</th><th>Sev</th><th>Conf</th><th>Type</th><th>Value</th><th>Entropy</th><th>Source</th><th>Status</th></tr></thead>
<tbody>{''.join(rows) if rows else '<tr><td colspan="8" style="text-align:center;padding:20px;color:#64748b">No high-confidence secrets detected — target appears hardened</td></tr>'}</tbody></table>
<div class="footer">SecretPulse v{__version__} by {__author__} — For Authorized Bug Bounty Testing Only</div>
</body></html>"""

        with open(filename, 'w') as f:
            f.write(html_out)
        print(f"{Colors.OKGREEN}[+] HTML: {filename}{Colors.ENDC}")
