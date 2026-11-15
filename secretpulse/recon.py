"""Certificate transparency, DNS, crawling, routing, and recon orchestration."""
from ._imports import *
from .storage import SecretPulseDB
from .utils import Colors

import urllib3

# Recon probes skip certificate validation on purpose: expired, self-signed, and
# mismatched certificates are themselves takeover signals. Silence the warnings
# that requests would otherwise print for every such host.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CertTransparency:
    """
    Query Certificate Transparency logs (crt.sh) to discover subdomains.
    Returns deduplicated, cleaned subdomain list.
    """

    CRTSH_URL = "https://crt.sh/?q={}&output=json"

    def __init__(self, session, verbose=False):
        self.session = session
        self.verbose = verbose
        self.subdomains: Set[str] = set()
        self.wildcard_count = 0
        self.raw_count = 0

    def query(self, domain: str, timeout: int = 30) -> List[str]:
        """Query crt.sh for all subdomains of a domain."""
        if self.verbose:
            print(f"{Colors.OKCYAN}  [CT] Querying Certificate Transparency logs for {domain}...{Colors.ENDC}")

        try:
            url = self.CRTSH_URL.format(f"%.{domain}")
            resp = self.session.get(url, timeout=timeout)
            if not resp or resp.status_code != 200:
                if self.verbose:
                    print(f"{Colors.WARNING}  [CT] crt.sh returned {resp.status_code if resp else 'no response'}{Colors.ENDC}")
                return []

            entries = resp.json()
            self.raw_count = len(entries)

            for entry in entries:
                name = entry.get('name_value', '').lower().strip()
                # Handle multiline entries
                for sub in name.split('\n'):
                    sub = sub.strip()
                    if not sub:
                        continue
                    # Skip wildcards but count them
                    if sub.startswith('*.'):
                        self.wildcard_count += 1
                        sub = sub[2:]  # Still add the base
                    # Clean and validate
                    sub = sub.strip('.')
                    if not sub or not sub.endswith(domain):
                        continue
                    # Skip obvious noise
                    if any(c in sub for c in [' ', '/', '\\', '<', '>']):
                        continue
                    self.subdomains.add(sub)

            # Always include the apex domain
            self.subdomains.add(domain)

            result = sorted(self.subdomains)
            if self.verbose:
                print(f"{Colors.OKGREEN}  [CT] Found {len(result)} unique subdomains "
                      f"({self.raw_count} raw entries, {self.wildcard_count} wildcards){Colors.ENDC}")
            return result

        except json.JSONDecodeError:
            if self.verbose:
                print(f"{Colors.WARNING}  [CT] crt.sh returned invalid JSON (try again later){Colors.ENDC}")
            return []
        except Exception as e:
            if self.verbose:
                print(f"{Colors.WARNING}  [CT] Error querying crt.sh: {str(e)[:60]}{Colors.ENDC}")
            return []


# ═══════════════════════════════════════════════════════════════════
#  PHASE 1: DNS Resolver — Filter Dead Subdomains
# ═══════════════════════════════════════════════════════════════════

class DNSResolver:
    """
    Batch DNS resolution to filter dead subdomains before scanning.
    Multi-threaded for speed. Returns only alive hosts.
    """

    def __init__(self, verbose=False, max_workers=20, timeout=3):
        self.verbose = verbose
        self.max_workers = max_workers
        self.timeout = timeout
        self.alive: List[Dict] = []
        self.dead: List[str] = []
        self.errors: List[str] = []

    def resolve_one(self, subdomain: str) -> Optional[Dict]:
        """Resolve a single subdomain."""
        try:
            socket.setdefaulttimeout(self.timeout)
            ips = socket.getaddrinfo(subdomain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if ips:
                # Get first IPv4 if available, else first result
                ip = None
                for family, _type, _proto, _canon, addr in ips:
                    if family == socket.AF_INET:
                        ip = addr[0]
                        break
                if not ip:
                    ip = ips[0][4][0]

                return {
                    'subdomain': subdomain,
                    'ip': ip,
                    'alive': True,
                }
        except (socket.gaierror, socket.timeout, OSError):
            return None
        return None

    def resolve_batch(self, subdomains: List[str]) -> List[Dict]:
        """Resolve all subdomains in parallel. Returns alive hosts."""
        if self.verbose:
            print(f"{Colors.OKCYAN}  [DNS] Resolving {len(subdomains)} subdomains "
                  f"({self.max_workers} workers)...{Colors.ENDC}")

        self.alive = []
        self.dead = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self.resolve_one, sd): sd for sd in subdomains}
            for future in as_completed(futures):
                sd = futures[future]
                try:
                    result = future.result()
                    if result:
                        self.alive.append(result)
                    else:
                        self.dead.append(sd)
                except Exception:
                    self.dead.append(sd)

        # Deduplicate by IP (multiple subdomains may point to same host)
        seen_ips = {}
        unique_alive = []
        for host in self.alive:
            ip = host['ip']
            if ip not in seen_ips:
                seen_ips[ip] = []
                unique_alive.append(host)
            seen_ips[ip].append(host['subdomain'])

        if self.verbose:
            print(f"{Colors.OKGREEN}  [DNS] {len(self.alive)} alive, {len(self.dead)} dead, "
                  f"{len(seen_ips)} unique IPs{Colors.ENDC}")
            if len(self.alive) > 5 and self.verbose:
                # Show IP clustering
                clustered = [(ip, subs) for ip, subs in seen_ips.items() if len(subs) > 1]
                if clustered:
                    for ip, subs in clustered[:3]:
                        print(f"{Colors.DIM}    {ip} -> {', '.join(subs[:4])}{'...' if len(subs) > 4 else ''}{Colors.ENDC}")

        return self.alive


# ═══════════════════════════════════════════════════════════════════
#  PHASE 1: Subdomain Risk Scorer — Prioritize Attack Surface
# ═══════════════════════════════════════════════════════════════════

class SubdomainRiskScorer:
    """
    Score subdomains by risk priority. High-risk subdomains get scanned first.
    Scoring based on name patterns, server type, HTTP status, and history.
    """

    # Subdomain name patterns that indicate higher risk
    HIGH_RISK_PATTERNS = {
        # Development / staging — often less secured
        'dev': 15, 'develop': 15, 'development': 15,
        'staging': 15, 'stage': 15, 'stg': 15,
        'test': 12, 'testing': 12, 'qa': 12, 'uat': 12,
        'sandbox': 12, 'demo': 10, 'beta': 10, 'alpha': 10,
        'preview': 10, 'pre-prod': 15, 'preprod': 15,
        # Internal / admin — high value targets
        'admin': 20, 'administrator': 20, 'panel': 15,
        'internal': 20, 'intranet': 18, 'private': 15,
        'console': 15, 'dashboard': 12, 'portal': 10,
        'manage': 12, 'manager': 12, 'management': 12,
        'backend': 15, 'backoffice': 15, 'bo': 10,
        'cms': 12, 'crm': 12, 'erp': 15,
        # API endpoints — often expose data
        'api': 15, 'api-v1': 15, 'api-v2': 15,
        'rest': 12, 'graphql': 15, 'grpc': 12,
        'gateway': 10, 'proxy': 10,
        # Infrastructure — might have exposed services
        'jenkins': 20, 'ci': 15, 'cd': 15, 'build': 12,
        'deploy': 12, 'gitlab': 18, 'git': 15, 'svn': 12,
        'docker': 15, 'k8s': 15, 'kubernetes': 15,
        'monitoring': 12, 'grafana': 15, 'kibana': 15,
        'elastic': 12, 'prometheus': 12, 'nagios': 12,
        'sonar': 12, 'sentry': 10, 'jira': 10,
        # Database / storage — jackpot if exposed
        'db': 20, 'database': 20, 'mysql': 20, 'postgres': 20,
        'mongo': 20, 'redis': 18, 'elastic': 15,
        'minio': 15, 's3': 15, 'storage': 12, 'backup': 15,
        'ftp': 12, 'sftp': 12, 'files': 10,
        # Auth / SSO — OAuth misconfigs
        'auth': 15, 'sso': 15, 'login': 12, 'oauth': 15,
        'idp': 15, 'identity': 12, 'accounts': 12,
        # Mail — sometimes has webmail or admin
        'mail': 10, 'webmail': 12, 'smtp': 10, 'imap': 10,
        'exchange': 12, 'owa': 15,
        # VPN / remote access
        'vpn': 15, 'remote': 12, 'rdp': 15, 'citrix': 15,
        'openvpn': 15, 'wireguard': 12,
    }

    # Low-risk patterns — deprioritize
    LOW_RISK_PATTERNS = {
        'www': -10, 'static': -8, 'cdn': -8, 'assets': -8,
        'img': -8, 'images': -8, 'media': -8, 'fonts': -8,
        'status': -5, 'docs': -3, 'help': -5, 'support': -3,
        'blog': -5, 'news': -5, 'marketing': -5,
    }

    @staticmethod
    def score(subdomain: str, domain: str, http_status: int = None,
              server: str = None, ip: str = None) -> Tuple[int, List[str]]:
        """
        Score a subdomain 0-100 for risk. Higher = scan first.
        Returns (score, list_of_risk_factors).
        """
        score = 30  # Base score
        factors = []

        # Extract the subdomain prefix (everything before the main domain)
        prefix = subdomain.replace(f".{domain}", "").lower()
        parts = re.split(r'[.\-_]', prefix)

        # Check name patterns
        for part in parts:
            if part in SubdomainRiskScorer.HIGH_RISK_PATTERNS:
                bonus = SubdomainRiskScorer.HIGH_RISK_PATTERNS[part]
                score += bonus
                factors.append(f"name:{part} (+{bonus})")
            elif part in SubdomainRiskScorer.LOW_RISK_PATTERNS:
                penalty = SubdomainRiskScorer.LOW_RISK_PATTERNS[part]
                score += penalty  # negative value
                factors.append(f"name:{part} ({penalty})")

        # Numeric prefix = likely autogenerated (lower risk)
        if parts and parts[0].isdigit():
            score -= 10
            factors.append("numeric_prefix (-10)")

        # Long subdomain chains = interesting (subdomain.of.subdomain.target.com)
        depth = prefix.count('.') + 1
        if depth >= 3:
            score += 10
            factors.append(f"deep_subdomain:{depth} (+10)")

        # HTTP status scoring
        if http_status:
            if http_status == 200:
                score += 5
                factors.append("http_200 (+5)")
            elif http_status in (401, 403):
                score += 15  # Forbidden = something worth protecting
                factors.append(f"http_{http_status}_auth_required (+15)")
            elif http_status == 301 or http_status == 302:
                score += 3
            elif http_status >= 500:
                score += 10  # Server errors = misconfigured
                factors.append(f"http_{http_status}_error (+10)")

        # Server header analysis
        if server:
            sv = server.lower()
            if any(s in sv for s in ['nginx', 'apache']):
                score += 2
            if any(s in sv for s in ['express', 'kestrel', 'gunicorn', 'uvicorn']):
                score += 5
                factors.append("app_server (+5)")
            if any(s in sv for s in ['iis', 'microsoft']):
                score += 3

        # IP-based scoring
        if ip:
            # Private IP ranges = internal service exposed
            if ip.startswith(('10.', '172.16.', '172.17.', '172.18.',
                              '192.168.', '127.')):
                score += 25
                factors.append(f"private_ip:{ip} (+25)")

        return (min(max(score, 0), 100), factors)

    @staticmethod
    def prioritize(subdomains: List[Dict], domain: str) -> List[Dict]:
        """Score and sort subdomains by risk priority."""
        for sd in subdomains:
            score, factors = SubdomainRiskScorer.score(
                sd['subdomain'], domain,
                http_status=sd.get('http_status'),
                server=sd.get('server'),
                ip=sd.get('ip'),
            )
            sd['risk_score'] = score
            sd['risk_factors'] = factors

        subdomains.sort(key=lambda x: x['risk_score'], reverse=True)
        return subdomains


# ═══════════════════════════════════════════════════════════════════
#  PHASE 1: Async Crawl Engine — Concurrent HTTP Foundation
# ═══════════════════════════════════════════════════════════════════

class AsyncCrawlEngine:
    """
    Async HTTP engine using aiohttp for 5-10x faster concurrent requests.
    Falls back to ThreadPoolExecutor if aiohttp not available.
    Used for: subdomain probing, batch URL fetching, alive checks.
    """

    def __init__(self, max_concurrent: int = 30, timeout: int = 8,
                 rate_limit: float = 0, verbose: bool = False,
                 ua: str = None):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.verbose = verbose
        self.ua = ua or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.results: List[Dict] = []

    def probe_subdomains(self, subdomains: List[str],
                         ports: List[int] = None) -> List[Dict]:
        """
        Probe subdomains for HTTP(S) services. Returns alive hosts with metadata.
        Uses async if available, falls back to threaded.
        """
        ports = ports or [443, 80]
        targets = []
        for sd in subdomains:
            for port in ports:
                scheme = 'https' if port == 443 else 'http'
                targets.append(f"{scheme}://{sd}:{port}" if port not in (80, 443)
                               else f"{scheme}://{sd}")

        if HAS_ASYNC:
            return self._probe_async(targets)
        else:
            return self._probe_threaded(targets)

    def _probe_async(self, urls: List[str]) -> List[Dict]:
        """Async probing with aiohttp."""
        results = []

        async def _probe_one(session, url, sem):
            async with sem:
                try:
                    if self.rate_limit > 0:
                        await asyncio.sleep(1.0 / self.rate_limit)
                    timeout = aiohttp.ClientTimeout(total=self.timeout)
                    async with session.get(url, timeout=timeout,
                                           allow_redirects=True,
                                           ssl=False) as resp:
                        server = resp.headers.get('Server', '')
                        content_type = resp.headers.get('Content-Type', '')
                        title = ''
                        # Read small chunk for title extraction
                        body = await resp.read()
                        body_text = body[:4000].decode('utf-8', errors='ignore')
                        m = re.search(r'<title[^>]*>([^<]+)</title>', body_text, re.I)
                        if m:
                            title = m.group(1).strip()[:80]

                        return {
                            'url': url,
                            'subdomain': urlparse(url).netloc,
                            'status': resp.status,
                            'server': server,
                            'content_type': content_type,
                            'title': title,
                            'content_length': len(body),
                            'redirect_url': str(resp.url) if str(resp.url) != url else '',
                            'alive': True,
                        }
                except Exception:
                    return None

        async def _run():
            sem = asyncio.Semaphore(self.max_concurrent)
            connector = aiohttp.TCPConnector(limit=self.max_concurrent, ssl=False)
            headers = {'User-Agent': self.ua}
            async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
                tasks = [_probe_one(session, url, sem) for url in urls]
                return await asyncio.gather(*tasks)

        if self.verbose:
            print(f"{Colors.OKCYAN}  [ASYNC] Probing {len(urls)} URLs "
                  f"({self.max_concurrent} concurrent)...{Colors.ENDC}")

        # Run the async event loop
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            raw_results = loop.run_until_complete(_run())
            loop.close()
        except Exception as e:
            if self.verbose:
                print(f"{Colors.WARNING}  [ASYNC] Fallback to threaded: {e}{Colors.ENDC}")
            return self._probe_threaded(urls)

        results = [r for r in raw_results if r is not None]
        if self.verbose:
            print(f"{Colors.OKGREEN}  [ASYNC] {len(results)}/{len(urls)} responded{Colors.ENDC}")
        return results

    def _probe_threaded(self, urls: List[str]) -> List[Dict]:
        """Fallback threaded probing."""
        results = []

        def _probe(url):
            try:
                resp = requests.get(url, timeout=self.timeout, verify=False,
                                    allow_redirects=True,
                                    headers={'User-Agent': self.ua})
                server = resp.headers.get('Server', '')
                title = ''
                m = re.search(r'<title[^>]*>([^<]+)</title>', resp.text[:4000], re.I)
                if m:
                    title = m.group(1).strip()[:80]
                return {
                    'url': url,
                    'subdomain': urlparse(url).netloc,
                    'status': resp.status_code,
                    'server': server,
                    'content_type': resp.headers.get('Content-Type', ''),
                    'title': title,
                    'content_length': len(resp.content),
                    'redirect_url': resp.url if resp.url != url else '',
                    'alive': True,
                }
            except Exception:
                return None

        if self.verbose:
            print(f"{Colors.OKCYAN}  [THREAD] Probing {len(urls)} URLs "
                  f"({min(self.max_concurrent, len(urls))} workers)...{Colors.ENDC}")

        with ThreadPoolExecutor(max_workers=min(self.max_concurrent, len(urls))) as pool:
            futures = {pool.submit(_probe, u): u for u in urls}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)

        if self.verbose:
            print(f"{Colors.OKGREEN}  [THREAD] {len(results)}/{len(urls)} responded{Colors.ENDC}")
        return results

    @staticmethod
    def dedupe_by_subdomain(results: List[Dict]) -> List[Dict]:
        """Keep best result per subdomain (prefer HTTPS, prefer 200)."""
        best = {}
        for r in results:
            sd = r['subdomain']
            if sd not in best:
                best[sd] = r
            else:
                existing = best[sd]
                # Prefer HTTPS
                if r['url'].startswith('https://') and existing['url'].startswith('http://'):
                    best[sd] = r
                # Prefer 200 over others
                elif r['status'] == 200 and existing['status'] != 200:
                    best[sd] = r
        return list(best.values())


# ═══════════════════════════════════════════════════════════════════
#  PHASE 1: Smart Router — Adaptive Module Selection
# ═══════════════════════════════════════════════════════════════════

class SmartRouter:
    """
    Intelligence-driven scanning. Analyzes each target and enables
    only the modules that make sense for that specific asset.

    This is the core differentiator: per-target module selection, not
    blanket scanning. Most tools scan everything everywhere. SecretPulse chooses.
    """

    # Asset classification rules: pattern → asset type
    ASSET_RULES = {
        'api': {
            'type': 'api_service',
            'modules': ['cors_check', 'jwt_exploit', 'probe_graphql', 'probe_swagger', 'fuzz_idor'],
            'reason': 'API endpoint — test auth, CORS, schema exposure',
        },
        'graphql': {
            'type': 'api_service',
            'modules': ['probe_graphql', 'cors_check', 'jwt_exploit'],
            'reason': 'GraphQL service — introspection + auth testing',
        },
        'rest': {
            'type': 'api_service',
            'modules': ['cors_check', 'jwt_exploit', 'probe_swagger', 'fuzz_idor'],
            'reason': 'REST API — schema + auth + access control',
        },
        'admin': {
            'type': 'admin_panel',
            'modules': ['open_redirect', 'cors_check', 'probe_env'],
            'reason': 'Admin panel — high value, test for XSS + redirect + env leak',
        },
        'panel': {
            'type': 'admin_panel',
            'modules': ['open_redirect', 'cors_check', 'probe_env'],
            'reason': 'Control panel — test auth bypass vectors',
        },
        'dashboard': {
            'type': 'admin_panel',
            'modules': ['open_redirect', 'cors_check'],
            'reason': 'Dashboard — client-side injection + redirect chains',
        },
        'console': {
            'type': 'admin_panel',
            'modules': ['probe_env', 'cors_check'],
            'reason': 'Console — likely management interface',
        },
        'internal': {
            'type': 'internal',
            'modules': ['probe_env', 'ssrf_probe', 'cors_check'],
            'reason': 'Internal service — often less hardened',
        },
        'intranet': {
            'type': 'internal',
            'modules': ['probe_env', 'ssrf_probe', 'cors_check'],
            'reason': 'Intranet — exposed internal tools',
        },
        'staging': {
            'type': 'staging',
            'modules': ['probe_env', 'cors_check', 'open_redirect'],
            'reason': 'Staging env — debug mode, exposed configs likely',
        },
        'dev': {
            'type': 'staging',
            'modules': ['probe_env', 'cors_check', 'probe_swagger'],
            'reason': 'Dev environment — weak security posture expected',
        },
        'test': {
            'type': 'staging',
            'modules': ['probe_env', 'cors_check'],
            'reason': 'Test environment — may have debug endpoints',
        },
        'auth': {
            'type': 'auth_service',
            'modules': ['jwt_exploit', 'cors_check', 'open_redirect'],
            'reason': 'Auth service — JWT + OAuth redirect chains',
        },
        'sso': {
            'type': 'auth_service',
            'modules': ['jwt_exploit', 'cors_check', 'open_redirect'],
            'reason': 'SSO — token manipulation + redirect bypass',
        },
        'login': {
            'type': 'auth_service',
            'modules': ['jwt_exploit', 'open_redirect', 'cors_check'],
            'reason': 'Login endpoint — credential + redirect attacks',
        },
        'oauth': {
            'type': 'auth_service',
            'modules': ['jwt_exploit', 'open_redirect', 'cors_check'],
            'reason': 'OAuth endpoint — redirect_uri + state bypass',
        },
        'storage': {
            'type': 'cloud_storage',
            'modules': ['cloud_perms', 'scan_cloud'],
            'reason': 'Storage service — test read/write permissions',
        },
        's3': {
            'type': 'cloud_storage',
            'modules': ['cloud_perms', 'scan_cloud'],
            'reason': 'S3 reference — bucket permission testing',
        },
        'cdn': {
            'type': 'static_asset',
            'modules': ['dep_confusion'],
            'reason': 'CDN — check source maps for dependency confusion',
        },
        'static': {
            'type': 'static_asset',
            'modules': ['dep_confusion'],
            'reason': 'Static assets — source map intelligence only',
        },
        'assets': {
            'type': 'static_asset',
            'modules': ['dep_confusion'],
            'reason': 'Asset server — source map mining',
        },
        'jenkins': {
            'type': 'ci_cd',
            'modules': ['probe_env', 'cors_check', 'ssrf_probe'],
            'reason': 'Jenkins CI — credential exposure + SSRF',
        },
        'gitlab': {
            'type': 'ci_cd',
            'modules': ['probe_env', 'cors_check'],
            'reason': 'GitLab — repo access + secret exposure',
        },
        'ci': {
            'type': 'ci_cd',
            'modules': ['probe_env', 'cors_check'],
            'reason': 'CI/CD — pipeline secrets',
        },
        'grafana': {
            'type': 'monitoring',
            'modules': ['cors_check', 'ssrf_probe', 'probe_env'],
            'reason': 'Grafana — SSRF via data sources + default creds',
        },
        'kibana': {
            'type': 'monitoring',
            'modules': ['cors_check', 'ssrf_probe'],
            'reason': 'Kibana — data access + SSRF',
        },
        'db': {
            'type': 'database',
            'modules': ['probe_env', 'ssrf_probe'],
            'reason': 'Database interface — connection string exposure',
        },
        'mongo': {
            'type': 'database',
            'modules': ['probe_env', 'cloud_perms'],
            'reason': 'MongoDB — open access testing',
        },
        'redis': {
            'type': 'database',
            'modules': ['probe_env', 'ssrf_probe'],
            'reason': 'Redis — unauthenticated access',
        },
        'mail': {
            'type': 'email',
            'modules': ['cors_check', 'open_redirect'],
            'reason': 'Mail service — phishing redirect potential',
        },
        'vpn': {
            'type': 'remote_access',
            'modules': ['cors_check', 'probe_env'],
            'reason': 'VPN — credential exposure',
        },
    }

    # Default modules for unknown asset types
    DEFAULT_MODULES = [
        'probe_env', 'cors_check', 'open_redirect',
        'probe_graphql', 'probe_swagger',
    ]

    # Always-on modules (run on every target regardless)
    ALWAYS_ON = ['scan_cloud', 'sensitive_files', 'takeover']

    @staticmethod
    def classify(subdomain: str, domain: str, http_data: dict = None) -> dict:
        """
        Classify a subdomain and determine which modules to enable.
        Returns: {'type': str, 'modules': list, 'reasons': list}
        """
        prefix = subdomain.replace(f".{domain}", "").lower()
        parts = re.split(r'[.\-_]', prefix)

        matched_modules = set()
        matched_types = set()
        reasons = []

        for part in parts:
            if part in SmartRouter.ASSET_RULES:
                rule = SmartRouter.ASSET_RULES[part]
                matched_modules.update(rule['modules'])
                matched_types.add(rule['type'])
                reasons.append(rule['reason'])

        # HTTP-based classification
        if http_data:
            title = (http_data.get('title', '') or '').lower()
            server = (http_data.get('server', '') or '').lower()
            ct = (http_data.get('content_type', '') or '').lower()

            # JSON API response → enable API modules
            if 'application/json' in ct:
                matched_modules.update(['cors_check', 'jwt_exploit', 'fuzz_idor'])
                matched_types.add('api_service')
                reasons.append('JSON content-type — likely API')

            # GraphQL indicator in response
            if 'graphql' in title or 'graphiql' in title:
                matched_modules.update(['probe_graphql', 'cors_check'])
                reasons.append('GraphQL detected in title')

            # Swagger/OpenAPI indicator
            if 'swagger' in title or 'openapi' in title:
                matched_modules.update(['probe_swagger', 'cors_check'])
                reasons.append('Swagger/OpenAPI detected')

            # Login page
            if any(kw in title for kw in ['login', 'sign in', 'log in', 'authenticate']):
                matched_modules.update(['jwt_exploit', 'open_redirect', 'cors_check'])
                matched_types.add('auth_service')
                reasons.append('Login page detected')

            # Admin indicators
            if any(kw in title for kw in ['admin', 'dashboard', 'panel', 'console', 'management']):
                matched_modules.update(['probe_env', 'cors_check'])
                matched_types.add('admin_panel')
                reasons.append('Admin interface detected in title')

            # Server-based hints
            if 'express' in server or 'node' in server:
                matched_modules.add('dep_confusion')
                reasons.append('Node.js server — check npm deps')
            if 'nginx' in server and http_data.get('status') == 403:
                matched_modules.add('probe_env')
                reasons.append('Nginx 403 — might have hidden paths')

        # Fallback: if nothing matched, use defaults
        if not matched_modules:
            matched_modules = set(SmartRouter.DEFAULT_MODULES)
            matched_types.add('web_app')
            reasons.append('Unknown asset type — using default modules')

        # Always-on modules
        matched_modules.update(SmartRouter.ALWAYS_ON)

        # Determine primary type
        type_priority = ['auth_service', 'admin_panel', 'api_service', 'ci_cd',
                         'database', 'internal', 'staging', 'cloud_storage',
                         'monitoring', 'remote_access', 'email', 'static_asset', 'web_app']
        primary_type = 'web_app'
        for t in type_priority:
            if t in matched_types:
                primary_type = t
                break

        if primary_type == 'static_asset':
            matched_modules.discard('sensitive_files')

        return {
            'type': primary_type,
            'modules': sorted(matched_modules),
            'reasons': reasons,
        }

    @staticmethod
    def plan(targets: List[dict], domain: str, verbose: bool = False) -> List[dict]:
        """
        Build a scan plan: for each target, determine what to scan.
        Returns targets enriched with module selections.
        """
        plans = []
        module_usage = defaultdict(int)

        for target in targets:
            sd = target.get('subdomain', '')
            classification = SmartRouter.classify(sd, domain, target)
            target['smart_type'] = classification['type']
            target['smart_modules'] = classification['modules']
            target['smart_reasons'] = classification['reasons']
            plans.append(target)

            for mod in classification['modules']:
                module_usage[mod] += 1

        if verbose or True:  # Always show the plan — it's the key feature
            print(f"\n{Colors.BOLD}{'=' * 60}")
            print(f"  SMART SCAN PLAN — {len(plans)} targets")
            print(f"{'=' * 60}{Colors.ENDC}")

            # Group by type
            by_type = defaultdict(list)
            for p in plans:
                by_type[p['smart_type']].append(p)

            type_colors = {
                'auth_service': Colors.FAIL,
                'admin_panel': Colors.FAIL,
                'api_service': Colors.WARNING,
                'ci_cd': Colors.FAIL,
                'database': Colors.FAIL,
                'internal': Colors.WARNING,
                'staging': Colors.WARNING,
                'cloud_storage': Colors.OKCYAN,
                'monitoring': Colors.OKCYAN,
                'web_app': Colors.DIM,
                'static_asset': Colors.DIM,
            }

            type_order = ['auth_service', 'admin_panel', 'database', 'ci_cd',
                          'api_service', 'internal', 'staging', 'monitoring',
                          'cloud_storage', 'web_app', 'static_asset']

            for asset_type in type_order:
                group = by_type.get(asset_type, [])
                if not group:
                    continue
                color = type_colors.get(asset_type, Colors.DIM)
                label = asset_type.upper().replace('_', ' ')
                print(f"\n  {color}{label} ({len(group)}):{Colors.ENDC}")
                for p in group[:8]:
                    mods = ', '.join(m for m in p['smart_modules']
                                     if m not in SmartRouter.ALWAYS_ON)
                    reason = p['smart_reasons'][0] if p['smart_reasons'] else ''
                    print(f"    [{p.get('risk_score', 0):3d}] {p['subdomain']}")
                    print(f"         {Colors.DIM}modules: {mods}{Colors.ENDC}")
                    if reason:
                        print(f"         {Colors.DIM}reason: {reason}{Colors.ENDC}")
                if len(group) > 8:
                    print(f"    {Colors.DIM}... +{len(group) - 8} more{Colors.ENDC}")

            # Module usage summary
            print(f"\n  {Colors.BOLD}Module Activation:{Colors.ENDC}")
            for mod, count in sorted(module_usage.items(), key=lambda x: -x[1]):
                if mod in SmartRouter.ALWAYS_ON:
                    continue
                bar = '+' * min(count, 30)
                print(f"    {mod:20s} {bar} ({count})")
            print()

        return plans

    @staticmethod
    def get_modules_for_url(url: str, plans: List[dict]) -> set:
        """Given a URL, return which modules should be active for it."""
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()

        for plan in plans:
            if plan.get('subdomain', '').lower() == netloc:
                return set(plan.get('smart_modules', []))

        # URL not in plan — return defaults + always-on
        return set(SmartRouter.DEFAULT_MODULES + SmartRouter.ALWAYS_ON)



class ReconOrchestrator:
    """
    Orchestrates the full recon pipeline:
    1. CT log query → raw subdomains
    2. DNS resolution → filter dead
    3. HTTP probing → check alive with metadata
    4. Risk scoring → prioritize targets
    5. Store in DB → persist for incremental scans
    """

    def __init__(self, session, db: SecretPulseDB = None, verbose: bool = False,
                 rate_limit: float = 0, max_workers: int = 20):
        self.session = session
        self.db = db
        self.verbose = verbose
        self.ct = CertTransparency(session, verbose)
        self.dns = DNSResolver(verbose, max_workers=max_workers)
        self.async_engine = AsyncCrawlEngine(
            max_concurrent=max_workers, rate_limit=rate_limit, verbose=verbose
        )
        self.subdomains: List[Dict] = []
        self.stats = {
            'ct_total': 0, 'dns_alive': 0, 'dns_dead': 0,
            'http_alive': 0, 'high_risk': 0,
        }

    def discover(self, domain: str, skip_dns: bool = False) -> List[Dict]:
        """
        Full recon pipeline. Returns prioritized list of alive subdomains.
        """
        print(f"\n{Colors.BOLD}{'=' * 60}")
        print(f"  RECON: Subdomain Discovery & Risk Scoring")
        print(f"{'=' * 60}{Colors.ENDC}")

        # Step 1: CT log query
        raw_subdomains = self.ct.query(domain)
        self.stats['ct_total'] = len(raw_subdomains)
        if not raw_subdomains:
            print(f"{Colors.WARNING}  [!] No subdomains found via CT logs{Colors.ENDC}")
            return []

        # Step 2: DNS resolution
        if not skip_dns:
            alive_hosts = self.dns.resolve_batch(raw_subdomains)
            self.stats['dns_alive'] = len(alive_hosts)
            self.stats['dns_dead'] = len(self.dns.dead)
        else:
            alive_hosts = [{'subdomain': s, 'ip': None, 'alive': True} for s in raw_subdomains]
            self.stats['dns_alive'] = len(alive_hosts)

        if not alive_hosts:
            print(f"{Colors.WARNING}  [!] No subdomains resolved — all appear dead{Colors.ENDC}")
            return []

        # Step 3: HTTP probing
        alive_subs = [h['subdomain'] for h in alive_hosts]
        http_results = self.async_engine.probe_subdomains(alive_subs)
        http_results = AsyncCrawlEngine.dedupe_by_subdomain(http_results)
        self.stats['http_alive'] = len(http_results)

        # Merge DNS + HTTP data
        ip_map = {h['subdomain']: h.get('ip') for h in alive_hosts}
        for r in http_results:
            r['ip'] = ip_map.get(r['subdomain'], '')

        # Step 4: Risk scoring
        scored = SubdomainRiskScorer.prioritize(http_results, domain)
        self.stats['high_risk'] = sum(1 for s in scored if s['risk_score'] >= 60)
        self.subdomains = scored

        # Step 5: Store in DB
        if self.db:
            for sd in scored:
                self.db.save_subdomain(
                    domain=domain,
                    subdomain=sd['subdomain'],
                    source='ct',
                    is_alive=True,
                    ip_address=sd.get('ip'),
                    risk_score=sd['risk_score'],
                    risk_factors=sd.get('risk_factors', []),
                )

        # Print summary
        self._print_results(domain, scored)
        return scored

    def _print_results(self, domain: str, scored: List[Dict]):
        """Display discovered subdomains grouped by risk."""
        print(f"\n{Colors.BOLD}  Recon Results for {domain}{Colors.ENDC}")
        print(f"  CT entries: {self.stats['ct_total']} | "
              f"DNS alive: {self.stats['dns_alive']} | "
              f"HTTP alive: {self.stats['http_alive']} | "
              f"High risk: {self.stats['high_risk']}")
        print()

        # Group by risk tier
        critical = [s for s in scored if s['risk_score'] >= 70]
        high     = [s for s in scored if 50 <= s['risk_score'] < 70]
        medium   = [s for s in scored if 30 <= s['risk_score'] < 50]
        low      = [s for s in scored if s['risk_score'] < 30]

        for label, group, color in [
            ("HIGH PRIORITY", critical, Colors.FAIL),
            ("MEDIUM PRIORITY", high, Colors.WARNING),
            ("NORMAL", medium, Colors.OKCYAN),
            ("LOW PRIORITY", low, Colors.DIM),
        ]:
            if not group:
                continue
            print(f"  {color}{label} ({len(group)}):{Colors.ENDC}")
            for sd in group[:10]:  # Show top 10 per tier
                risk = sd['risk_score']
                status = sd.get('status', '?')
                title = sd.get('title', '')[:40]
                server = sd.get('server', '')[:20]
                factors = ', '.join(sd.get('risk_factors', [])[:3])

                print(f"    {color}[{risk:3d}] {sd['subdomain']}{Colors.ENDC}"
                      f"  HTTP:{status}"
                      f"  {title}"
                      f"  {Colors.DIM}{factors}{Colors.ENDC}")
            if len(group) > 10:
                print(f"    {Colors.DIM}... and {len(group) - 10} more{Colors.ENDC}")
            print()

    def get_scan_urls(self, top_n: int = None) -> List[str]:
        """Get prioritized URLs to feed into the scanner."""
        urls = []
        subs = self.subdomains[:top_n] if top_n else self.subdomains
        for sd in subs:
            urls.append(sd.get('url', f"https://{sd['subdomain']}"))
        return urls
