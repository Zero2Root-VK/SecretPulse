"""Source-map, supply-chain, false-positive, and confidence analysis."""
from ._imports import *
from .utils import line_context, shannon_entropy

class SourceMapAnalyzer:
    """
    Deep source map analysis: file tree, framework detection,
    dependency mapping, comment mining for secrets.
    """

    FRAMEWORK_SIGNATURES = {
        'React': ['react-dom', 'react/jsx', 'useState', 'useEffect', 'createContext'],
        'Next.js': ['next/router', 'next/link', 'next/image', '_next/', 'getServerSideProps'],
        'Vue.js': ['vue/dist', '.vue', 'vuex', 'vue-router', 'createApp'],
        'Nuxt': ['nuxt/', '.nuxt/', 'nuxt.config'],
        'Angular': ['@angular/', 'angular/core', 'ngModule', 'zone.js'],
        'Svelte': ['svelte/', '.svelte', 'svelte/internal'],
        'Ember': ['ember/', '@ember/', 'ember-cli'],
        'Gatsby': ['gatsby/', 'gatsby-browser', 'gatsby-ssr'],
        'Remix': ['remix/', '@remix-run/'],
    }

    SECRET_COMMENT_PATTERNS = [
        (r'(?://|#|/\*)\s*(?:TODO|FIXME|HACK|XXX|BUG)\s*[:\-]?\s*(.{10,120})', 'TODO/FIXME'),
        (r'(?://|#|/\*)\s*(?:password|secret|token|key|api.?key)\s*[:\-=]\s*(.{5,120})', 'Secret Comment'),
        (r'(?://|#|/\*)\s*(?:TEMP|TEMPORARY|REMOVE|DELETE)\s*[:\-]?\s*(.{5,120})', 'Temp Note'),
    ]

    @staticmethod
    def analyze(sm_data: Dict, map_url: str) -> Dict:
        """Analyze a parsed source map JSON object."""
        sources = sm_data.get('sources', [])
        sources_content = sm_data.get('sourcesContent', [])

        intel = {
            'url': map_url,
            'total_files': len(sources),
            'total_lines': 0,
            'frameworks': [],
            'npm_packages': [],
            'file_tree': [],
            'comments': [],
            'directories': set(),
        }

        # ── File tree & directory structure ──
        pkg_set = set()
        for path in sources:
            intel['file_tree'].append(path)
            parts = path.replace('\\', '/').split('/')
            # Extract npm packages from node_modules paths
            for i, part in enumerate(parts):
                if part == 'node_modules' and i + 1 < len(parts):
                    pkg_name = parts[i + 1]
                    if pkg_name.startswith('@') and i + 2 < len(parts):
                        pkg_name = f"{pkg_name}/{parts[i + 2]}"
                    pkg_set.add(pkg_name)
            # Build directory set
            if len(parts) > 1:
                intel['directories'].add('/'.join(parts[:-1]))

        intel['npm_packages'] = sorted(pkg_set)

        # ── Framework detection ──
        all_sources_str = ' '.join(sources)
        for framework, signatures in SourceMapAnalyzer.FRAMEWORK_SIGNATURES.items():
            if any(sig in all_sources_str for sig in signatures):
                intel['frameworks'].append(framework)

        # Also check sourcesContent for framework imports
        content_sample = ''
        for i, content in enumerate(sources_content or []):
            if content and isinstance(content, str):
                intel['total_lines'] += content.count('\n') + 1
                if len(content_sample) < 50000:
                    content_sample += content[:5000]

        if content_sample:
            for framework, signatures in SourceMapAnalyzer.FRAMEWORK_SIGNATURES.items():
                if framework not in intel['frameworks']:
                    if any(sig in content_sample for sig in signatures):
                        intel['frameworks'].append(framework)

        # ── Comment mining ──
        for i, content in enumerate(sources_content or []):
            if not content or not isinstance(content, str):
                continue
            fname = sources[i] if i < len(sources) else 'unknown'
            for pattern, label in SourceMapAnalyzer.SECRET_COMMENT_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    comment_text = match.group(1).strip()
                    if len(comment_text) > 5:
                        intel['comments'].append({
                            'type': label, 'text': comment_text[:200],
                            'file': fname,
                        })

        intel['directories'] = sorted(intel['directories'])[:30]
        intel['file_tree'] = intel['file_tree'][:100]  # Cap display
        return intel


# ═══════════════════════════════════════════════════════════════════
#  Supply Chain Mapper — v2.9 (NEW)
# ═══════════════════════════════════════════════════════════════════

class SupplyChainMapper:
    """
    Maps 3rd-party JS dependencies, detects vulnerable library versions,
    checks SRI integrity, and builds a supply chain risk inventory.
    """

    # Known vulnerable library versions — v3.0: 50+ entries (was 10 in v2.9)
    # Format: (vuln_below_version, severity, CVE/description)
    VULNERABLE_LIBS = {
        'jquery': [
            ('3.5.0', 'MEDIUM', 'XSS via htmlPrefilter — CVE-2020-11022/11023'),
            ('3.0.0', 'HIGH', 'Selector XSS — CVE-2015-9251, CVE-2019-11358'),
            ('2.2.0', 'HIGH', 'XSS + prototype pollution — multiple CVEs'),
            ('1.12.0', 'CRITICAL', 'Arbitrary code execution — CVE-2015-9251'),
        ],
        'jquery-ui': [
            ('1.13.2', 'MEDIUM', 'XSS in dialog/tooltip — CVE-2022-31160'),
            ('1.12.0', 'HIGH', 'XSS via .position() — CVE-2021-41184'),
        ],
        'angular': [
            ('1.6.0', 'HIGH', 'Sandbox escape / XSS — CVE-2020-7676'),
            ('1.8.0', 'MEDIUM', 'Prototype pollution — CVE-2022-25869'),
        ],
        'angularjs': [
            ('1.8.0', 'MEDIUM', 'Prototype pollution / ReDoS'),
        ],
        'lodash': [
            ('4.17.21', 'HIGH', 'Prototype pollution — CVE-2021-23337'),
            ('4.17.12', 'CRITICAL', 'Prototype pollution — CVE-2019-10744'),
            ('4.17.5', 'HIGH', 'Prototype pollution — CVE-2018-16487'),
        ],
        'underscore': [
            ('1.13.6', 'MEDIUM', 'Code injection — CVE-2021-23358'),
            ('1.12.1', 'HIGH', 'Template injection — CVE-2021-23358'),
        ],
        'bootstrap': [
            ('5.2.0', 'LOW', 'Minor XSS in data-bs-* attributes'),
            ('4.3.1', 'MEDIUM', 'XSS via data-attributes — CVE-2019-8331'),
            ('3.4.0', 'MEDIUM', 'XSS in tooltip/popover — CVE-2018-14040'),
            ('3.0.0', 'HIGH', 'Multiple XSS — CVE-2016-10735'),
        ],
        'moment': [
            ('2.29.4', 'MEDIUM', 'ReDoS — CVE-2022-31129'),
            ('2.19.3', 'HIGH', 'Path traversal — CVE-2017-18214'),
        ],
        'axios': [
            ('1.6.0', 'HIGH', 'CSRF/SSRF bypass — CVE-2023-45857'),
            ('1.3.2', 'HIGH', 'SSRF via proxy — CVE-2023-45857'),
            ('0.21.1', 'MEDIUM', 'ReDoS in content-type parsing'),
        ],
        'dompurify': [
            ('3.0.6', 'HIGH', 'mXSS bypass — CVE-2023-48219'),
            ('2.4.1', 'HIGH', 'XSS bypass — CVE-2023-23631'),
            ('2.0.0', 'CRITICAL', 'Multiple bypass vectors'),
        ],
        'handlebars': [
            ('4.7.7', 'HIGH', 'Prototype pollution — CVE-2021-23369'),
            ('4.7.6', 'CRITICAL', 'RCE via template — CVE-2021-23383'),
        ],
        'vue': [
            ('3.2.47', 'LOW', 'Potential XSS in SSR hydration'),
            ('2.7.14', 'LOW', 'XSS via v-html directive'),
        ],
        'react-dom': [
            ('16.13.0', 'LOW', 'XSS via dangerouslySetInnerHTML edge case'),
        ],
        'express': [
            ('4.17.3', 'MEDIUM', 'Open redirect — CVE-2022-24999'),
        ],
        'next': [
            ('13.4.6', 'HIGH', 'SSRF via Server Actions — CVE-2023-46298'),
            ('12.3.0', 'MEDIUM', 'Open redirect — CVE-2023-27490'),
        ],
        'socket.io': [
            ('4.6.2', 'MEDIUM', 'DoS via malformed packet — CVE-2023-32695'),
            ('2.4.0', 'HIGH', 'Unauthorized access — CVE-2020-36049'),
        ],
        'marked': [
            ('4.0.10', 'HIGH', 'ReDoS — CVE-2022-21680/21681'),
            ('2.0.0', 'CRITICAL', 'XSS via HTML injection'),
        ],
        'highlight.js': [
            ('10.4.1', 'MEDIUM', 'Prototype pollution — CVE-2020-26237'),
        ],
        'chart.js': [
            ('2.9.4', 'LOW', 'Prototype pollution via config merge'),
        ],
        'tinymce': [
            ('5.10.0', 'HIGH', 'Stored XSS — CVE-2022-23494'),
        ],
        'ckeditor': [
            ('4.16.0', 'HIGH', 'XSS — CVE-2021-32808/32809'),
        ],
        'quill': [
            ('1.3.7', 'MEDIUM', 'XSS via paste handler — CVE-2021-3163'),
        ],
        'sweetalert2': [
            ('11.4.8', 'MEDIUM', 'XSS via HTML content'),
        ],
        'select2': [
            ('4.0.13', 'MEDIUM', 'XSS via title attribute — CVE-2022-40897'),
        ],
        'datatables': [
            ('1.10.0', 'MEDIUM', 'XSS via data rendering — CVE-2020-28458'),
        ],
        'd3': [
            ('5.0.0', 'LOW', 'Prototype pollution edge case'),
        ],
        'three': [
            ('0.125.0', 'LOW', 'Potential SSRF via loader URLs'),
        ],
        'lottie-web': [
            ('5.7.4', 'MEDIUM', 'XSS via SVG animation — CVE-2022-1466'),
        ],
        'video.js': [
            ('7.17.0', 'MEDIUM', 'XSS via text tracks — CVE-2021-43257'),
        ],
        'plyr': [
            ('3.6.9', 'MEDIUM', 'XSS via captions — CVE-2021-23369'),
        ],
        'backbone': [
            ('1.4.0', 'LOW', 'Model injection via set()'),
        ],
        'ember': [
            ('3.28.0', 'MEDIUM', 'Prototype pollution — CVE-2022-0235'),
        ],
        'polymer': [
            ('3.0.0', 'LOW', 'DOM XSS via data binding'),
        ],
        'knockout': [
            ('3.5.0', 'MEDIUM', 'Template injection — CVE-2019-14862'),
        ],
        'mustache': [
            ('4.2.0', 'LOW', 'Potential template injection'),
        ],
        'ejs': [
            ('3.1.7', 'CRITICAL', 'RCE via template injection — CVE-2022-29078'),
        ],
        'pug': [
            ('3.0.1', 'HIGH', 'Code injection via attributes — CVE-2021-21353'),
        ],
        'sanitize-html': [
            ('2.3.2', 'HIGH', 'XSS bypass — CVE-2021-26539'),
        ],
        'ua-parser-js': [
            ('0.7.31', 'CRITICAL', 'Supply chain attack — CVE-2021-44906'),
        ],
        'minimist': [
            ('1.2.6', 'CRITICAL', 'Prototype pollution — CVE-2021-44906'),
        ],
        'node-fetch': [
            ('2.6.7', 'HIGH', 'SSRF bypass — CVE-2022-0235'),
        ],
        'glob-parent': [
            ('5.1.2', 'HIGH', 'ReDoS — CVE-2020-28469'),
        ],
        'trim-newlines': [
            ('3.0.1', 'HIGH', 'ReDoS — CVE-2021-33623'),
        ],
        'json5': [
            ('2.2.2', 'MEDIUM', 'Prototype pollution — CVE-2022-46175'),
        ],
        'got': [
            ('11.8.5', 'MEDIUM', 'Open redirect — CVE-2022-33987'),
        ],
        'terser': [
            ('5.14.2', 'MEDIUM', 'ReDoS — CVE-2022-25858'),
        ],
    }

    # CDN exploit correlation — v3.0
    CDN_RISK_INTEL = {
        'cdn.jsdelivr.net': {
            'risk': 'MEDIUM',
            'notes': 'jsdelivr has served compromised packages (ua-parser-js, '
                     'colors, faker). Packages pulled directly from npm.',
        },
        'unpkg.com': {
            'risk': 'MEDIUM',
            'notes': 'unpkg mirrors npm — inherits supply chain risks. '
                     'No additional vetting.',
        },
        'cdnjs.cloudflare.com': {
            'risk': 'LOW',
            'notes': 'Cloudflare-hosted, manually curated. Lower supply chain risk.',
        },
        'cdn.bootcdn.net': {
            'risk': 'HIGH',
            'notes': 'Chinese CDN — potential MitM, HTTPS enforcement varies.',
        },
        'lib.baomitu.com': {
            'risk': 'HIGH',
            'notes': 'Regional CDN with limited security auditing.',
        },
        'ajax.aspnetcdn.com': {
            'risk': 'LOW',
            'notes': 'Microsoft-hosted CDN, well-maintained.',
        },
        'code.jquery.com': {
            'risk': 'LOW',
            'notes': 'Official jQuery CDN, MaxCDN/StackPath backed.',
        },
    }

    # CDN URL patterns to extract library name + version
    CDN_PATTERNS = [
        # cdnjs: /ajax/libs/{lib}/{version}/{file}
        r'cdnjs\.cloudflare\.com/ajax/libs/([a-z0-9\.\-]+)/([0-9][0-9a-z\.\-]*)',
        # unpkg: /package@version/file
        r'unpkg\.com/([a-z0-9@/\.\-]+)@([0-9][0-9a-z\.\-]*)',
        # jsdelivr: /npm/package@version/file
        r'cdn\.jsdelivr\.net/npm/([a-z0-9@/\.\-]+)@([0-9][0-9a-z\.\-]*)',
        # Google hosted: /ajax/libs/{lib}/{version}/{file}
        r'ajax\.googleapis\.com/ajax/libs/([a-z0-9\.\-]+)/([0-9][0-9a-z\.\-]*)',
        # generic: /lib-name/version/ or /lib-name.min.js
        r'/([a-z][a-z0-9\-]{1,30})[/\.\-]([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)',
    ]

    # Common inline version patterns in JS content
    INLINE_VERSION_PATTERNS = [
        r'(?:jQuery|jquery)\s+v?([0-9]+\.[0-9]+\.[0-9]+)',
        r'Bootstrap\s+v?([0-9]+\.[0-9]+\.[0-9]+)',
        r'Lodash\s+v?([0-9]+\.[0-9]+\.[0-9]+)',
        r'Angular(?:JS)?\s+v?([0-9]+\.[0-9]+\.[0-9]+)',
        r'Vue\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)',
        r'React\s+v?([0-9]+\.[0-9]+\.[0-9]+)',
    ]

    def __init__(self):
        self.inventory: List[Dict] = []
        self.vulnerabilities: List[Dict] = []
        self.sri_issues: List[Dict] = []
        self.cdn_origins: Set[str] = set()
        self.npm_packages: Set[str] = set()

    def analyze_script_tags(self, html: str, page_url: str):
        """Extract all <script> tags and analyze for supply chain risks."""
        for match in re.finditer(
            r'<script[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']([^>]*)>', html, re.I
        ):
            src = match.group(1)
            attrs = match.group(2)
            full_url = urljoin(page_url, src)
            parsed = urlparse(full_url)

            entry = {
                'url': full_url,
                'host': parsed.netloc,
                'is_external': parsed.netloc != urlparse(page_url).netloc,
                'has_sri': 'integrity=' in attrs.lower(),
                'has_crossorigin': 'crossorigin' in attrs.lower(),
                'library': None,
                'version': None,
                'vulnerabilities': [],
            }

            # Track CDN origins
            if entry['is_external']:
                self.cdn_origins.add(parsed.netloc)
                # v3.0: CDN risk correlation
                cdn_intel = self.CDN_RISK_INTEL.get(parsed.netloc)
                if cdn_intel:
                    entry['cdn_risk'] = cdn_intel['risk']
                    entry['cdn_notes'] = cdn_intel['notes']

            # Extract library and version from URL
            lib_name, lib_version = self._extract_lib_version(full_url)
            if lib_name:
                entry['library'] = lib_name
                entry['version'] = lib_version

                # Check vulnerabilities
                vulns = self._check_vulns(lib_name, lib_version)
                if vulns:
                    entry['vulnerabilities'] = vulns
                    for v in vulns:
                        self.vulnerabilities.append({
                            'library': lib_name, 'version': lib_version,
                            'severity': v['severity'], 'detail': v['detail'],
                            'source': page_url,
                        })

            # SRI check for external scripts (dedup by URL)
            if entry['is_external'] and not entry['has_sri']:
                if not any(s['url'] == full_url for s in self.sri_issues):
                    self.sri_issues.append({
                        'url': full_url, 'host': parsed.netloc,
                        'source': page_url,
                    })

            # Dedup by URL
            if not any(e['url'] == entry['url'] for e in self.inventory):
                self.inventory.append(entry)

    def analyze_js_content(self, content: str, js_url: str):
        """Detect library versions from inline JS comments/headers."""
        header = content[:3000]
        lib_map = {
            'jQuery': 'jquery', 'Bootstrap': 'bootstrap', 'Lodash': 'lodash',
            'Angular': 'angular', 'Vue.js': 'vue', 'React': 'react-dom',
        }
        for pattern in self.INLINE_VERSION_PATTERNS:
            m = re.search(pattern, header)
            if m:
                version = m.group(1)
                for display_name, lib_key in lib_map.items():
                    if display_name.lower() in pattern.lower():
                        vulns = self._check_vulns(lib_key, version)
                        # Only add if not already tracked
                        if not any(e.get('library') == lib_key and e.get('url') == js_url
                                   for e in self.inventory):
                            entry = {
                                'url': js_url, 'host': urlparse(js_url).netloc,
                                'is_external': False, 'has_sri': False,
                                'has_crossorigin': False,
                                'library': lib_key, 'version': version,
                                'vulnerabilities': vulns,
                                'detected_from': 'inline_header',
                            }
                            self.inventory.append(entry)
                            if vulns:
                                for v in vulns:
                                    self.vulnerabilities.append({
                                        'library': lib_key, 'version': version,
                                        'severity': v['severity'], 'detail': v['detail'],
                                        'source': js_url,
                                    })
                        break

    def add_npm_packages(self, packages: List[str]):
        """Add npm packages discovered from source maps."""
        self.npm_packages.update(packages)

    def _extract_lib_version(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract library name and version from CDN URL."""
        for pattern in self.CDN_PATTERNS:
            m = re.search(pattern, url, re.I)
            if m:
                lib = m.group(1).split('/')[-1].lower().rstrip('.')
                ver = m.group(2).rstrip('.')
                return lib, ver
        return None, None

    def _check_vulns(self, lib_name: str, version: str) -> List[Dict]:
        """Check if a library version has known vulnerabilities."""
        if not version:
            return []
        vulns_list = self.VULNERABLE_LIBS.get(lib_name.lower(), [])
        found = []
        for vuln_below, severity, detail in vulns_list:
            if self._version_lt(version, vuln_below):
                found.append({'severity': severity, 'detail': detail,
                              'fixed_in': vuln_below})
        return found

    @staticmethod
    def _version_lt(a: str, b: str) -> bool:
        """Compare version strings: return True if a < b."""
        try:
            def _parts(v):
                return [int(x) for x in re.findall(r'\d+', v)][:4]
            pa, pb = _parts(a), _parts(b)
            # Pad to same length
            while len(pa) < len(pb): pa.append(0)
            while len(pb) < len(pa): pb.append(0)
            return pa < pb
        except (ValueError, IndexError):
            return False

    def get_summary(self) -> Dict:
        """Return supply chain analysis summary."""
        return {
            'total_scripts': len(self.inventory),
            'external_scripts': sum(1 for e in self.inventory if e['is_external']),
            'cdn_origins': sorted(self.cdn_origins),
            'libraries_detected': sum(1 for e in self.inventory if e.get('library')),
            'vulnerable_libraries': len(self.vulnerabilities),
            'sri_missing': len(self.sri_issues),
            'npm_packages_from_sourcemaps': sorted(self.npm_packages),
            'inventory': self.inventory,
            'vulnerabilities': self.vulnerabilities,
            'sri_issues': self.sri_issues,
        }


# ═══════════════════════════════════════════════════════════════════
#  Security Headers Auditor — v3.0 (SRI/COOP/COEP/CSP)
# ═══════════════════════════════════════════════════════════════════

class SecurityHeadersAuditor:
    """Audit security-critical HTTP headers for misconfigurations."""

    CRITICAL_HEADERS = {
        'Content-Security-Policy': {
            'severity': 'HIGH',
            'detail': 'No CSP — XSS and data injection attacks possible',
        },
        'Strict-Transport-Security': {
            'severity': 'MEDIUM',
            'detail': 'No HSTS — vulnerable to SSL stripping',
        },
        'X-Content-Type-Options': {
            'severity': 'LOW',
            'detail': 'No nosniff — MIME-type confusion attacks',
        },
        'X-Frame-Options': {
            'severity': 'MEDIUM',
            'detail': 'No clickjacking protection',
        },
        'Cross-Origin-Opener-Policy': {
            'severity': 'MEDIUM',
            'detail': 'No COOP — cross-origin window attacks (Spectre)',
        },
        'Cross-Origin-Embedder-Policy': {
            'severity': 'MEDIUM',
            'detail': 'No COEP — cross-origin data leakage via SharedArrayBuffer',
        },
        'Cross-Origin-Resource-Policy': {
            'severity': 'LOW',
            'detail': 'No CORP — resources can be embedded by any origin',
        },
        'Permissions-Policy': {
            'severity': 'LOW',
            'detail': 'No Permissions-Policy — browser APIs unrestricted',
        },
    }

    CSP_DANGEROUS = [
        ("'unsafe-inline'", 'HIGH', 'Allows inline scripts (XSS)'),
        ("'unsafe-eval'", 'HIGH', 'Allows eval() (code injection)'),
        ('data:', 'MEDIUM', 'Allows data: URIs (XSS bypass)'),
        ('*', 'HIGH', 'Wildcard source (no protection)'),
        ('http:', 'MEDIUM', 'Allows HTTP sources (MitM)'),
    ]

    def __init__(self):
        self.findings: List[Dict] = []

    def audit(self, response_headers: Dict, url: str) -> List[Dict]:
        """Audit response headers and return findings."""
        headers_lower = {k.lower(): v for k, v in response_headers.items()}

        for header_name, info in self.CRITICAL_HEADERS.items():
            if header_name.lower() not in headers_lower:
                self.findings.append({
                    'header': header_name, 'issue': 'MISSING',
                    'severity': info['severity'], 'detail': info['detail'],
                    'url': url,
                })

        # CSP deep analysis
        csp = headers_lower.get('content-security-policy', '')
        if csp:
            for pattern, severity, detail in self.CSP_DANGEROUS:
                if pattern in csp:
                    self.findings.append({
                        'header': 'CSP', 'issue': f'DANGEROUS: {pattern}',
                        'severity': severity, 'detail': detail, 'url': url,
                    })
            # Check for report-only (not enforced)
            if 'content-security-policy-report-only' in headers_lower:
                self.findings.append({
                    'header': 'CSP', 'issue': 'REPORT-ONLY',
                    'severity': 'MEDIUM', 'detail': 'CSP is report-only, not enforced',
                    'url': url,
                })

        return self.findings


# ═══════════════════════════════════════════════════════════════════
#  False Positive Auto-Filter — v3.0
# ═══════════════════════════════════════════════════════════════════

class FalsePositiveFilter:
    """Context-aware false positive elimination with entropy thresholds."""

    # File path patterns that indicate test/example content
    TEST_FILE_PATTERNS = [
        r'(?:^|[/\\])(?:__)?tests?(?:__)?[/\\]', r'\.test\.[jt]sx?$',
        r'\.spec\.[jt]sx?$', r'\.stories\.[jt]sx?$',
        r'mock[/\\]', r'fixture[/\\]', r'__mocks__[/\\]',
        r'example[s]?[/\\]', r'sample[s]?[/\\]', r'demo[/\\]',
        r'storybook[/\\]', r'cypress[/\\]', r'e2e[/\\]',
    ]

    # Value patterns that are almost certainly placeholders
    PLACEHOLDER_PATTERNS = [
        r'^[xX]{8,}$',                    # xxxxxxxx
        r'^\*{6,}$',                       # ********
        r'^<.+>$',                         # <your_key>
        r'^\[.+\]$',                       # [API_KEY]
        r'^your[_\-]',                     # your_key
        r'^my[_\-]',                       # my_secret
        r'^CHANGE[_\-]?ME',               # CHANGEME
        r'^TODO',                          # TODO
        r'^REPLACE',                       # REPLACE_ME
        r'^INSERT',                        # INSERT_HERE
        r'^\$\{',                          # ${ENV_VAR}
        r'^process\.env\.',               # process.env.KEY
        r'^ENV\[',                         # ENV['KEY']
        r'^os\.environ',                  # os.environ['KEY']
        r'^env\(',                         # env('KEY')
        r'^%[A-Z_]+%$',                   # %ENV_VAR%
        r'^0{8,}$',                        # 00000000
        r'^1{8,}$',                        # 11111111
        r'^(?:test|demo|fake|dummy|sample|example)',
        r'(?:abc|xyz)(?:123|456|789)$',   # abc123
    ]

    # Known documentation/tutorial domains
    DOC_PATTERNS = [
        'documentation', 'readme', 'changelog', 'license',
        'contributing', 'authors', 'tutorial', 'getting-started',
    ]

    # ── MINIMUM ENTROPY THRESHOLDS PER SECRET TYPE ──
    # Below this entropy, it's almost certainly a false positive.
    # Higher threshold = stricter filtering.
    MIN_ENTROPY_THRESHOLDS = {
        'Hardcoded Password':       3.0,   # "password123" = ~3.0
        'High-Entropy Secret':      3.5,   # must actually be high entropy
        'Generic API Key':          3.0,
        'Generic Secret':           3.0,
        'Google API Key':           3.5,
        'AWS Access Key':           3.5,
        'Stripe API Key':           3.5,
        'Slack Token':              3.0,
        'GitHub Token':             3.5,
        'SendGrid API Key':         3.5,
        'Mapbox Token':             3.0,
        'JWT Token':                2.0,   # JWTs can be low entropy (short payloads)
        'Private Key':              1.0,   # PEM headers are low entropy but valid
        'Database Connection String': 2.0, # URIs can be low entropy
        'Slack Webhook':            2.0,   # URLs are structured
        'AWS S3 Bucket':            1.5,   # Bucket names are low entropy
    }
    DEFAULT_MIN_ENTROPY = 2.5  # for types not listed above

    # ── COMMON FALSE POSITIVE VALUES ──
    # Known values that appear in thousands of JS bundles (minified vars, defaults)
    KNOWN_FP_VALUES = {
        'undefined', 'null', 'true', 'false', 'none',
        'password', 'secret', 'token', 'apikey', 'api_key',
        'default', 'changeme', 'xxxxxxxx', 'placeholder',
        'not_a_real_key', 'sk_test_', 'pk_test_',
    }

    @staticmethod
    def is_false_positive(value: str, source: str, secret_type: str) -> Tuple[bool, str]:
        """Returns (is_fp, reason) tuple with entropy-aware filtering."""
        vl = value.lower().strip()
        src_lower = source.lower()

        # ── ReCAPTCHA site keys are PUBLIC by design (not secrets) ──
        if secret_type == 'Recaptcha Site Key':
            # Only flag if from third-party JS (not target's own recaptcha setup)
            if any(tp in src_lower for tp in [
                'googlesyndication.com', 'mgid.com', 'doubleclick.net',
                'btloader.com', 'adservice.google', 'googletagmanager.com',
            ]):
                return True, 'ReCAPTCHA key from third-party ad/analytics script (not target-owned)'
            # Check if it's actually a base64 fragment misidentified as recaptcha
            if not value.startswith('6L'):
                return True, 'Not a real ReCAPTCHA key (missing 6L prefix)'

        # ── Ad network base64 blobs misidentified as tokens ──
        ad_network_sources = [
            'pagead2.googlesyndication.com', 'googlesyndication.com',
            'securepubads.g.doubleclick.net', 'doubleclick.net',
            'jsc.mgid.com', 'mgid.com', 'btloader.com',
            'adservice.google.com', 'googleadservices.com',
        ]
        if any(ad in src_lower for ad in ad_network_sources):
            # Only allow highly specific tokens (Google API Key with AIza prefix)
            if secret_type not in ('Google API Key',) or not value.startswith('AIza'):
                return True, f'Token from ad network JS (not target secret): {secret_type}'

        # Check placeholder patterns
        for pattern in FalsePositiveFilter.PLACEHOLDER_PATTERNS:
            if re.match(pattern, value, re.IGNORECASE):
                return True, f'Placeholder pattern: {pattern}'

        # Check if source is test/example file
        for pattern in FalsePositiveFilter.TEST_FILE_PATTERNS:
            if re.search(pattern, source, re.IGNORECASE):
                return True, f'Test/example file: {source}'

        # Check documentation sources by exact path segment or filename stem
        src_path = re.split(r'[?#]', src_lower, maxsplit=1)[0]
        for part in re.split(r'[\\/]+', src_path):
            part = part.strip()
            if part in FalsePositiveFilter.DOC_PATTERNS:
                return True, f'Documentation source: {part}'
            if part.rsplit('.', 1)[0] in FalsePositiveFilter.DOC_PATTERNS:
                return True, f'Documentation source: {part}'

        # Repetitive characters (low entropy but matched regex)
        if len(set(vl)) <= 3 and len(vl) > 8:
            return True, 'Repetitive characters'

        # Common minified variable names that match patterns
        if secret_type == 'High-Entropy Secret' and len(value) < 24:
            if re.match(r'^[a-z]{1,3}\d{1,3}[a-z]{1,3}\d{1,3}$', value):
                return True, 'Likely minified variable name'

        # ── Known false positive values ──
        if vl in FalsePositiveFilter.KNOWN_FP_VALUES:
            return True, f'Known FP value: {vl}'

        # ── Entropy threshold check ──
        entropy = shannon_entropy(value)
        min_threshold = FalsePositiveFilter.MIN_ENTROPY_THRESHOLDS.get(
            secret_type, FalsePositiveFilter.DEFAULT_MIN_ENTROPY
        )
        if entropy < min_threshold:
            return True, (f'Entropy too low: {entropy:.1f} < {min_threshold} '
                          f'threshold for {secret_type}')

        # ── Source from external CDN / third-party (not target's secret) ──
        external_cdn_patterns = [
            r'cdnjs\.cloudflare\.com', r'cdn\.jsdelivr\.net', r'unpkg\.com',
            r'ajax\.googleapis\.com', r'cdn\.shopify\.com', r'assets\.shopify\.com',
            r'polyfill\.io', r'cdn\.polyfill\.io', r'stackpath\.bootstrapcdn',
            r'maxcdn\.bootstrapcdn', r'code\.jquery\.com',
        ]
        for cdn_pattern in external_cdn_patterns:
            if re.search(cdn_pattern, source, re.IGNORECASE):
                if secret_type in ('High-Entropy Secret', 'Hardcoded Password', 'Generic API Key'):
                    return True, f'Generic secret from external CDN: {cdn_pattern}'

        # ── Too short for secret type ──
        min_lengths = {
            'AWS Access Key': 16, 'GitHub Token': 20, 'Stripe API Key': 20,
            'Google API Key': 30, 'SendGrid API Key': 30, 'High-Entropy Secret': 16,
        }
        min_len = min_lengths.get(secret_type)
        if min_len and len(value) < min_len:
            return True, f'Too short for {secret_type}: {len(value)} < {min_len}'

        return False, ''

    @staticmethod
    def filter_findings(findings: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        """Filter findings, return (kept, removed) tuple."""
        kept, removed = [], []
        seen_hashes = set()
        for f in findings:
            is_fp, reason = FalsePositiveFilter.is_false_positive(
                f['value'], f['source'], f['type'])
            if is_fp:
                f['fp_reason'] = reason
                removed.append(f)
            else:
                # Deduplicate by value hash
                val_hash = hashlib.sha256(f['value'].encode()).hexdigest()[:16]
                if val_hash in seen_hashes:
                    f['fp_reason'] = 'Duplicate value'
                    removed.append(f)
                else:
                    seen_hashes.add(val_hash)
                    kept.append(f)
        return kept, removed


# ═══════════════════════════════════════════════════════════════════
#  Accuracy Engine v5.0 — 8 Intelligence Upgrades
# ═══════════════════════════════════════════════════════════════════

class AccuracyEngine:
    """
    Post-processing accuracy layer. Runs AFTER initial detection
    and BEFORE final output to maximize signal and minimize noise.

    8 Systems:
    1. Context window analysis    — surrounding code inspection
    2. Correlation dedup          — intelligent cross-source dedup
    3. Variable name scoring      — confidence from assignment context
    4. Dead code detection        — comments, disabled blocks
    5. Multi-file correlation     — cross-page confidence boost
    6. Base64/encoded detection   — decode-then-scan pre-pass
    7. JS deobfuscation           — basic beautify before scanning
    8. Confidence scoring (0-100) — unified numeric score
    """

    # ─── [1] CONTEXT WINDOW ANALYSIS ───
    # Patterns that indicate a finding is in dead/example/test context

    DEAD_CONTEXT_PATTERNS = [
        # Comments
        (r'(?:^|\n)\s*(?://|#|/\*)\s*.*{VALUE}', 'in_comment', -30),
        # Disabled / example code
        (r'if\s*\(\s*false\s*\)', 'if_false_block', -40),
        (r'if\s*\(\s*0\s*\)', 'if_zero_block', -40),
        (r'(?://|#)\s*(?:TODO|FIXME|HACK|XXX|OLD|DEPRECATED|DISABLED)', 'todo_comment', -20),
        (r'(?://|#)\s*(?:old|previous|deprecated|unused|remove|delete)', 'deprecated_comment', -20),
        # Console / debug
        (r'console\.\w+\s*\(', 'console_log', -15),
        (r'print\s*\(', 'print_statement', -10),
        (r'(?:debug|log|trace|warn)\s*[(\[]', 'debug_output', -10),
        # Documentation / examples
        (r'@example', 'doc_example', -35),
        (r'@param\s', 'doc_param', -25),
        (r'README|EXAMPLE|SAMPLE|TUTORIAL', 'doc_source', -30),
    ]

    # Patterns that BOOST confidence
    BOOST_CONTEXT_PATTERNS = [
        # Direct assignment in config/init
        (r'(?:config|settings|env|init|setup|credentials)\s*[.=\[]', 'config_assignment', +15),
        # Fetch / HTTP call with the key
        (r'(?:fetch|axios|request|http|xhr)\s*[(\.]', 'http_usage', +20),
        # Authorization header construction
        (r'(?:Authorization|Bearer|X-API-Key|api[_-]?key)\s*[:\=]', 'auth_header', +25),
        # Direct key usage
        (r'(?:headers|params|body|payload|data)\s*[\[.{]', 'request_params', +10),
        # .env file or config file
        (r'\.env(?:\.|$)', 'dotenv_source', +20),
    ]

    # ─── [3] VARIABLE NAME SCORING ───
    # Variable names that strongly suggest a real secret

    HIGH_CONFIDENCE_VARNAMES = {
        # Exact matches or prefixes that indicate real secrets
        'stripe_secret_key': 30, 'stripe_api_key': 30, 'sk_live': 25,
        'aws_secret_access_key': 30, 'aws_access_key_id': 30,
        'database_url': 25, 'db_password': 25, 'db_pass': 25,
        'api_secret': 25, 'client_secret': 25, 'private_key': 25,
        'secret_key': 20, 'api_key': 15, 'auth_token': 20,
        'access_token': 20, 'refresh_token': 20,
        'sendgrid_api_key': 25, 'twilio_auth_token': 25,
        'slack_token': 25, 'slack_webhook': 20,
        'firebase_api_key': 20, 'openai_api_key': 25,
        'anthropic_api_key': 25, 'github_token': 25,
        'gitlab_token': 25, 'heroku_api_key': 25,
        'mailgun_api_key': 25, 'datadog_api_key': 20,
        'sentry_dsn': 15, 'encryption_key': 25,
        'signing_key': 25, 'jwt_secret': 25,
        'password': 10, 'passwd': 10, 'pwd': 8,
    }

    LOW_CONFIDENCE_VARNAMES = {
        # Variable names that suggest placeholders or config templates
        'example': -20, 'sample': -20, 'demo': -20, 'test': -15,
        'mock': -20, 'fake': -25, 'dummy': -25, 'placeholder': -30,
        'template': -20, 'default': -10, 'fallback': -10,
        'temp': -10, 'tmp': -10, 'unused': -20, 'old': -15,
    }

    # ─── [4] DEAD CODE PATTERNS ───

    COMMENT_LINE_PATTERNS = [
        r'^\s*//',           # JS single-line comment
        r'^\s*#',            # Python/bash comment
        r'^\s*/\*',          # C-style block comment start
        r'\*/',              # C-style block comment end
        r'^\s*\*\s',         # Inside block comment
        r'<!--',             # HTML comment
        r'^\s*\'\'\' ',      # Python docstring
        r'^\s*"""',          # Python docstring
    ]

    # ─── [6] BASE64 ENCODED SECRET PATTERNS ───

    B64_SECRET_INDICATORS = [
        # Patterns that suggest base64-encoded secrets
        r'(?:secret|key|token|password|credential|auth).*base64',
        r'atob\s*\(\s*["\']([A-Za-z0-9+/=]{20,})["\']',
        r'btoa\s*\(\s*["\']',
        r'Buffer\.from\s*\(\s*["\']([A-Za-z0-9+/=]{20,})["\'].*base64',
        r'base64[_\-]?(?:decode|encoded?)\s*[:(]\s*["\']([A-Za-z0-9+/=]{20,})["\']',
        r'(?:data|config|secret|key)\s*[=:]\s*["\']([A-Za-z0-9+/=]{40,})["\']',
    ]

    # Known secret prefixes that might appear inside base64
    B64_DECODED_SIGNATURES = [
        'sk_live_', 'sk_test_', 'pk_live_', 'pk_test_',
        'AKIA', 'ABIA', 'ACCA', 'ASIA',
        'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_',
        'xoxb-', 'xoxp-', 'xoxa-', 'xoxr-',
        'SG.', 'key-', 'sq0atp-', 'sq0csp-',
        'eyJ',  # JWT prefix
    ]

    def __init__(self):
        self.cross_file_values = defaultdict(list)  # value_hash -> [sources]
        self.processed_count = 0
        self.upgrades_applied = defaultdict(int)

        # ── Upgrade 1: Calibration Mode ──
        self.calibration_log = []  # Stores all scored findings for analysis
        self.calibration_file = os.path.join(str(Path.home()), ".SecretPulse", "calibration.json")

        # ── Upgrade 2: Dynamic Weight Adjustment ──
        self.environment_profile = 'default'  # default, cloud, ci_cd, enterprise
        self.weight_overrides = {}

        # ── Upgrade 3: Trust Decay ──
        self.trust_decay_enabled = True
        self.known_secrets_db = os.path.join(str(Path.home()), ".SecretPulse", "known_secrets.json")

        # ── Upgrade 4: Cross-Repo Leak Correlation ──
        self.cross_repo_db = os.path.join(str(Path.home()), ".SecretPulse", "cross_repo.json")
        self.current_target = None

    # ═══════════════════════════════════════════
    #  [1] Context Window Analysis
    # ═══════════════════════════════════════════

    @staticmethod
    def analyze_context(value: str, content: str, match_start: int) -> dict:
        """Analyze the code context around a match. Returns scoring adjustments."""
        result = {
            'adjustments': [],
            'score_delta': 0,
            'is_dead_code': False,
            'context_type': 'live_code',
        }

        # Extract wider context window (5 lines around match)
        ctx_start = content.rfind('\n', 0, max(0, match_start - 500))
        ctx_end = content.find('\n', min(len(content), match_start + 500))
        if ctx_start < 0: ctx_start = 0
        if ctx_end < 0: ctx_end = len(content)
        window = content[ctx_start:ctx_end]

        # Extract the specific line containing the match
        line_start = content.rfind('\n', 0, match_start) + 1
        line_end = content.find('\n', match_start)
        if line_end < 0: line_end = len(content)
        match_line = content[line_start:line_end]

        # Check for dead/example context (penalties)
        for pattern, label, delta in AccuracyEngine.DEAD_CONTEXT_PATTERNS:
            pat = pattern.replace('{VALUE}', re.escape(value[:20]))
            if re.search(pat, window, re.IGNORECASE):
                result['adjustments'].append((label, delta))
                result['score_delta'] += delta

        # Check for boost context
        for pattern, label, delta in AccuracyEngine.BOOST_CONTEXT_PATTERNS:
            if re.search(pattern, window, re.IGNORECASE):
                result['adjustments'].append((label, delta))
                result['score_delta'] += delta

        # [4] Dead code detection — check if the line itself is a comment
        for comment_pat in AccuracyEngine.COMMENT_LINE_PATTERNS:
            if re.match(comment_pat, match_line):
                result['is_dead_code'] = True
                result['context_type'] = 'commented_out'
                result['adjustments'].append(('line_is_comment', -35))
                result['score_delta'] -= 35
                break

        # Check for block comment wrapping
        pre_content = content[max(0, match_start - 200):match_start]
        if '/*' in pre_content and '*/' not in pre_content:
            result['is_dead_code'] = True
            result['context_type'] = 'block_comment'
            result['adjustments'].append(('inside_block_comment', -40))
            result['score_delta'] -= 40

        # Check for HTML comment wrapping
        if '<!--' in pre_content and '-->' not in pre_content:
            result['is_dead_code'] = True
            result['context_type'] = 'html_comment'
            result['adjustments'].append(('inside_html_comment', -35))
            result['score_delta'] -= 35

        # Check if inside a try/catch error handler (less likely to be real usage)
        if re.search(r'catch\s*\(', window):
            result['adjustments'].append(('catch_block', -5))
            result['score_delta'] -= 5

        return result

    # ═══════════════════════════════════════════
    #  [3] Variable Name Scoring
    # ═══════════════════════════════════════════

    @staticmethod
    def score_variable_name(content: str, match_start: int, value: str) -> dict:
        """Score confidence based on the variable name assigning this value."""
        result = {'varname': None, 'score_delta': 0, 'label': None}

        # Look at 150 chars before the match to find the variable name
        pre = content[max(0, match_start - 150):match_start]

        # Common assignment patterns:
        # var_name = "value", var_name: "value", "var_name": "value"
        varname_patterns = [
            r'["\']?(\w{2,40})["\']?\s*[=:]\s*["\']?\s*$',
            r'["\'](\w{2,40})["\']\s*:\s*["\']?\s*$',
            r'(\w{2,40})\s*=\s*["\']?\s*$',
            r'\.(\w{2,40})\s*=\s*["\']?\s*$',
            r'(?:export\s+)?(?:const|let|var)\s+(\w{2,40})\s*=\s*["\']?\s*$',
            r'(\w{2,40})\s*:\s*["\']?\s*$',
        ]

        varname = None
        for pat in varname_patterns:
            m = re.search(pat, pre)
            if m:
                varname = m.group(1).lower()
                break

        if not varname:
            return result

        result['varname'] = varname

        # Check against high-confidence names
        for name_pat, boost in AccuracyEngine.HIGH_CONFIDENCE_VARNAMES.items():
            if name_pat in varname or varname in name_pat:
                result['score_delta'] = boost
                result['label'] = f'high_conf_var:{name_pat}'
                return result

        # Check against low-confidence names
        for name_pat, penalty in AccuracyEngine.LOW_CONFIDENCE_VARNAMES.items():
            if name_pat in varname:
                result['score_delta'] = penalty
                result['label'] = f'low_conf_var:{name_pat}'
                return result

        # Partial keyword matching
        security_keywords = ['key', 'secret', 'token', 'auth', 'cred', 'pass', 'api']
        for kw in security_keywords:
            if kw in varname:
                result['score_delta'] = 10
                result['label'] = f'keyword_in_var:{kw}'
                return result

        return result

    # ═══════════════════════════════════════════
    #  [2] Correlation & Intelligent Dedup
    # ═══════════════════════════════════════════

    def track_cross_file(self, value: str, source: str):
        """Track values across files for multi-file correlation."""
        # Normalize value for comparison
        normalized = value.strip().lower()
        val_hash = hashlib.sha256(normalized.encode()).hexdigest()[:16]
        self.cross_file_values[val_hash].append(source)

    def get_cross_file_count(self, value: str) -> int:
        """How many different sources contain this value?"""
        normalized = value.strip().lower()
        val_hash = hashlib.sha256(normalized.encode()).hexdigest()[:16]
        sources = self.cross_file_values.get(val_hash, [])
        return len(set(sources))

    @staticmethod
    def smart_dedup(findings: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        """
        Intelligent dedup that goes beyond exact-match:
        - Normalize whitespace/quotes before comparing
        - Group by secret value, keep highest-confidence instance
        - Merge metadata from duplicates into the primary
        """
        kept, removed = [], []
        value_groups = defaultdict(list)

        for f in findings:
            # Normalize: strip whitespace, quotes, common wrappers
            norm_val = f['value'].strip().strip('"\'`')
            # Additional normalization for URLs
            norm_val = norm_val.rstrip('/')
            val_hash = hashlib.sha256(norm_val.encode()).hexdigest()[:16]
            value_groups[val_hash].append(f)

        for val_hash, group in value_groups.items():
            if len(group) == 1:
                kept.append(group[0])
                continue

            # Sort by: verified_live first, then confidence_score desc, then severity
            sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            group.sort(key=lambda x: (
                0 if x.get('verified_live') else 1,
                -x.get('confidence_score', 50),
                sev_order.get(x.get('severity', 'LOW'), 4),
            ))

            primary = group[0]
            # Merge info from duplicates
            all_sources = list(set(f['source'] for f in group))
            primary['all_sources'] = all_sources
            primary['all_locations'] = [
                {'source': f.get('source', ''), 'line': f.get('line')}
                for f in group
            ]
            primary['duplicate_count'] = len(group) - 1
            if any(f.get('public_identifier') for f in group):
                primary['public_identifier'] = True
                primary['severity'] = 'LOW'
                primary['severity_pinned'] = True

            # [5] Multi-file correlation: found in multiple files = more confident
            if len(all_sources) > 1:
                primary['multi_file'] = True
                boost = min(len(all_sources) * 5, 20)  # +5 per additional source, cap +20
                primary['confidence_score'] = min(100,
                    primary.get('confidence_score', 50) + boost)
                primary.setdefault('accuracy_notes', []).append(
                    f'Found in {len(all_sources)} sources (+{boost} confidence)')

            kept.append(primary)

            for dup in group[1:]:
                dup['fp_reason'] = f'Duplicate of primary (from {primary["source"]})'
                removed.append(dup)

        return kept, removed

    # ═══════════════════════════════════════════
    #  [6] Base64 / Encoded Secret Detection
    # ═══════════════════════════════════════════

    @staticmethod
    def decode_base64_secrets(content: str, source: str) -> List[Dict]:
        """Scan for base64-encoded secrets. Decode and check for known patterns."""
        decoded_findings = []

        # Find base64 strings (40+ chars, valid base64 alphabet)
        b64_pattern = re.compile(r'["\']([A-Za-z0-9+/]{40,}={0,3})["\']')

        for match in b64_pattern.finditer(content):
            b64_str = match.group(1)
            try:
                decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
            except Exception:
                continue

            if not decoded or len(decoded) < 10:
                continue

            # Check decoded content for known secret signatures
            for sig in AccuracyEngine.B64_DECODED_SIGNATURES:
                if sig in decoded:
                    line_no, snippet = line_context(content, match.start(), match.end())
                    decoded_findings.append({
                        'type': 'Base64-Encoded Secret',
                        'value': decoded.strip()[:200],
                        'source': source,
                        'severity': 'HIGH',
                        'confidence': 'HIGH',
                        'validated': False,
                        'entropy': shannon_entropy(decoded),
                        'encoding': 'base64',
                        'original_encoded': b64_str[:40] + '...',
                        'line': line_no,
                        'snippet': snippet,
                        'accuracy_notes': [f'Decoded from base64, matched signature: {sig}'],
                    })
                    break

        # Also check for atob() calls with inline strings
        atob_pattern = re.compile(r'atob\s*\(\s*["\']([A-Za-z0-9+/=]{16,})["\']')
        for match in atob_pattern.finditer(content):
            b64_str = match.group(1)
            try:
                decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
            except Exception:
                continue
            if decoded and len(decoded) >= 8 and shannon_entropy(decoded) > 3.0:
                line_no, snippet = line_context(content, match.start(), match.end())
                decoded_findings.append({
                    'type': 'Base64-Encoded Secret (atob)',
                    'value': decoded.strip()[:200],
                    'source': source,
                    'severity': 'MEDIUM',
                    'confidence': 'MEDIUM',
                    'validated': False,
                    'entropy': shannon_entropy(decoded),
                    'encoding': 'base64_atob',
                    'line': line_no,
                    'snippet': snippet,
                    'accuracy_notes': ['Decoded from atob() call'],
                })

        # Check URL-encoded secrets
        url_encoded_pattern = re.compile(r'(%[0-9A-Fa-f]{2}){5,}')
        for match in url_encoded_pattern.finditer(content):
            try:
                from urllib.parse import unquote
                decoded = unquote(match.group(0))
            except Exception:
                continue
            if decoded and shannon_entropy(decoded) > 3.5:
                for sig in AccuracyEngine.B64_DECODED_SIGNATURES:
                    if sig in decoded:
                        line_no, snippet = line_context(content, match.start(), match.end())
                        decoded_findings.append({
                            'type': 'URL-Encoded Secret',
                            'value': decoded.strip()[:200],
                            'source': source,
                            'severity': 'HIGH',
                            'confidence': 'MEDIUM',
                            'validated': False,
                            'entropy': shannon_entropy(decoded),
                            'encoding': 'url_encoded',
                            'line': line_no,
                            'snippet': snippet,
                            'accuracy_notes': ['Decoded from URL encoding'],
                        })
                        break

        return decoded_findings

    # ═══════════════════════════════════════════
    #  [7] Minified JS Deobfuscation
    # ═══════════════════════════════════════════

    @staticmethod
    def light_deobfuscate(content: str) -> str:
        """
        Light deobfuscation / beautification of minified JS.
        Adds newlines and spacing to improve context extraction.
        Does NOT modify the actual content — used only for context analysis.
        """
        if not content or len(content) < 100:
            return content

        # Quick check: is this actually minified? (very long lines)
        lines = content.split('\n')
        avg_line_len = sum(len(l) for l in lines) / max(len(lines), 1)
        if avg_line_len < 300:
            return content  # Not minified, skip

        beautified = content
        # Add newlines after common statement endings
        beautified = re.sub(r';\s*', ';\n', beautified)
        beautified = re.sub(r'\{\s*', '{\n', beautified)
        beautified = re.sub(r'\}\s*', '}\n', beautified)
        # Add newlines after commas in object/array literals
        beautified = re.sub(r',\s*(["\'])', r',\n\1', beautified)

        return beautified

    @staticmethod
    def extract_string_assignments(content: str) -> List[Tuple[str, str, int]]:
        """
        Extract (varname, value, position) tuples from common patterns.
        Catches secrets in hex-encoded or concatenated strings.
        """
        results = []

        # Hex-encoded strings: "\x73\x6b\x5f" patterns
        hex_pattern = re.compile(r'["\']((\\x[0-9a-fA-F]{2}){8,})["\']')
        for m in hex_pattern.finditer(content):
            try:
                hex_str = m.group(1)
                decoded = bytes(hex_str, 'utf-8').decode('unicode_escape')
                if decoded and len(decoded) >= 8:
                    results.append(('hex_encoded', decoded, m.start()))
            except Exception:
                continue

        # Char code arrays: [115, 107, 95, 108, 105, 118, 101]
        charcode_pattern = re.compile(
            r'String\.fromCharCode\s*\(\s*((?:\d{1,3}\s*,\s*){4,}\d{1,3})\s*\)')
        for m in charcode_pattern.finditer(content):
            try:
                codes = [int(c.strip()) for c in m.group(1).split(',')]
                decoded = ''.join(chr(c) for c in codes if 32 <= c <= 126)
                if decoded and len(decoded) >= 8:
                    results.append(('charcode', decoded, m.start()))
            except Exception:
                continue

        # String concatenation: "sk_" + "live_" + "xxx"
        concat_pattern = re.compile(
            r'["\']((?:sk_|pk_|SG\.|AKIA|ghp_|xoxb)[^"\']{0,8})["\']\s*\+\s*["\']([^"\']{4,})["\']'
            r'(?:\s*\+\s*["\']([^"\']{4,})["\'])?')
        for m in concat_pattern.finditer(content):
            parts = [m.group(i) for i in range(1, 4) if m.group(i)]
            combined = ''.join(parts)
            if combined and len(combined) >= 12:
                results.append(('concatenated', combined, m.start()))

        return results

    # ═══════════════════════════════════════════
    #  [8] Unified Confidence Score (0-100)
    # ═══════════════════════════════════════════

    @staticmethod
    def calculate_confidence_score(finding: dict, context_result: dict = None,
                                    varname_result: dict = None,
                                    weights: dict = None) -> dict:
        """
        SecretPulse Secret Confidence Formula v2
        ═════════════════════════════════════
        Confidence = (Format Validity   x W1)
                   + (Context Strength  x W2)
                   + (Domain Ownership  x W3)
                   + (File Risk Weight  x W4)
                   + (Entropy Range Fit x W5)
                   + (Live Validation   x W6)

        Weights are dynamic (Upgrade 2) — auto-adjusted by environment profile.
        Returns dict with all factor scores + final confidence + risk score.
        """
        # Default weights if none provided
        if not weights:
            weights = {
                'format_validity': 0.30, 'context_strength': 0.20,
                'domain_ownership': 0.15, 'file_risk_weight': 0.10,
                'entropy_range_fit': 0.10, 'live_validation': 0.15,
            }
        ftype = finding.get('type', '')
        source = finding.get('source', '')
        value = finding.get('value', '')
        entropy = finding.get('entropy', 0)
        src_lower = source.lower()

        # Shared domain lists (used by multiple factors)
        THIRD_PARTY_CDN = [
            # CDNs
            'cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com',
            'ajax.googleapis.com', 'cdn.shopify.com', 'assets.shopify.com',
            'polyfill.io', 'stackpath.bootstrapcdn.com', 'maxcdn.bootstrapcdn.com',
            'code.jquery.com', 'fonts.googleapis.com', 'cdn.datatables.net',
            'cdnjs.com', 'rawgit.com', 'raw.githubusercontent.com',
            'cdn.bootcdn.net', 'lib.baomitu.com', 'cdn.staticfile.org',
            # Ad networks (NOT target-owned)
            'pagead2.googlesyndication.com', 'googlesyndication.com',
            'securepubads.g.doubleclick.net', 'doubleclick.net',
            'googleadservices.com', 'adservice.google.com',
            'jsc.mgid.com', 'mgid.com',
            'btloader.com', 'ad.mediaprimaplus.com.my',
            'ads-twitter.com', 'connect.facebook.net',
            'platform.twitter.com', 'static.ads-twitter.com',
            # Analytics (NOT target-owned)
            'www.googletagmanager.com', 'googletagmanager.com',
            'www.google-analytics.com', 'google-analytics.com',
            'www.googleoptimize.com', 'static.cloudflareinsights.com',
            'cloudflareinsights.com', 'analytics.tiktok.com',
            'snap.licdn.com', 'bat.bing.com',
            # Social embeds
            'platform.twitter.com', 'connect.facebook.net',
            'player.vimeo.com', 'www.youtube.com',
        ]
        ARCHIVE_DOMAINS = ['archive.org', 'web.archive.org', 'webcache.googleusercontent.com']

        # ══════════════════════════════════════
        #  FACTOR 1: Format Validity (0-100)
        #  Does it match exact known format?
        # ══════════════════════════════════════

        # Exact format: correct prefix + correct length range
        FORMAT_EXACT = {
            # type: (prefixes, min_len, max_len)
            'AWS Access Key':       (['AKIA', 'ABIA', 'ACCA', 'ASIA'], 20, 20),
            'Stripe API Key':       (['sk_live_', 'sk_test_', 'rk_live_', 'rk_test_'], 20, 60),
            'Stripe Publishable Key': (['pk_live_', 'pk_test_'], 20, 60),
            'GitHub Token':         (['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_'], 20, 100),
            'Slack Token':          (['xoxb-', 'xoxp-', 'xoxa-', 'xoxr-', 'xoxs-'], 20, 80),
            'SendGrid API Key':     (['SG.'], 40, 100),
            'Google API Key':       (['AIza'], 35, 45),
            'Twilio API Key':       (['SK'], 32, 34),
            'Shopify Access Token': (['shpat_', 'shpca_', 'shppa_'], 20, 60),
            'OpenAI API Key':       (['sk-'], 40, 220),
            'Anthropic API Key':    (['sk-ant-'], 40, 120),
            'Mapbox Token':         (['pk.eyJ'], 80, 200),
            'Mapbox Secret Token':  (['sk.eyJ'], 80, 200),
            'Square Access Token':  (['sq0atp-', 'sq0csp-'], 20, 60),
            'Telegram Bot Token':   ([], 40, 50),  # format: digits:alphanum
            'Private Key':          (['-----BEGIN'], 20, 5000),
            'Firebase Config':      (['AIza'], 35, 45),
            # v5.4: 2026 provider formats
            'OpenRouter API Key':   (['sk-or-v1-'], 73, 73),
            'Groq API Key':         (['gsk_'], 52, 52),
            'xAI API Key':          (['xai-'], 84, 84),
            'Perplexity API Key':   (['pplx-'], 53, 53),
            'Mistral API Key':      ([], 32, 32),
            'DeepSeek API Key':     (['sk-'], 35, 35),
            'Together API Key':     ([], 64, 64),
            'Supabase Secret Key':  (['sb_secret_'], 30, 100),
            'Resend API Key':       (['re_'], 20, 80),
            'Postman API Key':      (['PMAK-'], 64, 64),
            'Pulumi Access Token':  (['pul-'], 44, 44),
            'Sentry User Token':    (['sntryu_'], 71, 71),
            'Datadog API Key':      ([], 32, 32),
            'Databricks API Token': (['dapi'], 36, 40),
            'Doppler API Token':    (['dp.pt.'], 49, 49),
            'Fly.io Access Token':  (['fo1_'], 47, 47),
            'Slack App Token':      (['xapp-'], 30, 80),
            'Discord Webhook':      (['https://discord.com/api/webhooks/'], 90, 200),
            '1Password Service Account Token': (['ops_'], 250, 400),
            'Age Secret Key':       (['AGE-SECRET-KEY-1'], 74, 74),
            'AWS Bedrock API Key':  (['ABSK'], 113, 280),
            'AWS Secret Access Key': ([], 40, 40),
            'Google OAuth Client Secret': (['GOCSPX-'], 35, 35),
            'Azure AD Client Secret': ([], 35, 45),
        }

        f_format = 20  # default: only high entropy match
        if ftype in FORMAT_EXACT:
            prefixes, min_len, max_len = FORMAT_EXACT[ftype]
            has_prefix = not prefixes or any(value.startswith(p) for p in prefixes)
            correct_len = min_len <= len(value) <= max_len

            if has_prefix and correct_len:
                f_format = 100  # exact prefix + correct length
            elif has_prefix:
                f_format = 60   # prefix matches, length off
            elif correct_len:
                f_format = 40   # length right, no prefix
            else:
                f_format = 10   # weak match
        elif ftype in ('JWT Token',):
            f_format = 80 if value.startswith('eyJ') else 20
        elif ftype in ('Database Connection String',):
            f_format = 90 if any(p in value for p in ['://', 'mongodb', 'postgres', 'mysql', 'redis']) else 30
        elif ftype.startswith('Base64-Encoded'):
            f_format = 100  # only emitted when a known signature is decoded
        elif ftype.startswith('Obfuscated'):
            f_format = 50  # decoded, partial confidence
        elif ftype in ('High-Entropy Secret', 'Generic API Key', 'Generic Secret',
                        'Generic Bearer Token', 'Hardcoded Password'):
            f_format = 20  # generic = low format confidence
        elif '.wasm' in source or 'binary' in source.lower():
            f_format = 0   # binary blob = no format trust

        # If validated format checker passed, the provider format is confirmed.
        if finding.get('validated'):
            f_format = 100

        # ══════════════════════════════════════
        #  FACTOR 2: Context Strength (0-100)
        #  What's around the match?
        # ══════════════════════════════════════

        f_context = 40  # default: slightly below neutral (no context = less trust)

        if context_result:
            is_dead = context_result.get('is_dead_code', False)
            ctx_type = context_result.get('context_type', 'live_code')
            adjustments = context_result.get('adjustments', [])

            # Start from context clues
            boost_labels = {
                'config_assignment': 100,
                'auth_header': 95,
                'http_usage': 90,
                'request_params': 80,
                'dotenv_source': 100,
            }
            penalty_labels = {
                'in_comment': 40,
                'line_is_comment': 30,
                'inside_block_comment': 25,
                'inside_html_comment': 25,
                'if_false_block': 10,
                'if_zero_block': 10,
                'todo_comment': 35,
                'deprecated_comment': 30,
                'console_log': 45,
                'print_statement': 45,
                'debug_output': 40,
                'doc_example': 15,
                'doc_param': 20,
                'doc_source': 10,
                'catch_block': 50,
            }

            best_boost = 40
            for label, _ in adjustments:
                if label in boost_labels:
                    best_boost = max(best_boost, boost_labels[label])
                if label in penalty_labels:
                    best_boost = min(best_boost, penalty_labels[label])

            f_context = best_boost

            if is_dead:
                f_context = min(f_context, 30)

        # Variable name boost
        if varname_result and varname_result.get('varname'):
            vname = varname_result['varname']
            # High-confidence variable names push context up
            high_conf_vars = ['secret_key', 'api_key', 'access_key', 'private_key',
                              'auth_token', 'password', 'client_secret', 'api_secret',
                              'stripe', 'aws', 'sendgrid', 'twilio', 'slack', 'github',
                              'database_url', 'db_password', 'encryption_key', 'jwt_secret']
            low_conf_vars = ['example', 'sample', 'demo', 'test', 'mock', 'fake',
                             'dummy', 'placeholder', 'template', 'default']

            if any(hv in vname for hv in high_conf_vars):
                f_context = max(f_context, 90)
            elif any(lv in vname for lv in low_conf_vars):
                f_context = min(f_context, 20)

        # CDN/archive sources get lower context trust
        if any(cdn in src_lower for cdn in THIRD_PARTY_CDN):
            f_context = min(f_context, 25)
        if any(arc in src_lower for arc in ARCHIVE_DOMAINS):
            f_context = min(f_context, 10)

        # ══════════════════════════════════════
        #  FACTOR 3: Domain Ownership (0-100)
        #  Is the asset owned by the target?
        # ══════════════════════════════════════

        f_ownership = 80  # default: assume in-scope

        if any(cdn in src_lower for cdn in THIRD_PARTY_CDN):
            f_ownership = 30   # third-party CDN
        elif any(arc in src_lower for arc in ARCHIVE_DOMAINS):
            f_ownership = 0    # archive.org = not target's asset
        elif '.wasm' in src_lower:
            f_ownership = 10   # WASM binary = likely third-party
        elif finding.get('multi_file'):
            f_ownership = 95   # found across multiple target pages
        else:
            # First-party: check if source matches common first-party patterns
            f_ownership = 80   # default in-scope

        # ══════════════════════════════════════
        #  FACTOR 4: File Risk Weight (0-100)
        #  What type of file is this?
        # ══════════════════════════════════════

        FILE_RISK = {
            '.env': 100, '.env.local': 100, '.env.production': 100,
            '.env.development': 95, '.env.staging': 95, '.env.example': 40,
            '.tf': 95, '.tfvars': 95,
            '.yaml': 90, '.yml': 90,
            '.toml': 85, '.ini': 85, '.cfg': 85, '.conf': 85,
            '.properties': 80, '.config': 80,
            '.json': 70,
            '.py': 65, '.rb': 65, '.php': 65, '.go': 65, '.java': 65,
            '.js': 50, '.ts': 50, '.jsx': 50, '.tsx': 50,
            '.html': 40, '.htm': 40,
            '.css': 15,
            '.map': 10, '.js.map': 10,
            '.wasm': 0, '.bin': 0, '.dat': 0,
            '.png': 0, '.jpg': 0, '.gif': 0, '.svg': 5,
            '.min.js': 45,
        }

        f_file = 50  # default for unknown file types

        # Check most specific extension first
        for ext, risk in sorted(FILE_RISK.items(), key=lambda x: -len(x[0])):
            if src_lower.endswith(ext) or ext in src_lower:
                f_file = risk
                break

        # Boost if source looks like a config/secret file
        if any(kw in src_lower for kw in ['config', 'secret', 'credential', 'password', '.env']):
            f_file = max(f_file, 90)

        # ══════════════════════════════════════
        #  FACTOR 5: Entropy Range Fit (0-100)
        #  Does entropy match known token bands?
        # ══════════════════════════════════════

        # Known entropy ranges for real secrets
        ENTROPY_BANDS = {
            # type: (ideal_low, ideal_high, acceptable_low, acceptable_high)
            'AWS Access Key':       (3.0, 3.8, 2.8, 4.2),
            'Stripe API Key':       (3.5, 4.5, 3.0, 5.0),
            'GitHub Token':         (3.5, 4.5, 3.0, 5.0),
            'Slack Token':          (3.5, 4.5, 3.0, 5.0),
            'SendGrid API Key':     (4.0, 5.0, 3.5, 5.5),
            'Google API Key':       (3.5, 4.5, 3.0, 5.0),
            'Private Key':          (2.0, 5.5, 1.5, 6.0),
            'JWT Token':            (3.0, 5.5, 2.0, 6.0),
            'Database Connection String': (2.5, 4.5, 2.0, 5.0),
            'Hardcoded Password':   (2.5, 4.0, 2.0, 4.5),
        }

        default_band = (3.0, 4.5, 2.5, 5.0)
        ideal_low, ideal_high, acc_low, acc_high = ENTROPY_BANDS.get(ftype, default_band)

        if ideal_low <= entropy <= ideal_high:
            f_entropy = 100  # perfect range
        elif acc_low <= entropy <= acc_high:
            f_entropy = 60   # acceptable range
        elif entropy > acc_high:
            f_entropy = 10   # too high = likely binary/random noise
        elif entropy < acc_low:
            f_entropy = 10   # too low = likely placeholder
        else:
            f_entropy = 30

        # Binary signature entropy (very high) = likely not a real token
        if entropy > 5.5:
            f_entropy = 0

        # Binary/WASM files — entropy is meaningless noise
        if any(ext in src_lower for ext in ['.wasm', '.bin', '.dat', '.so', '.dll', '.exe']):
            f_entropy = 0

        # Generic types with high entropy are less trustworthy
        if ftype in ('High-Entropy Secret', 'Generic API Key', 'Generic Secret') and entropy > 4.2:
            f_entropy = min(f_entropy, 20)

        # Third-party CDN — entropy match is less meaningful
        if any(cdn in src_lower for cdn in THIRD_PARTY_CDN):
            f_entropy = min(f_entropy, 30)

        # ══════════════════════════════════════
        #  FACTOR 6: Live Validation (0-100)
        # ══════════════════════════════════════

        if finding.get('verified_live') is True:
            f_live = 100    # confirmed active
        elif finding.get('verified_live') is False:
            f_live = 0      # confirmed dead
        else:
            f_live = 50     # not tested = neutral

        # ══════════════════════════════════════
        #  WEIGHTED CONFIDENCE SCORE
        #  Upgrade 2: Weights are dynamic
        # ══════════════════════════════════════

        w = weights
        confidence = (
            (f_format    * w.get('format_validity', 0.30)) +
            (f_context   * w.get('context_strength', 0.20)) +
            (f_ownership * w.get('domain_ownership', 0.15)) +
            (f_file      * w.get('file_risk_weight', 0.10)) +
            (f_entropy   * w.get('entropy_range_fit', 0.10)) +
            (f_live      * w.get('live_validation', 0.15))
        )

        confidence = max(0, min(100, int(round(confidence))))

        # ══════════════════════════════════════
        #  EXPLOITABILITY = Confidence x Impact
        # ══════════════════════════════════════

        IMPACT_WEIGHTS = {
            'AWS Access Key': 100, 'AWS Secret Key': 100,
            'Private Key': 95,
            'Database Connection String': 95,
            'Stripe API Key': 90,
            'PayPal Client Secret': 90,
            'Terraform Cloud Token': 85,
            'GitHub Token': 80,
            'GitLab Token': 80,
            'Slack Token': 75,
            'SendGrid API Key': 75,
            'Twilio API Key': 75,
            'OpenAI API Key': 70,
            'Anthropic API Key': 70,
            'Google API Key': 30,
            'Firebase Config': 25,
            'Shopify Access Token': 70,
            'Square Access Token': 70,
            'Mapbox Token': 5,
            'Mapbox Secret Token': 85,
            'Stripe Publishable Key': 5,
            'JWT Token': 60,
            'OAuth Access Token': 65,
            'OAuth Refresh Token': 70,
            'Sentry DSN': 5,
            'Datadog RUM Token': 5,
            'Mixpanel Project Token': 5,
            'Amplitude API Key': 5,
            'LogRocket App ID': 5,
            'Auth0 Client ID': 5,
            'Recaptcha Site Key': 5,
            'FullStory Org ID': 5,
            'Intercom App ID': 5,
            'HubSpot Portal ID': 5,
            'Hardcoded Password': 70,
            'High-Entropy Secret': 50,
            'Generic API Key': 50,
            'Generic Secret': 40,
            'Generic Bearer Token': 55,
            'Base64-Encoded Secret': 60,
            'Base64-Encoded Secret (atob)': 60,
            'URL-Encoded Secret': 60,
        }

        impact = IMPACT_WEIGHTS.get(ftype, 50)
        risk_score = int(round((confidence * impact) / 100))

        # Return full breakdown for transparency
        return {
            'confidence': confidence,
            'risk_score': risk_score,
            'impact_weight': impact,
            'factors': {
                'format_validity': f_format,
                'context_strength': f_context,
                'domain_ownership': f_ownership,
                'file_risk_weight': f_file,
                'entropy_range_fit': f_entropy,
                'live_validation': f_live,
            },
        }

    @staticmethod
    def score_to_severity(score: int) -> str:
        """Map confidence score to severity tier."""
        if score >= 85:
            return 'CRITICAL'
        elif score >= 70:
            return 'HIGH'
        elif score >= 50:
            return 'MEDIUM'
        elif score >= 30:
            return 'LOW'
        else:
            return 'INFO'

    @staticmethod
    def score_to_label(score: int) -> str:
        """Map confidence score to confidence label."""
        if score >= 85:
            return 'HIGH'
        elif score >= 50:
            return 'MEDIUM'
        else:
            return 'LOW'

    # ═══════════════════════════════════════════
    #  Main Processing Pipeline
    # ═══════════════════════════════════════════

    def process_findings(self, findings: List[Dict], all_content: Dict[str, str] = None) -> List[Dict]:
        """
        Run all 8 accuracy systems on a list of findings.

        Args:
            findings: Raw findings from scanner
            all_content: Dict of {source_url: content} for context analysis
        """
        if not findings:
            return findings

        all_content = all_content or {}

        # ── Upgrade 2: Detect environment, set dynamic weights ──
        all_sources = [f.get('source', '') for f in findings]
        self.environment_profile = self.detect_environment(all_sources)
        dynamic_weights = self.get_weights()
        if self.environment_profile != 'default':
            self.upgrades_applied['dynamic_weights'] = self.environment_profile

        # ── Extract target domain for cross-repo ──
        target_domain = None
        for src in all_sources:
            if '://' in src:
                from urllib.parse import urlparse as _urlparse
                target_domain = _urlparse(src).netloc
                if target_domain:
                    break
        self.current_target = target_domain

        for f in findings:
            source = f.get('source', '')
            value = f.get('value', '')
            content = all_content.get(source, '')
            notes = f.get('accuracy_notes', [])

            # [1] Context window analysis
            ctx_result = {'score_delta': 0, 'is_dead_code': False}
            if content and value:
                pos = content.find(value)
                if pos >= 0:
                    ctx_result = self.analyze_context(value, content, pos)
                    if ctx_result['adjustments']:
                        adj_labels = [a[0] for a in ctx_result['adjustments']]
                        notes.append(f"Context: {', '.join(adj_labels)}")
                        self.upgrades_applied['context_analysis'] += 1

            # [3] Variable name scoring
            var_result = {'score_delta': 0}
            if content and value:
                pos = content.find(value)
                if pos >= 0:
                    var_result = self.score_variable_name(content, pos, value)
                    if var_result.get('varname'):
                        notes.append(f"Variable: {var_result['varname']}")
                        self.upgrades_applied['varname_scoring'] += 1

            # [2][5] Track for cross-file correlation
            self.track_cross_file(value, source)

            # [8] Calculate confidence score (v2 weighted, Upgrade 2: dynamic weights)
            score_result = self.calculate_confidence_score(
                f, ctx_result, var_result, weights=dynamic_weights
            )
            confidence = score_result['confidence']

            # ── Upgrade 3: Trust Decay ──
            decay_multiplier = self.trust_decay_apply(f)
            if decay_multiplier < 1.0:
                original_conf = confidence
                confidence = int(round(confidence * decay_multiplier))
                score_result['confidence'] = confidence
                score_result['risk_score'] = int(round((confidence * score_result['impact_weight']) / 100))
                notes.append(f"Trust decay: {decay_multiplier:.2f}x ({original_conf} -> {confidence})")
                self.upgrades_applied['trust_decay'] += 1

            # ── Upgrade 4: Cross-Repo Leak Correlation ──
            if target_domain:
                self.cross_repo_record(f, target_domain)
                repo_info = self.cross_repo_boost(f)
                if repo_info['boost_multiplier'] > 1.0:
                    original_conf = confidence
                    confidence = min(100, int(round(confidence * repo_info['boost_multiplier'])))
                    score_result['confidence'] = confidence
                    score_result['risk_score'] = int(round((confidence * score_result['impact_weight']) / 100))
                    f['cross_repo'] = repo_info
                    notes.append(
                        f"Cross-repo: {repo_info['repo_count']} targets "
                        f"(x{repo_info['boost_multiplier']:.1f} boost, {original_conf} -> {confidence})"
                    )
                    self.upgrades_applied['cross_repo_boost'] += 1
                if repo_info['is_leaked_widely']:
                    notes.append(f"WIDELY LEAKED across {repo_info['repo_count']} targets")

            # Apply final scores to finding
            f['confidence_score'] = confidence
            f['risk_score'] = score_result['risk_score']
            f['impact_weight'] = score_result['impact_weight']
            f['score_factors'] = score_result['factors']
            f['confidence'] = self.score_to_label(confidence)

            # Override severity based on confidence score. Exact provider formats
            # keep their declared severity: confidence ranks urgency, it must not
            # turn a canonical live credential into a lesser finding.
            computed_severity = self.score_to_severity(confidence)
            original_severity = f.get('severity', 'LOW')
            sev_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
            exact_format = (score_result['factors'].get('format_validity', 0) >= 100)
            if (sev_order.get(computed_severity, 0) < sev_order.get(original_severity, 0)
                    and exact_format and original_severity in ('CRITICAL', 'HIGH')
                    and not f.get('public_identifier')):
                f['severity_pinned'] = True
                f['severity_pin_reason'] = 'exact provider format'
                notes.append(
                    f"Severity pinned at {original_severity} (exact provider format)")
            if sev_order.get(computed_severity, 0) < sev_order.get(original_severity, 0):
                if f.get('severity_pinned'):
                    if not f.get('severity_pin_reason'):
                        notes.append(
                            f"Severity pinned at {original_severity} (rule-declared)")
                else:
                    f['severity'] = computed_severity
                    f['severity_downgraded'] = True
                    notes.append(f"Severity {original_severity} -> {computed_severity} (confidence {confidence})")
            if f.get('verified_live') is True and sev_order.get(computed_severity, 0) > sev_order.get(original_severity, 0):
                f['severity'] = computed_severity

            # Dead code annotation
            if ctx_result.get('is_dead_code'):
                notes.append(f"Possibly dead code ({ctx_result.get('context_type', 'unknown')})")

            # Store notes
            if notes:
                f['accuracy_notes'] = notes

            # ── Upgrade 1: Calibration logging ──
            self.calibration_record(f)

            self.processed_count += 1

        # [2] Smart dedup (also handles [5] multi-file correlation)
        findings, deduped = self.smart_dedup(findings)
        self.upgrades_applied['smart_dedup'] = len(deduped)

        # Sort by risk score descending (confidence x impact)
        findings.sort(key=lambda x: (-x.get('risk_score', 0), -x.get('confidence_score', 0)))

        # ── Upgrade 1: Save calibration data ──
        self.calibration_save()

        return findings

    def pre_scan_content(self, content: str, source: str) -> Tuple[str, List[Dict]]:
        """
        Pre-processing pass before main regex scanning.
        Returns: (possibly_enhanced_content, extra_findings)

        [6] Decodes base64/URL-encoded secrets
        [7] Light deobfuscation for context extraction
        """
        extra_findings = []

        # [6] Scan for encoded secrets
        encoded_finds = self.decode_base64_secrets(content, source)
        if encoded_finds:
            extra_findings.extend(encoded_finds)
            self.upgrades_applied['base64_decode'] += len(encoded_finds)

        # [7] Extract obfuscated strings (hex, charcode, concat)
        obf_strings = self.extract_string_assignments(content)
        for encoding_type, decoded_val, pos in obf_strings:
            if shannon_entropy(decoded_val) > 3.0:
                line_no, snippet = line_context(content, pos, pos + 1)
                extra_findings.append({
                    'type': f'Obfuscated Secret ({encoding_type})',
                    'value': decoded_val,
                    'source': source,
                    'severity': 'HIGH',
                    'confidence': 'HIGH',
                    'validated': False,
                    'entropy': shannon_entropy(decoded_val),
                    'encoding': encoding_type,
                    'line': line_no,
                    'snippet': snippet,
                    'accuracy_notes': [f'Decoded from {encoding_type} obfuscation'],
                })
                self.upgrades_applied['deobfuscation'] += 1

        return content, extra_findings

    # ═══════════════════════════════════════════
    #  UPGRADE 1: Calibration Mode
    #  Log findings → plot → tune weights
    # ═══════════════════════════════════════════

    def calibration_record(self, finding: dict):
        """Record a finding for calibration analysis."""
        record = {
            'timestamp': int(time.time()),
            'type': finding.get('type', ''),
            'confidence_score': finding.get('confidence_score', 0),
            'risk_score': finding.get('risk_score', 0),
            'factors': finding.get('score_factors', {}),
            'verified_live': finding.get('verified_live'),
            'severity': finding.get('severity', ''),
            'entropy': finding.get('entropy', 0),
            'source_ext': os.path.splitext(finding.get('source', ''))[-1],
            'value_hash': hashlib.sha256(finding.get('value', '').encode()).hexdigest()[:12],
        }
        self.calibration_log.append(record)

    def calibration_save(self):
        """Save calibration data to disk for analysis."""
        if not self.calibration_log:
            return
        try:
            os.makedirs(os.path.dirname(self.calibration_file), mode=0o700, exist_ok=True)
            existing = []
            if os.path.exists(self.calibration_file):
                with open(self.calibration_file) as f:
                    existing = json.load(f)
            existing.extend(self.calibration_log)
            # Keep last 2000 entries
            if len(existing) > 2000:
                existing = existing[-2000:]
            with open(self.calibration_file, 'w') as f:
                json.dump(existing, f, indent=1)
            os.chmod(self.calibration_file, 0o600)
        except Exception:
            pass

    @staticmethod
    def calibration_analyze(calibration_file: str) -> dict:
        """
        Analyze calibration data to suggest weight adjustments.
        Run: python3 -c "from SecretPulse import AccuracyEngine; AccuracyEngine.calibration_report()"

        Returns stats on how each factor correlates with live verification.
        """
        if not os.path.exists(calibration_file):
            return {'error': 'No calibration data found. Run more scans first.'}

        with open(calibration_file) as f:
            data = json.load(f)

        if len(data) < 20:
            return {'error': f'Only {len(data)} findings logged. Need 50+ for meaningful analysis.'}

        # Separate verified-live vs dead vs untested
        live = [d for d in data if d.get('verified_live') is True]
        dead = [d for d in data if d.get('verified_live') is False]
        untested = [d for d in data if d.get('verified_live') is None]

        # For each factor, calculate avg score for live vs dead findings
        factor_names = ['format_validity', 'context_strength', 'domain_ownership',
                        'file_risk_weight', 'entropy_range_fit', 'live_validation']

        analysis = {
            'total_findings': len(data),
            'verified_live': len(live),
            'verified_dead': len(dead),
            'untested': len(untested),
            'factor_correlation': {},
            'weight_suggestions': {},
        }

        current_weights = {
            'format_validity': 0.30, 'context_strength': 0.20,
            'domain_ownership': 0.15, 'file_risk_weight': 0.10,
            'entropy_range_fit': 0.10, 'live_validation': 0.15,
        }

        for factor in factor_names:
            if factor == 'live_validation':
                continue  # Skip — circular

            live_avg = 0
            dead_avg = 0
            if live:
                live_scores = [d.get('factors', {}).get(factor, 0) for d in live]
                live_avg = sum(live_scores) / len(live_scores)
            if dead:
                dead_scores = [d.get('factors', {}).get(factor, 0) for d in dead]
                dead_avg = sum(dead_scores) / len(dead_scores)

            # Separation = how well this factor distinguishes live from dead
            separation = live_avg - dead_avg
            analysis['factor_correlation'][factor] = {
                'live_avg': round(live_avg, 1),
                'dead_avg': round(dead_avg, 1),
                'separation': round(separation, 1),
            }

            # Suggest weight increase if high separation, decrease if low
            if separation > 30:
                suggestion = min(current_weights[factor] + 0.05, 0.40)
            elif separation < 10:
                suggestion = max(current_weights[factor] - 0.05, 0.05)
            else:
                suggestion = current_weights[factor]
            analysis['weight_suggestions'][factor] = round(suggestion, 2)

        return analysis

    # ═══════════════════════════════════════════
    #  UPGRADE 2: Dynamic Weight Adjustment
    #  Environment-aware weight profiles
    # ═══════════════════════════════════════════

    # Weight profiles for different environments
    WEIGHT_PROFILES = {
        'default': {
            'format_validity': 0.30, 'context_strength': 0.20,
            'domain_ownership': 0.15, 'file_risk_weight': 0.10,
            'entropy_range_fit': 0.10, 'live_validation': 0.15,
        },
        'cloud': {
            # Cloud repos: FILE weight up (IaC files = high risk), ownership matters more
            'format_validity': 0.25, 'context_strength': 0.15,
            'domain_ownership': 0.20, 'file_risk_weight': 0.20,
            'entropy_range_fit': 0.05, 'live_validation': 0.15,
        },
        'ci_cd': {
            # CI/CD: context matters more, live validation critical
            'format_validity': 0.25, 'context_strength': 0.25,
            'domain_ownership': 0.10, 'file_risk_weight': 0.10,
            'entropy_range_fit': 0.05, 'live_validation': 0.25,
        },
        'web_app': {
            # Web app scanning: format + live are king
            'format_validity': 0.30, 'context_strength': 0.15,
            'domain_ownership': 0.15, 'file_risk_weight': 0.05,
            'entropy_range_fit': 0.10, 'live_validation': 0.25,
        },
        'source_code': {
            # Source code review: context + variable names matter most
            'format_validity': 0.20, 'context_strength': 0.30,
            'domain_ownership': 0.10, 'file_risk_weight': 0.15,
            'entropy_range_fit': 0.10, 'live_validation': 0.15,
        },
    }

    def detect_environment(self, sources: List[str]) -> str:
        """Auto-detect environment profile from scan sources."""
        src_text = ' '.join(sources).lower()

        # Cloud indicators
        cloud_indicators = ['.tf', '.tfvars', 'terraform', 'cloudformation',
                            'k8s', 'kubernetes', 'helm', 'ansible', 'pulumi',
                            'aws', 'gcp', 'azure', '.yaml', '.yml']
        cloud_score = sum(1 for ind in cloud_indicators if ind in src_text)

        # CI/CD indicators
        ci_indicators = ['.github/workflows', 'gitlab-ci', 'jenkinsfile', 'circleci',
                         '.travis', 'bitbucket-pipelines', 'azure-pipelines',
                         'dockerfile', 'docker-compose', '.drone']
        ci_score = sum(1 for ind in ci_indicators if ind in src_text)

        # Source code indicators
        code_indicators = ['.py', '.js', '.ts', '.go', '.java', '.rb', '.php',
                           'src/', 'lib/', 'app/', 'internal/', 'pkg/']
        code_score = sum(1 for ind in code_indicators if ind in src_text)

        # Web app indicators (default for URL-based scanning)
        web_indicators = ['http://', 'https://', '.html', '.js', '.css',
                          'api/', 'graphql', 'swagger', '.env']
        web_score = sum(1 for ind in web_indicators if ind in src_text)

        scores = {
            'cloud': cloud_score,
            'ci_cd': ci_score,
            'source_code': code_score,
            'web_app': web_score,
        }

        best = max(scores, key=scores.get)
        if scores[best] >= 3:
            return best
        return 'default'

    def get_weights(self) -> dict:
        """Get current weight profile (with any manual overrides)."""
        profile = self.WEIGHT_PROFILES.get(self.environment_profile, self.WEIGHT_PROFILES['default'])
        weights = dict(profile)
        weights.update(self.weight_overrides)

        # Normalize to sum=1.0
        total = sum(weights.values())
        if total > 0:
            weights = {k: v / total for k, v in weights.items()}

        return weights

    # ═══════════════════════════════════════════
    #  UPGRADE 3: Trust Decay
    #  Old secrets lose confidence over time
    # ═══════════════════════════════════════════

    def trust_decay_load(self) -> dict:
        """Load known secrets database."""
        try:
            if os.path.exists(self.known_secrets_db):
                with open(self.known_secrets_db) as f:
                    return json.load(f)
        except Exception:
            pass
        return {'secrets': {}}

    def trust_decay_save(self, db: dict):
        """Save known secrets database."""
        try:
            os.makedirs(os.path.dirname(self.known_secrets_db), mode=0o700, exist_ok=True)
            with open(self.known_secrets_db, 'w') as f:
                json.dump(db, f, indent=1)
            os.chmod(self.known_secrets_db, 0o600)
        except Exception:
            pass

    def trust_decay_apply(self, finding: dict) -> float:
        """
        Calculate trust decay multiplier for a finding.

        Rules:
        - First time seen: multiplier = 1.0 (full trust)
        - Seen before, verified live last time: multiplier = 1.0
        - Seen before, NOT re-verified: decay based on age
          - < 7 days: 1.0
          - 7-30 days: 0.85
          - 30-90 days: 0.65
          - 90-180 days: 0.45
          - > 180 days: 0.25

        Returns multiplier (0.0 - 1.0) to apply to confidence.
        """
        if not self.trust_decay_enabled:
            return 1.0

        value_hash = hashlib.sha256(finding.get('value', '').encode()).hexdigest()[:16]
        db = self.trust_decay_load()
        secrets = db.get('secrets', {})

        now = int(time.time())

        if value_hash not in secrets:
            # First time seen — record it
            secrets[value_hash] = {
                'first_seen': now,
                'last_seen': now,
                'last_verified': now if finding.get('verified_live') is True else 0,
                'type': finding.get('type', ''),
                'times_seen': 1,
            }
            db['secrets'] = secrets
            self.trust_decay_save(db)
            return 1.0

        entry = secrets[value_hash]
        entry['last_seen'] = now
        entry['times_seen'] = entry.get('times_seen', 0) + 1

        # If just verified live, reset decay
        if finding.get('verified_live') is True:
            entry['last_verified'] = now
            db['secrets'] = secrets
            self.trust_decay_save(db)
            return 1.0

        # Calculate decay based on time since last verification
        last_verified = entry.get('last_verified') or entry.get('first_seen', now)
        age_days = (now - last_verified) / 86400

        if age_days < 7:
            multiplier = 1.0
        elif age_days < 30:
            multiplier = 0.85
        elif age_days < 90:
            multiplier = 0.65
        elif age_days < 180:
            multiplier = 0.45
        else:
            multiplier = 0.25

        db['secrets'] = secrets
        self.trust_decay_save(db)

        return multiplier

    # ═══════════════════════════════════════════
    #  UPGRADE 4: Cross-Repo Leak Correlation
    #  Same key across repos = exponential boost
    # ═══════════════════════════════════════════

    def cross_repo_load(self) -> dict:
        """Load cross-repo correlation database."""
        try:
            if os.path.exists(self.cross_repo_db):
                with open(self.cross_repo_db) as f:
                    return json.load(f)
        except Exception:
            pass
        return {'values': {}}

    def cross_repo_save(self, db: dict):
        """Save cross-repo database."""
        try:
            os.makedirs(os.path.dirname(self.cross_repo_db), mode=0o700, exist_ok=True)
            # Prune old entries (>90 days)
            now = int(time.time())
            values = db.get('values', {})
            pruned = {}
            for k, v in values.items():
                targets = {t: ts for t, ts in v.get('targets', {}).items()
                           if now - ts < 90 * 86400}
                if targets:
                    v['targets'] = targets
                    pruned[k] = v
            db['values'] = pruned
            with open(self.cross_repo_db, 'w') as f:
                json.dump(db, f, indent=1)
            os.chmod(self.cross_repo_db, 0o600)
        except Exception:
            pass

    def cross_repo_record(self, finding: dict, target_domain: str):
        """Record a finding's value against a target for cross-repo tracking."""
        value_hash = hashlib.sha256(finding.get('value', '').encode()).hexdigest()[:16]
        db = self.cross_repo_load()
        values = db.get('values', {})

        if value_hash not in values:
            values[value_hash] = {
                'type': finding.get('type', ''),
                'targets': {},
                'first_seen': int(time.time()),
            }

        values[value_hash]['targets'][target_domain] = int(time.time())
        db['values'] = values
        self.cross_repo_save(db)

    def cross_repo_boost(self, finding: dict) -> dict:
        """
        Check if this secret appears across multiple targets/repos.

        Returns:
        {
            'repo_count': N,
            'boost_multiplier': 1.0 - 2.0,
            'targets': ['target1.com', 'target2.com'],
            'is_leaked_widely': bool,
        }
        """
        value_hash = hashlib.sha256(finding.get('value', '').encode()).hexdigest()[:16]
        db = self.cross_repo_load()
        values = db.get('values', {})

        if value_hash not in values:
            return {'repo_count': 1, 'boost_multiplier': 1.0, 'targets': [], 'is_leaked_widely': False}

        entry = values[value_hash]
        targets = list(entry.get('targets', {}).keys())
        repo_count = len(targets)

        # Exponential boost: each additional repo dramatically increases confidence
        if repo_count >= 5:
            boost = 2.0     # 5+ repos = maximum boost
        elif repo_count >= 3:
            boost = 1.6     # 3-4 repos = strong boost
        elif repo_count >= 2:
            boost = 1.3     # 2 repos = moderate boost
        else:
            boost = 1.0     # 1 repo = no boost

        return {
            'repo_count': repo_count,
            'boost_multiplier': boost,
            'targets': targets[:10],  # Cap display at 10
            'is_leaked_widely': repo_count >= 3,
        }

    def get_stats(self) -> dict:
        """Return accuracy engine statistics."""
        return {
            'findings_processed': self.processed_count,
            'upgrades_applied': dict(self.upgrades_applied),
            'cross_file_values_tracked': len(self.cross_file_values),
            'environment_profile': self.environment_profile,
            'calibration_entries': len(self.calibration_log),
            'target_domain': self.current_target,
        }
