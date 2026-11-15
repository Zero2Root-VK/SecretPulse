"""Report generation, rule loaders, and SARIF export."""
from ._imports import *
from .constants import __version__
from .utils import Colors, mask_secret

class ReportGenerator:
    """
    Professional visual reports with severity charts, executive summary,
    attack chain diagrams. Supports HTML and PDF output.
    """

    @staticmethod
    def generate_severity_chart_svg(findings: List[Dict]) -> str:
        """Generate inline SVG severity donut chart."""
        by_sev = defaultdict(int)
        for f in findings:
            by_sev[f['severity']] += 1

        total = len(findings) or 1
        colors = {'CRITICAL': '#dc3545', 'HIGH': '#fd7e14', 'MEDIUM': '#0dcaf0', 'LOW': '#0d6efd'}
        sevs = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

        # SVG donut chart
        cx, cy, r = 80, 80, 60
        r_inner = 35
        svg_parts = [f'<svg width="260" height="180" xmlns="http://www.w3.org/2000/svg">']

        start_angle = -90
        for sev in sevs:
            count = by_sev.get(sev, 0)
            if count == 0:
                continue
            pct = count / total
            angle = pct * 360
            end_angle = start_angle + angle
            large = 1 if angle > 180 else 0

            x1 = cx + r * math.cos(math.radians(start_angle))
            y1 = cy + r * math.sin(math.radians(start_angle))
            x2 = cx + r * math.cos(math.radians(end_angle))
            y2 = cy + r * math.sin(math.radians(end_angle))
            x3 = cx + r_inner * math.cos(math.radians(end_angle))
            y3 = cy + r_inner * math.sin(math.radians(end_angle))
            x4 = cx + r_inner * math.cos(math.radians(start_angle))
            y4 = cy + r_inner * math.sin(math.radians(start_angle))

            path = (f'M {x1:.1f} {y1:.1f} A {r} {r} 0 {large} 1 {x2:.1f} {y2:.1f} '
                    f'L {x3:.1f} {y3:.1f} A {r_inner} {r_inner} 0 {large} 0 {x4:.1f} {y4:.1f} Z')
            svg_parts.append(f'<path d="{path}" fill="{colors[sev]}" opacity="0.9"/>')
            start_angle = end_angle

        # Center text
        svg_parts.append(f'<text x="{cx}" y="{cy-5}" text-anchor="middle" '
                         f'fill="#c9d1d9" font-size="20" font-weight="bold">{total}</text>')
        svg_parts.append(f'<text x="{cx}" y="{cy+12}" text-anchor="middle" '
                         f'fill="#8b949e" font-size="10">findings</text>')

        # Legend
        ly = 20
        for sev in sevs:
            count = by_sev.get(sev, 0)
            if count == 0:
                continue
            svg_parts.append(f'<rect x="175" y="{ly}" width="12" height="12" '
                             f'rx="2" fill="{colors[sev]}"/>')
            svg_parts.append(f'<text x="192" y="{ly+10}" fill="#c9d1d9" '
                             f'font-size="11">{sev}: {count}</text>')
            ly += 20

        svg_parts.append('</svg>')
        return '\n'.join(svg_parts)

    @staticmethod
    def generate_executive_summary(findings, stats, attack_chains, cve_results, rate_results):
        """Generate executive summary section."""
        total = len(findings)
        critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
        high = sum(1 for f in findings if f['severity'] == 'HIGH')
        live = sum(1 for f in findings if f.get('verified_live') is True)

        risk_level = 'CRITICAL' if critical > 0 else ('HIGH' if high > 0 else ('MEDIUM' if total > 0 else 'LOW'))
        risk_color = {'CRITICAL': '#dc3545', 'HIGH': '#fd7e14', 'MEDIUM': '#0dcaf0', 'LOW': '#198754'}

        summary = f'''
        <div class="exec-summary">
            <h2>Executive Summary</h2>
            <div class="risk-badge" style="background:{risk_color[risk_level]}">
                Overall Risk: {risk_level}
            </div>
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="summary-number">{total}</div>
                    <div class="summary-label">Total Findings</div>
                </div>
                <div class="summary-card" style="border-color:#dc3545">
                    <div class="summary-number" style="color:#dc3545">{critical}</div>
                    <div class="summary-label">Critical</div>
                </div>
                <div class="summary-card" style="border-color:#fd7e14">
                    <div class="summary-number" style="color:#fd7e14">{live}</div>
                    <div class="summary-label">Verified Live</div>
                </div>
                <div class="summary-card">
                    <div class="summary-number">{stats.get("source_maps_found", 0)}</div>
                    <div class="summary-label">Source Maps</div>
                </div>
            </div>
        '''

        if cve_results:
            cve_count = cve_results.get('confirmed_vulnerable', 0)
            if cve_count:
                summary += f'''
                <div class="alert alert-danger">
                    ⚠️ {cve_count} confirmed CVE(s) found in source map dependencies
                </div>'''

        if rate_results:
            unrestricted = rate_results.get('unrestricted', 0)
            if unrestricted:
                summary += f'''
                <div class="alert alert-warning">
                    💰 {unrestricted} API key(s) with NO rate limiting detected
                </div>'''

        summary += '</div>'
        return summary

    @staticmethod
    def generate_pdf(html_path: str, pdf_path: str) -> bool:
        """Convert HTML report to PDF using available tools (4 fallback engines)."""
        import subprocess

        # Engine 1: weasyprint (best quality)
        try:
            subprocess.run(['python3', '-c', 'import weasyprint'], check=True,
                           capture_output=True, timeout=5)
            result = subprocess.run([
                'python3', '-c',
                f"import weasyprint; weasyprint.HTML(filename='{html_path}').write_pdf('{pdf_path}')"
            ], check=True, capture_output=True, timeout=120)
            print(f"{Colors.OKGREEN}[+] PDF: {pdf_path} (weasyprint){Colors.ENDC}")
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            if hasattr(e, 'stderr') and e.stderr:
                err_msg = e.stderr.decode(errors='replace').strip().split('\n')[-1]
                print(f"{Colors.DIM}[!] weasyprint: {err_msg[:60]}{Colors.ENDC}")

        # Engine 2: wkhtmltopdf (widely available)
        try:
            subprocess.run(['wkhtmltopdf', '--quiet',
                           '--enable-local-file-access',
                           '--no-stop-slow-scripts',
                           '--javascript-delay', '500',
                           html_path, pdf_path],
                           check=True, capture_output=True, timeout=120)
            print(f"{Colors.OKGREEN}[+] PDF: {pdf_path} (wkhtmltopdf){Colors.ENDC}")
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Engine 3: chromium/chrome headless (common on Kali/Linux)
        for browser in ['chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable']:
            try:
                abs_html = os.path.abspath(html_path)
                abs_pdf = os.path.abspath(pdf_path)
                subprocess.run([browser, '--headless', '--disable-gpu', '--no-sandbox',
                               f'--print-to-pdf={abs_pdf}',
                               '--run-all-compositor-stages-before-draw',
                               '--virtual-time-budget=5000',
                               f'file://{abs_html}'],
                               check=True, capture_output=True, timeout=60)
                if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 100:
                    print(f"{Colors.OKGREEN}[+] PDF: {pdf_path} ({browser} headless){Colors.ENDC}")
                    return True
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
                continue

        # Engine 4: xhtml2pdf (pure Python fallback — no system deps)
        try:
            subprocess.run(['python3', '-c', 'import xhtml2pdf'], check=True,
                           capture_output=True, timeout=5)
            conv_script = (
                f"from xhtml2pdf import pisa; "
                f"src = open('{html_path}', 'r', encoding='utf-8').read(); "
                f"out = open('{pdf_path}', 'wb'); "
                f"pisa.CreatePDF(src, dest=out); out.close()"
            )
            subprocess.run(['python3', '-c', conv_script],
                           check=True, capture_output=True, timeout=120)
            if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 100:
                print(f"{Colors.OKGREEN}[+] PDF: {pdf_path} (xhtml2pdf){Colors.ENDC}")
                return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            pass

        print(f"{Colors.WARNING}[!] PDF skipped — install one of: "
              f"weasyprint, wkhtmltopdf, chromium, xhtml2pdf{Colors.ENDC}")
        print(f"{Colors.DIM}    pip install weasyprint  OR  apt install wkhtmltopdf  OR  "
              f"pip install xhtml2pdf{Colors.ENDC}")
        return False

def load_custom_rules(filepath: str) -> Dict:
    """
    Load custom patterns from YAML or JSON file.
    Format:
      rules:
        - name: "My Custom Token"
          patterns: ["(myapp_[a-z0-9]{32})"]
          severity: HIGH
          case_sensitive: true
    """
    rules = {}
    path = Path(filepath)
    if not path.exists():
        print(f"{Colors.FAIL}[!] Rules file not found: {filepath}{Colors.ENDC}")
        return rules

    try:
        content = path.read_text()
        if filepath.endswith(('.yaml', '.yml')):
            if not HAS_YAML:
                print(f"{Colors.FAIL}[!] PyYAML not installed. "
                      f"Install with: pip install pyyaml{Colors.ENDC}")
                return rules
            data = yaml.safe_load(content)
        else:
            data = json.loads(content)

        for rule in data.get('rules', []):
            name = rule.get('name', 'Custom Rule')
            rules[name] = {
                'patterns': rule.get('patterns', []),
                'severity': rule.get('severity', 'MEDIUM').upper(),
                'validate': None,
                'case_sensitive': rule.get('case_sensitive', False),
                'context_required': rule.get('context_required', False),
                'preserve_severity': rule.get('preserve_severity', False),
            }
        if rules:
            print(f"{Colors.OKGREEN}[+] Loaded {len(rules)} custom rules "
                  f"from {filepath}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error loading rules: {e}{Colors.ENDC}")

    return rules


def load_gitleaks_config(filepath: str) -> Dict:
    """Load a Gitleaks TOML config as SecretScanner pattern rules.

    Requires tomllib (Python 3.11+) or tomli. Gitleaks regexes, secretGroup,
    keywords, and allowlists are honored.
    """
    rules = {}
    path = Path(filepath)
    if not path.exists():
        print(f"{Colors.FAIL}[!] Gitleaks config not found: {filepath}{Colors.ENDC}")
        return rules
    try:
        import tomllib as toml_mod
    except ImportError:
        try:
            import tomli as toml_mod
        except ImportError:
            print(f"{Colors.FAIL}[!] Gitleaks TOML import needs Python 3.11+ "
                  f"or 'pip install tomli'{Colors.ENDC}")
            return rules
    try:
        data = toml_mod.loads(path.read_text(encoding='utf-8'))
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error parsing Gitleaks config: {e}{Colors.ENDC}")
        return rules

    global_allowlists = []
    for key in ('allowlist', 'allowlists'):
        val = data.get(key)
        if isinstance(val, dict):
            global_allowlists.append(val)
        elif isinstance(val, list):
            global_allowlists.extend(v for v in val if isinstance(v, dict))

    for rule in data.get('rules', []):
        rid = rule.get('id')
        regex = rule.get('regex')
        if not rid or not regex:
            continue
        allowlists = list(global_allowlists)
        for key in ('allowlist', 'allowlists'):
            val = rule.get(key)
            if isinstance(val, dict):
                allowlists.append(val)
            elif isinstance(val, list):
                allowlists.extend(v for v in val if isinstance(v, dict))
        for allowlist in allowlists:
            valid = []
            for pat in allowlist.get('regexes') or []:
                try:
                    re.compile(pat)
                    valid.append(pat)
                except re.error as e:
                    print(f"{Colors.WARNING}  [!] Skipping invalid allowlist regex "
                          f"in rule '{rid}': {e}{Colors.ENDC}")
            allowlist['regexes'] = valid
        raw_patterns = regex if isinstance(regex, list) else [regex]
        compiled_ok = []
        for pat in raw_patterns:
            try:
                re.compile(pat)
                compiled_ok.append(pat)
            except re.error as e:
                print(f"{Colors.WARNING}  [!] Skipping invalid regex in rule "
                      f"'{rid}': {e}{Colors.ENDC}")
        if not compiled_ok:
            continue
        rules[f"Gitleaks: {rid}"] = {
            'patterns': compiled_ok,
            'severity': str(rule.get('severity', 'MEDIUM')).upper(),
            'validate': None,
            'case_sensitive': False,
            'context_required': False,
            'secret_group': rule.get('secretGroup', 0),
            'keywords': rule.get('keywords', []),
            'allowlists': allowlists,
            'preserve_severity': True,
        }

    if rules:
        print(f"{Colors.OKGREEN}[+] Loaded {len(rules)} Gitleaks rules "
              f"from {filepath}{Colors.ENDC}")
    return rules


# ═══════════════════════════════════════════════════════════════════
#  SARIF Output — v2.8
# ═══════════════════════════════════════════════════════════════════

def export_sarif(findings: List[Dict], stats: Dict, filename: str):
    """Export findings in SARIF 2.1.0 format for GitHub/GitLab CI integration."""
    rules = {}
    results = []

    for f in findings:
        ftype = str(f.get('type') or f.get('category') or 'Finding')
        rule_id = re.sub(r'[^a-z0-9]+', '-', ftype.lower()).strip('-') or 'finding'
        severity = str(f.get('severity', 'INFO')).upper()
        source = f.get('source') or 'unknown'
        status = f.get('status', 'potential')
        ev = f.get('evidence') or {}

        if rule_id not in rules:
            cwe = f.get('cwe', '')
            rule_props = {
                'security-severity': {
                    'CRITICAL': '9.5', 'HIGH': '7.5',
                    'MEDIUM': '5.0', 'LOW': '2.5', 'INFO': '0.0',
                }.get(severity, '5.0')
            }
            if cwe:
                rule_props['cwe'] = cwe
                cwe_num = re.search(r'(\d+)', cwe)
                if cwe_num:
                    rule_props['helpUri'] = (
                        f'https://cwe.mitre.org/data/definitions/{cwe_num.group(1)}.html'
                    )
            if f.get('owasp'):
                rule_props['owasp'] = f['owasp']
            if f.get('remediation'):
                rule_props['remediation'] = f['remediation']
            rule = {
                'id': rule_id,
                'name': ftype,
                'shortDescription': {'text': f"Detected {ftype}"},
                'defaultConfiguration': {
                    'level': {
                        'CRITICAL': 'error', 'HIGH': 'error',
                        'MEDIUM': 'warning', 'LOW': 'note', 'INFO': 'note',
                    }.get(severity, 'warning')
                },
                'properties': rule_props,
            }
            if rule_props.get('helpUri'):
                rule['helpUri'] = rule_props['helpUri']
            rules[rule_id] = rule

        val_masked = str(f.get('value', '') or '')
        if len(val_masked) > 12:
            val_masked = val_masked[:6] + '***' + val_masked[-4:]

        level = rules[rule_id]['defaultConfiguration']['level']
        if status == 'lead':
            level = 'note'
        elif status == 'potential' and level == 'error':
            level = 'warning'

        physical = {'artifactLocation': {'uri': source}}
        line_no = f.get('line') or ev.get('line')
        region = {}
        if line_no:
            try:
                region['startLine'] = max(1, int(line_no))
            except (TypeError, ValueError):
                pass
        snippet = f.get('snippet') or ev.get('snippet')
        if snippet:
            snippet_text = str(snippet)[:500]
            raw_value = str(f.get('value', '') or '')
            if raw_value and raw_value in snippet_text:
                snippet_text = snippet_text.replace(raw_value, mask_secret(raw_value))
            region['snippet'] = {'text': snippet_text}
        if region:
            physical['region'] = region

        repro_text = str(f.get('repro', '') or '')
        raw_value = str(f.get('value', '') or '')
        if raw_value and raw_value in repro_text:
            repro_text = repro_text.replace(raw_value, mask_secret(raw_value))

        result = {
            'ruleId': rule_id,
            'level': level,
            'message': {
                'text': f"Found {ftype} [{status}] "
                        f"(confidence: {f.get('confidence', '?')})"
                        + (f" — {val_masked}" if val_masked else '')
            },
            'locations': [{'physicalLocation': physical}],
            'properties': {
                'status': status,
                'category': f.get('category', ''),
                'confidence': f.get('confidence', 'LOW'),
                'validated': ev.get('validated', f.get('validated', False)),
                'entropy': ev.get('entropy', f.get('entropy', 0)),
                'fingerprint': f.get('id', ''),
                'cwe': f.get('cwe', ''),
                'owasp': f.get('owasp', ''),
                'remediation': f.get('remediation', ''),
                'repro': repro_text,
                'line': line_no,
            },
            'partialFingerprints': {'secretPulse/v1': f.get('id', '')},
        }
        if ev.get('public_by_design'):
            result['properties']['public_by_design'] = True
            result['properties']['reason'] = ev.get('reason', '')
        verified = f.get('verified_live', ev.get('verified_live'))
        if verified is not None:
            result['properties']['verified_live'] = verified
            result['properties']['verification_detail'] = (
                f.get('verification_detail')
                or (f.get('verification') or {}).get('detail', ''))

        results.append(result)

    sarif = {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'SecretPulse',
                    'version': __version__,
                    'informationUri': 'https://github.com/Zero2Root-VK/SecretPulse',
                    'rules': list(rules.values()),
                }
            },
            'results': results,
            'invocations': [{
                'executionSuccessful': True,
                'properties': {'network_stats': stats},
            }],
        }]
    }

    with open(filename, 'w') as f:
        json.dump(sarif, f, indent=2, default=str)
    print(f"{Colors.OKGREEN}[+] SARIF exported to {filename}{Colors.ENDC}")
