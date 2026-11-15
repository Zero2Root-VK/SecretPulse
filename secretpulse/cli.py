"""Command-line interface and scan orchestration."""
from ._imports import *
from .constants import __author__, __version__
from .utils import Colors
from .analysis import FalsePositiveFilter
from .discovery import AttackChainBuilder, CICDIntegration, CloudNativeScanner, RateAbuseTester
from .exposure import CORSDetector, CloudPermissionTester, DependencyConfusionScanner, JWTExploitTester, OpenRedirectDetector
from .recon import ReconOrchestrator, SmartRouter
from .storage import SecretPulseDB
from .scanner import SecretScanner
from .reporting import export_sarif, load_custom_rules, load_gitleaks_config

def print_banner():
    v = f"v{__version__}"
    a = __author__
    import re

    # 256-color ANSI for gradient effect (cyan → blue → purple)
    c1 = '\033[38;5;87m'    # bright cyan
    c2 = '\033[38;5;75m'    # sky blue
    c3 = '\033[38;5;111m'   # light blue
    c4 = '\033[38;5;141m'   # lavender
    c5 = '\033[38;5;135m'   # purple
    cf = '\033[38;5;240m'   # frame gray
    cw = '\033[38;5;255m'   # bright white
    cy = '\033[38;5;220m'   # gold
    cd = '\033[38;5;245m'   # dim text
    ch = '\033[38;5;60m'    # hex gray
    cr = '\033[38;5;203m'   # warning coral
    B = Colors.BOLD
    R = Colors.ENDC
    W = 72

    def vl(s):
        return len(re.sub(r'\033\[[0-9;]*m', '', s))

    def fr(content=""):
        """Frame a line: ║ content padded to W ║"""
        pad = ' ' * max(0, W - vl(content))
        return f"  {cf}║{R}{content}{pad}{cf}║{R}"

    # SecretPulse in hex = 53 45 43 52 45 54 20 50 55 4C 53 45
    hex_sig = f"{ch}53 45 43 52 45 54 20 50 55 4C 53 45{R}"

    # Logo lines (ASCII art for SECRET PULSE)
    L = [
        f"{c1}{B}  ██████  ███████  ██████  ██████  ███████  ████████ {R}",
        f"{c2}{B} ██       ██      ██      ██   ██ ██          ██    {R}",
        f"{c3}{B}  █████   █████   ██      ██████  █████       ██    {R}",
        f"{c4}{B}      ██  ██      ██      ██   ██ ██          ██    {R}",
        f"{c5}{B}  ██████   ███████  ██████  ██   ██ ███████     ██    {R}",
        f" ",
        f"{c1}{B}  ██████  ██    ██ ██      ███████ ███████           {R}",
        f"{c2}{B}  ██   ██ ██    ██ ██      ██      ██                {R}",
        f"{c3}{B}  ██████  ██    ██ ██      █████   █████             {R}",
        f"{c4}{B}  ██      ██    ██ ██      ██      ██                {R}",
        f"{c5}{B}  ██       ██████  ███████ ███████ ███████           {R}",
    ]

    top = f"  {cf}╔{'═' * W}╗{R}"
    bot = f"  {cf}╚{'═' * W}╝{R}"
    sep = f"  {cf}║ {ch}{'─' * (W - 2)}{R} {cf}║{R}"

    print()
    print(top)
    print(fr())
    for line in L:
        print(fr(f"    {line}"))
    print(fr())
    print(sep)
    print(fr(f"   {ch}0x{R}{hex_sig}"))
    print(sep)
    print(fr())
    ce = '\033[38;5;79m'  # community teal
    print(fr(f"   {ce}◆{R} {cw}{B}{v}{R}                  {ce}◆{R} {ce}Standard Edition{R}"))
    print(fr(f"   {ce}◆{R} {cw}{a}{R}             {ce}◆{R} {cd}Full Features Unlocked{R}"))
    print(fr())
    print(fr(f"   {c1}▸{R} {cw}Identify secrets. Verify validity. Stealth mode enabled.{R}"))
    print(fr(f"   {c1}▸{R} {cd}Active analysis engine with offensive reconnaissance.{R}"))
    print(fr())
    print(fr(f"   {cr}⚠{R}  {cd}For authorized security testing only.{R}"))
    print(fr())
    print(bot)
    print()


def load_scan_config(path):
    """Load JSON/TOML scan config without silently accepting malformed values."""
    if not path:
        return {}
    p = Path(path).expanduser()
    if not p.is_file():
        raise ValueError(f'Config file not found: {path}')
    raw = p.read_text()
    if p.suffix.lower() == '.toml':
        try:
            import tomllib as toml_mod
        except ImportError:
            try:
                import tomli as toml_mod
            except ImportError as exc:
                raise ValueError(
                    'TOML config requires Python 3.11+ or: pip install tomli'
                ) from exc
        data = toml_mod.loads(raw)
    else:
        data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError('Config root must be an object/table')
    return data


def parse_header_lines(values):
    headers = {}
    for item in values or []:
        if ':' not in item:
            raise ValueError(f'Invalid header (expected Name: Value): {item!r}')
        name, value = item.split(':', 1)
        name, value = name.strip(), value.strip()
        if not name:
            raise ValueError(f'Invalid header name: {item!r}')
        headers[name] = value
    return headers


def main():
    parser = argparse.ArgumentParser(
        description=f'SecretPulse v{__version__} — High-Signal Secret & API Exposure Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Author: {__author__}

Examples:
  %(prog)s https://example.com --smart
  %(prog)s https://example.com --smart --verify --fail-on high
  %(prog)s https://example.com --scope scope.txt --baseline prev.json
  %(prog)s https://example.com --smart -o results.json --html report.html
  %(prog)s --path ./src --fail-on high
  %(prog)s --staged --fail-on high
  %(prog)s --git . --git-max-commits 200
        """
    )
    parser.add_argument('urls', nargs='*', help='URLs to scan')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-o', '--output', help='JSON output file')
    parser.add_argument('--html', help='HTML report file')
    parser.add_argument('--sarif', help='SARIF output file (for CI/CD)')
    parser.add_argument('--fail-on', choices=['none', 'critical', 'high', 'medium', 'low', 'any'],
                        default='none',
                        help='Exit 1 when confirmed/potential findings meet this severity (CI gate)')
    parser.add_argument('--scope', help='Scope file (one domain per line)')
    parser.add_argument('--verify', action='store_true', help='Active API verification (66 read-only routes)')
    parser.add_argument('--smart', action='store_true',
                        help='Intelligence-driven scanning: auto-selects modules per target')
    parser.add_argument('--path', help='Scan a local file or directory for secrets')
    parser.add_argument('--staged', nargs='?', const='.', metavar='REPO',
                        help='Scan staged git index changes (default: current repo)')
    parser.add_argument('--git', help='Scan a local git repository history for secrets')
    parser.add_argument('--git-max-commits', type=int, default=500,
                        help='Max commits to inspect with --git (0 = all)')
    parser.add_argument('--gitleaks-config', help='Import Gitleaks TOML rules')
    parser.add_argument('--db', action='store_true', help='Enable SQLite persistence and scan history')
    parser.add_argument('--diff', action='store_true', help='Show delta vs previous scan (requires --db)')
    parser.add_argument('--baseline', help='Baseline JSON for diff detection')
    parser.add_argument('--config', help='JSON/TOML scan config ([http]/[verify] sections)')
    parser.add_argument('--header', action='append', default=[],
                        help='Extra HTTP header for target requests (repeatable: Name: Value)')
    parser.add_argument('--cookie', help='Cookie header for authenticated target requests')
    parser.add_argument('--proxy', help='HTTP(S) proxy URL for target requests')
    parser.add_argument('--timeout', type=float,
                        help='Target request timeout in seconds (default: 15)')
    parser.add_argument('--max-response-kb', type=int,
                        help='Maximum response body size in KiB (default: 10240)')
    parser.add_argument('--verify-providers',
                        help='Comma-separated provider filters for --verify (e.g. stripe,github)')
    parser.add_argument('--allow-webhook-checks', action='store_true',
                        help='Allow side-effecting Slack webhook verification')

    parser.set_defaults(
        no_validate=False, depth=0, workers=5,
        retries=3, ua_rotate=False, probe_env=False, probe_graphql=False,
        probe_swagger=False, rate_limit=0, rules=None, no_progress=False,
        scan_cloud=False, notify=None, wayback=False, subtko=False,
        ssrf_probe=False, fuzz_idor=False, attack_chains=False,
        rate_abuse=False, cve_lookup=False,
        recon=False, cors_check=False, open_redirect=False,
        dep_confusion=False, jwt_exploit=False, cloud_perms=False,
    )

    args = parser.parse_args()

    # ── --smart flag: intelligence-driven ──
    if args.smart:
        args.recon = True
        args.db = True
        # Standard: --smart does NOT auto-enable --verify
        # Don't enable any exposure modules globally —
        # SmartRouter will enable them per-target

    if not args.urls and not args.path and not args.git and args.staged is None:
        parser.print_help()
        return

    print_banner()

    # ── Strict target validation ──
    def validate_target(url: str) -> Optional[str]:
        """Validate and clean a target URL. Returns cleaned URL or None."""
        url = url.strip()
        if not url or url.startswith('#'):
            return None
        # Reject empty strings, whitespace, control chars
        if not url or len(url) < 4:
            return None
        if any(c in url for c in ['\n', '\r', '\t', ' ']):
            return None
        # Auto-prepend https:// if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        # Validate URL structure
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                if args.verbose:
                    print(f"{Colors.WARNING}  [!] Rejected invalid target: {url}{Colors.ENDC}")
                return None
            host = (parsed.hostname or '').lower()
            in_scope = any(host == d or host.endswith('.' + d) for d in scope_domains)
            is_local = (host in ('localhost', '127.0.0.1', '0.0.0.0', '::1')
                        or host.endswith('.localhost'))
            try:
                ip = ipaddress.ip_address(host)
                is_local = is_local or ip.is_private or ip.is_loopback or ip.is_link_local
            except ValueError:
                pass
            if is_local and not in_scope:
                if args.verbose:
                    print(f"{Colors.WARNING}  [!] Rejected local/private target without scope: {url}{Colors.ENDC}")
                return None
            if not is_local and '.' not in parsed.netloc:
                if args.verbose:
                    print(f"{Colors.WARNING}  [!] Rejected invalid target: {url}{Colors.ENDC}")
                return None
        except Exception:
            return None
        return url

    # Load scope domains
    scope_domains = []
    if args.scope:
        try:
            with open(args.scope) as f:
                scope_domains = [l.strip().lower() for l in f if l.strip() and not l.startswith('#')]
            print(f"{Colors.OKGREEN}[+] Scope: {len(scope_domains)} domains{Colors.ENDC}")
        except FileNotFoundError:
            print(f"{Colors.FAIL}[!] Scope file not found: {args.scope}{Colors.ENDC}")
            sys.exit(2)

    # Load custom rules
    custom_rules = None
    if args.rules:
        custom_rules = load_custom_rules(args.rules)
    if args.gitleaks_config:
        custom_rules = custom_rules or {}
        custom_rules.update(load_gitleaks_config(args.gitleaks_config))

    # Initialize database if requested
    db = SecretPulseDB() if args.db else None

    # ── HTTP/verification config (CLI overrides file) ──
    try:
        scan_config = load_scan_config(args.config)
    except (ValueError, json.JSONDecodeError, OSError) as exc:
        print(f"{Colors.FAIL}[!] Config error: {exc}{Colors.ENDC}")
        return 2
    http_cfg = scan_config.get('http') or {}
    verify_cfg = scan_config.get('verify') or {}
    if not isinstance(http_cfg, dict) or not isinstance(verify_cfg, dict):
        print(f"{Colors.FAIL}[!] Config error: [http]/[verify] must be tables{Colors.ENDC}")
        return 2

    try:
        config_headers = http_cfg.get('headers') or {}
        if isinstance(config_headers, dict):
            custom_headers = {str(k): str(v) for k, v in config_headers.items()}
        elif isinstance(config_headers, list):
            custom_headers = parse_header_lines([str(v) for v in config_headers])
        else:
            raise ValueError('http.headers must be a table or list')
        custom_headers.update(parse_header_lines(args.header))

        cookies = args.cookie or http_cfg.get('cookies') or ''
        if isinstance(cookies, dict):
            cookies = '; '.join(f'{k}={v}' for k, v in cookies.items())
        proxy = args.proxy or http_cfg.get('proxy') or ''
        timeout = args.timeout if args.timeout is not None else http_cfg.get('timeout', 15.0)
        max_bytes = (
            int(args.max_response_kb) * 1024 if args.max_response_kb is not None
            else int(http_cfg.get('max_response_bytes', 10 * 1024 * 1024))
        )
        providers = (
            [p.strip() for p in args.verify_providers.split(',') if p.strip()]
            if args.verify_providers
            else [str(p).strip() for p in (verify_cfg.get('providers') or []) if str(p).strip()]
        )
        allow_webhooks = bool(
            args.allow_webhook_checks or verify_cfg.get('allow_webhooks', False)
        )
    except (TypeError, ValueError) as exc:
        print(f"{Colors.FAIL}[!] Config error: {exc}{Colors.ENDC}")
        return 2

    scanner = SecretScanner(
        verbose=args.verbose, max_workers=args.workers,
        crawl_depth=args.depth, no_validate=args.no_validate,
        max_retries=args.retries, ua_rotate=args.ua_rotate,
        probe_env=args.probe_env, probe_graphql=args.probe_graphql,
        show_progress=not args.no_progress, verify_live=args.verify,
        rate_limit=args.rate_limit, scope_domains=scope_domains,
        custom_rules=custom_rules, notify_url=args.notify,
        baseline_path=args.baseline, probe_swagger=args.probe_swagger,
        scan_cloud=args.scan_cloud,
        wayback=args.wayback, subtko=args.subtko,
        ssrf_probe=args.ssrf_probe, fuzz_idor=args.fuzz_idor,
        cors_check=args.cors_check, open_redirect=args.open_redirect,
        dep_confusion=args.dep_confusion,
        jwt_exploit=args.jwt_exploit, cloud_perms=args.cloud_perms,
        request_timeout=timeout, max_response_bytes=max_bytes,
        custom_headers=custom_headers, cookies=cookies, proxy=proxy,
        verify_providers=providers, allow_webhook_checks=allow_webhooks,
    )

    urls_to_scan = []
    if len(args.urls) == 1 and args.urls[0].endswith('.txt'):
        try:
            with open(args.urls[0]) as f:
                raw_lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            urls_to_scan = [u for u in (validate_target(t) for t in raw_lines) if u]
            print(f"[*] Loaded {len(urls_to_scan)} valid URLs\n")
        except FileNotFoundError:
            print(f"{Colors.FAIL}[!] File not found{Colors.ENDC}")
            sys.exit(2)
    else:
        # CLI args — validate each target
        for raw_url in args.urls:
            cleaned = validate_target(raw_url)
            if cleaned:
                urls_to_scan.append(cleaned)
            elif args.verbose:
                print(f"{Colors.WARNING}[!] Skipping invalid target: '{raw_url}'{Colors.ENDC}")

    local_scan_requested = bool(args.path or args.git or args.staged is not None)
    if not urls_to_scan and not local_scan_requested:
        print(f"{Colors.FAIL}[!] No valid targets to scan{Colors.ENDC}")
        sys.exit(2)
    if args.path and not Path(args.path).expanduser().exists():
        print(f"{Colors.FAIL}[!] Path not found: {args.path}{Colors.ENDC}")
        sys.exit(2)
    if args.staged is not None and not Path(args.staged).expanduser().exists():
        print(f"{Colors.FAIL}[!] Repository path not found: {args.staged}{Colors.ENDC}")
        sys.exit(2)
    if args.git and not Path(args.git).expanduser().exists():
        print(f"{Colors.FAIL}[!] Git repository not found: {args.git}{Colors.ENDC}")
        sys.exit(2)

    if urls_to_scan:
        print(f"[*] Targets: {len(urls_to_scan)}")
    if args.path:
        print(f"[*] Local path: {args.path}")
    if args.staged is not None:
        print(f"[*] Staged git index: {args.staged}")
    if args.git:
        commit_cap = args.git_max_commits if args.git_max_commits > 0 else 'all'
        print(f"[*] Git history: {args.git} (max {commit_cap} commits)")
    if args.depth:
        print(f"[*] Crawl depth: {args.depth}")
    print(f"[*] Workers: {args.workers} · Retries: {args.retries}")
    if args.ua_rotate:
        print(f"[*] UA rotation: ON")
    if args.verify:
        print(f"[*] Active verification: ON (66 read-only verifier routes)")
        if providers:
            print(f"[*] Verify providers: {', '.join(providers)}")
        if allow_webhooks:
            print(f"[*] Webhook side effects: ENABLED")
    if args.config:
        print(f"[*] Config: {args.config} · timeout {timeout:g}s · "
              f"body cap {max_bytes // 1024} KiB")
    if custom_headers or cookies or proxy:
        print(f"[*] Authenticated HTTP: {len(custom_headers)} header(s)"
              f"{' + cookie' if cookies else ''}{' + proxy' if proxy else ''}")
    if args.rate_limit:
        print(f"[*] Rate limit: {args.rate_limit} req/s")
    if args.probe_env:
        print(f"[*] .env probing: ON")
    if args.probe_graphql:
        print(f"[*] GraphQL probing: ON")
    if args.probe_swagger:
        print(f"[*] Swagger/OpenAPI probing: ON")
    if args.scan_cloud:
        print(f"[*] Cloud native scanning: ON")
    if args.wayback:
        print(f"[*] Wayback Machine mining: ON")
    if args.subtko:
        print(f"[*] Dangling DNS check: ON")
    if args.ssrf_probe:
        print(f"[*] Internal endpoint check: ON")
    if args.fuzz_idor:
        print(f"[*] Access control check: ON")
    if hasattr(args, 'attack_chains') and args.attack_chains:
        print(f"[*] Attack chain analysis: ON")
    if args.cve_lookup:
        print(f"[*] CVE auto-lookup: ON")
    if args.rate_abuse:
        print(f"[*] Rate limit analysis: ON (safe mode — max {RateAbuseTester.SAFE_MODE_MAX_PROBES} probes/key)")
    if args.notify:
        print(f"[*] Notifications: {args.notify[:50]}...")
    if args.baseline:
        print(f"[*] Baseline: {args.baseline}")
    if args.recon:
        print(f"[*] Subdomain recon: ON (CT logs + DNS + risk scoring)")
    if args.db:
        print(f"[*] SQLite persistence: ON (~/.SecretPulse/SecretPulse.db)")
    if args.cors_check:
        print(f"[*] CORS check: ON")
    if args.open_redirect:
        print(f"[*] Open redirect check: ON")
    if args.dep_confusion:
        print(f"[*] Dependency confusion check: ON")
    if args.jwt_exploit:
        print(f"[*] JWT exploitation: ON")
    if args.cloud_perms:
        print(f"[*] Cloud permission testing: ON (read-only)")
    if args.smart:
        print(f"[*] {Colors.OKGREEN}SMART MODE: ON — modules selected per target{Colors.ENDC}")
    print()

    # ── Phase 1: Subdomain Recon ──
    scan_id = None
    recon_urls = []
    if args.recon:
        # Extract domain from first target
        first_target = urls_to_scan[0] if urls_to_scan else ''
        target_domain = urlparse(first_target).netloc if first_target else ''
        if target_domain:
            recon = ReconOrchestrator(
                session=scanner.session, db=db, verbose=args.verbose,
                rate_limit=args.rate_limit, max_workers=args.workers,
            )
            discovered = recon.discover(target_domain)

            if discovered:
                recon_urls = recon.get_scan_urls()

                # Add recon URLs to scan queue (avoid duplicates)
                existing = set(urls_to_scan)
                for ru in recon_urls:
                    if ru not in existing:
                        urls_to_scan.append(ru)
                        existing.add(ru)

                if recon_urls:
                    print(f"{Colors.OKGREEN}[+] Added {len(recon_urls)} subdomain URLs "
                          f"to scan queue{Colors.ENDC}\n")

    # ── Smart Router: Build per-target scan plan ──
    smart_plan = []
    if args.smart and urls_to_scan:
        target_domain = urlparse(urls_to_scan[0]).netloc if urls_to_scan else ''
        # Build plan from recon data if available, else from URL list
        if recon_urls and hasattr(recon, 'subdomains') and recon.subdomains:
            smart_plan = SmartRouter.plan(recon.subdomains, target_domain, args.verbose)
        else:
            # Classify from URLs alone (no recon data)
            fake_targets = [{'subdomain': urlparse(u).netloc, 'risk_score': 50} for u in urls_to_scan]
            smart_plan = SmartRouter.plan(fake_targets, target_domain, args.verbose)

    # ── DB: Register scan ──
    if db:
        config = {
            'depth': args.depth, 'workers': args.workers,
            'verify': args.verify, 'recon': args.recon,
            'smart': args.smart,
        }
        target_str = urls_to_scan[0] if urls_to_scan else (
            args.git or args.path or args.staged or 'local')
        scan_id = db.start_scan(target_str, config)

    scanner.progress.set_total(len(urls_to_scan))
    start = time.time()

    if args.staged is not None:
        if scanner.scan_staged_changes(args.staged) < 0:
            if db:
                db.close()
            sys.exit(2)
    if args.path:
        scanner.scan_local_path(args.path)
    if args.git:
        scanner.scan_git_history(args.git, args.git_max_commits)

    for url in urls_to_scan:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        # Smart routing: dynamically enable/disable modules per target
        if args.smart and smart_plan:
            active_modules = SmartRouter.get_modules_for_url(url, smart_plan)
            scanner.smart_selected_modules.update(active_modules)
            scanner.probe_env = 'probe_env' in active_modules
            scanner.probe_graphql = 'probe_graphql' in active_modules
            scanner.probe_swagger = 'probe_swagger' in active_modules
            scanner.probe_sensitive = 'sensitive_files' in active_modules
            scanner.enable_subtko = 'takeover' in active_modules
            scanner.enable_ssrf = 'ssrf_probe' in active_modules
            scanner.enable_fuzz_idor = 'fuzz_idor' in active_modules
            scanner.enable_cors = 'cors_check' in active_modules
            scanner.enable_redirect = 'open_redirect' in active_modules
            scanner.enable_cloud_perms = 'cloud_perms' in active_modules
            scanner.enable_jwt_exploit = 'jwt_exploit' in active_modules
            scanner.enable_dep_confusion = 'dep_confusion' in active_modules
            # Lazy-init exposure modules only when needed (use getattr for safety)
            if scanner.enable_cors and not getattr(scanner, 'cors_detector', None):
                scanner.cors_detector = CORSDetector(scanner.session, scanner.rate_limiter, scanner.verbose)
            if scanner.enable_redirect and not getattr(scanner, 'redirect_detector', None):
                scanner.redirect_detector = OpenRedirectDetector(scanner.session, scanner.rate_limiter, scanner.verbose)
            if scanner.enable_cloud_perms and not getattr(scanner, 'cloud_perm_tester', None):
                scanner.cloud_perm_tester = CloudPermissionTester(scanner.session, scanner.rate_limiter, scanner.verbose)
            if 'scan_cloud' in active_modules and not scanner.cloud_scanner:
                scanner.cloud_scanner = CloudNativeScanner()

        scanner.scan_url(url, depth=0)

    elapsed = time.time() - start
    scanner.progress.finish()

    # v3.0: Apply false positive filter (enhanced with entropy thresholds)
    kept, removed = FalsePositiveFilter.filter_findings(scanner.found_secrets)
    scanner.fp_removed = removed
    scanner.found_secrets = kept
    scanner.stats['fp_filtered'] = len(removed)

    # v5.0: Apply AccuracyEngine (8 intelligence upgrades)
    if scanner.found_secrets:
        pre_count = len(scanner.found_secrets)
        scanner.found_secrets = scanner.accuracy_engine.process_findings(
            scanner.found_secrets, scanner.content_cache
        )
        acc_stats = scanner.accuracy_engine.get_stats()
        env_profile = acc_stats.get('environment_profile', 'default')
        if env_profile != 'default':
            print(f"\n{Colors.OKCYAN}[*] Environment detected: {env_profile} "
                  f"(weights auto-adjusted){Colors.ENDC}")
        if acc_stats.get('upgrades_applied'):
            upgrades_summary = ', '.join(
                f"{k}: {v}" for k, v in acc_stats['upgrades_applied'].items()
                if v and k != 'dynamic_weights'
            )
            if upgrades_summary:
                print(f"{Colors.OKCYAN}[*] Accuracy Engine: {upgrades_summary}{Colors.ENDC}")
            deduped = acc_stats['upgrades_applied'].get('smart_dedup', 0)
            if deduped:
                print(f"{Colors.DIM}    Smart dedup removed {deduped} duplicate(s){Colors.ENDC}")
        cal_count = acc_stats.get('calibration_entries', 0)
        if cal_count:
            print(f"{Colors.DIM}    Calibration: {cal_count} findings logged to ~/.SecretPulse/calibration.json{Colors.ENDC}")

    if removed:
        print(f"\n{Colors.DIM}[*] Filtered {len(removed)} false positive(s):{Colors.ENDC}")
        # Categorize removals
        reasons = {}
        for fp in removed:
            reason = fp.get('fp_reason', 'Unknown')
            # Simplify reason for display
            if 'Entropy too low' in reason:
                cat = 'Low entropy'
            elif 'Placeholder' in reason:
                cat = 'Placeholder pattern'
            elif 'Test/example' in reason:
                cat = 'Test/example file'
            elif 'Documentation' in reason:
                cat = 'Documentation source'
            elif 'external CDN' in reason:
                cat = 'External CDN'
            elif 'Duplicate' in reason:
                cat = 'Duplicate'
            elif 'Too short' in reason:
                cat = 'Too short'
            else:
                cat = 'Other'
            reasons[cat] = reasons.get(cat, 0) + 1
        for cat, count in sorted(reasons.items(), key=lambda x: -x[1]):
            print(f"{Colors.DIM}    {cat}: {count}{Colors.ENDC}")

    # v4.0: Wayback Machine mining
    if args.wayback and urls_to_scan:
        domain = urlparse(urls_to_scan[0]).netloc
        print(f"\n{Colors.OKCYAN}[*] Mining Wayback Machine for {domain} (target-scoped)...{Colors.ENDC}")
        wb_urls = scanner.wayback.mine(domain, max_results=50)
        scanner.stats['wayback_urls'] = len(wb_urls)
        if wb_urls:
            print(f"{Colors.OKGREEN}[+] Found {len(wb_urls)} in-scope archived URLs"
                  f" ({scanner.wayback.filtered_count} off-scope dropped){Colors.ENDC}")
            for wb_url in wb_urls[:20]:
                scanner.scan_url(wb_url, depth=0)

    # v4.0: Subdomain takeover check
    if args.subtko and urls_to_scan:
        domain = urlparse(urls_to_scan[0]).netloc
        print(f"\n{Colors.OKCYAN}[*] Checking subdomain takeover for {domain}...{Colors.ENDC}")
        scanner.subtko.check_cname(domain)
        scanner.stats['subtko_findings'] = len(scanner.subtko.findings)

    # v4.0: Collect recon stats
    scanner.stats['ssrf_vectors'] = len(scanner.ssrf_prober.vectors)
    scanner.stats['idor_candidates'] = len(scanner.idor_fuzzer.idor_candidates)
    scanner.stats['internal_routes'] = len(scanner.internal_api_enum.routes)

    # v4.0: Attack chain analysis
    if hasattr(args, 'attack_chains') and args.attack_chains:
        scanner.attack_chains = AttackChainBuilder.build_chains(scanner.found_secrets)
        scanner.stats['attack_chains'] = len(scanner.attack_chains)

    # v5.0: CVE auto-lookup from source map packages
    if args.cve_lookup and scanner.source_map_intel:
        print(f"\n{Colors.OKCYAN}[*] Running CVE lookup for source map packages...{Colors.ENDC}")
        all_pkgs = set()
        for sm in scanner.source_map_intel:
            all_pkgs.update(sm.get('npm_packages', []))
        sc_pkgs = scanner.supply_chain.npm_packages
        all_pkgs.update(sc_pkgs)
        if all_pkgs:
            scanner.cve_lookup.lookup_packages(sorted(all_pkgs), scanner.source_map_intel)
            cve_sum = scanner.cve_lookup.get_summary()
            scanner.stats['cve_confirmed'] = cve_sum['confirmed_vulnerable']
            scanner.stats['cve_potential'] = cve_sum['potential']
            print(f"{Colors.OKGREEN}[+] CVE lookup: {cve_sum['confirmed_vulnerable']} confirmed, "
                  f"{cve_sum['potential']} potential{Colors.ENDC}")

    # v5.0: API rate abuse testing
    if args.rate_abuse and scanner.rate_tester:
        print(f"\n{Colors.OKCYAN}[*] Checking rate limit protection on verified keys...{Colors.ENDC}")
        scanner.rate_tester.test_findings(scanner.found_secrets)
        rate_sum = scanner.rate_tester.get_summary()
        scanner.stats['rate_abuse_unrestricted'] = rate_sum['unrestricted']

    # Collect supply chain stats
    sc_sum = scanner.supply_chain.get_summary()
    scanner.stats['supply_chain_vulns'] = sc_sum['vulnerable_libraries']
    scanner.stats['sri_missing'] = sc_sum['sri_missing']
    scanner.stats['header_issues'] = len(scanner.headers_auditor.findings)
    scanner.stats['swagger_specs'] = len(scanner.api_discovery.swagger_specs)
    if scanner.cloud_scanner:
        scanner.stats['cloud_findings'] = len(scanner.cloud_scanner.findings)

    if scanner.found_secrets:
        print(f"\n{Colors.OKGREEN}[+] {len(scanner.found_secrets)} "
              f"secret(s) in {elapsed:.1f}s!{Colors.ENDC}")
        scanner.print_details()
    else:
        print(f"\n{Colors.OKBLUE}[*] No high-confidence secrets detected ({elapsed:.1f}s){Colors.ENDC}")

    scanner.print_summary()

    # v4.0: Attack chain display
    if scanner.attack_chains:
        AttackChainBuilder.print_chains(scanner.attack_chains)

    # v4.0: Offensive recon summary
    recon_items = []
    if scanner.ssrf_prober.vectors:
        recon_items.append(f"Internal endpoints: {len(scanner.ssrf_prober.vectors)}")
    if scanner.idor_fuzzer.idor_candidates:
        recon_items.append(f"IDOR candidates: {len(scanner.idor_fuzzer.idor_candidates)}")
    if scanner.internal_api_enum.routes:
        recon_items.append(f"Internal routes: {len(scanner.internal_api_enum.routes)}")
    if scanner.subtko.findings:
        recon_items.append(f"SubTKO findings: {len(scanner.subtko.findings)}")
    if scanner.wayback.archived_urls:
        recon_items.append(f"Wayback URLs: {len(scanner.wayback.archived_urls)}")
    if recon_items:
        print(f"\n{Colors.BOLD}Extended Recon:{Colors.ENDC}")
        for item in recon_items:
            print(f"  {item}")
    if scanner.internal_api_enum.routes:
        crit_routes = [r for r in scanner.internal_api_enum.routes if r['severity'] in ('CRITICAL', 'HIGH')]
        if crit_routes:
            print(f"\n{Colors.FAIL}High-value internal routes:{Colors.ENDC}")
            for r in crit_routes[:10]:
                print(f"  [{r['severity']}] {r['route']}  ({r['source'][:50]})")

    # ── v6.0: Exposure module results ──
    exposure_items = []

    # CORS results
    if getattr(scanner, 'cors_detector', None) and scanner.cors_detector.findings:
        cors_sum = scanner.cors_detector.get_summary()
        exposure_items.append(f"CORS misconfigs: {cors_sum['total']} ({cors_sum['critical']} critical)")
        if not args.verbose:
            for f in scanner.cors_detector.findings[:5]:
                print(f"  {Colors.FAIL}[CORS] [{f['severity']}]{Colors.ENDC} {f['detail']}")

    # Open redirect results
    if getattr(scanner, 'redirect_detector', None) and scanner.redirect_detector.findings:
        exposure_items.append(f"Open redirects: {len(scanner.redirect_detector.findings)}")

    # Cloud permissions
    if getattr(scanner, 'cloud_perm_tester', None) and scanner.cloud_perm_tester.findings:
        exposure_items.append(f"Cloud misconfigs: {len(scanner.cloud_perm_tester.findings)}")

    if exposure_items:
        print(f"\n{Colors.BOLD}Exposure Analysis:{Colors.ENDC}")
        for item in exposure_items:
            print(f"  {item}")

    smart_modules = getattr(scanner, 'smart_selected_modules', set())

    # v6.0: Dependency confusion (runs post-scan using source map data)
    if (args.dep_confusion or 'dep_confusion' in smart_modules) and scanner.source_map_intel:
        dep_scanner = DependencyConfusionScanner(scanner.session, scanner.rate_limiter, args.verbose)
        target_domain = urlparse(urls_to_scan[0]).netloc if urls_to_scan else ''
        dep_scanner.check_from_source_maps(scanner.source_map_intel, target_domain)
        scanner.dep_confusion_findings = dep_scanner.findings
        if dep_scanner.findings:
            print(f"\n{Colors.FAIL}[!] Dependency Confusion: "
                  f"{len(dep_scanner.findings)} vulnerable package(s){Colors.ENDC}")
            for f in dep_scanner.findings[:5]:
                print(f"  [{f['severity']}] {f['detail']}")

    # v6.0: JWT exploitation (runs post-scan on discovered JWTs)
    if (args.jwt_exploit or 'jwt_exploit' in smart_modules) and scanner.found_secrets:
        jwt_tester = JWTExploitTester(scanner.session, scanner.rate_limiter, args.verbose)
        jwt_findings = [f for f in scanner.found_secrets if 'JWT' in f.get('type', '').upper()
                        or f.get('type', '') == 'JSON Web Token']
        for jf in jwt_findings:
            jwt_tester.test_token(jf.get('value', ''), jf.get('source', ''))
        scanner.jwt_findings = jwt_tester.findings
        if jwt_tester.findings:
            print(f"\n{Colors.FAIL}[!] JWT Exploitation: "
                  f"{len(jwt_tester.findings)} finding(s){Colors.ENDC}")
            for f in jwt_tester.findings[:5]:
                print(f"  [{f['severity']}] {f['detail']}")

    # v6.0: Cloud permission testing (read-only, runs post-scan)
    if (args.cloud_perms or 'cloud_perms' in smart_modules) and scanner.found_secrets:
        if not getattr(scanner, 'cloud_perm_tester', None):
            scanner.cloud_perm_tester = CloudPermissionTester(
                scanner.session, scanner.rate_limiter, args.verbose)
        scanner.cloud_perm_tester.test_from_findings(scanner.found_secrets)
        if scanner.cloud_perm_tester.findings:
            print(f"\n{Colors.FAIL}[!] Cloud Permissions: "
                  f"{len(scanner.cloud_perm_tester.findings)} misconfig(s){Colors.ENDC}")
            for f in scanner.cloud_perm_tester.findings[:5]:
                print(f"  [{f['severity']}] {f['detail']}")

    current_findings = scanner.collect_findings()

    # v3.0: Baseline diff — the gate must evaluate only findings new since the baseline
    if args.baseline:
        new_findings, resolved = CICDIntegration.diff_baseline(
            current_findings, args.baseline)
        scanner.exit_findings = new_findings
        print(f"\n{Colors.BOLD}📊 Baseline Diff:{Colors.ENDC}")
        print(f"  New findings: {len(new_findings)}")
        print(f"  Resolved: {len(resolved)}")
        if new_findings:
            print(f"\n{Colors.WARNING}New findings:{Colors.ENDC}")
            for f in new_findings[:10]:
                print(f"  + [{f['severity']}] {f['type']} in {f.get('source', '')[:60]}")
        if resolved:
            print(f"\n{Colors.OKGREEN}Resolved:{Colors.ENDC}")
            for f in resolved[:10]:
                print(f"  - [{f['severity']}] {f['type']}")

    # v5.1.1: Top targets worth manual testing (v5.1.2: fixed empty modules)
    if args.smart and smart_plan:
        ranked = sorted(smart_plan, key=lambda x: x.get('risk_score', 0), reverse=True)
        top_targets = [t for t in ranked if t.get('risk_score', 0) >= 30][:5]
        if top_targets:
            print(f"\n{Colors.BOLD}🎯 TOP TARGETS WORTH MANUAL TESTING:{Colors.ENDC}")
            for i, t in enumerate(top_targets, 1):
                rs = t.get('risk_score', 0)
                rc = Colors.FAIL if rs >= 70 else (Colors.WARNING if rs >= 50 else Colors.OKCYAN)
                sub = t.get('subdomain', t.get('url', '?'))
                atype = t.get('smart_type', t.get('asset_type', 'unknown')).upper().replace('_', ' ')
                # Get modules from smart plan — try smart_modules first, then modules
                mods = t.get('smart_modules', t.get('modules', []))
                # Filter out always-on modules for cleaner display
                display_mods = [m for m in mods if m not in ('secret_scan', 'verify')][:5]
                if not display_mods:
                    # Recommend manual testing modules based on asset type
                    display_mods = ['manual: cors, headers, auth bypass']
                modules_str = ', '.join(display_mods)
                print(f"  {rc}{i}. {sub} (Score {rs}) [{atype}]{Colors.ENDC}")
                print(f"     {Colors.DIM}Modules: {modules_str}{Colors.ENDC}")

    # ── DB: Save findings and finalize ──
    prev_scan = None
    if db and scan_id and getattr(args, 'diff', False):
        # Snapshot the previous scan BEFORE this scan is marked complete.
        target_domain = urlparse(urls_to_scan[0]).netloc if urls_to_scan else (args.git or args.path or 'local')
        prev_scan = db.get_previous_scan_data(target_domain)
    if db and scan_id:
        for finding in current_findings:
            db.save_finding(scan_id, finding)
        for url in scanner.scanned_urls:
            content = scanner.content_cache.get(url, '')
            content_hash = hashlib.sha256(
                content.encode('utf-8', 'ignore')).hexdigest()[:16]
            db.save_url_state(scan_id, url, scanner.url_status.get(url, 0), content_hash)
        db.finish_scan(scan_id, len(scanner.scanned_urls) + scanner.local_files_scanned,
                       len(current_findings), elapsed)
        db_stats = db.get_stats()
        print(f"\n{Colors.DIM}[DB] Scan #{scan_id} saved | "
              f"Total: {db_stats['total_findings']} findings across "
              f"{db_stats['total_scans']} scans{Colors.ENDC}")

        # v5.1.1: Differential scan — compare with previous scan
        if getattr(args, 'diff', False):
            prev = prev_scan
            if prev and prev.get('scan_id') and prev['scan_id'] != scan_id:
                print(f"\n{Colors.BOLD}📊 DIFFERENTIAL SCAN (vs scan #{prev['scan_id']}):{Colors.ENDC}")
                current_hashes = set()
                for f in current_findings:
                    h = hashlib.sha256(
                        f"{f.get('type', '')}:{f.get('value', '')}".encode()).hexdigest()[:16]
                    current_hashes.add(h)
                new_finding_hashes = current_hashes - prev['finding_hashes']
                resolved_hashes = prev['finding_hashes'] - current_hashes
                if new_finding_hashes:
                    print(f"  {Colors.WARNING}New findings: {len(new_finding_hashes)}{Colors.ENDC}")
                    for f in current_findings:
                        h = hashlib.sha256(
                            f"{f.get('type', '')}:{f.get('value', '')}".encode()).hexdigest()[:16]
                        if h in new_finding_hashes:
                            print(f"    {Colors.WARNING}+ [{f.get('severity', '?')}] "
                                  f"{f['type']} in {f.get('source', '?')[:50]}{Colors.ENDC}")
                if resolved_hashes:
                    print(f"  {Colors.OKGREEN}Resolved: {len(resolved_hashes)} finding(s) no longer detected{Colors.ENDC}")

                # New endpoints
                current_urls = set(scanner.scanned_urls)
                prev_url_set = set(prev.get('url_hashes', {}).keys())
                new_urls = current_urls - prev_url_set
                if new_urls:
                    print(f"  {Colors.OKCYAN}New endpoints: {len(new_urls)}{Colors.ENDC}")
                    for u in sorted(new_urls)[:5]:
                        print(f"    + {u[:70]}")

                print(f"  {Colors.DIM}URLs scanned: {len(scanner.scanned_urls)} "
                      f"(prev: {len(prev.get('urls', []))}){Colors.ENDC}")
                if not new_finding_hashes and not resolved_hashes:
                    print(f"  {Colors.DIM}No finding changes detected{Colors.ENDC}")
            elif db_stats['total_scans'] <= 1:
                print(f"\n{Colors.DIM}[DIFF] First scan — no previous data to compare{Colors.ENDC}")

        db.close()

    if args.output:
        scanner.export_json(args.output)
    if args.html:
        scanner.export_html(args.html)
    if args.sarif:
        export_sarif(scanner.collect_findings(), scanner.stats, args.sarif)

    # v3.0: Webhook notification
    if scanner.notifier:
        target = urls_to_scan[0] if urls_to_scan else 'unknown'
        scanner.notifier.send_alert(scanner.found_secrets, scanner.stats, target)

    # v5.2: CI exit gate — only confirmed/potential findings count; leads never fail.
    if getattr(args, 'fail_on', 'none') != 'none':
        gate_findings = (scanner.exit_findings
                         if scanner.exit_findings is not None
                         else scanner.collect_findings())
        blocking_count = sum(
            1 for f in gate_findings if f['status'] in scanner.BLOCKING_STATUSES)
        code = scanner.compute_exit_code(args.fail_on, gate_findings)
        if code:
            print(f"{Colors.FAIL}[!] Failing build: {blocking_count} "
                  f"confirmed/potential finding(s) meet --fail-on "
                  f"{args.fail_on}{Colors.ENDC}")
        else:
            print(f"{Colors.OKGREEN}[+] Exit 0: no confirmed/potential findings "
                  f"at or above {args.fail_on}{Colors.ENDC}")
        sys.exit(code)
