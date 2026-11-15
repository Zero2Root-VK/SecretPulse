# Changelog

## v5.6.1 (2026-11-15)
### Security Fixes
- Removed shell-style interpolation of report paths in PDF conversion; engine scripts now receive paths as process arguments through `sys.executable`, so crafted `--html`/`--pdf` values cannot inject code
- Removed the unused offline licensing module and its hardcoded salt; SecretPulse is a single Standard License build with no dormant key validation or feature gating
- Cleaned repository ignore rules to cover `.env`, key material, databases, and scan artifacts without hiding benchmark fixtures

### Maintenance
- Removed the no-op CLI upgrade wrapper
- Aligned CI with the documented Python support range by testing 3.8 and 3.9 on Ubuntu 22.04 alongside 3.10, 3.12, and 3.13
- Removed stale line-count metadata from version constants and documentation

## v5.6.0 (2026-11-15)
### Signal Quality
- Added explicit public-identifier classification for 14 browser and ingestion identifiers, including Stripe publishable keys, Mapbox public tokens, Google/Firebase client keys, Sentry DSNs, Datadog RUM tokens, analytics project IDs, and auth/widget client IDs
- Public identifiers are emitted as LOW `lead` inventory with a reason and per-type verification policy; they cannot escalate to CRITICAL, be reported as verified credentials, or fail a CI gate
- Split mixed provider rules so secret and public forms cannot collide: Stripe secret vs publishable, Mapbox secret vs public, Intercom access token vs app ID, HubSpot API key vs portal ID
- Credential totals, public-identifier totals, and raw candidate counts are reported separately in the console summary and JSON
- Exact-format high-impact credentials now keep their declared severity (for example, `sk_live_` stays CRITICAL at 82 confidence); confidence still controls risk ordering, and the pin reason is recorded in evidence

### Evidence Depth
- Every secret and public-identifier finding now carries an exact line number and a bounded context snippet
- Unified findings include a copy-ready reproduction command: `sed` for local files, `curl | sed` for URL findings with a line, and `grep` as a fallback
- HTML reports show source line references, escaped snippets, and public-by-design notes
- SARIF exports line regions, masked snippets, CWE/OWASP metadata, remediation, and stable fingerprints
- Exact secret values are masked in SARIF snippets and reproduction text

### Verification Safety
- Active verification is GET-only and now supports provider allowlists with `--verify-providers`
- Slack webhook verification is disabled by default and requires `--allow-webhook-checks` because delivery has side effects
- Public identifiers skip or scope verification according to provider policy
- Verification details are redacted before they reach output or JSON

### Request Safety and Authenticated Scanning
- Added `--config`, `--header`, `--cookie`, `--proxy`, `--timeout`, `--max-response-kb`, `--verify-providers`, and `--allow-webhook-checks`
- JSON and TOML config support `[http]` and `[verify]` sections with CLI precedence and validation
- Redirects are followed manually up to 5 hops with scope checks on every hop; out-of-scope redirects are blocked and counted
- Response bodies are streamed and capped before parsing, with truncation tracked in scan stats
- Worker threads use isolated `requests.Session` objects sharing the configured headers, cookies, proxy, retry strategy, and TLS settings
- Authenticated scans apply headers and cookies to all target HTTP paths, including sensitive-file probes

### Detection Quality Benchmark
- Added a labeled corpus and benchmark runner that exercises the production pipeline: regex detection, decoded-secret prepass, false-positive filtering, confidence scoring, and source-map extraction
- Reports micro-averaged precision, recall, F1, line accuracy, category accuracy, severity accuracy, per-type recall, and clean-noise cases
- Supports JSON and Markdown artifacts, configurable quality thresholds, and baseline regression comparison for CI
- Manifest validation rejects path traversal, duplicate case IDs, invalid categories/severities, and unknown detection types before any fixture is scanned
- Built-in corpus covers 12 realistic cases and 27 labeled findings across JavaScript, minified bundles, `.env`, Python settings, PEM keys, base64 payloads, Jupyter notebooks, webpack source maps, lockfiles, vendor code, and documentation placeholders
- Refactored source-map extraction into a reusable `scan_sourcemap_data()` path used by both live harvesting and the benchmark

### Staged, Notebook, and Signing-Secret Coverage
- Added `--staged [REPO]`, which reads staged blobs from the git index rather than the working tree; deleted files, binaries, and oversized blobs are skipped
- Added cell-aware Jupyter notebook scanning for cell sources, stream output, tracebacks, and text/HTML/Markdown/JSON display data; malformed notebooks fall back to raw text scanning
- Added signing material detection for `JWT_SECRET`, `SESSION_SECRET`, `CSRF_SECRET`, `SIGNING_KEY`, `ENCRYPTION_KEY`, `HMAC_SECRET`, `APP_SECRET`, and related assignments, with placeholder and entropy filtering
- Benchmark corpus expanded to 12 cases and 27 findings with a notebook cell/output case and a low-entropy signing-secret hard negative
- Added a pre-commit hook example that scans exactly what is about to be committed
- Added GitHub Actions CI for bundle freshness, compilation, the full test suite, and strict benchmark thresholds

### Security Fixes
- Console finding details now mask secret values instead of printing the full credential; JSON/SARIF evidence masking behavior is unchanged

### Bug Fixes Found by the Benchmark
- Fixed Mapbox public and secret token patterns to accept base64url characters (`-` and `_`), which previously missed valid tokens
- Exact-format and locally validated high-impact credentials now keep their declared severity instead of being downgraded by confidence; this covers PEM private keys, database connection strings, Twilio credentials, and signature-confirmed base64 secrets
- PEM private-key findings now validate the header regardless of whether the full key body was captured

### Modular Source Layout
- Moved the monolith into focused modules under `secretpulse/` while preserving the standalone `python3 SecretPulse.py` distribution
- Added `build_secretpulse.py` to bundle the modular source deterministically into `SecretPulse.py`, with `--check` for CI staleness detection
- Added `python3 -m secretpulse` as an equivalent package entrypoint
- Added layout tests that verify the bundle is current, standalone, and exports the core scanner components

### Output Schema
- `findings` and `unified_findings` are now identical in JSON; raw detection records are labeled `secret_candidates`
- JSON includes a non-secret `scan_config` summary and separate `secrets_total`, `public_identifiers_total`, and `secret_candidates_total`
- Test suite expanded from 14 to 50 tests, adding public-identifier behavior, exact-format severity pinning, verifier safety, real HTTP response caps and redirects, concurrent session isolation, config validation, SARIF redaction, benchmark scoring, corpus validation, source-map extraction, benchmark artifact redaction, regression detection, modular bundle consistency, staged-index scanning, notebook cell/output scanning, CLI gate redaction, and signing-secret detection

## v5.5.0 (2026-11-14)
### New Exposure Coverage
- Added validated sensitive-file discovery for Git, Mercurial, and SVN metadata; `.DS_Store`; SSH private keys; SQL and ZIP backups; PHP config backups; IIS/app settings; Spring Actuator; Apache server-status; phpinfo; Terraform state; and Docker Compose
- Sensitive-path probing reads only a 16 KB prefix and validates content signatures, so SPA soft-404 pages returning 200 HTML are not reported
- Added `.env`, GraphQL introspection, OpenAPI, gRPC indicators, and sensitive-file findings to the unified finding model, JSON, HTML, and SARIF
- GraphQL findings merge the lightweight and full-schema probes into one result per endpoint and raise severity when mutations are exposed

### Takeover Analysis
- Replaced the previous heuristic with DNS-over-HTTPS CNAME resolution and claimable-service matching
- Takeover findings now require a CNAME to a known service plus a matching fingerprint or an unreachable destination
- Removed NXDOMAIN and TLS-error false positives
- `--smart` now runs takeover analysis on scanned subdomains automatically

### Reporting
- Unified findings now include CWE, OWASP category, remediation, and a copy-ready reproduction command
- HTML exposure table renders evidence, CWE/OWASP, remediation, and repro commands
- SARIF rules include CWE `helpUri`, remediation, repro, and per-finding partial fingerprints

### Bug Fixes
- Unclassified web apps now run GraphQL, OpenAPI, and open-redirect discovery by default instead of only `.env` and CORS
- Fixed WAF stealth mode permanently disabling `.env`, GraphQL, Swagger, sensitive-file, and takeover probes; probes are restored after the cooldown
- Removed the inert `verify` module from smart always-on routing and replaced it with real sensitive-file and takeover modules
- Added exposure validation coverage in `tests/test_v55_exposure.py`; full suite now covers 14 detection, verifier, exposure, takeover, WAF, and SARIF tests

## v5.4.0 (2026-11-14)
### New Detection Coverage
- Added 30 provider types and 36 patterns for 2026 infrastructure:
  - AI/inference: OpenRouter, Groq, xAI, Perplexity, Mistral, DeepSeek, Together
  - Developer/data: Supabase secret keys, Resend, Postman, Pulumi, Sentry user/org tokens, Datadog, Databricks, Doppler, Fly.io
  - Collaboration: Slack app tokens, Telegram bot tokens, Discord and Microsoft Teams webhooks, Atlassian, Mailchimp
  - Infrastructure: 1Password service accounts, Age secret keys, AWS Bedrock keys, AWS secret access keys, Google OAuth client secrets, Azure AD client secrets, Azure Storage account keys
- Expanded OpenAI detection to `sk-proj-`, `sk-svcacct-`, and `sk-admin-` keys
- Expanded GitLab detection to job, deploy, and runner authentication tokens
- Fixed Mailgun rule matching inside Age secret keys

### Verification
- Added 14 read-only verifier routes: OpenRouter, Groq, xAI, Mistral, DeepSeek, Together, Resend, Postman, Pulumi, Sentry user, Datadog, Telegram, Discord webhooks, and Mailchimp
- Verification uses GET requests only; no provider resources are created, modified, or deleted
- Verifier routes now total 66, with provider details included in `verification_detail`

### Accuracy
- Added exact format and length checks for all new prefixed token families
- Added provider-aware confidence keywords and high-confidence classifications
- Regression suite in `tests/test_capability_pack.py` confirms all 30 new types detect without cross-provider false positives
- Verifier tests confirm all 14 new routes use GET-only requests and provider-specific auth headers

## v5.3.0 (2026-11-14)
### Breaking Changes
- CLI reduced to 16 flags: URLs, `-v`, `-o`, `--html`, `--sarif`, `--fail-on`, `--scope`, `--verify`, `--smart`, `--path`, `--git`, `--git-max-commits`, `--gitleaks-config`, `--db`, `--diff`, `--baseline`
- Removed standalone flags for crawl depth, workers, retries, rate limiting, UA rotation, `.env`/GraphQL/Swagger probes, custom rules, cloud-native scanning, webhooks, Wayback, takeover, SSRF/IDOR indicators, attack chains, target lists, PDF reports, CVE lookup, recon-only, database utilities, CORS, redirect, dependency confusion, JWT, cloud permissions, full mode, and CI/CD generators
- Advanced web modules remain available through `--smart`, which selects them per target
- Smart mode now lazily initializes cloud-native scanning instead of relying on the removed `--scan-cloud` flag

### Documentation
- Split competitor comparison into secret-scanning parity and web-exposure scope
- Corrected the misleading "GitGuardian Binary" claim; GitGuardian exposes five validity states plus severity/risk
- Marked web-only capabilities as `N/A` for repository secret scanners instead of presenting them as weaknesses
- Added TruffleHog verification and Gitleaks baseline capabilities to the comparison

## v5.2.0 (2026-11-14)
### New Features
- **Unified findings model** — secrets, CORS, redirects, JWT, dependency confusion, cloud permissions, takeover indicators, headers, and recon leads share one status model: `confirmed`, `potential`, or `lead`
- **CI severity gate** — `--fail-on {critical,high,medium,low,any}` fails only on confirmed/potential findings
- **Local and history scanning** — `--path` for files/directories, `--git` for native git history, `--gitleaks-config` for TOML rule import including rule/global allowlists
- **Baseline-aware gating** — `--baseline` now suppresses pre-existing findings from the exit gate
- **Complete persistence** — all unified findings and URL content hashes are stored per scan, so `--diff` reports real changes

### Security and Accuracy Fixes
- Removed S3 write/delete probe; cloud permission checks are read-only
- Corrected CORS wildcard+credentials and client-side open-redirect status claims
- Cloud-native regex indicators and subdomain takeover signatures are now leads, not confirmed findings
- Fixed false-positive path matching that dropped findings under directories containing `test/`
- Fixed smart-mode JWT/dependency/cloud modules being enabled by the planner but never run
- Fixed generated GitHub Actions/GitLab CI filenames, YAML, and missing `--fail-on`
- SARIF now maps leads to `note` and potential findings to `warning`
- PostHog verification now uses a read-only project listing instead of a POST
- Docs now match the implementation: 50 verifiers, 6 CORS checks + 25 redirect params, precise pattern counts, and no unmeasured false-positive-rate claims

## v5.1.2 (2026-02-16)
### New Features
- **WAF oscillation fix** — 90-second cooldown prevents stealth↔resume bouncing
- **Deep stealth escalation** — drops to 1 worker / 0.5 req/s when WAF persists
- **Smart retry backoff** — stealth mode reduces retries, skips heavily-blocked domains
- **WAF intelligence summary** — block rate, scan efficiency, recommendations in output
- **PDF 4-engine fallback** — weasyprint → wkhtmltopdf → chromium → xhtml2pdf
- **Premium banner** — 256-color gradient, Unicode frame, hex signature

### Bug Fixes
- Fixed Top Targets showing empty modules (smart_modules key mismatch)
- Cautious WAF recovery for heavy targets (50+ blocks → 33% worker recovery)

## v5.1.1 (2026-02-16)
### New Features
- WAF adaptive intelligence (auto-stealth under 403 pressure)
- Exploit path suggestions with probability scoring
- Differential scanning (`--diff` mode)
- Progress ETA with live retry/WAF counters
- Early exit intelligence for low-value sites
- Smart no-findings report with attack surface guidance
- HTML finding deduplication by value hash
- Auto-scope warning for external domains
- Supply chain inventory table in HTML reports

### Bug Fixes
- Source map deduplication (88→4 findings)
- SRI missing deduplication (90→5 findings)
- Stack trace prevention in PDF generation
- Database None handling in getattr() calls

## v5.0.0 (2026-01-28)
- Initial release
- 90+ secret patterns, 50 API verifiers
- 13 scanning modules
- 6-factor confidence scoring (0-100)
- SmartRouter asset classification
- Subdomain recon (CT logs + DNS)
- SQLite persistence
- HTML/PDF/JSON/SARIF output
- CI/CD generators (GitHub Actions, GitLab CI, pre-commit)
