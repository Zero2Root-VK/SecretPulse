# Changelog

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
