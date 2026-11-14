# Changelog

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
- 90+ secret patterns, 50+ API verifiers
- 13 scanning modules
- 6-factor confidence scoring (0-100)
- SmartRouter asset classification
- Subdomain recon (CT logs + DNS)
- SQLite persistence
- HTML/PDF/JSON/SARIF output
- CI/CD generators (GitHub Actions, GitLab CI, pre-commit)
