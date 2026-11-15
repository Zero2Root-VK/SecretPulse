# <img src="secretpulse-icon.svg" width="32" height="32" alt=""> SecretPulse — The Scanner That Proves It

![Version](https://img.shields.io/badge/version-5.6.1-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-Standard-cyan)
![Findings](https://img.shields.io/badge/findings-unified-purple)

**Find secrets. Score them 0-100. Free forever.**

SecretPulse is a high-signal secret scanner that goes beyond pattern matching — it classifies targets, selects relevant modules, adapts to WAF pressure, and scores every finding with 6-factor confidence scoring. Built for bug bounty hunters who want signal, not noise.

```
$ python3 SecretPulse.py https://target.com --smart

[RECON] CT: 47 subs | DNS: 23 alive | High risk: 6
[SMART] api.target.com → cors, jwt, swagger
[SMART] admin.target.com → env, cors, open-redirect

[CRITICAL] Stripe Secret Key
  Confidence: 94/100  |  Risk: 87/100
```

---

## How SecretPulse compares

SecretPulse combines secret scanning with per-target web exposure checks. It is not a drop-in replacement for repository-only secret scanners, so the comparison is split by scope.

### Secret scanning

| Capability | SecretPulse | TruffleHog | Gitleaks | GitGuardian |
|------------|-------------|------------|----------|-------------|
| Detection breadth | 162 patterns / 112 types | 800+ detectors | Large built-in ruleset | Large detector set |
| Live credential verification | 66 routes | ✓ Verified-only mode | ✗ | ✓ 5-state validity |
| Finding prioritization | 6-factor confidence heuristic (0-100) | Verification + detector metadata | Entropy + allowlists | Validity + severity/risk |
| Local files + git history | ✓ Native | ✓ | ✓ | ✓ Via integrations/`ggshield` |
| Baseline / history comparison | ✓ `--diff`, `--baseline` | ✓ Git ranges | ✓ `--baseline-path` | ✓ Incident lifecycle |
| CI failure gate | ✓ `--fail-on` | ✓ `--fail`, `--fail-verified` | ✓ `--exit-code` | ✓ CI integrations |

### Web exposure extras

| Capability | SecretPulse | TruffleHog | Gitleaks | GitGuardian |
|------------|-------------|------------|----------|-------------|
| Per-target smart routing | ✓ | N/A | N/A | N/A |
| WAF adaptation | ✓ Auto-stealth | N/A | N/A | N/A |
| CORS testing | ✓ 6 checks | N/A | N/A | N/A |
| Open redirect testing | ✓ 25 parameters | N/A | N/A | N/A |
| Other web probes | JWT, `.env`, GraphQL, Swagger, cloud permissions, dependency confusion, SSRF/IDOR indicators, takeover | N/A | N/A | N/A |

`N/A` means the capability is outside that tool's scope, not that it is missing. TruffleHog and Gitleaks are repository scanners; GitGuardian is a secret-detection platform. Compare the web-exposure row against web scanners such as Nuclei or Burp Suite, not against secret scanners.

Comparison sources, accessed 2026-11-14: [TruffleHog](https://github.com/trufflesecurity/trufflehog), [TruffleHog CI](https://trufflesecurity.com/docs/scanning-in-ci), [Gitleaks](https://github.com/gitleaks/gitleaks), [GitGuardian validity checks](https://docs.gitguardian.com/secrets-detection/customize-detection/validity-checks).

---

## Quick Start

```bash
# No installation. No key. Just run it.
python3 SecretPulse.py https://target.com --smart
```

### Requirements
- Python 3.8+
- `pip install -r requirements.txt` (only required dependency is `requests`)
- `--gitleaks-config` requires Python 3.11+ (`tomllib`) or `pip install tomli`

### Project Layout

The release artifact is still one standalone file, but the source is modular:

| Path | Purpose |
|------|---------|
| `secretpulse/` | Source of truth — scanner, analysis, verification, recon, reporting, and CLI modules |
| `build_secretpulse.py` | Builds the standalone `SecretPulse.py` bundle |
| `SecretPulse.py` | Generated single-file distribution — do not edit directly |
| `benchmarks/` | Detection-quality corpus and benchmark runner |
| `tests/` | Regression and integration tests |
| `.github/workflows/ci.yml` | Bundle, test, and detection-quality CI gates |

After changing source modules, rebuild and verify the bundle:

```bash
python3 build_secretpulse.py
python3 build_secretpulse.py --check
```

The package can also be run directly with `python3 -m secretpulse`. See
[CONTRIBUTING.md](CONTRIBUTING.md) for development setup, detection-change standards,
and the pull-request checklist.

CI enforces the same contract on every push and pull request: the generated bundle
must be current, the test suite must pass, and benchmark precision, recall, line,
category, and severity accuracy must remain at 1.0 with zero clean-noise cases.

### Recommended Command

```bash
python3 SecretPulse.py https://target.com \
  --smart \
  --db --diff \
  -o results.json \
  --html report.html \
  --fail-on high
```

---

## Features

- **162 built-in secret-pattern regexes across 112 types** — API keys, tokens, credentials, cloud secrets
- **Public-identifier separation** — publishable Stripe/Mapbox keys, browser API keys, Sentry DSNs, and analytics IDs are reported as LOW `lead` inventory, never as CRITICAL credentials or CI failures
- **2026 provider coverage** — OpenRouter, Groq, xAI, Perplexity, Mistral, DeepSeek, Together, Supabase secret keys, Postman, Pulumi, Sentry, Datadog, Telegram, AWS secret keys, and more
- **Staged-index scanning** — `--staged` reads the git index, so pre-commit hooks and CI catch exactly what is about to be committed, including Jupyter notebooks
- **Notebook coverage** — `.ipynb` cell sources, stream output, tracebacks, and text/HTML/JSON display data are scanned with cell-aware source and line evidence
- **Signing-secret detection** — `JWT_SECRET`, `SESSION_SECRET`, `SIGNING_KEY`, `ENCRYPTION_KEY`, and related signing material are treated as high-severity credentials with entropy and placeholder filtering
- **Modular scanning** — secrets, CORS, JWT, open redirect, read-only cloud permissions, dependency confusion, SSRF indicators, IDOR candidates, subdomain takeover
- **Sensitive-file discovery** — validated probes for Git/Mercurial/SVN metadata, backups, private keys, Actuator, Terraform state, and Docker Compose
- **CNAME takeover analysis** — DNS-over-HTTPS CNAME resolution plus service fingerprinting, without NXDOMAIN false positives
- **Unified findings** — every result carries `confirmed`, `potential`, or `lead`; only confirmed/potential findings can fail a CI build
- **Evidence-grade output** — exact line, context snippet, CWE, OWASP mapping, remediation, and copy-ready repro commands in JSON, HTML, and SARIF
- **Reproducible detection benchmark** — labeled corpus, precision/recall/F1, line/category/severity accuracy, clean-noise tracking, thresholds, and baseline regression checks
- **Safe active verification** — GET-only provider routes, provider allowlists, public-identifier skip, opt-in side-effecting webhook checks, and masked verification details
- **Operator-controlled HTTP** — custom headers, cookie auth, proxy, timeout, and response-size caps applied consistently, including scope-checked redirects
- **6-factor confidence scoring** — format, context, ownership, file path, entropy, live validation → single 0-100 score
- **Smart mode** — classifies each subdomain (API, admin, auth, staging) and runs only relevant modules
- **Subdomain recon** — CT logs + DNS resolution + HTTP probe + risk scoring
- **WAF adaptive intelligence** — auto-detects Cloudflare/Akamai pressure, enters stealth mode, escalates to deep stealth, then restores paused probes after recovery
- **Differential scanning** — `--diff` shows new findings, resolved issues, new endpoints vs previous scan
- **SQLite persistence** — track findings across scans with `--db`
- **JSON + HTML + SARIF output** — dark-themed HTML reports with finding deduplication and exposure evidence

---

## What Counts as a Finding?

SecretPulse separates three things that are commonly mixed together:

| Class | Meaning | Exit gate |
|-------|---------|-----------|
| `confirmed` | Live verification succeeded for a real credential | Fails at the configured level |
| `potential` | Credential-shaped secret with supporting context | Fails at the configured level |
| `lead` | Public-by-design identifier or unverified exposure candidate | Never fails CI |

Stripe publishable keys, Mapbox public tokens, browser Google/Firebase identifiers, Sentry
DSNs, Datadog RUM tokens, analytics project IDs, and similar identifiers are still reported —
as LOW-severity inventory leads with a reason, never as CRITICAL secrets. This prevents the
classic scanner failure mode where every frontend bundle produces a fake emergency.

Every unified finding carries `line`, `snippet`, `value`, `cwe`, `owasp`, `remediation`,
`repro`, `fingerprint`, and `category`. JSON exposes the unified list as both `findings` and
`unified_findings`; raw detection-stage records remain available under `secret_candidates`.
SARIF includes the line region, masked snippet, CWE rule metadata, and a stable fingerprint.

---

## Detection Benchmark

The benchmark runs the real detection pipeline — pattern matching, false-positive
filtering, decoded-secret prepass, confidence scoring, and source-map extraction —
against a labeled corpus. It reports micro-averaged precision, recall, F1, line
accuracy, category accuracy, severity accuracy, per-type recall, and clean-noise cases.

```bash
# Human-readable report
python3 benchmarks/run_benchmark.py --verbose

# CI artifacts
python3 benchmarks/run_benchmark.py \
  --json benchmark.json \
  --markdown benchmark.md

# Fail the job if quality drops versus a saved run
python3 benchmarks/run_benchmark.py --baseline benchmark.json
```

The default corpus covers 12 cases and 27 labeled findings across JavaScript
bundles, minified code, `.env` files, Python settings, PEM private keys,
base64-encoded secrets, webpack source maps, Jupyter cell/output leaks, lockfiles,
vendor bundles, documentation placeholders, and public identifiers. Add cases by
editing `benchmarks/corpus/manifest.json`; each label declares accepted types, line,
category, and optional severity. The manifest is validated before scanning: path
traversal, duplicate IDs, invalid metadata, and unknown detection types are rejected.
Thresholds default to 0.95 precision, 0.95 recall, 0.90 line accuracy, 0.95 category
accuracy, 0.90 severity accuracy, and zero clean-noise cases.

---

## Scan Modes

```bash
# Smart scan (recommended — selects modules per target)
python3 SecretPulse.py https://target.com --smart

# Smart scan with active verification and a CI severity gate
python3 SecretPulse.py https://target.com --smart --verify --fail-on high

# Local files, staged index, or git history (no network target required)
python3 SecretPulse.py --path ./src --fail-on high
python3 SecretPulse.py --staged --fail-on high
python3 SecretPulse.py --staged ../another-repo --fail-on high
python3 SecretPulse.py --git . --git-max-commits 200

# Import Gitleaks TOML rules, including allowlists
python3 SecretPulse.py --path ./src --gitleaks-config .gitleaks.toml

# Authenticated scan with a reusable config and extra headers
python3 SecretPulse.py https://target.com --config scan.toml \
  --header "X-API-Key: $API_KEY" --cookie "session=$SESSION"

# Cap response size, tune timeout, and restrict verification providers
python3 SecretPulse.py https://target.com --verify \
  --verify-providers github,stripe --timeout 10 --max-response-kb 2048
```

`--config` accepts JSON or TOML with `[http]` and `[verify]` sections. CLI flags override
config values. Headers can be a map (`{"X-API-Key": "..."}`) or a list of
`"Name: Value"` strings. Invalid header lines are rejected before any request is sent.

```toml
[http]
timeout = 10
max_response_bytes = 2097152
headers = ["X-API-Key: ..."]
cookies = "session=..."
proxy = "http://127.0.0.1:8080"

[verify]
providers = ["github", "stripe"]
allow_webhooks = false
```

To block secrets before they land in history, add a local pre-commit hook:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: secretpulse-staged
        name: SecretPulse staged scan
        entry: python3 /path/to/SecretPulse.py --staged --fail-on high
        language: system
        pass_filenames: false
        stages: [pre-commit]
```

The hook scans the staged blob rather than the working tree, so it sees exactly
what is about to be committed. Notebook cells and text outputs are scanned with
cell-aware evidence, and console output masks secret values.

Advanced modules — CORS, JWT, open redirect, cloud permissions, dependency confusion, SSRF/IDOR indicators, sensitive-file discovery, and subdomain takeover — are selected automatically by `--smart`. They are not exposed as separate flags.

---

## Sample Output

```
══════════════════════════════════════════════════════════════
  SMART SCAN PLAN — 23 targets
══════════════════════════════════════════════════════════════

  API SERVICE (3):
    [ 78] api.target.com
         modules: cors_check, jwt_exploit, probe_swagger, probe_graphql
    [ 65] graphql.target.com
         modules: probe_graphql, cors_check

  ADMIN PANEL (1):
    [ 82] admin.target.com
         modules: probe_env, cors_check, open_redirect

  AUTH SERVICE (2):
    [ 85] auth.target.com
         modules: jwt_exploit, cors_check, probe_env
```

---

## CLI Reference

| Flag | Description |
|------|-------------|
| `URL...` | One or more targets to scan |
| `-v, --verbose` | Verbose output |
| `-o FILE` | JSON output |
| `--html FILE` | HTML report |
| `--sarif FILE` | SARIF 2.1.0 output for code scanning |
| `--fail-on LEVEL` | Exit 1 on confirmed/potential findings at or above LEVEL |
| `--scope FILE` | Scope file (one domain per line) |
| `--verify` | Active API verification (66 read-only routes) |
| `--smart` | Adaptive module selection per target (recommended) |
| `--path PATH` | Scan a local file or directory |
| `--staged [REPO]` | Scan staged git index changes (default: current repository) |
| `--git REPO` | Scan a local git repository's history |
| `--git-max-commits N` | Max commits to inspect with `--git` (0 = all) |
| `--gitleaks-config FILE` | Import Gitleaks TOML rules, including allowlists |
| `--db` | SQLite persistence |
| `--diff` | Show delta vs previous scan |
| `--baseline FILE` | Suppress baseline findings from the exit gate |
| `--config FILE` | JSON/TOML config for HTTP and verification settings |
| `--header "Name: Value"` | Extra request header (repeatable) |
| `--cookie STRING` | Cookie header for authenticated scans |
| `--proxy URL` | Route target requests through an HTTP(S) proxy |
| `--timeout SECONDS` | Per-request timeout (default 15) |
| `--max-response-kb N` | Response body cap in KiB (default 10240) |
| `--verify-providers LIST` | Restrict verification to providers, e.g. `github,stripe` |
| `--allow-webhook-checks` | Opt in to side-effecting Slack webhook verification |

---

## Author

**Vinod Kumar Bontha**

SecretPulse is a modular Python source tree shipped as one generated standalone file. No frameworks. No backend service. No telemetry.

For authorized security testing only.

---

## Star History

If SecretPulse helps you find something real, consider giving it a ⭐
