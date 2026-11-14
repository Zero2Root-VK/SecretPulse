# <img src="secretpulse-icon.svg" width="32" height="32" alt=""> SecretPulse — The Scanner That Proves It

![Version](https://img.shields.io/badge/version-5.4.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-Standard-cyan)
![Modules](https://img.shields.io/badge/modules-13-purple)

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
| Detection breadth | 160 patterns / 108 types | 800+ detectors | Large built-in ruleset | Large detector set |
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
- `pip install requests` (only required dependency)
- `--gitleaks-config` requires Python 3.11+ (`tomllib`) or `pip install tomli`

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

- **160 built-in secret-pattern regexes across 108 types** — API keys, tokens, credentials, cloud secrets
- **2026 provider coverage** — OpenRouter, Groq, xAI, Perplexity, Mistral, DeepSeek, Together, Supabase secret keys, Postman, Pulumi, Sentry, Datadog, Telegram, AWS secret keys, and more
- **Modular scanning** — secrets, CORS, JWT, open redirect, read-only cloud permissions, dependency confusion, SSRF indicators, IDOR candidates, subdomain takeover
- **Unified findings** — every result carries `confirmed`, `potential`, or `lead`; only confirmed/potential findings can fail a CI build
- **6-factor confidence scoring** — format, context, ownership, file path, entropy, live validation → single 0-100 score
- **Smart mode** — classifies each subdomain (API, admin, auth, staging) and runs only relevant modules
- **Subdomain recon** — CT logs + DNS resolution + HTTP probe + risk scoring
- **WAF adaptive intelligence** — auto-detects Cloudflare/Akamai pressure, enters stealth mode, escalates to deep stealth
- **Differential scanning** — `--diff` shows new findings, resolved issues, new endpoints vs previous scan
- **SQLite persistence** — track findings across scans with `--db`
- **JSON + HTML + SARIF output** — dark-themed HTML reports with finding deduplication

---

## Scan Modes

```bash
# Smart scan (recommended — selects modules per target)
python3 SecretPulse.py https://target.com --smart

# Smart scan with active verification and a CI severity gate
python3 SecretPulse.py https://target.com --smart --verify --fail-on high

# Local files or git history (no network target required)
python3 SecretPulse.py --path ./src --fail-on high
python3 SecretPulse.py --git . --git-max-commits 200

# Import Gitleaks TOML rules, including allowlists
python3 SecretPulse.py --path ./src --gitleaks-config .gitleaks.toml
```

Advanced modules — CORS, JWT, open redirect, cloud permissions, dependency confusion, SSRF/IDOR indicators, and subdomain takeover — are selected automatically by `--smart`. They are not exposed as separate flags.

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
| `--git REPO` | Scan a local git repository's history |
| `--git-max-commits N` | Max commits to inspect with `--git` (0 = all) |
| `--gitleaks-config FILE` | Import Gitleaks TOML rules, including allowlists |
| `--db` | SQLite persistence |
| `--diff` | Show delta vs previous scan |
| `--baseline FILE` | Suppress baseline findings from the exit gate |

---

## Author

**Vinod Kumar Bontha**

Built as a single Python file. 11,600+ lines. No frameworks. No backend service. No telemetry.

For authorized security testing only.

---

## Star History

If SecretPulse helps you find something real, consider giving it a ⭐
