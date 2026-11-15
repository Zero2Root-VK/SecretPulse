# Contributing

SecretPulse is a security tool and is intended for authorized testing only. Keep
fixtures synthetic, never commit real credentials, and do not add functionality that
enables unauthorized access or destructive behavior.

## Development setup

Requirements: Python 3.8+ and `git`. CI covers Python 3.8 through 3.13.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip -r requirements.txt
```

## Source layout

The source of truth is `secretpulse/`. `SecretPulse.py` is a generated single-file
distribution and must not be edited directly.

```bash
python3 build_secretpulse.py          # regenerate SecretPulse.py
python3 build_secretpulse.py --check  # fail if the bundle is stale
```

Both entrypoints must behave identically:

```bash
python3 SecretPulse.py --help
python3 -m secretpulse --help
```

## Tests and quality gates

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile SecretPulse.py
python3 benchmarks/run_benchmark.py --verbose
```

CI additionally enforces 1.0 precision, recall, line accuracy, category accuracy,
severity accuracy, and zero clean-noise cases. Do not weaken a threshold to make a
change pass; fix the detector or add a justified fixture instead.

## Detection changes

- Add a focused regression test for every new detection rule, including a near-miss
  or placeholder that must not match.
- Benchmark fixtures must use synthetic values. Labels declare accepted detection
  types, line number, category, and optional severity.
- Preserve the public-identifier model: public-by-design browser identifiers are
  LOW `lead` findings and never fail a CI gate.
- New verifier routes must be read-only (`GET`/`HEAD`) and must redact credentials
  and provider response details.

## Pull requests

Keep changes scoped, rebuild the bundle, and include:

1. What changed and why.
2. Tests and benchmark results.
3. Security impact, including any new network behavior or output path.

Use conventional commit subjects such as `feat:`, `fix:`, `docs:`, `test:`, and
`refactor:`. Avoid committing generated reports, local databases, environment files,
or credentials. `SECURITY.md` describes how to report vulnerabilities privately.
