## Summary

Explain the problem and the change in one or two paragraphs.

## Verification

- [ ] `python3 build_secretpulse.py --check`
- [ ] `python3 -m py_compile SecretPulse.py`
- [ ] `python3 -m unittest discover -s tests -v`
- [ ] `python3 benchmarks/run_benchmark.py`

## Security review

- [ ] Fixtures use synthetic credentials only.
- [ ] New network behavior is read-only, scoped, and documented.
- [ ] Output paths mask secret values where required.
- [ ] No generated reports, databases, environment files, or real keys are included.
