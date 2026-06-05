---
name: Bug report
about: Report a defect in the PACT Passport implementation or wire spec
title: ''
labels: bug
assignees: ''
---

**Do not use this template for security issues.** Use the private disclosure path in [SECURITY.md](../SECURITY.md).

### What happened

A clear, specific description of the bug. Include what you observed, not what you expected.

### What you expected

A clear, specific description of the correct behavior, with a reference to the spec section or code path if applicable.

### Reproduction

Minimum reproducible steps. If possible, a single script:

```python
# minimal repro
```

### Environment

- PACT Passport version: (e.g. 0.5.4 — `python -c "import pact; print(pact.__version__)"`)
- Python version: (e.g. 3.12.1)
- OS: (e.g. macOS 14.5 / Ubuntu 22.04 / Windows 11)
- Install source: PyPI / git main / git tag / local

### Wire trace (if applicable)

If the bug involves message-level behavior, paste the relevant REQ / RES / receipt JSON. Redact identifiers if needed.

### Spec reference (if applicable)

If you believe the implementation diverges from `spec/PACT_v1.md`, cite the spec section.

### Anything else

Logs, stack traces, related issues, prior attempts at a fix — anything that would save the maintainer a round-trip.
