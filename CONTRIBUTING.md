# Contributing to PACT Passport

PACT Passport is a trust protocol. The bar for changes is correctness first, surface area second.

If you're considering a contribution, please read this file end-to-end first.

## Before you open a PR

**For bug fixes:** open an issue describing the bug, ideally with a reproduction. Then the PR can reference it.

**For features:** open an issue *first* and wait for a decision. The v0.x scope is deliberately small. Most "feature" requests belong one layer up (in an orchestration layer like MCP, A2A, or in application code) rather than in the substrate. See README §Non-goals.

**For security issues:** **do not open a public issue or PR.** Use the private disclosure path in [SECURITY.md](SECURITY.md).

## Setup

```bash
git clone https://github.com/bene-art/pact-passport.git
cd pact-passport
python3 -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev,cbor,fast]"
```

Python 3.11+ required.

## Running tests

```bash
pytest -q
```

The full suite is fast (~25s). It must pass on macOS and Linux. Windows skips four POSIX-only checks.

For race-condition coverage:

```bash
PACT_CHAOS=1 pytest -q
```

This injects random delays at race-prone code paths. Slower (~60s) but surfaces concurrency bugs that pass without it.

## Code expectations

- **Type hints** on all public functions and class attributes.
- **No new dependencies** without an issue discussion first. PACT's whole credibility is its small surface; adding dependencies expands attack surface and supply chain risk.
- **Tests required.** Any behavior change needs a test that exercises it. Tests live in `tests/` (unit) or `tests/integration/` (multi-agent, durability, concurrency).
- **Single-layer changes.** Don't bundle a refactor with a feature with a bug fix. One layer per PR.
- **Spec compliance.** If you touch wire-affecting code (`message.py`, `capability.py`, `receipt.py`, `transport/`), the change must be consistent with `spec/PACT_v1.md`. If the spec needs updating, do it in the same PR.
- **No public-API breakage** in a patch release. Deprecate first, remove in the next minor.

## What counts as wire-affecting

- Any change to the JSON schema of REQ, RES, RES_CHUNK, capability tokens, or receipts.
- Any change to canonical-JSON serialization (`message._canonical_json`).
- Any change to the signature algorithm or what bytes are signed.
- Any change to mandatory vs optional fields.
- Any change to defaults that affects how messages are interpreted.

Non-wire-affecting changes (local storage formats, internal API shape, docs, tests, CI) do not need spec edits.

## Commit messages

Format: `<type>: <summary>`

- `vX.Y.Z: <release summary>` for releases
- `fix: <what was broken>` for bug fixes
- `feat: <what's new>` for features
- `docs: <what changed>` for documentation
- `refactor: <what was reshaped>` for non-behavior changes
- `test: <what's tested>` for test-only commits
- `ci: <what changed in CI>` for CI/workflow changes

Body should explain *why*, not *what* (the diff shows what). Reference issue numbers with `closes #N` where applicable.

## PR review checklist

Before requesting review:

- [ ] `pytest -q` passes on your machine
- [ ] `PACT_CHAOS=1 pytest -q` passes if your change touches concurrent code paths
- [ ] Type hints present on new public functions
- [ ] No new dependencies (or an issue was opened first)
- [ ] If wire-affecting: `spec/PACT_v1.md` updated, test vectors regenerated (`tests/vectors/generate_vectors.py`)
- [ ] If user-facing behavior changed: `CHANGELOG.md` updated under "Unreleased"
- [ ] If a public API was deprecated: warning emitted, removal version named

## Reviewer expectations

A maintainer will respond within ~7 days. The first response may be questions, not approval. PACT is small and reviewed conservatively; expect more back-and-forth than on a typical library PR.

## License

By contributing, you agree your contributions are licensed under the [MIT License](LICENSE) of this project.
