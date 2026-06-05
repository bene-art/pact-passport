### What this changes

A short, specific description. One layer per PR — if this bundles multiple concerns, please split before requesting review.

### Why

The motivation. If there's a linked issue, reference it with `closes #N`.

### Wire-affecting?

- [ ] No (internal-only, docs, tests, CI)
- [ ] Yes — `spec/PACT_v1.md` is updated in this PR
- [ ] Yes — test vectors regenerated (`tests/vectors/generate_vectors.py`)

If wire-affecting, name the affected message field(s) or token field(s).

### Tests

- [ ] `pytest -q` passes locally
- [ ] `PACT_CHAOS=1 pytest -q` passes locally (required if touching concurrent code paths)
- [ ] A new test exercises the changed behavior

What's the new test, and why does it catch the regression?

### Backwards compatibility

- [ ] No public API change
- [ ] Public API added (additive only)
- [ ] Public API deprecated (warning emitted, removal version named in code + CHANGELOG)
- [ ] Public API removed (only allowed in a minor or major version bump per `CONTRIBUTING.md`)

### Checklist

- [ ] `CHANGELOG.md` updated under the appropriate version section
- [ ] If wire-affecting: spec section updated, test vectors regenerated
- [ ] If deprecating: `DeprecationWarning` emitted, removal version named
- [ ] No new dependencies added (or an issue exists discussing them)
- [ ] Commit message follows `CONTRIBUTING.md` format (`<type>: <summary>`)
