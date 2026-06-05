# Changelog

All notable changes to PACT Passport are recorded in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.5] — 2026-06-05

Source-tree polish + one user-facing bug fix. No wire changes.

### Fixed
- Three `ImportError` messages previously told users to run `pip install pact-protocol[cbor|fast|lak]` when triggered — that package name is squatted by another publisher on PyPI, so the suggested command failed. Updated to `pact-passport[cbor|fast|lak]` to match the actual package name (renamed 2026-05-01). Affects `_canonical.py:39`, `_canonical.py:53`, `transport/async_server.py:202`.
- Five docstrings referencing the old `pact-protocol` install command also updated for consistency: `_canonical.py:33`, `_canonical.py:47`, `transport/async_server.py:4`, `transport/async_server.py:172`, `contrib/lak_channel.py:16`.
- `tests/vectors/generate_vectors.py` and the generated `tests/vectors/pact_v1_vectors.json` carried `"generated_by": "pact-protocol reference implementation"`. Updated to `pact-passport reference implementation` for public test-vector consistency.

### Added
- `CHANGELOG.md` (this file), `CONTRIBUTING.md`, `.github/ISSUE_TEMPLATE/bug_report.md`, `.github/ISSUE_TEMPLATE/feature_request.md`, `.github/ISSUE_TEMPLATE/config.yml`, `.github/PULL_REQUEST_TEMPLATE.md`.
- `tests/test_cli.py`: 14 CLI smoke tests covering `init`, `identity`, `caps`, `grant`, `revoke`, `receipts`, `peers`, `doctor`, and the auto-resolve-single-agent path. Uses `PACT_HOME` env redirect for store isolation.
- `tests/integration/test_agent_ask.py`: 3 end-to-end tests exercising `PACTAgent.ask()` (the high-level client API that was completely uncovered). Happy path with capability, unknown target, failed-receipt-on-error.

### Changed
- `spec/PACT_v1.md` revised to `v1.1.0-draft` (2026-06-05). The §12 addendum sections already documented every wire-affecting change from v0.2.0 through v0.5.3, but supersession over §1–§11 was conversational rather than normative. v1.1 rewrites the §12 preamble to make supersession explicit, adds inline pointers (`→ §12.x`) in the affected §1–§11 sections so top-down readers cannot miss the amendments, expands the §10 conformance checklist from 6 items to 10, and adds new §13 = line-item change summary + versioning policy. Draft status (`-draft`) retained until external validation per HotNets paper §6. **No wire changes.**
- Ruff lint pass on `src/pact/`: 56 findings closed (51 auto-fixed + 5 manual).
  - `UP035`: Moved `Callable` / `Iterator` from `typing` to `collections.abc` (5 files).
  - `UP037`: Removed redundant quoted type annotations.
  - `UP041`: Replaced `socket.timeout` alias with builtin `TimeoutError` (`transport/server.py`).
  - `UP017`: Used `datetime.UTC` alias.
  - `SIM108` / `SIM105`: Replaced if/else blocks with ternaries; replaced try/except/pass with `contextlib.suppress`.
  - `RUF022`: Sorted `__all__` in `pact/__init__.py`.
  - `F401`: Removed unused `CBOR_CONTENT_TYPE` import in `transport/client.py` (CBOR client send path is not yet wired through; tracked as issue #27 for v0.6).
  - `B904`: Three places now use `raise ImportError(...) from None` to suppress the noisy `ModuleNotFoundError` chain on missing optional deps; one place uses `raise ValueError(...) from e` to preserve original parse-failure detail in caveat validation.
  - `RUF002`: Replaced ambiguous Unicode `×` with `x` in `contrib/lak_channel.py:25` docstring.

### Deferred
- Client-side CBOR request encoding (asymmetry with server) — tracked as GitHub issue #27 for v0.6.
- The full v0.6 backlog is now visible as GitHub issues #22 (trusted_issuers), #23 (app-level caveat enforcement), #24 (cross-machine revocation propagation), #25 (post-quantum signatures), #26 (per-token cost accounting), #27 (client-side CBOR).

### Tests
- 164 → 181. Project-wide coverage 64% → 74%. `cli.py` 0% → 41%. `agent.py` 77% → 83%.

## [0.5.4] — 2026-06-05

Public-surface polish. No wire changes.

### Fixed
- README `agent_id` formula corrected to `sha256(alg || base64(pubkey))` — previously omitted the `base64()` step and disagreed with `spec/PACT_v1.md` §3 and `src/pact/identity.py`.

### Added
- `[project.urls]` in `pyproject.toml`: Homepage, Source, Issues, Documentation, Changelog, Security policy. Previously `null` on PyPI; sidebar links now visible to package adopters.
- `SECURITY.md`: vulnerability disclosure policy via GitHub private advisories. In-scope / out-of-scope clearly defined.

### Deprecated
- `PACTAgent(auto_grant=...)` now emits `DeprecationWarning` when explicitly passed. The argument has been a no-op since v0.5.1. Scheduled for removal in v1.0.

### Changed
- `pact` CLI no longer passes `auto_grant=` internally (was a no-op since v0.5.1; removal silences the new deprecation warning for CLI users).

## [0.5.3] — 2026-05-05

Input-validation patch. Closes 5 audit-surfaced gaps (PR #21).

### Fixed
- Negative or non-numeric `Content-Length` headers now rejected (F1, DoS hardening).
- Malformed base64 in signature, holder-proof, and receipt verifiers fails closed instead of raising `binascii.Error` (F2).
- `max_invocations` and `expires` caveat values validated at `issue_capability` and `attenuate` (F3).
- Streaming write-order race resolved — cache write happens before receipt write (F4).
- TOFU rejects malformed pubkey base64 cleanly (F5).
- `test_oversize_request_rejected` macOS CI flake stabilized.

### Added
- Spec §12.10 addendum documenting fail-closed input validation.

## [0.5.2] — 2026-05-04

Honesty patch. Closes 4 cluster-surfaced gaps (PR #20).

### Fixed
- Dispatch errors now produce signed `outcome=failed` receipts instead of being lost (E1).
- `cap_envelope` foot-gun closed: `build_req(cap_envelope=...)` now requires `cap_id` or auto-derives it from the envelope, raising `ValueError` if neither is present (E11). Previously the envelope was silently transported without verification.

### Added
- `HandlerFailure` exception for explicit handler-side failure signaling (E2).
- Server-side `max_deadline_seconds` ceiling on REQ deadlines, default 3600s, configurable per agent (E7). New fault code `deadline_too_far`.
- Spec single-issuer trust-model note.

## [0.5.1] — 2026-05-03

Polish release.

### Fixed
- Async server parity with sync server (request validation, error responses).
- `lak_channel` import typo.
- Dead `auto_grant` code path removed (no functional change; parameter remains for v0.x back-compat).
- Three audit bugs in streaming detection.

### Added
- 6 new test vectors.
- Three-platform CI matrix (macOS, Linux, Windows 11). 9 CI jobs.
- 19 public exports declared in `pact/__init__.py`.

## [0.5.0] — 2026-05-02

### Added
- Streaming `RES_CHUNK` responses (PR #18, closes #11). NDJSON over HTTP chunked transfer encoding. Handlers can yield iteratively; clients receive chunks as they arrive.

## [0.4.0] — 2026-05-02

### Added
- `cap_envelope` field on REQ messages (PR #17, closes #10). Three-agent delegation (Alice → Bob → Carol) now works inline over the wire. Bob embeds Alice's capability + Bob's attenuation in Carol's REQ; Alice verifies the full chain from the envelope alone.

## [0.3.1] — 2026-05-01

### Fixed
- Rotation peer refresh now performs KERI continuity check on first message from a rotated peer (PR #16, closes #4). XFAIL retired.

## [0.3.0] — 2026-05-01

### Added
- Durable idempotency cache + invocation counts (PR #15, closes #5). Per-agent JSON storage with LRU bound (`idempotency_cache_max`, default 10,000). Survives process restart.

## [0.2.1] — 2026-05-01

### Fixed
- Slow-loris defense: request size limit + read timeout on server (#6, #9).
- Windows binary I/O fix for Ed25519 seed storage (#6).
- Dispatch decomposition: 161-line `_handle_task` refactored into a pipeline of 7 small validators (#13).

## [0.2.0] — 2026-05-01

Auth-bypass triangle closed. Three coordinated security fixes.

### Fixed
- `holder_proof` is **mandatory** when `cap_id` is present (#3). Capability tokens now require a fresh nonce signature from the holder's private key; possession of the token alone is insufficient.
- REQs from unregistered peers are **rejected** unless they include `identity_doc` for trust-on-first-use (#2). Previously the `if sender_pub and not verify_message(...)` short-circuit silently allowed unknown peers.
- `verify_capability` is **fail-closed** when delegation chain keys are missing from cache (#8). Previously a forged chain claiming "Bob delegated to Eve" passed silently if Bob's key was unknown.

## [0.1.4] — 2026-04-30

### Added
- Concurrency safety: `_task_lock` serializes dispatch, fixing the idempotency race and rate-limit-counter race.
- `PACT_CHAOS=1` env var injects random delays at race-prone code paths (chaos testing mode).

### Fixed
- Windows binary-mode key write (`_write_key` now uses `O_BINARY` on platforms that need it). Without it, ~12% of Ed25519 seeds were corrupted by LF→CRLF translation on save. Cross-platform issue.
- Receipt filenames sanitized for NTFS (colons replaced).

## [0.1.0] — 2026-04-29

Initial public release.

### Added
- Self-certifying identity (KERI-style with pre-rotation commitment).
- Holder-bound capability tokens (Macaroons-style, attenuable caveats).
- Three message types: REQ, RES, with bilateral signed receipts.
- `pact` CLI (13 subcommands).
- mDNS discovery via `zeroconf`.
- Formal wire specification (`spec/PACT_v1.md`).
- Deterministic test vectors.
- 111 unit tests.

[0.5.5]: https://github.com/bene-art/pact-passport/releases/tag/v0.5.5
[0.5.4]: https://github.com/bene-art/pact-passport/releases/tag/v0.5.4
[0.5.3]: https://github.com/bene-art/pact-passport/releases/tag/v0.5.3
[0.5.2]: https://github.com/bene-art/pact-passport/releases/tag/v0.5.2
[0.5.1]: https://github.com/bene-art/pact-passport/releases/tag/v0.5.1
[0.5.0]: https://github.com/bene-art/pact-passport/releases/tag/v0.5.0
[0.4.0]: https://github.com/bene-art/pact-passport/releases/tag/v0.4.0
[0.3.1]: https://github.com/bene-art/pact-passport/releases/tag/v0.3.1
[0.3.0]: https://github.com/bene-art/pact-passport/releases/tag/v0.3.0
[0.2.1]: https://github.com/bene-art/pact-passport/releases/tag/v0.2.1
[0.2.0]: https://github.com/bene-art/pact-passport/releases/tag/v0.2.0
[0.1.4]: https://github.com/bene-art/pact-passport/releases/tag/v0.1.4
[0.1.0]: https://github.com/bene-art/pact-passport/releases/tag/v0.1.0
