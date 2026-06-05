# Changelog

All notable changes to PACT Passport are recorded in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
