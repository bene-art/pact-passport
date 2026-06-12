# Changelog

All notable changes to PACT Passport are recorded in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.1] — 2026-06-12

README-only patch. v0.7.0's README didn't reflect v0.7.0's own rename — shipped to PyPI with stale `src/pact/` paths and a Status line still saying v0.6.1. No code change.

### Fixed (README only)

- **Status block** updated from "v0.6.1" to "v0.7.x" and now describes the rename + PQ soften + Node 24 actions. Includes a one-line migration note (`from pact import X` → `from pact_passport import X`).
- **Overview** LOC line: `src/pact/` → `src/pact_passport/`.
- **Primitives table** Source column: 5 rows updated from `src/pact/X.py` to `src/pact_passport/X.py` (identity, capability, visa, message, receipt).
- **Features-by-Release table** dropped v0.5.4 (oldest), added v0.7.0 + v0.7.1 rows. Intro updated from "last 3" to "last 4".

### Why a release for README-only

PyPI displays the README from the wheel METADATA, frozen per release. The v0.7.0 wheel had a stale README baked in. Fixing the GitHub README would leave PyPI showing inconsistent paths until the next substantive release. v0.7.1 ships a corrected README via the same OIDC publish workflow.

## [0.7.0] — 2026-06-11

Module rename for namespace hygiene + post-quantum claim softened. No wire / on-disk / behavior changes. Both fixes prompted by external review of v0.6.1.

### Breaking changes

- **Python module renamed: `pact` → `pact_passport`.** The previous import path silently shadowed [`pact-python`](https://pypi.org/project/pact-python/) — the widely-used Pact Foundation contract-testing library, which also installs as the `pact` module. Any environment with both packages installed had unpredictable behavior depending on `sys.path` order. After v0.7.0, both packages coexist without conflict.

  **Migration (every import path):**

  ```python
  # Before (v0.6.x and earlier):
  from pact import PACTAgent
  from pact.capability import issue_capability, Caveat
  from pact.message import build_req, verify_message

  # After (v0.7.0+):
  from pact_passport import PACTAgent
  from pact_passport.capability import issue_capability, Caveat
  from pact_passport.message import build_req, verify_message
  ```

  **Unchanged:**
  - PyPI package name: `pact-passport` (`pip install pact-passport` works as before).
  - CLI binary: `pact` (no conflict — pact-python ships `pact-broker`, `pact-stub-service`, etc., not a bare `pact`).
  - Wire protocol, on-disk format, capability tokens, receipts, test vectors, spec — no changes. v0.6.1 receipts/caps remain valid; only the import path moves.

### Changed

- **Post-quantum claim softened in README.** Architecture box and Non-goals previously said `crypto.py` was "a single-file seam for the eventual migration" / "post-quantum swap = one file change". Both overclaimed — a real PQ migration changes `agent_id` derivation (PQ pubkeys are 1–4KB vs Ed25519's 32B), signature/token sizes, the spec, and test vectors. Updated to acknowledge the migration is non-trivial; the architectural point ("crypto isolated to one module") is preserved.

### Tests

282 tests, all passing. No count change — every test file's imports moved from `pact` to `pact_passport`; no test behavior changes.

## [0.6.1] — 2026-06-11

Bug 10 fix + documentation pass. No wire changes.

### Fixed

- **Bug 10 — stream-partition transport handler missed the Windows exception variant.** The Bug 7 fix to `_run_streaming_handler` (v0.6.0) was correct, but the transport-layer catch at `transport/server.py:171` enumerated POSIX exception types only: `(BrokenPipeError, ConnectionResetError)`. On Windows, consumer disconnect raises `ConnectionAbortedError` (WinError 10053), which escaped the catch and bypassed `chunks_iter.close()` cleanup. Mac and Linux passed locally; only the CI matrix on the v0.6.0 release push surfaced the gap (Windows × Python 3.11 / 3.12 / 3.13 all failed `test_c3_stage1_partition_writes_cancelled_receipt` with `expected exactly 1 cancelled receipt; got 0`). Fixed by widening the catch to the parent class `ConnectionError`, which covers `BrokenPipeError` + `ConnectionResetError` + `ConnectionAbortedError` and any future platform-specific subclass. Regression test in `tests/test_server.py::test_send_stream_catches_all_connection_error_subclasses` asserts the exception hierarchy our fix depends on and that the source code uses the parent class, not the narrower tuple.

### Documentation

- **README polish (26 changes):** compressed run-on Status paragraph to one-sentence headline + bullets; trimmed Breaking-changes list to v0.5.2 → v0.6 + link to CHANGELOG; updated Overview LOC count (~3,750 → ~4,600); softened `refs[]` causal-ordering claim to acknowledge sender-assertion; added Trust-gradient row to Guarantees table (passport / visa / refusal); updated Capability + Receipt rows in Primitives table; added Visa row; updated Non-goals version references (post-v0.6 → post-v0.7); added `--agent` + `--capabilities` flags to CLI Commands table; added `visa.py` to Architecture diagram; trimmed Features-by-Release table to last 3 releases; replaced 281-test paragraph with bulleted coverage; updated Platform-support table with actual CI matrix status; reconciled 5-vs-9 bug count by pointing to EXPERIMENTS.md Part 2; removed internal jargon (NUC-bridge, C-tier, B1/B3 labels, "load-bearing"); dropped v0.5.5 row (subsumed into v0.6.0, never released standalone).
- **EXPERIMENTS.md Part 2 added** covering v0.5.5 → v0.6.1 paper-revision experiments. Bugs 6 / 7 / 8 / 9 / 10 documented with same narrative style as v0.1.3's Part 1. Stage 2 cross-machine probe harness section. Updated "What I learned" lessons (#5: the CI matrix is an adversary too). Updated "Where this leaves PACT" for v0.6.1 state. Part 1 (v0.1.3 case study) preserved intact as historical record.

### Tests

281 → 282 (+1 Bug 10 regression test). Coverage unchanged. CI matrix green across macOS / Linux / Windows × Python 3.11 / 3.12 / 3.13.

## [0.6.0] — 2026-06-11

Two bug fixes for issues surfaced by C-tier cluster testing (#29, #30), one rate-limit binding fix (Bug 8), one capability-chain correctness fix (Bug 9), the V-tier visa machinery, and an emit-only `protocol_advertisement` field. Spec moves v1.1.0-draft → v1.3.0-draft. **Wire changes — see "Breaking changes" below.**

### Added

- **V-tier visa machinery** (`src/pact/visa.py`). Three-tier trust gradient (passport → visa → refusal) above the v0.5 capability layer. `PACTAgent(visa_policy=...)` accepts a policy hook; default policy ships an opt-in `visa_eligible` predicate with idempotent-action allowlist, ≤4KB / ≤100ms / ≤5-per-60s-per-peer caps, and per-peer serialization to close V6 amplification races. Verified by V1–V7 adversarial battery (7/7 green, `tests/integration/test_v_tier_v1_v7.py`).
- **`ProtocolAdvertisement` field on visa-grant + visa-refusal payloads.** Optional, signed via the existing response signature, **emit-only by architectural mandate**: PACT contains no code path that consumes, parses-for-action, fetches, logs, or branches on a received advertisement. Spec §16.5 enforces the MUST-NOT; test 6.4 (`tests/integration/test_v_tier_protocol_advertisement.py`) is the load-bearing no-consumption proof. Constructor knob: `PACTAgent(advertise_protocol=ProtocolAdvertisement(...))`; per-decision override via `VisaGrant.protocol_advertisement` / `VisaRefuse.protocol_advertisement`.
- **Stage 2 adversarial probe harness** (`tests/stage2/`): 25 pre-registered probes across A/C/L/M/P/R/S/V tiers (~3.4K LOC). Each probe self-describes via `@probe` decorator (pairing, prediction, failure threshold, citation) and writes one JSON to a timestamped results dir. Loopback smoke: 24/33 sub-probes green; remaining 9 documented `new_finding` pending cross-machine NUC-bridge runs.
- 14 CLI smoke tests (`tests/test_cli.py`) covering `init`, `identity`, `caps`, `grant`, `revoke`, `receipts`, `peers`, `doctor`. 3 `PACTAgent.ask()` integration tests (`tests/integration/test_agent_ask.py`) — happy path, unknown target, failed-receipt-on-error.
- `CHANGELOG.md`, `CONTRIBUTING.md`, `.github/ISSUE_TEMPLATE/{bug_report,feature_request,config}.{md,yml}`, `.github/PULL_REQUEST_TEMPLATE.md`.

### Fixed

- **#29 — multi-hop delegation chains (K≥3) fail verification (Bug 6).** `verify_capability` now checks each `DelegationLink` against its own contemporaneous `parent_cap_id` instead of the final token's parent. Chains of any depth verify; v0.5.x verifiers rejected K≥3 chains spuriously. Wire change — see Breaking changes.
- **#30 — stream partition skipped server-side receipt write (Bug 7).** `_run_streaming_handler` restructured to `try/finally` with an `outcome` state variable defaulting to `"cancelled"`. `GeneratorExit` (raised on `BrokenPipeError`) no longer bypasses receipt persistence. §3.5 unilateral-receipt claim now actually holds for streaming; §12.9's `outcome="cancelled"` is now emitted (previously specified but never written).
- **Bug 8 — `ctx.cap_token` unbound during rate-limit refusals.** Dispatch binds the verified visa onto the context *before* rate-limit refusal so receipts under visa carry the correct `visa_cap_id` even on the refusal path.
- **Bug 9 — rogue-delegator forgery accepted by chain verifier.** `attenuate()` signs the link over `canonical_json({parent_cap_id, action_at_step, caveats_at_step})`; `verify_capability` walks the chain enforcing (1) action preservation, (2) caveat append-only, (3) final-token consistency. Macaroons-style chain re-derivation ported to Ed25519. Surfaced 2026-06-08 when the Bug 6 fix unmasked prior B1 vacuous rejections. All Bugs 1–9 from the v0.1 case-study battery are now closed at the reference-implementation level; cross-machine validation pending Stage 2 runs.
- Three `ImportError` messages told users to `pip install pact-protocol[...]` — a squatted name on PyPI. Updated to `pact-passport[...]` across `_canonical.py` and `transport/async_server.py`. Five docstrings + test-vector generator metadata updated for the same rename.

### Changed

- **Spec bumped: v1.1.0-draft → v1.2.0-draft → v1.3.0-draft.** v1.2 adds §14 (three-tier trust gradient, visa REQ/RES shape, holder-proof binds visa nonce, default issuance policy, Bug 6/7/8 normative codification, Bug 9 acknowledged-but-deferred) + §15 changelog. v1.3 adds §16 (chain re-derivation, action/caveat preservation, pre-v1.3 fallback with `DeprecationWarning`, threat-model boundaries) + §16.5 `protocol_advertisement` MUST-NOT + §17 changelog. v1.3 verifier closes Bug 9 normatively. Spec length: 684 → ~990 lines.
- Ruff lint pass on `src/pact/`: 56 findings closed (51 auto-fixed + 5 manual). UP035 (`Callable`/`Iterator` → `collections.abc`), UP041 (`socket.timeout` → `TimeoutError`), UP017 (`datetime.UTC`), SIM108/SIM105, RUF022, F401 (unused `CBOR_CONTENT_TYPE` — CBOR client path tracked as #27), B904 (`from None` on optional-dep `ImportError`), RUF002 (`×` → `x` in `lak_channel.py`).

### Breaking changes

- **Pre-v1.3 delegation chains verify with `DeprecationWarning` only at K=2.** v1.3 chains verify natively at any depth. v1.4 will drop pre-v1.3 chain support. Re-issue long-lived multi-hop capabilities before v1.4.
- **`cancelled` receipt outcome now emits on stream partition.** Downstream code that assumed streaming receipts were only `{completed, failed}` must add a `cancelled` branch.

### Deferred (visible as GitHub issues)

#22 `trusted_issuers` (cross-org capability chains), #23 application-level caveat enforcement, #24 cross-machine revocation propagation, #25 post-quantum signatures, #26 per-token cost accounting, #27 client-side CBOR.

### Tests

281 collected, 281 passed locally (macOS). Linux + Windows pending CI on push. Coverage 64% → 74%. Stage 2 probe harness (25 probes) runs standalone, not under `pytest`.

### Release cadence

HotNets paper deadline 2026-07-16. Subsequent releases will continue shipping fixes and Stage 2 probe results as the cross-machine experiments complete. This release reflects local-loopback validation; cross-machine empirical results follow.

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
