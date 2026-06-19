# Changelog

All notable changes to PACT Passport are recorded in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] — 2026-06-18

Substrate upgrade informed by external audit of [AIP v0.3.0](https://github.com/sunilp/aip) (`draft-prakash-aip-00`). Closes Bug 11 (P_BIND falsification) via domain-separated signing strings. Adds structured audit context, normative fault taxonomy, three-profile policy model, and bilateral-receipt floor. Spec v1.3.0-draft → v1.4.0-draft. Pre-registered at tag `v0.8.0-pre-registration` (commit `f29b56c`) — the frozen artifact the HotNets paper evidence cites.

### Added

- **Domain-separated signing payloads** (spec §18.1). `holder_proof` signs `{domain:"pact/hp/v1", req_id, cap_id, to_agent}` instead of just the request id. Visa-use signs `{domain:"pact/visa/v1", nonce}`. Closes P_BIND. `pact_passport.message` exports `HOLDER_PROOF_DOMAIN_V1`, `VISA_USE_DOMAIN_V1`, `holder_proof_payload()`, `visa_use_payload()`. v0.7 forms accepted with `DeprecationWarning` during the 90-day §18.7 migration window.
- **`audit_context` field on PACTMessage** (spec §18.2). Required REQ field with `{purpose, audience_hint, requested_action, expires_at}`. `build_req` auto-synthesizes it from existing arguments; receivers in v0.8.0 expose `audit_req()` library function but do not yet enforce at dispatch (v0.8.1 plumbs enforcement).
- **`pact_passport.audit` module** (NEW, 310 lines). `AuditResult` dataclass, `audit_req()`, `audit_receipt()`, `sign_initiator_ack()`, `make_bilateral_receipt()`, `scenario_predicts_match()`. Bilateral receipts per spec §18.6.
- **`pact_passport.policy` module** (NEW, 360 lines). `PolicyProfile` enum (Simple / Standard / Advanced) per spec §18.4. Simple-profile byte-normative factories: `make_action_caveat`, `make_budget_caveat`, `make_depth_caveat`, `make_expiry_caveat`. Standard predicate registry; Advanced opt-in third-party caveats. `classify_caveat_profile()`, `evaluate_caveats()`. Macaroons-style (not Datalog).
- **13-code wire-level fault taxonomy** (spec §18.3). `errors.py` adds `pact_audit_required`, `pact_audit_audience`, `pact_audit_expired`, `pact_audit_malformed`, `pact_cap_invalid`, `pact_cap_expired`, `pact_cap_chain`, `pact_cap_caveat_failed`, `pact_replay`, `pact_rate_limited`, `pact_bind_invalid`, `pact_unknown_message`, `pact_handler_error`. `FAULT_HTTP_STATUS` table + `http_status_for_fault()` helper map each to 400/401/403/410/429/500. Legacy Python exception classes coexist; transport plumbing is library-only in v0.8.0 (v0.8.1/v0.8.2 wire it).
- **Spec §18 — v1.4 amendments** (9 subsections): domain separation, audit_context, fault taxonomy, three policy profiles, identity-document `public_keys` array with rotation overlap windows, bilateral-receipt floor, 90-day pre-v1.4 migration window, attack catalogue reference, threat-model boundary.
- **Spec §19** — v1.3 → v1.4 changelog.
- **Spec §20** — NEW Security Considerations section (8 subsections, IETF I-D convention). AIP v0.3.0 has no equivalent section.
- **Spec §2** — RFC 2119 keyword block.
- **`spec/attacks/attacks.json`** (NEW). 12 attack scenarios, each cross-referenced to formal lemma + Stage 2 probe + predicted fault code + HTTP status + v0.7/v0.8 behavior delta + AIP comparison. AIP ships 3 scenarios; PACT now ships 12.
- **`spec/models/pact_core_v0_8.spthy`** (NEW). v0.8 Tamarin model. Run 3 (2026-06-18): 7/7 lemmas verified including P_BIND in 10 steps. With KEY_CONT (in `pact_rotation.spthy`) + P_OPAQUE (ProVerif): **9/9 formal lemmas pass on v0.8** (was 8/9 on v0.7). `PROOF_LOG.md` Run 3 entry preserved; Run 2 retained as historical.
- **81 v1.4 conformance unit tests** under `tests/v1_4/` — holder_proof_v0_8 (14), audit_context (10), audit_module (7), error_codes (8), policy_profiles (28), attack_catalogue (16).

### Changed

- **Spec bumped: v1.3.0-draft → v1.4.0-draft** (932 → 1313 lines, +381 normative). v1.3 §16 amendments preserved.
- **Receipts are normatively bilateral** (spec §18.6). v0.7 unilateral receipts still verify; v0.8 introduces the bilateral floor in the spec and the library helper. Wire round-trip via new `INITIATOR_ACK` message type ships in v0.8.2.
- **Identity documents** carry a `public_keys` array with `valid_from` / `valid_until` overlap windows (spec §18.5). Self-certifying only — PACT explicitly refuses AIP's `aip:web:` DNS-anchored identity form (spec §20.3 + §3.5).

### Fixed

- **Bug 11 — `holder_proof` replay across different (cap, audience) pairs.** v0.7 signed only `req_id`, so a captured holder-proof could be replayed within a fresh REQ to a different audience or for a different cap. v0.8's domain-separated payload binds `cap_id` + `to_agent` into the signed bytes. Tamarin v0.7 falsified P_BIND in 8 steps; Tamarin v0.8 verifies P_BIND in 10 steps. Counterexample-search wall clock dropped 0.86s → 0.61s.

### Deprecated

- **v0.7 `holder_proof` payload** (raw `req_id` only). Accepted with `DeprecationWarning` per spec §18.7 90-day migration window; will be rejected in v0.9.
- **Legacy fault names** in `errors.py` Python exception classes. New code should construct wire-level `pact_*` faults via the v1.4 taxonomy; legacy exception classes retained for one minor cycle.

### Library-complete vs dispatch-integrated

v0.8.0 ships the v1.4 library modules; dispatch-pipeline plumbing is split into follow-on releases per Option D pre-registration discipline:

- **v0.8.0 (this release)** — library modules + spec + tests + formal-verification freeze.
- **v0.8.1 (planned)** — plumb `audit_req` into REQ + V-tier dispatch, audit-side `pact_*` fault codes + HTTP mapping at transport, replace caveat loop with `policy.evaluate_caveats`, CLI v0.8 surface.
- **v0.8.2 (planned)** — bilateral receipt round-trip via new `INITIATOR_ACK` message type, completion of `pact_*` fault taxonomy across non-audit dispatch sites.

Each release pre-registers its own tag and re-runs the Phase A / B / B-2 confirmatory probes for clean attribution of any §12 cell movement.

### Tests

282 → 412 dynamic (+130: 81 v1.4 conformance + 49 incidental). Stage 2 harness probes count unchanged (10 STOCH wired to real Ollama via `ollama_chat` helper, was 10 stubs). Formal verification 8/9 → 9/9 lemmas. 1 by-design negative-control falsification (`pact_opaque_negative_control.pv`) confirms the equivalence query has teeth.

### Pre-registration evidence stack

Frozen at tag `v0.8.0-pre-registration` (commit `f29b56c`):

- **D1** — threat coverage matrix at `~/Desktop/PACT_HotNets_Paper/D1_threat_coverage_matrix.md`.
- **D2** — Tamarin + ProVerif 9/9 lemmas (Run 3 logs at `spec/models/run_logs/run3_*.txt`).
- **D3** — calibrated harness with provenance stamps (M1 K-defect manifest).
- **D3.5** — §12 ablation matrix (clean 5×5 diagonal Mac + NUC).
- **D4** — Phase A confirmatory: Mac gemma4:e4b + NUC gemma3:12b. 347/348 cross-machine cell agreement (H5 invariance under heterogeneous LLM + OS).
- **D4 supplement** — M1 K-sweep, sensitivity 0.6 at K=5.
- **D5** — Phase B + B-2 exploratory: 3 adversaries (gemma4:e4b on Mac, gemma3:12b on NUC, Qwen3-235B-A22B via DeepInfra) × 5 Gap-B targets × 210+ iterations = **0 real findings** on v0.7, **0 real findings** on v0.8 re-run.
- **D6** — PACT vs AIP + v0.7 vs v0.8 comparison at `~/Desktop/PACT_HotNets_Paper/D6_PACT_VS_AIP_AND_V07_VS_V08.md`.

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

[0.8.0]: https://github.com/bene-art/pact-passport/releases/tag/v0.8.0-pre-registration
[0.7.1]: https://github.com/bene-art/pact-passport/releases/tag/v0.7.1
[0.7.0]: https://github.com/bene-art/pact-passport/releases/tag/v0.7.0
[0.6.1]: https://github.com/bene-art/pact-passport/releases/tag/v0.6.1
[0.6.0]: https://github.com/bene-art/pact-passport/releases/tag/v0.6.0
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
