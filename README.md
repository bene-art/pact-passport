# PACT Passport

**The cryptographic substrate for agent-to-agent trust.**

[![Tests](https://github.com/bene-art/pact-passport/actions/workflows/test.yml/badge.svg)](https://github.com/bene-art/pact-passport/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/pact-passport)](https://pypi.org/project/pact-passport/)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Self-certifying identity, holder-bound capabilities, structured audit context, and bilaterally-signed receipts for agent-to-agent systems. Three message types — REQ, RES, RES_CHUNK (with `INITIATOR_ACK` as a fourth in v0.8.2). Everything else is built at the edges.

> **Status: v0.8.0 — pre-registered at `v0.8.0-pre-registration`** (commit `f29b56c`). Spec v1.3.0-draft → v1.4.0-draft (§18 amendments + §19 changelog + §20 Security Considerations). Domain-separated signing closes Bug 11 (P_BIND falsification): Tamarin 8/9 → 9/9 lemmas verified. Library modules `audit.py` + `policy.py` ship in v0.8.0; dispatch-pipeline plumbing of audit enforcement + fault taxonomy ships in v0.8.1 / v0.8.2 (each with its own pre-registration tag and confirmatory run).
>
> - **Closes Bug 11 (P_BIND).** `holder_proof` now signs `{domain:"pact/hp/v1", req_id, cap_id, to_agent}` instead of `req_id` alone; visa-use signs `{domain:"pact/visa/v1", nonce}`. v0.7 forms accepted with `DeprecationWarning` during the spec §18.7 90-day migration window.
> - **Three policy profiles** (spec §18.4): Simple (byte-normative templates), Standard (registered predicates), Advanced (third-party caveats). Macaroons-style — PACT explicitly refuses Datalog.
> - **Bilateral receipts** are the normative floor (spec §18.6). Library helper ships now; wire round-trip via new `INITIATOR_ACK` message type ships in v0.8.2.
> - **13-code wire-level fault taxonomy** (spec §18.3) with `FAULT_HTTP_STATUS` mapping to 400 / 401 / 403 / 410 / 429 / 500.
> - **12-scenario attack catalogue** (`spec/attacks/attacks.json`) cross-referenced to formal lemmas + Stage 2 probes + fault codes. AIP v0.3.0 ships 3 scenarios; PACT now ships 12.
> - **412 dynamic tests + 9/9 formal lemmas** (was 282 + 8/9). 81 v1.4 conformance tests under `tests/v1_4/`. Stage 2 adversarial harness wired to real Ollama (10 STOCH probes).
> - **D6 evidence stack**: Tamarin Run 3 + Phase A confirmatory Mac & NUC + Phase B + Phase B-2 DeepInfra Qwen3-235B = 0 real findings across 210+ v0.7 + v0.8 adversary iterations. H5 invariance confirmed (Mac gemma4:e4b vs NUC gemma3:12b, 347/348 cross-machine cell agreement).
> - Full case-study details in [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md) Part 2 (v0.5.5 → v0.6.1) and v0.8 release notes in [CHANGELOG.md](CHANGELOG.md).

> **Breaking changes (v0.5.2 → v0.6):** see [CHANGELOG.md](CHANGELOG.md) for the full v0.2 → v0.5.1 history.
> - `build_req(cap_envelope=...)` without an explicit `cap_id` now auto-derives `cap_id` from the envelope, or raises `ValueError` if the envelope lacks one (v0.5.2; was silent pass).
> - REQs with deadlines further than `max_deadline_seconds` (default 3600s) in the future are rejected with new fault code `deadline_too_far` (v0.5.2; bump the constructor arg for long-running streaming intents).
> - `DelegationLink` gains required-from-v1.3 `action_at_step` + `caveats_at_step` fields; pre-v1.3 chains verify at K=2 only with `DeprecationWarning`. v1.4 will drop pre-v1.3 support — re-issue long-lived multi-hop capabilities before then (v0.6.0, Bug 9 / spec §16.1).
> - `cancelled` receipt outcome emits on streaming partition; downstream code assuming `{completed, failed}` only must add a `cancelled` branch (v0.6.0, #30 / Bug 7).

## Overview

PACT Passport is a Python implementation of the cryptographic substrate from which agent-to-agent trust systems are built. It supplies three things: self-certifying identity, holder-bound capability tokens, and unilateral signed receipts. The substrate is composed with application-layer caveat enforcement and authorization decisions to deliver trust — the same way TLS supplies authenticated transport that PKI and applications compose into secure communication. It sits below orchestration protocols like MCP and A2A as the layer that answers *who is this agent, what can they do, and what did they do*. No central authority, no shared secrets, no registry.

The reference implementation is ~5,058 LOC in `src/pact_passport/`. The wire protocol is specified in [`spec/PACT_v1.md`](spec/PACT_v1.md) — sufficient for independent implementations. Deterministic test vectors at [`tests/vectors/pact_v1_vectors.json`](tests/vectors/pact_v1_vectors.json). The 12-scenario attack catalogue at [`spec/attacks/attacks.json`](spec/attacks/attacks.json) cross-references every adversary against the formal lemma it would have to break.

### Design principle

**Minimize the arc from an external verdict that something landed wrong to targeted revocation.** Bounded blast-radius + attributable trace + fast fail-closed revoke is the honest envelope. The substrate does not detect compromise; once detected (out-of-band), it makes the response cheap and aimed.

This principle informs every primitive: short-TTL caps + `max_invocations` cap the blast radius; signed receipts (unilateral in v0.7, bilateral floor from v0.8) give the principal something to point at and a key to revoke; the v0.9 `REVOKE` beacon (roadmap) is the arc-minimization extension for cross-machine settings.

### Guarantees

| Property | Mechanism |
|---|---|
| Authenticity | Every message + receipt signed Ed25519 (PyNaCl). `verify_message` is fail-closed on malformed input. |
| Identity | `agent_id = sha256(alg \|\| base64(pubkey))`. Self-certifying; no CA. |
| Key rotation | KERI-style pre-rotation via `next_key_digest`. First post-rotation message proves continuity. |
| Authorization | Holder-bound capability tokens with append-only caveat chain. Stolen tokens require the holder's private key to present (`holder_proof`). |
| Replay safety | Mandatory `idempotency_key` per REQ. Durable cache survives process restart. |
| Causal ordering | `refs[]` field carries sender-asserted back-references; a cooperative sender forms a causal DAG over message history. |
| Liveness | Mandatory `deadline` with server-side enforcement and configurable upper bound (default 3600s). |
| Audit | Each side writes its own signed receipt. v0.8 makes bilateral receipts the normative floor (spec §18.6); the v0.8.0 library ships the bilateral helper, the v0.8.2 wire round-trip via new `INITIATOR_ACK` message type follows. `outcome ∈ {completed, failed, cancelled}` including stream partition. |
| Audit context | Every REQ carries structured `audit_context = {purpose, audience_hint, requested_action, expires_at}` (spec §18.2). Receivers can audit before dispatch; enforcement plumbing lands in v0.8.1. |
| Policy profiles | Simple (byte-normative templates) / Standard (registered predicates) / Advanced (third-party caveats) per spec §18.4. Macaroons-style — not Datalog. |
| Fault taxonomy | 13 wire-level `pact_*` codes (spec §18.3) mapped to HTTP 400 / 401 / 403 / 410 / 429 / 500 via `FAULT_HTTP_STATUS`. |
| Formal verification | Tamarin verifies 8 + KEY_CONT lemmas including P_AUTH, P_MONO (unbounded K), P_BIND (v0.8), P_REPLAY; ProVerif verifies P_OPAQUE observational equivalence. **9/9 lemmas on v0.8** (was 8/9 on v0.7 — P_BIND closed by spec §18.1 domain separation). See [`spec/models/PROOF_LOG.md`](spec/models/PROOF_LOG.md). |
| Trust gradient | Three tiers: passport (full identity), visa (session-scoped attenuated capability for passport-less peers), refusal (opaque, no information leak). v0.6+. |
| Detection precondition | PACT assumes detection of compromise is out-of-band. The substrate makes the *response* to detected compromise cheap and aimed (bounded blast-radius via `max_invocations` + attributable trace + fast fail-closed revoke); it does not detect the compromise itself. |

### Primitives

| Primitive | What it is | Source |
|---|---|---|
| **Identity** | Ed25519 keypair with self-certifying `agent_id` derived from the pubkey, plus a `next_key_digest` commitment for KERI-style rotation. | `src/pact_passport/identity.py` |
| **Capability** | Signed, holder-bound token. Caveats append-only; verifier re-derives action + caveats at each chain step (Macaroons-style). Multi-hop delegation at any depth verifies inline via `cap_envelope`. | `src/pact_passport/capability.py` |
| **Visa** | Session-scoped, attenuated capability bound to an ephemeral key. Issued by a gatekeeper to a passport-less counterparty; binds the *session*, not the *identity*. | `src/pact_passport/visa.py` |
| **Message** | `REQ` / `RES` / `RES_CHUNK` (streaming). Mandatory `deadline` + `idempotency_key`. `refs[]` carries sender-asserted causal back-references. | `src/pact_passport/message.py` |
| **Receipt** | Each side writes its own signed receipt unilaterally — no coordination required. Both receipts share `task_ref`, so the pair reconstructs a bilateral trace post-hoc. `outcome ∈ {completed, failed, cancelled}`. | `src/pact_passport/receipt.py` |

### Architectural contract

PACT supplies the cryptographic substrate. The application layer enforces caveats and makes authorization decisions. The composition is the trust system.

- **PACT's job:** sign, verify, attenuate, bind, record. The wire-level invariants.
- **The application's job:** decide whether a caveat is satisfied. Decide whether the bilateral receipt trace warrants action (or revocation). Decide what the principal authorized.
- **The composition:** a trust system. Neither layer alone is. Both together are.

This is the same pattern as TLS + PKI + application logic. PACT is the TLS-shaped piece.

### Non-goals

- **Cross-organization capability chains.** v0.8 still enforces strict `issuer must be self`. Cross-org via a `trusted_issuers` set is v0.9 roadmap.
- **Cross-machine revocation propagation.** Issuer-local only — no CRL, no push-REVOKE. The v0.9 `REVOKE` beacon (roadmap) is the planned arc-minimization extension.
- **Post-quantum signatures.** Ed25519 throughout. Crypto is isolated to one module (`crypto.py`) — but a real PQ migration changes `agent_id` derivation, signature/token sizes, the spec, and test vectors. Not a one-line swap; the surface is just contained.
- **Per-token cost accounting.** Rate limits via `max_invocations` only. Token economics belong one layer up.

## Install

```bash
pip install pact-passport
```

Or directly from this repo:
```bash
pip install git+https://github.com/bene-art/pact-passport.git
```

Optional extras:
```bash
pip install pact-passport[cbor]    # CBOR encoding support
pip install pact-passport[fast]    # Async uvicorn server
pip install pact-passport[lak]     # local-agent-kit integration
```

The Python module is `pact_passport` (matches the PyPI distribution name). Import as `from pact_passport import PACTAgent`. v0.6.x and earlier installed the module as `pact`, which silently shadowed the `pact-python` contract-testing library when both were installed — see CHANGELOG migration notes for v0.7.0.

## Quick Start

### CLI

```bash
# Terminal 1: Create and serve an agent
pact init alice
pact serve --agent alice --capabilities get_weather

# Terminal 2: Create another agent, discover, and ask
pact init bob
pact discover
pact ask alice get_weather '{"city": "Chicago"}'
pact receipts
```

### Python API

```python
from pact_passport import PACTAgent

agent = PACTAgent("alice", capabilities=["get_weather"])

@agent.handle("get_weather")
def weather(payload):
    return {"temp": 72, "condition": "clear"}

agent.serve()
```

### Demo

```bash
python examples/demo.py
```

Runs two agents in-process, exchanges a capability-scoped task, and verifies receipts.

## CLI Commands

| Command | Purpose |
|---------|---------|
| `pact init <name>` | Create agent identity with pre-rotation key commitment |
| `pact serve` | Start HTTP server + mDNS broadcast. Flags: `--agent NAME`, `--capabilities a,b,c` (comma-separated). |
| `pact discover` | Find agents on local network |
| `pact ask <target> <action> [payload]` | Send a task (auto-handshake on first contact) |
| `pact grant <holder> <action>` | Issue a capability token |
| `pact revoke <cap_id>` | Revoke a capability |
| `pact caps` | List issued capabilities |
| `pact rotate` | Rotate keys using pre-rotation |
| `pact doctor` | Validate keys, event log, permissions |
| `pact trace <msg_id>` | Walk the causal message DAG |
| `pact receipts` | List audit receipts |
| `pact identity` | Show public identity document |
| `pact peers` | List known peers |

## Architecture

```
crypto.py                All PyNaCl in one module (crypto surface isolated; PQ migration is non-trivial but contained)
identity.py              Ed25519 identity, agent_id, key event log, rotation
capability.py            Token issue, attenuate, verify, multi-hop delegation chains (Macaroons-style re-derivation)
visa.py                  V-tier visa machinery: issuance policy, holder-proof binding (v0.8 domain-separated), peer-network-id rate limits
message.py               REQ/RES builder, signer, verifier (v0.8 audit_context field + domain-separated holder_proof)
receipt.py               Signed audit receipts (bilateral floor from v0.8 spec §18.6)
audit.py                 v0.8: AuditResult, audit_req, audit_receipt, sign_initiator_ack, make_bilateral_receipt
policy.py                v0.8: PolicyProfile enum (Simple/Standard/Advanced), caveat factories, evaluate_caveats
errors.py                Python exception classes + v0.8 13-code wire fault taxonomy + FAULT_HTTP_STATUS mapping
store.py                 Filesystem storage (~/.pact/)
_ablations.py            §12 ablation env-var guards (BIND, CHAIN, RECEIPT, NONCE, RATE) — research-only
_canonical.py            Canonical JSON (sort_keys + no whitespace + ASCII-safe)
transport/
  server.py              HTTP server with CBOR content negotiation
  async_server.py        Optional async server via uvicorn
  client.py              HTTP client with CBOR support
  discovery.py           mDNS via zeroconf
agent.py                 PACTAgent high-level API
cli.py                   `pact` command (13 subcommands; v0.8.1 will add `pact audit` + --audit-purpose surface)
contrib/
  lak_channel.py         local-agent-kit integration
```

## Features by Release

Last 5 releases below; see [CHANGELOG.md](CHANGELOG.md) for v0.1 → v0.5.4 history.

| Release | Feature | Status |
|---|---|---|
| v0.6.1 | Bug 10 fix: stream-partition transport handler now catches `ConnectionError` (parent class), covering `ConnectionAbortedError` (Windows WinError 10053). README polish + EXPERIMENTS.md Part 2 documenting Bugs 6–10. | Done |
| v0.7.0 | **Python module renamed `pact` → `pact_passport`** to avoid silent shadowing with [`pact-python`](https://pypi.org/project/pact-python/). Post-quantum claim softened per external review. **Import-path breaking change — see CHANGELOG.md for migration.** | Done |
| v0.7.1 | README-only patch correcting v0.7.0's stale paths and Status line. | Done |
| v0.8.0 | **Spec v1.4.0-draft + Bug 11 closure.** Domain-separated `holder_proof` payload (`pact/hp/v1` + `pact/visa/v1`) closes P_BIND falsification; Tamarin 8/9 → 9/9 lemmas verified. New library modules: `audit.py` (bilateral receipts per spec §18.6), `policy.py` (three-profile model per §18.4). 13-code wire fault taxonomy + `FAULT_HTTP_STATUS` mapping (§18.3). 12-scenario attack catalogue cross-referenced to lemmas + probes. Library-complete; dispatch plumbing scheduled for v0.8.1 + v0.8.2. Pre-registered at `v0.8.0-pre-registration`. | Done |
| v0.8.1 (planned) | Plumb `audit_req()` into REQ + V-tier visa dispatch (spec §18.2 enforcement). Audit-side `pact_*` fault codes wired through transport (§18.3 audit subset). `policy.evaluate_caveats` replaces hand-rolled caveat loop in capability verifier (§18.4 enforcement). CLI `pact audit` + `--audit-purpose` surface. Own pre-registration tag + confirmatory re-run. | Planned |
| v0.8.2 (planned) | Bilateral receipt wire round-trip via new `INITIATOR_ACK` message type (§18.6 enforcement). Remaining 9 of 13 `pact_*` fault codes wired through dispatch + transport. Own pre-registration tag + confirmatory re-run. | Planned |
| v0.9 (roadmap) | `REVOKE` beacon — multicast, signed by issuer, fail-closed at every holder. Hash-chained receipts + checkpoint gossip (audit equivocation closure). Channel-bound peer identity (Noise / TLS exporter). Cross-org chains via `trusted_issuers`. Runtime cost metering. | Planned |

## Tests

```bash
pip install -e ".[dev,cbor,fast]"
pytest -v
```

412 dynamic tests + 9/9 formal lemmas (Tamarin + ProVerif) + 1 by-design negative-control falsification. 1 strict-xfail (B0_TLS baseline, deferred to Phase C). Coverage:

- **Cryptography, identity, key rotation, doctor validation** — Ed25519 round-trip, key event log, KERI pre-rotation, store-permission checks.
- **Capabilities** — issue, attenuate, verify, multi-hop chains at K ∈ {3, 5, 7, 10}, `cap_envelope`, append-only caveats, chain re-derivation (Macaroons-style).
- **Messages** — REQ / RES / RES_CHUNK, signing, deadline enforcement, idempotency, sender-asserted `refs[]`.
- **Receipts** — completed / failed / cancelled, including stream-partition cancellation across POSIX + Windows exception variants.
- **Transport** — HTTP, CBOR content negotiation, async (uvicorn), mDNS discovery, slow-loris read-timeout.
- **Integration** — two-agent + three-agent delegation, V-tier visa battery (V1–V7), `protocol_advertisement` no-consumption proof, deep-delegation regression.
- **Stress** — 5 race-conditions under concurrent dispatch, `PACT_CHAOS=1` chaos mode.
- **CLI smoke** — `init` / `identity` / `caps` / `grant` / `revoke` / `receipts` / `peers` / `doctor`.
- **End-to-end** — `PACTAgent.ask()` happy path / unknown target / failed-receipt-on-error.
- **Formal models** — Tamarin verifies 5 PACT properties (P-MONO unbounded K, others) + 3 sanity canaries; ProVerif verifies P-OPAQUE with model-has-teeth negative control. P-BIND falsified → drives v0.8 domain-separation roadmap. See [`spec/models/PROOF_LOG.md`](spec/models/PROOF_LOG.md).
- **§12 ablation matrix** — clean attribution diagonal on Mac loopback: every defense attributes to exactly one mechanism. Two independent attribution mechanisms (formal + empirical) converge. See [`tests/stage2/ablations/`](tests/stage2/ablations/).

**v1.4 conformance** (81 tests under [`tests/v1_4/`](tests/v1_4/)) — holder_proof v0.8 domain separation, audit_context structure, audit module, fault-code taxonomy, three policy profiles, attack catalogue cross-references.

Stage 2 adversarial probe harness (33 probe scripts across DET + STOCH + ATTR + xmachine + adversary_loop tiers) runs standalone, not under `pytest` — see [`tests/stage2/`](tests/stage2/). 10 STOCH probes wired to real Ollama via `ollama_chat` helper in v0.8.

### Platform support

| Platform | Status |
|---|---|
| **macOS** | green (CI matrix: macos-latest × Python 3.11 / 3.12 / 3.13) |
| **Linux** | green (CI matrix: ubuntu-latest × Python 3.11 / 3.12 / 3.13) |
| **Windows 11** | green (CI matrix: windows-latest × Python 3.11 / 3.12 / 3.13; some POSIX-only tests skipped) |

### Concurrency stress mode

Set `PACT_CHAOS=1` to inject random delays at race-prone code paths. Useful for catching idempotency / rate-limit races that would otherwise surface 1-in-1000:

```bash
PACT_CHAOS=1 pytest -v
```

## Specification

- **Concept document:** [docs/PACT_Specification.md](docs/PACT_Specification.md)
- **Formal v1 spec:** [spec/PACT_v1.md](spec/PACT_v1.md) — sufficient for independent implementation
- **Test vectors:** [tests/vectors/pact_v1_vectors.json](tests/vectors/pact_v1_vectors.json) — deterministic, reproducible
- **Case study (v0.1.3 + paper-revision through v0.6.1):** [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md) — Part 1 covers 23 stress experiments and 5 bugs in the v0.1.3 era; Part 2 covers paper-revision experiments and 5 additional bugs (Bugs 6–10), including one caught by CI matrix on the v0.6.0 release push.

### Theoretical Foundations

| Paper | Contribution |
|-------|-------------|
| Saltzer, Reed, Clark — *End-to-End Arguments* (1984) | Push verification to agents, not transport |
| Waldo et al. — *A Note on Distributed Computing* (1994) | Failure is explicit, never abstracted away |
| Lamport — *Time, Clocks, and the Ordering of Events* (1978) | Causal ordering via message DAG |
| Birgisson et al. — *Macaroons* (2014) | Attenuable, context-bound capability tokens |
| Smith — *KERI* (2019) | Self-certifying identity with pre-rotation |
| Miller — *Robust Composition* (2006) | Capability discipline, no ambient authority |
| Tomašev et al. — *Virtue Is Knowledge: Trust as a Substrate for Agent Cooperation* (2026) | Concurrent academic framing of trust-as-substrate; complements PACT's implementation-grounded case study |

## License

MIT
