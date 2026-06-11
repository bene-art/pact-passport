# PACT Passport

**The agent ID.**

[![Tests](https://github.com/bene-art/pact-passport/actions/workflows/test.yml/badge.svg)](https://github.com/bene-art/pact-passport/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/pact-passport)](https://pypi.org/project/pact-passport/)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Self-certifying identity, holder-bound capabilities, and unilateral audit receipts for agent-to-agent systems. Three message types — REQ, RES, RES_CHUNK. Everything else is built at the edges.

> **Status:** v0.6.0 — V-tier visa machinery (request-visa / grant / refusal as a three-tier trust gradient above v0.5 capabilities), emit-only `protocol_advertisement` field as the smallest substrate-discovery primitive (MUST-NOT consume, enforced architecturally + tested empirically), and Bugs 6/7/8/9 closed from C-tier cluster testing (per-link `parent_cap_id` for K≥3 chain verification, cancelled-receipt on stream partition, rate-limit cap_token binding, rogue-delegator chain re-derivation). Spec v1.1.0-draft → v1.3.0-draft codifies the wire changes. All Bugs 1–9 from the v0.1 case-study battery closed at the reference-implementation level; cross-machine validation pending Stage 2 runs. 281 tests passing locally (macOS); Linux + Windows pending CI on push. v0.6.0 also subsumes the planned v0.5.5 scope (install-string fix, CHANGELOG/CONTRIBUTING/templates, CLI smoke tests, ruff lint pass). Stage 2 adversarial probe harness (25 pre-registered probes) staged for cross-machine NUC-bridge runs.

> **Breaking changes from v0.1 → v0.5:**
> - `holder_proof` is mandatory when `cap_id` is present (v0.2.0, issue #3)
> - REQs from unknown peers are rejected unless they include `identity_doc` for trust-on-first-use (v0.2.0, issue #2)
> - `verify_capability` fails closed when delegation chain keys are missing (v0.2.0, issue #8)
> - `cap_id` claimed without local cap or `cap_envelope` is rejected explicitly instead of silently falling through (v0.4.0, issue #10)
> - `auto_grant` constructor parameter is now a no-op (v0.5.1) — was always dead code, kept for back-compat
> - `build_req(cap_envelope=...)` without an explicit `cap_id` now auto-derives `cap_id` from the envelope, or raises `ValueError` if the envelope lacks one. Previously the envelope was silently transported without verification (v0.5.2)
> - REQs with deadlines further than `max_deadline_seconds` (default 3600s) in the future are rejected with new fault code `deadline_too_far`. Bump the constructor arg for long-running streaming intents (v0.5.2)
> - DelegationLink gains required-from-v1.3 `action_at_step` + `caveats_at_step` fields; pre-v1.3 chains verify with `DeprecationWarning` at K=2 only. v1.4 will drop pre-v1.3 support. Re-issue long-lived multi-hop capabilities before v1.4 (v0.6.0, Bug 9 / spec §16.1)
> - `cancelled` receipt outcome emits on streaming partition; previously specified in spec §12.9 but never written. Downstream code assuming `{completed, failed}` only must add a `cancelled` branch (v0.6.0, #30 / Bug 7)

## Overview

PACT Passport is a Python implementation of a minimal trust substrate for agent-to-agent interaction. It sits below orchestration protocols like MCP and A2A as the layer that answers *who is this agent, what can they do, and what did they do*. Three primitives — self-certifying identity, holder-bound capability tokens, signed messages — plus unilateral audit receipts. No central authority, no shared secrets, no registry.

The reference implementation is ~3,750 LOC in `src/pact/`. The wire protocol is specified in [`spec/PACT_v1.md`](spec/PACT_v1.md) — sufficient for independent implementations. Deterministic test vectors at [`tests/vectors/pact_v1_vectors.json`](tests/vectors/pact_v1_vectors.json).

### Guarantees

| Property | Mechanism |
|---|---|
| Authenticity | Every message + receipt signed Ed25519 (PyNaCl). `verify_message` is fail-closed on malformed input. |
| Identity | `agent_id = sha256(alg \|\| base64(pubkey))`. Self-certifying; no CA. |
| Key rotation | KERI-style pre-rotation via `next_key_digest`. First post-rotation message proves continuity. |
| Authorization | Holder-bound capability tokens with append-only caveat chain. Stolen tokens require the holder's private key to present (`holder_proof`). |
| Replay safety | Mandatory `idempotency_key` per REQ. Durable cache survives process restart. |
| Causal ordering | `refs[]` field forms a DAG over message history. |
| Liveness | Mandatory `deadline` with server-side enforcement and configurable upper bound (default 3600s). |
| Audit | Bilateral signed receipts written for every dispatch — `outcome ∈ {completed, failed, cancelled}` including stream partition. |

### Primitives

| Primitive | What it is | Source |
|---|---|---|
| **Identity** | Ed25519 keypair with self-certifying `agent_id` derived from the pubkey, plus a `next_key_digest` commitment for KERI-style rotation. | `src/pact/identity.py` |
| **Capability** | Signed, holder-bound token. Caveats append-only; chain verifies fail-closed. Three-agent delegation works inline via `cap_envelope`. | `src/pact/capability.py` |
| **Message** | `REQ` / `RES` / `RES_CHUNK` (streaming). Mandatory `deadline` + `idempotency_key`. `refs[]` forms causal DAG. | `src/pact/message.py` |
| **Receipt** | Unilateral signed record of every dispatch. `outcome` ∈ {`completed`, `failed`, `cancelled`}. Bilateral receipts share `task_ref` for cross-machine trace reconstruction. | `src/pact/receipt.py` |

### Non-goals

- **Cross-organization capability chains.** v0.5 enforces strict `issuer must be self`. Cross-org via a `trusted_issuers` set is post-v0.6.
- **Application-level caveat enforcement.** Caveats validate structurally at issue/attenuate; handler-side enforcement is post-v0.6.
- **Cross-machine revocation propagation.** Issuer-local only — no CRL, no push-REVOKE.
- **Post-quantum signatures.** Ed25519 throughout. `crypto.py` is a single-file seam for the eventual migration.
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

The Python module is `pact` regardless of the distribution name — `from pact import PACTAgent` works either way.

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
from pact import PACTAgent

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
| `pact serve` | Start HTTP server + mDNS broadcast |
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
crypto.py                All PyNaCl in one file (post-quantum swap = one file change)
identity.py              Ed25519 identity, agent_id, key event log, rotation
capability.py            Token issue, attenuate, verify, delegation chains
message.py               REQ/RES builder, signer, verifier
receipt.py               Unilateral signed audit receipts
store.py                 Filesystem storage (~/.pact/)
transport/
  server.py              HTTP server with CBOR content negotiation
  async_server.py        Optional async server via uvicorn
  client.py              HTTP client with CBOR support
  discovery.py           mDNS via zeroconf
agent.py                 PACTAgent high-level API
cli.py                   `pact` command (13 subcommands)
contrib/
  lak_channel.py         local-agent-kit integration
```

## Features by Release

| Release | Feature | Status |
|---|---|---|
| v0.1 | Identity, capabilities, REQ/RES, receipts, mDNS, CLI, formal spec, test vectors | Done |
| v0.2.0 | Auth-bypass-by-default closed: TOFU handshake (`identity_doc`), mandatory holder-proof, fail-closed chain verification | Done |
| v0.2.1 | Request size limit + read timeout (slow-loris defense), Windows compat, dispatch decomposition (pipeline of validators) | Done |
| v0.3.0 | Durable idempotency cache + invocation counts (per-agent JSON, LRU bound) | Done |
| v0.3.1 | Rotation peer refresh via KERI continuity check | Done |
| v0.4.0 | Cap envelope inline (`cap_envelope`) — three-agent delegation works end-to-end over the wire | Done |
| v0.5.0 | Streaming RES_CHUNK responses (NDJSON over chunked transfer encoding) | Done |
| v0.5.1 | Polish: docs, exports, async-server parity, CI matrix | Done |
| v0.5.2 | Honesty patch: signed `outcome=failed` receipts (E1), `HandlerFailure` for explicit failure signaling (E2), `cap_envelope` foot-gun closed (E11), server-side `max_deadline_seconds` ceiling (E7). All four gaps surfaced by cluster testing. | Done |
| v0.5.3 | Input-validation patch: negative `Content-Length` DoS closed (F1), malformed base64 in signature/holder-proof/receipt fails closed (F2), `max_invocations`/`expires` caveat values validated at issue/attenuate (F3), streaming write-order race fixed (F4), TOFU rejects malformed pubkey base64 (F5). | Done |
| v0.5.4 | Public-surface polish: README `agent_id` formula corrected (`sha256(alg \|\| base64(pubkey))` to match `spec/PACT_v1.md`), `[project.urls]` added to `pyproject.toml` (Homepage / Source / Issues / Documentation / Changelog / Security policy now visible on PyPI), `SECURITY.md` added with private vulnerability reporting via GitHub advisories, `auto_grant` constructor argument now emits `DeprecationWarning` when explicitly passed (scheduled for removal in v1.0). No wire changes. | Done |
| v0.5.5 | Source-tree polish + bug fix. Stale `pact-protocol` package name replaced with `pact-passport` in 10 places — including 3 user-facing `ImportError` messages that previously told users to run an install command for a squatted package name. Ruff lint pass: 56 findings closed (modernized imports, exception chaining, removed dead `CBOR_CONTENT_TYPE` import). Spec revised to `v1.1.0-draft` with normative supersession of §1–§11 by §12 (new §10 conformance checklist, new §13 line-item change summary). Repo hygiene: `CHANGELOG.md`, `CONTRIBUTING.md`, GitHub issue + PR templates. CLI smoke tests + `agent.ask()` end-to-end tests added (164 → 181 tests; cli.py 0% → 41%; agent.py 77% → 83%). v0.6 deferred items now visible as GitHub issues #22–#27. No wire changes. Subsumed into v0.6.0; never released standalone. | Done |
| v0.6.0 | V-tier visa machinery (request-visa / grant / refusal as a three-tier trust gradient above v0.5 capabilities) + emit-only `protocol_advertisement` field (MUST-NOT consume, architecturally enforced) + Bugs 6/7/8/9 closed from C-tier cluster testing (per-link `parent_cap_id` for K≥3 chain verification, cancelled-receipt on stream partition, rate-limit cap_token binding, rogue-delegator chain re-derivation). Spec v1.1.0-draft → v1.3.0-draft codifies wire changes. Stage 2 adversarial probe harness (25 pre-registered probes) staged for cross-machine NUC-bridge runs. **Wire changes — see breaking changes above.** | Done |

## Tests

```bash
pip install -e ".[dev,cbor,fast]"
pytest -v
```

281 tests, 0 xfails covering: crypto, identity, capabilities, attenuation, messages, receipts, storage, HTTP transport, CBOR content negotiation, async server, key rotation, rate limiting, doctor validation, test vector verification, two-agent integration, three-agent delegation chain (over the wire), determinism, 5 race-condition scenarios under concurrent dispatch, the v0.2 auth hardening triangle, durable idempotency across restarts, rotation refresh, cap envelope verification, RES_CHUNK streaming, the v0.5.2 honesty-patch suite (signed-failed-receipts, HandlerFailure, cap_envelope auto-derive, deadline ceiling), the v0.5.3 input-validation suite (Content-Length sanitization, malformed-base64 fail-closed, caveat-value validation, streaming write-order, TOFU fault tolerance), CLI smoke (init/identity/caps/grant/revoke/receipts/peers/doctor), `PACTAgent.ask()` end-to-end (happy path / unknown target / failed-receipt-on-error), the v0.6.0 V-tier visa battery (V1–V7), `protocol_advertisement` no-consumption proof (6.4 load-bearing), B1 deep-chain attenuation (Bug 6), B3 deep-delegation regression, chain re-derivation (Bug 9), and stream-partition cancelled-receipt (Bug 7). Stage 2 adversarial probe harness (25 pre-registered probes) runs standalone, not under `pytest`.

### Platform support

| Platform | Status |
|---|---|
| **macOS** | 281 passed (v0.6.0 local) |
| **Linux** (CI + Alpine on WSL2) | pending CI on v0.6.0 push |
| **Windows 11** | pending CI on v0.6.0 push |

### Concurrency stress mode

Set `PACT_CHAOS=1` to inject random delays at race-prone code paths. Useful for catching idempotency / rate-limit races that would otherwise surface 1-in-1000:

```bash
PACT_CHAOS=1 pytest -v
```

## Specification

- **Concept document:** [docs/PACT_Specification.md](docs/PACT_Specification.md)
- **Formal v1 spec:** [spec/PACT_v1.md](spec/PACT_v1.md) — sufficient for independent implementation
- **Test vectors:** [tests/vectors/pact_v1_vectors.json](tests/vectors/pact_v1_vectors.json) — deterministic, reproducible
- **Case study (v0.1.3):** [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md) — what 23 stress experiments found, including 5 real bugs in this implementation

### Theoretical Foundations

| Paper | Contribution |
|-------|-------------|
| Saltzer, Reed, Clark — *End-to-End Arguments* (1984) | Push verification to agents, not transport |
| Waldo et al. — *A Note on Distributed Computing* (1994) | Failure is explicit, never abstracted away |
| Lamport — *Time, Clocks, and the Ordering of Events* (1978) | Causal ordering via message DAG |
| Birgisson et al. — *Macaroons* (2014) | Attenuable, context-bound capability tokens |
| Smith — *KERI* (2019) | Self-certifying identity with pre-rotation |
| Miller — *Robust Composition* (2006) | Capability discipline, no ambient authority |

## License

MIT
