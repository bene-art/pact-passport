# PACT Passport

**The agent ID.**

[![Tests](https://github.com/bene-art/pact-passport/actions/workflows/test.yml/badge.svg)](https://github.com/bene-art/pact-passport/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/pact-passport)](https://pypi.org/project/pact-passport/)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Self-certifying identity, holder-bound capabilities, and unilateral audit receipts for agent-to-agent systems. Three message types — REQ, RES, RES_CHUNK. Everything else is built at the edges.

> **Status: v0.6.1** — three-tier trust gradient (passport / visa / refusal) shipped on top of the v0.5 capability layer. Spec v1.1 → v1.3 codifies the wire changes. Bugs 1–10 from the v0.1 case-study battery + paper-revision experiments closed at the reference-implementation level; cross-machine Stage 2 runs pending.
>
> - V-tier visa machinery + emit-only `protocol_advertisement` field (PACT itself never reads or acts on a received advertisement — see spec §16.5).
> - Bugs 6 / 7 / 8 / 9 closed in v0.6.0; Bug 10 (Windows-only gap in the Bug 7 stream-partition fix) closed in v0.6.1 after the CI matrix caught it on the v0.6.0 release push.
> - 282 tests passing across macOS / Linux / Windows (CI matrix green; some POSIX-only tests skipped on Windows).
> - Stage 2 adversarial probe harness (25 pre-registered probes) ready for cross-machine runs.
> - Full case-study details in [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md) Part 2.

> **Breaking changes (v0.5.2 → v0.6):** see [CHANGELOG.md](CHANGELOG.md) for the full v0.2 → v0.5.1 history.
> - `build_req(cap_envelope=...)` without an explicit `cap_id` now auto-derives `cap_id` from the envelope, or raises `ValueError` if the envelope lacks one (v0.5.2; was silent pass).
> - REQs with deadlines further than `max_deadline_seconds` (default 3600s) in the future are rejected with new fault code `deadline_too_far` (v0.5.2; bump the constructor arg for long-running streaming intents).
> - `DelegationLink` gains required-from-v1.3 `action_at_step` + `caveats_at_step` fields; pre-v1.3 chains verify at K=2 only with `DeprecationWarning`. v1.4 will drop pre-v1.3 support — re-issue long-lived multi-hop capabilities before then (v0.6.0, Bug 9 / spec §16.1).
> - `cancelled` receipt outcome emits on streaming partition; downstream code assuming `{completed, failed}` only must add a `cancelled` branch (v0.6.0, #30 / Bug 7).

## Overview

PACT Passport is a Python implementation of a minimal trust substrate for agent-to-agent interaction. It sits below orchestration protocols like MCP and A2A as the layer that answers *who is this agent, what can they do, and what did they do*. Three primitives — self-certifying identity, holder-bound capability tokens, signed messages — plus unilateral audit receipts. No central authority, no shared secrets, no registry.

The reference implementation is ~4,600 LOC in `src/pact/`. The wire protocol is specified in [`spec/PACT_v1.md`](spec/PACT_v1.md) — sufficient for independent implementations. Deterministic test vectors at [`tests/vectors/pact_v1_vectors.json`](tests/vectors/pact_v1_vectors.json).

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
| Audit | Each side writes its own signed receipt unilaterally. `outcome ∈ {completed, failed, cancelled}` including stream partition. |
| Trust gradient | Three tiers: passport (full identity), visa (session-scoped attenuated capability for passport-less peers), refusal (opaque, no information leak). v0.6+. |

### Primitives

| Primitive | What it is | Source |
|---|---|---|
| **Identity** | Ed25519 keypair with self-certifying `agent_id` derived from the pubkey, plus a `next_key_digest` commitment for KERI-style rotation. | `src/pact/identity.py` |
| **Capability** | Signed, holder-bound token. Caveats append-only; verifier re-derives action + caveats at each chain step (Macaroons-style). Multi-hop delegation at any depth verifies inline via `cap_envelope`. | `src/pact/capability.py` |
| **Visa** | Session-scoped, attenuated capability bound to an ephemeral key. Issued by a gatekeeper to a passport-less counterparty; binds the *session*, not the *identity*. | `src/pact/visa.py` |
| **Message** | `REQ` / `RES` / `RES_CHUNK` (streaming). Mandatory `deadline` + `idempotency_key`. `refs[]` carries sender-asserted causal back-references. | `src/pact/message.py` |
| **Receipt** | Each side writes its own signed receipt unilaterally — no coordination required. Both receipts share `task_ref`, so the pair reconstructs a bilateral trace post-hoc. `outcome ∈ {completed, failed, cancelled}`. | `src/pact/receipt.py` |

### Non-goals

- **Cross-organization capability chains.** v0.6 enforces strict `issuer must be self`. Cross-org via a `trusted_issuers` set is post-v0.7.
- **Application-level caveat enforcement.** Caveats validate structurally at issue/attenuate; handler-side enforcement is post-v0.7.
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
crypto.py                All PyNaCl in one file (post-quantum swap = one file change)
identity.py              Ed25519 identity, agent_id, key event log, rotation
capability.py            Token issue, attenuate, verify, multi-hop delegation chains (Macaroons-style re-derivation)
visa.py                  V-tier visa machinery: issuance policy, holder-proof binding, peer-network-id rate limits
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

Last 3 releases below; see [CHANGELOG.md](CHANGELOG.md) for v0.1 → v0.5.3 history.

| Release | Feature | Status |
|---|---|---|
| v0.5.4 | Public-surface polish: README `agent_id` formula corrected, `[project.urls]` added to `pyproject.toml`, `SECURITY.md` added, `auto_grant` emits `DeprecationWarning` (scheduled for v1.0 removal). No wire changes. | Done |
| v0.6.0 | V-tier visa machinery + emit-only `protocol_advertisement` field + Bugs 6/7/8/9 closed (per-link `parent_cap_id` at K≥3, cancelled-receipt on stream partition, rate-limit cap_token binding, rogue-delegator chain re-derivation). Spec v1.1.0-draft → v1.3.0-draft. Stage 2 adversarial probe harness staged. **Wire changes — see breaking changes above.** | Done |
| v0.6.1 | Bug 10 fix: stream-partition transport handler now catches `ConnectionError` (parent class), covering `ConnectionAbortedError` (Windows WinError 10053) in addition to `BrokenPipeError` / `ConnectionResetError` (POSIX). Caught by CI matrix on the v0.6.0 release push. README polish + EXPERIMENTS.md Part 2 documenting Bugs 6–10. No wire changes. | Done |

## Tests

```bash
pip install -e ".[dev,cbor,fast]"
pytest -v
```

282 tests, 0 xfails. Coverage:

- **Cryptography, identity, key rotation, doctor validation** — Ed25519 round-trip, key event log, KERI pre-rotation, store-permission checks.
- **Capabilities** — issue, attenuate, verify, multi-hop chains at K ∈ {3, 5, 7, 10}, `cap_envelope`, append-only caveats, chain re-derivation (Macaroons-style).
- **Messages** — REQ / RES / RES_CHUNK, signing, deadline enforcement, idempotency, sender-asserted `refs[]`.
- **Receipts** — completed / failed / cancelled, including stream-partition cancellation across POSIX + Windows exception variants.
- **Transport** — HTTP, CBOR content negotiation, async (uvicorn), mDNS discovery, slow-loris read-timeout.
- **Integration** — two-agent + three-agent delegation, V-tier visa battery (V1–V7), `protocol_advertisement` no-consumption proof, deep-delegation regression.
- **Stress** — 5 race-conditions under concurrent dispatch, `PACT_CHAOS=1` chaos mode.
- **CLI smoke** — `init` / `identity` / `caps` / `grant` / `revoke` / `receipts` / `peers` / `doctor`.
- **End-to-end** — `PACTAgent.ask()` happy path / unknown target / failed-receipt-on-error.

Stage 2 adversarial probe harness (25 pre-registered probes) runs standalone, not under `pytest` — see [`tests/stage2/`](tests/stage2/).

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

## License

MIT
