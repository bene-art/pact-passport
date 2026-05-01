# PACT — Protocol for Agent Capability and Trust

[![Tests](https://github.com/bene-art/pact-protocol/actions/workflows/test.yml/badge.svg)](https://github.com/bene-art/pact-protocol/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/pact-protocol)](https://pypi.org/project/pact-protocol/)
[![Python](https://img.shields.io/pypi/pyversions/pact-protocol)](https://pypi.org/project/pact-protocol/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A v1 reference implementation of an agent-to-agent trust protocol. Two message types, holder-bound capabilities, and self-certifying identity. Everything else is built at the edges.

> **Status:** v0.1.3 reference implementation. The protocol design is stable; known security and durability gaps from this implementation are tracked in [open issues](https://github.com/bene-art/pact-protocol/issues) for v0.2 hardening. Suitable for experimentation, learning, and as a starting point — not yet for production deployment without addressing the linked issues.

## What is PACT?

PACT is a minimal trust protocol for agent-to-agent interaction. It sits **below** orchestration protocols like MCP and A2A as the **trust substrate** — the layer where identity is self-certifying, authority is holder-bound and attenuable, ordering is causal, and failure is explicit.

### Three Primitives

1. **Agent Identity** — Ed25519 keypair with self-certifying agent ID and pre-rotation key commitment. Identity survives key rotation without a central registry.

2. **Capability Token** — Signed, holder-bound proof of authority with delegation chains. Caveats can only restrict, never expand. Stolen tokens are useless without the holder's private key.

3. **Message** — Two types: REQ (request with capability proof) and RES (result or error). Message references form a causal DAG. Deadlines and idempotency keys are mandatory.

Plus: **unilateral audit receipts** — each agent signs their own view, no cooperation required.

## Install

```bash
pip install pact-protocol
```

Optional extras:
```bash
pip install pact-protocol[cbor]    # CBOR encoding support
pip install pact-protocol[fast]    # Async uvicorn server
pip install pact-protocol[lak]     # local-agent-kit integration
```

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

## Features by Phase

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | Identity, capabilities, REQ/RES, receipts, mDNS, CLI | Done |
| 2 | Capability attenuation (A→B→C), explicit grants, idempotency, DAG traversal | Done |
| 3 | Key rotation, rate limiting (max_invocations), `pact doctor` | Done |
| 4 | Formal spec (`spec/PACT_v1.md`), deterministic test vectors, interop suite | Done |
| 5 | CBOR encoding, async uvicorn server, local-agent-kit integration | Done |

## Tests

```bash
pip install -e ".[dev,cbor,fast]"
pytest -v
```

118 tests + 1 documented xfail covering: crypto, identity, capabilities, attenuation, messages, receipts, storage, HTTP transport, CBOR content negotiation, async server, key rotation, rate limiting, doctor validation, test vector verification, two-agent integration, three-agent delegation chain, determinism, and 5 race-condition scenarios under concurrent dispatch.

### Platform support

| Platform | Status |
|---|---|
| **macOS** (Darwin) | 118 passed, 1 xfailed |
| **Linux** (Alpine on WSL2) | 118 passed, 1 xfailed |
| **Windows 11** | 114 passed, 4 skipped (POSIX-only checks), 1 xfailed |

The xfail tracks a known peer-cache-staleness bug after key rotation; see [#4](https://github.com/bene-art/pact-protocol/issues/4).

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
