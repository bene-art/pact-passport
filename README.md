# PACT — Protocol for Agent Capability and Trust

Two message types, holder-bound capabilities, and self-certifying identity. Everything else is built at the edges.

## What is PACT?

PACT is a minimal trust protocol for agent-to-agent interaction. It sits **below** orchestration protocols like MCP and A2A as the **trust substrate** — the layer where identity is self-certifying, authority is holder-bound and attenuable, ordering is causal, and failure is explicit.

### Three Primitives

1. **Agent Identity** — Ed25519 keypair with self-certifying agent ID and pre-rotation key commitment. Identity survives key rotation without a central registry.

2. **Capability Token** — Signed, holder-bound proof of authority. Caveats can only restrict, never expand. Stolen tokens are useless without the holder's private key.

3. **Message** — Two types: REQ (request with capability proof) and RES (result or error). Message references form a causal DAG. Deadlines and idempotency keys are mandatory.

Plus: **unilateral audit receipts** — each agent signs their own view, no cooperation required.

## Install

```bash
pip install pact-protocol
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

## Architecture

```
crypto.py           All PyNaCl in one file (post-quantum swap = one file change)
identity.py         Ed25519 identity, agent_id derivation, key event log
capability.py       Token issue, holder-bind, verify, caveats
message.py          REQ/RES builder, signer, verifier
receipt.py          Unilateral signed audit receipts
store.py            Filesystem storage (~/.pact/)
transport/
  server.py         HTTP server (single POST endpoint)
  client.py         HTTP client
  discovery.py      mDNS via zeroconf
agent.py            PACTAgent high-level API
cli.py              `pact` command
```

## Tests

```bash
pip install -e ".[dev]"
pytest -v
```

46 tests covering crypto, identity, capabilities, messages, receipts, storage, HTTP transport, and a full two-agent integration test.

## Specification

Full protocol specification: [docs/PACT_Specification.md](docs/PACT_Specification.md)

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
