# PACT — Protocol for Agent Capability and Trust (v3)

## Overview

PACT (Protocol for Agent Capability and Trust) is a proposed minimal communication layer that enables software agents to interact through **trusted, capability-scoped, and auditable exchanges of intent**.

It is not a replacement for the internet.
It is a **new layer on top of existing infrastructure**.

---

## Core Idea

> PACT enables agents to exchange **signed, capability-scoped intent** — where authority is attenuable, identity survives key rotation, ordering is causal, and failure is never hidden.

---

## Where PACT Fits (Internet Stack Evolution)

| Layer | Purpose |
|-------|---------|
| Physical | Wires, radio, signals |
| Network | TCP/IP (packet routing) |
| Application | HTTP (data exchange) |
| Identity | OAuth (access control) |
| **Intent (PACT)** | **Delegated action + trust between agents** |

---

## Problem Statement

Current systems allow:
- Data exchange (HTTP)
- Service access (APIs)
- Authentication (OAuth)

But they lack:
- Agent identity verification **with rotation and recovery**
- Capability discovery between systems
- Permission-scoped context sharing **with attenuation**
- Structured task negotiation **with explicit failure semantics**
- Verifiable interaction records **with causal ordering**

---

## Goal

Design a **minimal, open, composable protocol** that allows:

- Agents to prove identity **via self-certifying key event logs**
- Agents to declare capabilities
- Agents to exchange tasks within explicit permission **that can be narrowed but never widened**
- Agents to share minimal necessary context
- Agents to produce verifiable receipts **with causal ordering**
- Agents to **handle partial failure as a first-class concern**

---

## Non-Goals

PACT does **not**:
- Replace TCP/IP or HTTP
- Define AI reasoning
- Require a central authority
- Enforce a global identity system
- Act as a platform or product
- Guarantee delivery — that is the transport's job
- Make distribution transparent — remote interaction is fundamentally different from local

---

## Core Principles

1. **Ownership First**
   Agents act on behalf of a defined owner.

2. **Explicit Identity**
   Every interaction is verifiable. Identity is not a static key — it is a verifiable log of key events.

3. **Minimal Disclosure**
   Only required data is shared.

4. **Capability as Sole Authority**
   Access is granted by possession of a valid capability token, not by identity checks against an access control list. If you hold a valid capability, you can act. If you don't, you can't. There is no ambient authority.

5. **Scoped Consent via Attenuation**
   Permissions are:
   - specific
   - time-limited
   - revocable
   - **attenuable** — a recipient can delegate a narrower subset, never a wider one
   - **context-bound** — caveats can restrict use to specific conditions

6. **End-to-End Verification**
   Verification, authorization, and ordering are agent-level concerns. The transport layer moves bytes — it does not enforce protocol correctness.

7. **Distribution is Not Transparent**
   Remote agent interaction is fundamentally different from local interaction. Latency, partial failure, and lack of shared memory are not edge cases — they are the norm. PACT does not abstract these away; it makes them explicit.

8. **Transport Agnostic**
   Works over HTTP, WebSocket, P2P, or radio.

9. **Stateless Interaction, Stateful Audit**
   Interactions are simple; logs are durable.

10. **Composable Design**
    Each component is independent.

11. **No Central Dependency**
    No required registry or broker.

12. **Rebuildable Simplicity**
    One engineer should be able to implement the core from scratch.

---

## Core Primitives (exactly 3)

### 1. Agent Identity

An agent is a **self-certifying identifier** bound to a cryptographic key.

```
agent_id = hash(algorithm_id + inception_public_key)
```

**Crypto-agility is mandatory.** Every signature and key reference carries an `alg` field. The protocol does not specify which algorithms — it specifies that the algorithm is always declared.

```json
{
  "agent_id": "sha256:abc123...",
  "alg": "Ed25519",
  "public_key": "...",
  "next_key_digest": "sha256:def456..."
}
```

**Key rotation** uses pre-rotation: the digest of the next key is committed before it is needed. A compromised current key cannot forge a rotation because the next key was committed in a prior event.

**Key Event Log:**
```json
{
  "agent_id": "sha256:abc123...",
  "event_type": "inception",
  "sequence": 0,
  "current_keys": ["key_0_pub"],
  "next_keys_digest": "hash(key_1_pub)",
  "alg": "Ed25519",
  "signature": "signed_by_key_0"
}
```

**Rotation Event:**
```json
{
  "agent_id": "sha256:abc123...",
  "event_type": "rotation",
  "sequence": 1,
  "prior_event_digest": "hash(event_0)",
  "current_keys": ["key_1_pub"],
  "next_keys_digest": "hash(key_2_pub)",
  "alg": "Ed25519",
  "signature": "signed_by_key_1"
}
```

**Why this matters:**
- `agent_id` is stable across key rotations — an agent's identity survives compromise recovery
- Pre-rotation prevents a compromised key from hijacking the identity
- No blockchain or central registry needed — the event log is self-verifying
- Revocation = rotation to a null key

**Key storage assumption:** private keys live in hardware (TEE, HSM, Secure Enclave) by default. The protocol never transmits private key material.

**Hardware attestation (optional, first-class):**
```json
{
  "agent_id": "sha256:abc123...",
  "attestation": {
    "type": "tee",
    "platform": "arm-cca",
    "measurement": "hash_of_enclave_code",
    "certificate_chain": ["..."]
  }
}
```

This answers trust bootstrapping without a central authority: "I don't just know *who* signed this — I know *what environment* produced it."

---

### 2. Capability Token

A capability is **a signed, attenuable, holder-bound proof of authority**. Possession of the token IS the authorization.

**Root capability (issued by the authorizing agent):**
```json
{
  "cap_id": "c-001",
  "issuer": "sha256:abc123...",
  "holder": "sha256:def456...",
  "action": "schedule_meeting",
  "caveats": [
    {"restrict": "expires", "value": "2026-05-01T00:00:00Z"}
  ],
  "alg": "Ed25519",
  "signature": "..."
}
```

**Attenuated capability (delegated with restrictions):**
```json
{
  "cap_id": "c-001-sub",
  "parent": "c-001",
  "issuer": "sha256:def456...",
  "holder": "sha256:ghi789...",
  "action": "schedule_meeting",
  "caveats": [
    {"restrict": "expires", "value": "2026-05-01T00:00:00Z"},
    {"restrict": "max_invocations", "value": 3},
    {"restrict": "no_further_delegation", "terminal": true}
  ],
  "delegation_chain": [
    {"from": "sha256:abc123...", "sig": "..."},
    {"from": "sha256:def456...", "sig": "..."}
  ],
  "alg": "Ed25519",
  "signature": "..."
}
```

**Key properties:**
- **Asymmetric signatures, not HMAC** — the issuer signs with their private key; anyone can verify with the issuer's public key. No shared secrets. No issuer-must-be-online problem.
- **Holder-bound** — the `holder` field binds the capability to a specific agent. The holder must prove possession of their key when presenting. Stolen tokens are useless without the holder's private key.
- **Attenuation only** — caveats can only be appended. The effective permission is the AND of all caveats. You can only narrow, never widen.
- **Resource-accountable** — `max_invocations` is a first-class caveat type, preventing unlimited request flooding.

---

### 3. Message

**Two message types. That's it.**

| Type | Direction | Purpose |
|------|-----------|---------|
| **REQ** | A → B | Request with capability proof |
| **RES** | B → A | Result, error, or redirect |

Everything else is a payload within REQ/RES:

| Concept | v3 Equivalent |
|---------|---------------|
| Identity exchange | REQ with `intent: "identity"` |
| Capability discovery | REQ/RES with `intent: "discover"` |
| Capability issuance | RES containing a capability token |
| Task request | REQ with `intent: "task"` |
| Task result | RES with `status: "ok"` |
| Failure | RES with `status: "error"` |
| Audit | Unilateral — see Audit section |

**Message structure:**
```json
{
  "id": "m-003",
  "type": "REQ",
  "from": "sha256:abc123...",
  "to": "sha256:def456...",
  "refs": ["m-001", "m-002"],
  "intent": "task",
  "cap_id": "c-001",
  "holder_proof": "signature_proving_holder_identity",
  "deadline": "2026-04-30T12:00:00Z",
  "idempotency_key": "ik-abc-001",
  "payload": { "...": "..." },
  "alg": "Ed25519",
  "signature": "..."
}
```

**Design decisions:**

- **`refs` provides causal ordering.** Each message references the messages it depends on. The message graph IS the ordering — no logical clocks, no synchronized wall clocks. Any observer can reconstruct causality by traversing the DAG.
- **`deadline` is mandatory on REQ.** After deadline, the outcome is indeterminate. The protocol does not pretend otherwise.
- **`idempotency_key` is mandatory on REQ.** Retries with the same key produce the same effect. This is the agent's responsibility — the protocol declares the contract.
- **`holder_proof`** — the agent presenting a capability signs a challenge (the message ID) with their private key. Intercepted messages can't be replayed because the proof is message-specific.
- **Encoding:** canonical wire format is **CBOR** (compact, binary, schema-friendly for constrained devices). JSON is a valid serialization for debugging and human readability.

**Error responses carry structured fault information:**
```json
{
  "id": "m-004",
  "type": "RES",
  "from": "sha256:def456...",
  "to": "sha256:abc123...",
  "refs": ["m-003"],
  "status": "error",
  "fault": {
    "code": "capability_expired",
    "detail": "cap_id c-001 expired at 2026-05-01T00:00:00Z"
  },
  "alg": "Ed25519",
  "signature": "..."
}
```

**Failure semantics are explicit.** When Agent A sends REQ to Agent B, four outcomes are possible:

| Outcome | What happened | What A knows |
|---------|---------------|--------------|
| Success | B completed, A received RES | Full knowledge |
| Declared failure | B could not complete, sent error RES | Full knowledge |
| Timeout | No response within deadline | **Ambiguous** — B may have acted |
| Partial failure | B acted, RES lost in transit | **Ambiguous** — A doesn't know |

PACT does not hide ambiguity. Timeout means indeterminate. Idempotency keys enable safe retries.

---

## Identity / Location Separation

An agent's identity is permanent. Its network address is not.

**Identity document (long-lived, follows the agent):**
```json
{
  "agent_id": "sha256:abc123...",
  "alg": "Ed25519",
  "public_key": "...",
  "next_key_digest": "sha256:def456...",
  "attestation": { "...": "..." }
}
```

**Service endpoint (ephemeral, changes with deployment):**
```json
{
  "agent_id": "sha256:abc123...",
  "endpoints": [
    {"transport": "https", "uri": "https://agent.example/pact"},
    {"transport": "wss", "uri": "wss://agent.example/pact"}
  ],
  "capabilities": ["schedule_meeting"],
  "ttl": 3600
}
```

An agent can move between hosts, change transports, go offline and return — its identity is stable. Discovery of endpoints is out-of-band (DNS-like resolution, DHT, gossip, manual configuration). The protocol doesn't prescribe it because the right answer depends on the deployment context.

---

## Audit (Unilateral Receipts)

Each agent signs its own view. No cooperation required.

```json
{
  "type": "receipt",
  "agent": "sha256:abc123...",
  "task_ref": "m-003",
  "refs": ["m-003", "m-004"],
  "outcome": "completed",
  "alg": "Ed25519",
  "signature": "..."
}
```

If both parties publish receipts, a third party can compare them. Discrepancies are evidence. If one party refuses, the other party's signed receipt still stands as a unilateral claim.

Agents MAY exchange receipts and co-sign for stronger guarantees. But the protocol does not require it.

---

## Semantic Interoperability

Capabilities are opaque strings. The protocol carries the contract — it does not define the language.

Interop happens through:
1. **Shared schemas** — agents that want to interoperate agree on payload schemas out-of-band
2. **Capability namespacing** — `org.example.schedule_meeting` avoids collisions
3. **Discovery negotiation** — a REQ with `intent: "discover"` returns the agent's capability schemas, not just names

---

## Post-Quantum Migration Path

The `alg` field on every signature is the migration mechanism.

| Phase | Algorithms |
|-------|-----------|
| Now | `Ed25519` or `ECDSA-P256` |
| Transition | Hybrid: `Ed25519 + ML-DSA-65` (both signatures present) |
| Post-quantum | `ML-DSA-65` or `SLH-DSA-128s` alone |

No protocol version bump needed. No flag day. Agents upgrade independently because the algorithm is self-describing.

---

## Minimal Interaction Flow

```
A → B : REQ  intent:"identity"     (who are you?)
B → A : RES  (identity document)
A → B : REQ  intent:"discover"     (what can you do?)
B → A : RES  (capability list + schemas)
A → B : REQ  intent:"task" + cap   (do this, here's my authority)
B → A : RES  (result or error)
A, B  : receipt                    (each signs their own view)
```

Agents that already know each other skip straight to the task REQ.

---

## Key Insight

PACT is not just about communication.

It is about:

> **structured, constrained, and accountable interaction between autonomous systems** — where authority is proven by possession, identity survives key rotation, causality replaces timestamps, and failure is never silent.

---

## Technical Domains Involved

- Distributed systems (message passing, **partial failure, causal ordering**)
- Cryptography (signatures, identity, **key pre-rotation, crypto-agility**)
- Security (authorization, revocation, **capability discipline, confused deputy prevention**)
- Protocol design (minimal interfaces, **end-to-end arguments**)
- Multi-agent systems (coordination)

---

## Transport Layer (Unchanged)

PACT runs on top of:
- HTTP / HTTPS
- WebSocket
- gRPC
- P2P / mesh
- radio (optional, not required)

The transport moves bytes. It does not verify identity, enforce authorization, order events, or guarantee delivery. Those are agent-level responsibilities.

---

## Key Challenges

| Challenge | Approach |
|-----------|----------|
| Trust bootstrapping (first contact) | Self-certifying key logs + optional hardware attestation |
| Key compromise recovery | Pre-rotation — next key committed before needed |
| Permission delegation chains | Asymmetric capability tokens with append-only caveats |
| Preventing privilege escalation | Capability discipline — no ambient authority |
| Causal ordering without shared clock | Message reference DAG |
| Partial failure and indeterminacy | Explicit deadlines + mandatory idempotency keys |
| Keeping the protocol minimal | Two message types; push complexity to the edges |
| Semantic interoperability | Opaque capabilities + out-of-band schema agreement |
| Post-quantum readiness | Mandatory `alg` field; hybrid signature migration path |

---

## Development Path

### Phase 1 — Proof
- Two agents with Ed25519 identity and pre-rotation commitment
- One holder-bound capability token
- REQ/RES over HTTPS with JSON encoding
- Deadline + idempotency semantics
- Unilateral receipts
- **Deliverable: working demo**

### Phase 2 — Delegation and Failure
- Capability attenuation chains (2-3 levels)
- Message DAG traversal for audit
- Retry handling with idempotency
- **Deliverable: multi-agent task completion with failure recovery**

### Phase 3 — Harden
- CBOR wire encoding
- Hardware-backed key storage (Secure Enclave / TEE)
- Hardware attestation
- Hybrid post-quantum signatures
- Rate limiting via `max_invocations` caveats
- **Deliverable: hardened reference implementation**

### Phase 4 — Specification
- Minimal open spec
- Test vectors
- Interop test suite
- **Deliverable: spec another engineer can implement independently**

---

## Success Criteria

Two independent implementations can:
- Establish identity without prior trust (self-certifying keys, optionally hardware-attested)
- Issue, attenuate, and verify holder-bound capabilities
- Complete a task via REQ/RES with deadline and idempotency
- Survive key rotation without losing identity
- Produce unilateral audit receipts a third party can verify
- Do all of this with post-quantum hybrid signatures

---

## Final Framing

PACT is:
- not a product
- not a platform
- not a framework

It is:

> a minimal primitive for **machine-level responsibility and interaction** — two message types, holder-bound capabilities, and self-certifying identity. Everything else is built at the edges.

---

## Theoretical Foundations

| Paper | Contribution to PACT |
|-------|--------------------|
| Saltzer, Reed, Clark — *End-to-End Arguments in System Design* (1984) | Push verification to the agents, not the transport |
| Waldo et al. — *A Note on Distributed Computing* (1994) | Failure is explicit, never abstracted away |
| Lamport — *Time, Clocks, and the Ordering of Events* (1978) | Causal ordering via message DAG, not wall clocks |
| Birgisson et al. — *Macaroons* (2014) | Attenuable, context-bound capability tokens |
| Smith — *KERI* (2019) | Self-certifying identity with pre-rotation |
| Miller — *Robust Composition* (2006) | Capability discipline, no ambient authority |

---

## One-Line Summary

> PACT is two message types, holder-bound capabilities, and self-certifying identity — everything else is built at the edges.
