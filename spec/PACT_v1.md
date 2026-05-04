# PACT v1 Specification

**Protocol for Agent Capability and Trust**
Version: 1.0.0-draft
Date: 2026-04-29

---

## 1. Overview

PACT is a minimal protocol enabling trusted, capability-scoped, auditable interaction between software agents. It defines three primitives: agent identity, capability tokens, and messages. All other features are built at the edges by implementations.

This document is sufficient for an independent implementation. Test vectors are provided in `tests/vectors/pact_v1_vectors.json`.

---

## 2. Conventions

- All byte strings are encoded as **base64** (standard, with padding) in JSON.
- All hashes use **SHA-256**, represented as `sha256:<64 hex chars>`.
- All signatures use **Ed25519** (RFC 8032).
- The algorithm identifier is the string `"Ed25519"`.
- All JSON serialized for signing uses **canonical form** (Section 3).
- Timestamps are **ISO 8601** with timezone (e.g., `2026-04-29T15:30:00+00:00`).

---

## 3. Canonical JSON

Before signing any JSON object, it MUST be serialized in canonical form:

1. Keys sorted lexicographically (Unicode code point order).
2. No whitespace between tokens (separators: `,` and `:`).
3. ASCII-safe (`ensure_ascii=true`).
4. UTF-8 encoded to bytes.

Example:
```
Input:  {"z": 1, "a": 2}
Output: {"a":2,"z":1}
Bytes:  7b2261223a322c227a223a317d
```

The `signature` field is ALWAYS excluded from the object before canonical serialization.

---

## 4. Agent Identity

### 4.1 Agent ID Derivation

```
agent_id = sha256(ALG + base64(inception_public_key))
```

Where:
- `ALG` = `"Ed25519"` (the literal string)
- `inception_public_key` = the 32-byte Ed25519 public key from the inception event
- `base64()` = standard base64 encoding with padding
- Concatenation is string concatenation before UTF-8 encoding

The agent_id is **permanent** — it does not change when keys are rotated.

### 4.2 Key Event Log

An agent's identity is a chronologically ordered log of key events.

#### Inception Event (sequence 0)

```json
{
  "agent_id": "sha256:...",
  "event_type": "inception",
  "sequence": 0,
  "current_keys": ["<base64 public key>"],
  "next_keys_digest": "sha256:...",
  "alg": "Ed25519",
  "signature": "<base64 signature>"
}
```

Fields:
- `agent_id`: Derived as in Section 4.1.
- `event_type`: `"inception"`.
- `sequence`: `0`.
- `current_keys`: Array of one base64-encoded public key.
- `next_keys_digest`: `sha256(<raw 32-byte next public key>)`. This is the **pre-rotation commitment**.
- `alg`: `"Ed25519"`.
- `signature`: Ed25519 signature of the canonical JSON of all fields except `signature`, signed with the inception private key.

#### Rotation Event (sequence > 0)

```json
{
  "agent_id": "sha256:...",
  "event_type": "rotation",
  "sequence": 1,
  "prior_event_digest": "sha256:...",
  "current_keys": ["<base64 new public key>"],
  "next_keys_digest": "sha256:...",
  "alg": "Ed25519",
  "signature": "<base64 signature>"
}
```

Fields:
- `prior_event_digest`: `sha256(canonical_json(previous_event without signature))`. Chains events.
- `current_keys`: The new public key. MUST match `next_keys_digest` from the previous event: `sha256(<raw 32-byte new public key>) == previous.next_keys_digest`.
- `next_keys_digest`: Commitment to the *next* rotation key.
- `signature`: Signed with the **new** key (the one listed in `current_keys`), proving possession of the pre-committed key.

#### Verification Rules

1. First event MUST be `inception` with `sequence: 0`.
2. Each subsequent event MUST have `event_type: "rotation"` and `sequence: N` where N is its position.
3. `prior_event_digest` MUST equal `sha256(canonical_json(events[N-1] without signature))`.
4. `sha256(base64_decode(current_keys[0]))` MUST equal `events[N-1].next_keys_digest`.
5. `signature` MUST verify against `current_keys[0]`.

### 4.3 Identity Document

The public identity document (shared with peers):

```json
{
  "agent_id": "sha256:...",
  "alg": "Ed25519",
  "public_key": "<base64 current public key>",
  "next_key_digest": "sha256:..."
}
```

### 4.4 Key Storage

Private keys MUST be stored with restrictive permissions (0o600 on POSIX systems). The protocol never transmits private key material.

---

## 5. Capability Tokens

### 5.1 Root Capability

```json
{
  "cap_id": "<uuid>",
  "issuer": "<agent_id of the resource owner>",
  "holder": "<agent_id of the authorized agent>",
  "action": "<string identifying the capability>",
  "caveats": [
    {"restrict": "expires", "value": "<ISO 8601 timestamp>"},
    {"restrict": "max_invocations", "value": 10}
  ],
  "alg": "Ed25519",
  "signature": "<base64>"
}
```

Fields:
- `cap_id`: UUID v4, unique identifier.
- `issuer`: agent_id of the entity granting the capability.
- `holder`: agent_id of the entity authorized to use it.
- `action`: Opaque string identifying what the holder can do.
- `caveats`: Array of restrictions (Section 5.3).
- `signature`: Ed25519 signature of canonical JSON (excluding `signature`), signed by the issuer.

### 5.2 Attenuated Capability (Delegation)

When a holder delegates to another agent with narrower permissions:

```json
{
  "cap_id": "<uuid>",
  "issuer": "<original root issuer agent_id>",
  "holder": "<new holder agent_id>",
  "action": "<same action as parent>",
  "caveats": ["<parent caveats> + <additional restrictions>"],
  "parent": "<cap_id of parent token>",
  "delegation_chain": [
    {"from": "<delegator agent_id>", "sig": "<base64>"}
  ],
  "alg": "Ed25519",
  "signature": "<base64>"
}
```

Fields:
- `issuer`: The **root** issuer, preserved through the chain.
- `parent`: cap_id of the parent token.
- `delegation_chain`: Array of links. Each link contains `from` (the delegator's agent_id) and `sig` (the delegator's Ed25519 signature of the parent's `cap_id` encoded as UTF-8).
- `signature`: Signed by the **delegator** (not the root issuer).

#### Attenuation Rules

1. Caveats are **append-only**. The child's caveats are the parent's caveats plus additional restrictions.
2. For `max_invocations`: new value MUST be ≤ minimum existing value.
3. For `expires`: new value MUST be ≤ minimum existing value.
4. If parent has `{"restrict": "no_further_delegation", "terminal": true}`, attenuation is REJECTED.
5. Only the current `holder` of the parent can attenuate.
6. The `action` MUST remain unchanged.

### 5.3 Caveat Types

| restrict | value type | semantics |
|----------|-----------|-----------|
| `expires` | ISO 8601 string | Token invalid after this time |
| `max_invocations` | integer | Maximum number of uses (effective = min of all) |
| `no_further_delegation` | boolean (with `terminal: true`) | Prevents further attenuation |

Implementations MAY define additional caveat types. Unknown caveats MUST be preserved during attenuation.

### 5.4 Verification Rules

1. If `revoked: true`, REJECT.
2. `holder` MUST match the presenting agent's agent_id.
3. For root tokens (no `delegation_chain`): `signature` MUST verify against the issuer's public key.
4. For attenuated tokens: `signature` MUST verify against the last delegator's public key. Each `delegation_chain` link's `sig` MUST verify against that link's `from` agent's public key, signing the `parent` cap_id.
5. All `expires` caveats MUST not be in the past.
6. Invocation count MUST not exceed the minimum of all `max_invocations` caveats.

---

## 6. Messages

### 6.1 Message Types

PACT has exactly **two** message types:

| Type | Direction | Purpose |
|------|-----------|---------|
| `REQ` | A → B | Request with capability proof |
| `RES` | B → A | Result, error, or information |

### 6.2 REQ Message

```json
{
  "id": "<uuid>",
  "type": "REQ",
  "from_agent": "<sender agent_id>",
  "to_agent": "<recipient agent_id>",
  "refs": ["<message IDs this depends on>"],
  "intent": "<string>",
  "cap_id": "<capability token ID>",
  "holder_proof": "<base64>",
  "deadline": "<ISO 8601>",
  "idempotency_key": "<uuid>",
  "payload": {},
  "alg": "Ed25519",
  "signature": "<base64>"
}
```

Fields:
- `id`: UUID v4, unique per message.
- `refs`: Message IDs this message causally depends on. Forms a DAG.
- `intent`: One of `"identity"`, `"discover"`, `"task"`, or implementation-defined strings.
- `cap_id`: (optional) The capability token authorizing this request.
- `holder_proof`: Ed25519 signature of the `id` field (as UTF-8 bytes), signed by the holder's private key. Binds the capability to this specific message — prevents replay.
- `deadline`: **MANDATORY**. After this time, the outcome is indeterminate.
- `idempotency_key`: **MANDATORY**. UUID v4. Retries with the same key MUST produce the same response.
- `signature`: Ed25519 signature of canonical JSON (excluding `signature`), signed by `from_agent`.

### 6.3 RES Message

```json
{
  "id": "<uuid>",
  "type": "RES",
  "from_agent": "<responder agent_id>",
  "to_agent": "<requester agent_id>",
  "refs": ["<REQ message ID>"],
  "intent": "<same as REQ>",
  "payload": {},
  "status": "ok",
  "alg": "Ed25519",
  "signature": "<base64>"
}
```

For errors:
```json
{
  "status": "error",
  "fault": {
    "code": "<error_code>",
    "detail": "<human-readable explanation>"
  }
}
```

#### Standard Fault Codes

| code | meaning |
|------|---------|
| `deadline_exceeded` | REQ deadline has passed |
| `capability_invalid` | Token verification failed |
| `capability_expired` | Token expiry caveat failed |
| `rate_limited` | max_invocations exceeded |
| `holder_proof_invalid` | Holder proof verification failed |
| `invalid_signature` | Message signature verification failed |
| `no_handler` | No handler registered for action |
| `unknown_intent` | Unrecognized intent |

### 6.4 Causal Ordering

Messages form a directed acyclic graph (DAG) via the `refs` field. A RES MUST include the REQ's `id` in its `refs`. This establishes happened-before ordering without synchronized clocks.

### 6.5 Failure Semantics

| Outcome | What A knows |
|---------|--------------|
| RES received with `status: "ok"` | Task completed |
| RES received with `status: "error"` | Task failed (known reason) |
| No RES before deadline | **Indeterminate** — B may or may not have acted |
| RES lost in transit | **Indeterminate** — A doesn't know |

The protocol does not hide ambiguity. Idempotency keys enable safe retries.

---

## 7. Receipts

Each agent signs their own view. No cooperation required.

```json
{
  "type": "receipt",
  "agent": "<signer's agent_id>",
  "task_ref": "<REQ message ID>",
  "refs": ["<all message IDs in this interaction>"],
  "outcome": "completed",
  "timestamp": "<ISO 8601>",
  "alg": "Ed25519",
  "signature": "<base64>"
}
```

- `outcome`: One of `"completed"`, `"failed"`, `"timeout"`.
- `signature`: Ed25519 signature of canonical JSON (excluding `signature`).

If both parties publish receipts, a third party can compare them. Discrepancies are evidence.

---

## 8. Transport

### 8.1 HTTP Binding

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/pact/v1/message` | All PACT messages |
| GET | `/pact/v1/health` | Health check |
| GET | `/pact/v1/identity` | Public identity document |

All protocol responses use HTTP 200. The `status` field inside the body carries the protocol-level outcome. HTTP 4xx/5xx is reserved for transport failures.

Content-Type: `application/json` (v1). Future versions MAY support `application/cbor`.

### 8.2 mDNS Discovery

Service type: `_pact._tcp.local.` (RFC 6763)

TXT records:
- `agent_id`: Full agent_id string
- `caps`: Comma-separated capability action names
- `v`: Protocol version (`"1"`)

---

## 9. Security Considerations

- **Private keys** MUST NOT be transmitted. Store with 0o600 permissions.
- **Holder proof** binds capability use to a specific message, preventing replay.
- **Pre-rotation** prevents a compromised current key from hijacking identity.
- **Attenuation** is append-only — a delegatee can never gain more authority than the delegator.
- **No ambient authority** — capabilities are the sole source of authorization.
- **Canonical JSON** prevents signature mismatch from non-deterministic serialization.
- **Deadlines** prevent indefinite resource consumption from abandoned requests.

---

## 10. Interoperability

An implementation is PACT v1 compatible if it can:

1. Derive `agent_id` from a known public key and produce the expected value.
2. Serialize JSON canonically and produce identical bytes.
3. Sign and verify Ed25519 signatures.
4. Issue and verify capability tokens (including attenuation chains).
5. Build and verify REQ/RES messages with holder proofs.
6. Produce and verify unilateral receipts.

All of the above are testable against the provided test vectors.

---

## 11. Test Vectors

Test vectors are provided in `tests/vectors/pact_v1_vectors.json`. They include:

- Known keypairs (deterministic seeds)
- Agent ID derivation
- Canonical JSON serialization
- Ed25519 signatures
- Inception events
- Capability tokens
- REQ and RES messages with holder proofs
- Receipts

---

## 12. v0.2 — v0.5 Addendum (the parts §1–§11 don't describe)

Sections 1–11 above were frozen at v0.1 and represent the original
protocol design. Releases v0.2 through v0.5 added the fields and rules
below. The reference implementation is the source of truth; this
addendum exists so an alternate implementer doesn't have to read
agent.py to know what they're missing.

### 12.1 Three message types (§6.1 update)

PACT now has **three** message types: `REQ`, `RES`, and `RES_CHUNK`.

`RES_CHUNK` is the streaming response variant. A REQ with `stream: true`
expects a sequence of one or more `RES_CHUNK` messages instead of a
single `RES`. Each chunk is a fully-formed signed PACTMessage.

### 12.2 New REQ fields (§6.2 update)

| Field | Type | When to include | Purpose |
|---|---|---|---|
| `identity_doc` | object | First contact OR after rotation | Trust-on-first-use OR rotation-continuity refresh |
| `cap_envelope` | object | When the receiver may not have the cap locally | Inline cap dict for cross-machine delegation |
| `stream` | bool | When the client wants a streaming response | Opt-in to RES_CHUNK sequence |

**Mandatory rule (v0.2.0):** when `cap_id` is present, `holder_proof`
MUST also be present and verify against the sender's pubkey. Receivers
MUST reject with fault code `holder_proof_required` otherwise.

**Trust-on-first-use (v0.2.0):** when the receiver does not have the
sender in its peer cache AND `identity_doc` is present, the receiver
MUST verify that `agent_id == sha256(alg || base64(public_key))` from
the doc. If valid, the doc is cached and the message signature is
verified against the doc's pubkey. If absent or invalid, the receiver
MUST reject with `unknown_peer`.

**Rotation continuity (v0.3.1):** when an established peer rotates
keys, the first post-rotation REQ should include the fresh
`identity_doc`. The receiver detects signature failure, then verifies
`hash(new_doc.public_key) == cached_doc.next_key_digest`. If the
continuity proof holds, the cache is refreshed and verification
retries against the new pubkey. If it fails, treated as attack.

### 12.3 RES_CHUNK schema (§6.3 update)

```
{
  "id":          "<uuid>",
  "type":        "RES_CHUNK",
  "from_agent":  "<server_agent_id>",
  "to_agent":    "<client_agent_id>",
  "refs":        ["<original_REQ_id>"],
  "intent":      "task",
  "payload":     { ... },        // chunk content
  "chunk_seq":   <int>,          // monotonic, starts at 0
  "chunk_final": <bool>,         // true on terminal chunk only
  "alg":         "Ed25519",
  "signature":   "<base64>"
}
```

Each chunk is independently signed. Tampering with any field —
including `chunk_seq` or `chunk_final` — invalidates that chunk's
signature without affecting others. Receivers MUST verify each chunk
independently as it arrives.

### 12.4 Streaming transport

Streaming responses are sent as `Content-Type: application/x-ndjson`
over HTTP `Transfer-Encoding: chunked`. Each line is one fully-formed
RES_CHUNK in JSON. Chunks SHOULD arrive in monotonic `chunk_seq` order;
out-of-order arrival is a transport bug, not a protocol property.

### 12.5 Updated fault codes (§6.3 update)

Additional standard fault codes introduced in v0.2-v0.5:

| Code | When |
|---|---|
| `unknown_peer` | Sender not in peer cache and no `identity_doc` provided |
| `holder_proof_required` | `cap_id` present, `holder_proof` absent |
| `cap_unknown` | `cap_id` claimed but neither in local store nor inline `cap_envelope` |
| `handler_error` | The application handler raised an exception |

### 12.6 Verification rules update (§5.4)

Capability chain verification is fail-closed: if any link's pubkey is
absent from `known_keys`, the verifier MUST return invalid (reason
`Cannot verify: missing key for delegator <id>`). Pre-v0.2.0
implementations silently skipped checks for missing keys, which
admitted forged chains.

### 12.7 Cap envelope inline (v0.4.0)

When the receiver does not have the cap locally and `cap_envelope` is
present, the receiver MUST:

1. Verify `cap_envelope.cap_id == msg.cap_id`
2. Verify `cap_envelope.issuer` is the receiver's own agent_id
3. Gather pubkeys for all chain delegators from peer cache
4. Run §5.4 verification with those known_keys
5. On success, cache the cap locally and dispatch
6. On failure, reject with `capability_invalid`

If `cap_id` is present without local cap and without `cap_envelope`,
receivers MUST reject with `cap_unknown` (do not silently fall through
to action-name dispatch).

### 12.8 Durable state (v0.3.0)

Reference-implementation guidance: idempotency cache and per-cap
invocation counts SHOULD persist across agent restarts. The
spec-level contract (idempotent dedup, max_invocations enforcement)
is process-independent; how it's stored is implementation-defined.

An implementation that produces identical outputs for these inputs is interoperable.
