# PACT v1 Specification

**Protocol for Agent Capability and Trust**
Version: 1.2.0-draft
Date: 2026-06-08

> **Reading this spec.** Sections 1–11 describe the v1.0.0-draft baseline (PACT reference implementation v0.1.4). Section 12 documents the wire-affecting changes introduced in reference implementation versions v0.2.0 through v0.5.3 and **supersedes the §1–§11 sections it references**. Section 14 documents the v1.2 additions introduced in reference implementation v0.6 (V-tier visa machinery, per-link `parent_cap_id`, cancelled-receipt emission) and **supersedes/extends §12 where they overlap**. An implementation matching only §1–§11 is **not** compatible with current PACT peers; matching §1–§11 *as amended by* §12 *and §14* is. Changelogs in §13 (v1.0→v1.1) and §15 (v1.1→v1.2).

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

> **Extended by §12.6, §12.7, §12.9, and §12.10.** v1.1 requires fail-closed behavior on missing delegator keys (§12.6), defines `cap_envelope` inline verification (§12.7), enforces the single-issuer trust model with explicit rejection (§12.9), and validates caveat values at issue/attenuate time (§12.10).

1. If `revoked: true`, REJECT.
2. `holder` MUST match the presenting agent's agent_id.
3. For root tokens (no `delegation_chain`): `signature` MUST verify against the issuer's public key.
4. For attenuated tokens: `signature` MUST verify against the last delegator's public key. Each `delegation_chain` link's `sig` MUST verify against that link's `from` agent's public key, signing the `parent` cap_id.
5. All `expires` caveats MUST not be in the past.
6. Invocation count MUST not exceed the minimum of all `max_invocations` caveats.

---

## 6. Messages

### 6.1 Message Types

> **Superseded by §12.1.** v1.1 defines **three** message types — `REQ`, `RES`, and `RES_CHUNK` (streaming response variant).

The v1.0 baseline defined two:

| Type | Direction | Purpose |
|------|-----------|---------|
| `REQ` | A → B | Request with capability proof |
| `RES` | B → A | Result, error, or information |

### 6.2 REQ Message

> **Superseded by §12.2 and §12.7.** v1.1 adds the optional fields `identity_doc`, `cap_envelope`, and `stream`, and makes `holder_proof` **mandatory** whenever `cap_id` is present.

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

> **Extended by §12.9.** v1.1 requires receivers to write a signed `outcome=failed` receipt for every error path (not just for completed dispatches).

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

> **Extended by §12.5 and §12.9.** v1.1 adds `unknown_peer`, `holder_proof_required`, `cap_unknown`, `handler_error`, and `deadline_too_far`.

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

- `outcome`: One of `"completed"`, `"failed"`, `"cancelled"`. *(v1.1 supersedes v1.0's `"timeout"` value; see §12.9.)*
- `signature`: Ed25519 signature of canonical JSON (excluding `signature`).

> **Extended by §12.9.** v1.1 requires receivers to write signed receipts on **every** dispatch outcome — including rejections at any pipeline step (deadline_exceeded, invalid_signature, holder_proof_required, cap_unknown, capability_invalid, no_handler, handler_error, deadline_too_far). Pre-v1.1 implementations omitted receipts on failure paths.

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

> **Extended by §12.4 and §12.10.** v1.1 defines `application/x-ndjson` over chunked transfer for streaming responses (§12.4), and requires HTTP servers to validate `Content-Length` (reject non-integer, ≤ 0, or oversize values) to close a slow-loris DoS path (§12.10).

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

An implementation is **PACT v1.1 compatible** if it can:

1. Derive `agent_id` from a known public key and produce the expected value.
2. Serialize JSON canonically and produce identical bytes.
3. Sign and verify Ed25519 signatures.
4. Issue and verify capability tokens (including attenuation chains), with fail-closed behavior on missing delegator keys (§12.6) and validated caveat values (§12.10).
5. Build and verify REQ/RES messages with holder proofs, including: `holder_proof` mandatory when `cap_id` is present (§12.2); reject unknown peers unless `identity_doc` is included (§12.2); reject REQs whose deadline exceeds the configured ceiling (§12.9).
6. Send and receive RES_CHUNK streaming responses over `application/x-ndjson` + HTTP chunked transfer (§12.1, §12.3, §12.4).
7. Verify inline `cap_envelope` for cross-machine delegation, requiring `cap_id` to be present alongside (§12.7).
8. Produce signed unilateral receipts for **every** dispatch outcome — `completed`, `failed`, or `cancelled` (§12.9).
9. Validate HTTP `Content-Length` (reject non-integer, ≤ 0, or oversize values) (§12.10).
10. Fail closed on malformed base64 in any signature, holder-proof, receipt, or identity-doc field (§12.10).

A v1.0-only implementation (sections 1–11 alone) is **not** v1.1 compatible and will fail handshake with current PACT peers.

All of the above are testable against the provided test vectors (§11).

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

## 12. v1.1 amendments (supersede §1–§11)

Sections 1–11 above are the v1.0.0-draft baseline (reference implementation v0.1.4).

**Section 12 is normative for v1.1.** Each sub-section supersedes the §1–§11 section it references. Where §12.x and §1–§11 conflict, §12.x is authoritative. The reference implementation (v0.5.4+) tracks §12.

An implementation matching §1–§11 alone will fail handshake against current PACT peers. The conformance checklist in §10 enumerates what §12 requires beyond the v1.0 baseline.

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

### 12.9 v0.5.2 additions (audit, caps, deadlines, trust model)

**Signed `outcome=failed` receipts on dispatch errors.** Receivers MUST
write a signed receipt with `outcome: "failed"` whenever a REQ is
rejected at any pipeline step (deadline_exceeded, invalid_signature,
holder_proof_required, cap_unknown, capability_invalid, no_handler,
handler_error, deadline_too_far). The receipt's `refs` MUST include
both the inbound REQ id and the signed error RES id. Pre-v0.5.2
implementations did not write receipts on failure paths, breaking the
bilateral-receipt promise on rejection.

**Receipt outcomes are exhaustive:**
- `completed` — handler returned a payload and a signed RES was sent
- `failed` — dispatch was rejected at any pipeline step OR handler
  raised `HandlerFailure(code, detail)` for explicit failure signaling
- `cancelled` — streaming consumer disconnected mid-stream

**HandlerFailure exception (reference impl).** Apps that wrap remote
calls (e.g. peer delegation) SHOULD raise `HandlerFailure(code, detail)`
rather than returning an error dict, so the failure produces a signed
error response with the custom code and an `outcome=failed` receipt.
Returned dicts continue to mean success; only raised exceptions
(unhandled or `HandlerFailure`) produce error responses.

**`cap_envelope` requires `cap_id` (§6.2 / §12.7 update).** A REQ
including `cap_envelope` MUST also include `cap_id`. The reference
impl auto-derives `cap_id` from `cap_envelope.cap_id` at build time,
or raises `ValueError` if the envelope is malformed. Pre-v0.5.2 builds
allowed `cap_envelope` without `cap_id`, in which case the receiver's
cap-verification step was silently skipped. Receivers MUST treat
`cap_envelope` without `cap_id` as a malformed message.

**Deadline upper bound.** Receivers MUST enforce a configurable
`max_deadline_seconds` ceiling (reference default: 3600s). REQs whose
deadline lies further in the future than the ceiling MUST be rejected
with new fault code `deadline_too_far`. This prevents a malicious peer
from pinning the dispatch lock with a year-2099 deadline plus a hung
handler.

**New standard fault code:**

| Code | When |
|---|---|
| `deadline_too_far` | REQ deadline exceeds receiver's `max_deadline_seconds` ceiling |

**Single-issuer trust model (clarification, not change).** PACT v0.5
verifiers reject capabilities whose `issuer` does not equal the
verifier's own `agent_id` (fault code `capability_invalid`,
detail `cap issuer ... is not this agent`). This is intentional:
agents only honor caps they issued themselves. Cross-organization
delegation chains (where agent A trusts caps issued by agent B because
A trusts B's identity) require a `trusted_issuers` set per agent —
deferred to post-v0.6.

### 12.10 v0.5.3 additions (input validation, fail-closed)

**Signature/key field tolerance.** Signature verification (`verify_message`,
`verify_holder_proof`, `verify_receipt`, `verify_capability`) MUST treat
malformed base64 in the relevant field as a verification failure rather
than propagating the underlying decoder exception. Pre-v0.5.3 a single
malformed signature in any incoming message could crash the dispatcher.
The fail-closed contract is: malformed input → return False / return a
structured failure result; never raise.

**Identity-doc fault tolerance.** TOFU registration of an inline
`identity_doc` MUST reject documents whose `public_key` field is not
parseable base64. Same applies to the rotation-refresh path. Implementations
return a clean rejection (None / fault) instead of raising.

**Caveat value validation at issue/attenuate.** Caveats whose values
are structurally invalid MUST be rejected at the time the cap is
issued or attenuated, not at verification time. Required validations:
- `max_invocations`: MUST be a positive integer (>= 1). Negative
  values silently produce a cap that's dead-on-arrival under the
  enforcement check `count >= max`.
- `expires`: MUST be a parseable ISO 8601 timestamp. Unparseable
  values would otherwise crash the verifier on the comparison step.

Implementations raise (e.g. `ValueError`) at issue/attenuate time so
the bug surfaces at the source rather than at verification time on
some other agent.

**HTTP body length sanitization.** HTTP transports MUST validate
`Content-Length`:
- Non-integer values → 400 Bad Request
- Values <= 0 → 400 Bad Request
- Values > `max_body_bytes` → 413 Content Too Large

Pre-v0.5.3 the sync server's `int(self.headers.get("Content-Length", 0))`
accepted negative values, falling through to `rfile.read(-1)`, which
blocks indefinitely waiting for EOF — a slow-loris-shaped DoS using a
single byte of header. v0.5.3 closes this; the async server (which
reads via the ASGI protocol) was already immune.

**Streaming write order.** During RES_CHUNK streaming completion, the
idempotency cache MUST be persisted before the receipt is written.
Pre-v0.5.3 wrote receipt first, cache second. A crash between those
two writes would result in a retry of the same `idempotency_key`
re-executing the handler and writing a SECOND receipt — creating
duplicate audit entries for one logical request. The corrected order
ensures that on retry, the cache hit returns the cached chunks
without re-execution and without a second receipt.

An implementation that produces identical outputs for these inputs is interoperable.

---

## 13. Changes from v1.0.0-draft to v1.1.0-draft

Line-item summary for implementers tracking the diff. Each row points to the §12 sub-section that defines the change normatively.

| § | Change | Wire-affecting? | Reference impl version |
|---|---|---|---|
| §12.1 | Third message type `RES_CHUNK` for streaming responses | Yes (new type) | v0.5.0 |
| §12.2 | New optional REQ fields: `identity_doc`, `cap_envelope`, `stream` | Yes (new fields) | v0.2.0–v0.5.0 |
| §12.2 | `holder_proof` MUST be present whenever `cap_id` is present | Yes (tightening) | v0.2.0 |
| §12.2 | Receivers MUST reject unknown peers unless `identity_doc` is included for TOFU | Yes (tightening) | v0.2.0 |
| §12.2 | Rotation continuity: first post-rotation REQ should carry fresh `identity_doc`; receiver verifies against cached `next_key_digest` | Yes (clarification + new verification path) | v0.3.1 |
| §12.3 | RES_CHUNK schema (independent signature per chunk; `chunk_seq`, `chunk_final`) | Yes (new schema) | v0.5.0 |
| §12.4 | Streaming transport: `application/x-ndjson` over HTTP chunked transfer | Yes (new transport mode) | v0.5.0 |
| §12.5 | New fault codes: `unknown_peer`, `holder_proof_required`, `cap_unknown`, `handler_error` | Yes (vocabulary extension) | v0.2.0–v0.5.0 |
| §12.6 | Capability chain verification MUST be fail-closed on missing delegator keys | Yes (tightening; was silent-pass) | v0.2.0 |
| §12.7 | `cap_envelope` inline verification rules; `cap_id` MUST accompany `cap_envelope` | Yes (new verification path + tightening) | v0.4.0, tightened v0.5.2 |
| §12.8 | Idempotency cache + per-cap invocation counts SHOULD persist across restarts | No (implementation guidance) | v0.3.0 |
| §12.9 | Signed `outcome=failed` receipts on dispatch errors (all rejection paths) | Yes (audit-trail requirement) | v0.5.2 |
| §12.9 | Receipt outcome enum is `completed` / `failed` / `cancelled` (supersedes v1.0 `timeout`) | Yes (vocabulary change) | v0.5.2 |
| §12.9 | Server-side `max_deadline_seconds` ceiling; new fault `deadline_too_far` | Yes (tightening + new fault code) | v0.5.2 |
| §12.9 | Single-issuer trust model: capabilities whose `issuer` ≠ verifier's `agent_id` MUST be rejected | Clarification (was implicit) | v0.5.x |
| §12.10 | Signature/key/receipt verifiers MUST fail closed on malformed base64 (no propagated `binascii.Error`) | Yes (tightening) | v0.5.3 |
| §12.10 | TOFU MUST reject identity-doc with unparseable `public_key` field | Yes (tightening) | v0.5.3 |
| §12.10 | Caveat values (`max_invocations`, `expires`) MUST be validated at issue/attenuate time, not at verification | Yes (tightening; surfaces bugs at source) | v0.5.3 |
| §12.10 | HTTP `Content-Length` MUST be validated: non-integer → 400; ≤ 0 → 400; > `max_body_bytes` → 413 | Yes (closes slow-loris DoS path) | v0.5.3 |
| §12.10 | During RES_CHUNK streaming completion, idempotency cache MUST be persisted before receipt | Yes (durability ordering) | v0.5.3 |

**Versioning policy.** PACT spec versions follow semver. v1.0 → v1.1 indicates additive and tightening changes — any conformant v1.1 implementation is a *strict subset* of v1.0 behavior (v1.1 rejects things v1.0 allowed; v1.1 supports things v1.0 didn't define). A v2.0 would indicate breaking changes that v1.1 implementations cannot interpret. **Draft status (`-draft`) remains** until external validation: a second independent implementation passing the conformance checklist (§10) against the published test vectors (§11) is the gate for dropping `-draft`.

**Test vectors.** `tests/vectors/pact_v1_vectors.json` is current as of v1.1.0-draft. The reference implementation passes its own vector check (`tests/test_vectors.py`) on every commit.

---

## 14. v1.2 amendments (extend §12; supersede §1–§11)

Section 14 is normative for v1.2 and is tracked by reference implementation **v0.6**. Where §14.x conflicts with §12.x or §1–§11, §14.x is authoritative. §14 introduces the **V-tier visa mechanism** for session-bounded interaction with passport-less peers, closes two correctness gaps in earlier versions (multi-hop chain verification at depth ≥ 3, and the missing-receipt-on-stream-partition path), and acknowledges one known limitation that defers to v1.3 / reference implementation v0.7.

### 14.1 Trust gradient (§3 extension)

PACT exposes a three-tier trust gradient:

| Tier | Issued by | Identity established? | Wire shape |
|---|---|---|---|
| **Passport** | The holder itself (KERI-style self-certifying identifier) | Yes | Standard `from_agent` + cap chain (§5) |
| **Visa** | The destination agent (gatekeeper) | **No — binds the session, not the principal** | Capability token with `visa: true` (§14.2) |
| **Refusal** | The gatekeeper | N/A | Fault response, no session created |

A visa is a **session-scoped, attenuated, non-delegable capability token** that a gatekeeper issues to a counterparty whose identity it cannot establish. The visa binds the *session* via an ephemeral key, not the *principal*. The honest legal analogue is a **stateless-person transit document**, not a tourist visa: it grants bounded passage precisely because identity cannot be established, and the issuer accepts the risk by scoping tightly and logging everything.

### 14.2 Visa capability extension (§5 extension)

A visa is a `CapabilityToken` with three additional optional fields. All three are part of `signable_dict` and therefore covered by the issuer's signature:

| Field | Type | Required when | Purpose |
|---|---|---|---|
| `visa` | bool (`true`) | This cap is a visa | Routes verification to visa-specific paths (§14.4) |
| `nonce` | string (url-safe base64, 16-22 bytes) | This cap is a visa | Server-issued; signed by holder on use to bind the session (§14.4) |
| `ephemeral_key_fingerprint` | string (`sha256:<hex>`) | This cap is a visa | Gatekeeper-internal audit; not surfaced on the wire to other parties |

A visa MUST carry the caveat `no_further_delegation: true` (terminal). A visa SHOULD carry a tight `expires` caveat (default 30 s) and SHOULD carry `max_invocations: 1`. The visa's `issuer` MUST be the gatekeeper's own `agent_id` (single-issuer trust model, per §12.9 inherits).

### 14.3 The `request_visa` intent (§6 extension)

A passport-less peer requests a visa by sending a REQ with `intent: "request_visa"`. The payload MUST contain `{"action": "<requested_action_name>"}`. The peer MUST include an inline `identity_doc` (TOFU per §12.2); the message is signed by the ephemeral key.

The gatekeeper runs an **issuance policy** (§14.5). On grant, the response payload is `{"visa": <full_cap_dict>, "nonce": "<server_issued_nonce>"}`. On refusal, the response is `{"status": "error", "fault": {"code": "denied", "detail": "denied"}}`. The refusal MUST be opaque to the peer; the gatekeeper records the full policy rationale only in its own receipt (§14.7).

### 14.4 Visa-aware `holder_proof` (§5.4 extension)

When `cap_envelope` carries `visa: true`, the verification of `holder_proof` is modified:

- For a non-visa cap (§12.2): `holder_proof` is a signature over `msg.id` using the holder's key.
- **For a visa: `holder_proof` MUST be a signature over the visa's `nonce` field** using the ephemeral key whose `agent_id` matches `cap.holder`.

This binding ensures a captured `holder_proof` cannot be replayed against a different visa (whose nonce differs). All other §5.4 verification (issuer check, holder match, caveat enforcement, chain verification) applies unchanged.

### 14.5 Visa issuance policy hook (new)

A gatekeeper that accepts visa requests MUST implement an issuance-policy callable with the signature:

```
policy(ctx: VisaContext) -> VisaGrant | VisaRefuse
```

`VisaContext` carries gatekeeper-observed values:

| Field | Type | Meaning |
|---|---|---|
| `action` | string | The action the peer requested |
| `payload_hash` | string (`sha256:<hex>`) | Canonical-JSON hash of the request payload |
| `peer_network_id` | string | See §14.6 |
| `recent_visa_count_window` | int | Count of visas issued to this `peer_network_id` in the prior 60 s |
| `resource_headroom` | float (0.0–1.0) | Implementation-defined load signal; default 1.0 |

`VisaGrant` returns the caveat list to attach to the visa. `VisaRefuse` returns a `reason` string that MUST be recorded in the gatekeeper's receipt but MUST NOT be returned to the peer.

**Default shipped policy.** Implementations SHALL ship a default policy that issues a visa only when ALL of the following hold:

1. `action` is opt-in (the handler was registered with `visa_eligible=true`); unannotated handlers default to refusal.
2. The handler declares `idempotent=true`.
3. The handler declares `payload_bytes ≤ 4096` and `compute_ms ≤ 100`.
4. `recent_visa_count_window` ≤ 4 (i.e., fewer than 5 visas in the prior 60 s window for this `peer_network_id`).

The default policy's caveat ceiling: `expires` = now + 30 s, `max_invocations: 1`, `no_further_delegation: true`. All other requests → refusal.

**Concurrency.** `recent_visa_count_window` MUST be read at issuance time, and the issuance path MUST be serialized per `peer_network_id` so the rate-ceiling read-modify-write cannot race. Without this, two threads observing `count == 4` could both grant, breaching the ceiling.

### 14.6 `peer_network_id` derivation (new)

`peer_network_id` is the source IPv4 /24 prefix (or IPv6 /48) observed at the gatekeeper's transport boundary at issuance time. Loopback addresses MAY be aggregated as a single sentinel (`loopback:<host>`). Addresses the gatekeeper cannot observe MUST yield `peer_network_id = "unknown"`; the default policy MUST refuse on `"unknown"`.

This aggregation key is *intentionally naive* — trivially rotatable on any cloud provider — and is the chosen v1.2 default because the limitation is honest. Stronger aggregation keys (TLS-session-bound, post-handshake-derived, peer-network attestation) are non-normative future work and may extend §14.6 in v1.3.

### 14.7 Receipts under visa (§7 extension)

Every visa-related dispatch MUST produce a signed receipt with the standard fields (§7) plus visa-specific audit fields:

| Receipt event | Required extra fields |
|---|---|
| `event_type: "visa_grant"` | `visa_cap_id`, `ephemeral_key_fingerprint`, `action`, `peer_network_id`, `visa_nonce`, `policy_id` |
| `event_type: "visa_refused"` | `ephemeral_key_fingerprint`, `action`, `peer_network_id`, `rationale`, `policy_id`. `rationale` MUST NOT appear in any peer-visible response. |
| `event_type: "visa_use"` | `visa_cap_id`, `ephemeral_key_fingerprint`, `action`, `visa_nonce`. Emitted on both successful and refused visa-use dispatches; the standard `outcome` field distinguishes (`completed` / `failed`). |

The receipt MUST allow post-hoc reconstruction of the full compromise window from receipts alone — issuer, visa_cap_id, ephemeral_key_fingerprint, action, signed nonce, and timestamp must all be present on every record. The dispatch pipeline MUST bind the verified visa to the dispatch context **before** rate-limit and other refusal checks so that refused-use receipts carry full attribution (this implementation defect, closed in reference v0.6, was Bug 8 of the running case study).

### 14.8 `DelegationLink.parent_cap_id` (§5.4 update — Bug 6 fix)

Each `DelegationLink` minted under v1.2 MUST carry a `parent_cap_id` field recording the cap_id signed by that link at its own attenuation step. The verifier MUST check each link's signature against `link.parent_cap_id` rather than against `token.parent` (the final token's parent).

```
DelegationLink {
  "from":           "<delegator_agent_id>",
  "sig":            "<base64>",
  "parent_cap_id":  "<uuid of the cap this link signed>"   // v1.2+
}
```

**Pre-v1.2 migration window.** A v1.2 verifier MAY accept a chain link lacking `parent_cap_id` by falling back to `token.parent`. When it does so, it MUST emit a `DeprecationWarning` indicating pre-v1.2 chain format. The fallback admits clean chains only at depth K = 2 (where `link.parent_cap_id` and `token.parent` coincide); chains at depth K ≥ 3 in the pre-v1.2 format will be rejected, which is the existing v1.1 behavior. **v1.3 verifiers MUST reject any chain link lacking `parent_cap_id`.**

This change closes Bug 6 of the case study: pre-v1.2 verifiers checked every link against `token.parent`, which accidentally coincided with each link's signed value only at K = 2. At K ≥ 3 every clean chain was rejected.

### 14.9 Cancelled receipt emission (§12.9 implementation alignment — Bug 7 fix)

§12.9 specifies `outcome ∈ {"completed", "failed", "cancelled"}`, but pre-v0.6 reference implementations never emitted `"cancelled"` — a streaming `BrokenPipeError` skipped the receipt-write block by raising `GeneratorExit` (a `BaseException`, not `Exception`) past the existing `except Exception` clause. v1.2 reference implementations MUST emit a signed receipt with `outcome="cancelled"` on every streaming partition, referencing the chunks that were emitted before the disconnect. The receipt-write block MUST be reachable from every exit path (normal completion, handler raise, consumer disconnect). The idempotency cache MUST NOT be populated on cancelled outcomes; a retry with the same `idempotency_key` MUST re-execute the handler.

This closes Bug 7 of the case study and aligns the implementation with the v1.1 spec text.

### 14.10 Known limitation: rogue-delegator forgery (Bug 9, deferred to v1.3)

A capability verifier in v1.2 trusts the values of `action` and `caveats` written into the child cap dict, rather than re-deriving them from the legitimate chain. A delegator whose private key has been compromised can construct a child cap with a different `action` or with caveats stripped, re-sign it with the compromised key, and the v1.2 verifier accepts it (because every chain link still verifies against its stable `parent_cap_id` and the outer signature is valid).

**Threat model.** This vulnerability requires compromise of an intermediate delegator's private key. With that compromise, the attacker can mint arbitrary children — including children with widened authority — beneath the compromised delegator's position in the chain. Damage is bounded to caps downstream of the compromised key; the original issuer and any siblings are unaffected.

**Status in v1.2.** Known and deferred. v1.3 verifiers SHOULD walk the delegation chain to accumulate the legitimate `action` and caveat set from each link, rejecting children whose declared values diverge. The wire shape that supports this may require chain links to also commit to the child's cap_id (or to the accumulated caveat set); the trade-off is open as of 2026-06-08.

**Implementations.** v1.2 implementations MAY add this check as an optional verifier mode; doing so does not break v1.2 compliance.

---

## 15. Changes from v1.1.0-draft to v1.2.0-draft

Line-item summary for implementers tracking the diff. Each row points to the §14 sub-section that defines the change normatively.

| § | Change | Wire-affecting? | Reference impl version |
|---|---|---|---|
| §14.1 | Three-tier trust gradient (passport / visa / refusal) added to §3 | No (framing) | v0.6 |
| §14.2 | `CapabilityToken` gains optional `visa`, `nonce`, `ephemeral_key_fingerprint` fields | Yes (new optional fields; signable) | v0.6 |
| §14.3 | New REQ `intent="request_visa"`; visa-issuance response shape | Yes (new intent + new payload shape) | v0.6 |
| §14.4 | When cap is a visa, `holder_proof` MUST sign the visa's `nonce` (not `msg.id`) | Yes (tightening; visa-specific path) | v0.6 |
| §14.5 | Visa issuance policy hook contract + default shipped policy + per-peer issuance serialization | No (implementation guidance + new internal contract) | v0.6 |
| §14.6 | `peer_network_id` is source IPv4 /24 or IPv6 /48 (intentionally naive v1.2 default) | No (implementation guidance) | v0.6 |
| §14.7 | Receipts under visa carry `event_type` + visa-specific audit fields; visa binding MUST precede rate-limit refusal | Yes (audit-trail requirement; closes Bug 8) | v0.6 |
| §14.8 | `DelegationLink` gains required-from-v1.2 `parent_cap_id` field; verifier checks each link's signature against its own contemporaneous parent; pre-v1.2 fallback with `DeprecationWarning` | Yes (new field, tightening) | v0.6 |
| §14.9 | Cancelled-receipt emission is now mandatory on streaming partition (closes spec-vs-implementation gap from §12.9) | Yes (audit-trail requirement; closes Bug 7) | v0.6 |
| §14.10 | Rogue-delegator forgery (Bug 9) acknowledged as known v1.2 limitation, deferred to v1.3 | Clarification (no behavior change) | v0.6 |

**Versioning policy continued.** v1.1 → v1.2 indicates additive amendments (the V-tier visa mechanism) and tightening fixes (Bug 6 + Bug 7 + Bug 8). v1.2 verifiers accept caps in either v1.1 or v1.2 chain-link format; v1.3 will drop the v1.1 fallback. **Draft status (`-draft`) remains** until external validation — a second independent implementation passing the conformance checklist (§10) against the published test vectors (§11) is the gate for dropping `-draft`. The V-tier surface (§14.1–§14.7) and the Bug 6 chain-link tightening (§14.8) are the new conformance requirements for v1.2.

**Test vectors.** `tests/vectors/pact_v1_vectors.json` is current as of v1.1.0-draft. A v1.2 vector update covering visa caps + per-link `parent_cap_id` is pending; the reference implementation's full test suite (`tests/`) exercises the v1.2 paths in the meantime.
