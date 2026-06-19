# PACT v1 Specification

**Protocol for Agent Capability and Trust**
Version: 1.4.0-draft
Date: 2026-06-18

> **Reading this spec.** Sections 1–11 describe the v1.0.0-draft baseline (PACT reference implementation v0.1.4). Section 12 documents the wire-affecting changes introduced in reference implementation versions v0.2.0 through v0.5.3 and **supersedes the §1–§11 sections it references**. Section 14 documents the v1.2 additions introduced in reference implementation v0.6 (V-tier visa machinery, per-link `parent_cap_id`, cancelled-receipt emission). Section 16 documents the v1.3 chain-walk additions introduced in reference implementation v0.7 (per-link `action_at_step` + `caveats_at_step`, closing Bug 9 rogue-delegator forgery). Section 18 documents the v1.4 additions introduced in reference implementation v0.8 (domain-separated holder_proof closing Bug 11 / P_BIND, structured audit_context, normative error taxonomy, three-tier policy profiles, key-rotation overlap windows). Section 20 is a new normative Security Considerations section informed by the Stage 2 pre-registered methodology (D4, D5) and machine-checked formal verification (D2 / Tamarin Run 3). §14, §16, and §18 **supersede/extend §12 where they overlap**. An implementation matching only §1–§11 is **not** compatible with current PACT peers; matching §1–§11 *as amended by* §12, §14, §16, *and §18* is. Changelogs in §13 (v1.0→v1.1), §15 (v1.1→v1.2), §17 (v1.2→v1.3), and §19 (v1.3→v1.4).

---

## 1. Overview

PACT is a minimal protocol enabling trusted, capability-scoped, auditable interaction between software agents. It defines three primitives: agent identity, capability tokens, and messages. All other features are built at the edges by implementations.

This document is sufficient for an independent implementation. Test vectors are provided in `tests/vectors/pact_v1_vectors.json`.

---

## 2. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119] (added in v1.4).

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

### 14.10 Known limitation: rogue-delegator forgery (Bug 9, ~~deferred to v1.3~~ **closed in v1.3**)

A capability verifier in v1.2 trusts the values of `action` and `caveats` written into the child cap dict, rather than re-deriving them from the legitimate chain. A delegator whose private key has been compromised can construct a child cap with a different `action` or with caveats stripped, re-sign it with the compromised key, and the v1.2 verifier accepts it (because every chain link still verifies against its stable `parent_cap_id` and the outer signature is valid).

**Threat model.** This vulnerability requires compromise of an intermediate delegator's private key. With that compromise, the attacker can mint arbitrary children — including children with widened authority — beneath the compromised delegator's position in the chain. Damage is bounded to caps downstream of the compromised key; the original issuer and any siblings are unaffected.

**Closure in v1.3 (see §16.1).** Per-link `action_at_step` + `caveats_at_step` fields bind the child's content into the link's signature. The verifier walks the delegation chain re-deriving the expected `(action, caveats)` at each hop with action-preservation and caveat-append-only checks; the final token's content MUST match the last link's recorded values. Mechanism follows Macaroons §III (Birgisson et al. NDSS 2014) ported to PACT's Ed25519 chain. Reference v0.7 implements this; pre-v1.3 chains fall back to v1.2 behavior with a `DeprecationWarning` and v1.4 will require the new fields.

**Implementations.** v1.2 implementations MAY add the v1.3 check as an optional verifier mode; doing so does not break v1.2 compliance but is recommended where supply-chain-of-keys is part of the threat model.

### 16.5 V-tier protocol advertisement (passive, emit-only)

A gatekeeper agent MAY attach an optional `protocol_advertisement` field to the payload of a visa-grant response or a structured-refusal response. The field consists of exactly two strings: `protocol` (e.g. `"PACT/1.3"`) and `spec_uri` (a URI where the spec is published).

```
"protocol_advertisement": {
  "protocol": "PACT/1.3",
  "spec_uri": "<URI of the spec>"
}
```

The field is signed by the outer `build_res` signature; MITM tampering breaks verification. The advertisement is conditionally included on the wire only when configured at the issuing agent (agent-level `advertise_protocol` knob) or specified per-decision by the issuance policy (`VisaGrant.protocol_advertisement` / `VisaRefuse.protocol_advertisement`). Absence is the norm; presence does not affect any other field's semantics.

**MUST-NOT.** Implementations MUST NOT take automated action on a received `protocol_advertisement` field. The field is emit-only metadata for human-mediated discovery — a developer building a non-PACT counterparty may read it out-of-band, follow the `spec_uri` to the published spec, and decide whether to add PACT support to their stack. It is NOT a handshake, NOT an install instruction, NOT a substrate-bootstrap mechanism. Any code path that consumes, parses-for-action, or acts on a received advertisement violates v1.3 conformance.

**Specific consumption paths that are forbidden:**

- No outbound network call on parse. Deserializing a message containing the field MUST NOT trigger a fetch of `spec_uri`.
- No protocol-level logging that surfaces the advertisement specially. Application code that reads the field manually is fine; PACT's own logger MUST NOT call it out.
- No telemetry, metrics, or counters about advertisements seen.
- No convenience methods that act on the field (no `grant.follow_advertisement()`, no auto-fetch).
- No dispatch-decision branch keyed off a received advertisement.

**Future PACT versions MUST preserve this MUST-NOT.** The advertisement is permanent emit-only metadata; making it actionable in a later spec revision would constitute a security-model break. Adoption is a human deliberation, not an automated agent decision — see §6 future work on the deferred outbound-presentation direction. The MUST-NOT is the architectural enforcement of the distinction the V-tier already makes between *PACT advertising what it speaks* (passive, safe) and *PACT propagating itself* (active, threat-bearing, explicitly out of scope).

**Refusal-posture interaction (§3 *Refusal posture*).** The structured-refusal response's `fault` remains opaque (`"code": "denied"`); the optional advertisement leaks one thing — that the gatekeeper speaks PACT — which is intentional and orthogonal to the policy rationale that the refusal continues to hide.

**Receipts.** The advertisement is NOT recorded in receipts. Receipts are the audit primitive (§7) and remain inert with respect to advertisement fields; actionable content in the audit log corrupts the audit primitive and re-opens the consumption-injection surface that §16.5 exists to prevent.

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

---

## 16. v1.3 amendments (extend §14; closes Bug 9)

Section 16 is normative for v1.3 and is tracked by reference implementation **v0.7**. Where §16.x conflicts with §14.x, §16.x is authoritative. §16 closes Bug 9 (rogue-delegator forgery, §14.10) by binding the child's `action` and `caveats` into each delegation-link signature and having the verifier walk the chain re-deriving the expected values at each hop.

### 16.1 `DelegationLink` extension (§14.8 update — Bug 9 closure)

Each `DelegationLink` minted under v1.3 MUST carry two additional fields:

| Field | Type | Required from | Purpose |
|---|---|---|---|
| `action_at_step` | string | v1.3+ | The action of the cap created at this attenuation step |
| `caveats_at_step` | array of caveats | v1.3+ | The full caveat list of the cap created at this attenuation step |

The link's signature MUST be over a canonical JSON encoding of the payload:

```
{
  "parent_cap_id":   "<uuid>",
  "action_at_step":  "<action>",
  "caveats_at_step": [ { "restrict": "...", "value": ... }, ... ]
}
```

This binds the child's content into the link's signature. A rogue delegator who mutates `action` or strips `caveats` post-attenuate() cannot re-sign the chain link without producing a payload whose hash diverges from the chain-walk's reconstruction.

### 16.2 Chain verification — `action` + caveat re-derivation

The v1.3 verifier walks the delegation chain enforcing two invariants in addition to the v1.2 link signature checks:

1. **Action preservation.** Every link's `action_at_step` MUST equal every other link's `action_at_step`. Action is constant across the chain (caps preserve action through attenuation; attenuation narrows scope, not changes purpose).
2. **Caveat append-only.** Each link's `caveats_at_step` MUST be a superset of the previous link's `caveats_at_step` (as a multiset of `(restrict, value)` tuples, with structured values canonicalized).

After walking the chain, the verifier MUST check that the final token's `action` matches the last link's `action_at_step` and the final token's `caveats` matches the last link's `caveats_at_step`. Either mismatch indicates the leaf was mutated after legitimate attenuation.

Rejection reasons MUST be reported with sufficient context for debugging (chain index, expected vs. actual values).

### 16.3 Pre-v1.3 migration window

A v1.3 verifier MAY accept a chain link lacking `action_at_step` or `caveats_at_step` by falling back to v1.2 behavior (the v1.2 `parent_cap_id` check, §14.8). When it does so, it MUST emit a `DeprecationWarning` indicating pre-v1.3 chain format and noting that action/caveat re-derivation cannot be enforced for that link. **v1.4 verifiers MUST reject any chain link lacking the v1.3 fields.**

### 16.4 Threat-model boundary

§16.1–§16.3 close Bug 9 — the rogue-delegator forgery surface. They do NOT extend protection against:

* **A compromised root issuer.** A root key compromise lets the attacker mint arbitrary caps directly; chain re-derivation provides no defense. Issuer key rotation (§4) is the only mitigation.
* **A leaf-holder colluding with their delegator.** If both keys are compromised, the chain is by-design valid; PACT cannot distinguish legitimate from collusive attenuation.
* **Authoritative-time skew.** Caveat enforcement is the verifier's responsibility (§5.4); chain walk doesn't affect time-based caveats.

These boundaries are deliberate; v1.3 closes the rogue-delegator surface specifically.

---

## 17. Changes from v1.2.0-draft to v1.3.0-draft

Line-item summary for implementers tracking the diff. Each row points to the §16 sub-section that defines the change normatively.

| § | Change | Wire-affecting? | Reference impl version |
|---|---|---|---|
| §16.1 | `DelegationLink` gains required-from-v1.3 `action_at_step` + `caveats_at_step` fields; link signature is over the canonical-JSON payload binding `parent_cap_id` + `action_at_step` + `caveats_at_step` | Yes (new fields, signature semantics tightened) | v0.7 |
| §16.2 | Chain verifier walks the delegation chain enforcing action preservation + caveat append-only; final token's `(action, caveats)` MUST match the last link's recorded values (closes Bug 9 — §14.10) | Yes (audit-trail tightening; new fault paths) | v0.7 |
| §16.3 | Pre-v1.3 chains lacking the new fields verify with `DeprecationWarning` (v1.2 fallback path); v1.4 will reject pre-v1.3 chains | Yes (migration window) | v0.7 |
| §16.4 | Threat-model boundaries: §16 closes rogue-delegator forgery only; root-key compromise, leaf-delegator collusion, and time-skew are out of scope for the chain-walk mechanism | Clarification (no behavior change) | v0.7 |
| §16.5 | V-tier optional `protocol_advertisement` field on visa-grant and structured-refusal payloads; signed by outer envelope; normatively inert (MUST-NOT on consumption); MUST be preserved as emit-only in all future versions | Yes (additive optional field on existing wire envelopes) | v0.7 |

**Versioning policy continued.** v1.2 → v1.3 indicates additive tightening (the per-link content binding + chain-walk re-derivation), a known-limitation closure (Bug 9), and one additive V-tier extension (the passive protocol-advertisement field, §16.5). v1.3 verifiers accept caps in v1.1, v1.2, or v1.3 chain-link format with a deprecation cascade; v1.4 drops the v1.1 + v1.2 fallbacks. The substrate now has zero known unfixed correctness gaps documented in the case study (Bugs 1–9 all closed at the reference-implementation level). The §16.5 MUST-NOT on advertisement consumption MUST be preserved in all future versions; relaxing it would constitute a security-model break. **Draft status (`-draft`) remains** until external validation — a second independent implementation passing the conformance checklist (§10) against the published test vectors (§11) is the gate for dropping `-draft`.

**Test vectors.** A v1.3 vector update covering chain-walk re-derivation is pending; the reference implementation's full test suite exercises the v1.3 paths in the meantime.

---

## 18. v1.4 amendments (extend §16; closes Bug 11 — P_BIND falsification)

Section 18 is normative for v1.4 and is tracked by reference implementation **v0.8**. Where §18.x conflicts with §14.x or §16.x, §18.x is authoritative. §18 closes **Bug 11** (the absence of domain separation in `holder_proof` and `visa_use` signatures), surfaced as the P_BIND falsification trace in Tamarin Run 2 (spec/models/PROOF_LOG.md, Finding #1). The closure was machine-checked in Tamarin Run 3 (spec/models/pact_core_v0_8.spthy, see PROOF_LOG.md §"Run 3").

§18 also incorporates several patterns informed by an audit of Agent Identity Protocol (AIP, github.com/sunilp/aip) v0.3.0, reframed to serve PACT's peer-to-peer / bilateral-receipt / Macaroons-style-attenuation ethos. Where AIP and PACT both address a concern, this document cites the parallel; the substantive design choices remain PACT's.

### 18.1 Domain-separated `holder_proof` (closes Bug 11 / P_BIND)

Each `holder_proof` signature minted under v1.4 MUST be computed over a structured payload that distinguishes it from any other signature class the holder produces. The signed payload is the canonical-JSON encoding of:

```json
{
  "domain":   "pact/hp/v1",
  "req_id":   "<REQ.id, UUIDv4>",
  "cap_id":   "<REQ.cap_envelope.cap_id, UUIDv4 — or '' if no cap>",
  "to_agent": "<REQ.to_agent, sha256:...>"
}
```

The `domain` field MUST be the literal string `"pact/hp/v1"`. The field order in the source object is irrelevant; canonical JSON (§3) sorts keys lexicographically before signing.

The `holder_proof` wire field on REQ messages (§6.2 / §12.2) is the base64-encoded Ed25519 signature of this canonical-JSON payload computed with the holder's private key.

Receivers MUST reconstruct the expected payload from the REQ they received (REQ.id, REQ.cap_envelope.cap_id, REQ.to_agent) and verify the `holder_proof` signature against the canonical-JSON of that reconstructed payload using the holder's public key (resolved from the identity document referenced by REQ.cap_envelope.holder).

**Wire-affecting:** Yes. v0.7 implementations sign and verify `holder_proof` over the bare `REQ.id` bytes; v1.4 verifiers MUST reject such v0.7-format signatures with fault `pact_holder_proof_invalid` (§18.3) after the v1.4 migration window closes.

**Visa-use signing.** v1.4 also tightens the visa-use signature. The `visa_use` signature MUST be computed over the canonical-JSON encoding of:

```json
{
  "domain": "pact/visa/v1",
  "nonce":  "<visa.nonce, sha256:...>"
}
```

The `domain` field MUST be the literal string `"pact/visa/v1"` — distinct from `"pact/hp/v1"` above. This distinction is load-bearing for P_BIND: in v0.7 the visa-use signature is over a bare nonce, which a Tamarin Run 2 trace shows can be replayed as a holder_proof for any req_id matching the nonce. With distinct domain tags, the two signatures are structurally non-substitutable.

**Formal verification.** Tamarin proves P_BIND under the v1.4 signing structure. See `spec/models/pact_core_v0_8.spthy` and `spec/models/PROOF_LOG.md` §"Run 3" for the model, the proof, and the closure trace.

**AIP parallel.** AIP v0.3.0 calls a related construct "invocation-binding" but ties the signature only to the bare invocation context. PACT's binding goes further by including `cap_id` and `to_agent` so that even within the holder_proof domain, signatures cannot cross-use between different caps or against different receivers.

### 18.2 Structured `audit_context` field on REQ (required)

Every REQ message under v1.4 MUST carry a top-level `audit_context` field whose value is a JSON object with the following required keys:

| Key | Type | Constraint |
|---|---|---|
| `purpose` | string | Non-empty. SHOULD be one of: `"task"`, `"delegation-step"`, `"tool-call"`, `"audit-export"`, `"revocation-broadcast"`, `"research-subtask"`, `"system"`. Implementations MAY accept others. |
| `request_id` | string | UUIDv4. SHOULD equal REQ.id; MAY differ for sub-requests. |
| `audience_hint` | string | The receiver's `agent_id` (`sha256:...`). MUST equal REQ.to_agent. |
| `expires_at` | string | ISO 8601 timestamp. MUST be in the future at sign-time. |

The `audit_context` object MUST be included in the canonical-JSON payload that the REQ's outer envelope signature covers (§6.2 signature scope).

Receivers MUST reject REQs missing `audit_context` or with any required key missing, empty, or malformed with fault `pact_token_malformed` (§18.3).

Receivers MUST reject REQs where `audit_context.audience_hint != REQ.to_agent` with fault `pact_audience_mismatch` (§18.3) (added 2026-06-18 — `pact_audience_mismatch` is new in v1.4).

**Wire-affecting:** Yes. New required field on REQ.

**Rationale.** v0.7 receipts contain the bilateral REQ/RES pair, but the *purpose* of the exchange is implicit in the application-layer payload. Making purpose explicit at the protocol layer enables protocol-layer audit ("how many revocation-broadcast REQs did this agent send in window W?") without parsing application payloads.

**AIP parallel.** AIP requires a per-delegation `context` field but as free-form text. PACT v1.4 makes it structured (enabling machine-auditable purpose) and binds the audience explicitly (closing a class of audience-confusion attacks AIP treats with a separate error type).

### 18.3 Normative error taxonomy

PACT v1.4 defines the following normative fault codes. Implementations MUST emit one of these codes (in the `fault.code` field of RES messages, §6.3) when rejecting a REQ. The HTTP status mapping applies when PACT is carried over HTTP (§8.1).

**Authentication-class faults (HTTP 401):**

| Code | Meaning |
|---|---|
| `pact_token_missing` | REQ envelope lacks required signed fields (e.g., no signature, no holder_proof when one is required). |
| `pact_token_malformed` | REQ structure violates spec (missing field, wrong type, malformed canonical JSON, missing `audit_context`). |
| `pact_signature_invalid` | Outer envelope or cap-chain signature does not verify against the claimed signer's public key. |
| `pact_holder_proof_invalid` | `holder_proof` signature does not verify against the reconstructed canonical payload (§18.1) OR uses the v0.7 bare-payload format after the v1.4 migration window closes. |
| `pact_identity_unresolvable` | Receiver cannot resolve the signer's identity document (no inline identity_doc, no advertise_protocol, no out-of-band registration). |
| `pact_token_expired` | `audit_context.expires_at` is in the past, OR cap-chain element's expiry has passed. |
| `pact_key_revoked` | Signer's key has been revoked per a revocation record observed by the receiver. |

**Authorization-class faults (HTTP 403):**

| Code | Meaning |
|---|---|
| `pact_scope_insufficient` | Cap's `action` does not cover the requested operation, OR cap's caveats forbid this operation. |
| `pact_budget_exceeded` | Cumulative cost-of-operation exceeds the budget caveat on the cap. |
| `pact_depth_exceeded` | Delegation chain exceeds the `max_depth` caveat. |
| `pact_audience_mismatch` | `audit_context.audience_hint != REQ.to_agent`, OR cap's `holder != REQ.from_agent`. |
| `pact_receipt_not_bilateral` | When operating in bilateral mode (§18.6), a returned receipt lacks the counterparty's required signature. |

**Operational signals (HTTP 410):**

| Code | Meaning |
|---|---|
| `pact_revocation_observed` | The signer's identity, key, or cap has a revocation record but the REQ is otherwise valid — distinguishes "your token is fine but the key was revoked at T" from "your specific token is bad". |

Implementations MAY define additional codes for application-layer concerns; such codes MUST NOT use the `pact_` prefix.

**Wire-affecting:** Yes. v0.7 implementations may emit different fault codes; v1.4 receivers normalize to this taxonomy.

**AIP parallel.** AIP v0.3.0 defines 9 codes for MCP/A2A bindings (`aip_token_missing` through `aip_key_revoked`). PACT's taxonomy is structurally similar — Ed25519-based protocols share rejection classes — but adds three PACT-specific codes (`pact_holder_proof_invalid`, `pact_receipt_not_bilateral`, `pact_revocation_observed`) reflecting PACT's bilateral-receipt and real-revocation commitments.

### 18.4 Policy profiles (Simple, Standard, Advanced)

PACT v1.4 defines three policy profiles for the caveat language. Implementations MAY support any subset; identity documents MAY advertise a `minimum_policy_profile` declaring which profiles a receiver requires. Profiles graduate complexity additively — a Standard implementation also implements Simple, an Advanced implementation also implements both.

#### 18.4.1 Simple profile

The Simple profile uses four templated caveat types. Implementations MUST generate the exact byte patterns shown below when serializing Simple caveats; this normativity enables cross-implementation conformance testing.

| Template | Canonical-JSON form |
|---|---|
| Action allowlist | `{"restrict":"action","value":["<a1>","<a2>",...]}` |
| Budget ceiling (USD-cents) | `{"restrict":"budget_cents","value":<int>}` |
| Depth ceiling | `{"restrict":"depth","value":<int>}` |
| Expiry (absolute time) | `{"restrict":"expires_at","value":"<ISO 8601>"}` |

Caveat satisfaction:
- Action: `intent.action` MUST be in the `value` array.
- Budget: cumulative cost-of-operation (impl-defined; minimal interpretation = number of REQs against the cap) MUST be `<= value`.
- Depth: delegation chain length to the leaf token MUST be `<= value`.
- Expiry: current time MUST be `< value`.

Each caveat type SHOULD appear at most once per cap; duplicates are union-intersected (the most restrictive wins).

#### 18.4.2 Standard profile

The Standard profile adds custom predicates beyond the four templates. A custom predicate is a JSON object:

```json
{
  "restrict":  "<name>",
  "evaluator": "<URI scheme reserved for future versions; SHOULD be absent in v1.4>",
  "value":     "<arbitrary JSON>"
}
```

Receivers under the Standard profile MUST evaluate custom predicates against the impl-registered predicate handler. If no handler is registered for the named predicate, the receiver MUST reject the REQ with `pact_scope_insufficient` (a missing predicate handler is fail-closed by definition).

Standard predicates MUST terminate in `<=100` evaluation steps for any single REQ. Implementations MUST enforce this limit and reject with `pact_scope_insufficient` if exceeded.

#### 18.4.3 Advanced profile

The Advanced profile permits third-party caveats. A third-party caveat is a Standard predicate plus:

```json
{
  "restrict": "<name>",
  "third_party": true,
  "verifier_endpoint": "<URI the verifier must consult>",
  "verifier_pubkey":  "<base64 Ed25519 pubkey of the verifier>"
}
```

Receivers under the Advanced profile MUST contact `verifier_endpoint` (signed by `verifier_pubkey`) before honoring the cap. The verifier endpoint returns a signed assertion that the predicate holds.

Implementations MAY refuse Advanced. If an identity document advertises `minimum_policy_profile: "advanced"` and the receiver does not implement Advanced, the receiver SHOULD return `pact_scope_insufficient` rather than attempting evaluation.

**Wire-affecting:** Additive. Simple is the v0.7 baseline (templated caveats already exist informally). Standard and Advanced are new in v1.4.

**AIP parallel.** AIP's three policy profiles (`Simple` / `Standard` / `Advanced` per `aip-tokens.md` §7) inspire PACT's tiering structure. PACT's profiles use Macaroons-style caveats with normative byte patterns; AIP's use Biscuit/Datalog. The byte-level normativity in PACT's Simple profile mirrors AIP's "implementations MUST generate exactly these patterns" requirement and enables the same cross-implementation determinism, but without taking a Datalog dependency.

### 18.5 Key rotation with overlap windows

The identity document (§4.3) is extended in v1.4 to support multiple concurrent public keys with explicit validity windows:

```json
{
  "agent_id": "sha256:...",
  "public_keys": [
    {
      "id":          "k0",
      "type":        "Ed25519",
      "public_key":  "base64...",
      "valid_from":  "ISO 8601",
      "valid_until": "ISO 8601 — or null for indefinite"
    },
    {
      "id":          "k1",
      "type":        "Ed25519",
      "public_key":  "base64...",
      "valid_from":  "ISO 8601 (overlaps k0's valid_until window)",
      "valid_until": "ISO 8601"
    }
  ],
  ...
}
```

Each signature received MUST be verified against a key whose validity window includes the signature's timestamp. (For REQs, the relevant timestamp is `audit_context.expires_at - 1` — i.e., the most-permissive interpretation that the signer was authoritative at request creation time.)

A key MAY be revoked mid-window via the v0.8 REVOKE beacon (separate mechanism, not part of §18). Revocation supersedes the window's `valid_until`.

The Key Event Log (§4.2) is unchanged in v1.4; rotation events now MAY produce overlapping keys instead of strict succession. The first key (`id: "k0"`) is still the inception-event key whose hash defines `agent_id`.

**Wire-affecting:** Additive. v0.7 identity documents have a single key; v1.4 documents MAY have multiple. v1.4 receivers MUST handle both shapes (the `public_keys` array is the new normative form; the legacy single-key form (§4.3) is accepted via the v1.4 migration window in §18.7).

**AIP parallel.** AIP's `aip-core.md` §3.2 + §6.1 specify dual-key overlap windows for `aip:web:` identities. PACT adopts the same dual-window pattern but only for self-certifying (`pact:key:` analogue) identities; PACT explicitly refuses the DNS-anchored `aip:web:` flow on self-sovereignty grounds.

### 18.6 Bilateral receipts (clarification)

§7 already describes that receipts are signed by both the request initiator and the receiver. v1.4 makes this explicitly normative:

A receipt under v1.4 is *bilateral* iff it carries BOTH:
1. The signature of the receiver over the canonical-JSON RES payload (`receipt.receiver_signature`)
2. The acknowledgment signature of the initiator over the canonical-JSON receipt (`receipt.initiator_ack_signature`)

A receipt missing either signature is *non-bilateral*. Non-bilateral receipts MAY exist in implementation but MUST NOT be presented as audit evidence between distrustful parties.

A receiver in *bilateral mode* (advertised via identity document `protocols.pact.bilateral_required: true`) MUST refuse to honor a REQ unless the RES it sends back will also carry an initiator-ack signature within the audit window. If the initiator fails to ack, the receiver MUST emit a *cancelled receipt* (§14.9) and MAY return `pact_receipt_not_bilateral` to subsequent REQs from the same initiator.

**Wire-affecting:** Mostly clarification. The signature structure is already established in §7 and §14.7; v1.4 names the bilateral-vs-non-bilateral distinction and gives receivers the `pact_receipt_not_bilateral` rejection path.

**AIP parallel.** AIP's `aip-provenance.md` §3.2 defines three trust levels for completion blocks: `self_reported` (Level 1), `counter_signed` (Level 2), `peer_verified` / `human_verified` (Level 3). PACT's bilateral receipt is structurally AIP Level 2 by default (delegator-counterparty signs), making PACT's *floor* equivalent to AIP's opt-in mid-tier. PACT explicitly refuses Level 1 self-reported semantics; the receipt is bilateral or it is not a PACT receipt.

### 18.7 Pre-v1.4 migration window

A v1.4 verifier:

- MUST accept v1.3 chain-link format (§16) — that gate is unchanged.
- SHOULD accept v0.7 bare-payload `holder_proof` for an explicitly time-bounded migration window (default: 90 days from v1.4 release tag), emitting `DeprecationWarning` on accept. After the window closes, v0.7-format `holder_proof` MUST be rejected with `pact_holder_proof_invalid`.
- SHOULD accept REQs lacking `audit_context` for the same migration window (synthesize a placeholder `audit_context` with `purpose: "task"`, `request_id: REQ.id`, `audience_hint: REQ.to_agent`, `expires_at: REQ.deadline`), emitting `DeprecationWarning`. After the window closes, missing `audit_context` MUST be rejected with `pact_token_malformed`.
- MAY accept legacy single-key identity documents (§4.3) indefinitely — single-key is a special case of the new array form (`public_keys: [{id: "k0", ...}]`).

A v1.4 sender MUST emit the v1.4 forms (domain-separated `holder_proof`, present `audit_context`, public-keys-array identity doc).

**Wire-affecting:** Migration semantics.

### 18.8 Attack scenario catalogue

PACT v1.4 ships a machine-readable attack scenario catalogue at `spec/attacks/attacks.json`. Each scenario records:

| Field | Type | Purpose |
|---|---|---|
| `id` | string | Stable identifier (e.g., `holder-proof-replay`) |
| `title` | string | Human-readable title |
| `lemma_ref` | string | Reference to a formal lemma (e.g., `P-BIND`) |
| `test_ref` | string | Reference to a Stage 2 probe (e.g., `ATTR_BIND`) or formal model file |
| `predicted_error` | string | Expected `fault.code` value (§18.3) |
| `predicted_status` | int | Expected HTTP status (when over HTTP) |
| `notes` | string | Migration notes (e.g., "v0.7 vulnerable, v0.8 fixed") |

Conformant implementations SHOULD be able to demonstrate that every catalogued scenario produces the predicted error code. The catalogue is versioned with the spec; v1.5 may add or refine scenarios.

The v1.4 catalogue includes 12 scenarios spanning P-AUTH, P-BIND, P-MONO, P-REPLAY, P-AUDIT, and P-OPAQUE coverage. See `spec/attacks/attacks.json` for the canonical list.

**Wire-affecting:** No.

**AIP parallel.** AIP v0.3.0 ships 3 catalogued scenarios at `site/paper/data/attacks.json` (`scope-widening`, `replay-after-expiry`, `depth-bypass`). PACT's catalogue supersets AIP's three (with PACT-specific framing) and adds the bilateral-receipt and revocation-observed scenarios that AIP's model doesn't cover.

### 18.9 Threat-model boundary

§18.1–§18.8 close Bug 11 (P_BIND falsification) and tighten the audit / error-reporting surface. They do NOT extend protection against:

* **A compromised holder key.** A key compromise lets the attacker compute valid `holder_proof` signatures over any `(req_id, cap_id, to_agent)` triple. Domain separation does not help against this. Mitigation is key rotation (§18.5) or revocation (§18.3 / out-of-band REVOKE beacon).
* **Side-channel attacks on the Ed25519 implementation.** Library responsibility.
* **Social engineering of the LLM driving an agent.** PACT operates below the LLM semantic layer; the substrate's signing checks are valid regardless of what prompt the LLM responds to. See D5 for empirical evidence across three independent LLM adversaries.
* **Application-layer concerns beyond purpose-of-use.** `audit_context.purpose` is a coarse tag (`"task"`, `"delegation-step"`, etc.); fine-grained authorization is the caveat language's job (§18.4).

These boundaries are deliberate; v1.4 closes the P_BIND surface specifically and tightens audit-context structure to enable downstream analysis.

---

## 19. Changes from v1.3.0-draft to v1.4.0-draft

Line-item summary for implementers tracking the diff. Each row points to the §18 sub-section that defines the change normatively.

| § | Change | Wire-affecting? | Reference impl version |
|---|---|---|---|
| §18.1 | `holder_proof` signature MUST be over canonical-JSON `{domain:"pact/hp/v1", req_id, cap_id, to_agent}`; visa-use signature MUST be over `{domain:"pact/visa/v1", nonce}`. Closes Bug 11 (P_BIND falsification, Tamarin Run 2 Finding #1). Verified by Tamarin Run 3 (`pact_core_v0_8.spthy`). | Yes (signature semantics tightened) | v0.8 |
| §18.2 | New required REQ field `audit_context` with structured `{purpose, request_id, audience_hint, expires_at}` keys; covered by outer envelope signature. | Yes (new required field) | v0.8 |
| §18.3 | Normative 12-code error taxonomy (`pact_token_missing` ... `pact_revocation_observed`) with HTTP status mapping. v0.7 implementations may emit different codes; v1.4 normalizes. | Yes (fault-code normalization) | v0.8 |
| §18.4 | Three policy profiles (Simple / Standard / Advanced). Simple uses four templated caveat types with byte-normative canonical JSON; Standard adds custom predicates with bounded evaluation; Advanced permits third-party caveats. | Additive (Simple is v0.7-equivalent; Standard/Advanced are new) | v0.8 |
| §18.5 | Identity document gains `public_keys` array with `valid_from` / `valid_until` overlap windows. Legacy single-key form accepted via migration. | Yes (additive in identity doc; receivers handle both) | v0.8 |
| §18.6 | Bilateral receipts named normatively: receipt MUST carry both receiver and initiator-ack signatures. Receivers MAY advertise `bilateral_required: true`. | Mostly clarification | v0.8 |
| §18.7 | Pre-v1.4 migration window: v0.7 bare-payload `holder_proof` and missing `audit_context` accepted with `DeprecationWarning` for 90 days from v1.4 release; rejected after. | Yes (transition semantics) | v0.8 |
| §18.8 | Machine-readable attack scenario catalogue at `spec/attacks/attacks.json` shipped with spec. 12 scenarios mapped to formal lemmas and Stage 2 probes. | No (informative) | v0.8 |
| §18.9 | Threat-model boundary: §18 closes P_BIND under PACT's Dolev-Yao + LLM-adversary model; key compromise, side channels, social engineering, application-layer authorization remain out of scope. | Clarification | v0.8 |

**Versioning policy continued.** v1.3 → v1.4 indicates closure of the one remaining falsified formal lemma (P_BIND, via §18.1's domain separation), tightening of audit-context structure (§18.2), and adoption of patterns informed by an audit of AIP v0.3.0 (§18.4 policy profiles, §18.5 key rotation, §18.6 bilateral-receipt vocabulary). v1.4 verifiers accept v1.3 chain-link format unchanged and v0.7 `holder_proof` / `audit_context` formats during a 90-day migration window. The substrate's formal verification status improves from 8/9 lemmas (v1.3) to **9/9** (v1.4, per Tamarin Run 3). **Draft status (`-draft`) remains** until external validation — a second independent implementation passing the conformance checklist (§10) against the published test vectors (§11) and attack scenario catalogue (§18.8) is the gate for dropping `-draft`.

**Test vectors.** A v1.4 vector update covering the new `holder_proof` payload structure, `audit_context` field, and policy-profile canonical forms is pending; the reference implementation's full test suite (`tests/`) exercises the v1.4 paths in the meantime.

**Stage 2 evidence trail.** Phase A (D4) confirmed H1-H5 on v0.7 with 347/348 cross-machine cell agreement. Phase B + B-2 (D5) recorded 0 real findings across three independent LLM adversaries × 5 Gap-B coverage cells × 210 iterations on v0.7. Formal verification (D2 / Tamarin Run 3) closes the one remaining falsified lemma on v0.8. Re-run of Phase A/B/B-2 on v0.8 is scheduled and predicted to maintain v0.7's results, as v0.8 is a strict strengthening of v0.7's substrate.

---

## 20. Security Considerations (new in v1.4)

This section is normative for v1.4 and informs implementations of the threat model PACT is designed against, the cryptographic assumptions it depends on, and the limitations it does not claim to address. The pre-registered Stage 2 methodology (`PACT_RESEARCH_PLAN.md`) and the deliverables it produced (D1, D4, D5, D6) are the empirical evidence for this section.

### 20.1 Threat model

PACT v1.4 is designed against:

* **A Dolev-Yao network attacker** with the standard capabilities (intercept, modify, replay, drop, inject network messages; cannot break cryptographic primitives). This is the attacker model used by Tamarin (`spec/models/pact_core_v0_8.spthy`) and ProVerif (`spec/models/pact_opaque.pv`).
* **An LLM-driven semantic adversary** running the agent at one or both ends of a PACT exchange. The LLM may produce arbitrary application-layer content; PACT's substrate operates below this layer (signature verification cannot be reached through prompt manipulation). D5 records empirical evidence across three independent LLM adversaries (gemma4:e4b, gemma3:12b, Qwen3-235B) producing 0 real findings across 210 iterations on v0.7.
* **A maliciously-instructed delegating agent** (DELEG-MAL). Mitigated by Bug 9 chain-walk re-derivation (§16) and the bilateral-receipt requirement (§18.6).
* **A peer-malicious agent** (PEER-MAL). Mitigated by holder-binding (§18.1) and capability attenuation (§5.2).
* **A Sybil adversary attempting to forge `agent_id`**. Mitigated by self-certifying identity (§4.1) and SHA-256 collision resistance (§20.4).

### 20.2 Out-of-scope concerns (deliberate)

PACT explicitly does NOT address:

* **Confidentiality of message contents.** The wire is signed but plaintext (§9). Implementations needing confidentiality MUST run PACT over an encrypted transport (HTTPS, Noise) but the substrate does not require it. Listed in `D1_threat_coverage_matrix.md` Gap class A as a documented limitation.
* **Content sanitization of LLM outputs.** PACT signs whatever bytes the application produces; what those bytes mean to a downstream LLM is outside the substrate's scope. Empirical evidence: Phase A S-tier probes (S1-S6) confirm that 100% of LLM-emitted byte sequences pass through the substrate opaquely.
* **Runtime cost enforcement.** §10 C4 lists this as a v0.8 hardening item. The current `budget_cents` caveat (§18.4.1) is author-declared; runtime measurement and enforcement is out of scope.
* **Side-channel attacks on the Ed25519 implementation.** Library responsibility (e.g., libsodium / RustCrypto / Go x/crypto). PACT requires the library expose a constant-time signing primitive but does not validate this property.

### 20.3 Documented adversary-model limitations

The following are scenarios where PACT cannot defend against the attack class, by design:

* **Key compromise (KEY-COMP).** An attacker holding the legitimate private key can produce all the signatures the legitimate holder can. The substrate provides no defense against this; mitigation is key rotation (§18.5) or revocation. D5 Phase B records 0 real findings across the KEY-COMP × {P-AUTH, P-BIND} coverage cells, confirming the substrate behaves correctly (accepts the stolen-key adversary as legitimate, per the design).
* **Mutual collusion of all signers.** A bilateral receipt requires both parties to sign; if both parties are colluding, they can produce arbitrary receipts. PACT cannot distinguish honest from colluding signing.
* **Application-layer time skew beyond bounded skew tolerance.** `audit_context.expires_at` and `caveat.expires_at` are interpreted against the receiver's clock; receivers MAY tolerate up to 60 seconds of skew but MUST reject signatures more than 60 seconds in the future.

### 20.4 Cryptographic assumptions

PACT v1.4 depends on:

* **Ed25519 EUF-CMA security** (RFC 8032). Used for all signature operations.
* **SHA-256 collision resistance** (FIPS 180-4). Used for `agent_id` derivation (§4.1) and content hashing in caveats.
* **Canonical JSON determinism** (§3). Used to ensure that a given object always produces the same byte sequence for signing across implementations.
* **Ed25519 implementation constant-timeness.** The signing operation MUST NOT leak the private key via timing. This is the responsibility of the underlying library; PACT does not test for it.

A future failure of any of these assumptions (e.g., Ed25519 broken by post-quantum cryptanalysis, SHA-256 collisions become tractable) would necessitate a v2 substrate redesign, not a v1.x amendment.

### 20.5 Domain separation discipline

§18.1's `domain` field carries the literal strings `"pact/hp/v1"` and `"pact/visa/v1"`. The discipline:

* Each distinct signature class (holder_proof, visa-use, receipt, cap-chain-link, identity-doc-self-signature, REVOKE beacon, etc.) MUST sign over a canonical-JSON payload whose first field is `"domain"` with a literal string identifying the class and version.
* Two signature classes MUST NOT share a domain tag.
* When a signature class is extended in a way that changes the signed-payload structure, the domain version MUST bump (e.g., `"pact/hp/v1"` → `"pact/hp/v2"`).

This discipline is what enables Tamarin to prove P_BIND on v1.4 (`pact_core_v0_8.spthy`) and what protects against the class of cross-context-replay attacks that the v0.7 falsification trace exhibited.

### 20.6 Revocation freshness

A revocation record's effect is monotonic — once revoked, always revoked from that timestamp forward. However, propagation of the revocation between agents is bounded:

* The v0.8 REVOKE beacon mechanism (separate spec, post-v1.4) SHOULD propagate revocations to all subscribed peers within 60 seconds of revocation issuance.
* Receivers MAY cache revocation records for up to 5 minutes between fetches to a revocation oracle.
* A receiver that has not consulted a revocation oracle within the cache window MAY accept a REQ whose signer was revoked outside that window, then later emit a cancelled receipt (§14.9) on observing the revocation.

This means there is a 5-minute (worst case) window in which a revoked key can still produce accepted signatures. Bilateral receipts make this window auditable: a third party reviewing the receipts can detect signatures produced after the revocation timestamp.

### 20.7 Bilateral-receipt non-repudiation

A bilateral receipt (§18.6) is non-repudiable in the standard cryptographic sense iff:

1. Both signatures verify under their claimed signers' valid (non-revoked, within-window) keys, AND
2. The receipt's `audit_context.expires_at` is in the past at the time of audit (the receipt has run its course).

A receipt missing either signature is *not* a non-repudiable artifact and SHOULD NOT be presented as audit evidence between distrustful parties.

A receipt produced after one party's key has been revoked (§20.6) is non-repudiable only if the revocation post-dates the receipt; otherwise the receipt is suspect.

### 20.8 Implementation hardening checklist

This checklist is informative. Implementations claiming v1.4 conformance SHOULD verify all of the following:

* [ ] Ed25519 implementation is constant-time (verified externally — e.g., libsodium documentation, RustCrypto audit, Go x/crypto release notes).
* [ ] Canonical JSON implementation matches §3 byte-for-byte against the published test vectors.
* [ ] All `holder_proof` signing sites compute over the §18.1 structured payload — verified by running the negative-control probe (`probe_attr_bind_xmachine.py` or equivalent) and confirming the substrate rejects with `pact_holder_proof_invalid`.
* [ ] All REQ producers emit non-empty `audit_context` with all four required fields.
* [ ] All REQ receivers reject malformed `audit_context` with `pact_token_malformed`.
* [ ] All RES producers emit receiver-signature; all RES consumers emit initiator-ack-signature when in bilateral mode.
* [ ] Identity-document parser handles both legacy single-key and v1.4 `public_keys` array forms.
* [ ] Revocation cache respects the 5-minute upper bound (§20.6).
* [ ] All 12 catalogued attack scenarios (§18.8 / `spec/attacks/attacks.json`) produce the predicted fault codes when run against the implementation.

Formal verification status: Tamarin Run 3 verifies the v1.4 design under the Dolev-Yao + perfect-cryptography assumptions. The implementation hardening checklist above bridges from the formal proof to the deployed code.
