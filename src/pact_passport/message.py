"""PACT messages: REQ and RES.

Only two message types. Everything else is a payload within REQ/RES.

v1.4 / v0.8 changes (spec §18.1, §18.2):
  - ``holder_proof`` signature MUST be over the structured canonical-JSON
    payload ``{"domain":"pact/hp/v1", "req_id":..., "cap_id":..., "to_agent":...}``
    instead of the bare ``msg.id`` bytes used in v0.7. This closes the P_BIND
    falsification trace from Tamarin Run 2 (spec/models/PROOF_LOG.md Finding #1).
    Verified by Tamarin Run 3 (spec/models/pact_core_v0_8.spthy).
  - REQ messages MUST carry a structured ``audit_context`` field with required
    keys (``purpose``, ``request_id``, ``audience_hint``, ``expires_at``).
  - Migration window: pre-v1.4 ``holder_proof`` (bare ``msg.id`` bytes) is
    accepted for 90 days from v1.4 release with a ``DeprecationWarning``.
    See ``verify_holder_proof()``'s ``allow_legacy_v07`` parameter.
"""

from __future__ import annotations

import base64
import binascii
import uuid
import warnings
from datetime import datetime, timedelta, UTC
from dataclasses import dataclass, field

from pact_passport import crypto
from pact_passport._canonical import canonical_json


# ---------------------------------------------------------------------------
# v1.4 / v0.8 domain separation tags (spec §18.1, §20.5)
# ---------------------------------------------------------------------------

HOLDER_PROOF_DOMAIN_V1 = "pact/hp/v1"
"""Domain tag for non-visa holder_proof signatures (spec §18.1)."""

VISA_USE_DOMAIN_V1 = "pact/visa/v1"
"""Domain tag for visa-use holder_proof signatures (spec §18.1).

Distinct from ``HOLDER_PROOF_DOMAIN_V1`` so the two signature classes
are structurally non-substitutable. This is what closes the P_BIND
falsification trace from Tamarin Run 2.
"""


def holder_proof_payload(req_id: str, cap_id: str | None, to_agent: str) -> bytes:
    """Return the canonical-JSON bytes that v1.4 ``holder_proof`` MUST sign over.

    Per spec §18.1, the signed payload is::

        {"domain": "pact/hp/v1", "req_id": "<uuid>", "cap_id": "<uuid or ''>", "to_agent": "<aid>"}

    canonical-JSON serialization sorts keys lexicographically. The same
    function is used on both the sign side (build_req) and the verify side
    (verify_holder_proof), so the byte sequences match exactly.

    cap_id of ``None`` is normalized to the empty string ``""`` for
    canonicalization stability (no spec rule against caps-less REQs at
    the signing layer; the cap-presence check happens elsewhere).
    """
    return canonical_json({
        "domain": HOLDER_PROOF_DOMAIN_V1,
        "req_id": req_id,
        "cap_id": cap_id if cap_id is not None else "",
        "to_agent": to_agent,
    })


def visa_use_payload(nonce: str) -> bytes:
    """Return the canonical-JSON bytes that v1.4 visa-use holder_proof MUST sign over.

    Per spec §18.1, the signed payload is::

        {"domain": "pact/visa/v1", "nonce": "<sha256:...>"}

    The ``domain`` value is distinct from ``HOLDER_PROOF_DOMAIN_V1``,
    making the two signature classes (visa-use vs. non-visa holder_proof)
    structurally non-substitutable. This is the closure of the v0.7
    P_BIND falsification trace.
    """
    return canonical_json({
        "domain": VISA_USE_DOMAIN_V1,
        "nonce": nonce,
    })


@dataclass
class PACTMessage:
    """A PACT protocol message (REQ, RES, or RES_CHUNK)."""
    id: str
    type: str  # "REQ", "RES", or "RES_CHUNK"
    from_agent: str  # agent_id
    to_agent: str  # agent_id
    refs: list[str] = field(default_factory=list)
    intent: str = ""  # "identity", "discover", "task"
    cap_id: str | None = None
    holder_proof: str | None = None  # base64-encoded
    deadline: str | None = None  # ISO 8601
    idempotency_key: str | None = None
    payload: dict = field(default_factory=dict)
    status: str | None = None  # "ok" or "error" (RES only)
    fault: dict | None = None  # (RES only)
    # Streaming fields (RES_CHUNK only). Issue #11. Each chunk is a
    # complete signed PACTMessage; chunk_seq is monotonic (0, 1, 2, ...);
    # chunk_final marks the terminal chunk in the stream. The REQ that
    # triggered streaming has stream=True.
    stream: bool | None = None  # REQ only — opt-in to streaming response
    chunk_seq: int | None = None  # RES_CHUNK only
    chunk_final: bool | None = None  # RES_CHUNK only
    # Trust-on-first-use field. When the receiver doesn't have the sender
    # in its peer cache, an inline identity_doc lets it verify the sender
    # ad-hoc: agent_id must derive from the doc's public_key, and the
    # message signature must verify against that key. Issue #2.
    identity_doc: dict | None = None
    # Capability envelope. When the sender presents a cap_id the receiver
    # doesn't have locally, an inline cap_envelope (the full cap dict)
    # lets the receiver verify the delegation chain and cache the cap.
    # Required for cross-machine delegation (A→B→C). Issue #10.
    cap_envelope: dict | None = None
    # Structured audit context (v1.4 / spec §18.2). Required on REQ messages.
    # Keys: ``purpose`` (string), ``request_id`` (uuid), ``audience_hint``
    # (must equal ``to_agent``), ``expires_at`` (ISO 8601). The field is
    # included in the canonical-JSON payload that the outer envelope
    # signature covers, so tampering with audit_context is signature-
    # detected. Migration window: v1.4 receivers SHOULD synthesize a
    # placeholder for v0.7 REQs lacking the field (§18.7).
    audit_context: dict | None = None
    alg: str = crypto.ALG
    signature: str = ""  # base64-encoded

    def to_dict(self) -> dict:
        d: dict = {
            "id": self.id,
            "type": self.type,
            "from_agent": self.from_agent,
            "to_agent": self.to_agent,
            "refs": self.refs,
            "intent": self.intent,
            "alg": self.alg,
            "signature": self.signature,
        }
        if self.cap_id is not None:
            d["cap_id"] = self.cap_id
        if self.holder_proof is not None:
            d["holder_proof"] = self.holder_proof
        if self.deadline is not None:
            d["deadline"] = self.deadline
        if self.idempotency_key is not None:
            d["idempotency_key"] = self.idempotency_key
        if self.payload:
            d["payload"] = self.payload
        if self.status is not None:
            d["status"] = self.status
        if self.fault is not None:
            d["fault"] = self.fault
        if self.identity_doc is not None:
            d["identity_doc"] = self.identity_doc
        if self.cap_envelope is not None:
            d["cap_envelope"] = self.cap_envelope
        if self.audit_context is not None:
            d["audit_context"] = self.audit_context
        if self.stream is not None:
            d["stream"] = self.stream
        if self.chunk_seq is not None:
            d["chunk_seq"] = self.chunk_seq
        if self.chunk_final is not None:
            d["chunk_final"] = self.chunk_final
        return d

    @classmethod
    def from_dict(cls, d: dict) -> PACTMessage:
        return cls(
            id=d["id"],
            type=d["type"],
            from_agent=d["from_agent"],
            to_agent=d["to_agent"],
            refs=d.get("refs", []),
            intent=d.get("intent", ""),
            cap_id=d.get("cap_id"),
            holder_proof=d.get("holder_proof"),
            deadline=d.get("deadline"),
            idempotency_key=d.get("idempotency_key"),
            payload=d.get("payload", {}),
            status=d.get("status"),
            fault=d.get("fault"),
            identity_doc=d.get("identity_doc"),
            cap_envelope=d.get("cap_envelope"),
            audit_context=d.get("audit_context"),
            stream=d.get("stream"),
            chunk_seq=d.get("chunk_seq"),
            chunk_final=d.get("chunk_final"),
            alg=d.get("alg", crypto.ALG),
            signature=d.get("signature", ""),
        )

    def signable_dict(self) -> dict:
        """Dict for signing (everything except signature)."""
        d = self.to_dict()
        d.pop("signature", None)
        return d


def build_req(
    from_private_key: bytes,
    from_id: str,
    to_id: str,
    intent: str,
    payload: dict | None = None,
    cap_id: str | None = None,
    holder_proof_key: bytes | None = None,
    deadline_seconds: int = 30,
    refs: list[str] | None = None,
    identity_doc: dict | None = None,
    cap_envelope: dict | None = None,
    stream: bool = False,
    audit_context: dict | None = None,
    audit_purpose: str = "task",
) -> PACTMessage:
    """Build and sign a v1.4 / v0.8 REQ message.

    Args:
        audit_context: Optional structured audit context per spec §18.2.
            If None, this function synthesizes a v1.4-compliant audit_context
            from the message's own fields (request_id = msg.id,
            audience_hint = to_id, expires_at = deadline, purpose =
            ``audit_purpose``).
        audit_purpose: The ``purpose`` value to use when synthesizing
            audit_context. Defaults to ``"task"``. Other recommended
            values per spec §18.2: ``"delegation-step"``, ``"tool-call"``,
            ``"audit-export"``, ``"revocation-broadcast"``,
            ``"research-subtask"``, ``"system"``.

    Holder proof (spec §18.1): when ``holder_proof_key`` is provided, this
    function signs the canonical-JSON of ``{"domain":"pact/hp/v1", "req_id":
    msg.id, "cap_id": cap_id or "", "to_agent": to_id}`` with the holder's
    key. This is the v0.8 domain-separated signing string; it is structurally
    distinct from the v0.7 bare-``msg.id`` form and from the visa-use
    domain-separated form (``pact/visa/v1``). Tamarin Run 3 verifies
    P_BIND under this structure.

    Set stream=True to request a streaming response (RES_CHUNK sequence
    instead of single RES). The handler on the receiver side must yield
    chunks for streaming to actually happen; otherwise it falls back to
    a normal one-shot RES.
    """
    msg_id = str(uuid.uuid4())
    deadline = (datetime.now(UTC) + timedelta(seconds=deadline_seconds)).isoformat()

    # If a cap_envelope was supplied without an explicit cap_id, derive
    # cap_id from the envelope. Without this, the receiver's cap
    # verification step is silently skipped (see _step_verify_capability)
    # — the envelope is just along for the ride. Sending a cap and
    # expecting it to be enforced should not require the caller to
    # remember to also set cap_id.
    if cap_envelope is not None and cap_id is None:
        env_cap_id = cap_envelope.get("cap_id")
        if not env_cap_id:
            raise ValueError(
                "cap_envelope is missing 'cap_id'. Either pass an explicit "
                "cap_id or include a valid cap_envelope dict (with cap_id) "
                "as produced by CapabilityToken.to_dict()."
            )
        cap_id = env_cap_id

    # Synthesize audit_context if not provided (spec §18.2). This ensures
    # all v1.4 REQs emitted by build_req() carry a non-empty audit_context.
    # Callers who want a different purpose tag or non-default request_id
    # MAY pass an explicit dict.
    if audit_context is None:
        audit_context = {
            "purpose": audit_purpose,
            "request_id": msg_id,
            "audience_hint": to_id,
            "expires_at": deadline,
        }
    else:
        # Validate that the caller-supplied audit_context has all four
        # required keys (spec §18.2). audience_hint MUST match to_id.
        required = {"purpose", "request_id", "audience_hint", "expires_at"}
        missing = required - set(audit_context)
        if missing:
            raise ValueError(
                f"audit_context missing required keys: {sorted(missing)} "
                f"(spec §18.2)"
            )
        if audit_context.get("audience_hint") != to_id:
            raise ValueError(
                f"audit_context.audience_hint ({audit_context.get('audience_hint')!r}) "
                f"must equal to_id ({to_id!r}) per spec §18.2"
            )

    msg = PACTMessage(
        id=msg_id,
        type="REQ",
        from_agent=from_id,
        to_agent=to_id,
        refs=refs or [],
        intent=intent,
        cap_id=cap_id,
        deadline=deadline,
        idempotency_key=str(uuid.uuid4()),
        payload=payload or {},
        identity_doc=identity_doc,
        cap_envelope=cap_envelope,
        audit_context=audit_context,
        stream=stream if stream else None,  # only include when True
    )

    # Holder proof (spec §18.1): sign over the structured canonical-JSON
    # payload, not the bare msg_id. The structured payload binds (req_id,
    # cap_id, to_agent) so that a signature for one tuple cannot be replayed
    # for another. The 'pact/hp/v1' domain tag distinguishes this from the
    # visa-use signing string ('pact/visa/v1'). Tamarin Run 3 proves P_BIND
    # under this structure.
    if holder_proof_key:
        proof_sig = crypto.sign(
            holder_proof_payload(msg_id, cap_id, to_id),
            holder_proof_key,
        )
        msg.holder_proof = base64.b64encode(proof_sig).decode("ascii")

    # Sign the whole message envelope (includes audit_context now)
    sig = crypto.sign(canonical_json(msg.signable_dict()), from_private_key)
    msg.signature = base64.b64encode(sig).decode("ascii")

    return msg


def build_res(
    from_private_key: bytes,
    from_id: str,
    req: PACTMessage,
    payload: dict | None = None,
    status: str = "ok",
    fault: dict | None = None,
) -> PACTMessage:
    """Build and sign a RES message in response to a REQ."""
    msg = PACTMessage(
        id=str(uuid.uuid4()),
        type="RES",
        from_agent=from_id,
        to_agent=req.from_agent,
        refs=[req.id],
        intent=req.intent,
        payload=payload or {},
        status=status,
        fault=fault,
    )

    sig = crypto.sign(canonical_json(msg.signable_dict()), from_private_key)
    msg.signature = base64.b64encode(sig).decode("ascii")

    return msg


def build_res_chunk(
    from_private_key: bytes,
    from_id: str,
    req: PACTMessage,
    chunk_seq: int,
    chunk_final: bool,
    payload: dict | None = None,
    status: str = "ok",
    fault: dict | None = None,
) -> PACTMessage:
    """Build and sign one RES_CHUNK in response to a streaming REQ.

    Each chunk is a fully-formed signed PACTMessage. chunk_seq is
    monotonic (0, 1, 2, ...). chunk_final marks the terminal chunk.
    Both fields are part of the signed bytes — tampering with either
    invalidates the chunk's signature.
    """
    msg = PACTMessage(
        id=str(uuid.uuid4()),
        type="RES_CHUNK",
        from_agent=from_id,
        to_agent=req.from_agent,
        refs=[req.id],
        intent=req.intent,
        payload=payload or {},
        status=status,
        fault=fault,
        chunk_seq=chunk_seq,
        chunk_final=chunk_final,
    )
    sig = crypto.sign(canonical_json(msg.signable_dict()), from_private_key)
    msg.signature = base64.b64encode(sig).decode("ascii")
    return msg


def verify_message(msg: PACTMessage, sender_public_key: bytes) -> bool:
    """Verify a message's signature.

    Returns False on malformed base64 in the signature field rather than
    propagating binascii.Error. Pre-v0.5.3 a malformed signature crashed
    the dispatcher; now it fails-closed as a normal verification failure.
    """
    try:
        sig_bytes = base64.b64decode(msg.signature)
    except (binascii.Error, ValueError, TypeError):
        return False
    return crypto.verify(canonical_json(msg.signable_dict()), sig_bytes, sender_public_key)


def verify_holder_proof(
    msg: PACTMessage,
    holder_public_key: bytes,
    allow_legacy_v07: bool = True,
) -> bool:
    """Verify the holder_proof in a REQ message.

    v1.4 / v0.8 (spec §18.1): the holder_proof signature is over the
    canonical-JSON payload produced by ``holder_proof_payload(msg.id,
    msg.cap_id, msg.to_agent)``. The signed payload structure is::

        {"domain": "pact/hp/v1", "req_id": <uuid>, "cap_id": <uuid or "">, "to_agent": <aid>}

    Args:
        msg: The PACT REQ message to verify.
        holder_public_key: The holder's Ed25519 public key.
        allow_legacy_v07: If True, also accept v0.7 bare-``msg.id``
            signatures during the 90-day migration window (spec §18.7).
            Emits a ``DeprecationWarning`` when a legacy signature is
            accepted. After the migration window closes, this argument
            SHOULD be set False so legacy signatures are rejected with
            ``pact_holder_proof_invalid``.

    Returns False on malformed base64 (same fail-closed treatment as
    ``verify_message`` — see v0.5.3 honesty patch).
    """
    if not msg.holder_proof:
        return False
    try:
        proof_bytes = base64.b64decode(msg.holder_proof)
    except (binascii.Error, ValueError, TypeError):
        return False

    # v0.8 path: structured payload (default).
    v08_payload = holder_proof_payload(msg.id, msg.cap_id, msg.to_agent)
    if crypto.verify(v08_payload, proof_bytes, holder_public_key):
        return True

    # Migration window: try v0.7 bare-bytes form (spec §18.7).
    if allow_legacy_v07:
        if crypto.verify(msg.id.encode(), proof_bytes, holder_public_key):
            warnings.warn(
                "Accepting v0.7 bare-payload holder_proof. v1.4 receivers "
                "MUST reject this format after the migration window closes "
                "(spec §18.7). Update senders to v1.4 structured holder_proof "
                "(message.holder_proof_payload).",
                DeprecationWarning,
                stacklevel=2,
            )
            return True

    return False


def is_deadline_exceeded(msg: PACTMessage) -> bool:
    """Check if a REQ's deadline has passed."""
    if not msg.deadline:
        return False
    deadline = datetime.fromisoformat(msg.deadline)
    return datetime.now(UTC) > deadline
