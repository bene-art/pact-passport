"""PACT messages: REQ and RES.

Only two message types. Everything else is a payload within REQ/RES.
"""

from __future__ import annotations

import base64
import uuid
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field

from pact import crypto
from pact._canonical import canonical_json


@dataclass
class PACTMessage:
    """A PACT protocol message (REQ or RES)."""
    id: str
    type: str  # "REQ" or "RES"
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
) -> PACTMessage:
    """Build and sign a REQ message."""
    msg_id = str(uuid.uuid4())
    deadline = (datetime.now(timezone.utc) + timedelta(seconds=deadline_seconds)).isoformat()

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
    )

    # Holder proof: sign the message ID with the holder's key
    if holder_proof_key:
        proof_sig = crypto.sign(msg_id.encode(), holder_proof_key)
        msg.holder_proof = base64.b64encode(proof_sig).decode("ascii")

    # Sign the whole message
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


def verify_message(msg: PACTMessage, sender_public_key: bytes) -> bool:
    """Verify a message's signature."""
    sig_bytes = base64.b64decode(msg.signature)
    return crypto.verify(canonical_json(msg.signable_dict()), sig_bytes, sender_public_key)


def verify_holder_proof(msg: PACTMessage, holder_public_key: bytes) -> bool:
    """Verify the holder_proof in a REQ message."""
    if not msg.holder_proof:
        return False
    proof_bytes = base64.b64decode(msg.holder_proof)
    return crypto.verify(msg.id.encode(), proof_bytes, holder_public_key)


def is_deadline_exceeded(msg: PACTMessage) -> bool:
    """Check if a REQ's deadline has passed."""
    if not msg.deadline:
        return False
    deadline = datetime.fromisoformat(msg.deadline)
    return datetime.now(timezone.utc) > deadline
