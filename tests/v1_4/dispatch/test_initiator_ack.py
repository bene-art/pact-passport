"""δ.2.2 dispatch-integration tests for INITIATOR_ACK message type (spec §18.6).

Verifies the bilateral-receipt round-trip closure path:

1. Receiver writes a unilateral receipt for a task.
2. Initiator signs the receipt's canonical bytes (minus the
   initiator_ack_signature field) and sends INITIATOR_ACK to the receiver.
3. Receiver verifies the ack signature, merges it into the stored receipt,
   and the receipt is now bilateral per spec §18.6.

Faults exercised:
- pact_token_malformed (bad payload shape)
- pact_token_missing (no receipt for task_ref)
- pact_signature_invalid (bad envelope or ack signature)
- pact_identity_unresolvable (unknown sender, no identity_doc)
"""
from __future__ import annotations

import base64
import uuid

import pytest

from pact_passport import PACTAgent, PACTMessage, crypto
from pact_passport._canonical import canonical_json
from pact_passport.errors import (
    PACT_IDENTITY_UNRESOLVABLE,
    PACT_SIGNATURE_INVALID,
    PACT_TOKEN_MALFORMED,
    PACT_TOKEN_MISSING,
)
from pact_passport.receipt import create_receipt


# =============================================================================
# Helpers
# =============================================================================

class _Peer:
    def __init__(self):
        self.private_key, self.public_key = crypto.generate_keypair()
        pub_b64 = base64.b64encode(self.public_key).decode("ascii")
        self.agent_id = crypto.sha256_digest(f"{crypto.ALG}{pub_b64}".encode())
        self.identity_doc = {
            "agent_id": self.agent_id,
            "public_key": pub_b64,
            "alg": crypto.ALG,
        }


def _sign(msg: PACTMessage, private_key: bytes) -> dict:
    sig = crypto.sign(canonical_json(msg.signable_dict()), private_key)
    msg.signature = base64.b64encode(sig).decode("ascii")
    return msg.to_dict()


def _initiator_ack_msg(
    initiator: _Peer,
    receiver_id: str,
    *,
    task_ref: str,
    ack_sig_b64: str,
) -> dict:
    msg = PACTMessage(
        id=str(uuid.uuid4()),
        type="INITIATOR_ACK",
        from_agent=initiator.agent_id,
        to_agent=receiver_id,
        intent="bilateral-ack",
        payload={
            "task_ref": task_ref,
            "initiator_ack_signature": ack_sig_b64,
        },
        identity_doc=initiator.identity_doc,
    )
    return _sign(msg, initiator.private_key)


def _stored_unilateral_receipt(agent: PACTAgent, task_ref: str) -> dict:
    identity = agent._ensure_identity()
    receipt = create_receipt(
        private_key=identity._private_key,
        agent_id=identity.agent_id,
        task_ref=task_ref,
        refs=[task_ref],
        outcome="completed",
    )
    agent._store.save_receipt(agent.name, receipt)
    return receipt


@pytest.fixture
def receiver(tmp_path):
    agent = PACTAgent("receiver", store_dir=tmp_path / "recv")
    agent._ensure_identity()
    return agent


@pytest.fixture
def initiator():
    return _Peer()


# =============================================================================
# δ.2.2 — INITIATOR_ACK handler
# =============================================================================

def test_initiator_ack_happy_path_promotes_receipt_to_bilateral(receiver, initiator):
    """Valid ack signature → receipt mutates to include initiator_ack_signature."""
    receiver_id = receiver._ensure_identity().agent_id
    task_ref = "task-001"

    # Register initiator's key on the receiver via TOFU
    receiver._tofu_register(initiator.agent_id, initiator.identity_doc)

    # Store a unilateral receipt
    receipt = _stored_unilateral_receipt(receiver, task_ref)
    assert receipt.get("initiator_ack_signature") is None

    # Initiator signs the receipt's canonical bytes minus the ack field
    signable = {k: v for k, v in receipt.items() if k != "initiator_ack_signature"}
    ack_sig = crypto.sign(canonical_json(signable), initiator.private_key)
    ack_sig_b64 = base64.b64encode(ack_sig).decode("ascii")

    # Send INITIATOR_ACK
    ack_msg = _initiator_ack_msg(initiator, receiver_id,
                                 task_ref=task_ref, ack_sig_b64=ack_sig_b64)
    res = receiver._dispatch(ack_msg)

    assert res["status"] == "ok", res
    assert res["payload"]["bilateral"] is True
    assert res["payload"]["task_ref"] == task_ref

    # Stored receipt now has the ack signature merged in
    updated = next(r for r in receiver._store.list_receipts("receiver")
                   if r.get("task_ref") == task_ref)
    assert updated["initiator_ack_signature"] == ack_sig_b64


def test_initiator_ack_unknown_task_ref_returns_token_missing(receiver, initiator):
    """No receipt for the referenced task_ref → pact_token_missing."""
    receiver._tofu_register(initiator.agent_id, initiator.identity_doc)
    receiver_id = receiver._ensure_identity().agent_id

    ack_msg = _initiator_ack_msg(initiator, receiver_id,
                                 task_ref="task-missing", ack_sig_b64="abc")
    res = receiver._dispatch(ack_msg)
    assert res["status"] == "error", res
    assert res["fault"]["code"] == PACT_TOKEN_MISSING, res


def test_initiator_ack_malformed_payload_missing_task_ref(receiver, initiator):
    receiver._tofu_register(initiator.agent_id, initiator.identity_doc)
    receiver_id = receiver._ensure_identity().agent_id

    msg = PACTMessage(
        id=str(uuid.uuid4()),
        type="INITIATOR_ACK",
        from_agent=initiator.agent_id,
        to_agent=receiver_id,
        payload={"initiator_ack_signature": "abc"},  # missing task_ref
        identity_doc=initiator.identity_doc,
    )
    ack_msg = _sign(msg, initiator.private_key)
    res = receiver._dispatch(ack_msg)
    assert res["status"] == "error", res
    assert res["fault"]["code"] == PACT_TOKEN_MALFORMED, res


def test_initiator_ack_malformed_payload_missing_signature(receiver, initiator):
    receiver._tofu_register(initiator.agent_id, initiator.identity_doc)
    receiver_id = receiver._ensure_identity().agent_id

    msg = PACTMessage(
        id=str(uuid.uuid4()),
        type="INITIATOR_ACK",
        from_agent=initiator.agent_id,
        to_agent=receiver_id,
        payload={"task_ref": "task-001"},  # missing initiator_ack_signature
        identity_doc=initiator.identity_doc,
    )
    ack_msg = _sign(msg, initiator.private_key)
    res = receiver._dispatch(ack_msg)
    assert res["status"] == "error", res
    assert res["fault"]["code"] == PACT_TOKEN_MALFORMED, res


def test_initiator_ack_bad_ack_signature(receiver, initiator):
    """Wrong-content ack signature → pact_signature_invalid."""
    receiver._tofu_register(initiator.agent_id, initiator.identity_doc)
    receiver_id = receiver._ensure_identity().agent_id

    _stored_unilateral_receipt(receiver, "task-001")

    # Sign the WRONG content
    bad_sig = crypto.sign(b"not the receipt bytes", initiator.private_key)
    bad_sig_b64 = base64.b64encode(bad_sig).decode("ascii")

    ack_msg = _initiator_ack_msg(initiator, receiver_id,
                                 task_ref="task-001", ack_sig_b64=bad_sig_b64)
    res = receiver._dispatch(ack_msg)
    assert res["status"] == "error", res
    assert res["fault"]["code"] == PACT_SIGNATURE_INVALID, res


def test_initiator_ack_malformed_base64(receiver, initiator):
    receiver._tofu_register(initiator.agent_id, initiator.identity_doc)
    receiver_id = receiver._ensure_identity().agent_id

    _stored_unilateral_receipt(receiver, "task-001")

    ack_msg = _initiator_ack_msg(initiator, receiver_id,
                                 task_ref="task-001",
                                 ack_sig_b64="not_valid_base64_!@#$%^")
    res = receiver._dispatch(ack_msg)
    assert res["status"] == "error", res
    assert res["fault"]["code"] == PACT_SIGNATURE_INVALID, res


def test_initiator_ack_unknown_sender_no_identity_doc(receiver, initiator):
    """Unknown sender without identity_doc → pact_identity_unresolvable."""
    receiver_id = receiver._ensure_identity().agent_id
    _stored_unilateral_receipt(receiver, "task-001")

    # Build a properly-signed but no-identity-doc message
    msg = PACTMessage(
        id=str(uuid.uuid4()),
        type="INITIATOR_ACK",
        from_agent=initiator.agent_id,
        to_agent=receiver_id,
        payload={"task_ref": "task-001", "initiator_ack_signature": "x"},
        identity_doc=None,  # explicitly no identity_doc
    )
    ack_msg = _sign(msg, initiator.private_key)

    res = receiver._dispatch(ack_msg)
    assert res["status"] == "error", res
    assert res["fault"]["code"] == PACT_IDENTITY_UNRESOLVABLE, res


def test_initiator_ack_idempotent_on_already_bilateral_receipt(receiver, initiator):
    """Sending the SAME ack twice → second call returns idempotent=True without
    re-mutating the receipt."""
    receiver._tofu_register(initiator.agent_id, initiator.identity_doc)
    receiver_id = receiver._ensure_identity().agent_id

    receipt = _stored_unilateral_receipt(receiver, "task-001")
    signable = {k: v for k, v in receipt.items() if k != "initiator_ack_signature"}
    ack_sig = crypto.sign(canonical_json(signable), initiator.private_key)
    ack_sig_b64 = base64.b64encode(ack_sig).decode("ascii")

    # First call promotes to bilateral
    ack_msg = _initiator_ack_msg(initiator, receiver_id,
                                 task_ref="task-001", ack_sig_b64=ack_sig_b64)
    res1 = receiver._dispatch(ack_msg)
    assert res1["status"] == "ok"
    assert res1["payload"]["bilateral"] is True
    assert "idempotent" not in res1["payload"] or not res1["payload"].get("idempotent")

    # Second call with the same ack — idempotent OK
    ack_msg2 = _initiator_ack_msg(initiator, receiver_id,
                                  task_ref="task-001", ack_sig_b64=ack_sig_b64)
    res2 = receiver._dispatch(ack_msg2)
    assert res2["status"] == "ok"
    assert res2["payload"]["bilateral"] is True
    assert res2["payload"]["idempotent"] is True


def test_initiator_ack_after_audit_receipt_passes_bilateral_check(receiver, initiator):
    """End-to-end: stored unilateral receipt → ack → audit_receipt now passes."""
    from pact_passport.audit import audit_receipt

    receiver._tofu_register(initiator.agent_id, initiator.identity_doc)
    receiver_id = receiver._ensure_identity().agent_id

    receipt = _stored_unilateral_receipt(receiver, "task-001")

    # Pre-ack: audit flags as non-bilateral
    pre = audit_receipt(receipt, receiver_public_key=receiver._ensure_identity().public_key)
    assert not pre.passed
    pre_codes = [c for c, _ in pre.errors]
    assert "pact_receipt_not_bilateral" in pre_codes

    # Send ack
    signable = {k: v for k, v in receipt.items() if k != "initiator_ack_signature"}
    ack_sig = crypto.sign(canonical_json(signable), initiator.private_key)
    ack_sig_b64 = base64.b64encode(ack_sig).decode("ascii")
    ack_msg = _initiator_ack_msg(initiator, receiver_id,
                                 task_ref="task-001", ack_sig_b64=ack_sig_b64)
    receiver._dispatch(ack_msg)

    # Post-ack: receipt now carries initiator_ack_signature
    updated = next(r for r in receiver._store.list_receipts("receiver")
                   if r.get("task_ref") == "task-001")
    assert "initiator_ack_signature" in updated

    # audit_receipt with initiator's pubkey verifies it bilaterally
    post = audit_receipt(updated,
                        receiver_public_key=receiver._ensure_identity().public_key,
                        initiator_public_key=initiator.public_key)
    assert post.passed, post.errors
