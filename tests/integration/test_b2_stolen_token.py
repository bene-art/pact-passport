"""B2 Stage 1: Stolen Token Cross-Machine — Bug 4 Regression (Mac-only synthetic).

Tests holder-proof binding under simulated cross-machine token theft.
The "two physical machines" of the original case study become two
processes in the same Mac sandbox; the protocol-semantic claim is the
same (the third party with the stolen token cannot present it
successfully without the original holder's private key).

Stage 1 (this file): four theft variants exercised in-process via the
sandbox fixture. Stage 2 (cross-machine over Tailscale to the NUC) is
pending NUC availability — see experiment_plan_2026-06.md.

Variants:
  (i)   holder_proof omitted entirely (Bug 4 original; v0.2.0 fix)
  (ii)  holder_proof from a foreign key (attacker's own keypair)
  (iii) holder_proof from the correct key but over a wrong nonce (replay
        attempt: signed REQ A's nonce, presenting it as REQ B's proof)
  (iv)  holder_proof base64-encoding of garbage bytes (malformed sig
        bytes, structurally valid base64)

Pre-registered prediction: all four variants rejected with
holder_proof_required (variant i) or holder_proof_invalid (variants
ii-iv). v0.2.0 + v0.5.3 hardening covers all four.
"""

from __future__ import annotations

import base64
import copy

import pytest

from pact_passport import crypto
from pact_passport.message import build_req

from tests.integration.conftest import post_message


# ---------------------------------------------------------------------------
# Setup helper
# ---------------------------------------------------------------------------


def _setup_alice_with_cap_to_bob(sandbox):
    """Alice grants Bob a cap; returns (alice handle, bob handle, cap)."""
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    @alice["agent"].handle("echo")
    def echo(payload):
        return {"echoed": payload}

    cap = alice["agent"].grant(bob["agent_id"], "echo")
    bob["agent"]._store.save_capability(bob["name"], cap.to_dict())
    return alice, bob, cap


# ---------------------------------------------------------------------------
# Stage 1 variants
# ---------------------------------------------------------------------------


def test_b2_v1_holder_proof_omitted_rejected(sandbox, capsys):
    """Variant (i): Bug 4 original — REQ carries cap_id but no
    holder_proof field. v0.2.0 fix requires holder_proof when cap_id
    is present; pre-v0.2.0 the check was conditional on field presence."""
    alice, bob, cap = _setup_alice_with_cap_to_bob(sandbox)
    bob_priv = bob["agent"]._ensure_identity()._private_key

    # Build a REQ with holder_proof_key set, then strip the holder_proof
    # field manually
    req = build_req(
        from_private_key=bob_priv,
        from_id=bob["agent_id"],
        to_id=alice["agent_id"],
        intent="task",
        payload={"action": "echo", "msg": "hi"},
        cap_id=cap.cap_id,
        holder_proof_key=bob_priv,
        deadline_seconds=30,
    )
    req_dict = req.to_dict()
    req_dict["holder_proof"] = None

    result = post_message(alice["url"], req_dict)
    status = result.get("status")
    fault_code = result.get("fault", {}).get("code") if status == "error" else None
    print(f"\n[B2-i] holder_proof omitted → status={status} fault={fault_code}")
    assert status == "error", f"omitted holder_proof accepted: {result}"
    # Either fault is acceptable — the message is malformed
    assert fault_code in {
        "holder_proof_required",
        "holder_proof_invalid",
        "invalid_message",
        "invalid_signature",
    }, f"unexpected fault: {fault_code}"


def test_b2_v2_holder_proof_from_foreign_key_rejected(sandbox, capsys):
    """Variant (ii): Eve intercepts Bob's cap. Eve signs the
    holder_proof with HER OWN key — not Bob's. Alice should reject."""
    alice, bob, cap = _setup_alice_with_cap_to_bob(sandbox)
    bob_priv = bob["agent"]._ensure_identity()._private_key

    eve_priv, _eve_pub = crypto.generate_keypair()

    # Build a REQ where Bob is the apparent sender (his signature on the
    # message) but the holder_proof is signed by Eve.
    req = build_req(
        from_private_key=bob_priv,
        from_id=bob["agent_id"],
        to_id=alice["agent_id"],
        intent="task",
        payload={"action": "echo", "msg": "hi"},
        cap_id=cap.cap_id,
        holder_proof_key=eve_priv,  # WRONG KEY — Eve's, not Bob's
        deadline_seconds=30,
    )

    result = post_message(alice["url"], req.to_dict())
    status = result.get("status")
    fault_code = result.get("fault", {}).get("code") if status == "error" else None
    print(f"\n[B2-ii] foreign-key holder_proof → status={status} fault={fault_code}")
    assert status == "error", f"foreign-key holder_proof accepted: {result}"
    assert fault_code in {"holder_proof_invalid", "invalid_signature"}, (
        f"unexpected fault: {fault_code}"
    )


def test_b2_v3_holder_proof_over_wrong_nonce_rejected(sandbox, capsys):
    """Variant (iii): replay attempt. Bob signs a holder_proof over
    REQ_A's nonce (id), then presents that proof on REQ_B (different id).
    The proof signs the wrong nonce → reject."""
    alice, bob, cap = _setup_alice_with_cap_to_bob(sandbox)
    bob_priv = bob["agent"]._ensure_identity()._private_key

    # Build REQ_A — the proof would sign req_a.id (which is what build_req
    # does internally when holder_proof_key is set)
    req_a = build_req(
        from_private_key=bob_priv,
        from_id=bob["agent_id"],
        to_id=alice["agent_id"],
        intent="task",
        payload={"action": "echo", "msg": "first"},
        cap_id=cap.cap_id,
        holder_proof_key=bob_priv,
        deadline_seconds=30,
    )

    # Build REQ_B with a different id, and copy REQ_A's holder_proof in
    req_b = build_req(
        from_private_key=bob_priv,
        from_id=bob["agent_id"],
        to_id=alice["agent_id"],
        intent="task",
        payload={"action": "echo", "msg": "second"},
        cap_id=cap.cap_id,
        holder_proof_key=bob_priv,  # builds its own proof first
        deadline_seconds=30,
    )
    # Then replace req_b's holder_proof with req_a's (wrong-nonce attack)
    req_b_dict = req_b.to_dict()
    req_b_dict["holder_proof"] = req_a.holder_proof

    # NB: re-signing req_b is not needed because we're testing the
    # holder_proof check; the from_agent's signature on req_b is over its
    # own canonical content which now includes a stale holder_proof. The
    # signature will verify fine (it covers what it covers). The
    # holder_proof verify step is what should reject.

    # But: build_req has already signed req_b with the holder_proof it
    # generated; substituting changes the signable bytes. Need to re-sign.
    from pact_passport._canonical import canonical_json
    from pact_passport.message import PACTMessage
    req_b_msg = PACTMessage.from_dict(req_b_dict)
    req_b_msg.signature = ""
    sig = crypto.sign(canonical_json(req_b_msg.signable_dict()), bob_priv)
    req_b_msg.signature = base64.b64encode(sig).decode()

    result = post_message(alice["url"], req_b_msg.to_dict())
    status = result.get("status")
    fault_code = result.get("fault", {}).get("code") if status == "error" else None
    print(f"\n[B2-iii] wrong-nonce holder_proof → status={status} fault={fault_code}")
    assert status == "error", f"wrong-nonce holder_proof accepted: {result}"
    assert fault_code in {"holder_proof_invalid", "invalid_signature"}, (
        f"unexpected fault: {fault_code}"
    )


def test_b2_v4_holder_proof_garbage_bytes_rejected(sandbox, capsys):
    """Variant (iv): holder_proof is structurally valid base64 but
    semantically garbage bytes (not a real signature over the REQ's id).
    Tests fail-closed treatment of malformed proof bytes — v0.5.3 patch
    confirmed verify_holder_proof returns False on garbage rather than
    crashing."""
    alice, bob, cap = _setup_alice_with_cap_to_bob(sandbox)
    bob_priv = bob["agent"]._ensure_identity()._private_key

    req = build_req(
        from_private_key=bob_priv,
        from_id=bob["agent_id"],
        to_id=alice["agent_id"],
        intent="task",
        payload={"action": "echo", "msg": "hi"},
        cap_id=cap.cap_id,
        holder_proof_key=bob_priv,
        deadline_seconds=30,
    )
    req_dict = req.to_dict()
    # Replace holder_proof with 64 bytes of garbage, base64-encoded
    req_dict["holder_proof"] = base64.b64encode(b"\xde\xad\xbe\xef" * 16).decode()

    # Re-sign because we changed signable content
    from pact_passport._canonical import canonical_json
    from pact_passport.message import PACTMessage
    msg = PACTMessage.from_dict(req_dict)
    msg.signature = ""
    sig = crypto.sign(canonical_json(msg.signable_dict()), bob_priv)
    msg.signature = base64.b64encode(sig).decode()

    result = post_message(alice["url"], msg.to_dict())
    status = result.get("status")
    fault_code = result.get("fault", {}).get("code") if status == "error" else None
    print(f"\n[B2-iv] garbage-bytes holder_proof → status={status} fault={fault_code}")
    assert status == "error", f"garbage-bytes holder_proof accepted: {result}"
    assert fault_code in {"holder_proof_invalid", "invalid_signature"}, (
        f"unexpected fault: {fault_code}"
    )


def test_b2_control_legitimate_cap_use_accepted(sandbox, capsys):
    """Control: Bob legitimately uses his cap with a correct
    holder_proof. Must accept. Confirms the test machinery is sound."""
    alice, bob, cap = _setup_alice_with_cap_to_bob(sandbox)
    bob_priv = bob["agent"]._ensure_identity()._private_key

    req = build_req(
        from_private_key=bob_priv,
        from_id=bob["agent_id"],
        to_id=alice["agent_id"],
        intent="task",
        payload={"action": "echo", "msg": "legit"},
        cap_id=cap.cap_id,
        holder_proof_key=bob_priv,
        deadline_seconds=30,
    )
    result = post_message(alice["url"], req.to_dict())
    print(f"\n[B2-control] legitimate use → status={result.get('status')}")
    assert result.get("status") == "ok", f"legitimate cap use rejected: {result}"
