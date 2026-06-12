"""v0.2 auth-hardening tests — the triangle of authorization bypasses.

These tests document the three bypasses tracked as issues #2, #3, #8.
Before the v0.2 fixes, all three demonstrate the protocol accepting
attacks that should be rejected. After the fixes, all three pass with
explicit rejection.

Each test is paired: a positive (legit) case and a negative (attack)
case. The positive case proves the legitimate flow still works after
the fix; the negative case proves the attack is rejected.
"""

from __future__ import annotations

import base64
import json

import pytest

from pact_passport import crypto
from pact_passport._canonical import canonical_json
from pact_passport.capability import (
    Caveat, CapabilityToken, DelegationLink,
    issue_capability, attenuate, verify_capability,
)
from pact_passport.message import build_req

from tests.integration.conftest import post_message


# ============================================================================
# Issue #2 — auth-bypass-by-default
# ============================================================================

def test_unknown_peer_rejected_in_strict_mode(sandbox):
    """An agent not registered in the receiver's peer cache must be rejected.

    Pre-v0.2: the agent.py:140-141 conditional silently skipped verification
    when sender_pub was None, so unknown peers' REQs went straight through.
    Post-v0.2: receivers reject with `unknown_peer` (or auto-handshake via
    inline identity_doc).
    """
    bob = sandbox["bob"]

    @bob["agent"].handle("ping")
    def ping(payload):
        return {"pong": True}

    # An identity bob has never seen. Brand new keypair.
    rogue_priv, rogue_pub = crypto.generate_keypair()
    rogue_pub_b64 = base64.b64encode(rogue_pub).decode()
    rogue_id = crypto.sha256_digest(f"Ed25519{rogue_pub_b64}".encode())

    req = build_req(
        from_private_key=rogue_priv,
        from_id=rogue_id,
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "ping"},
    )
    res = post_message(bob["url"], req.to_dict())

    assert res["status"] == "error", (
        f"unknown peer should be rejected, got: {res}"
    )
    fault_code = res.get("fault", {}).get("code", "")
    assert fault_code in ("unknown_peer", "invalid_signature"), (
        f"expected unknown_peer or invalid_signature, got: {fault_code}"
    )


def test_unknown_peer_with_inline_identity_handshake_works(sandbox):
    """Trust-on-first-use: a brand-new peer that includes its identity_doc
    inline in the REQ is auto-cached by the receiver after agent_id is
    verified to derive from the doc's pubkey, then the message signature
    is verified against that pubkey.
    """
    bob = sandbox["bob"]

    @bob["agent"].handle("ping")
    def ping(payload):
        return {"pong": True}

    # Brand-new identity bob hasn't seen
    from pact_passport.identity import Identity
    from pact_passport.store import PACTStore
    from pathlib import Path
    import tempfile, os
    tmp = Path(tempfile.mkdtemp())
    new_store = PACTStore(tmp)
    new_agent = Identity.create("first_contact", new_store)

    # Build REQ with identity_doc inline for trust-on-first-use handshake.
    # Receiver verifies the doc binds to from_agent, then uses doc's
    # pubkey to verify the message signature. Both happen atomically.
    req = build_req(
        from_private_key=new_agent._private_key,
        from_id=new_agent.agent_id,
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "ping"},
        identity_doc=new_agent.to_identity_document(),
    )

    res = post_message(bob["url"], req.to_dict())
    assert res["status"] == "ok", (
        f"first-contact handshake should succeed when identity_doc is "
        f"included and consistent: {res}"
    )


# ============================================================================
# Issue #3 — holder-proof bypass
# ============================================================================

def test_holder_proof_required_when_cap_present(sandbox):
    """When a REQ presents a cap_id, holder_proof is mandatory.

    Pre-v0.2: holder_proof check was only run if the field was present.
    An attacker omitting the field skipped the check entirely.
    Post-v0.2: omitting holder_proof when cap_id is present → reject.
    """
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    @bob["agent"].handle("ping")
    def ping(payload):
        return {"pong": True}

    cap = issue_capability(
        bob["identity"]._private_key,
        bob["agent_id"],
        alice["agent_id"],
        "ping",
    )
    bob["agent"]._store.save_capability("bob", cap.to_dict())

    # REQ with cap but NO holder_proof
    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "ping"},
        cap_id=cap.cap_id,
        # holder_proof_key=None  ← deliberately omitted
    )
    msg_dict = req.to_dict()
    msg_dict.pop("holder_proof", None)

    res = post_message(bob["url"], msg_dict)
    assert res["status"] == "error", (
        f"missing holder_proof should be rejected: {res}"
    )
    fault_code = res.get("fault", {}).get("code", "")
    assert "holder_proof" in fault_code, (
        f"expected holder_proof_required-ish error, got: {fault_code}"
    )


def test_holder_proof_present_and_valid_works(sandbox):
    """Sanity: legit REQ with valid holder_proof succeeds."""
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    @bob["agent"].handle("ping")
    def ping(payload):
        return {"pong": True}

    cap = issue_capability(
        bob["identity"]._private_key,
        bob["agent_id"],
        alice["agent_id"],
        "ping",
    )
    bob["agent"]._store.save_capability("bob", cap.to_dict())

    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "ping"},
        cap_id=cap.cap_id,
        holder_proof_key=alice["identity"]._private_key,  # included
    )
    res = post_message(bob["url"], req.to_dict())
    assert res["status"] == "ok", (
        f"legitimate cap+holder_proof should work: {res}"
    )


# ============================================================================
# Issue #8 — forged delegation chains pass with missing keys
# ============================================================================

def test_chain_verification_fails_closed_on_missing_key():
    """When delegation chain references an agent whose pubkey isn't in
    known_keys, verify_capability must return False — not silently pass.

    Pre-v0.2: silent pass, allowing forged chains.
    Post-v0.2: explicit rejection with reason indicating missing key.
    """
    priv_a, pub_a = crypto.generate_keypair()
    priv_b, pub_b = crypto.generate_keypair()
    priv_eve, pub_eve = crypto.generate_keypair()

    id_a = crypto.sha256_digest(f"Ed25519{base64.b64encode(pub_a).decode()}".encode())
    id_b = crypto.sha256_digest(f"Ed25519{base64.b64encode(pub_b).decode()}".encode())
    id_eve = crypto.sha256_digest(f"Ed25519{base64.b64encode(pub_eve).decode()}".encode())

    # Real root cap from A to B
    root = issue_capability(priv_a, id_a, id_b, "act")

    # Eve forges a child claiming "B delegated to Eve" — she signs as last delegator
    import uuid
    forged = CapabilityToken(
        cap_id=str(uuid.uuid4()),
        issuer=id_a,
        holder=id_eve,
        action="act",
        caveats=[Caveat("max_invocations", 9999)],
        parent=root.cap_id,
        delegation_chain=[
            DelegationLink(
                from_agent=id_b,
                sig=base64.b64encode(crypto.sign(root.cap_id.encode(), priv_eve)).decode(),
            ),
        ],
    )
    forged.signature = base64.b64encode(
        crypto.sign(canonical_json(forged.signable_dict()), priv_eve)
    ).decode()

    # Verifier WITHOUT B's key — B is the claimed delegator, but verifier
    # has never met B. Pre-v0.2 this silently passes.
    known_keys_no_b = {id_a: pub_a, id_eve: pub_eve}
    result = verify_capability(forged, id_eve, pub_a, known_keys_no_b)

    assert not result.valid, (
        f"forged chain with missing delegator key must be rejected: {result.reason}"
    )
    assert result.reason and ("missing" in result.reason.lower() or "unverifiable" in result.reason.lower() or "key" in result.reason.lower()), (
        f"reason should indicate the missing key: {result.reason}"
    )


def test_chain_verification_passes_with_all_keys_present():
    """Sanity: a legit chain with all keys present still verifies."""
    priv_a, pub_a = crypto.generate_keypair()
    priv_b, pub_b = crypto.generate_keypair()
    priv_c, pub_c = crypto.generate_keypair()

    id_a = crypto.sha256_digest(f"Ed25519{base64.b64encode(pub_a).decode()}".encode())
    id_b = crypto.sha256_digest(f"Ed25519{base64.b64encode(pub_b).decode()}".encode())
    id_c = crypto.sha256_digest(f"Ed25519{base64.b64encode(pub_c).decode()}".encode())

    root = issue_capability(priv_a, id_a, id_b, "act")
    child = attenuate(root, priv_b, id_b, id_c, [Caveat("max_invocations", 5)])

    known_keys = {id_a: pub_a, id_b: pub_b, id_c: pub_c}
    result = verify_capability(child, id_c, pub_a, known_keys)
    assert result.valid, f"legit chain should verify: {result.reason}"
