"""Scenario 4: communication survives key rotation.

The README states: "identity survives key rotation without a central
registry." The KERI-style theoretical foundation backs this claim.

v0.3.1 fix (issue #4): when verify_message fails on a cached peer AND
the REQ includes a fresh identity_doc, the receiver checks rotation
continuity:

    hash(new_doc.public_key) == old_doc.next_key_digest

If the continuity proof holds, the cache is refreshed and verification
retried. The rotated party must include their fresh identity_doc on
the first post-rotation REQ — that's the protocol contract.
"""

from __future__ import annotations

from pact_passport.message import build_req

from tests.integration.conftest import post_message


def test_communication_survives_rotation(sandbox):
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    @bob["agent"].handle("ping")
    def ping(payload):
        return {"pong": True}

    # Sanity: pre-rotation REQ works.
    pre_req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "ping"},
    )
    pre_res = post_message(bob["url"], pre_req.to_dict())
    assert pre_res["status"] == "ok", f"baseline pre-rotation REQ failed: {pre_res}"

    # Alice rotates her keys.
    alice["identity"].rotate()

    # Alice signs a new REQ with the new key AND includes her fresh
    # identity_doc so bob can refresh his peer cache via the
    # KERI-style continuity check.
    post_req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "ping"},
        identity_doc=alice["identity"].to_identity_document(),
    )
    post_res = post_message(bob["url"], post_req.to_dict())

    assert post_res["status"] == "ok", (
        f"post-rotation REQ rejected: {post_res} — "
        "rotation continuity refresh failed"
    )

    # Bob's peer cache should now have alice's NEW pubkey.
    refreshed = bob["agent"]._store.load_peer(alice["agent_id"])
    assert refreshed["public_key"] == alice["identity"].public_key_b64()


def test_rotation_without_continuity_proof_rejected(sandbox):
    """An attacker swapping in a fresh keypair (with an unrelated
    next_key_digest history) cannot impersonate a rotated peer. The
    continuity check fails because the attacker's pubkey hash doesn't
    match the cached doc's next_key_digest."""
    from pact_passport.identity import Identity
    from pact_passport.store import PACTStore
    from pathlib import Path
    import tempfile

    bob = sandbox["bob"]
    alice = sandbox["alice"]

    @bob["agent"].handle("ping")
    def ping(payload):
        return {"pong": True}

    # Establish alice in bob's peer cache via a normal REQ first
    initial = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "ping"},
    )
    assert post_message(bob["url"], initial.to_dict())["status"] == "ok"

    # Now an ATTACKER generates a fresh identity claiming alice's agent_id.
    # They cannot produce a doc with the right next_key_digest because
    # they don't have alice's pre-rotation commitment.
    tmp = Path(tempfile.mkdtemp())
    attacker_store = PACTStore(tmp)
    attacker = Identity.create("impostor", attacker_store)
    # Forge a doc that claims alice's agent_id (signature on REQ will
    # fail anyway because attacker_pub != alice_pub, but they provide
    # an identity_doc to trigger the refresh path)
    forged_doc = attacker.to_identity_document()
    forged_doc["agent_id"] = alice["agent_id"]  # claim alice's identity

    forged_req = build_req(
        from_private_key=attacker._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "ping"},
        identity_doc=forged_doc,
    )
    res = post_message(bob["url"], forged_req.to_dict())
    assert res["status"] == "error", "attacker should be rejected"
    assert res["fault"]["code"] == "invalid_signature"
