"""A2: Key Rotation Continuity.

Tests KERI-style rotation continuity enforcement at the dispatch layer.

A peer's first post-rotation REQ must include a fresh identity_doc
whose new pubkey hashes to the previously-committed `next_key_digest`.
If the hash does NOT match (an unannounced key swap by a forging
attacker), the receiver must reject.

Pre-registered prediction: 100% rejection on forged rotations.

Adversarial vector: a sender presents a brand-new keypair as a
"rotation" but the new pubkey is NOT the one pre-committed at inception.
The receiver sees verify_message fail against the cached pubkey,
attempts rotation refresh, computes sha256(forged_pubkey), and finds it
does not match the cached next_key_digest → rejection.

Control: a legitimate rotation (using the pre-committed next key) is
accepted, demonstrating the test machinery is sound.
"""

from __future__ import annotations

from pact import crypto
from pact.message import build_req

from tests.integration.conftest import post_message


def test_a2_legitimate_rotation_accepted_control(sandbox, capsys):
    """Control: alice rotates legitimately (using the pre-committed next
    key) and her post-rotation REQ is accepted by bob.

    This matches the existing test_concurrency_rotation.py scenario.
    Included here as the baseline against which A2's forging variant
    fails closed.
    """
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    @bob["agent"].handle("ping")
    def ping(payload):
        return {"pong": True}

    # Sanity: pre-rotation REQ works
    pre_req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "ping"},
    )
    assert post_message(bob["url"], pre_req.to_dict())["status"] == "ok"

    # Legitimate rotation
    alice["identity"].rotate()

    # Post-rotation REQ with fresh identity_doc
    post_req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "ping"},
        identity_doc=alice["identity"].to_identity_document(),
    )
    result = post_message(bob["url"], post_req.to_dict())
    print(f"\n[A2-control] legitimate rotation → status={result.get('status')}")
    assert result["status"] == "ok", (
        f"legitimate rotation should be accepted; got: {result}"
    )


def test_a2_forged_rotation_unannounced_key_swap_rejected(sandbox, capsys):
    """A2 main adversarial vector: alice attempts an unannounced key swap.

    Alice generates a brand-new keypair that is NOT the next_key_digest
    she pre-committed to at inception. She signs a REQ with the new key
    and presents an identity_doc with the forged pubkey. Bob's rotation
    continuity check must fail: sha256(forged_pubkey) != cached
    next_key_digest → rejection with invalid_signature (the refresh
    fails, falls through to the standard signature rejection).
    """
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    @bob["agent"].handle("ping")
    def ping(payload):
        return {"pong": True}

    # Sanity baseline
    pre_req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "ping"},
    )
    assert post_message(bob["url"], pre_req.to_dict())["status"] == "ok"

    # Forge a fresh keypair that was NEVER pre-committed
    fake_priv, fake_pub = crypto.generate_keypair()

    # Craft a forged identity_doc claiming alice's agent_id but with the
    # fake pubkey. This is what an attacker would present after
    # compromising alice's signing-time environment but without knowing
    # the pre-rotation seed.
    import base64
    forged_identity_doc = {
        "agent_id": alice["agent_id"],
        "alg": "Ed25519",
        "public_key": base64.b64encode(fake_pub).decode(),
        # The "next_key_digest" field in the doc is irrelevant — the
        # check is against the previously-cached doc's next_key_digest,
        # not what the new doc claims.
        "next_key_digest": "sha256:" + "f" * 64,
    }

    # Build a REQ signed with the fake key, presenting the forged doc.
    # We can't use build_req's identity_doc parameter directly because
    # build_req would sign with the real alice key. Instead, we'll
    # construct a message with the fake key signing it and manually
    # attach the forged doc.
    fake_alice_req = build_req(
        from_private_key=fake_priv,
        from_id=alice["agent_id"],  # claiming to be alice
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "ping"},
        identity_doc=forged_identity_doc,
    )

    result = post_message(bob["url"], fake_alice_req.to_dict())
    status = result.get("status")
    fault_code = result.get("fault", {}).get("code") if status == "error" else None
    print(f"\n[A2-V1] forged-rotation → status={status} fault={fault_code}")

    # Pre-registered: rejection. Accepted rejection codes are
    # invalid_signature (rotation refresh failed → fell through to
    # signature rejection) or invalid_message.
    assert status == "error", (
        f"forged rotation should be rejected; got: {result}"
    )
    assert fault_code in {"invalid_signature", "invalid_message", "unknown_peer"}, (
        f"unexpected fault code on forged rotation: {fault_code}"
    )


def test_a2_no_identity_doc_after_rotation_rejected(sandbox, capsys):
    """A2 variant 2: alice rotates legitimately but FORGETS to include
    the fresh identity_doc on the post-rotation REQ. Bob's cached pubkey
    no longer verifies; without a fresh identity_doc, there's no
    rotation-continuity path. Must be rejected.

    This is a regression-style test — the v0.3.1 fix requires the fresh
    doc to be present for refresh; without it, rejection is the correct
    behavior.
    """
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    @bob["agent"].handle("ping")
    def ping(payload):
        return {"pong": True}

    # Sanity baseline
    pre = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "ping"},
    )
    assert post_message(bob["url"], pre.to_dict())["status"] == "ok"

    alice["identity"].rotate()

    # Post-rotation REQ WITHOUT identity_doc
    post_req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "ping"},
        # identity_doc NOT included
    )
    result = post_message(bob["url"], post_req.to_dict())
    status = result.get("status")
    fault_code = result.get("fault", {}).get("code") if status == "error" else None
    print(f"\n[A2-V2] rotation-without-doc → status={status} fault={fault_code}")
    assert status == "error", (
        f"post-rotation REQ without fresh identity_doc should be rejected; got: {result}"
    )
    assert fault_code == "invalid_signature"
