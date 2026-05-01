"""Scenario 4: communication survives key rotation.

The README states: "identity survives key rotation without a central
registry." The KERI-style theoretical foundation backs this claim.

This test verifies the claim end-to-end: alice rotates her keys, then
sends a REQ signed with the new key. Bob — who handshaked with alice
before the rotation — should still verify the REQ.

The current implementation caches peer identity at first contact
(agent.py:243) and never refreshes it. After alice rotates, bob's cached
public key is stale and verification fails with invalid_signature.

Marked xfail until the verifier learns to refresh the peer's identity
document (or walk the peer's event log) when verification against the
cached key fails.
"""

from __future__ import annotations

import pytest

from pact.message import build_req

from tests.integration.conftest import post_message


@pytest.mark.xfail(
    reason="Bob's peer cache holds alice's old key; no event-log walk on verify failure. "
    "Tracked as a deliverable for the historical-key-verification feature.",
    strict=True,
)
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

    # Alice signs a new REQ with the new key.
    post_req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "ping"},
    )
    post_res = post_message(bob["url"], post_req.to_dict())

    # Per the README's promise, this should succeed.
    # Currently fails: bob's peer cache has alice's pre-rotation key.
    assert post_res["status"] == "ok", (
        f"post-rotation REQ rejected: {post_res} — "
        "bob's peer cache is stale and verifier has no recovery path"
    )
