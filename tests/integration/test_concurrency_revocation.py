"""Scenario 3: revocation is atomic at dispatch.

Spec: when a capability is revoked, requests that have already passed the
cap-verification step at dispatch entry complete normally. Subsequent
requests (those entering dispatch after the revoke writes to disk) fail
with capability_invalid.

This documents the chosen revocation semantics (option C — atomic at
dispatch) and asserts the implementation matches.
"""

from __future__ import annotations

from pact.capability import issue_capability
from pact.message import build_req

from tests.integration.conftest import post_message


def _make_cap(alice, bob):
    cap = issue_capability(
        bob["identity"]._private_key,
        bob["agent_id"],
        alice["agent_id"],
        "ping",
    )
    bob["agent"]._store.save_capability("bob", cap.to_dict())
    return cap


def _ping(alice, bob, cap):
    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "ping"},
        cap_id=cap.cap_id,
        holder_proof_key=alice["identity"]._private_key,
    )
    return post_message(bob["url"], req.to_dict())


def test_revocation_atomic_at_dispatch(sandbox):
    alice = sandbox["alice"]
    bob = sandbox["bob"]
    cap = _make_cap(alice, bob)

    @bob["agent"].handle("ping")
    def ping(payload):
        return {"pong": True}

    # Pre-revoke: succeeds.
    r1 = _ping(alice, bob, cap)
    assert r1["status"] == "ok", f"pre-revoke request failed: {r1}"

    # Revoke.
    assert bob["agent"].revoke(cap.cap_id) is True

    # Post-revoke: rejected with capability_invalid (reason mentions revoked).
    r2 = _ping(alice, bob, cap)
    assert r2["status"] == "error", f"post-revoke request unexpectedly succeeded: {r2}"
    fault = r2.get("fault", {})
    assert fault.get("code") == "capability_invalid", (
        f"expected capability_invalid, got: {fault}"
    )
    assert "revoked" in fault.get("detail", "").lower(), (
        f"expected 'revoked' in reason, got: {fault}"
    )


def test_revocation_visible_immediately(sandbox):
    """A request fired immediately after revoke() returns must see the
    revoked state. No window where a stale on-disk read would let a
    revoked cap through."""
    alice = sandbox["alice"]
    bob = sandbox["bob"]
    cap = _make_cap(alice, bob)

    @bob["agent"].handle("ping")
    def ping(payload):
        return {"pong": True}

    bob["agent"].revoke(cap.cap_id)
    r = _ping(alice, bob, cap)
    assert r["status"] == "error"
    assert r.get("fault", {}).get("code") == "capability_invalid"
