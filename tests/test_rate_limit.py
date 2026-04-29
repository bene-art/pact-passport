"""Tests for max_invocations rate limiting (Phase 3)."""

import uuid
from datetime import datetime, timezone, timedelta

from pact.identity import Identity
from pact.capability import issue_capability, Caveat
from pact.message import PACTMessage
from pact.agent import PACTAgent


def test_rate_limit_enforced(store):
    """Requests beyond max_invocations are rejected."""
    alice = Identity.create("alice_rl", store)
    bob_agent = PACTAgent("bob_rl", store_dir=store.base)

    @bob_agent.handle("limited_action")
    def handler(payload):
        return {"ok": True}

    bob_identity = bob_agent._ensure_identity()

    # Issue capability with max_invocations=2
    cap = issue_capability(
        bob_identity._private_key, bob_identity.agent_id, alice.agent_id,
        "limited_action",
        caveats=[Caveat("max_invocations", 2)],
    )
    store.save_capability("bob_rl", cap.to_dict())

    def make_req():
        return PACTMessage(
            id=str(uuid.uuid4()),
            type="REQ",
            from_agent=alice.agent_id,
            to_agent=bob_identity.agent_id,
            intent="task",
            payload={"action": "limited_action"},
            cap_id=cap.cap_id,
            deadline=(datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat(),
            idempotency_key=str(uuid.uuid4()),
            signature="",
        ).to_dict()

    # First two should succeed
    res1 = bob_agent._dispatch(make_req())
    assert res1.get("status") == "ok"

    res2 = bob_agent._dispatch(make_req())
    assert res2.get("status") == "ok"

    # Third should be rate limited
    res3 = bob_agent._dispatch(make_req())
    assert res3.get("status") == "error"
    assert res3["fault"]["code"] == "rate_limited"


def test_no_rate_limit_without_caveat(store):
    """Requests without max_invocations caveat are unlimited."""
    alice = Identity.create("alice_norl", store)
    bob_agent = PACTAgent("bob_norl", store_dir=store.base)

    @bob_agent.handle("unlimited")
    def handler(payload):
        return {"ok": True}

    bob_identity = bob_agent._ensure_identity()

    cap = issue_capability(
        bob_identity._private_key, bob_identity.agent_id, alice.agent_id,
        "unlimited",
    )
    store.save_capability("bob_norl", cap.to_dict())

    def make_req():
        return PACTMessage(
            id=str(uuid.uuid4()),
            type="REQ",
            from_agent=alice.agent_id,
            to_agent=bob_identity.agent_id,
            intent="task",
            payload={"action": "unlimited"},
            cap_id=cap.cap_id,
            deadline=(datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat(),
            idempotency_key=str(uuid.uuid4()),
            signature="",
        ).to_dict()

    # Should all succeed
    for _ in range(10):
        res = bob_agent._dispatch(make_req())
        assert res.get("status") == "ok"
