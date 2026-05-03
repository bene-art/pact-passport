"""v0.3.0 — durable idempotency cache regression test.

Pre-v0.3.0: idempotency cache was in-memory. Restart wiped it. A
network-retried REQ with the same idempotency_key would re-execute.
Documented as issue #5 and demonstrated live in `exp_amnesia.py`.

Post-v0.3.0: cache persists per-agent on disk. Restart preserves
the cache. Same REQ replayed after restart returns the cached
response, handler does NOT run again.
"""

from __future__ import annotations

import json

from pact.agent import PACTAgent
from pact.identity import Identity
from pact.message import build_req
from pact.store import PACTStore


def test_idempotency_survives_restart(tmp_path):
    """Same signed REQ replayed after agent restart returns cached response."""
    store_dir = tmp_path / "alice"

    # Sender (alice) — separate identity that we register with the receiver
    sender_store = PACTStore(tmp_path / "sender")
    sender = Identity.create("sender", sender_store)

    # First lifecycle: create agent, dispatch a REQ, observe handler runs
    handler_calls: list[int] = []

    agent_v1 = PACTAgent("alice", store_dir=store_dir)
    @agent_v1.handle("count")
    def count(payload):
        handler_calls.append(1)
        return {"call": len(handler_calls)}

    # Pre-register sender as a peer
    agent_v1._store.save_peer(sender.agent_id, sender.to_identity_document())

    receiver_id = agent_v1._ensure_identity().agent_id
    req = build_req(
        from_private_key=sender._private_key,
        from_id=sender.agent_id,
        to_id=receiver_id,
        intent="task",
        payload={"action": "count"},
        deadline_seconds=3600,
    )
    msg_dict = req.to_dict()

    # First send — handler runs
    res1 = agent_v1._dispatch(msg_dict)
    assert res1["status"] == "ok"
    assert res1["payload"]["call"] == 1
    assert len(handler_calls) == 1

    # Second send (same process, same key) — cache hit
    res2 = agent_v1._dispatch(msg_dict)
    assert res2["payload"]["call"] == 1
    assert len(handler_calls) == 1

    # Restart: simulate by creating a fresh agent instance with the same
    # store. In-memory state is wiped; disk state is preserved.
    agent_v2 = PACTAgent("alice", store_dir=store_dir)
    @agent_v2.handle("count")
    def count_v2(payload):
        handler_calls.append(1)
        return {"call": len(handler_calls)}

    # The peer cache, identity, and now idempotency cache all carry over
    res3 = agent_v2._dispatch(msg_dict)

    # CRITICAL: handler should NOT have run a third time. The cached
    # response from before restart should be returned. Pre-v0.3.0
    # this assertion would fail (call=2, len(handler_calls)=2).
    assert len(handler_calls) == 1, (
        f"handler ran {len(handler_calls)} times across restart; "
        f"idempotency cache lost durability"
    )
    assert res3["payload"]["call"] == 1


def test_invocation_counts_survive_restart(tmp_path):
    """Cap invocation counters persist across agent restart."""
    from pact.capability import Caveat, issue_capability

    store_dir = tmp_path / "bob"
    sender_store = PACTStore(tmp_path / "sender")
    sender = Identity.create("sender", sender_store)

    handler_runs: list[int] = []

    # Lifecycle 1
    bob_v1 = PACTAgent("bob", store_dir=store_dir)
    @bob_v1.handle("limited")
    def limited(payload):
        handler_runs.append(1)
        return {"ok": True}

    bob_v1._store.save_peer(sender.agent_id, sender.to_identity_document())
    bob_id = bob_v1._ensure_identity()

    cap = issue_capability(
        bob_id._private_key, bob_id.agent_id, sender.agent_id,
        "limited", caveats=[Caveat("max_invocations", 3)],
    )
    bob_v1._store.save_capability("bob", cap.to_dict())

    def make_req():
        return build_req(
            from_private_key=sender._private_key,
            from_id=sender.agent_id,
            to_id=bob_id.agent_id,
            intent="task",
            payload={"action": "limited"},
            cap_id=cap.cap_id,
            holder_proof_key=sender._private_key,
            deadline_seconds=300,
        ).to_dict()

    # Use 2 of 3 invocations
    assert bob_v1._dispatch(make_req())["status"] == "ok"
    assert bob_v1._dispatch(make_req())["status"] == "ok"
    assert len(handler_runs) == 2

    # Restart — counter should NOT reset to 0
    bob_v2 = PACTAgent("bob", store_dir=store_dir)
    @bob_v2.handle("limited")
    def limited_v2(payload):
        handler_runs.append(1)
        return {"ok": True}

    # Use the 3rd allowed invocation
    assert bob_v2._dispatch(make_req())["status"] == "ok"
    assert len(handler_runs) == 3

    # 4th should be rate limited even though it's a fresh process
    res = bob_v2._dispatch(make_req())
    assert res["status"] == "error", (
        "rate limit reset after restart — invocation counter not durable"
    )
    assert res["fault"]["code"] == "rate_limited"


def test_lru_cap_bounds_growth(tmp_path):
    """Cache bounded by idempotency_cache_max — older entries evicted."""
    store_dir = tmp_path / "alice"
    sender_store = PACTStore(tmp_path / "sender")
    sender = Identity.create("sender", sender_store)

    agent = PACTAgent("alice", store_dir=store_dir, idempotency_cache_max=5)
    @agent.handle("ping")
    def ping(payload):
        return {"pong": True}

    agent._store.save_peer(sender.agent_id, sender.to_identity_document())
    receiver_id = agent._ensure_identity().agent_id

    # Fire 10 unique REQs — 5x the cap
    for i in range(10):
        req = build_req(
            from_private_key=sender._private_key,
            from_id=sender.agent_id,
            to_id=receiver_id,
            intent="task",
            payload={"action": "ping", "n": i},
            deadline_seconds=300,
        )
        res = agent._dispatch(req.to_dict())
        assert res["status"] == "ok"

    assert len(agent._idempotency_cache) <= 5, (
        f"cache grew to {len(agent._idempotency_cache)}, expected ≤ 5"
    )
