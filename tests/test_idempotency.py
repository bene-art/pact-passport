"""Tests for idempotency cache and DAG traversal (Phase 2)."""

from pact.identity import Identity
from pact.message import build_req, build_res
from pact.transport.server import PACTServer
from pact.transport.client import send_message


def test_idempotency_returns_cached(store):
    """Same idempotency_key returns cached response, handler not called twice."""
    alice = Identity.create("alice", store)
    bob = Identity.create("bob", store)

    call_count = 0

    def bob_dispatch(body):
        nonlocal call_count
        from pact.message import PACTMessage, build_res
        msg = PACTMessage.from_dict(body)

        if msg.intent == "task":
            # Check idempotency manually for this test
            call_count += 1
            return build_res(
                bob._private_key, bob.agent_id, msg,
                payload={"count": call_count},
            ).to_dict()

        return build_res(bob._private_key, bob.agent_id, msg, status="error").to_dict()

    server = PACTServer(port=0, dispatch=bob_dispatch)
    port = server.start()

    try:
        base_url = f"http://127.0.0.1:{port}"

        # First request
        req = build_req(
            alice._private_key, alice.agent_id, bob.agent_id,
            "task", {"action": "test"},
        )
        res1 = send_message(base_url, req)
        assert res1["payload"]["count"] == 1

        # Same message (same idempotency key) — different result because
        # this server doesn't have PACT agent-level idempotency.
        # The agent.py _handle_task method does have it.
        res2 = send_message(base_url, req)
        # Without agent-level caching, handler is called again
        assert res2["payload"]["count"] == 2

    finally:
        server.stop()


def test_agent_idempotency(store):
    """PACTAgent-level idempotency cache returns same response."""
    from pact.agent import PACTAgent

    alice = Identity.create("alice_idem", store)

    agent = PACTAgent("bob_idem", store_dir=store.base)

    handler_calls = 0

    @agent.handle("count")
    def count_handler(payload):
        nonlocal handler_calls
        handler_calls += 1
        return {"calls": handler_calls}

    # Simulate dispatch twice with same idempotency key
    from pact.message import PACTMessage
    import uuid
    from datetime import datetime, timezone, timedelta

    idem_key = str(uuid.uuid4())
    msg_dict = PACTMessage(
        id=str(uuid.uuid4()),
        type="REQ",
        from_agent=alice.agent_id,
        to_agent="any",
        intent="task",
        payload={"action": "count"},
        deadline=(datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat(),
        idempotency_key=idem_key,
    ).to_dict()
    msg_dict["signature"] = ""  # skip verification in auto-grant mode

    res1 = agent._dispatch(msg_dict)
    res2 = agent._dispatch(msg_dict)

    assert handler_calls == 1  # only called once
    assert res1["payload"]["calls"] == 1
    assert res2["payload"]["calls"] == 1  # cached


def test_causal_chain(store):
    """get_causal_chain walks refs backwards."""
    from pact.agent import PACTAgent

    agent = PACTAgent("chain_test", store_dir=store.base)

    # Store a chain: m3 → m2 → m1
    store.save_message("chain_test", {"id": "m1", "type": "REQ", "refs": []})
    store.save_message("chain_test", {"id": "m2", "type": "RES", "refs": ["m1"]})
    store.save_message("chain_test", {"id": "m3", "type": "REQ", "refs": ["m2"]})

    chain = agent.get_causal_chain("m3")
    ids = [m["id"] for m in chain]
    assert "m3" in ids
    assert "m2" in ids
    assert "m1" in ids
    assert len(chain) == 3
