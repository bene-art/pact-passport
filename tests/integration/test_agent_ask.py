"""End-to-end test for `PACTAgent.ask()` — the high-level client API.

The two-agent integration tests use lower-level `build_req` + `send_message`
directly, which means `agent.ask()` (target resolution → handshake → cap
lookup → REQ build → send → receipt write) has been completely uncovered
since v0.1. This file exercises the full ask path.

mDNS discovery (`resolve_agent`) is monkey-patched to point at the sandbox
loopback agent so the test doesn't depend on a real local network.
"""

from __future__ import annotations

import pytest


def test_agent_ask_with_capability_succeeds(sandbox, monkeypatch):
    """The happy path: bob holds an echo cap from alice, asks alice, gets a result.

    This exercises:
    - resolve_agent (stubbed)
    - peer cache hit (sandbox pre-shares identities)
    - _find_capability_for (bob's local store)
    - build_req with cap_id + holder_proof
    - send_message over the loopback sandbox server
    - receipt write on completion
    """
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    @alice["agent"].handle("echo")
    def echo_handler(payload):
        return {"echo": payload}

    # Stub mDNS resolution: bob's ask("alice", ...) needs to map "alice" to her loopback URL
    def fake_resolve(target: str):
        if target == "alice":
            return {
                "name": "alice",
                "agent_id": alice["agent_id"],
                "host": "127.0.0.1",
                "port": alice["agent"].port,
                "capabilities": ["echo"],
            }
        return None
    monkeypatch.setattr("pact_passport.agent.resolve_agent", fake_resolve)

    # Alice grants bob an echo capability. Then transfer the cap to bob's store
    # (mimicking what a real out-of-band cap delivery would do).
    cap = alice["agent"].grant(bob["agent_id"], "echo")
    bob["agent"]._store.save_capability(bob["name"], cap.to_dict())

    result = bob["agent"].ask("alice", "echo", payload={"msg": "hello"})

    assert result.get("status") == "ok", f"unexpected result: {result}"
    assert result["payload"]["echo"]["msg"] == "hello"

    # Receipt should have been written on bob's side
    receipts = bob["agent"]._store.list_receipts(bob["name"])
    assert any(r.get("outcome") == "completed" for r in receipts), (
        f"expected at least one completed receipt, got: {receipts}"
    )


def test_agent_ask_unknown_target_returns_not_found(sandbox, monkeypatch):
    """If resolve_agent returns None, ask reports a clean fault rather than raising."""
    bob = sandbox["bob"]

    monkeypatch.setattr("pact_passport.agent.resolve_agent", lambda target: None)

    result = bob["agent"].ask("nonexistent", "echo", payload={})

    assert result.get("status") == "error"
    assert result["fault"]["code"] == "not_found"
    assert "nonexistent" in result["fault"]["detail"]


def test_agent_ask_writes_failed_receipt_on_error(sandbox, monkeypatch):
    """When the remote rejects, ask still writes a receipt with outcome=failed."""
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    # Alice has no handler registered for "missing_action"
    monkeypatch.setattr("pact_passport.agent.resolve_agent", lambda target: {
        "name": "alice",
        "agent_id": alice["agent_id"],
        "host": "127.0.0.1",
        "port": alice["agent"].port,
        "capabilities": [],
    } if target == "alice" else None)

    # Bob has a cap so the rejection happens at the handler stage, not at auth
    cap = alice["agent"].grant(bob["agent_id"], "missing_action")
    bob["agent"]._store.save_capability(bob["name"], cap.to_dict())

    result = bob["agent"].ask("alice", "missing_action", payload={})

    assert result.get("status") == "error"
    # Receipt should still be written with outcome=failed
    receipts = bob["agent"]._store.list_receipts(bob["name"])
    assert any(r.get("outcome") == "failed" for r in receipts), (
        f"expected a failed receipt, got: {receipts}"
    )
