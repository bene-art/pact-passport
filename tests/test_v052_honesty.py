"""v0.5.2 honesty patch — covers four fixes:
- E1: signed `outcome=failed` receipt on dispatch error
- E2: HandlerFailure exception → custom fault + failed receipt
- E11: cap_envelope without cap_id auto-derives or rejects
- E7: server-side max_deadline_seconds clamp
"""
from __future__ import annotations

import pytest

from pact import (
    PACTAgent, HandlerFailure,
    build_req, send_message, fetch_identity,
    issue_capability, Caveat,
)


@pytest.fixture
def alice(tmp_path):
    """Standalone agent for direct dispatch tests (no HTTP)."""
    a = PACTAgent("alice", capabilities=["echo", "boom", "fail"], store_dir=tmp_path)
    a._ensure_identity()

    @a.handle("echo")
    def echo(payload):
        return {"echoed": payload}

    @a.handle("boom")
    def boom(payload):
        raise RuntimeError("kaboom")

    @a.handle("fail")
    def fail(payload):
        raise HandlerFailure("custom_fault", "explicit failure")

    return a


def _direct_dispatch(agent, req):
    """Bypass HTTP — drive the dispatch pipeline directly."""
    return agent._handle_task(req, agent._identity)


def test_e1_dispatch_error_writes_failed_receipt(alice):
    me = alice._identity
    # Build a REQ for an unknown action — triggers _dispatch_err("no_handler")
    req = build_req(
        from_private_key=me._private_key, from_id=me.agent_id,
        to_id=me.agent_id, intent="task",
        payload={"action": "unknown_action"},
        identity_doc=me.to_identity_document(),
        deadline_seconds=60,
    )
    res = _direct_dispatch(alice, req)
    assert res["status"] == "error"
    assert res["fault"]["code"] == "no_handler"
    # E1: receipt was written despite error
    receipts = [
        r for r in alice._store.list_receipts(alice.name)
        if r.get("task_ref") == req.id
    ]
    assert len(receipts) == 1
    assert receipts[0]["outcome"] == "failed"


def test_e2_handler_failure_uses_custom_fault(alice):
    me = alice._identity
    req = build_req(
        from_private_key=me._private_key, from_id=me.agent_id,
        to_id=me.agent_id, intent="task",
        payload={"action": "fail"},
        identity_doc=me.to_identity_document(),
        deadline_seconds=60,
    )
    res = _direct_dispatch(alice, req)
    assert res["status"] == "error"
    # The custom fault code from HandlerFailure, NOT generic handler_error
    assert res["fault"]["code"] == "custom_fault"
    assert res["fault"]["detail"] == "explicit failure"
    # Failed receipt written (via E1 fix)
    receipts = [
        r for r in alice._store.list_receipts(alice.name)
        if r.get("task_ref") == req.id
    ]
    assert len(receipts) == 1
    assert receipts[0]["outcome"] == "failed"


def test_e2_unhandled_exception_still_handler_error(alice):
    """Regression check: unhandled exceptions still produce handler_error fault."""
    me = alice._identity
    req = build_req(
        from_private_key=me._private_key, from_id=me.agent_id,
        to_id=me.agent_id, intent="task",
        payload={"action": "boom"},
        identity_doc=me.to_identity_document(),
        deadline_seconds=60,
    )
    res = _direct_dispatch(alice, req)
    assert res["status"] == "error"
    assert res["fault"]["code"] == "handler_error"
    assert "kaboom" in res["fault"]["detail"]


def test_e11_cap_envelope_without_cap_id_auto_derives(tmp_path):
    """build_req should auto-set cap_id from envelope.cap_id."""
    issuer = PACTAgent("issuer", store_dir=tmp_path / "i")
    issuer._ensure_identity()
    cap = issue_capability(
        issuer_private_key=issuer._identity._private_key,
        issuer_id=issuer._identity.agent_id,
        holder_id=issuer._identity.agent_id,
        action="x",
        caveats=[Caveat(restrict="max_invocations", value=5)],
    )

    req = build_req(
        from_private_key=issuer._identity._private_key,
        from_id=issuer._identity.agent_id,
        to_id=issuer._identity.agent_id,
        intent="task",
        payload={"action": "x"},
        identity_doc=issuer._identity.to_identity_document(),
        deadline_seconds=60,
        cap_envelope=cap.to_dict(),  # no explicit cap_id
    )
    # cap_id should now be auto-derived
    assert req.cap_id == cap.cap_id


def test_e11_cap_envelope_missing_cap_id_raises(tmp_path):
    """build_req should reject cap_envelope dict without 'cap_id'."""
    issuer = PACTAgent("issuer2", store_dir=tmp_path / "i2")
    issuer._ensure_identity()
    bad_envelope = {"action": "x", "issuer": "fake"}  # no cap_id key
    with pytest.raises(ValueError, match="cap_id"):
        build_req(
            from_private_key=issuer._identity._private_key,
            from_id=issuer._identity.agent_id,
            to_id=issuer._identity.agent_id,
            intent="task",
            payload={"action": "x"},
            identity_doc=issuer._identity.to_identity_document(),
            deadline_seconds=60,
            cap_envelope=bad_envelope,
        )


def test_e7_far_future_deadline_rejected(tmp_path):
    """Server enforces max_deadline_seconds (default 3600 = 1h)."""
    a = PACTAgent("server", store_dir=tmp_path)
    a._ensure_identity()

    @a.handle("ping")
    def ping(payload):
        return {"pong": True}

    me = a._identity
    # 10-year deadline
    req = build_req(
        from_private_key=me._private_key, from_id=me.agent_id,
        to_id=me.agent_id, intent="task",
        payload={"action": "ping"},
        identity_doc=me.to_identity_document(),
        deadline_seconds=315_360_000,  # 10 years
    )
    res = _direct_dispatch(a, req)
    assert res["status"] == "error"
    assert res["fault"]["code"] == "deadline_too_far"


def test_e7_normal_deadline_accepted(tmp_path):
    """Normal deadlines under the cap pass through."""
    a = PACTAgent("server2", store_dir=tmp_path, max_deadline_seconds=3600)
    a._ensure_identity()

    @a.handle("ping")
    def ping(payload):
        return {"pong": True}

    me = a._identity
    req = build_req(
        from_private_key=me._private_key, from_id=me.agent_id,
        to_id=me.agent_id, intent="task",
        payload={"action": "ping"},
        identity_doc=me.to_identity_document(),
        deadline_seconds=120,
    )
    res = _direct_dispatch(a, req)
    assert res["status"] == "ok"


def test_e7_max_deadline_configurable(tmp_path):
    """Constructor arg overrides the default 3600s ceiling."""
    a = PACTAgent("longrun", store_dir=tmp_path, max_deadline_seconds=86400)
    a._ensure_identity()

    @a.handle("ping")
    def ping(payload):
        return {"pong": True}

    me = a._identity
    # 6-hour deadline — would fail under default 3600, must pass under 86400
    req = build_req(
        from_private_key=me._private_key, from_id=me.agent_id,
        to_id=me.agent_id, intent="task",
        payload={"action": "ping"},
        identity_doc=me.to_identity_document(),
        deadline_seconds=6 * 3600,
    )
    res = _direct_dispatch(a, req)
    assert res["status"] == "ok"
