"""A6: Deadline Ceiling Boundary Fuzz.

Tests the v0.5.2 server-side `max_deadline_seconds` ceiling under edge
conditions. Default ceiling is 3600s; verifies boundary handling at
3599 (under), 3600 (exactly at), 3601 (just over) plus extreme values
(year 9999, year 1970, near-int-max).

Pre-registered prediction:
- 3599s → accepted (within ceiling)
- 3600s → accepted OR rejected depending on inclusive/exclusive comparison
  (this experiment surfaces the actual choice; either is acceptable as
  long as it's consistent and documented)
- 3601s → rejected with deadline_too_far
- Year 9999 → rejected with deadline_too_far
- Year 1970 → rejected (already-exceeded; deadline_exceeded)
- int_max seconds → rejected with deadline_too_far

Risk: off-by-one possible at exactly 3600s. Worth surfacing the
comparison-strictness choice explicitly.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from pact_passport import PACTAgent
from pact_passport.message import build_req


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def agent(tmp_path):
    """Standalone agent for direct-dispatch deadline tests."""
    a = PACTAgent("alice", store_dir=tmp_path)
    a._ensure_identity()

    @a.handle("ping")
    def ping(payload):
        return {"pong": True}

    return a


def _direct_dispatch(agent_obj, req):
    """Bypass HTTP — drive the dispatch pipeline directly."""
    return agent_obj._dispatch(req.to_dict())


def _build_req_with_deadline_seconds(agent_obj, deadline_seconds: int):
    """Build a self-addressed REQ with the given deadline_seconds offset."""
    me = agent_obj._identity
    return build_req(
        from_private_key=me._private_key,
        from_id=me.agent_id,
        to_id=me.agent_id,
        intent="task",
        payload={"action": "ping"},
        identity_doc=me.to_identity_document(),
        deadline_seconds=deadline_seconds,
    )


def _build_req_with_explicit_deadline(agent_obj, deadline_iso: str):
    """Build a self-addressed REQ whose deadline field is set explicitly
    to an ISO 8601 string (bypasses the helper's seconds-from-now math)."""
    me = agent_obj._identity
    req = build_req(
        from_private_key=me._private_key,
        from_id=me.agent_id,
        to_id=me.agent_id,
        intent="task",
        payload={"action": "ping"},
        identity_doc=me.to_identity_document(),
        deadline_seconds=30,
    )
    # Overwrite deadline + re-sign
    req.deadline = deadline_iso
    from pact_passport import crypto
    from pact_passport._canonical import canonical_json
    req.signature = ""
    payload_bytes = canonical_json(req.signable_dict())
    sig = crypto.sign(payload_bytes, agent_obj._identity._private_key)
    import base64
    req.signature = base64.b64encode(sig).decode()
    return req


# ---------------------------------------------------------------------------
# A6 — boundary cases
# ---------------------------------------------------------------------------


def test_a6_deadline_3599s_accepted(agent, capsys):
    """3599s — one second under the 3600s ceiling. Must be accepted."""
    req = _build_req_with_deadline_seconds(agent, 3599)
    res = _direct_dispatch(agent, req)
    print(f"\n[A6] deadline=3599s → status={res.get('status')}")
    assert res.get("status") == "ok", f"3599s should be accepted; got: {res}"


def test_a6_deadline_3600s_boundary(agent, capsys):
    """3600s — exactly at the ceiling. The comparison may be inclusive
    or exclusive; this test surfaces whichever choice the code makes."""
    req = _build_req_with_deadline_seconds(agent, 3600)
    res = _direct_dispatch(agent, req)
    status = res.get("status")
    fault_code = res.get("fault", {}).get("code") if status == "error" else None
    print(f"\n[A6] deadline=3600s → status={status} fault={fault_code}")

    # Either outcome is acceptable; we just need it to be consistent and
    # not produce an unexpected fault.
    if status == "ok":
        # Comparison is `deadline > now + max_deadline_seconds` (exclusive)
        # Document for the registry
        pass
    else:
        # Comparison is `deadline >= now + max_deadline_seconds` (inclusive)
        assert fault_code == "deadline_too_far", (
            f"3600s rejected with unexpected fault: {fault_code}; got: {res}"
        )


def test_a6_deadline_3601s_rejected(agent, capsys):
    """3601s — one second over the ceiling. Must be rejected with
    deadline_too_far."""
    req = _build_req_with_deadline_seconds(agent, 3601)
    res = _direct_dispatch(agent, req)
    status = res.get("status")
    fault_code = res.get("fault", {}).get("code") if status == "error" else None
    print(f"\n[A6] deadline=3601s → status={status} fault={fault_code}")
    assert status == "error", f"3601s should be rejected; got: {res}"
    assert fault_code == "deadline_too_far", (
        f"3601s should produce deadline_too_far; got: {fault_code}"
    )


def test_a6_deadline_year_9999_rejected(agent, capsys):
    """Extreme far-future deadline (year 9999) must be rejected with
    deadline_too_far (consistent with the v0.5.2 test_e7_far_future_deadline)."""
    far_future = "9999-12-31T23:59:59+00:00"
    req = _build_req_with_explicit_deadline(agent, far_future)
    res = _direct_dispatch(agent, req)
    status = res.get("status")
    fault_code = res.get("fault", {}).get("code") if status == "error" else None
    print(f"\n[A6] deadline=year 9999 → status={status} fault={fault_code}")
    assert status == "error"
    assert fault_code == "deadline_too_far", (
        f"year 9999 should produce deadline_too_far; got: {fault_code}"
    )


def test_a6_deadline_year_1970_rejected(agent, capsys):
    """Already-past deadline (year 1970 epoch). Must be rejected as
    deadline_exceeded (NOT deadline_too_far — it's in the past, not too
    far in the future).
    """
    past = "1970-01-01T00:00:01+00:00"
    req = _build_req_with_explicit_deadline(agent, past)
    res = _direct_dispatch(agent, req)
    status = res.get("status")
    fault_code = res.get("fault", {}).get("code") if status == "error" else None
    print(f"\n[A6] deadline=year 1970 → status={status} fault={fault_code}")
    assert status == "error"
    assert fault_code == "deadline_exceeded", (
        f"year 1970 should produce deadline_exceeded; got: {fault_code}"
    )


def test_a6_deadline_near_int_max_rejected(agent, capsys):
    """Near-int32-max seconds (2,147,483,647 ≈ year 2038 + decades).
    Must be rejected with deadline_too_far."""
    req = _build_req_with_deadline_seconds(agent, 2_147_483_647)
    res = _direct_dispatch(agent, req)
    status = res.get("status")
    fault_code = res.get("fault", {}).get("code") if status == "error" else None
    print(f"\n[A6] deadline=2^31 seconds → status={status} fault={fault_code}")
    assert status == "error"
    assert fault_code == "deadline_too_far"


def test_a6_custom_ceiling_boundary(tmp_path, capsys):
    """Server with custom max_deadline_seconds=86400 (24h) should accept
    a 12h deadline but reject a 25h deadline. Confirms the boundary
    enforcement is parameterized, not hardcoded to 3600s."""
    a = PACTAgent("longrun", store_dir=tmp_path, max_deadline_seconds=86400)
    a._ensure_identity()

    @a.handle("ping")
    def ping(payload):
        return {"pong": True}

    # 12h — under custom ceiling
    req_under = _build_req_with_deadline_seconds(a, 43200)
    res_under = _direct_dispatch(a, req_under)
    print(f"\n[A6-custom] deadline=12h (ceiling=24h) → status={res_under.get('status')}")
    assert res_under.get("status") == "ok"

    # 25h — over custom ceiling
    req_over = _build_req_with_deadline_seconds(a, 90000)
    res_over = _direct_dispatch(a, req_over)
    print(f"[A6-custom] deadline=25h (ceiling=24h) → status={res_over.get('status')}")
    assert res_over.get("status") == "error"
    assert res_over["fault"]["code"] == "deadline_too_far"
