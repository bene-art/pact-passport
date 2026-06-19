"""Tests for v1.4 / v0.8 policy profiles (spec §18.4)."""
from __future__ import annotations

from datetime import datetime, timedelta, UTC

import pytest

from pact_passport._canonical import canonical_json
from pact_passport.errors import (
    PACT_BUDGET_EXCEEDED,
    PACT_DEPTH_EXCEEDED,
    PACT_SCOPE_INSUFFICIENT,
    PACT_TOKEN_EXPIRED,
)
from pact_passport.policy import (
    AdvancedProfileSupport,
    PolicyProfile,
    PolicyProfileError,
    SIMPLE_CAVEAT_RESTRICTS,
    canonical_simple_caveat_bytes,
    classify_caveat_profile,
    classify_cap_profile,
    disable_advanced_profile,
    enable_advanced_profile,
    evaluate_caveats,
    make_action_caveat,
    make_budget_caveat,
    make_depth_caveat,
    make_expiry_caveat,
    register_standard_predicate,
    unregister_standard_predicate,
)


# ---------------------------------------------------------------------------
# Simple-profile templates (spec §18.4.1) — byte-normative
# ---------------------------------------------------------------------------

def test_action_caveat_canonical_form():
    """spec §18.4.1 — implementations MUST generate exactly this byte pattern."""
    c = make_action_caveat(["search", "browse"])
    expected = b'{"restrict":"action","value":["browse","search"]}'
    assert canonical_simple_caveat_bytes(c) == expected


def test_action_caveat_dedupes_and_sorts():
    """Lists are normalized to sorted-unique for byte stability."""
    c = make_action_caveat(["browse", "search", "browse"])
    assert c["value"] == ["browse", "search"]


def test_action_caveat_empty_rejected():
    with pytest.raises(ValueError, match="at least one"):
        make_action_caveat([])


def test_budget_caveat_canonical_form():
    c = make_budget_caveat(50)
    expected = b'{"restrict":"budget_cents","value":50}'
    assert canonical_simple_caveat_bytes(c) == expected


def test_budget_caveat_negative_rejected():
    with pytest.raises(ValueError, match="non-negative"):
        make_budget_caveat(-1)


def test_depth_caveat_canonical_form():
    c = make_depth_caveat(3)
    expected = b'{"restrict":"depth","value":3}'
    assert canonical_simple_caveat_bytes(c) == expected


def test_depth_caveat_zero_rejected():
    """depth must be ≥1 (chain of length 0 = root cap, no delegation)."""
    with pytest.raises(ValueError):
        make_depth_caveat(0)


def test_expiry_caveat_with_datetime():
    expires = datetime(2030, 1, 1, tzinfo=UTC)
    c = make_expiry_caveat(expires)
    expected = b'{"restrict":"expires_at","value":"2030-01-01T00:00:00+00:00"}'
    assert canonical_simple_caveat_bytes(c) == expected


def test_expiry_caveat_naive_datetime_rejected():
    naive = datetime(2030, 1, 1)
    with pytest.raises(ValueError, match="timezone"):
        make_expiry_caveat(naive)


def test_expiry_caveat_with_string_iso8601():
    c = make_expiry_caveat("2030-06-15T12:30:00+00:00")
    expected = b'{"restrict":"expires_at","value":"2030-06-15T12:30:00+00:00"}'
    assert canonical_simple_caveat_bytes(c) == expected


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def test_classify_simple_caveat():
    assert classify_caveat_profile(make_action_caveat(["x"])) == PolicyProfile.SIMPLE
    assert classify_caveat_profile(make_budget_caveat(0)) == PolicyProfile.SIMPLE


def test_classify_standard_caveat():
    c = {"restrict": "custom_rule", "value": 42}
    assert classify_caveat_profile(c) == PolicyProfile.STANDARD


def test_classify_advanced_caveat():
    c = {
        "restrict": "kyc_verified",
        "third_party": True,
        "verifier_endpoint": "https://kyc.example.com",
        "verifier_pubkey": "base64...",
    }
    assert classify_caveat_profile(c) == PolicyProfile.ADVANCED


def test_classify_cap_uses_max_profile():
    caveats = [
        make_action_caveat(["search"]),
        {"restrict": "custom", "value": 1},
    ]
    assert classify_cap_profile(caveats) == PolicyProfile.STANDARD


# ---------------------------------------------------------------------------
# Simple-profile satisfaction
# ---------------------------------------------------------------------------

def test_action_caveat_satisfied():
    c = make_action_caveat(["search", "browse"])
    evaluate_caveats([c], {"action": "search"})  # no raise = satisfied


def test_action_caveat_violation():
    c = make_action_caveat(["search"])
    with pytest.raises(PolicyProfileError) as exc:
        evaluate_caveats([c], {"action": "delete"})
    assert exc.value.code == PACT_SCOPE_INSUFFICIENT


def test_budget_caveat_satisfied():
    c = make_budget_caveat(100)
    evaluate_caveats([c], {"cost_cents": 50})


def test_budget_caveat_violation():
    c = make_budget_caveat(100)
    with pytest.raises(PolicyProfileError) as exc:
        evaluate_caveats([c], {"cost_cents": 200})
    assert exc.value.code == PACT_BUDGET_EXCEEDED


def test_depth_caveat_satisfied():
    c = make_depth_caveat(3)
    evaluate_caveats([c], {"chain_depth": 2})


def test_depth_caveat_violation():
    c = make_depth_caveat(2)
    with pytest.raises(PolicyProfileError) as exc:
        evaluate_caveats([c], {"chain_depth": 5})
    assert exc.value.code == PACT_DEPTH_EXCEEDED


def test_expiry_caveat_satisfied():
    future = (datetime.now(UTC) + timedelta(seconds=300)).isoformat()
    c = make_expiry_caveat(future)
    evaluate_caveats([c], {})  # current time < future


def test_expiry_caveat_violation():
    past = (datetime.now(UTC) - timedelta(seconds=60)).isoformat()
    c = make_expiry_caveat(past)
    with pytest.raises(PolicyProfileError) as exc:
        evaluate_caveats([c], {})
    assert exc.value.code == PACT_TOKEN_EXPIRED


# ---------------------------------------------------------------------------
# Standard-profile predicate registry
# ---------------------------------------------------------------------------

def test_standard_predicate_registration_and_eval():
    def always_true(caveat, ctx):
        return True

    register_standard_predicate("trust_check", always_true)
    try:
        c = {"restrict": "trust_check", "value": "x"}
        evaluate_caveats([c], {})
    finally:
        unregister_standard_predicate("trust_check")


def test_standard_predicate_missing_handler_fails_closed():
    """spec §18.4.2 — missing handler MUST reject."""
    c = {"restrict": "unregistered_predicate", "value": 0}
    with pytest.raises(PolicyProfileError) as exc:
        evaluate_caveats([c], {})
    assert exc.value.code == PACT_SCOPE_INSUFFICIENT


def test_standard_predicate_cannot_shadow_simple_restrict():
    def f(c, ctx): return True
    with pytest.raises(ValueError, match="shadows"):
        register_standard_predicate("action", f)


# ---------------------------------------------------------------------------
# Advanced profile
# ---------------------------------------------------------------------------

def test_advanced_caveat_rejected_when_advanced_disabled():
    """spec §18.4.3 — Advanced is opt-in. Default = reject."""
    disable_advanced_profile()  # ensure default state
    c = {
        "restrict": "kyc", "third_party": True,
        "verifier_endpoint": "https://x", "verifier_pubkey": "b64",
    }
    with pytest.raises(PolicyProfileError) as exc:
        evaluate_caveats([c], {})
    assert exc.value.code == PACT_SCOPE_INSUFFICIENT


def test_advanced_caveat_evaluated_when_enabled():
    """Enabling Advanced runs the registered third-party handler."""
    calls = []

    def handler(caveat, ctx):
        calls.append(caveat["verifier_endpoint"])
        return True  # assertion passes

    enable_advanced_profile(handler)
    try:
        c = {
            "restrict": "kyc", "third_party": True,
            "verifier_endpoint": "https://x", "verifier_pubkey": "b64",
        }
        evaluate_caveats([c], {})
        assert calls == ["https://x"]
    finally:
        disable_advanced_profile()


def test_advanced_caveat_handler_rejection_propagates():
    def handler(caveat, ctx): return False

    enable_advanced_profile(handler)
    try:
        c = {
            "restrict": "kyc", "third_party": True,
            "verifier_endpoint": "https://x", "verifier_pubkey": "b64",
        }
        with pytest.raises(PolicyProfileError) as exc:
            evaluate_caveats([c], {})
        assert exc.value.code == PACT_SCOPE_INSUFFICIENT
    finally:
        disable_advanced_profile()
