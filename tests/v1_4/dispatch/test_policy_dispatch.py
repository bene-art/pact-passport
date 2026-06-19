"""δ.1.4 — policy.evaluate_caveats dispatch-integration tests (spec §18.4).

v0.8.1 exposes the three-profile policy model (Simple / Standard / Advanced)
as part of the v0.8.1 public API. These tests verify the integration:

1. Public-API surface: evaluate_caveats + factories are importable from
   ``pact_passport``.
2. Simple-profile byte-normative factories produce canonical-JSON forms
   matching spec §18.4.1.
3. evaluate_caveats raises ``PolicyProfileError`` with the correct wire-level
   pact_* fault code per the spec §18.4 → §18.3 mapping.
4. Mixed-profile caps classify as the highest-tier profile present.

The existing legacy ``Caveat`` dataclass and capability.py verifier remain
the v0.7 path; this module's tests cover the new v0.8/v1.4 policy path.
"""
from __future__ import annotations

from datetime import datetime, timedelta, UTC

import pytest

from pact_passport import (
    PolicyProfile,
    PolicyProfileError,
    classify_cap_profile,
    classify_caveat_profile,
    evaluate_caveats,
    make_action_caveat,
    make_budget_caveat,
    make_depth_caveat,
    make_expiry_caveat,
)
from pact_passport._canonical import canonical_json
from pact_passport.errors import (
    PACT_BUDGET_EXCEEDED,
    PACT_DEPTH_EXCEEDED,
    PACT_SCOPE_INSUFFICIENT,
    PACT_TOKEN_EXPIRED,
)


# =============================================================================
# Public-API surface (δ.1.4 deliverable)
# =============================================================================

def test_policy_api_importable_from_top_level():
    """All policy + audit symbols are re-exported from pact_passport.__init__."""
    import pact_passport as pp
    assert hasattr(pp, "evaluate_caveats")
    assert hasattr(pp, "PolicyProfile")
    assert hasattr(pp, "PolicyProfileError")
    assert hasattr(pp, "make_action_caveat")
    assert hasattr(pp, "make_budget_caveat")
    assert hasattr(pp, "make_depth_caveat")
    assert hasattr(pp, "make_expiry_caveat")
    assert hasattr(pp, "classify_cap_profile")
    assert hasattr(pp, "classify_caveat_profile")


def test_audit_api_importable_from_top_level():
    """Audit module API also exposed for v0.8.1."""
    import pact_passport as pp
    assert hasattr(pp, "audit_req")
    assert hasattr(pp, "audit_receipt")
    assert hasattr(pp, "AuditResult")
    assert hasattr(pp, "make_bilateral_receipt")
    assert hasattr(pp, "sign_initiator_ack")


# =============================================================================
# Simple-profile byte-normative factories (spec §18.4.1)
# =============================================================================

def test_make_action_caveat_canonical_form():
    """Spec §18.4.1 action caveat → {"restrict":"action","value":[...]}"""
    c = make_action_caveat(["ping", "echo"])
    assert c == {"restrict": "action", "value": ["echo", "ping"]}
    # Canonical-JSON byte form (sorted keys, no whitespace)
    assert canonical_json(c) == b'{"restrict":"action","value":["echo","ping"]}'


def test_make_budget_caveat_canonical_form():
    c = make_budget_caveat(50000)
    assert c == {"restrict": "budget_cents", "value": 50000}
    assert canonical_json(c) == b'{"restrict":"budget_cents","value":50000}'


def test_make_depth_caveat_canonical_form():
    c = make_depth_caveat(3)
    assert c == {"restrict": "depth", "value": 3}
    assert canonical_json(c) == b'{"restrict":"depth","value":3}'


def test_make_expiry_caveat_canonical_form():
    iso = "2026-12-31T23:59:59+00:00"
    c = make_expiry_caveat(iso)
    assert c == {"restrict": "expires_at", "value": iso}


# =============================================================================
# classify_caveat_profile / classify_cap_profile
# =============================================================================

def test_simple_caveat_classifies_as_simple():
    for c in [make_action_caveat(["ping"]),
              make_budget_caveat(100),
              make_depth_caveat(2),
              make_expiry_caveat("2099-01-01T00:00:00+00:00")]:
        assert classify_caveat_profile(c) == PolicyProfile.SIMPLE


def test_standard_caveat_classifies_as_standard():
    """Caveat with restrict outside Simple set → Standard."""
    c = {"restrict": "geographic_region", "value": "US"}
    assert classify_caveat_profile(c) == PolicyProfile.STANDARD


def test_advanced_caveat_classifies_as_advanced():
    """Third-party verifier endpoint marker → Advanced."""
    c = {
        "restrict": "third_party_credit_check",
        "value": "ok",
        "third_party": True,
        "verifier_endpoint": "https://example.com/verify",
        "verifier_pubkey": "abc",
    }
    assert classify_caveat_profile(c) == PolicyProfile.ADVANCED


def test_cap_with_mixed_profiles_classifies_as_highest():
    """Mixed: Simple + Standard → Standard; + Advanced → Advanced."""
    cap_simple_only = [make_action_caveat(["ping"]),
                       make_budget_caveat(100)]
    assert classify_cap_profile(cap_simple_only) == PolicyProfile.SIMPLE

    cap_with_standard = cap_simple_only + [{"restrict": "geo", "value": "US"}]
    assert classify_cap_profile(cap_with_standard) == PolicyProfile.STANDARD

    cap_with_advanced = cap_with_standard + [{
        "restrict": "third_party_x",
        "value": "ok",
        "third_party": True,
        "verifier_endpoint": "https://e.com/v",
        "verifier_pubkey": "k",
    }]
    assert classify_cap_profile(cap_with_advanced) == PolicyProfile.ADVANCED


# =============================================================================
# evaluate_caveats — Simple-profile fault-code mapping (spec §18.4 → §18.3)
# =============================================================================

def test_evaluate_action_caveat_satisfied():
    """Action caveat allows the requested action → no exception."""
    caveats = [make_action_caveat(["ping", "echo"])]
    evaluate_caveats(caveats, {"action": "ping"})  # no raise


def test_evaluate_action_caveat_violated_raises_scope_insufficient():
    caveats = [make_action_caveat(["ping"])]
    with pytest.raises(PolicyProfileError) as exc:
        evaluate_caveats(caveats, {"action": "delete"})
    assert exc.value.code == PACT_SCOPE_INSUFFICIENT


def test_evaluate_budget_caveat_satisfied():
    caveats = [make_budget_caveat(50000)]
    evaluate_caveats(caveats, {"cost_cents": 10000})  # under ceiling


def test_evaluate_budget_caveat_violated_raises_budget_exceeded():
    caveats = [make_budget_caveat(100)]
    with pytest.raises(PolicyProfileError) as exc:
        evaluate_caveats(caveats, {"cost_cents": 500})
    assert exc.value.code == PACT_BUDGET_EXCEEDED


def test_evaluate_depth_caveat_violated_raises_depth_exceeded():
    caveats = [make_depth_caveat(2)]
    with pytest.raises(PolicyProfileError) as exc:
        evaluate_caveats(caveats, {"chain_depth": 5})
    assert exc.value.code == PACT_DEPTH_EXCEEDED


def test_evaluate_expiry_caveat_violated_raises_token_expired():
    past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    caveats = [make_expiry_caveat(past)]
    with pytest.raises(PolicyProfileError) as exc:
        evaluate_caveats(caveats, {"now": datetime.now(UTC)})
    assert exc.value.code == PACT_TOKEN_EXPIRED


def test_evaluate_standard_profile_unknown_predicate_fails_closed():
    """Standard predicate with no registered handler → fail-closed
    pact_scope_insufficient (spec §18.4.2)."""
    caveats = [{"restrict": "no_such_predicate", "value": "x"}]
    with pytest.raises(PolicyProfileError) as exc:
        evaluate_caveats(caveats, {})
    assert exc.value.code == PACT_SCOPE_INSUFFICIENT


def test_evaluate_multiple_simple_caveats_all_satisfied():
    """A cap with action + budget + depth all satisfied dispatches cleanly."""
    caveats = [
        make_action_caveat(["ping"]),
        make_budget_caveat(50000),
        make_depth_caveat(3),
    ]
    evaluate_caveats(caveats, {
        "action": "ping",
        "cost_cents": 1000,
        "chain_depth": 2,
    })


def test_evaluate_fails_on_first_violated_caveat():
    """Caveat list evaluated in order — first violation determines fault."""
    caveats = [
        make_action_caveat(["ping"]),       # would pass
        make_budget_caveat(100),            # would fail (cost=500)
        make_depth_caveat(2),               # would also fail (depth=5)
    ]
    with pytest.raises(PolicyProfileError) as exc:
        evaluate_caveats(caveats, {
            "action": "ping",
            "cost_cents": 500,
            "chain_depth": 5,
        })
    # First violation: budget; would not reach depth
    assert exc.value.code == PACT_BUDGET_EXCEEDED
