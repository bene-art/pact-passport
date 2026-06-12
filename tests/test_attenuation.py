"""Tests for capability attenuation (Phase 2)."""

import pytest
from datetime import datetime, timezone, timedelta

from pact_passport import crypto
from pact_passport.capability import (
    Caveat, CapabilityToken, issue_capability, attenuate,
    verify_capability, DelegationLink,
)
from pact_passport.errors import AttenuationViolation


@pytest.fixture
def three_agents():
    """Create three agents: issuer (A), delegator (B), final holder (C)."""
    priv_a, pub_a = crypto.generate_keypair()
    priv_b, pub_b = crypto.generate_keypair()
    priv_c, pub_c = crypto.generate_keypair()
    id_a = crypto.sha256_digest(pub_a)
    id_b = crypto.sha256_digest(pub_b)
    id_c = crypto.sha256_digest(pub_c)
    return {
        "a": {"priv": priv_a, "pub": pub_a, "id": id_a},
        "b": {"priv": priv_b, "pub": pub_b, "id": id_b},
        "c": {"priv": priv_c, "pub": pub_c, "id": id_c},
    }


def test_attenuate_basic(three_agents):
    """A issues to B, B attenuates to C with tighter caveat."""
    a, b, c = three_agents["a"], three_agents["b"], three_agents["c"]

    root = issue_capability(a["priv"], a["id"], b["id"], "read_data")
    child = attenuate(root, b["priv"], b["id"], c["id"], [
        Caveat("max_invocations", 5),
    ])

    assert child.parent == root.cap_id
    assert child.holder == c["id"]
    assert child.issuer == a["id"]  # root issuer preserved
    assert child.action == "read_data"
    assert len(child.delegation_chain) == 1
    assert child.delegation_chain[0].from_agent == b["id"]


def test_attenuate_inherits_caveats(three_agents):
    """Child inherits all parent caveats plus additional ones."""
    a, b, c = three_agents["a"], three_agents["b"], three_agents["c"]

    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    root = issue_capability(a["priv"], a["id"], b["id"], "action",
                           caveats=[Caveat("expires", future)])

    child = attenuate(root, b["priv"], b["id"], c["id"], [
        Caveat("max_invocations", 3),
    ])

    restrict_types = [c.restrict for c in child.caveats]
    assert "expires" in restrict_types
    assert "max_invocations" in restrict_types
    assert len(child.caveats) == 2


def test_attenuate_reject_widen_max_invocations(three_agents):
    """Cannot widen max_invocations beyond parent's value."""
    a, b, c = three_agents["a"], three_agents["b"], three_agents["c"]

    root = issue_capability(a["priv"], a["id"], b["id"], "action",
                           caveats=[Caveat("max_invocations", 5)])

    with pytest.raises(AttenuationViolation, match="Cannot widen max_invocations"):
        attenuate(root, b["priv"], b["id"], c["id"], [
            Caveat("max_invocations", 10),
        ])


def test_attenuate_reject_widen_expiry(three_agents):
    """Cannot extend expiry beyond parent's value."""
    a, b, c = three_agents["a"], three_agents["b"], three_agents["c"]

    soon = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    later = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()

    root = issue_capability(a["priv"], a["id"], b["id"], "action",
                           caveats=[Caveat("expires", soon)])

    with pytest.raises(AttenuationViolation, match="Cannot extend expiry"):
        attenuate(root, b["priv"], b["id"], c["id"], [
            Caveat("expires", later),
        ])


def test_attenuate_ok_tighter_expiry(three_agents):
    """Can tighten expiry to earlier than parent's."""
    a, b, c = three_agents["a"], three_agents["b"], three_agents["c"]

    later = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
    sooner = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    root = issue_capability(a["priv"], a["id"], b["id"], "action",
                           caveats=[Caveat("expires", later)])

    child = attenuate(root, b["priv"], b["id"], c["id"], [
        Caveat("expires", sooner),
    ])
    # Parent's expiry + child's tighter expiry both present
    assert len([c for c in child.caveats if c.restrict == "expires"]) == 2


def test_attenuate_reject_terminal(three_agents):
    """Cannot attenuate a token with no_further_delegation."""
    a, b, c = three_agents["a"], three_agents["b"], three_agents["c"]

    root = issue_capability(a["priv"], a["id"], b["id"], "action",
                           caveats=[Caveat("no_further_delegation", True, terminal=True)])

    with pytest.raises(AttenuationViolation, match="no_further_delegation"):
        attenuate(root, b["priv"], b["id"], c["id"], [])


def test_attenuate_reject_wrong_delegator(three_agents):
    """Only the holder can attenuate."""
    a, b, c = three_agents["a"], three_agents["b"], three_agents["c"]

    root = issue_capability(a["priv"], a["id"], b["id"], "action")

    with pytest.raises(AttenuationViolation, match="not the holder"):
        attenuate(root, c["priv"], c["id"], c["id"], [])


def test_verify_attenuated_with_known_keys(three_agents):
    """Verify an attenuated token using known_keys for chain validation."""
    a, b, c = three_agents["a"], three_agents["b"], three_agents["c"]

    root = issue_capability(a["priv"], a["id"], b["id"], "action")
    child = attenuate(root, b["priv"], b["id"], c["id"], [
        Caveat("max_invocations", 3),
    ])

    known_keys = {a["id"]: a["pub"], b["id"]: b["pub"], c["id"]: c["pub"]}
    result = verify_capability(child, c["id"], a["pub"], known_keys=known_keys)
    assert result.valid


def test_verify_revoked_token(three_agents):
    """Revoked tokens fail verification."""
    a, b = three_agents["a"], three_agents["b"]

    root = issue_capability(a["priv"], a["id"], b["id"], "action")
    root.revoked = True

    result = verify_capability(root, b["id"], a["pub"])
    assert not result.valid
    assert "revoked" in result.reason


def test_delegation_chain_round_trip(three_agents):
    """Delegation chain survives serialization."""
    a, b, c = three_agents["a"], three_agents["b"], three_agents["c"]

    root = issue_capability(a["priv"], a["id"], b["id"], "action")
    child = attenuate(root, b["priv"], b["id"], c["id"], [])

    d = child.to_dict()
    restored = CapabilityToken.from_dict(d)
    assert restored.parent == root.cap_id
    assert len(restored.delegation_chain) == 1
    assert restored.delegation_chain[0].from_agent == b["id"]
