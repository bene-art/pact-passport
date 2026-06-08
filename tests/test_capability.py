"""Tests for capability module."""

import warnings
from datetime import datetime, timezone, timedelta

import pytest

from pact import crypto
from pact.capability import (
    attenuate,
    Caveat, CapabilityToken, DelegationLink,
    issue_capability, verify_capability, CapabilityResult,
)


def test_issue_capability():
    priv, pub = crypto.generate_keypair()
    issuer_id = crypto.sha256_digest(pub)
    holder_id = "sha256:holder123"

    token = issue_capability(priv, issuer_id, holder_id, "get_weather")
    assert token.issuer == issuer_id
    assert token.holder == holder_id
    assert token.action == "get_weather"
    assert token.signature


def test_verify_capability():
    priv, pub = crypto.generate_keypair()
    issuer_id = crypto.sha256_digest(pub)
    holder_id = "sha256:holder123"

    token = issue_capability(priv, issuer_id, holder_id, "get_weather")
    result = verify_capability(token, holder_id, pub)
    assert result.valid


def test_verify_wrong_holder():
    priv, pub = crypto.generate_keypair()
    issuer_id = crypto.sha256_digest(pub)

    token = issue_capability(priv, issuer_id, "sha256:real_holder", "get_weather")
    result = verify_capability(token, "sha256:wrong_holder", pub)
    assert not result.valid
    assert "Holder mismatch" in result.reason


def test_verify_wrong_key():
    priv1, _ = crypto.generate_keypair()
    _, pub2 = crypto.generate_keypair()
    issuer_id = "sha256:issuer"
    holder_id = "sha256:holder"

    token = issue_capability(priv1, issuer_id, holder_id, "action")
    result = verify_capability(token, holder_id, pub2)
    assert not result.valid
    assert "Invalid signature" in result.reason


def test_expired_capability():
    priv, pub = crypto.generate_keypair()
    issuer_id = crypto.sha256_digest(pub)
    holder_id = "sha256:holder"

    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    token = issue_capability(
        priv, issuer_id, holder_id, "action",
        caveats=[Caveat("expires", past)],
    )
    result = verify_capability(token, holder_id, pub)
    assert not result.valid
    assert "expired" in result.reason


def test_valid_expiry():
    priv, pub = crypto.generate_keypair()
    issuer_id = crypto.sha256_digest(pub)
    holder_id = "sha256:holder"

    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    token = issue_capability(
        priv, issuer_id, holder_id, "action",
        caveats=[Caveat("expires", future)],
    )
    result = verify_capability(token, holder_id, pub)
    assert result.valid


def test_token_round_trip():
    priv, pub = crypto.generate_keypair()
    token = issue_capability(priv, "issuer", "holder", "action")
    d = token.to_dict()
    restored = CapabilityToken.from_dict(d)
    assert restored.cap_id == token.cap_id
    assert restored.signature == token.signature


# ---------------------------------------------------------------------------
# DelegationLink.parent_cap_id (v0.6, closes Bug 6 / GH #29)
# ---------------------------------------------------------------------------


def test_delegation_link_parent_cap_id_round_trip():
    """to_dict() / from_dict() preserves parent_cap_id when set."""
    link = DelegationLink(from_agent="alice", sig="sig123", parent_cap_id="cap-abc")
    d = link.to_dict()
    assert d["parent_cap_id"] == "cap-abc"
    restored = DelegationLink.from_dict(d)
    assert restored == link


def test_delegation_link_legacy_format_loads_without_parent_cap_id():
    """Pre-v0.6 link dicts (no parent_cap_id key) load with the field
    set to None. Backwards-compat path for the v0.6 → v0.7 deprecation
    window."""
    legacy = {"from": "alice", "sig": "sig123"}    # no parent_cap_id
    link = DelegationLink.from_dict(legacy)
    assert link.parent_cap_id is None
    # to_dict round-trip preserves the absence (does not write the key)
    assert "parent_cap_id" not in link.to_dict()


def _build_two_hop_chain():
    """Helper: build a depth-2 cap. Alice → Bob → Carol.
    Returns (alice_pub, bob_id, carol_id, child_cap, known_keys)."""
    alice_priv, alice_pub = crypto.generate_keypair()
    bob_priv, bob_pub = crypto.generate_keypair()
    carol_priv, carol_pub = crypto.generate_keypair()
    alice_id = crypto.sha256_digest(alice_pub)
    bob_id = crypto.sha256_digest(bob_pub)
    carol_id = crypto.sha256_digest(carol_pub)

    root = issue_capability(alice_priv, alice_id, bob_id, "action")
    child = attenuate(
        root,
        delegator_private_key=bob_priv,
        delegator_id=bob_id,
        new_holder_id=carol_id,
        additional_caveats=[],
    )
    known_keys = {alice_id: alice_pub, bob_id: bob_pub, carol_id: carol_pub}
    return alice_pub, carol_id, child, known_keys


def _build_legacy_two_hop_chain():
    """Build a depth-2 cap the pre-v0.6 way: chain link has no
    parent_cap_id field, and the outer token signature is computed
    over the legacy signable_dict (which omits parent_cap_id from
    every link dict). This is what an in-the-wild v0.5.x cap looks
    like to a v0.6 verifier.
    """
    import base64 as b64
    import uuid
    from pact._canonical import canonical_json

    alice_priv, alice_pub = crypto.generate_keypair()
    bob_priv, bob_pub = crypto.generate_keypair()
    carol_priv, carol_pub = crypto.generate_keypair()
    alice_id = crypto.sha256_digest(alice_pub)
    bob_id = crypto.sha256_digest(bob_pub)
    carol_id = crypto.sha256_digest(carol_pub)

    root = issue_capability(alice_priv, alice_id, bob_id, "action")

    # Pre-v0.6 attenuation: bob signs root.cap_id, but the link dict
    # carries no parent_cap_id, and the outer token is signed over the
    # legacy signable_dict (no parent_cap_id keys anywhere).
    chain_sig = crypto.sign(root.cap_id.encode(), bob_priv)
    legacy_link = DelegationLink(
        from_agent=bob_id,
        sig=b64.b64encode(chain_sig).decode("ascii"),
        parent_cap_id=None,
    )
    legacy_child = CapabilityToken(
        cap_id=str(uuid.uuid4()),
        issuer=alice_id,
        holder=carol_id,
        action="action",
        caveats=[],
        parent=root.cap_id,
        delegation_chain=[legacy_link],
    )
    outer_sig = crypto.sign(canonical_json(legacy_child.signable_dict()), bob_priv)
    legacy_child.signature = b64.b64encode(outer_sig).decode("ascii")

    known_keys = {alice_id: alice_pub, bob_id: bob_pub, carol_id: carol_pub}
    return alice_pub, carol_id, legacy_child, known_keys


def test_pre_v0_6_chain_format_emits_deprecation_warning():
    """A genuine pre-v0.6 chain (no parent_cap_id field; outer signature
    over the legacy signable_dict) verifies at K=2 and triggers a
    DeprecationWarning. This is the v0.6 → v0.7 migration signal."""
    alice_pub, carol_id, legacy_child, known_keys = _build_legacy_two_hop_chain()
    assert legacy_child.delegation_chain[0].parent_cap_id is None

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = verify_capability(legacy_child, carol_id, alice_pub, known_keys)
    assert result.valid, f"legacy K=2 chain should verify: {result.reason}"
    deprecation_warnings = [
        w for w in caught
        if issubclass(w.category, DeprecationWarning)
        and "parent_cap_id" in str(w.message)
    ]
    assert deprecation_warnings, (
        f"expected DeprecationWarning for pre-v0.6 chain format; "
        f"caught={[str(w.message) for w in caught]}"
    )


def test_mutated_parent_cap_id_invalidates_chain():
    """Tampering with a link's parent_cap_id must invalidate the chain.

    The outer token signature covers the link's parent_cap_id (it's
    part of signable_dict), so mutation breaks the outer signature
    before chain-link verification even runs. Either rejection reason
    is acceptable — the property under test is that the chain does
    NOT verify."""
    alice_pub, carol_id, child, known_keys = _build_two_hop_chain()
    mutated_dict = child.to_dict()
    mutated_dict["delegation_chain"][0]["parent_cap_id"] = "tampered-cap-id"
    mutated = CapabilityToken.from_dict(mutated_dict)
    result = verify_capability(mutated, carol_id, alice_pub, known_keys)
    assert not result.valid, "chain with tampered parent_cap_id must not verify"
    # The mutation breaks the outer delegator signature first (because
    # parent_cap_id is part of signable_dict). That's a stronger
    # rejection than reaching the chain-link check. Either reason path
    # is acceptable; both prove the field is part of the trust surface.
    assert (
        "signature" in result.reason.lower()
        or "delegation chain link" in result.reason.lower()
    ), f"unexpected rejection reason: {result.reason}"
