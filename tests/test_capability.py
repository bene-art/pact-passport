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


# ---------------------------------------------------------------------------
# v1.3 chain re-derivation of action + caveats (Bug 9 closure)
# ---------------------------------------------------------------------------


def test_delegation_link_v1_3_round_trip():
    """to_dict() / from_dict() preserves action_at_step + caveats_at_step
    when set, alongside the v1.2 parent_cap_id."""
    cv = [Caveat(restrict="expires", value="2099-12-31T23:59:59+00:00")]
    link = DelegationLink(
        from_agent="alice",
        sig="sig123",
        parent_cap_id="cap-abc",
        action_at_step="read_doc",
        caveats_at_step=cv,
    )
    d = link.to_dict()
    assert d["action_at_step"] == "read_doc"
    assert d["caveats_at_step"] == [{"restrict": "expires", "value": "2099-12-31T23:59:59+00:00"}]
    restored = DelegationLink.from_dict(d)
    assert restored.action_at_step == "read_doc"
    assert restored.caveats_at_step == cv


def test_v1_3_chain_rejects_final_token_action_mutation():
    """Mutating the final token's action without re-running attenuate()
    must be rejected by the v1.3 chain-walk's final-token check."""
    alice_pub, carol_id, child, known_keys = _build_two_hop_chain()
    # Confirm chain carries v1.3 fields
    assert child.delegation_chain[0].action_at_step is not None
    assert child.delegation_chain[0].caveats_at_step is not None

    import copy
    forged = copy.deepcopy(child)
    forged.action = "write_doc"  # mutate without re-signing the chain

    result = verify_capability(forged, carol_id, alice_pub, known_keys)
    assert not result.valid, "mutated final action should be rejected"
    # Either the outer signature breaks first (action is in signable_dict)
    # or the v1.3 chain-walk catches it.
    assert (
        "action" in result.reason.lower()
        or "signature" in result.reason.lower()
    ), f"unexpected rejection reason: {result.reason}"


def test_v1_3_chain_rejects_final_token_caveat_stripping():
    """Stripping caveats from the final token without re-running
    attenuate() must be rejected by the v1.3 chain-walk's final-token
    consistency check."""
    alice_pub, carol_id, child, known_keys = _build_two_hop_chain()
    # Add a parent caveat by re-attenuating with a real caveat first
    bob_pub_b64 = "fake"  # placeholder; not used
    # Build a fresh root with caveats to make stripping observable
    alice_priv2, alice_pub2 = crypto.generate_keypair()
    bob_priv2, bob_pub2 = crypto.generate_keypair()
    carol_priv2, carol_pub2 = crypto.generate_keypair()
    alice_id2 = crypto.sha256_digest(alice_pub2)
    bob_id2 = crypto.sha256_digest(bob_pub2)
    carol_id2 = crypto.sha256_digest(carol_pub2)

    root = issue_capability(
        alice_priv2, alice_id2, bob_id2, "action",
        caveats=[Caveat(restrict="max_invocations", value=5)],
    )
    child = attenuate(
        root,
        delegator_private_key=bob_priv2,
        delegator_id=bob_id2,
        new_holder_id=carol_id2,
        additional_caveats=[],
    )
    known_keys2 = {alice_id2: alice_pub2, bob_id2: bob_pub2, carol_id2: carol_pub2}

    import copy
    forged = copy.deepcopy(child)
    forged.caveats = []  # strip everything

    result = verify_capability(forged, carol_id2, alice_pub2, known_keys2)
    assert not result.valid, "stripped final caveats should be rejected"
    assert (
        "caveat" in result.reason.lower()
        or "signature" in result.reason.lower()
    ), f"unexpected rejection reason: {result.reason}"


def test_v1_2_chain_format_emits_deprecation_warning_in_v1_3_verifier():
    """A v1.2-format chain (parent_cap_id present but no action_at_step /
    caveats_at_step) verifies at K=2 under v1.3 with a
    DeprecationWarning announcing the pre-v1.3 format. Bug 9 mitigation
    cannot be enforced for such chains; v1.4 will reject them."""
    import base64 as b64
    import uuid
    from pact._canonical import canonical_json

    # Build a v1.2-format chain (no action_at_step / caveats_at_step)
    alice_priv, alice_pub = crypto.generate_keypair()
    bob_priv, bob_pub = crypto.generate_keypair()
    carol_priv, carol_pub = crypto.generate_keypair()
    alice_id = crypto.sha256_digest(alice_pub)
    bob_id = crypto.sha256_digest(bob_pub)
    carol_id = crypto.sha256_digest(carol_pub)
    root = issue_capability(alice_priv, alice_id, bob_id, "action")

    # v1.2 attenuation: link signs only parent_cap_id
    chain_sig = crypto.sign(root.cap_id.encode(), bob_priv)
    v12_link = DelegationLink(
        from_agent=bob_id,
        sig=b64.b64encode(chain_sig).decode("ascii"),
        parent_cap_id=root.cap_id,
        # action_at_step and caveats_at_step intentionally omitted
    )
    v12_child = CapabilityToken(
        cap_id=str(uuid.uuid4()),
        issuer=alice_id,
        holder=carol_id,
        action="action",
        caveats=[],
        parent=root.cap_id,
        delegation_chain=[v12_link],
    )
    outer_sig = crypto.sign(canonical_json(v12_child.signable_dict()), bob_priv)
    v12_child.signature = b64.b64encode(outer_sig).decode("ascii")

    known_keys = {alice_id: alice_pub, bob_id: bob_pub, carol_id: carol_pub}

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = verify_capability(v12_child, carol_id, alice_pub, known_keys)

    assert result.valid, f"v1.2 chain at K=2 should still verify: {result.reason}"
    pre_v13_warnings = [
        w for w in caught
        if issubclass(w.category, DeprecationWarning)
        and ("pre-v1.3" in str(w.message) or "action_at_step" in str(w.message))
    ]
    assert pre_v13_warnings, (
        f"expected DeprecationWarning for pre-v1.3 chain format; "
        f"caught={[str(w.message) for w in caught]}"
    )
