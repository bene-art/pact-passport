"""Tests for v1.4 / v0.8 domain-separated holder_proof (spec §18.1).

These tests are the runtime companion to the Tamarin Run 3 closure of
P_BIND (spec/models/PROOF_LOG.md §"Run 3"). Where Tamarin proves the
symbolic claim, these tests verify the byte-level wire conformance.
"""
from __future__ import annotations

import base64

import pytest

from pact_passport import crypto
from pact_passport.message import (
    HOLDER_PROOF_DOMAIN_V1,
    VISA_USE_DOMAIN_V1,
    build_req,
    holder_proof_payload,
    verify_holder_proof,
    visa_use_payload,
)
from pact_passport.visa import sign_visa_holder_proof, verify_visa_holder_proof
from pact_passport._canonical import canonical_json


@pytest.fixture
def holder_keypair():
    return crypto.generate_keypair()


@pytest.fixture
def sender_keypair():
    return crypto.generate_keypair()


# ---------------------------------------------------------------------------
# Domain separation: the two signing strings differ at every level
# ---------------------------------------------------------------------------

def test_domain_tags_are_distinct_strings():
    """spec §18.1 — the two domain tags MUST be different literals."""
    assert HOLDER_PROOF_DOMAIN_V1 == "pact/hp/v1"
    assert VISA_USE_DOMAIN_V1 == "pact/visa/v1"
    assert HOLDER_PROOF_DOMAIN_V1 != VISA_USE_DOMAIN_V1


def test_holder_proof_payload_canonical_form():
    """spec §18.1 — canonical-JSON keys MUST be sorted."""
    payload = holder_proof_payload(
        req_id="abc-123",
        cap_id="cap-456",
        to_agent="sha256:dead",
    )
    # canonical_json sorts keys alphabetically. cap_id < domain < req_id < to_agent.
    expected = (
        b'{"cap_id":"cap-456","domain":"pact/hp/v1","req_id":"abc-123","to_agent":"sha256:dead"}'
    )
    assert payload == expected


def test_visa_use_payload_canonical_form():
    """spec §18.1 — visa-use signing string also canonical-form."""
    payload = visa_use_payload(nonce="sha256:nonce-xyz")
    expected = b'{"domain":"pact/visa/v1","nonce":"sha256:nonce-xyz"}'
    assert payload == expected


def test_holder_proof_and_visa_payloads_differ_for_same_id(holder_keypair):
    """spec §18.1 — load-bearing: signatures over the two payloads MUST be different.

    This is the closure of the Run 2 P_BIND falsification: an attacker
    observing a visa-use signature cannot replay it as a non-visa
    holder_proof because the signed terms differ.
    """
    private_key, _ = holder_keypair
    same_id = "same-bytes-here"

    hp_sig = crypto.sign(
        holder_proof_payload(same_id, "cap-X", "sha256:rcvr"),
        private_key,
    )
    visa_sig = crypto.sign(visa_use_payload(same_id), private_key)

    assert hp_sig != visa_sig, (
        "If these were equal, P_BIND would still falsify — "
        "domain separation is structurally broken"
    )


def test_holder_proof_payload_binds_req_id():
    """spec §18.1 — signature for one req_id MUST NOT verify for another."""
    p1 = holder_proof_payload("req-A", "cap-X", "sha256:rcvr")
    p2 = holder_proof_payload("req-B", "cap-X", "sha256:rcvr")
    assert p1 != p2


def test_holder_proof_payload_binds_cap_id():
    """spec §18.1 — signature for one cap_id MUST NOT verify for another."""
    p1 = holder_proof_payload("req-A", "cap-X", "sha256:rcvr")
    p2 = holder_proof_payload("req-A", "cap-Y", "sha256:rcvr")
    assert p1 != p2


def test_holder_proof_payload_binds_to_agent():
    """spec §18.1 — signature for one to_agent MUST NOT verify for another."""
    p1 = holder_proof_payload("req-A", "cap-X", "sha256:rcvr1")
    p2 = holder_proof_payload("req-A", "cap-X", "sha256:rcvr2")
    assert p1 != p2


def test_holder_proof_payload_none_cap_id_normalized_to_empty():
    """cap_id of None is normalized to '' for canonicalization stability."""
    p1 = holder_proof_payload("req-A", None, "sha256:rcvr")
    p2 = holder_proof_payload("req-A", "", "sha256:rcvr")
    assert p1 == p2


# ---------------------------------------------------------------------------
# build_req produces v0.8 holder_proof and verifies under v0.8 verifier
# ---------------------------------------------------------------------------

def test_build_req_signs_v0_8_holder_proof(holder_keypair, sender_keypair):
    """build_req signs over the v1.4 structured payload, not bare msg.id."""
    holder_priv, holder_pub = holder_keypair
    sender_priv, _ = sender_keypair

    msg = build_req(
        from_private_key=sender_priv,
        from_id="sha256:sender",
        to_id="sha256:receiver",
        intent="task",
        cap_id="cap-1",
        holder_proof_key=holder_priv,
    )

    assert msg.holder_proof is not None

    # The v0.8 verifier (without legacy fallback) MUST accept.
    assert verify_holder_proof(msg, holder_pub, allow_legacy_v07=False) is True


def test_v0_8_holder_proof_does_NOT_verify_under_bare_id_check(holder_keypair, sender_keypair):
    """The v0.8 signature is NOT recoverable as a bare-msg.id signature.

    This proves that an attacker capturing a v0.8 holder_proof cannot use
    it where a bare-msg.id signature is expected (and vice versa).
    """
    holder_priv, holder_pub = holder_keypair
    sender_priv, _ = sender_keypair

    msg = build_req(
        from_private_key=sender_priv,
        from_id="sha256:sender",
        to_id="sha256:receiver",
        intent="task",
        cap_id="cap-1",
        holder_proof_key=holder_priv,
    )

    # If we strip the v0.8 verifier and only check bare msg.id, the v0.8
    # signature MUST NOT verify — proving the two formats are incompatible.
    sig_bytes = base64.b64decode(msg.holder_proof)
    assert crypto.verify(msg.id.encode(), sig_bytes, holder_pub) is False


# ---------------------------------------------------------------------------
# Migration window (spec §18.7) — legacy v0.7 holder_proof accepted with warning
# ---------------------------------------------------------------------------

def test_legacy_v0_7_holder_proof_accepted_with_deprecation_warning(holder_keypair, sender_keypair):
    """spec §18.7 — v0.7 bare-msg.id signatures accepted during migration window."""
    holder_priv, holder_pub = holder_keypair
    sender_priv, _ = sender_keypair

    # Build a REQ but replace holder_proof with v0.7 bare-bytes form.
    msg = build_req(
        from_private_key=sender_priv,
        from_id="sha256:sender",
        to_id="sha256:receiver",
        intent="task",
        cap_id="cap-1",
        holder_proof_key=holder_priv,  # produces v0.8 form
    )

    # Replace with v0.7 form: sign bare msg.id
    v07_sig = crypto.sign(msg.id.encode(), holder_priv)
    msg.holder_proof = base64.b64encode(v07_sig).decode("ascii")

    # With allow_legacy_v07=True (default), accept + warn
    with pytest.warns(DeprecationWarning, match="v0.7 bare-payload"):
        result = verify_holder_proof(msg, holder_pub, allow_legacy_v07=True)
    assert result is True

    # With allow_legacy_v07=False, reject (post-migration-window behavior)
    result = verify_holder_proof(msg, holder_pub, allow_legacy_v07=False)
    assert result is False


# ---------------------------------------------------------------------------
# Visa-use signing (the visa side of the v0.8 fix)
# ---------------------------------------------------------------------------

def test_sign_visa_holder_proof_uses_domain_separated_payload(holder_keypair):
    """spec §18.1 — visa-use signature MUST be over the structured payload."""
    holder_priv, holder_pub = holder_keypair
    nonce = "sha256:abcdef"

    proof = sign_visa_holder_proof(nonce, holder_priv)

    # Verify with the v1.4 verifier (no legacy fallback) — MUST accept.
    assert verify_visa_holder_proof(proof, nonce, holder_pub, allow_legacy_v07=False)


def test_visa_holder_proof_does_NOT_cross_verify_as_non_visa(holder_keypair):
    """The closure of P_BIND: visa signature cannot replay as holder_proof.

    Same key, same nonce, same canonical-JSON serialization on both sides —
    but the domain tags differ, so the signed payloads differ, so the
    signatures are not interchangeable.
    """
    from pact_passport.message import PACTMessage

    holder_priv, holder_pub = holder_keypair
    nonce = "sha256:nonce123"

    visa_proof_b64 = sign_visa_holder_proof(nonce, holder_priv)
    visa_sig_bytes = base64.b64decode(visa_proof_b64)

    # Construct a REQ where req_id = nonce, simulating the Run 2 attack.
    msg = PACTMessage(
        id=nonce,
        type="REQ",
        from_agent="sha256:attacker",
        to_agent="sha256:victim",
        cap_id="cap-Y",
    )
    msg.holder_proof = visa_proof_b64

    # The non-visa verify_holder_proof MUST reject — the visa signature was
    # over <"pact/visa/v1", nonce> but verify_holder_proof now expects
    # <"pact/hp/v1", req_id, cap_id, to_agent>.
    result = verify_holder_proof(msg, holder_pub, allow_legacy_v07=False)
    assert result is False, (
        "If True, the v0.8 design is structurally broken — visa replay "
        "as holder_proof MUST be rejected"
    )


def test_legacy_v0_7_visa_holder_proof_accepted_with_deprecation_warning(holder_keypair):
    """spec §18.7 — v0.7 bare-nonce visa signatures accepted during migration."""
    holder_priv, holder_pub = holder_keypair
    nonce = "sha256:abcdef"

    # v0.7 form: sign bare nonce bytes
    v07_sig = crypto.sign(nonce.encode(), holder_priv)
    v07_proof_b64 = base64.b64encode(v07_sig).decode("ascii")

    with pytest.warns(DeprecationWarning, match="v0.7 bare-payload visa"):
        result = verify_visa_holder_proof(v07_proof_b64, nonce, holder_pub, allow_legacy_v07=True)
    assert result is True

    # Post-window: reject
    result = verify_visa_holder_proof(v07_proof_b64, nonce, holder_pub, allow_legacy_v07=False)
    assert result is False
