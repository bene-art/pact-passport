"""Tests for v1.4 / v0.8 audit module — bilateral receipts (spec §18.6)."""
from __future__ import annotations

import base64

import pytest

from pact_passport import crypto
from pact_passport._canonical import canonical_json
from pact_passport.audit import (
    audit_receipt,
    make_bilateral_receipt,
    sign_initiator_ack,
)
from pact_passport.errors import (
    PACT_RECEIPT_NOT_BILATERAL,
    PACT_SIGNATURE_INVALID,
    PACT_TOKEN_MISSING,
)


@pytest.fixture
def receiver_keys():
    return crypto.generate_keypair()


@pytest.fixture
def initiator_keys():
    return crypto.generate_keypair()


def _make_signed_receipt(receiver_priv):
    """Helper: make a one-side-signed (receiver-only) receipt."""
    body = {
        "receipt_id": "rcpt-1",
        "req_id": "req-1",
        "from_agent": "sha256:r",
        "to_agent": "sha256:s",
        "status": "ok",
    }
    sig = crypto.sign(canonical_json(body), receiver_priv)
    body["signature"] = base64.b64encode(sig).decode("ascii")
    return body


def test_non_bilateral_receipt_flagged(receiver_keys):
    """A receipt with only the receiver's signature is non-bilateral."""
    receiver_priv, receiver_pub = receiver_keys
    receipt = _make_signed_receipt(receiver_priv)

    result = audit_receipt(receipt, receiver_pub)
    assert not result.passed
    codes = [c for c, _ in result.errors]
    assert PACT_RECEIPT_NOT_BILATERAL in codes


def test_bilateral_receipt_passes_audit(receiver_keys, initiator_keys):
    """A receipt with both signatures verifies cleanly."""
    receiver_priv, receiver_pub = receiver_keys
    initiator_priv, initiator_pub = initiator_keys

    receipt = _make_signed_receipt(receiver_priv)
    bilateral = make_bilateral_receipt(receipt, initiator_priv)

    result = audit_receipt(bilateral, receiver_pub, initiator_pub)
    assert result.passed, f"errors: {result.errors}"
    assert result.metadata.get("bilateral_signature_status") == "verified"


def test_make_bilateral_receipt_doesnt_mutate_input(receiver_keys, initiator_keys):
    """make_bilateral_receipt returns a new dict, doesn't mutate caller's."""
    receiver_priv, _ = receiver_keys
    initiator_priv, _ = initiator_keys

    receipt = _make_signed_receipt(receiver_priv)
    original_keys = set(receipt)

    bilateral = make_bilateral_receipt(receipt, initiator_priv)

    assert "initiator_ack_signature" not in receipt  # original unchanged
    assert "initiator_ack_signature" in bilateral
    assert set(receipt) == original_keys


def test_initiator_ack_signature_does_not_cover_itself(receiver_keys, initiator_keys):
    """The initiator-ack sig is over receipt MINUS the ack sig field itself."""
    receiver_priv, _ = receiver_keys
    initiator_priv, _ = initiator_keys

    receipt = _make_signed_receipt(receiver_priv)

    # Direct call to sign_initiator_ack
    ack_sig_1 = sign_initiator_ack(receipt, initiator_priv)

    # If we add ack to the receipt and call again, the ack signature
    # should be IDENTICAL because the signed bytes exclude it.
    receipt["initiator_ack_signature"] = "anything-here"
    ack_sig_2 = sign_initiator_ack(receipt, initiator_priv)

    assert ack_sig_1 == ack_sig_2


def test_tampered_bilateral_receipt_fails(receiver_keys, initiator_keys):
    """Tampering any field after bilateral signing breaks verification."""
    receiver_priv, receiver_pub = receiver_keys
    initiator_priv, initiator_pub = initiator_keys

    receipt = _make_signed_receipt(receiver_priv)
    bilateral = make_bilateral_receipt(receipt, initiator_priv)

    # Tamper the status field after both signatures applied
    bilateral["status"] = "TAMPERED"

    result = audit_receipt(bilateral, receiver_pub, initiator_pub)
    assert not result.passed
    codes = [c for c, _ in result.errors]
    # Either signature verifies first; whichever it is, signature_invalid fires
    assert PACT_SIGNATURE_INVALID in codes


def test_missing_receiver_signature_flagged():
    """No 'signature' field at all → pact_token_missing."""
    bare_receipt = {"receipt_id": "x", "status": "ok"}
    fake_pub = bytes(32)

    result = audit_receipt(bare_receipt, fake_pub)
    codes = [c for c, _ in result.errors]
    assert PACT_TOKEN_MISSING in codes


def test_audit_metadata_includes_receipt_id(receiver_keys):
    """AuditResult metadata SHOULD carry receipt_id for traceability."""
    receiver_priv, receiver_pub = receiver_keys
    receipt = _make_signed_receipt(receiver_priv)

    result = audit_receipt(receipt, receiver_pub)
    assert result.metadata.get("receipt_id") == "rcpt-1"
