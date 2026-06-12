"""Tests for receipt module."""

from pact_passport import crypto
from pact_passport.receipt import create_receipt, verify_receipt


def test_create_receipt():
    priv, pub = crypto.generate_keypair()
    r = create_receipt(priv, "sha256:agent", "m-001", ["m-001", "m-002"], "completed")
    assert r["type"] == "receipt"
    assert r["agent"] == "sha256:agent"
    assert r["outcome"] == "completed"
    assert r["signature"]


def test_verify_receipt():
    priv, pub = crypto.generate_keypair()
    r = create_receipt(priv, "sha256:agent", "m-001", ["m-001"], "completed")
    assert verify_receipt(r, pub)


def test_verify_receipt_wrong_key():
    priv1, _ = crypto.generate_keypair()
    _, pub2 = crypto.generate_keypair()
    r = create_receipt(priv1, "sha256:agent", "m-001", ["m-001"], "completed")
    assert not verify_receipt(r, pub2)


def test_receipt_tamper():
    priv, pub = crypto.generate_keypair()
    r = create_receipt(priv, "sha256:agent", "m-001", ["m-001"], "completed")
    r["outcome"] = "failed"  # tamper
    assert not verify_receipt(r, pub)
