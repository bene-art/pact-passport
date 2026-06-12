"""Tests for crypto module."""

from pact_passport import crypto


def test_generate_keypair():
    priv, pub = crypto.generate_keypair()
    assert len(priv) == 32
    assert len(pub) == 32


def test_sign_and_verify():
    priv, pub = crypto.generate_keypair()
    msg = b"hello pact"
    sig = crypto.sign(msg, priv)
    assert len(sig) == 64
    assert crypto.verify(msg, sig, pub)


def test_verify_wrong_key():
    priv1, pub1 = crypto.generate_keypair()
    _, pub2 = crypto.generate_keypair()
    msg = b"hello"
    sig = crypto.sign(msg, priv1)
    assert not crypto.verify(msg, sig, pub2)


def test_verify_tampered_message():
    priv, pub = crypto.generate_keypair()
    sig = crypto.sign(b"original", priv)
    assert not crypto.verify(b"tampered", sig, pub)


def test_sha256_digest():
    d = crypto.sha256_digest(b"test")
    assert d.startswith("sha256:")
    assert len(d) == 71  # "sha256:" + 64 hex chars


def test_alg_constant():
    assert crypto.ALG == "Ed25519"
