"""Tests for capability module."""

from datetime import datetime, timezone, timedelta

from pact import crypto
from pact.capability import (
    Caveat, CapabilityToken, issue_capability, verify_capability, CapabilityResult,
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
