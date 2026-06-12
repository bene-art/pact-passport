"""Tests for message module."""

from pact_passport import crypto
from pact_passport.message import (
    PACTMessage, build_req, build_res, verify_message,
    verify_holder_proof, is_deadline_exceeded,
)


def test_build_req():
    priv, pub = crypto.generate_keypair()
    msg = build_req(priv, "sha256:from", "sha256:to", "task", {"key": "val"})
    assert msg.type == "REQ"
    assert msg.intent == "task"
    assert msg.deadline is not None
    assert msg.idempotency_key is not None
    assert msg.signature


def test_build_res():
    priv_a, _ = crypto.generate_keypair()
    priv_b, _ = crypto.generate_keypair()
    req = build_req(priv_a, "sha256:a", "sha256:b", "task")
    res = build_res(priv_b, "sha256:b", req, {"result": "ok"})
    assert res.type == "RES"
    assert res.refs == [req.id]
    assert res.to_agent == "sha256:a"


def test_verify_message():
    priv, pub = crypto.generate_keypair()
    msg = build_req(priv, "sha256:from", "sha256:to", "task")
    assert verify_message(msg, pub)


def test_verify_message_wrong_key():
    priv, _ = crypto.generate_keypair()
    _, pub2 = crypto.generate_keypair()
    msg = build_req(priv, "sha256:from", "sha256:to", "task")
    assert not verify_message(msg, pub2)


def test_holder_proof():
    priv, pub = crypto.generate_keypair()
    msg = build_req(priv, "sha256:from", "sha256:to", "task", holder_proof_key=priv)
    assert msg.holder_proof is not None
    assert verify_holder_proof(msg, pub)


def test_holder_proof_wrong_key():
    priv1, _ = crypto.generate_keypair()
    _, pub2 = crypto.generate_keypair()
    msg = build_req(priv1, "sha256:from", "sha256:to", "task", holder_proof_key=priv1)
    assert not verify_holder_proof(msg, pub2)


def test_deadline_not_exceeded():
    priv, _ = crypto.generate_keypair()
    msg = build_req(priv, "sha256:from", "sha256:to", "task", deadline_seconds=60)
    assert not is_deadline_exceeded(msg)


def test_message_round_trip():
    priv, _ = crypto.generate_keypair()
    msg = build_req(priv, "sha256:from", "sha256:to", "task", {"data": 42})
    d = msg.to_dict()
    restored = PACTMessage.from_dict(d)
    assert restored.id == msg.id
    assert restored.payload == {"data": 42}
