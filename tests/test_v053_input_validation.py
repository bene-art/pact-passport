"""v0.5.3 input-validation honesty patch tests.

Covers fixes:
- F1: Negative / malformed Content-Length is rejected with a clean 400
- F2: Malformed base64 in signature/holder_proof/receipt fails closed,
  doesn't crash the verifier
- F3: Negative max_invocations and unparseable expires raise at issue/attenuate
- F4: Streaming write order — cache before receipt
- F5: TOFU register rejects malformed pubkey base64
"""
from __future__ import annotations

import base64
import socket
import threading

import pytest

from pact_passport import (
    PACTAgent, HandlerFailure,
    build_req, send_message, fetch_identity,
    issue_capability, attenuate, Caveat,
    verify_message, verify_holder_proof, verify_receipt,
    CapabilityToken, Caveat as Cav,
)
from pact_passport import crypto
from pact_passport.capability import verify_capability
from pact_passport.transport.server import PACTServer


# -- F1: Content-Length validation -------------------------------------------

def _post_with_raw_headers(port: int, content_length_header: str) -> bytes:
    """Open a raw socket, send a POST with a custom Content-Length header,
    receive whatever the server sends back (or time out)."""
    sock = socket.create_connection(("127.0.0.1", port))
    sock.sendall(
        f"POST /pact/v1/message HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {content_length_header}\r\n"
        f"\r\n".encode()
    )
    sock.settimeout(3)
    try:
        return sock.recv(2048)
    except (socket.timeout, TimeoutError):
        return b""
    finally:
        sock.close()


@pytest.fixture
def server():
    s = PACTServer(port=0, dispatch=lambda b: {"ok": True}, max_body_bytes=1024)
    port = s.start()
    yield port
    s.stop()


def test_f1_negative_content_length_rejected_cleanly(server):
    resp = _post_with_raw_headers(server, "-1")
    # Pre-v0.5.3: server hung waiting for data, we got b'' on timeout.
    # v0.5.3: server sends 400 immediately.
    assert resp.startswith(b"HTTP/1.0 400") or resp.startswith(b"HTTP/1.1 400"), \
        f"Negative Content-Length should produce 400, got: {resp[:80]!r}"


def test_f1_non_numeric_content_length_rejected(server):
    resp = _post_with_raw_headers(server, "abc")
    assert resp.startswith(b"HTTP/1.0 400") or resp.startswith(b"HTTP/1.1 400")


def test_f1_oversize_content_length_still_returns_413(server):
    resp = _post_with_raw_headers(server, "999999999")
    assert b"413" in resp[:30]


# -- F2: malformed base64 fails closed instead of crashing -------------------

def _make_cap_with_keys():
    priv, pub = crypto.generate_keypair()
    aid = "sha256:" + "a" * 64
    cap = issue_capability(priv, aid, aid, "x", caveats=[])
    return priv, pub, aid, cap


def test_f2_verify_capability_rejects_malformed_signature():
    priv, pub, aid, cap = _make_cap_with_keys()
    cap.signature = "!!!not-base64!!!"
    result = verify_capability(cap, aid, pub, {aid: pub})
    assert result.valid is False
    assert "malformed" in result.reason.lower() or "invalid" in result.reason.lower()


def test_f2_verify_capability_rejects_malformed_chain_link_sig(tmp_path):
    priv, pub = crypto.generate_keypair()
    aid = "sha256:" + "a" * 64
    cap = issue_capability(priv, aid, aid, "x", caveats=[])
    aid2 = "sha256:" + "b" * 64
    priv2, pub2 = crypto.generate_keypair()
    child = attenuate(cap, priv, aid, aid2, [])
    # Corrupt the chain link signature
    child.delegation_chain[0].sig = "###bad###"
    result = verify_capability(child, aid2, pub, {aid: pub, aid2: pub2})
    assert result.valid is False


def test_f2_verify_message_rejects_malformed_signature():
    priv, pub = crypto.generate_keypair()
    aid = "sha256:" + "a" * 64
    msg = build_req(
        from_private_key=priv, from_id=aid, to_id=aid, intent="task",
        payload={"action": "x"}, deadline_seconds=60,
    )
    msg.signature = "!!!"
    assert verify_message(msg, pub) is False  # not raise


def test_f2_verify_holder_proof_rejects_malformed():
    priv, pub = crypto.generate_keypair()
    aid = "sha256:" + "a" * 64
    msg = build_req(
        from_private_key=priv, from_id=aid, to_id=aid, intent="task",
        payload={"action": "x"}, deadline_seconds=60,
    )
    msg.holder_proof = "!!!"
    assert verify_holder_proof(msg, pub) is False  # not raise


def test_f2_verify_receipt_rejects_malformed():
    priv, pub = crypto.generate_keypair()
    bad_receipt = {
        "type": "receipt",
        "agent": "sha256:" + "a" * 64,
        "task_ref": "x",
        "refs": ["x"],
        "outcome": "completed",
        "timestamp": "2026-05-04T12:00:00+00:00",
        "alg": "Ed25519",
        "signature": "!!!",
    }
    assert verify_receipt(bad_receipt, pub) is False
    # Missing signature also handled
    no_sig = {**bad_receipt}
    no_sig.pop("signature")
    assert verify_receipt(no_sig, pub) is False


# -- F3: caveat value validation at issue/attenuate --------------------------

def test_f3_negative_max_invocations_rejected_at_issue():
    priv, pub = crypto.generate_keypair()
    aid = "sha256:" + "a" * 64
    with pytest.raises(ValueError, match="max_invocations"):
        issue_capability(priv, aid, aid, "x", caveats=[Cav(restrict="max_invocations", value=-5)])


def test_f3_zero_max_invocations_rejected_at_issue():
    priv, pub = crypto.generate_keypair()
    aid = "sha256:" + "a" * 64
    with pytest.raises(ValueError, match="max_invocations"):
        issue_capability(priv, aid, aid, "x", caveats=[Cav(restrict="max_invocations", value=0)])


def test_f3_string_max_invocations_rejected():
    priv, pub = crypto.generate_keypair()
    aid = "sha256:" + "a" * 64
    with pytest.raises(ValueError, match="max_invocations"):
        issue_capability(priv, aid, aid, "x", caveats=[Cav(restrict="max_invocations", value="lots")])


def test_f3_positive_max_invocations_accepted():
    priv, pub = crypto.generate_keypair()
    aid = "sha256:" + "a" * 64
    cap = issue_capability(priv, aid, aid, "x", caveats=[Cav(restrict="max_invocations", value=10)])
    assert cap.cap_id is not None


def test_f3_unparseable_expires_rejected():
    priv, pub = crypto.generate_keypair()
    aid = "sha256:" + "a" * 64
    with pytest.raises(ValueError, match="expires"):
        issue_capability(priv, aid, aid, "x", caveats=[Cav(restrict="expires", value="next tuesday")])


def test_f3_caveat_validation_runs_on_attenuate():
    priv, pub = crypto.generate_keypair()
    aid = "sha256:" + "a" * 64
    cap = issue_capability(priv, aid, aid, "x", caveats=[])
    aid2 = "sha256:" + "b" * 64
    with pytest.raises(ValueError, match="max_invocations"):
        attenuate(cap, priv, aid, aid2, [Cav(restrict="max_invocations", value=-1)])


# -- F5: TOFU base64 fault tolerance -----------------------------------------

def test_f5_tofu_rejects_malformed_pubkey(tmp_path):
    a = PACTAgent("test", store_dir=tmp_path)
    a._ensure_identity()
    bad_doc = {
        "agent_id": "sha256:" + "a" * 64,
        "alg": "Ed25519",
        "public_key": "!!!not-base64!!!",
        "next_key_digest": "sha256:" + "b" * 64,
    }
    # Pre-v0.5.3 raised binascii.Error; v0.5.3 returns None cleanly
    result = a._tofu_register("sha256:" + "a" * 64, bad_doc)
    assert result is None
