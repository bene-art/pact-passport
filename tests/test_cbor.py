"""Tests for CBOR encoding and content negotiation (Phase 5)."""

import json
import urllib.request

from pact._canonical import (
    canonical_cbor, decode_cbor, encode_message, decode_message,
    JSON_CONTENT_TYPE, CBOR_CONTENT_TYPE,
)
from pact.transport.server import PACTServer
from pact.transport.client import send_message
from pact.identity import Identity
from pact.message import build_req


def test_canonical_cbor_round_trip():
    """CBOR encode/decode preserves data."""
    obj = {"action": "test", "value": 42, "nested": {"a": 1}}
    encoded = canonical_cbor(obj)
    assert isinstance(encoded, bytes)
    decoded = decode_cbor(encoded)
    assert decoded == obj


def test_canonical_cbor_deterministic():
    """Same input produces same CBOR bytes."""
    obj = {"z": 1, "a": 2, "m": 3}
    b1 = canonical_cbor(obj)
    b2 = canonical_cbor(obj)
    assert b1 == b2


def test_encode_message_json():
    """encode_message with JSON content type."""
    obj = {"test": True}
    body, ct = encode_message(obj, JSON_CONTENT_TYPE)
    assert ct == JSON_CONTENT_TYPE
    assert json.loads(body) == obj


def test_encode_message_cbor():
    """encode_message with CBOR content type."""
    obj = {"test": True}
    body, ct = encode_message(obj, CBOR_CONTENT_TYPE)
    assert ct == CBOR_CONTENT_TYPE
    decoded = decode_message(body, CBOR_CONTENT_TYPE)
    assert decoded == obj


def test_server_cbor_response():
    """Server responds with CBOR when Accept: application/cbor."""
    server = PACTServer(
        port=0,
        dispatch=lambda body: {"echo": body},
        identity_doc={"agent_id": "sha256:test"},
    )
    port = server.start()
    try:
        # Send JSON, request CBOR response
        url = f"http://127.0.0.1:{port}/pact/v1/message"
        data = json.dumps({"intent": "test"}).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={
                "Content-Type": JSON_CONTENT_TYPE,
                "Accept": CBOR_CONTENT_TYPE,
            },
        )
        with urllib.request.urlopen(req) as resp:
            assert resp.headers["Content-Type"] == CBOR_CONTENT_TYPE
            result = decode_cbor(resp.read())
            assert result["echo"]["intent"] == "test"
    finally:
        server.stop()


def test_server_cbor_request():
    """Server accepts CBOR request body."""
    server = PACTServer(
        port=0,
        dispatch=lambda body: {"received": body.get("key", "none")},
    )
    port = server.start()
    try:
        url = f"http://127.0.0.1:{port}/pact/v1/message"
        cbor_body = canonical_cbor({"key": "cbor_value"})
        req = urllib.request.Request(
            url, data=cbor_body,
            headers={
                "Content-Type": CBOR_CONTENT_TYPE,
                "Accept": JSON_CONTENT_TYPE,
            },
        )
        with urllib.request.urlopen(req) as resp:
            assert resp.headers["Content-Type"] == JSON_CONTENT_TYPE
            result = json.loads(resp.read())
            assert result["received"] == "cbor_value"
    finally:
        server.stop()


def test_client_cbor_round_trip(store):
    """Client sends CBOR, server responds with CBOR."""
    alice = Identity.create("alice_cbor", store)
    bob = Identity.create("bob_cbor", store)

    def dispatch(body):
        from pact.message import PACTMessage, build_res
        msg = PACTMessage.from_dict(body)
        return build_res(
            bob._private_key, bob.agent_id, msg,
            payload={"encoding": "cbor"},
        ).to_dict()

    server = PACTServer(port=0, dispatch=dispatch)
    port = server.start()
    try:
        req = build_req(
            alice._private_key, alice.agent_id, bob.agent_id,
            "task", {"test": "cbor"},
        )
        result = send_message(
            f"http://127.0.0.1:{port}", req,
            content_type=CBOR_CONTENT_TYPE,
        )
        assert result.get("status") == "ok"
        assert result["payload"]["encoding"] == "cbor"
    finally:
        server.stop()
