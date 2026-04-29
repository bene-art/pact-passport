"""Tests for async uvicorn server (Phase 5)."""

import json
import urllib.request

from pact.transport.async_server import AsyncPACTServer


def test_async_health():
    """Async server health endpoint."""
    server = AsyncPACTServer(
        port=0,
        dispatch=lambda body: {"echo": body},
        identity_doc={"agent_id": "sha256:async_test"},
    )
    port = server.start()
    try:
        url = f"http://127.0.0.1:{port}/pact/v1/health"
        with urllib.request.urlopen(url) as resp:
            data = json.loads(resp.read())
        assert data["status"] == "ok"
        assert data["agent_id"] == "sha256:async_test"
    finally:
        server.stop()


def test_async_identity():
    """Async server identity endpoint."""
    doc = {"agent_id": "sha256:abc", "alg": "Ed25519", "public_key": "test"}
    server = AsyncPACTServer(port=0, identity_doc=doc)
    port = server.start()
    try:
        url = f"http://127.0.0.1:{port}/pact/v1/identity"
        with urllib.request.urlopen(url) as resp:
            data = json.loads(resp.read())
        assert data == doc
    finally:
        server.stop()


def test_async_message_dispatch():
    """Async server processes PACT messages."""
    server = AsyncPACTServer(
        port=0,
        dispatch=lambda body: {"received": body.get("intent", "none")},
    )
    port = server.start()
    try:
        url = f"http://127.0.0.1:{port}/pact/v1/message"
        data = json.dumps({"intent": "task"}).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
        assert result["received"] == "task"
    finally:
        server.stop()


def test_async_cbor_negotiation():
    """Async server supports CBOR content negotiation."""
    from pact._canonical import canonical_cbor, decode_cbor, CBOR_CONTENT_TYPE

    server = AsyncPACTServer(
        port=0,
        dispatch=lambda body: {"echo": body.get("key")},
    )
    port = server.start()
    try:
        url = f"http://127.0.0.1:{port}/pact/v1/message"
        cbor_body = canonical_cbor({"key": "async_cbor"})
        req = urllib.request.Request(
            url, data=cbor_body,
            headers={
                "Content-Type": CBOR_CONTENT_TYPE,
                "Accept": CBOR_CONTENT_TYPE,
            },
        )
        with urllib.request.urlopen(req) as resp:
            assert resp.headers["Content-Type"] == CBOR_CONTENT_TYPE
            result = decode_cbor(resp.read())
            assert result["echo"] == "async_cbor"
    finally:
        server.stop()
