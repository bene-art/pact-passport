"""Tests for HTTP server."""

import json
import urllib.request

from pact.transport.server import PACTServer


def test_health_endpoint():
    def dispatch(body):
        return {"echo": body}

    server = PACTServer(
        port=0,
        dispatch=dispatch,
        identity_doc={"agent_id": "sha256:test"},
    )
    port = server.start()
    try:
        url = f"http://127.0.0.1:{port}/pact/v1/health"
        with urllib.request.urlopen(url) as resp:
            data = json.loads(resp.read())
        assert data["status"] == "ok"
        assert data["agent_id"] == "sha256:test"
    finally:
        server.stop()


def test_identity_endpoint():
    doc = {"agent_id": "sha256:abc", "alg": "Ed25519", "public_key": "test"}
    server = PACTServer(port=0, identity_doc=doc)
    port = server.start()
    try:
        url = f"http://127.0.0.1:{port}/pact/v1/identity"
        with urllib.request.urlopen(url) as resp:
            data = json.loads(resp.read())
        assert data == doc
    finally:
        server.stop()


def test_message_dispatch():
    def dispatch(body):
        return {"received": body.get("intent", "none")}

    server = PACTServer(port=0, dispatch=dispatch)
    port = server.start()
    try:
        url = f"http://127.0.0.1:{port}/pact/v1/message"
        payload = json.dumps({"intent": "test"}).encode()
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
        assert data["received"] == "test"
    finally:
        server.stop()
