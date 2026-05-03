"""Tests for HTTP server."""

import json
import socket
import time
import urllib.error
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


def test_oversize_request_rejected():
    """Issue #9: Content-Length above max_body_bytes returns HTTP 413."""
    server = PACTServer(port=0, dispatch=lambda b: {"ok": True}, max_body_bytes=1024)
    port = server.start()
    try:
        url = f"http://127.0.0.1:{port}/pact/v1/message"
        body = b"x" * 2048  # twice the limit
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as resp:
                # If urllib didn't raise, the status should be the 413 we returned
                assert resp.status == 413
        except urllib.error.HTTPError as e:
            assert e.code == 413
            body_resp = json.loads(e.read())
            assert "request too large" in body_resp.get("error", "").lower()
            assert body_resp.get("max_bytes") == 1024
    finally:
        server.stop()


def test_slow_loris_read_timeout():
    """Issue #9: a client that declares a Content-Length but never sends
    the bytes is dropped after read_timeout instead of holding the thread."""
    server = PACTServer(
        port=0,
        dispatch=lambda b: {"ok": True},
        max_body_bytes=10 * 1024 * 1024,
        read_timeout=1.0,  # short for the test
    )
    port = server.start()
    try:
        # Open a raw socket and send only headers — never the body
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(("127.0.0.1", port))
        headers = (
            "POST /pact/v1/message HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 100000\r\n"  # promise 100KB
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        s.sendall(headers)
        # Send a tiny prefix, never the rest
        s.sendall(b"{")

        # Server should give up after read_timeout (1s) and close
        t0 = time.perf_counter()
        data = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break
        elapsed = time.perf_counter() - t0
        s.close()

        # Should have dropped well before our 5s client-side timeout
        assert elapsed < 4.0, (
            f"server held connection for {elapsed:.1f}s — read_timeout didn't fire"
        )
    finally:
        server.stop()
