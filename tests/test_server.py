"""Tests for HTTP server."""

import json
import socket
import time
import urllib.error
import urllib.request

from pact_passport.transport.server import PACTServer


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
    """Issue #9: Content-Length above max_body_bytes returns HTTP 413.

    Three valid outcomes — the test accepts any of them as "server
    rejected the oversize body":
      1. urllib reads a clean HTTPError with code 413 (typical)
      2. The server closes the TCP connection before the 413 lands,
         surfacing as ConnectionResetError (observed on macOS CI; the
         server sent the response, but client didn't read it before
         the close — race in BaseHTTPServer's connection handling)
      3. URLError wrapping a ConnectionResetError (same as #2 but
         caught at a different layer)
    All three indicate the server rejected the body. Earlier versions
    of this test caught only #1 and produced spurious failures on
    macOS roughly 1-in-3 PR runs.
    """
    server = PACTServer(port=0, dispatch=lambda b: {"ok": True}, max_body_bytes=1024)
    port = server.start()
    try:
        url = f"http://127.0.0.1:{port}/pact/v1/message"
        body = b"x" * 2048  # twice the limit
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as resp:
                assert resp.status == 413
        except urllib.error.HTTPError as e:
            assert e.code == 413
            body_resp = json.loads(e.read())
            assert "request too large" in body_resp.get("error", "").lower()
            assert body_resp.get("max_bytes") == 1024
        except (ConnectionResetError, urllib.error.URLError) as e:
            # Server sent 413 but closed the connection before the
            # client could read the body. Still a rejection, just one
            # the kernel got to before urllib did.
            cause = getattr(e, "reason", e)
            assert isinstance(cause, ConnectionResetError) or isinstance(e, ConnectionResetError), \
                f"Expected ConnectionResetError-shaped failure, got: {e!r}"
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


def test_send_stream_catches_all_connection_error_subclasses():
    """Bug 10 regression: pre-v0.6.1, _send_stream caught
    (BrokenPipeError, ConnectionResetError) only. Windows raises
    ConnectionAbortedError (WinError 10053) on consumer disconnect,
    which escaped the catch and bypassed chunks_iter.close() cleanup —
    leaving zero cancelled receipts written. Fix: catch ConnectionError
    (parent class).

    This test verifies (1) the Python exception hierarchy our fix
    depends on and (2) the source code uses ConnectionError, not the
    narrower POSIX-only tuple. Combined with C3 integration runs
    across the CI matrix (macOS / Linux / Windows), this locks in
    the fix and catches future regressions if anyone narrows the
    catch back.
    """
    import inspect
    import pact_passport.transport.server as server_module

    # The hierarchy our fix relies on:
    assert issubclass(BrokenPipeError, ConnectionError)
    assert issubclass(ConnectionResetError, ConnectionError)
    assert issubclass(ConnectionAbortedError, ConnectionError)

    # Source confirms the widened catch is in place:
    source = inspect.getsource(server_module)
    assert "except ConnectionError:" in source, (
        "Bug 10 regression: _send_stream must catch ConnectionError, "
        "not the narrower (BrokenPipeError, ConnectionResetError) tuple"
    )

