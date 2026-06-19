"""HTTP server for PACT agents.

Single POST endpoint: /pact/v1/message
Convenience GETs: /pact/v1/health, /pact/v1/identity
HTTP 200 for all protocol responses (errors in body).
Supports content negotiation: application/json (default) and application/cbor.
"""

from __future__ import annotations

import json
import logging
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from collections.abc import Callable

from pact_passport._canonical import (
    encode_message, decode_message,
    JSON_CONTENT_TYPE, CBOR_CONTENT_TYPE,
)
from pact_passport.errors import http_status_for_fault, ALL_FAULT_CODES

logger = logging.getLogger(__name__)


DEFAULT_MAX_BODY_BYTES = 1024 * 1024  # 1 MB
DEFAULT_READ_TIMEOUT = 30.0  # seconds


def _status_for_response(response: dict) -> int:
    """Derive HTTP status from a PACT response dict (spec §18.3).

    Returns 200 for status='ok' responses. For status='error' responses,
    looks up fault.code in the v1.4 ``pact_*`` taxonomy and returns the
    mapped HTTP status (401/403/410). Legacy fault codes (non-``pact_*``)
    keep the v0.7 behavior of HTTP 200 with the fault in the body — until
    v0.8.2 completes the taxonomy roll-out.
    """
    if not isinstance(response, dict):
        return 200
    if response.get("status") != "error":
        return 200
    fault = response.get("fault")
    if not isinstance(fault, dict):
        return 200
    code = fault.get("code")
    if isinstance(code, str) and code in ALL_FAULT_CODES:
        return http_status_for_fault(code)
    return 200


class PACTHandler(BaseHTTPRequestHandler):
    """HTTP request handler for PACT protocol messages."""

    # Set by the server instance
    dispatch: Callable[[dict], dict] | None = None
    identity_doc: dict | None = None
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    read_timeout: float = DEFAULT_READ_TIMEOUT

    def setup(self):
        super().setup()
        # Bound socket-level read timeout. Slow-loris attacks (issue #9)
        # rely on the server willing to wait indefinitely for body bytes.
        self.request.settimeout(self.read_timeout)

    def log_message(self, format, *args):
        logger.debug(format, *args)

    def _preferred_content_type(self) -> str:
        """Determine response content type from Accept header."""
        accept = self.headers.get("Accept", JSON_CONTENT_TYPE)
        if CBOR_CONTENT_TYPE in accept:
            return CBOR_CONTENT_TYPE
        return JSON_CONTENT_TYPE

    def _send_response(self, data: dict, status: int = 200) -> None:
        """Send a response with content negotiation."""
        ct = self._preferred_content_type()
        try:
            body, actual_ct = encode_message(data, ct)
        except ImportError:
            # CBOR not installed, fall back to JSON
            body, actual_ct = encode_message(data, JSON_CONTENT_TYPE)

        self.send_response(status)
        self.send_header("Content-Type", actual_ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/pact/v1/health":
            agent_id = (self.identity_doc or {}).get("agent_id", "unknown")
            self._send_response({"status": "ok", "agent_id": agent_id})
        elif self.path == "/pact/v1/identity":
            if self.identity_doc:
                self._send_response(self.identity_doc)
            else:
                self._send_response({"error": "no identity"}, 500)
        else:
            self._send_response({"error": "not found"}, 404)

    def do_POST(self) -> None:
        if self.path != "/pact/v1/message":
            self._send_response({"error": "not found"}, 404)
            return

        # Parse Content-Length defensively. A non-integer or missing value
        # falls through to 0 → empty-body 400. Negative values would
        # otherwise call rfile.read(-1), which blocks indefinitely waiting
        # for EOF — a slow-loris-shaped DoS via a single byte of header.
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            self._send_response({"error": "invalid Content-Length"}, 400)
            return
        if content_length <= 0:
            self._send_response({"error": "empty body"}, 400)
            return

        # Cap request size — issue #9. Without this, a client can declare
        # any size and the server will attempt to read it, leading to OOM
        # or slow-loris resource exhaustion.
        if content_length > self.max_body_bytes:
            self.send_response(413)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                f'{{"error": "request too large", "max_bytes": {self.max_body_bytes}}}'.encode()
            )
            return

        # Decode based on incoming Content-Type
        incoming_ct = self.headers.get("Content-Type", JSON_CONTENT_TYPE)
        try:
            raw = self.rfile.read(content_length)
        except TimeoutError:
            # Slow-loris: client declared content_length but never sent
            # the bytes. read_timeout fires; we give up cleanly instead
            # of holding the thread open.
            self._send_response({"error": "read timeout"}, 408)
            return

        try:
            body = decode_message(raw, incoming_ct)
        except Exception:
            self._send_response({"error": "invalid body"}, 400)
            return

        if self.dispatch:
            try:
                # Pass the transport-boundary remote address through so
                # the V-tier visa policy can derive peer_network_id
                # (v0.6). Dispatchers that don't take the kwarg fall
                # back to the legacy single-arg form for compatibility.
                try:
                    result = self.dispatch(body, remote_addr=self.client_address)
                except TypeError:
                    result = self.dispatch(body)
                # Streaming path: dispatcher returned an iterator (issue #11).
                # We write each chunk as one NDJSON line over chunked
                # transfer encoding. Connection drop mid-stream raises a
                # ConnectionError subclass (BrokenPipeError on POSIX,
                # ConnectionAbortedError on Windows), which we treat as
                # cancellation in _send_stream.
                if hasattr(result, "__next__") and not isinstance(result, dict):
                    self._send_stream(result)
                else:
                    self._send_response(result, status=_status_for_response(result))
            except Exception as e:
                logger.exception("Dispatch error")
                self._send_response({"error": str(e)}, 500)
        else:
            self._send_response({"error": "no dispatch handler"}, 500)

    def _send_stream(self, chunks_iter) -> None:
        """Write a stream of chunk dicts as NDJSON over HTTP chunked
        transfer encoding. Each line is one fully-signed RES_CHUNK.
        ConnectionError = consumer disconnected = cancellation. Covers
        BrokenPipeError + ConnectionResetError on POSIX and
        ConnectionAbortedError (WinError 10053) on Windows; using the
        parent class catches all platform variants without enumerating
        them. Closes Bug 10 (Windows-only gap in the Bug 7 fix)."""
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        try:
            for chunk_dict in chunks_iter:
                line = (json.dumps(chunk_dict) + "\n").encode("utf-8")
                # HTTP chunked transfer encoding: <hex-size>\r\n<bytes>\r\n
                self.wfile.write(f"{len(line):X}\r\n".encode())
                self.wfile.write(line)
                self.wfile.write(b"\r\n")
                self.wfile.flush()
            # Terminating zero-length chunk
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except ConnectionError:
            # Consumer disconnected mid-stream. Explicitly close the
            # iterator so the streaming generator inside dispatch
            # receives GeneratorExit synchronously — its finally block
            # writes the cancelled receipt before this handler
            # returns. Without the explicit close, cleanup depends on
            # GC timing and a test that reads the receipt log
            # immediately after disconnect can race the collector.
            # Closes Bug 7 (GH #30) — see bug7_fix_design.md.
            logger.info("client disconnected mid-stream")
            try:
                chunks_iter.close()
            except Exception:
                # close() can raise if the generator's finally block
                # itself raises. Log and continue — we're already in
                # the error path; don't mask the original disconnect.
                logger.exception("chunks_iter.close() raised during cleanup")


class PACTServer:
    """Threaded HTTP server for PACT agents."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 0,
        dispatch: Callable[[dict], dict] | None = None,
        identity_doc: dict | None = None,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        read_timeout: float = DEFAULT_READ_TIMEOUT,
    ):
        self.host = host
        self.port = port
        self._dispatch = dispatch
        self._identity_doc = identity_doc
        self._max_body_bytes = max_body_bytes
        self._read_timeout = read_timeout
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> int:
        """Start the server in a background thread. Returns the actual port."""
        handler_class = type(
            "BoundHandler",
            (PACTHandler,),
            {
                "dispatch": staticmethod(self._dispatch) if self._dispatch else None,
                "identity_doc": self._identity_doc,
                "max_body_bytes": self._max_body_bytes,
                "read_timeout": self._read_timeout,
            },
        )

        self._server = ThreadingHTTPServer((self.host, self.port), handler_class)
        actual_port = self._server.server_address[1]
        self.port = actual_port

        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

        return actual_port

    def stop(self) -> None:
        """Stop the server."""
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def set_dispatch(self, dispatch: Callable[[dict], dict]) -> None:
        self._dispatch = dispatch
        if self._server and self._server.RequestHandlerClass:
            self._server.RequestHandlerClass.dispatch = staticmethod(dispatch)

    def set_identity_doc(self, doc: dict) -> None:
        self._identity_doc = doc
        if self._server and self._server.RequestHandlerClass:
            self._server.RequestHandlerClass.identity_doc = doc
