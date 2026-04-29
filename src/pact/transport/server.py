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
from typing import Callable

from pact._canonical import (
    encode_message, decode_message,
    JSON_CONTENT_TYPE, CBOR_CONTENT_TYPE,
)

logger = logging.getLogger(__name__)


class PACTHandler(BaseHTTPRequestHandler):
    """HTTP request handler for PACT protocol messages."""

    # Set by the server instance
    dispatch: Callable[[dict], dict] | None = None
    identity_doc: dict | None = None

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

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self._send_response({"error": "empty body"}, 400)
            return

        # Decode based on incoming Content-Type
        incoming_ct = self.headers.get("Content-Type", JSON_CONTENT_TYPE)
        raw = self.rfile.read(content_length)

        try:
            body = decode_message(raw, incoming_ct)
        except Exception:
            self._send_response({"error": "invalid body"}, 400)
            return

        if self.dispatch:
            try:
                result = self.dispatch(body)
                self._send_response(result)
            except Exception as e:
                logger.exception("Dispatch error")
                self._send_response({"error": str(e)}, 500)
        else:
            self._send_response({"error": "no dispatch handler"}, 500)


class PACTServer:
    """Threaded HTTP server for PACT agents."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 0,
        dispatch: Callable[[dict], dict] | None = None,
        identity_doc: dict | None = None,
    ):
        self.host = host
        self.port = port
        self._dispatch = dispatch
        self._identity_doc = identity_doc
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
