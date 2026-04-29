"""Async ASGI server for PACT agents via uvicorn.

Optional upgrade from ThreadingHTTPServer. Same endpoints, async dispatch.
Requires: pip install pact-protocol[fast]
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Callable

from pact._canonical import (
    encode_message, decode_message,
    JSON_CONTENT_TYPE, CBOR_CONTENT_TYPE,
)

logger = logging.getLogger(__name__)


def _make_asgi_app(
    dispatch: Callable[[dict], dict] | None = None,
    identity_doc: dict | None = None,
) -> Callable:
    """Create a raw ASGI application for PACT.

    No framework dependency — just the ASGI spec.
    """

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return

        method = scope["method"]
        path = scope["path"]

        # Read request body
        body = b""
        while True:
            msg = await receive()
            body += msg.get("body", b"")
            if not msg.get("more_body", False):
                break

        # Determine content types
        headers = dict(scope.get("headers", []))
        incoming_ct = headers.get(b"content-type", JSON_CONTENT_TYPE.encode()).decode()
        accept = headers.get(b"accept", JSON_CONTENT_TYPE.encode()).decode()
        response_ct = CBOR_CONTENT_TYPE if CBOR_CONTENT_TYPE in accept else JSON_CONTENT_TYPE

        async def send_response(data: dict, status: int = 200):
            try:
                resp_body, actual_ct = encode_message(data, response_ct)
            except ImportError:
                resp_body, actual_ct = encode_message(data, JSON_CONTENT_TYPE)

            await send({
                "type": "http.response.start",
                "status": status,
                "headers": [
                    [b"content-type", actual_ct.encode()],
                    [b"content-length", str(len(resp_body)).encode()],
                ],
            })
            await send({
                "type": "http.response.body",
                "body": resp_body,
            })

        # Route
        if method == "GET" and path == "/pact/v1/health":
            agent_id = (identity_doc or {}).get("agent_id", "unknown")
            await send_response({"status": "ok", "agent_id": agent_id})

        elif method == "GET" and path == "/pact/v1/identity":
            if identity_doc:
                await send_response(identity_doc)
            else:
                await send_response({"error": "no identity"}, 500)

        elif method == "POST" and path == "/pact/v1/message":
            if not body:
                await send_response({"error": "empty body"}, 400)
                return

            try:
                parsed = decode_message(body, incoming_ct)
            except Exception:
                await send_response({"error": "invalid body"}, 400)
                return

            if dispatch:
                try:
                    result = dispatch(parsed)
                    await send_response(result)
                except Exception as e:
                    logger.exception("Dispatch error")
                    await send_response({"error": str(e)}, 500)
            else:
                await send_response({"error": "no dispatch handler"}, 500)

        else:
            await send_response({"error": "not found"}, 404)

    return app


class AsyncPACTServer:
    """Async PACT server using uvicorn.

    Drop-in replacement for PACTServer with better concurrency.
    Requires: pip install pact-protocol[fast]
    """

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
        self._server = None
        self._thread: threading.Thread | None = None

    def start(self) -> int:
        """Start the async server in a background thread. Returns the actual port."""
        try:
            import uvicorn
        except ImportError:
            raise ImportError(
                "Async server requires uvicorn. Install with: pip install pact-protocol[fast]"
            )

        app = _make_asgi_app(self._dispatch, self._identity_doc)

        # Use port 0 trick: bind to find a free port
        if self.port == 0:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("", 0))
            self.port = s.getsockname()[1]
            s.close()

        config = uvicorn.Config(
            app,
            host=self.host,
            port=self.port,
            log_level="warning",
        )
        self._server = uvicorn.Server(config)

        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()

        # Wait for server to be ready
        import time
        for _ in range(50):
            if self._server.started:
                break
            time.sleep(0.1)

        return self.port

    def stop(self) -> None:
        """Stop the async server."""
        if self._server:
            self._server.should_exit = True
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        self._server = None
