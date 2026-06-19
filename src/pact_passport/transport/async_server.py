"""Async ASGI server for PACT agents via uvicorn.

Optional upgrade from ThreadingHTTPServer. Same endpoints, async dispatch.
Requires: pip install pact-passport[fast]

v0.5.1 brought to parity with the sync server: max_body_bytes (#9),
streaming RES_CHUNK (#11). Read timeout is enforced by uvicorn's
http_protocol_class (set via timeout_keep_alive); explicit per-request
read timeout would require monkeypatching uvicorn internals — left for
a later release.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable, Iterator

from pact_passport.transport.server import _status_for_response
from pact_passport._canonical import (
    encode_message, decode_message,
    JSON_CONTENT_TYPE, CBOR_CONTENT_TYPE,
)
import contextlib

logger = logging.getLogger(__name__)

DEFAULT_MAX_BODY_BYTES = 1024 * 1024  # 1 MB
DEFAULT_READ_TIMEOUT = 30.0  # seconds (passed to uvicorn timeout_keep_alive)


def _make_asgi_app(
    dispatch: Callable[[dict], dict] | None = None,
    identity_doc: dict | None = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> Callable:
    """Create a raw ASGI application for PACT.

    No framework dependency — just the ASGI spec.
    """

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return

        method = scope["method"]
        path = scope["path"]

        # Read request body, enforcing max_body_bytes (#9). We accumulate
        # incrementally and reject as soon as the cap is exceeded so a
        # malicious Content-Length: 10GB doesn't actually allocate 10GB.
        body = b""
        while True:
            msg = await receive()
            body += msg.get("body", b"")
            if len(body) > max_body_bytes:
                await send({
                    "type": "http.response.start",
                    "status": 413,
                    "headers": [[b"content-type", b"application/json"]],
                })
                await send({
                    "type": "http.response.body",
                    "body": json.dumps({
                        "error": "request too large",
                        "max_bytes": max_body_bytes,
                    }).encode(),
                })
                return
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

        async def send_stream(chunks_iter: Iterator[dict]):
            """Stream RES_CHUNK dicts as NDJSON (#11). One http.response.body
            event per chunk with more_body=True until the final chunk."""
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    [b"content-type", b"application/x-ndjson"],
                ],
            })
            try:
                buffered = list(chunks_iter)
                for i, chunk in enumerate(buffered):
                    line = (json.dumps(chunk) + "\n").encode("utf-8")
                    is_last = i == len(buffered) - 1
                    await send({
                        "type": "http.response.body",
                        "body": line,
                        "more_body": not is_last,
                    })
            except Exception:
                logger.exception("stream dispatch error")
                # Best-effort terminate
                with contextlib.suppress(Exception):
                    await send({"type": "http.response.body", "body": b"", "more_body": False})

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
                    # Streaming path: dispatch returned a generator (#11).
                    # Same detection contract as the sync server.
                    if hasattr(result, "__next__") and not isinstance(result, dict):
                        await send_stream(result)
                    else:
                        await send_response(result, status=_status_for_response(result))
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
    Requires: pip install pact-passport[fast]

    v0.5.1: gains max_body_bytes (issue #9) and streaming response
    support (issue #11). Brings parity with the sync PACTServer.
    """

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
        self._server = None
        self._thread: threading.Thread | None = None

    def start(self) -> int:
        """Start the async server in a background thread. Returns the actual port."""
        try:
            import uvicorn
        except ImportError:
            raise ImportError(
                "Async server requires uvicorn. Install with: pip install pact-passport[fast]"
            ) from None

        app = _make_asgi_app(
            self._dispatch, self._identity_doc, self._max_body_bytes,
        )

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
            timeout_keep_alive=int(self._read_timeout),
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
