"""HTTP client for sending PACT messages.

Supports content negotiation: application/json (default) and application/cbor.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from collections.abc import Iterator

from pact_passport.message import PACTMessage
from pact_passport._canonical import (
    encode_message, decode_message,
    JSON_CONTENT_TYPE,
)


def send_message(
    target_base_url: str,
    msg: PACTMessage,
    timeout: float = 30.0,
    content_type: str = JSON_CONTENT_TYPE,
) -> dict:
    """Send a PACT message to a target agent.

    Args:
        target_base_url: e.g. "http://192.168.1.100:9100"
        msg: The PACTMessage to send.
        timeout: HTTP timeout in seconds.
        content_type: Request encoding (application/json or application/cbor).

    Returns:
        The response body as a dict.
    """
    url = f"{target_base_url}/pact/v1/message"

    try:
        data, actual_ct = encode_message(msg.to_dict(), content_type)
    except ImportError:
        data, actual_ct = encode_message(msg.to_dict(), JSON_CONTENT_TYPE)

    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": actual_ct,
            "Accept": actual_ct,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_ct = resp.headers.get("Content-Type", JSON_CONTENT_TYPE)
            return decode_message(resp.read(), resp_ct)
    except urllib.error.HTTPError as e:
        body = e.read()
        resp_ct = e.headers.get("Content-Type", JSON_CONTENT_TYPE) if e.headers else JSON_CONTENT_TYPE
        try:
            return decode_message(body, resp_ct)
        except Exception:
            return {"status": "error", "fault": {"code": "http_error", "detail": body.decode("utf-8", errors="replace")}}
    except urllib.error.URLError as e:
        return {"status": "error", "fault": {"code": "unreachable", "detail": str(e.reason)}}
    except TimeoutError:
        return {"status": "error", "fault": {"code": "timeout", "detail": "Request timed out"}}


def send_message_streaming(
    target_base_url: str,
    msg: PACTMessage,
    timeout: float = 120.0,
) -> Iterator[dict]:
    """Send a streaming REQ and yield each RES_CHUNK dict as it arrives.

    The REQ should have stream=True. The server responds with
    Content-Type: application/x-ndjson over chunked transfer encoding;
    each line is one fully-signed RES_CHUNK. Issue #11.

    The generator yields chunk dicts in arrival order. The terminal
    chunk has chunk_final=True. If the server returns an error response
    (one-shot dict, not a stream), it's yielded once and the generator
    ends.
    """
    url = f"{target_base_url}/pact/v1/message"
    data = json.dumps(msg.to_dict()).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": JSON_CONTENT_TYPE,
            "Accept": "application/x-ndjson, application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        ct = resp.headers.get("Content-Type", "")
        if "ndjson" not in ct:
            # Server didn't stream — could be an error response or a
            # handler that returned dict (not generator). Yield once.
            yield decode_message(resp.read(), ct)
            return
        # NDJSON stream — one chunk per line.
        for line in resp:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def fetch_identity(target_base_url: str, timeout: float = 10.0) -> dict | None:
    """Fetch a remote agent's identity document."""
    url = f"{target_base_url}/pact/v1/identity"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            resp_ct = resp.headers.get("Content-Type", JSON_CONTENT_TYPE)
            return decode_message(resp.read(), resp_ct)
    except Exception:
        return None
