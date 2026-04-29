"""HTTP client for sending PACT messages."""

from __future__ import annotations

import json
import urllib.request
import urllib.error

from pact.message import PACTMessage


def send_message(target_base_url: str, msg: PACTMessage, timeout: float = 30.0) -> dict:
    """Send a PACT message to a target agent.

    Args:
        target_base_url: e.g. "http://192.168.1.100:9100"
        msg: The PACTMessage to send.
        timeout: HTTP timeout in seconds.

    Returns:
        The response body as a dict.
    """
    url = f"{target_base_url}/pact/v1/message"
    data = json.dumps(msg.to_dict()).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {"status": "error", "fault": {"code": "http_error", "detail": body}}
    except urllib.error.URLError as e:
        return {"status": "error", "fault": {"code": "unreachable", "detail": str(e.reason)}}
    except TimeoutError:
        return {"status": "error", "fault": {"code": "timeout", "detail": "Request timed out"}}


def fetch_identity(target_base_url: str, timeout: float = 10.0) -> dict | None:
    """Fetch a remote agent's identity document."""
    url = f"{target_base_url}/pact/v1/identity"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception:
        return None
