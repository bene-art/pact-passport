"""Sandbox harness for concurrency / race-condition tests.

Spins up two PACTAgent instances on loopback, each with its own store and
HTTP server. Pre-shares peer identities so signature verification works
without an mDNS handshake. Yields handles; tears down on test exit.

Designed for in-process testing — same ThreadingHTTPServer that runs in
production, so race conditions are real.
"""

from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from typing import Any

import pytest

from pact_passport.agent import PACTAgent
from pact_passport.transport.server import PACTServer


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _http_get_json(url: str, timeout: float = 1.0) -> tuple[int, dict | None]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return 0, None


def _wait_ready(url: str, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        status, body = _http_get_json(url)
        if status == 200 and body and body.get("status") == "ok":
            return
        time.sleep(0.05)
    raise TimeoutError(f"server not ready at {url}")


def post_message(url: str, msg_dict: dict, timeout: float = 5.0) -> dict:
    """POST a message dict to /pact/v1/message and return the parsed response."""
    data = json.dumps(msg_dict).encode("utf-8")
    req = urllib.request.Request(
        f"{url}/pact/v1/message",
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read())
        except Exception:
            return {"status": "error", "fault": {"code": "http_error", "detail": str(e)}}


def _start_agent(name: str, store_dir, port: int) -> dict[str, Any]:
    agent = PACTAgent(name, store_dir=store_dir, host="127.0.0.1", port=port)
    identity = agent._ensure_identity()
    server = PACTServer(
        host="127.0.0.1",
        port=port,
        dispatch=agent._dispatch,
        identity_doc=identity.to_identity_document(),
    )
    actual_port = server.start()
    agent.port = actual_port
    agent._server = server
    return {
        "name": name,
        "agent": agent,
        "identity": identity,
        "agent_id": identity.agent_id,
        "public_key": identity.public_key,
        "url": f"http://127.0.0.1:{actual_port}",
        "server": server,
    }


@pytest.fixture
def sandbox(tmp_path):
    """Two PACT agents on loopback. Yields {alice, bob} handles."""
    alice = _start_agent("alice", tmp_path / "alice", _free_port())
    bob = _start_agent("bob", tmp_path / "bob", _free_port())

    _wait_ready(f"{alice['url']}/pact/v1/health")
    _wait_ready(f"{bob['url']}/pact/v1/health")

    # Pre-share peer identities so signature verification works on REQ.
    alice_doc = alice["identity"].to_identity_document()
    bob_doc = bob["identity"].to_identity_document()
    alice["agent"]._store.save_peer(bob["agent_id"], bob_doc)
    bob["agent"]._store.save_peer(alice["agent_id"], alice_doc)

    try:
        yield {"alice": alice, "bob": bob}
    finally:
        alice["server"].stop()
        bob["server"].stop()
