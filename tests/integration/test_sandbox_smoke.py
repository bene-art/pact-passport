"""Smoke test: harness comes up, agents are reachable, basic REQ/RES works."""

from __future__ import annotations

from pact.message import build_req, PACTMessage, verify_message

from tests.integration.conftest import _http_get_json, post_message


def test_health_endpoints(sandbox):
    for h in (sandbox["alice"], sandbox["bob"]):
        status, body = _http_get_json(f"{h['url']}/pact/v1/health")
        assert status == 200
        assert body["status"] == "ok"


def test_basic_req_res(sandbox):
    """Alice sends a task to Bob with a registered handler."""
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    @bob["agent"].handle("echo")
    def echo(payload):
        return {"got": payload.get("msg", "")}

    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"msg": "hi", "action": "echo"},
    )
    body = post_message(bob["url"], req.to_dict())
    assert body["status"] == "ok"
    assert body["payload"]["got"] == "hi"

    # Verify Bob's response signature
    res = PACTMessage.from_dict(body)
    assert verify_message(res, bob["public_key"])
