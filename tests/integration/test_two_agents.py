"""Integration test: two agents communicate via PACT."""

import time
import base64

from pact_passport.identity import Identity
from pact_passport.capability import issue_capability, Caveat
from pact_passport.message import build_req, build_res, verify_message
from pact_passport.receipt import create_receipt, verify_receipt
from pact_passport.transport.server import PACTServer
from pact_passport.transport.client import send_message, fetch_identity


def test_full_exchange(store):
    """Alice asks Bob for weather. Full PACT flow with verification."""
    # Create identities
    alice = Identity.create("alice", store)
    bob = Identity.create("bob", store)

    # Bob issues a capability to Alice
    cap = issue_capability(
        bob._private_key, bob.agent_id, alice.agent_id, "get_weather",
    )
    store.save_capability("bob", cap.to_dict())

    # Bob sets up a server
    def bob_dispatch(body):
        from pact_passport.message import PACTMessage, build_res
        msg = PACTMessage.from_dict(body)

        if msg.intent == "identity":
            return build_res(
                bob._private_key, bob.agent_id, msg,
                payload=bob.to_identity_document(),
            ).to_dict()

        if msg.intent == "task":
            return build_res(
                bob._private_key, bob.agent_id, msg,
                payload={"temp": 72, "condition": "clear"},
            ).to_dict()

        return build_res(
            bob._private_key, bob.agent_id, msg,
            status="error", fault={"code": "unknown"},
        ).to_dict()

    server = PACTServer(port=0, dispatch=bob_dispatch, identity_doc=bob.to_identity_document())
    port = server.start()

    try:
        base_url = f"http://127.0.0.1:{port}"

        # Alice fetches Bob's identity
        bob_doc = fetch_identity(base_url)
        assert bob_doc["agent_id"] == bob.agent_id

        # Alice sends a task REQ
        req = build_req(
            from_private_key=alice._private_key,
            from_id=alice.agent_id,
            to_id=bob.agent_id,
            intent="task",
            payload={"city": "Chicago", "action": "get_weather"},
            cap_id=cap.cap_id,
            holder_proof_key=alice._private_key,
        )
        result = send_message(base_url, req)

        # Verify response
        assert result["status"] == "ok"
        assert result["payload"]["temp"] == 72

        # Verify response signature
        from pact_passport.message import PACTMessage
        res_msg = PACTMessage.from_dict(result)
        assert verify_message(res_msg, bob.public_key)

        # Both create receipts
        alice_receipt = create_receipt(
            alice._private_key, alice.agent_id,
            task_ref=req.id, refs=[req.id, res_msg.id], outcome="completed",
        )
        bob_receipt = create_receipt(
            bob._private_key, bob.agent_id,
            task_ref=req.id, refs=[req.id, res_msg.id], outcome="completed",
        )

        # Verify both receipts
        assert verify_receipt(alice_receipt, alice.public_key)
        assert verify_receipt(bob_receipt, bob.public_key)

        # Both agree on outcome
        assert alice_receipt["outcome"] == "completed"
        assert bob_receipt["outcome"] == "completed"
        assert alice_receipt["task_ref"] == bob_receipt["task_ref"]

    finally:
        server.stop()
