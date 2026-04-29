"""Integration test: A→B→C capability delegation chain."""

from datetime import datetime, timezone, timedelta

from pact import crypto
from pact.identity import Identity
from pact.capability import (
    issue_capability, attenuate, verify_capability, Caveat,
)
from pact.message import build_req, build_res, verify_message
from pact.receipt import create_receipt, verify_receipt
from pact.transport.server import PACTServer
from pact.transport.client import send_message


def test_three_agent_delegation(store):
    """A issues to B, B attenuates to C, C uses the capability against A's server."""
    # Create three identities
    alice = Identity.create("alice", store)  # resource owner / server
    bob = Identity.create("bob", store)      # intermediary
    charlie = Identity.create("charlie", store)  # end user

    # Alice issues a root capability to Bob
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    root_cap = issue_capability(
        alice._private_key, alice.agent_id, bob.agent_id, "read_data",
        caveats=[Caveat("expires", future), Caveat("max_invocations", 10)],
    )
    store.save_capability("alice", root_cap.to_dict())

    # Bob attenuates and delegates to Charlie with tighter limits
    child_cap = attenuate(
        root_cap, bob._private_key, bob.agent_id, charlie.agent_id,
        additional_caveats=[
            Caveat("max_invocations", 3),  # tighter than parent's 10
        ],
    )
    store.save_capability("alice", child_cap.to_dict())

    # Verify the chain
    known_keys = {
        alice.agent_id: alice.public_key,
        bob.agent_id: bob.public_key,
        charlie.agent_id: charlie.public_key,
    }

    # Child should be valid for Charlie
    result = verify_capability(child_cap, charlie.agent_id, alice.public_key, known_keys)
    assert result.valid, f"Chain verification failed: {result.reason}"

    # Child should NOT be valid for Bob (wrong holder)
    result_wrong = verify_capability(child_cap, bob.agent_id, alice.public_key, known_keys)
    assert not result_wrong.valid

    # Alice's server processes Charlie's request
    def alice_dispatch(body):
        from pact.message import PACTMessage, build_res
        msg = PACTMessage.from_dict(body)
        if msg.intent == "task":
            return build_res(
                alice._private_key, alice.agent_id, msg,
                payload={"data": "secret_value", "delegated_through": "bob"},
            ).to_dict()
        return build_res(alice._private_key, alice.agent_id, msg, status="error").to_dict()

    server = PACTServer(port=0, dispatch=alice_dispatch)
    port = server.start()

    try:
        base_url = f"http://127.0.0.1:{port}"

        # Charlie sends a task using the attenuated capability
        req = build_req(
            from_private_key=charlie._private_key,
            from_id=charlie.agent_id,
            to_id=alice.agent_id,
            intent="task",
            payload={"action": "read_data", "query": "all"},
            cap_id=child_cap.cap_id,
            holder_proof_key=charlie._private_key,
        )

        response = send_message(base_url, req)
        assert response["status"] == "ok"
        assert response["payload"]["data"] == "secret_value"

        # Verify response signature
        from pact.message import PACTMessage
        res_msg = PACTMessage.from_dict(response)
        assert verify_message(res_msg, alice.public_key)

        # All three agents can produce independent receipts
        charlie_receipt = create_receipt(
            charlie._private_key, charlie.agent_id,
            task_ref=req.id, refs=[req.id, res_msg.id], outcome="completed",
        )
        assert verify_receipt(charlie_receipt, charlie.public_key)

        # Verify the delegation chain structure
        assert child_cap.parent == root_cap.cap_id
        assert len(child_cap.delegation_chain) == 1
        assert child_cap.delegation_chain[0].from_agent == bob.agent_id
        assert child_cap.issuer == alice.agent_id  # root issuer preserved

        # Verify caveats were inherited + appended
        max_inv_caveats = [c for c in child_cap.caveats if c.restrict == "max_invocations"]
        assert len(max_inv_caveats) == 2  # parent's 10 + child's 3
        # Effective limit is the AND (min) = 3
        assert min(c.value for c in max_inv_caveats) == 3

    finally:
        server.stop()
