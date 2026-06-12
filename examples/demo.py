#!/usr/bin/env python3
"""PACT Demo: Two agents, one task, verified receipts.

Run: python examples/demo.py
"""

import os
import sys
import tempfile

# Use a temp directory so we don't pollute ~/.pact
tmp = tempfile.mkdtemp(prefix="pact_demo_")
os.environ["PACT_HOME"] = tmp

from pact_passport.identity import Identity
from pact_passport.capability import issue_capability, verify_capability, Caveat
from pact_passport.message import build_req, build_res, verify_message, verify_holder_proof
from pact_passport.receipt import create_receipt, verify_receipt
from pact_passport.store import PACTStore
from pact_passport.transport.server import PACTServer
from pact_passport.transport.client import send_message, fetch_identity


def main():
    store = PACTStore()

    print("=" * 60)
    print("PACT Demo — Protocol for Agent Capability and Trust")
    print("=" * 60)

    # Step 1: Create identities
    print("\n[1] Creating identities...")
    alice = Identity.create("alice", store)
    bob = Identity.create("bob", store)
    print(f"  Alice: {alice.agent_id[:30]}...")
    print(f"  Bob:   {bob.agent_id[:30]}...")

    # Step 2: Bob issues a capability to Alice
    print("\n[2] Bob issues capability to Alice...")
    cap = issue_capability(
        bob._private_key, bob.agent_id, alice.agent_id, "get_weather",
        caveats=[],
    )
    print(f"  cap_id: {cap.cap_id[:20]}...")
    print(f"  action: {cap.action}")
    print(f"  holder: Alice")

    # Step 3: Verify the capability
    result = verify_capability(cap, alice.agent_id, bob.public_key)
    print(f"  valid:  {result.valid}")

    # Step 4: Bob starts a server
    print("\n[3] Bob starts serving...")

    def bob_dispatch(body):
        from pact_passport.message import PACTMessage, build_res
        msg = PACTMessage.from_dict(body)
        if msg.intent == "identity":
            return build_res(bob._private_key, bob.agent_id, msg,
                             payload=bob.to_identity_document()).to_dict()
        if msg.intent == "task":
            print(f"  Bob received task: {msg.payload}")
            return build_res(bob._private_key, bob.agent_id, msg,
                             payload={"temp": 72, "condition": "clear"}).to_dict()
        return build_res(bob._private_key, bob.agent_id, msg,
                         status="error", fault={"code": "unknown"}).to_dict()

    server = PACTServer(port=0, dispatch=bob_dispatch,
                        identity_doc=bob.to_identity_document())
    port = server.start()
    base_url = f"http://127.0.0.1:{port}"
    print(f"  Bob listening on port {port}")

    try:
        # Step 5: Alice fetches Bob's identity
        print("\n[4] Alice fetches Bob's identity...")
        bob_doc = fetch_identity(base_url)
        print(f"  Verified: agent_id matches = {bob_doc['agent_id'] == bob.agent_id}")

        # Step 6: Alice sends a task REQ
        print("\n[5] Alice sends REQ to Bob...")
        req = build_req(
            from_private_key=alice._private_key,
            from_id=alice.agent_id,
            to_id=bob.agent_id,
            intent="task",
            payload={"city": "Chicago", "action": "get_weather"},
            cap_id=cap.cap_id,
            holder_proof_key=alice._private_key,
        )
        print(f"  Message ID:      {req.id[:20]}...")
        print(f"  Intent:          {req.intent}")
        print(f"  Capability:      {req.cap_id[:20]}...")
        print(f"  Holder proof:    present")
        print(f"  Deadline:        {req.deadline}")
        print(f"  Idempotency key: {req.idempotency_key[:20]}...")

        # Step 7: Send and receive
        print("\n[6] Sending REQ over HTTP...")
        response = send_message(base_url, req)

        from pact_passport.message import PACTMessage
        res_msg = PACTMessage.from_dict(response)
        print(f"  Status:  {res_msg.status}")
        print(f"  Payload: {res_msg.payload}")

        # Step 8: Verify response signature
        print("\n[7] Verifying response signature...")
        sig_valid = verify_message(res_msg, bob.public_key)
        print(f"  Signature valid: {sig_valid}")

        # Step 9: Both create receipts
        print("\n[8] Creating unilateral receipts...")
        alice_receipt = create_receipt(
            alice._private_key, alice.agent_id,
            task_ref=req.id, refs=[req.id, res_msg.id], outcome="completed",
        )
        bob_receipt = create_receipt(
            bob._private_key, bob.agent_id,
            task_ref=req.id, refs=[req.id, res_msg.id], outcome="completed",
        )

        a_valid = verify_receipt(alice_receipt, alice.public_key)
        b_valid = verify_receipt(bob_receipt, bob.public_key)
        print(f"  Alice receipt valid: {a_valid}")
        print(f"  Bob receipt valid:   {b_valid}")
        print(f"  Outcomes match:      {alice_receipt['outcome'] == bob_receipt['outcome']}")

        print("\n" + "=" * 60)
        print("PACT exchange complete.")
        print("  Identity:    self-certifying Ed25519 with pre-rotation")
        print("  Authority:   holder-bound capability token")
        print("  Messages:    2 types (REQ/RES)")
        print("  Audit:       unilateral receipts, independently verifiable")
        print("=" * 60)

    finally:
        server.stop()

    # Cleanup
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
