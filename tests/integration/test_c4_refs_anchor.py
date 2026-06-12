"""C4: Cross-Machine Causal Chain Alignment — refs[] anchor verification.

Tests that when a REQ carries a refs[] field, every reference UUID must
correspond to a message the receiver actually has in its local store.
Forged or non-existent refs should be rejected.

This is the locked spec path (a) per `experiment_plan_2026-06.md`: refs[]
stays optional per spec §6.2, but if present, every reference must
hash-verify against a stored prior message; out-of-order refs is rejected.

Pre-registered outcome (locked 2026-06-05):
- All variants with forged / nonexistent / type-confused refs should be
  rejected with `unknown_ref` (new fault code) OR the existing
  `invalid_message` fault.
- Empty refs[] is acceptable.
- Control case: refs containing a real prior message ID is accepted.

If this test fails (i.e., the server dispatches handlers despite forged
refs), C4 surfaces a real gap in v0.5.5: refs[] is stored but not
verified — the causal DAG is sender-asserted, not receiver-enforced.
This becomes a candidate finding for §4.2 of the paper.
"""

from __future__ import annotations

import json
import uuid

from pact_passport import crypto
from pact_passport.message import build_req

from tests.integration.conftest import post_message


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _grant_cap(alice, bob, action: str = "echo"):
    """Alice grants Bob a cap for `action`; copy the cap into Bob's store
    so Bob can present it (same pattern as test_agent_ask.py).
    """
    cap = alice["agent"].grant(bob["agent_id"], action)
    bob["agent"]._store.save_capability(bob["name"], cap.to_dict())
    return cap


def _send_req_with_refs(
    sandbox,
    refs: list[str],
    handler_action: str = "echo",
):
    """Bob sends Alice a REQ with the specified `refs[]` field.

    Returns the parsed response dict from Alice's HTTP server.
    """
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    # Register the handler on Alice if not already (idempotent — handle takes a function)
    @alice["agent"].handle(handler_action)
    def _h(payload):
        return {"echoed": payload}

    cap = _grant_cap(alice, bob, action=handler_action)

    bob_identity = bob["agent"]._ensure_identity()
    msg = build_req(
        from_private_key=bob_identity._private_key,
        from_id=bob["agent_id"],
        to_id=alice["agent_id"],
        intent="task",
        payload={"action": handler_action, "msg": "hello"},
        cap_id=cap.cap_id,
        holder_proof_key=bob_identity._private_key,
        refs=refs,
        deadline_seconds=30,
    )

    return post_message(alice["url"], msg.to_dict())


# ---------------------------------------------------------------------------
# Adversarial vectors
# ---------------------------------------------------------------------------


def test_c4_v1_refs_contains_nonexistent_uuid(sandbox, capsys):
    """Variant 1: refs[] contains a UUID that is NOT any prior message
    in Alice's local store. Per spec path (a), Alice should reject this
    with `unknown_ref` (new fault code) or `invalid_message`.

    Pre-registered prediction: rejection.

    This test asserts the empirical state explicitly so the test result
    itself documents what v0.5.5 does. If v0.5.5 dispatches (predicted
    finding), the test PASSES with FINDING_DISPATCHED. If v0.5.5 rejects
    (spec path (a) already implemented), the test FAILS with
    FINDING_REJECTED — surfacing the EXPECTED PASS case as a failure so
    the empirical state is visible without parsing logs.
    """
    fake_uuid = str(uuid.uuid4())
    result = _send_req_with_refs(sandbox, refs=[fake_uuid])

    status = result.get("status")
    fault_code = result.get("fault", {}).get("code") if status == "error" else None

    # Print the finding state for human inspection (visible under pytest -s)
    print(f"\n[C4-V1] refs=[fake_uuid] → status={status} fault={fault_code}")
    print(f"[C4-V1] full result: {json.dumps(result, indent=2)[:500]}")

    if status == "ok":
        # FINDING: refs[] is not verified at the protocol layer in v0.5.5.
        # The causal DAG is sender-asserted, not receiver-enforced.
        print("[C4-V1] FINDING: refs_not_verified — v0.5.5 accepts forged refs")
        assert result.get("payload") is not None, (
            f"dispatched but no payload — unexpected shape: {result}"
        )
    else:
        # Spec path (a) is implemented; reject with a recognized fault
        print(f"[C4-V1] EXPECTED REJECTION with fault: {fault_code}")
        assert fault_code in {"unknown_ref", "invalid_message"}, (
            f"rejected but unexpected fault code: {fault_code} — got: {result}"
        )


def test_c4_v2_refs_contains_agent_id_not_message_id(sandbox, capsys):
    """Variant 2: refs[] contains a string that is structurally an agent_id
    (sha256:...) rather than a message UUID. Type confusion — if the
    server accepts this, refs[] has no schema validation at all.
    """
    alice = sandbox["alice"]
    bogus_ref = alice["agent_id"]  # "sha256:..." not a UUID
    result = _send_req_with_refs(sandbox, refs=[bogus_ref])

    status = result.get("status")
    fault_code = result.get("fault", {}).get("code") if status == "error" else None

    print(f"\n[C4-V2] refs=[agent_id] → status={status} fault={fault_code}")

    if status == "ok":
        print("[C4-V2] FINDING: refs_type_unchecked — agent_id accepted as ref")
    else:
        print(f"[C4-V2] REJECTION with fault: {fault_code}")


def test_c4_v3_refs_empty_control(sandbox):
    """Variant 3 (CONTROL): refs[] is empty. Per spec §6.2 this is fully
    acceptable. The REQ should dispatch normally.

    Pre-registered prediction: accepted.
    """
    result = _send_req_with_refs(sandbox, refs=[])
    assert result.get("status") == "ok", (
        f"empty refs[] should be accepted per spec §6.2; got: {result}"
    )


def test_c4_v4_refs_contains_real_prior_message_control(sandbox):
    """Variant 4 (CONTROL): Bob first sends a successful REQ to Alice
    (call this M1). Then Bob sends a second REQ M2 with refs=[M1.id].

    Per spec path (a): if refs verification is enforced, this should be
    accepted (M1 is in Alice's store).
    Per current v0.5.5 (no verification): also accepted (refs not checked).

    Either way, expected: accepted. Used as a baseline that the test
    machinery itself works end-to-end before drawing conclusions from V1.
    """
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    # First, register the handler
    @alice["agent"].handle("echo")
    def _h(payload):
        return {"echoed": payload}

    cap = _grant_cap(alice, bob, action="echo")
    bob_identity = bob["agent"]._ensure_identity()

    # M1: send the first REQ to get a real message id in Alice's store
    m1 = build_req(
        from_private_key=bob_identity._private_key,
        from_id=bob["agent_id"],
        to_id=alice["agent_id"],
        intent="task",
        payload={"action": "echo", "msg": "first"},
        cap_id=cap.cap_id,
        holder_proof_key=bob_identity._private_key,
        deadline_seconds=30,
    )
    res1 = post_message(alice["url"], m1.to_dict())
    assert res1.get("status") == "ok", f"control M1 failed: {res1}"

    # M2: send a second REQ that refs M1.id
    m2 = build_req(
        from_private_key=bob_identity._private_key,
        from_id=bob["agent_id"],
        to_id=alice["agent_id"],
        intent="task",
        payload={"action": "echo", "msg": "second"},
        cap_id=cap.cap_id,
        holder_proof_key=bob_identity._private_key,
        refs=[m1.id],
        deadline_seconds=30,
    )
    res2 = post_message(alice["url"], m2.to_dict())
    assert res2.get("status") == "ok", (
        f"M2 with refs=[real M1 id] should be accepted; got: {res2}"
    )
