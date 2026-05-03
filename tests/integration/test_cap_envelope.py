"""v0.4.0 — cap envelope inline regression tests.

Pre-v0.4.0: when a sender presented a cap_id the receiver didn't have
locally, the receiver silently fell through to action-name dispatch
without verifying the chain. Documented as issue #10. The case study's
cross-machine delegation experiment (A6) demonstrated the gap.

Post-v0.4.0: senders include a cap_envelope (the full cap_dict) when
the receiver may not have the cap locally. Receivers verify the chain
against pub keys gathered from the peer cache, and cache the cap on
success.
"""

from __future__ import annotations

import pytest

from pact import crypto
from pact.capability import Caveat, attenuate, issue_capability
from pact.identity import Identity
from pact.message import build_req
from pact.store import PACTStore

from tests.integration.conftest import post_message


def test_three_agent_delegation_over_the_wire(sandbox, tmp_path):
    """The killer scenario: A issues to B, B re-issues to C, C presents to A.

    Pre-v0.4.0 this fell through silently to no auth. Post-v0.4.0,
    A verifies the chain via cap_envelope.
    """
    alice = sandbox["alice"]  # the issuer / receiver
    bob = sandbox["bob"]      # the intermediary

    @alice["agent"].handle("read_doc")
    def read_doc(payload):
        return {"doc": "secret", "delegated_through": "bob"}

    # Carol is a third agent on the same machine (sandbox is alice/bob; we
    # spin up carol's identity in tmp_path).
    carol_store = PACTStore(tmp_path / "carol")
    carol = Identity.create("carol", carol_store)

    # Pre-register peer identities so signature verification works.
    # In production this happens via TOFU on first contact.
    alice_agent = alice["agent"]
    alice_agent._store.save_peer(bob["agent_id"], bob["identity"].to_identity_document())
    alice_agent._store.save_peer(carol.agent_id, carol.to_identity_document())

    # Alice mints a root cap to Bob with max_invocations=10
    root_cap = issue_capability(
        alice["identity"]._private_key,
        alice["agent_id"],
        bob["agent_id"],
        "read_doc",
        caveats=[Caveat("max_invocations", 10)],
    )
    # Alice already has root_cap in her store (she issued it).
    alice_agent._store.save_capability("alice", root_cap.to_dict())

    # Bob attenuates and grants to Carol with max_invocations=2
    child_cap = attenuate(
        root_cap,
        bob["identity"]._private_key,
        bob["agent_id"],
        carol.agent_id,
        additional_caveats=[Caveat("max_invocations", 2)],
    )

    # Carol's cap is NOT in alice's store. She presents it via cap_envelope.
    req = build_req(
        from_private_key=carol._private_key,
        from_id=carol.agent_id,
        to_id=alice["agent_id"],
        intent="task",
        payload={"action": "read_doc"},
        cap_id=child_cap.cap_id,
        holder_proof_key=carol._private_key,
        cap_envelope=child_cap.to_dict(),
    )
    res = post_message(alice["url"], req.to_dict())

    assert res["status"] == "ok", f"three-agent delegation failed: {res}"
    assert res["payload"]["doc"] == "secret"

    # Cap should now be cached for future uses. Send again WITHOUT the
    # envelope — should still work.
    req2 = build_req(
        from_private_key=carol._private_key,
        from_id=carol.agent_id,
        to_id=alice["agent_id"],
        intent="task",
        payload={"action": "read_doc"},
        cap_id=child_cap.cap_id,
        holder_proof_key=carol._private_key,
    )
    res2 = post_message(alice["url"], req2.to_dict())
    assert res2["status"] == "ok", "cap should have been cached after first use"


def test_unknown_cap_without_envelope_rejected(sandbox):
    """v0.4.0: cap_id that the receiver doesn't know AND no envelope = reject.

    Pre-v0.4.0 this silently fell through. Now it's an explicit error.
    """
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    @bob["agent"].handle("ping")
    def ping(payload):
        return {"pong": True}

    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "ping"},
        cap_id="some-fake-cap-id-bob-has-never-seen",
        holder_proof_key=alice["identity"]._private_key,
    )
    res = post_message(bob["url"], req.to_dict())
    assert res["status"] == "error"
    assert res["fault"]["code"] == "cap_unknown"


def test_envelope_with_mismatched_cap_id_rejected(sandbox):
    """A cap_envelope whose cap_id doesn't match msg.cap_id is rejected."""
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    @bob["agent"].handle("ping")
    def ping(payload):
        return {"pong": True}

    cap = issue_capability(
        bob["identity"]._private_key,
        bob["agent_id"],
        alice["agent_id"],
        "ping",
    )

    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "ping"},
        cap_id="not-the-real-cap-id",
        holder_proof_key=alice["identity"]._private_key,
        cap_envelope=cap.to_dict(),
    )
    res = post_message(bob["url"], req.to_dict())
    assert res["status"] == "error"
    assert res["fault"]["code"] == "capability_invalid"


def test_envelope_with_wrong_issuer_rejected(sandbox, tmp_path):
    """An envelope claiming a cap issued by someone other than us is rejected."""
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    @bob["agent"].handle("ping")
    def ping(payload):
        return {"pong": True}

    # Some random third party issues a cap claiming bob as issuer (forged)
    third_priv, third_pub = crypto.generate_keypair()
    import base64
    third_id = crypto.sha256_digest(f"Ed25519{base64.b64encode(third_pub).decode()}".encode())
    forged = issue_capability(
        third_priv, third_id, alice["agent_id"], "ping",
    )

    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "ping"},
        cap_id=forged.cap_id,
        holder_proof_key=alice["identity"]._private_key,
        cap_envelope=forged.to_dict(),
    )
    res = post_message(bob["url"], req.to_dict())
    assert res["status"] == "error"
    assert res["fault"]["code"] == "capability_invalid"
    assert "issuer" in res["fault"]["detail"].lower()
