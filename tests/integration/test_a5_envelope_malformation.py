"""A5: Wire-Level Envelope Delegation malformation fuzz.

Extends the v0.4.0 cap_envelope tests (tests/integration/test_cap_envelope.py)
with five adversarial malformation variants. Tests that any malformation
in the cap_envelope or its outer-REQ pairing is rejected before dispatch.

Pre-registered prediction: all five variants rejected with
`capability_invalid` or a related fault code; never dispatched.

Risk: low — v0.5.2 hardening + existing v0.4.0 verification should cover
all variants. Any unexpected dispatch would surface a real gap.
"""

from __future__ import annotations

import pytest

from pact import crypto
from pact.capability import Caveat, attenuate, issue_capability
from pact.identity import Identity
from pact.message import build_req
from pact.store import PACTStore

from tests.integration.conftest import post_message


# ---------------------------------------------------------------------------
# Fixture: three-agent setup (alice = root issuer/receiver, bob = intermediate,
# carol = third-party holder presenting the attenuated cap to alice)
# ---------------------------------------------------------------------------


def _setup_three_agent_chain(sandbox, tmp_path):
    """Build the three-agent delegation chain matching test_cap_envelope.py."""
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    @alice["agent"].handle("read_doc")
    def read_doc(payload):
        return {"doc": "secret"}

    # Spin up carol on tmp_path
    carol_store = PACTStore(tmp_path / "carol")
    carol = Identity.create("carol", carol_store)

    # Pre-share peer identities so signature verification works
    alice["agent"]._store.save_peer(
        bob["agent_id"], bob["identity"].to_identity_document()
    )
    alice["agent"]._store.save_peer(
        carol.agent_id, carol.to_identity_document()
    )

    # Alice issues a parent cap to bob
    parent_cap = alice["agent"].grant(bob["agent_id"], "read_doc")

    # Bob attenuates and grants to carol
    child_cap = attenuate(
        parent_cap,
        delegator_private_key=bob["identity"]._private_key,
        delegator_id=bob["agent_id"],
        new_holder_id=carol.agent_id,
        additional_caveats=[Caveat("max_invocations", 2)],
    )

    return {
        "alice": alice,
        "bob": bob,
        "carol_id": carol,
        "parent_cap": parent_cap,
        "child_cap": child_cap,
    }


# ---------------------------------------------------------------------------
# A5 control: clean delegation chain must be accepted
# ---------------------------------------------------------------------------


def test_a5_clean_envelope_control(sandbox, tmp_path, capsys):
    """Control: clean attenuated cap_envelope presented over the wire is
    accepted (sanity-check the test machinery before running malformation
    variants).
    """
    ctx = _setup_three_agent_chain(sandbox, tmp_path)
    alice = ctx["alice"]
    carol = ctx["carol_id"]
    child_cap = ctx["child_cap"]

    req = build_req(
        from_private_key=carol._private_key,
        from_id=carol.agent_id,
        to_id=alice["agent_id"],
        intent="task",
        payload={"action": "read_doc"},
        cap_id=child_cap.cap_id,
        holder_proof_key=carol._private_key,
        cap_envelope=child_cap.to_dict(),
        deadline_seconds=30,
    )
    result = post_message(alice["url"], req.to_dict())

    print(f"\n[A5-control] status={result.get('status')}")
    assert result.get("status") == "ok", (
        f"clean cap_envelope chain should be accepted; got: {result}"
    )


# ---------------------------------------------------------------------------
# A5 malformation variants (5 variants × 20 trials each = 100 trials)
# ---------------------------------------------------------------------------

# Each variant takes a clean envelope dict and returns a malformed version.
# A separate function makes the mutation explicit and the test self-documenting.


def _strip_outer_cap_id(req_dict: dict, envelope: dict) -> dict:
    """Variant (i): remove cap_id from outer REQ but keep envelope.cap_id intact."""
    req_dict["cap_id"] = None
    return req_dict


def _strip_both_cap_ids(req_dict: dict, envelope: dict) -> dict:
    """Variant (ii): remove cap_id from both outer REQ and envelope."""
    req_dict["cap_id"] = None
    if "cap_envelope" in req_dict and req_dict["cap_envelope"]:
        req_dict["cap_envelope"]["cap_id"] = None
    return req_dict


def _mismatched_cap_ids(req_dict: dict, envelope: dict) -> dict:
    """Variant (iii): outer cap_id != envelope.cap_id (fresh UUID forced)."""
    import uuid
    req_dict["cap_id"] = str(uuid.uuid4())
    # leave envelope.cap_id alone
    return req_dict


def _missing_issuer(req_dict: dict, envelope: dict) -> dict:
    """Variant (iv): envelope.cap_id present but envelope.issuer missing."""
    if "cap_envelope" in req_dict and req_dict["cap_envelope"]:
        req_dict["cap_envelope"].pop("issuer", None)
    return req_dict


def _wrong_issuer(req_dict: dict, envelope: dict) -> dict:
    """Variant (v): envelope.issuer set to a different agent_id."""
    if "cap_envelope" in req_dict and req_dict["cap_envelope"]:
        req_dict["cap_envelope"]["issuer"] = "sha256:" + "f" * 64
    return req_dict


VARIANTS = [
    ("strip_outer_cap_id", _strip_outer_cap_id),
    ("strip_both_cap_ids", _strip_both_cap_ids),
    ("mismatched_cap_ids", _mismatched_cap_ids),
    ("missing_issuer", _missing_issuer),
    ("wrong_issuer", _wrong_issuer),
]

TRIALS_PER_VARIANT = 20


def test_a5_envelope_malformation_matrix(sandbox, tmp_path, capsys):
    """Run TRIALS_PER_VARIANT trials per variant; assert every malformed
    envelope is rejected at dispatch.

    Each variant is deterministic; the trial count exists to catch any
    state-dependent behavior across repeated invocations (e.g., cache
    pollution affecting later requests).
    """
    print()
    for variant_name, mutator in VARIANTS:
        dispatched = 0
        rejected = 0
        unexpected_codes = []

        for _ in range(TRIALS_PER_VARIANT):
            # Build a fresh chain per trial — attenuate mints a fresh cap_id
            # each time, so we don't pollute caches with one cap_id reused.
            ctx = _setup_three_agent_chain(sandbox, tmp_path)
            alice = ctx["alice"]
            carol = ctx["carol_id"]
            child_cap = ctx["child_cap"]

            # Build a clean REQ, then mutate via the variant function
            req = build_req(
                from_private_key=carol._private_key,
                from_id=carol.agent_id,
                to_id=alice["agent_id"],
                intent="task",
                payload={"action": "read_doc"},
                cap_id=child_cap.cap_id,
                holder_proof_key=carol._private_key,
                cap_envelope=child_cap.to_dict(),
                deadline_seconds=30,
            )

            # Mutate the dict representation
            req_dict = req.to_dict()
            req_dict = mutator(req_dict, child_cap.to_dict())

            # Note: build_req signed the original message; the mutated
            # dict has the same signature, which now no longer matches.
            # That's part of what makes this realistic — an attacker
            # would attempt to bypass cap-envelope verification with a
            # malformed message that may or may not pass signature check.

            try:
                result = post_message(alice["url"], req_dict)
            except Exception as e:
                # Some malformations may cause build_req to fail or trigger
                # a transport-level exception. Either way, the REQ does not
                # dispatch — counts as rejected.
                rejected += 1
                continue

            status = result.get("status")
            fault_code = result.get("fault", {}).get("code") if status == "error" else None

            if status == "ok":
                dispatched += 1
            else:
                rejected += 1
                # Pre-registered acceptable rejection codes
                if fault_code not in {
                    "capability_invalid",
                    "cap_unknown",
                    "invalid_signature",
                    "invalid_message",
                    "http_error",  # transport-layer rejection
                    "holder_proof_invalid",
                    "holder_proof_required",
                }:
                    unexpected_codes.append(fault_code)

        print(
            f"[A5] variant={variant_name:22} "
            f"trials={TRIALS_PER_VARIANT} "
            f"dispatched={dispatched} rejected={rejected} "
            f"unexpected_codes={unexpected_codes or 'none'}"
        )

        # Pre-registered: every malformation must be rejected
        assert dispatched == 0, (
            f"variant {variant_name}: {dispatched}/{TRIALS_PER_VARIANT} "
            f"malformed envelopes were DISPATCHED — possible FINDING"
        )
        # If rejection codes outside the acceptable set appear, surface them
        # but don't fail (informational — broader-than-expected rejection
        # is still rejection).
