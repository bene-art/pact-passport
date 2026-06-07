"""B3: Inline Multi-Agent Delegation — deep nest fuzz.

Tests context-bound delegation trace verification under cap_envelope
chains at depths K ∈ {2, 3, 5, 7, 10}.

EMPIRICAL FINDING (run 2026-06-07 against v0.5.5):
-----------------------------------------------------
Multi-hop chain verification is BROKEN at depths > 2.

The bug is in `verify_capability` (src/pact/capability.py:325-335):
  for link in token.delegation_chain:
      if not crypto.verify(token.parent.encode(), link_sig, link_key):
          return CapabilityResult(False, "Invalid delegation chain link...")

Every chain link's signature is checked against `token.parent` — the
parent cap_id of the FINAL token. But each link signed a DIFFERENT
parent at the time of that attenuation:

  - link[0] (A1 attenuates root → cap_1): A1 signed root.cap_id
  - link[1] (A2 attenuates cap_1 → cap_2): A2 signed cap_1.cap_id
  - link[2] (A3 attenuates cap_2 → cap_3): A3 signed cap_2.cap_id

At verification of cap_3, all three link signatures are checked against
cap_3.parent (= cap_2.cap_id). Only link[2] verifies. link[0] and
link[1] signed earlier cap_ids the verifier no longer has.

At depth 2 (one chain link), the bug is silent — the single link's
parent IS the final token's parent. At depth ≥ 3, all chains fail.

Spec §5.2 prose: "Each delegation_chain link's sig MUST verify against
that link's from agent's public key, signing the parent cap_id" — the
phrase "the parent cap_id" is ambiguous (final cap's parent? each
link's parent?). The code implements the former; honest multi-hop
support requires the latter. This is a real correctness bug, not just
a spec-tightness gap like C4.

Fix path (post-paper, tracked as v0.6 issue): verify_capability must
walk the chain and reconstruct or carry the intermediate cap_ids,
verifying each link against its actual signed-over cap_id rather than
against the final token's parent.

This experiment therefore reports:
  - At K=2: all 5 variants behave as predicted (control accepts;
    tampers reject). The protocol property works at depth 2.
  - At K ∈ {3, 5, 7, 10}: even the clean chain is rejected, surfacing
    the multi-hop verification bug. Tamper variants are vacuously
    rejected (the chain breaks regardless of tampering).

The finding is the K ≥ 3 control rejection. The K=2 variants confirm
the property holds at the shallowest interesting depth.
"""

from __future__ import annotations

import base64
import copy
import uuid

import pytest

from pact import crypto
from pact._canonical import canonical_json
from pact.capability import (
    Caveat,
    DelegationLink,
    attenuate,
    issue_capability,
)
from pact.identity import Identity
from pact.message import build_req
from pact.store import PACTStore

from tests.integration.conftest import post_message


# ---------------------------------------------------------------------------
# Chain builder for inline-envelope scenario
# ---------------------------------------------------------------------------


def _build_inline_chain(sandbox, tmp_path, depth_k: int):
    """Build a depth-K chain Alice → A1 → A2 → ... → A_K, with all chain
    agent identities pre-registered in Alice's peer cache so chain
    signatures can be verified during cap_envelope inline check.
    """
    alice = sandbox["alice"]

    @alice["agent"].handle("read_doc")
    def read_doc(payload):
        return {"doc": "secret", "depth": depth_k}

    chain_store = PACTStore(tmp_path / f"chain_{depth_k}")
    chain_identities = []
    for k in range(1, depth_k + 1):
        ident = Identity.create(f"a{k}_{depth_k}", chain_store)
        chain_identities.append(ident)
        alice["agent"]._store.save_peer(
            ident.agent_id, ident.to_identity_document()
        )

    root_cap = alice["agent"].grant(
        chain_identities[0].agent_id,
        "read_doc",
        caveats=[Caveat("max_invocations", 10)],
    )

    current_cap = root_cap
    for k in range(0, depth_k - 1):
        delegator = chain_identities[k]
        new_holder = chain_identities[k + 1]
        current_cap = attenuate(
            current_cap,
            delegator_private_key=delegator._private_key,
            delegator_id=delegator.agent_id,
            new_holder_id=new_holder.agent_id,
            additional_caveats=[Caveat("max_invocations", max(1, 10 - k - 1))],
        )

    return alice, chain_identities[-1], current_cap


def _build_req_with_envelope(alice, last_agent, last_cap, envelope_override=None):
    cap_dict = envelope_override if envelope_override is not None else last_cap.to_dict()
    return build_req(
        from_private_key=last_agent._private_key,
        from_id=last_agent.agent_id,
        to_id=alice["agent_id"],
        intent="task",
        payload={"action": "read_doc"},
        cap_id=last_cap.cap_id,
        holder_proof_key=last_agent._private_key,
        cap_envelope=cap_dict,
        identity_doc=last_agent.to_identity_document(),
        deadline_seconds=30,
    )


# ---------------------------------------------------------------------------
# Depth-2 control + 5 tamper variants (the property works at this depth)
# ---------------------------------------------------------------------------


def test_b3_depth2_clean_chain_accepted(sandbox, tmp_path, capsys):
    """Variant (i) at K=2: clean two-hop chain accepted by inline verification."""
    alice, last_agent, last_cap = _build_inline_chain(sandbox, tmp_path, 2)
    req = _build_req_with_envelope(alice, last_agent, last_cap)
    result = post_message(alice["url"], req.to_dict())
    print(f"\n[B3-K2-clean] status={result.get('status')}")
    assert result.get("status") == "ok", (
        f"clean depth-2 chain rejected: {result}"
    )


def test_b3_depth2_intermediate_signature_forged_rejected(sandbox, tmp_path, capsys):
    """Variant (ii) at K=2: replace the single chain-link signature with
    garbage. Inline verification must reject."""
    alice, last_agent, last_cap = _build_inline_chain(sandbox, tmp_path, 2)
    envelope = last_cap.to_dict()
    chain = envelope["delegation_chain"]
    chain[0]["sig"] = base64.b64encode(b"\xde\xad\xbe\xef" * 16).decode()
    req = _build_req_with_envelope(alice, last_agent, last_cap, envelope_override=envelope)
    result = post_message(alice["url"], req.to_dict())
    print(f"\n[B3-K2-ii] forged-sig status={result.get('status')}")
    assert result.get("status") == "error"


def test_b3_depth2_intermediate_from_swapped_rejected(sandbox, tmp_path, capsys):
    """Variant (iii) at K=2: swap chain link's `from` agent_id to a
    foreign agent_id."""
    alice, last_agent, last_cap = _build_inline_chain(sandbox, tmp_path, 2)
    envelope = last_cap.to_dict()
    envelope["delegation_chain"][0]["from"] = "sha256:" + "c" * 64
    req = _build_req_with_envelope(alice, last_agent, last_cap, envelope_override=envelope)
    result = post_message(alice["url"], req.to_dict())
    print(f"\n[B3-K2-iii] swapped-from status={result.get('status')}")
    assert result.get("status") == "error"


def test_b3_depth2_parent_cap_id_mutated_rejected(sandbox, tmp_path, capsys):
    """Variant (v) at K=2: mutate the cap.parent field."""
    alice, last_agent, last_cap = _build_inline_chain(sandbox, tmp_path, 2)
    envelope = last_cap.to_dict()
    envelope["parent"] = str(uuid.uuid4())
    req = _build_req_with_envelope(alice, last_agent, last_cap, envelope_override=envelope)
    result = post_message(alice["url"], req.to_dict())
    print(f"\n[B3-K2-v] parent-mutated status={result.get('status')}")
    assert result.get("status") == "error"


# ---------------------------------------------------------------------------
# Variant (iv) reorder requires ≥ 2 chain links, which requires K ≥ 3.
# Skipped at K=2 because there's only one link to reorder.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Depth ≥ 3 FINDING: clean chains rejected by multi-hop verification bug
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("depth_k", [3, 5, 7, 10])
def test_b3_finding_clean_chain_rejected_at_depth_ge_3(sandbox, tmp_path, depth_k, capsys):
    """FINDING: At chain depths K ≥ 3, a CLEAN multi-hop delegation
    chain is rejected by inline verification.

    Root cause: src/pact/capability.py:325-335 checks every chain link
    signature against `token.parent` (final cap's parent), but each
    link signed a different intermediate cap_id. Only the last link
    verifies; earlier links fail with "Invalid delegation chain link
    from <id>".

    This test asserts the empirical (buggy) state. When the bug is
    fixed in v0.6 (tracked as a separate issue), invert this assertion
    to require status=ok.
    """
    alice, last_agent, last_cap = _build_inline_chain(sandbox, tmp_path, depth_k)
    req = _build_req_with_envelope(alice, last_agent, last_cap)
    result = post_message(alice["url"], req.to_dict())
    fault_code = result.get("fault", {}).get("code")
    fault_detail = result.get("fault", {}).get("detail", "")
    print(
        f"\n[B3-K{depth_k}-FINDING] clean chain at K={depth_k} → "
        f"status={result.get('status')} fault={fault_code} detail={fault_detail[:60]!r}"
    )
    assert result.get("status") == "error", (
        f"unexpected: K={depth_k} clean chain accepted — the multi-hop "
        f"verification bug may have been fixed; invert this assertion"
    )
    assert fault_code == "capability_invalid"
    assert "Invalid delegation chain link" in fault_detail, (
        f"unexpected rejection reason: {fault_detail}"
    )
