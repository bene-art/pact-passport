"""B3: Inline Multi-Agent Delegation — deep nest fuzz.

Tests context-bound delegation trace verification under cap_envelope
chains at depths K ∈ {2, 3, 5, 7, 10}.

HISTORICAL FINDING (2026-06-07, against v0.5.5):
-------------------------------------------------
Multi-hop chain verification was BROKEN at depths > 2. The bug was in
``verify_capability`` (src/pact/capability.py:325-335):

  for link in token.delegation_chain:
      if not crypto.verify(token.parent.encode(), link_sig, link_key):
          return CapabilityResult(False, "Invalid delegation chain link...")

Every chain link's signature was checked against ``token.parent`` — the
parent cap_id of the FINAL token. But each link signed a DIFFERENT
parent at the time of that attenuation. At depth K=2 the two values
coincide accidentally; at K>=3 every clean chain is rejected.

FIX (2026-06-08, v0.6, see ``bug6_fix_design.md`` and GH #29):
--------------------------------------------------------------
``DelegationLink`` gained a ``parent_cap_id`` field. ``attenuate()``
records what each link signed at its own step. ``verify_capability()``
checks each link against its own contemporaneous parent rather than
against the final token's parent. This test inverts post-fix: every
clean chain at K ∈ {2, 3, 5, 7, 10} should now verify.
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
# Depth >= 3: clean chains verify post-v0.6 fix (Bug 6 closed, GH #29)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("depth_k", [3, 5, 7, 10])
def test_b3_clean_chain_accepted_at_depth_ge_3(sandbox, tmp_path, depth_k, capsys):
    """Clean multi-hop chain at K >= 3 must verify after the v0.6 fix.

    Before v0.6, the verifier checked every chain link against
    ``token.parent`` (final cap's parent) rather than each link's own
    signed-over parent. Clean chains at K >= 3 were rejected by
    construction. v0.6 added ``DelegationLink.parent_cap_id`` and
    routes each link's verification through its own contemporaneous
    parent. This test exercises the fix.
    """
    alice, last_agent, last_cap = _build_inline_chain(sandbox, tmp_path, depth_k)
    req = _build_req_with_envelope(alice, last_agent, last_cap)
    result = post_message(alice["url"], req.to_dict())
    fault = result.get("fault", {})
    print(
        f"\n[B3-K{depth_k}] clean chain at K={depth_k} → "
        f"status={result.get('status')} fault={fault.get('code')}"
    )
    assert result.get("status") == "ok", (
        f"K={depth_k} clean chain rejected after v0.6 fix: "
        f"fault={fault.get('code')} detail={fault.get('detail', '')[:80]!r}"
    )


@pytest.mark.parametrize("depth_k", [3, 5, 7])
def test_b3_intermediate_signature_forged_rejected_at_depth_ge_3(sandbox, tmp_path, depth_k, capsys):
    """Tampering with any chain link's signature must invalidate the
    chain at K >= 3 (post-fix). Demonstrates the verifier still
    fail-closes on forged chains now that clean chains pass.
    """
    alice, last_agent, last_cap = _build_inline_chain(sandbox, tmp_path, depth_k)
    envelope = last_cap.to_dict()
    # Mutate the FIRST chain link's signature — the one that would have
    # been silently rejected pre-fix anyway because of Bug 6. Post-fix,
    # the rejection reason must be the forged signature, not the bug.
    envelope["delegation_chain"][0]["sig"] = base64.b64encode(b"\xde\xad\xbe\xef" * 16).decode()
    req = _build_req_with_envelope(alice, last_agent, last_cap, envelope_override=envelope)
    result = post_message(alice["url"], req.to_dict())
    print(
        f"\n[B3-K{depth_k}-forged] tampered first link → "
        f"status={result.get('status')} fault={result.get('fault', {}).get('code')}"
    )
    assert result.get("status") == "error"
    assert result.get("fault", {}).get("code") == "capability_invalid"


@pytest.mark.parametrize("depth_k", [3, 5])
def test_b3_mutated_parent_cap_id_rejected_at_depth_ge_3(sandbox, tmp_path, depth_k, capsys):
    """Tampering with ``parent_cap_id`` on any link must invalidate
    the chain (post-fix, new attack surface created by the new field).
    """
    alice, last_agent, last_cap = _build_inline_chain(sandbox, tmp_path, depth_k)
    envelope = last_cap.to_dict()
    # Mutate the first link's parent_cap_id to a fresh random value.
    envelope["delegation_chain"][0]["parent_cap_id"] = str(uuid.uuid4())
    req = _build_req_with_envelope(alice, last_agent, last_cap, envelope_override=envelope)
    result = post_message(alice["url"], req.to_dict())
    print(
        f"\n[B3-K{depth_k}-pcid-mut] mutated parent_cap_id → "
        f"status={result.get('status')} fault={result.get('fault', {}).get('code')}"
    )
    assert result.get("status") == "error"
    assert result.get("fault", {}).get("code") == "capability_invalid"
