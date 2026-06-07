"""B1: Downstream Attenuation Continuity — deep-chain fuzz.

Tests strict enforcement of caveat restriction parameters across N-hop
delegation chains. Five attempted-loosening attack vectors per chain
depth (N ∈ {2, 3, 5, 10}).

Pre-registered prediction: every loosening attempt is rejected — either
at attenuate() time (the v0.5.3 caveat-validation patch + the v0.4.0
attenuation rules) or at verify_capability time (the chain-signature
check). Caveats are append-only across all chain depths.

Adversarial vectors:
  (i)   Increase max_invocations from parent's value
  (ii)  Extend expires beyond parent's value
  (iii) Attenuate a terminal (no_further_delegation) cap
  (iv)  Forge a child cap with a different action (bypassing attenuate)
  (v)   Forge a child cap with caveats stripped (bypassing attenuate)

Build cost target: 2-4 hrs. Actual ~1 hr (this experiment exercises
existing attenuate() and verify_capability validation paths that the
v0.4.0 + v0.5.3 patches already implement; the fuzz is depth coverage,
not new failure-mode coverage).
"""

from __future__ import annotations

import base64
import copy

import pytest

from pact import crypto
from pact._canonical import canonical_json
from pact.capability import (
    AttenuationViolation,
    Caveat,
    CapabilityToken,
    DelegationLink,
    attenuate,
    issue_capability,
    verify_capability,
)


# ---------------------------------------------------------------------------
# Chain builder — N legitimate hops, fresh keys per agent
# ---------------------------------------------------------------------------


def _build_chain(n_hops: int):
    """Build a legitimate N-hop chain Alice -> A1 -> A2 -> ... -> A_n.

    Returns:
        agents:        list of (priv, pub, agent_id) tuples, length n_hops + 1
        caps:          list of CapabilityTokens, length n_hops; caps[k] is
                       held by agents[k+1]
        known_keys:    dict mapping each agent_id to its public key
                       (what a verifier needs to check the chain)
    """
    agents = []
    for _ in range(n_hops + 1):
        priv, pub = crypto.generate_keypair()
        pub_b64 = base64.b64encode(pub).decode()
        aid = crypto.sha256_digest(f"Ed25519{pub_b64}".encode())
        agents.append((priv, pub, aid))

    # Alice issues a root cap to A1 with a tight caveat set we can later
    # try to loosen.
    alice_priv, _, alice_id = agents[0]
    a1_id = agents[1][2]

    root_cap = issue_capability(
        alice_priv, alice_id, a1_id, "read_doc",
        caveats=[
            Caveat("max_invocations", 5),
            Caveat("expires", "2026-12-31T23:59:59+00:00"),
        ],
    )

    caps = [root_cap]
    for k in range(1, n_hops):
        delegator_priv = agents[k][0]
        delegator_id = agents[k][2]
        new_holder_id = agents[k + 1][2]
        parent = caps[-1]
        # Each hop tightens max_invocations by 1 (legitimate attenuation)
        # to keep the chain valid.
        child = attenuate(
            parent,
            delegator_private_key=delegator_priv,
            delegator_id=delegator_id,
            new_holder_id=new_holder_id,
            additional_caveats=[Caveat("max_invocations", max(1, 5 - k))],
        )
        caps.append(child)

    known_keys = {agents[i][2]: agents[i][1] for i in range(n_hops + 1)}
    return agents, caps, known_keys


# ---------------------------------------------------------------------------
# Attack matrix — five loosening vectors at the last hop
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("n_hops", [2, 3, 5, 10])
def test_b1_increase_max_invocations_rejected(n_hops, capsys):
    """Variant (i): at the last hop, attempt to attenuate with
    max_invocations=999 (LARGER than parent). attenuate() must raise
    AttenuationViolation."""
    agents, caps, _ = _build_chain(n_hops)
    # caps[-1] is held by agents[n_hops]; delegator at the next hop is
    # that holder. Generate a fresh downstream agent as the new holder.
    last_delegator_priv = agents[n_hops][0]
    last_delegator_id = agents[n_hops][2]
    downstream_priv, downstream_pub = crypto.generate_keypair()
    downstream_pub_b64 = base64.b64encode(downstream_pub).decode()
    new_holder_id = crypto.sha256_digest(f"Ed25519{downstream_pub_b64}".encode())
    parent = caps[-1]
    parent_max = min(
        c.value for c in parent.caveats if c.restrict == "max_invocations"
    )

    print(f"\n[B1-i N={n_hops}] parent max_invocations={parent_max}; attempting 999")
    with pytest.raises(AttenuationViolation, match="max_invocations"):
        attenuate(
            parent,
            delegator_private_key=last_delegator_priv,
            delegator_id=last_delegator_id,
            new_holder_id=new_holder_id,
            additional_caveats=[Caveat("max_invocations", 999)],
        )


@pytest.mark.parametrize("n_hops", [2, 3, 5, 10])
def test_b1_extend_expires_rejected(n_hops, capsys):
    """Variant (ii): at the last hop, attempt to attenuate with
    expires = year 2099 (later than parent). attenuate() must raise."""
    agents, caps, _ = _build_chain(n_hops)
    # caps[-1] is held by agents[n_hops]; delegator at the next hop is
    # that holder. Generate a fresh downstream agent as the new holder.
    last_delegator_priv = agents[n_hops][0]
    last_delegator_id = agents[n_hops][2]
    downstream_priv, downstream_pub = crypto.generate_keypair()
    downstream_pub_b64 = base64.b64encode(downstream_pub).decode()
    new_holder_id = crypto.sha256_digest(f"Ed25519{downstream_pub_b64}".encode())
    parent = caps[-1]

    print(f"\n[B1-ii N={n_hops}] attempting to extend expires to 2099")
    with pytest.raises(AttenuationViolation, match="expir"):
        attenuate(
            parent,
            delegator_private_key=last_delegator_priv,
            delegator_id=last_delegator_id,
            new_holder_id=new_holder_id,
            additional_caveats=[Caveat("expires", "2099-12-31T23:59:59+00:00")],
        )


@pytest.mark.parametrize("n_hops", [2, 3, 5, 10])
def test_b1_attenuate_terminal_cap_rejected(n_hops, capsys):
    """Variant (iii): build a chain whose last cap is terminal
    (no_further_delegation=true), then attempt to attenuate it.
    attenuate() must raise."""
    agents, caps, _ = _build_chain(n_hops)
    # caps[-1] is held by agents[n_hops]; that holder makes a legitimate
    # terminal child for a fresh downstream agent. Then a second hop is
    # attempted on the terminal child — that must fail.
    delegator_priv = agents[n_hops][0]
    delegator_id = agents[n_hops][2]
    downstream_priv, downstream_pub = crypto.generate_keypair()
    downstream_pub_b64 = base64.b64encode(downstream_pub).decode()
    downstream_id = crypto.sha256_digest(f"Ed25519{downstream_pub_b64}".encode())
    parent = caps[-1]

    # Make a terminal cap held by the downstream agent.
    parent_with_terminal = attenuate(
        parent,
        delegator_private_key=delegator_priv,
        delegator_id=delegator_id,
        new_holder_id=downstream_id,
        additional_caveats=[
            Caveat("no_further_delegation", True, terminal=True),
        ],
    )

    # Now attempt to attenuate the terminal cap one hop further.
    # The downstream agent is the holder; they try to re-delegate.
    further_priv, further_pub = crypto.generate_keypair()
    further_pub_b64 = base64.b64encode(further_pub).decode()
    further_id = crypto.sha256_digest(f"Ed25519{further_pub_b64}".encode())

    print(f"\n[B1-iii N={n_hops}] attempting to attenuate a terminal cap")
    with pytest.raises(AttenuationViolation, match="no_further_delegation|terminal"):
        attenuate(
            parent_with_terminal,
            delegator_private_key=downstream_priv,
            delegator_id=downstream_id,
            new_holder_id=further_id,
            additional_caveats=[Caveat("max_invocations", 1)],
        )


@pytest.mark.parametrize("n_hops", [2, 3, 5, 10])
def test_b1_forge_child_with_different_action_rejected(n_hops, capsys):
    """Variant (iv): construct a forged child cap with a DIFFERENT
    action than the parent (bypassing attenuate()'s action-inheritance
    rule). verify_capability must reject the chain."""
    agents, caps, known_keys = _build_chain(n_hops)
    parent = caps[-1]
    # caps[-1] is held by agents[n_hops]; that holder is the delegator
    # for the attack hop. Generate a fresh downstream agent as the new
    # holder of the forged child.
    delegator_priv = agents[n_hops][0]
    delegator_id = agents[n_hops][2]
    downstream_priv, downstream_pub = crypto.generate_keypair()
    downstream_pub_b64 = base64.b64encode(downstream_pub).decode()
    new_holder_id = crypto.sha256_digest(f"Ed25519{downstream_pub_b64}".encode())

    # Build a legitimate child first, then forge by mutating action
    legit_child = attenuate(
        parent,
        delegator_private_key=delegator_priv,
        delegator_id=delegator_id,
        new_holder_id=new_holder_id,
        additional_caveats=[Caveat("max_invocations", 1)],
    )

    # Mutate action then re-sign with the delegator's key (the attacker
    # has the delegator's key in this scenario — they're the rogue
    # delegator).
    forged = copy.deepcopy(legit_child)
    forged.action = "write_doc"  # different from parent's "read_doc"
    sig = crypto.sign(canonical_json(forged.signable_dict()), delegator_priv)
    forged.signature = base64.b64encode(sig).decode("ascii")

    print(f"\n[B1-iv N={n_hops}] forged action='write_doc' (parent='read_doc')")
    # verify_capability against the root issuer's PUBLIC KEY (alice's pubkey).
    # Action mismatch may show up as chain integrity failure since the
    # forged child claims action="write_doc" but the original delegation
    # chain was for "read_doc".
    result = verify_capability(forged, new_holder_id, agents[0][1], known_keys)
    # The result should be invalid — but the specific reason depends on
    # how verify_capability orders its checks. Either it rejects because
    # the child's action doesn't trace back through legitimate
    # attenuation, or it rejects because the chain itself has signature
    # mismatches at intermediate links (signed over the original
    # "read_doc" cap_id).
    assert not result.valid, (
        f"forged action should be rejected; got valid result: {result}"
    )


@pytest.mark.parametrize("n_hops", [2, 3, 5, 10])
def test_b1_forge_child_with_stripped_caveats_rejected(n_hops, capsys):
    """Variant (v): construct a forged child cap with caveats STRIPPED
    (bypassing the append-only rule). The forged child re-signs with
    the delegator's key but presents a permissive caveat list.
    verify_capability must reject — either because the chain link
    signatures don't match the modified cap_id (different content →
    different cap_id), or because the verifier re-derives caveats from
    the chain rather than trusting the child's caveat field."""
    agents, caps, known_keys = _build_chain(n_hops)
    parent = caps[-1]
    delegator_priv = agents[n_hops][0]
    delegator_id = agents[n_hops][2]
    downstream_priv, downstream_pub = crypto.generate_keypair()
    downstream_pub_b64 = base64.b64encode(downstream_pub).decode()
    new_holder_id = crypto.sha256_digest(f"Ed25519{downstream_pub_b64}".encode())

    legit_child = attenuate(
        parent,
        delegator_private_key=delegator_priv,
        delegator_id=delegator_id,
        new_holder_id=new_holder_id,
        additional_caveats=[Caveat("max_invocations", 1)],
    )

    # Strip ALL caveats from the forged child and re-sign
    forged = copy.deepcopy(legit_child)
    forged.caveats = []  # no restrictions claimed
    sig = crypto.sign(canonical_json(forged.signable_dict()), delegator_priv)
    forged.signature = base64.b64encode(sig).decode("ascii")

    print(f"\n[B1-v N={n_hops}] forged with caveats stripped")
    result = verify_capability(forged, new_holder_id, agents[0][1], known_keys)
    # The chain delegation links sign over the parent's cap_id at each
    # hop. Stripping caveats from the child changes the canonical bytes
    # of the child but does NOT change the parent's cap_id — so the
    # chain link sigs may still verify against the delegators' keys.
    # The child's OWN signature (just re-signed by the delegator) also
    # verifies. The remaining question: does verify_capability enforce
    # the append-only property by re-deriving caveats from the chain,
    # or does it trust the child's caveat field?
    #
    # If valid: FINDING — verifier trusts child's caveat field without
    # checking append-only inheritance. Surfaces a real gap.
    # If invalid: append-only is enforced at verification.
    if result.valid:
        print(
            f"[B1-v N={n_hops}] FINDING: caveat-stripping accepted by verify_capability. "
            f"Verifier trusts child.caveats without re-deriving from chain."
        )
    else:
        print(f"[B1-v N={n_hops}] rejected: {result.reason}")

    assert not result.valid, (
        f"forged caveat-stripped child should be rejected; got valid: {result}"
    )
