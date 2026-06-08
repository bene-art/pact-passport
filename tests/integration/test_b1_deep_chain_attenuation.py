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


# ---------------------------------------------------------------------------
# Rogue-delegator forgery — unmasked by the Bug 6 fix (2026-06-08).
#
# Both tests below previously passed *vacuously*. Pre-v0.6, the chain-link
# verifier checked every link against ``token.parent`` (final cap's parent),
# so any chain with >= 2 links was structurally rejected — masking the fact
# that the verifier doesn't re-derive ``action`` or caveats from the chain.
# With Bug 6 closed (commit `b9bcb3e + 6ab733e + this commit`), the rogue
# delegator's forgeries now pass chain verification but expose a deeper
# gap: the verifier trusts ``child.action`` and ``child.caveats`` rather
# than reconstructing them from the legitimate chain.
#
# Filed as Bug 9 (PACT v0.7 issue): verifier must re-derive action and
# caveats from the delegation chain at verification time, not trust the
# child's fields. Threat model: a compromised intermediate delegator's
# private key can mint wider children. Bug class: trust-the-child-field
# at a layer boundary (sibling to Bug 6's convenient-value substitution).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("n_hops", [2, 3, 5, 10])
def test_b1_finding_rogue_delegator_forges_action(n_hops, capsys):
    """FINDING (Bug 9, surfaced 2026-06-08 by the Bug 6 fix):

    A rogue intermediate delegator (with their legitimate private key)
    can mint a child cap with a DIFFERENT action than the legitimate
    chain authorizes. The verifier accepts it because it trusts the
    child's ``action`` field rather than re-deriving it from the chain.

    Pre-fix: this attack was masked by Bug 6 — chain-link verification
    against ``token.parent`` rejected all chains with >= 2 links, so
    the forged action never had a chance to be inspected.

    Post-fix: chain links verify correctly, the delegator's outer
    signature on the forged token is valid (they have the key), and
    the verifier accepts the cap with a forged action. v0.7 fix path:
    walk the chain, re-derive the legitimate action, reject mismatches.
    """
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

    forged = copy.deepcopy(legit_child)
    forged.action = "write_doc"  # different from parent's "read_doc"
    sig = crypto.sign(canonical_json(forged.signable_dict()), delegator_priv)
    forged.signature = base64.b64encode(sig).decode("ascii")

    result = verify_capability(forged, new_holder_id, agents[0][1], known_keys)
    print(
        f"\n[B1-iv N={n_hops}] FINDING (Bug 9): forged action='write_doc' "
        f"accepted: valid={result.valid}"
    )
    # This documents the empirical state. v0.7 must fail-close on this.
    assert result.valid, (
        f"unexpected: rogue-delegator action forgery rejected at K={n_hops}. "
        f"If Bug 9 has been fixed in v0.7, invert this assertion."
    )


@pytest.mark.parametrize("n_hops", [2, 3, 5, 10])
def test_b1_finding_rogue_delegator_strips_caveats(n_hops, capsys):
    """FINDING (Bug 9, surfaced 2026-06-08 by the Bug 6 fix):

    A rogue intermediate delegator (with their legitimate private key)
    can mint a child cap with ALL caveats stripped, bypassing the
    append-only rule. The verifier accepts it because it trusts the
    child's ``caveats`` field rather than re-deriving the legitimate
    caveat set from the chain.

    Pre-fix: masked by Bug 6 (multi-link chains rejected vacuously).
    Post-fix: chain links verify; delegator's outer signature on the
    forged token is valid; verifier accepts the wider cap. v0.7 fix
    path: walk the chain, accumulate caveats, reject any child whose
    declared caveats are not a subset of the accumulated set.
    """
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

    forged = copy.deepcopy(legit_child)
    forged.caveats = []  # all parent caveats stripped
    sig = crypto.sign(canonical_json(forged.signable_dict()), delegator_priv)
    forged.signature = base64.b64encode(sig).decode("ascii")

    result = verify_capability(forged, new_holder_id, agents[0][1], known_keys)
    print(
        f"\n[B1-v N={n_hops}] FINDING (Bug 9): caveat-stripped forge "
        f"accepted: valid={result.valid}"
    )
    # This documents the empirical state. v0.7 must fail-close on this.
    assert result.valid, (
        f"unexpected: rogue-delegator caveat-stripping rejected at K={n_hops}. "
        f"If Bug 9 has been fixed in v0.7, invert this assertion."
    )
