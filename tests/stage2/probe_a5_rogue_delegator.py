"""Tier A / A5 — rogue-delegator with stale peer cache (Bug 5 × Bug 9).

Three-agent chain: Alice (Mac) → Bob (NUC, key "compromised") →
Carol (loopback on Mac). Bob constructs a forged child cap with
mutated action. Carol presents it to Alice; Alice's peer cache for
Bob is wiped (rm -rf ~/.pact/peers/) so Alice's verifier must
fail-close on the missing key.

Pre-registered: Bug 5 fix fires first (missing-key fail-close);
Bug 9 fix (chain re-derivation action-preservation) is the second-
layer defense for chains where keys ARE present.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from pact import attenuate, issue_capability, verify_capability

from tests.stage2._harness import (
    probe, stand_up_agent, teardown,
)


@probe(
    probe_id="A5_rogue_delegator",
    tier="A",
    pairing={
        "mac": "Alice + Carol (gemma3:e4b each, loopback)",
        "nuc": "Bob (gemma3:e4b, simulated 'compromised' key)",
        "roles": "Bob attenuates a cap to Carol with mutated action; Alice's peer cache for Bob is empty",
        "transport": "Tailscale + loopback (Carol loopback on Mac)",
    },
    prediction=(
        "v0.2.0 Bug 5 fix: verifier fail-closes on missing keys. Alice's "
        "verifier sees Bob in the chain, can't find Bob's pubkey in "
        "known_keys, returns 'Cannot verify chain link: missing key for "
        "sha256:...'. Bug 9's chain re-derivation is not even reached — "
        "the missing-key check fires first."
    ),
    threshold=(
        "Verifier silently passes the forged cap without Bob's key. "
        "Bug 5 regression with implications for Bug 9 (chain re-derivation "
        "can't fire without keys)."
    ),
    citation="Bug 5 (v0.2.0); Bug 9 (v0.7); Macaroons §III chain.",
)
def run(result):
    with tempfile.TemporaryDirectory() as tmp:
        alice = stand_up_agent("alice-a5", Path(tmp) / "alice", host="127.0.0.1")
        bob = stand_up_agent("bob-a5", Path(tmp) / "bob", host="127.0.0.1")
        carol = stand_up_agent("carol-a5", Path(tmp) / "carol", host="127.0.0.1")
        # Pre-share Alice<->Carol; deliberately DO NOT share Bob with Alice
        # (Alice's peer cache for Bob is "stale/empty" by design).
        alice["agent"]._store.save_peer(
            carol["agent_id"], carol["identity"].to_identity_document()
        )
        carol["agent"]._store.save_peer(
            alice["agent_id"], alice["identity"].to_identity_document()
        )
        try:
            # Step 1: Alice issues root cap to Bob
            root_cap = issue_capability(
                issuer_private_key=alice["private_key"],
                issuer_id=alice["agent_id"],
                holder_id=bob["agent_id"],
                action="ask",
            )
            # Step 2: Bob attenuates and mutates the action to Carol
            child_cap = attenuate(
                root_cap,
                bob["private_key"],
                bob["agent_id"],
                carol["agent_id"],
                [],
            )
            # Force action mutation (Bob is "rogue")
            child_cap.action = "admin"

            # Step 3: Alice's verifier evaluates the chain with Bob MISSING
            # from known_keys.
            known_keys = {
                alice["agent_id"]: alice["public_key"],
                # bob deliberately omitted
                carol["agent_id"]: carol["public_key"],
            }
            verdict = verify_capability(
                child_cap,
                carol["agent_id"],
                alice["public_key"],
                known_keys=known_keys,
            )

            result["observations"] = {
                "verdict_ok": getattr(verdict, "ok", None),
                "verdict_reason": getattr(verdict, "reason", None),
                "missing_key_for_bob": bob["agent_id"] not in known_keys,
            }
            # Pass criterion: verdict.ok == False AND reason mentions
            # missing key. Bug 5's fail-closed behavior.
            ok = getattr(verdict, "ok", True)
            reason = (getattr(verdict, "reason", "") or "").lower()
            fail_closed_correctly = (not ok) and ("missing" in reason or "key" in reason)
            result["outcome"] = "pass" if fail_closed_correctly else "new_finding"
        finally:
            teardown(alice, bob, carol)


if __name__ == "__main__":
    run()
