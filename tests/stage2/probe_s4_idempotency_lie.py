"""Tier S / S4 — LLM lies about idempotency.

Handler declares idempotent=True but the LLM is non-deterministic
(returns a random hex string per call). PACT cannot detect this;
the idempotency cache caches the FIRST response. Pre-registered:
PACT honors the declaration; cached responses returned for the
same idempotency_key.
"""
from __future__ import annotations

import os
import secrets
import tempfile
from pathlib import Path

from pact_passport import HandlerCost, build_req, issue_capability, send_message

from tests.stage2._harness import (
    cross_share_identities,
    ollama_chat,
    probe,
    record_llm_call,
    resolve_model_digest,
    stand_up_agent,
    teardown,
)
from tests.stage2._prompts import ADVERSARIAL_PROMPTS

MODEL = os.environ.get("STAGE2_LLM_MODEL", "gemma4:e4b")


@probe(
    probe_id="S4_idempotency_lie",
    tier="S",
    pairing={
        "mac": f"{MODEL} (handler, declared idempotent=True; LLM returns variable text)",
        "nuc": f"{MODEL} (client; reuses idempotency_key)",
        "roles": "Handler lies; protocol honors declaration and caches first response",
        "transport": "Tailscale (loopback in dev)",
    },
    prediction=(
        "PACT's idempotency cache returns the FIRST response for subsequent "
        "calls sharing the idempotency_key. The application sees a "
        "deterministic-looking sequence despite the LLM being non-deterministic "
        "across-trial. The cost-honesty footnote (§14.5) applies: cost-of-trust "
        "is the developer's, not the protocol's."
    ),
    threshold=(
        "Receiver re-invokes the handler for the same idempotency_key OR "
        "rejects subsequent calls on a heuristic that wasn't spec'd."
    ),
    citation="Spec §14.5 cost-honesty; idempotency cache (Bug 1 fix).",
    classification="STOCHASTIC",
    n_trials=30,
)
def run(result):
    with tempfile.TemporaryDirectory() as tmp:
        mac = stand_up_agent("mac-s4", Path(tmp) / "mac", host="127.0.0.1")
        nuc = stand_up_agent("nuc-s4", Path(tmp) / "nuc", host="127.0.0.1")
        cross_share_identities(mac, nuc)
        try:
            trial_index = result["trial_index"]
            result["model_digests"][MODEL] = resolve_model_digest(MODEL)
            adversarial = ADVERSARIAL_PROMPTS["S4_idempotency_lie"]
            call_count = []

            @mac["agent"].handle("rand", cost=HandlerCost(
                payload_bytes=64, compute_ms=50, idempotent=True))
            def rand_handler(_p):
                call_count.append(1)
                out = ollama_chat(
                    MODEL, adversarial,
                    seed=trial_index, temperature=0.7, num_predict=32, think=False,
                )
                record_llm_call(
                    result, model=MODEL,
                    seed=trial_index, temperature=0.7, num_predict=32,
                )
                hex_emitted = out["text"].strip()[:32] or secrets.token_hex(16)
                return {"hex": hex_emitted}

            cap = issue_capability(
                issuer_private_key=mac["private_key"], issuer_id=mac["agent_id"],
                holder_id=nuc["agent_id"], action="rand",
            )
            req1 = build_req(
                from_private_key=nuc["private_key"], from_id=nuc["agent_id"],
                to_id=mac["agent_id"], intent="task",
                payload={"action": "rand"}, cap_envelope=cap.to_dict(),
                holder_proof_key=nuc["private_key"],
            )
            shared_key = req1.idempotency_key
            req2 = build_req(
                from_private_key=nuc["private_key"], from_id=nuc["agent_id"],
                to_id=mac["agent_id"], intent="task",
                payload={"action": "rand"}, cap_envelope=cap.to_dict(),
                holder_proof_key=nuc["private_key"],
            )
            req2.idempotency_key = shared_key
            req3 = build_req(
                from_private_key=nuc["private_key"], from_id=nuc["agent_id"],
                to_id=mac["agent_id"], intent="task",
                payload={"action": "rand"}, cap_envelope=cap.to_dict(),
                holder_proof_key=nuc["private_key"],
            )
            req3.idempotency_key = shared_key

            r1 = send_message(mac["url"], req1)
            r2 = send_message(mac["url"], req2)
            r3 = send_message(mac["url"], req3)
            hex1 = (r1.get("payload") or {}).get("hex")
            hex2 = (r2.get("payload") or {}).get("hex")
            hex3 = (r3.get("payload") or {}).get("hex")

            result["receipts"] = [r1, r2, r3]
            result["observations"] = {
                "handler_invocations": len(call_count),
                "hex1": hex1, "hex2": hex2, "hex3": hex3,
                "all_three_match": hex1 == hex2 == hex3,
            }
            result["outcome"] = "pass" if (
                len(call_count) == 1 and hex1 == hex2 == hex3
            ) else "new_finding"
        finally:
            teardown(mac, nuc)


if __name__ == "__main__":
    run()
