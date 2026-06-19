"""Tier S / S1 — LLM emits malformed JSON.

Handler dispatches the adversarial prompt to Ollama and returns whatever
text the model emits. PACT signs that text opaquely. Receiver's
verify_message checks signature, not payload content. No protocol fault.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from pact_passport import build_req, issue_capability, send_message

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

# Ben 2026-06-17: gemma3:e4b never existed in the Ollama registry; the
# active local-first e4b model is gemma4:e4b. S7's 4-model sweep covers
# capability variance; S1 pins one model for the substrate-invariance claim.
MODEL = os.environ.get("STAGE2_LLM_MODEL", "gemma4:e4b")


@probe(
    probe_id="S1_malformed_json",
    tier="S",
    pairing={
        "mac": f"{MODEL} (handler dispatches adversarial prompt to Ollama)",
        "nuc": f"{MODEL} (client)",
        "roles": "Mac handler calls ollama_chat; output flows into the response payload",
        "transport": "Tailscale (loopback in dev)",
    },
    prediction=(
        "PACT signs whatever bytes the LLM emits, opaquely. Receiver "
        "verify_message checks signature, not payload content. No protocol fault."
    ),
    threshold=(
        "PACT crashes in build_res, OR verify_message rejects on payload "
        "content, OR receiver emits protocol_error for payload-content."
    ),
    citation="Tomašev §4.9 Verification Subversion; SoK §3.1.",
    classification="STOCHASTIC",
    n_trials=30,
)
def run(result):
    with tempfile.TemporaryDirectory() as tmp:
        mac = stand_up_agent("mac-s1", Path(tmp) / "mac", host="127.0.0.1")
        nuc = stand_up_agent("nuc-s1", Path(tmp) / "nuc", host="127.0.0.1")
        cross_share_identities(mac, nuc)
        try:
            adversarial_text = ADVERSARIAL_PROMPTS["S1_malformed"]
            trial_index = result["trial_index"]
            result["model_digests"][MODEL] = resolve_model_digest(MODEL)

            @mac["agent"].handle("ask")
            def ask(_p):
                out = ollama_chat(
                    MODEL,
                    adversarial_text,
                    seed=trial_index,
                    temperature=0.7,
                    num_predict=64,
                    think=False,  # gemma4:e4b reasoning-budget swallow guard
                )
                record_llm_call(
                    result,
                    model=MODEL,
                    seed=trial_index,
                    temperature=0.7,
                    num_predict=64,
                )
                return {"text": out["text"]}

            cap = issue_capability(
                issuer_private_key=mac["private_key"], issuer_id=mac["agent_id"],
                holder_id=nuc["agent_id"], action="ask",
            )
            req = build_req(
                from_private_key=nuc["private_key"], from_id=nuc["agent_id"],
                to_id=mac["agent_id"], intent="task",
                payload={"action": "ask", "prompt": adversarial_text},
                cap_envelope=cap.to_dict(),
                holder_proof_key=nuc["private_key"],
            )
            res = send_message(mac["url"], req)

            result["receipts"] = [res]
            result["observations"] = {
                "response_status": res.get("status"),
                "has_protocol_fault": "fault" in res,
                "payload_byte_len": len(str(res.get("payload", ""))),
                "llm_emitted_text_len": len(str((res.get("payload") or {}).get("text", ""))),
            }
            ok = res.get("status") == "ok" and "fault" not in res
            result["outcome"] = "pass" if ok else "new_finding"
        finally:
            teardown(mac, nuc)


if __name__ == "__main__":
    run()
