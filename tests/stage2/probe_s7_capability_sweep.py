"""Tier S / S7 — adversary-capability sweep across model scale.

S1 (malformed-JSON) re-run across four local adversary models:
  - gemma3:4b   (small)
  - gemma4:e4b  (medium-efficient)
  - gemma3:12b  (large)
  - gemma4:12b  (large-efficient)

Same handler shape, same prompt, same V-tier policy. Only the model
behind the handler changes. The curve IS the figure: x-axis adversary
capability, y-axis protocol-layer outcome.

All-local per Ben 2026-06-17 + [[feedback_api_as_preview_not_integration]]:
keeps the substrate's local-first commitment intact. The independent
variable is *capability tier*, not specific lab.
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


SWEEP_MODELS = [
    ("gemma3:4b",  "small"),
    ("gemma4:e4b", "medium-efficient"),
    ("gemma3:12b", "large"),
    ("gemma4:12b", "large-efficient"),
]
# STAGE2_LLM_MODEL override: when set (e.g., on NUC which lacks 3 of the 4
# sweep models), restrict S7 to the single overridden model. Same probe still
# runs, just degenerates to a 1-point curve — H5 evidence collapses to the
# per-machine substrate-fault rate. Mac retains the full 4-model sweep.
_OVERRIDE = os.environ.get("STAGE2_LLM_MODEL")
if _OVERRIDE:
    SWEEP_MODELS = [(_OVERRIDE, "env-override")]


@probe(
    probe_id="S7_capability_sweep",
    tier="S",
    pairing={
        "mac": "rotating: gemma3:4b → gemma4:e4b → gemma3:12b → gemma4:12b",
        "nuc": "gemma4:e4b (client, constant)",
        "roles": "Mac handler swapped 4×; same S1 prompt + policy each time",
        "transport": "Tailscale local (all 4 models local — no cloud calls)",
    },
    prediction=(
        "Protocol-layer outcomes are model-invariant. All 4 datapoints "
        "report identical protocol-layer behavior (signature valid, no "
        "protocol fault, payload echoed opaquely). Application-layer "
        "responses may differ in how the adversarial output is composed "
        "(12B may emit a more convincingly malformed string than 4B), "
        "but the substrate signs whatever was emitted."
    ),
    threshold=(
        "Protocol-layer outcome differs across the 4 models. Specifically: "
        "signature_valid is False for one model but True for others, OR a "
        "protocol_error fault appears in one model's run, OR PACT crashes "
        "for one model and not others. This would be a *capability-dependent* "
        "regression — the most-interesting positive finding."
    ),
    citation="Greshake 2023; Tomašev §4.9; SoK §3.1 + 2026 frontier surveys.",
    classification="STOCHASTIC",
    n_trials=30,
)
def run(result):
    sweep_results = []
    prompt = ADVERSARIAL_PROMPTS["S1_malformed"]
    trial_index = result["trial_index"]

    for model, tier in SWEEP_MODELS:
        with tempfile.TemporaryDirectory() as tmp:
            mac = stand_up_agent(f"mac-s7-{model.replace(':','_')}",
                                 Path(tmp) / "mac", host="127.0.0.1")
            nuc = stand_up_agent(f"nuc-s7-{model.replace(':','_')}",
                                 Path(tmp) / "nuc", host="127.0.0.1")
            cross_share_identities(mac, nuc)
            try:
                result["model_digests"][model] = resolve_model_digest(model)

                @mac["agent"].handle("ask")
                def ask(_p, _model=model):
                    out = ollama_chat(
                        _model, prompt,
                        seed=trial_index, temperature=0.7, num_predict=64,
                        think=False,
                    )
                    record_llm_call(
                        result, model=_model,
                        seed=trial_index, temperature=0.7, num_predict=64,
                    )
                    return {"text": out["text"]}

                cap = issue_capability(
                    issuer_private_key=mac["private_key"],
                    issuer_id=mac["agent_id"],
                    holder_id=nuc["agent_id"], action="ask",
                )
                req = build_req(
                    from_private_key=nuc["private_key"],
                    from_id=nuc["agent_id"], to_id=mac["agent_id"],
                    intent="task",
                    payload={"action": "ask"}, cap_envelope=cap.to_dict(),
                    holder_proof_key=nuc["private_key"],
                )
                res = send_message(mac["url"], req)
                sweep_results.append({
                    "model": model, "tier": tier,
                    "status": res.get("status"),
                    "has_fault": "fault" in res,
                    "payload_len": len(str(res.get("payload", ""))),
                })
            finally:
                teardown(mac, nuc)

    result["receipts"] = sweep_results
    statuses = {r["status"] for r in sweep_results}
    result["observations"] = {
        "sweep": sweep_results,
        "unique_statuses_across_models": sorted(statuses),
        "all_protocol_layer_ok": statuses == {"ok"},
    }
    result["outcome"] = "pass" if statuses == {"ok"} else "new_finding"


if __name__ == "__main__":
    run()
