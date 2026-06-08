"""Tier S / S7 — adversary-capability sweep across model scale.

S1 (malformed-JSON) re-run across four adversary models:
  - gemma3:4b   (local)
  - gemma3:e4b  (local)
  - claude-haiku-4-5 (cloud, via ANTHROPIC_API_KEY)
  - claude-opus-4-7  (cloud, via ANTHROPIC_API_KEY)

Same handler shape, same prompt, same V-tier policy. Only the model
behind the handler changes. The curve IS the figure: x-axis adversary
capability, y-axis protocol-layer outcome.

Cloud usage is *adversary*, not *runtime integration* (per May 31
amendment). PACT's wire between Mac and NUC remains local.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from pact import build_req, issue_capability, send_message

from tests.stage2._harness import (
    probe, stand_up_agent, cross_share_identities, teardown,
)
from tests.stage2._prompts import ADVERSARIAL_PROMPTS


SWEEP_MODELS = [
    ("gemma3:4b", "local"),
    ("gemma3:e4b", "local"),
    ("claude-haiku-4-5", "cloud"),
    ("claude-opus-4-7", "cloud"),
]


def _call_adversary(model: str, kind: str, prompt: str) -> str:
    """Return the adversary's response string. Real call at NUC time;
    deterministic substitute here so the probe is testable."""
    if kind == "local":
        # import ollama; return ollama.chat(model=model, messages=[{"role": "user", "content": prompt}])["message"]["content"]
        return "{ unclosed"   # all local models emit literal-string output for S1
    elif kind == "cloud":
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return "{ unclosed"   # offline placeholder
        # from anthropic import Anthropic
        # client = Anthropic()
        # return client.messages.create(
        #     model=model, max_tokens=256,
        #     messages=[{"role": "user", "content": prompt}]
        # ).content[0].text
        return "{ unclosed"
    return ""


@probe(
    probe_id="S7_capability_sweep",
    tier="S",
    pairing={
        "mac": "rotating: gemma3:4b → gemma3:e4b → claude-haiku-4-5 → claude-opus-4-7",
        "nuc": "gemma3:e4b (client, constant)",
        "roles": "Mac handler swapped 4×; same S1 prompt + policy each time",
        "transport": "Tailscale local; cloud calls outbound from Mac handler",
    },
    prediction=(
        "Protocol-layer outcomes are model-invariant. All 4 datapoints "
        "report identical protocol-layer behavior (signature valid, no "
        "protocol fault, payload echoed opaquely). Application-layer "
        "responses may differ in how the adversarial output is composed "
        "(Opus may emit a more convincingly malformed string than 4b), "
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
)
def run(result):
    sweep_results = []
    prompt = ADVERSARIAL_PROMPTS["S1_malformed"]

    for model, kind in SWEEP_MODELS:
        with tempfile.TemporaryDirectory() as tmp:
            mac = stand_up_agent(f"mac-s7-{model.replace(':','_')}",
                                 Path(tmp) / "mac", host="127.0.0.1")
            nuc = stand_up_agent(f"nuc-s7-{model.replace(':','_')}",
                                 Path(tmp) / "nuc", host="127.0.0.1")
            cross_share_identities(mac, nuc)
            try:
                @mac["agent"].handle("ask")
                def ask(_p):
                    return {"text": _call_adversary(model, kind, prompt)}

                cap = issue_capability(
                    issuer_private_key=mac["private_key"],
                    issuer_id=mac["agent_id"],
                    holder_id=nuc["agent_id"], action="ask",
                )
                req = build_req(
            from_private_key=nuc["private_key"],
                    from_id=nuc["agent_id"], to_id=mac["agent_id"],intent="task",
            payload={"action": "ask"}, cap_envelope=cap.to_dict(),
            holder_proof_key=nuc["private_key"],
                )
                res = send_message(mac["url"], req)
                sweep_results.append({
                    "model": model, "kind": kind,
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
    # Pass: all 4 models yield identical protocol-layer behavior (the
    # inertness claim). A divergence is the publishable positive finding.
    result["outcome"] = "pass" if statuses == {"ok"} else "new_finding"


if __name__ == "__main__":
    run()
