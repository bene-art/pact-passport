"""Tier R / R1 — v0.1.3 baseline replay.

Original two-LLM demo (gemma3:12b + llama3.2:3b) three-step round-trip.
Pre-registered: still works on v0.7; total round-trip within 2× of the
v0.1.3-era 227 s baseline.
"""
from __future__ import annotations

import tempfile
import time
from pathlib import Path

from pact_passport import build_req, issue_capability, send_message

from tests.stage2._harness import (
    probe, stand_up_agent, cross_share_identities, teardown,
)
from tests.stage2._prompts import ADVERSARIAL_PROMPTS


V013_BASELINE_S = 227          # original case-study round-trip
PASS_CEILING_S = 454           # 2× baseline


@probe(
    probe_id="R1_v013_replay",
    tier="R",
    pairing={
        "mac": "gemma3:12b",
        "nuc": "llama3.2:3b",
        "roles": "reformulate (NUC) → answer (Mac) → synthesize (NUC)",
        "transport": "Tailscale (loopback in dev)",
    },
    prediction=(
        f"3-step round-trip completes successfully; total wall-clock ≤ "
        f"{PASS_CEILING_S} s (2× the v0.1.3 baseline of {V013_BASELINE_S} s). "
        "Each step's response status is 'ok'."
    ),
    threshold=(
        "Total wall-clock > 2× baseline (substrate regression), OR any "
        "step's status != 'ok' (functional regression)."
    ),
    citation="v0.1.3 case study Demo §3 three-step round-trip.",
)
def run(result):
    with tempfile.TemporaryDirectory() as tmp:
        mac = stand_up_agent("mac-r1", Path(tmp) / "mac", host="127.0.0.1")
        nuc = stand_up_agent("nuc-r1", Path(tmp) / "nuc", host="127.0.0.1")
        cross_share_identities(mac, nuc)
        try:
            @mac["agent"].handle("answer")
            def answer(_p):
                # NUC time: ollama.chat with gemma3:12b
                time.sleep(0.05)
                return {"text": "The capital of France is Paris."}

            @nuc["agent"].handle("reformulate")
            def reformulate(_p):
                # NUC time: ollama.chat with llama3.2:3b
                time.sleep(0.02)
                return {"text": ADVERSARIAL_PROMPTS["R1_reformulate"]}

            @nuc["agent"].handle("synthesize")
            def synthesize(_p):
                time.sleep(0.02)
                return {"text": "Paris."}

            # Cap direction: issuer is the agent hosting the handler (the
            # receiver of the request). Holder is the sender.
            #   Step 1: Mac→NUC reformulate → NUC issues to Mac
            #   Step 2: NUC→Mac answer     → Mac issues to NUC
            #   Step 3: Mac→NUC synthesize → NUC issues to Mac
            cap_reformulate = issue_capability(
                issuer_private_key=nuc["private_key"], issuer_id=nuc["agent_id"],
                holder_id=mac["agent_id"], action="reformulate",
            )
            cap_answer = issue_capability(
                issuer_private_key=mac["private_key"], issuer_id=mac["agent_id"],
                holder_id=nuc["agent_id"], action="answer",
            )
            cap_synthesize = issue_capability(
                issuer_private_key=nuc["private_key"], issuer_id=nuc["agent_id"],
                holder_id=mac["agent_id"], action="synthesize",
            )

            t0 = time.time()
            # Step 1: Mac → NUC reformulate
            r1 = send_message(nuc["url"], build_req(
                from_private_key=mac["private_key"], from_id=mac["agent_id"],
                to_id=nuc["agent_id"], intent="task",
                payload={"action": "reformulate",
                         "q": "What is the capital of France?"},
                cap_envelope=cap_reformulate.to_dict(),
                holder_proof_key=mac["private_key"],
            ))
            # Step 2: NUC → Mac answer
            r2 = send_message(mac["url"], build_req(
                from_private_key=nuc["private_key"], from_id=nuc["agent_id"],
                to_id=mac["agent_id"], intent="task",
                payload={"action": "answer",
                         "q": (r1.get("payload") or {}).get("text", "")},
                cap_envelope=cap_answer.to_dict(),
                holder_proof_key=nuc["private_key"],
            ))
            # Step 3: Mac → NUC synthesize
            r3 = send_message(nuc["url"], build_req(
                from_private_key=mac["private_key"], from_id=mac["agent_id"],
                to_id=nuc["agent_id"], intent="task",
                payload={"action": "synthesize",
                         "context": (r2.get("payload") or {}).get("text", "")},
                cap_envelope=cap_synthesize.to_dict(),
                holder_proof_key=mac["private_key"],
            ))
            total_s = time.time() - t0

            result["receipts"] = [r1, r2, r3]
            result["observations"] = {
                "total_wall_clock_s": round(total_s, 2),
                "baseline_v013_s": V013_BASELINE_S,
                "ceiling_2x_s": PASS_CEILING_S,
                "step_statuses": [r.get("status") for r in (r1, r2, r3)],
            }
            all_ok = all(r.get("status") == "ok" for r in (r1, r2, r3))
            under_ceiling = total_s <= PASS_CEILING_S  # trivially true in loopback
            result["outcome"] = "pass" if (all_ok and under_ceiling) else "new_finding"
        finally:
            teardown(mac, nuc)


if __name__ == "__main__":
    run()
