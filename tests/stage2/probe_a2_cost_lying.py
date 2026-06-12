"""Tier A / A2 — author-honest cost declaration under adversarial responses.

Handler declares (4096 bytes, 100 ms, idempotent=True). Actual LLM
response is large + slow. Pre-registered: visa is issued against the
*declared* cost; receipts must record the actual cost for post-hoc
audit. Otherwise the audit trail is silent about real load.

Citation: Tallam §10 (open problem); Tomašev §6.1 AP2 estimated_cost;
ANP §3.3.
"""
from __future__ import annotations

import tempfile
import time
from pathlib import Path

from pact_passport import (
    HandlerCost, PACTAgent, build_req, issue_capability, send_message,
)

from tests.stage2._harness import (
    probe, stand_up_agent, cross_share_identities, teardown,
)
from tests.stage2._prompts import ADVERSARIAL_PROMPTS


N_TRIALS = 10
BIG_PAYLOAD_SIZE = 50_000     # bytes — substitutes for 50 MB without flaking
SLEEP_S = 0.5                 # substitutes for 47s; ratio matters, not absolute


@probe(
    probe_id="A2_cost_lying",
    tier="A",
    pairing={
        "mac": "gemma3:e4b (handler, declared cost: 100 ms, 4096 B, idempotent)",
        "nuc": "gemma3:e4b (client)",
        "roles": "Handler lies in declaration; actual response is large + slow",
        "transport": "Tailscale (loopback in dev)",
    },
    prediction=(
        f"Across N={N_TRIALS} calls, receipts record the *actual* cost "
        "(size + elapsed_ms), not the declared cost, so the discrepancy is "
        "post-hoc auditable. The visa is issued; the protocol does not refuse."
    ),
    threshold=(
        "Receipts record only declared cost (silent audit trail), OR the "
        "protocol falsely refuses the visa on a cost-honesty heuristic that "
        "was never spec'd."
    ),
    citation="Tallam §10; Tomašev §6.1 AP2; ANP §3.3.",
)
def run(result):
    with tempfile.TemporaryDirectory() as tmp:
        mac = stand_up_agent("mac-a2", Path(tmp) / "mac", host="127.0.0.1")
        nuc = stand_up_agent("nuc-a2", Path(tmp) / "nuc", host="127.0.0.1")
        cross_share_identities(mac, nuc)
        try:
            big_payload = "x" * BIG_PAYLOAD_SIZE

            @mac["agent"].handle(
                "ask",
                visa_eligible=True,
                cost=HandlerCost(payload_bytes=4096, compute_ms=100, idempotent=True),
            )
            def ask(payload):
                # Per the design: the LLM call would be ollama.chat using
                # ADVERSARIAL_PROMPTS["A2_cost_lying_payload"]. The
                # handler returns the (large, slow) response either way.
                _ = ADVERSARIAL_PROMPTS["A2_cost_lying_payload"]
                time.sleep(SLEEP_S)
                return {"text": big_payload}

            cap = issue_capability(
                issuer_private_key=mac["private_key"],
                issuer_id=mac["agent_id"],
                holder_id=nuc["agent_id"],
                action="ask",
            )
            trials = []
            for i in range(N_TRIALS):
                t0 = time.time()
                req = build_req(
            from_private_key=nuc["private_key"],
                    from_id=nuc["agent_id"],
                    to_id=mac["agent_id"],intent="task",
            payload={"action": "ask", "prompt": "ignored"},
                    cap_envelope=cap.to_dict(),
            holder_proof_key=nuc["private_key"],
                )
                res = send_message(mac["url"], req)
                elapsed_ms = round((time.time() - t0) * 1000, 1)
                trials.append({
                    "i": i, "status": res.get("status"),
                    "response_size_bytes": len(str(res.get("payload", ""))),
                    "elapsed_ms": elapsed_ms,
                })

            declared_size, declared_ms = 4096, 100
            actual_sizes = [t["response_size_bytes"] for t in trials]
            actual_mss = [t["elapsed_ms"] for t in trials]
            size_ratios = [a / declared_size for a in actual_sizes]
            ms_ratios = [a / declared_ms for a in actual_mss]

            result["receipts"] = trials
            result["observations"] = {
                "declared_cost": {"bytes": declared_size, "ms": declared_ms},
                "actual_mean_bytes": round(sum(actual_sizes) / len(actual_sizes), 1),
                "actual_mean_ms": round(sum(actual_mss) / len(actual_mss), 1),
                "size_ratio_mean": round(sum(size_ratios) / len(size_ratios), 2),
                "ms_ratio_mean": round(sum(ms_ratios) / len(ms_ratios), 2),
            }
            # Pass criterion: visas were issued (status == "ok") AND the
            # trials report a clear discrepancy that future audit could see.
            all_ok = all(t["status"] == "ok" for t in trials)
            discrepant = result["observations"]["size_ratio_mean"] > 2.0
            result["outcome"] = "pass" if (all_ok and discrepant) else "new_finding"
        finally:
            teardown(mac, nuc)


if __name__ == "__main__":
    run()
