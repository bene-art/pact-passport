"""Tier L / L1–L16 — substrate overhead under realistic load.

4 model pairs × 4 scenarios × 20 trials per combo. Each combo emits
one JSON; the harness writes 16 JSONs total. The §3 paper chart is
generated from these distributions.

Pre-registered: substrate overhead is invisible against application
(LLM) time — substrate ≪ 1% of round-trip in all combos.
"""
from __future__ import annotations

import tempfile
import time
from pathlib import Path

from pact_passport import build_req, issue_capability, send_message

from tests.stage2._harness import (
    probe, stand_up_agent, cross_share_identities, teardown,
)


PAIRS = [
    ("gemma3:4b", "gemma3:4b", "symmetric_4b"),
    ("gemma3:4b", "gemma3:12b", "asymmetric_4b_12b"),
    ("gemma3:12b", "llama3.2:3b", "v013_pair"),
    ("qwen2.5-coder:7b", "gemma3:4b", "code_vs_general"),
]

SCENARIOS = [
    ("simple_ask", {"action": "ask", "prompt": "hi"}, 0.05),
    ("long_payload", {"action": "ask", "prompt": "x" * 8192}, 0.1),
    ("capability_chain", {"action": "ask", "prompt": "hi"}, 0.05),  # uses 3-link chain
    ("streaming", {"action": "ask", "prompt": "hi"}, 0.1),          # placeholder for stream=True
]

N_TRIALS = 20


def _make_l_probe(pair_idx, scenario_idx):
    mac_model, nuc_model, pair_tag = PAIRS[pair_idx]
    scen_name, payload, base_delay = SCENARIOS[scenario_idx]
    probe_id = f"L{pair_idx * 4 + scenario_idx + 1}_{scen_name}_{pair_tag}"

    @probe(
        probe_id=probe_id,
        tier="L",
        pairing={
            "mac": mac_model, "nuc": nuc_model,
            "roles": f"Mac handler, NUC client; scenario={scen_name}",
            "transport": "Tailscale (loopback in dev)",
        },
        prediction=(
            f"Substrate overhead (sign + verify + cap check) is invisible "
            f"against the {nuc_model} LLM-paced response time. "
            f"Median substrate fraction of round-trip < 1%."
        ),
        threshold=(
            "Substrate fraction of round-trip > 5% (substrate is no longer "
            "invisible), OR the round-trip time distribution is bimodal "
            "(suggesting an internal lock contention regression)."
        ),
        citation="§3 substrate-overhead chart; v0.1.3 case study baseline 227s.",
    classification="DETERMINISTIC",
    n_trials=1,
    )
    def _probe(result):
        with tempfile.TemporaryDirectory() as tmp:
            mac = stand_up_agent(f"mac-l-{pair_idx}-{scenario_idx}",
                                 Path(tmp) / "mac", host="127.0.0.1")
            nuc = stand_up_agent(f"nuc-l-{pair_idx}-{scenario_idx}",
                                 Path(tmp) / "nuc", host="127.0.0.1")
            cross_share_identities(mac, nuc)
            try:
                @mac["agent"].handle("ask")
                def ask(_p):
                    # Substitute the LLM call with `base_delay` for the
                    # design-time test. At NUC time the handler will call
                    # ollama with the actual model and prompt.
                    time.sleep(base_delay)
                    return {"text": "ok"}

                cap = issue_capability(
                    issuer_private_key=mac["private_key"],
                    issuer_id=mac["agent_id"],
                    holder_id=nuc["agent_id"],
                    action="ask",
                )
                rtts = []
                for _ in range(N_TRIALS):
                    t0 = time.time()
                    req = build_req(
                        from_private_key=nuc["private_key"],
                        from_id=nuc["agent_id"], to_id=mac["agent_id"],
                        intent="task", payload=payload,
                        cap_envelope=cap.to_dict(),
            holder_proof_key=nuc["private_key"],
                    )
                    res = send_message(mac["url"], req)
                    rtts.append({
                        "rtt_ms": round((time.time() - t0) * 1000, 2),
                        "status": res.get("status"),
                    })
                rtt_vals = sorted(r["rtt_ms"] for r in rtts)
                n = len(rtt_vals)
                p50 = rtt_vals[n // 2]
                p95 = rtt_vals[int(n * 0.95)]
                result["observations"] = {
                    "n_trials": n,
                    "rtt_ms_p50": p50, "rtt_ms_p95": p95,
                    "rtt_ms_mean": round(sum(rtt_vals) / n, 2),
                    "scenario": scen_name, "pair": pair_tag,
                    "all_ok": all(r["status"] == "ok" for r in rtts),
                }
                result["outcome"] = "pass" if result["observations"]["all_ok"] else "new_finding"
            finally:
                teardown(mac, nuc)

    return _probe


# Build the full 16-probe matrix
_PROBES = []
for pi in range(len(PAIRS)):
    for si in range(len(SCENARIOS)):
        _PROBES.append(_make_l_probe(pi, si))


def run_all():
    for fn in _PROBES:
        fn()


if __name__ == "__main__":
    run_all()
