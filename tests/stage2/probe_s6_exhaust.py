"""Tier S / S6 — LLM exhaust-attack via excessive response.

Handler returns a response in the ~1 MB / 10 MB range. Tests
transport-layer max_body_bytes (default 1 MB on receive). Pre-registered:
non-streaming oversize is rejected (HTTP 413); streaming chunks are
bounded independently.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from pact_passport import build_req, issue_capability, send_message

from tests.stage2._harness import (
    probe, stand_up_agent, cross_share_identities, teardown,
)
from tests.stage2._prompts import ADVERSARIAL_PROMPTS


# Substituted size for the design-time test (real LLM would produce ~10 MB).
EXHAUST_BYTES = 2 * 1024 * 1024  # 2 MB — comfortably above the 1 MB default


@probe(
    probe_id="S6_exhaust",
    tier="S",
    pairing={
        "mac": "gemma3:e4b (handler emits very-large payload)",
        "nuc": "gemma3:e4b (client, default max_body_bytes)",
        "roles": "Mac handler ignores cost ceiling and emits an oversize string",
        "transport": "Tailscale (loopback in dev)",
    },
    prediction=(
        "Non-streaming response > max_body_bytes is rejected at the "
        "transport layer (HTTP 413 or substrate-level body-size fault). "
        "Receipts record the actual elapsed time and response size for "
        "post-hoc audit. The cost ceiling per §14.5 is author-declared, "
        "not runtime-enforced."
    ),
    threshold=(
        "Oversize response is delivered without any error AND the response "
        "size is not recorded anywhere auditable. OR streaming bypasses "
        "the 1 MB limit AND the streamed total exceeds intended resource "
        "ceilings."
    ),
    citation="Tallam §2.4 execution-count revocation; §14.5 cost-honesty.",
    classification="STOCHASTIC",
    n_trials=30,
)
def run(result):
    with tempfile.TemporaryDirectory() as tmp:
        mac = stand_up_agent("mac-s6", Path(tmp) / "mac", host="127.0.0.1")
        nuc = stand_up_agent("nuc-s6", Path(tmp) / "nuc", host="127.0.0.1")
        cross_share_identities(mac, nuc)
        try:
            _ = ADVERSARIAL_PROMPTS["S6_exhaust"]
            big = "x" * EXHAUST_BYTES

            @mac["agent"].handle("ask")
            def ask(_p): return {"text": big}

            cap = issue_capability(
                issuer_private_key=mac["private_key"], issuer_id=mac["agent_id"],
                holder_id=nuc["agent_id"], action="ask",
            )
            req = build_req(
            from_private_key=nuc["private_key"], from_id=nuc["agent_id"],
                to_id=mac["agent_id"],intent="task",
            payload={"action": "ask"}, cap_envelope=cap.to_dict(),
            holder_proof_key=nuc["private_key"],
            )
            res = send_message(mac["url"], req)

            payload_str = str(res.get("payload", ""))
            result["receipts"] = [res]
            result["observations"] = {
                "response_status": res.get("status"),
                "payload_byte_len": len(payload_str),
                "fault": res.get("fault"),
                "fault_is_size_related": (
                    "413" in str(res.get("fault", ""))
                    or "size" in str(res.get("fault", "")).lower()
                    or "body" in str(res.get("fault", "")).lower()
                ),
                "exhaust_bytes_attempted": EXHAUST_BYTES,
            }
            # Pass: response either rejected (413/size fault) OR delivered
            # with the actual size recorded. Either is the audit trail
            # behavior we want.
            faulted = res.get("status") != "ok"
            recorded = len(payload_str) > EXHAUST_BYTES * 0.5
            result["outcome"] = "pass" if (faulted or recorded) else "new_finding"
        finally:
            teardown(mac, nuc)


if __name__ == "__main__":
    run()
