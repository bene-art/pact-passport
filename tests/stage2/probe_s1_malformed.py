"""Tier S / S1 — LLM emits malformed JSON.

Handler returns a literally malformed string as the response. PACT
treats it as opaque payload bytes. Receiver's verify_message checks
signature, not payload content. No protocol fault.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from pact import build_req, issue_capability, send_message

from tests.stage2._harness import (
    probe, stand_up_agent, cross_share_identities, teardown,
)
from tests.stage2._prompts import ADVERSARIAL_PROMPTS


@probe(
    probe_id="S1_malformed_json",
    tier="S",
    pairing={
        "mac": "gemma3:e4b (handler emits malformed string)",
        "nuc": "gemma3:e4b (client)",
        "roles": "Mac handler returns the literal S1_malformed text",
        "transport": "Tailscale (loopback in dev)",
    },
    prediction=(
        "PACT signs the malformed string opaquely. Receiver verify_message "
        "checks signature, not payload content. No protocol fault."
    ),
    threshold=(
        "PACT crashes in build_res, OR verify_message rejects on payload "
        "content, OR receiver emits protocol_error for payload-content."
    ),
    citation="Tomašev §4.9 Verification Subversion; SoK §3.1.",
)
def run(result):
    with tempfile.TemporaryDirectory() as tmp:
        mac = stand_up_agent("mac-s1", Path(tmp) / "mac", host="127.0.0.1")
        nuc = stand_up_agent("nuc-s1", Path(tmp) / "nuc", host="127.0.0.1")
        cross_share_identities(mac, nuc)
        try:
            adversarial_text = ADVERSARIAL_PROMPTS["S1_malformed"]

            @mac["agent"].handle("ask")
            def ask(_p):
                # NUC time: ollama.chat returns this text; we substitute
                # the literal output (the LLM's output IS the malformed string).
                return {"text": "{ unclosed"}

            cap = issue_capability(
                issuer_private_key=mac["private_key"], issuer_id=mac["agent_id"],
                holder_id=nuc["agent_id"], action="ask",
            )
            req = build_req(
            from_private_key=nuc["private_key"], from_id=nuc["agent_id"],
                to_id=mac["agent_id"],intent="task",
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
                "echo_includes_malformed": "{ unclosed" in str(res.get("payload", "")),
            }
            ok = res.get("status") == "ok" and "fault" not in res
            result["outcome"] = "pass" if ok else "new_finding"
        finally:
            teardown(mac, nuc)


if __name__ == "__main__":
    run()
