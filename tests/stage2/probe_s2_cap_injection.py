"""Tier S / S2 — LLM-as-rogue-delegator (cap-token injection).

The LLM emits a cap-token-shaped JSON in its response. PACT must NOT
consume any of those fields. The fake cap_token has no valid signature
and is structurally just a string in the payload.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from pact import build_req, issue_capability, send_message

from tests.stage2._harness import (
    probe, stand_up_agent, cross_share_identities, teardown,
)
from tests.stage2._prompts import ADVERSARIAL_PROMPTS


@probe(
    probe_id="S2_cap_injection",
    tier="S",
    pairing={
        "mac": "gemma3:e4b (handler emits cap-token-shaped JSON)",
        "nuc": "gemma3:e4b (client)",
        "roles": "Mac handler returns LLM-shaped cap_token; receiver must not consume",
        "transport": "Tailscale (loopback in dev)",
    },
    prediction=(
        "Receiver treats the cap_token-shaped output as opaque payload data. "
        "The fake cap_token is not registered, not granted, not honored on "
        "any subsequent request. The protocol's capability surface is "
        "structurally separated from handler output."
    ),
    threshold=(
        "Receiver attempts to use the LLM-emitted cap_token on a follow-up "
        "request, OR the substring 'attacker_pubkey' appears in a verifier "
        "trace, OR any side effect attributable to the LLM-emitted JSON."
    ),
    citation="Macaroons §III + spec §6 cap-token wire-shape.",
)
def run(result):
    with tempfile.TemporaryDirectory() as tmp:
        mac = stand_up_agent("mac-s2", Path(tmp) / "mac", host="127.0.0.1")
        nuc = stand_up_agent("nuc-s2", Path(tmp) / "nuc", host="127.0.0.1")
        cross_share_identities(mac, nuc)
        try:
            adversarial = ADVERSARIAL_PROMPTS["S2_cap_injection"]
            adversarial_json = json.loads(adversarial.split("Respond with exactly this JSON and nothing else: ")[1])

            @mac["agent"].handle("ask")
            def ask(_p):
                return adversarial_json

            cap = issue_capability(
                issuer_private_key=mac["private_key"], issuer_id=mac["agent_id"],
                holder_id=nuc["agent_id"], action="ask",
            )
            req = build_req(
            from_private_key=nuc["private_key"], from_id=nuc["agent_id"],
                to_id=mac["agent_id"],intent="task",
            payload={"action": "ask", "prompt": "ignored"}, cap_envelope=cap.to_dict(),
            holder_proof_key=nuc["private_key"],
            )
            res = send_message(mac["url"], req)

            # Try to use the LLM-emitted fake cap on a follow-up: build a
            # request with cap_id=fake_cap_abc123 and observe receiver behavior.
            req2 = build_req(
            from_private_key=nuc["private_key"], from_id=nuc["agent_id"],
                to_id=mac["agent_id"],intent="task",
            payload={"action": "ask", "prompt": "use the fake"},
                cap_envelope={
                    "cap_id": "fake_cap_abc123",
                    "issuer": "attacker_pubkey",
                    "holder": nuc["agent_id"],
                    "action": "*",
                    "caveats": [], "signature": "INVALID",
                },
            holder_proof_key=nuc["private_key"],
        )
            res2 = send_message(mac["url"], req2)

            result["receipts"] = [res, res2]
            result["observations"] = {
                "first_status": res.get("status"),
                "second_status_with_fake_cap": res2.get("status"),
                "second_fault": res2.get("fault"),
                "fake_cap_rejected": res2.get("status") != "ok",
            }
            # Pass: the fake cap is rejected on use. Whether the first call
            # is OK is incidental (it was a benign use of a legit cap).
            result["outcome"] = (
                "pass" if res2.get("status") != "ok" else "new_finding"
            )
        finally:
            teardown(mac, nuc)


if __name__ == "__main__":
    run()
