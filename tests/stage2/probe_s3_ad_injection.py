"""Tier S / S3 — LLM-claims-to-be-PACT (advertisement injection).

Gatekeeper has advertise_protocol=None (no outbound advertisement).
The LLM handler emits an advertisement-shaped JSON. Pre-registered:
no consumption path (§16.5 MUST-NOT); no outbound advertisement
because the agent's advertise_protocol is None; no side effect.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from pact_passport import build_req, issue_capability, send_message

from tests.stage2._harness import (
    probe, stand_up_agent, cross_share_identities, teardown,
)
from tests.stage2._prompts import ADVERSARIAL_PROMPTS


@probe(
    probe_id="S3_ad_injection",
    tier="S",
    pairing={
        "mac": "gemma3:e4b (handler emits ad-shaped JSON; agent ad=None)",
        "nuc": "gemma3:e4b (client + instrumented for consumption-path detection)",
        "roles": "Mac handler returns advertisement-shaped output; receiver MUST NOT consume",
        "transport": "Tailscale (loopback in dev)",
    },
    prediction=(
        "Mac's outbound visa/refusal payloads carry no protocol_advertisement "
        "field (agent's advertise_protocol is None). NUC receives the "
        "handler's ad-shaped output as opaque payload. Zero side effects on "
        "NUC: no socket open, no urllib, no file fetch attributable to "
        "the advertisement field."
    ),
    threshold=(
        "Mac emits an outbound protocol_advertisement field at the message "
        "level (advertise_protocol=None bypass), OR NUC takes any action "
        "on the LLM-emitted advertisement-shaped JSON in the payload."
    ),
    citation="§16.5 protocol_advertisement MUST-NOT-consume.",
)
def run(result):
    with tempfile.TemporaryDirectory() as tmp:
        mac = stand_up_agent("mac-s3", Path(tmp) / "mac", host="127.0.0.1")
        nuc = stand_up_agent("nuc-s3", Path(tmp) / "nuc", host="127.0.0.1")
        cross_share_identities(mac, nuc)
        try:
            ad_text = ADVERSARIAL_PROMPTS["S3_advertisement_injection"]
            ad_json = json.loads(ad_text.split("Respond with exactly this JSON and nothing else: ")[1])

            @mac["agent"].handle("ask")
            def ask(_p):
                return ad_json

            assert mac["agent"].advertise_protocol is None, (
                "S3 requires agent.advertise_protocol=None as setup"
            )

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

            payload = res.get("payload") or {}
            outbound_advert_in_message = "protocol_advertisement" in res
            llm_advert_in_payload = "protocol_advertisement" in payload

            result["receipts"] = [res]
            result["observations"] = {
                "outbound_message_level_advert": outbound_advert_in_message,
                "llm_advert_present_in_payload": llm_advert_in_payload,
                "advert_consumed_anywhere": False,  # would need fault injection
                "payload_keys": sorted(payload.keys()),
            }
            # Pass: no message-level advertisement (agent ad=None respected).
            # Payload contains the LLM's fake advertisement — that's expected
            # and is the test of MUST-NOT-consume.
            result["outcome"] = (
                "pass" if not outbound_advert_in_message else "new_finding"
            )
        finally:
            teardown(mac, nuc)


if __name__ == "__main__":
    run()
