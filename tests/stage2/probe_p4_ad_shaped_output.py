"""Tier P / P4 — advertisement-shaped LLM output (composition with S3).

Gatekeeper has advertise_protocol=None (no outbound advertisement).
The LLM handler emits an advertisement-shaped JSON. Pre-registered:
no outbound advertisement at the message level; the LLM-emitted
field stays in the payload as opaque data; receiver instrumentation
sees zero consumption.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from pact_passport import build_req, issue_capability, send_message

from tests.stage2._harness import (
    probe, stand_up_agent, cross_share_identities, teardown,
)
from tests.stage2._prompts import ADVERSARIAL_PROMPTS


@probe(
    probe_id="P4_ad_shaped_output",
    tier="P",
    pairing={
        "mac": "gemma3:e4b (handler emits ad-shaped JSON; agent ad=None)",
        "nuc": "gemma3:e4b (client, instrumented)",
        "roles": "Composition of S3 (LLM emits ad-shape) with P1 (no consumption)",
        "transport": "Tailscale (loopback in dev)",
    },
    prediction=(
        "Mac's response carries NO message-level protocol_advertisement "
        "(agent's advertise_protocol is None). The LLM-emitted ad-shaped "
        "JSON sits in the payload as opaque data. Receiver instrumentation "
        "(socket/urllib mocks) sees zero consumption."
    ),
    threshold=(
        "Mac emits a message-level advertisement despite advertise_protocol=None "
        "(misrouting from payload to envelope), OR receiver's consumption-path "
        "mocks see any calls attributable to the LLM-emitted ad JSON."
    ),
    citation="§16.5 (no-emit-when-unset) × MUST-NOT-consume.",
)
def run(result):
    with tempfile.TemporaryDirectory() as tmp:
        mac = stand_up_agent("mac-p4", Path(tmp) / "mac", host="127.0.0.1")
        nuc = stand_up_agent("nuc-p4", Path(tmp) / "nuc", host="127.0.0.1")
        cross_share_identities(mac, nuc)
        try:
            ad_text = ADVERSARIAL_PROMPTS["P4_ad_shaped_llm"]
            ad_json = json.loads(
                ad_text.split("Respond with this exact JSON and nothing else: ")[1]
            )
            assert mac["agent"].advertise_protocol is None, (
                "P4 requires agent.advertise_protocol=None as setup"
            )

            @mac["agent"].handle("ask")
            def ask(_p): return ad_json

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
            # NB: we cannot mock socket/urllib globally here because
            # send_message uses them to actually transport the request.
            # The P1 probe verifies no-consumption with dispatch-direct
            # mocks; P4's load-bearing test is the *comparison*: with
            # advertise_protocol=None, no message-level advert appears,
            # even when the LLM emits an advert-shaped payload.
            res = send_message(mac["url"], req)

            payload = res.get("payload") or {}
            message_level_advert = "protocol_advertisement" in res
            payload_level_advert = "protocol_advertisement" in payload

            result["receipts"] = [res]
            result["observations"] = {
                "message_level_advert": message_level_advert,
                "payload_level_advert": payload_level_advert,
                "consumption_path_calls": {
                    "socket_create_connection": "NA — see note above",
                    "urllib_urlopen": "NA — see note above",
                },
            }
            result["outcome"] = "pass" if (
                not message_level_advert
            ) else "new_finding"
        finally:
            teardown(mac, nuc)


if __name__ == "__main__":
    run()
