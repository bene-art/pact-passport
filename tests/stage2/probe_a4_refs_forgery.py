"""Tier A / A4 — receipt-causality forgery cross-machine.

Mac dispatches REQ → NUC responds → Mac records receipt A. NUC then
sends a fresh REQ with refs=[<fabricated_receipt_id>]. Mac receives.

Pre-registered (per C4 + spec §6.2): refs[] is sender-asserted and not
receiver-cross-verified against Mac's local receipt store. Mac accepts.
The audit-trail-reconstructor would flag the orphan post-hoc.

This probe EXPECTS to surface the C4 limitation cross-machine, not
to fail it. Confirmation of C4 cross-machine → §6 sentence + E7 cite.
"""
from __future__ import annotations

import tempfile
import uuid
from pathlib import Path

from pact import build_req, issue_capability, send_message

from tests.stage2._harness import (
    probe, stand_up_agent, cross_share_identities, teardown,
)


@probe(
    probe_id="A4_refs_forgery",
    tier="A",
    pairing={
        "mac": "gemma3:e4b (sender + receiver)",
        "nuc": "gemma3:e4b (responder; fabricates refs[] on follow-up)",
        "roles": "Mac dispatches; NUC responds, then sends a fresh REQ with fabricated refs[]",
        "transport": "Tailscale loopback in dev",
    },
    prediction=(
        "Per spec §6.2: refs[] is sender-asserted, not receiver-enforced. Mac "
        "accepts the fresh REQ with fabricated refs. The audit-trail "
        "reconstructor at §3.5 would flag the orphan post-hoc. This is the "
        "C4 known limitation confirmed cross-machine."
    ),
    threshold=(
        "Mac REJECTS the fresh REQ on a refs[] check that didn't exist in "
        "v0.7 — regression of the C4 finding, OR the check grew silently "
        "(in which case the §6 paper sentence is wrong and must be revised)."
    ),
    citation="Lamport 1978; Auvolat TCS 2021; experiments_2026-06-08.md E7.",
)
def run(result):
    with tempfile.TemporaryDirectory() as tmp:
        mac = stand_up_agent("mac-a4", Path(tmp) / "mac", host="127.0.0.1")
        nuc = stand_up_agent("nuc-a4", Path(tmp) / "nuc", host="127.0.0.1")
        cross_share_identities(mac, nuc)
        try:
            @mac["agent"].handle("ask")
            def mac_ask(_payload):
                return {"text": "ok"}

            @nuc["agent"].handle("ask")
            def nuc_ask(_payload):
                return {"text": "ok"}

            # Mac → NUC; produces receipt A on Mac side.
            cap_mac_to_nuc = issue_capability(
                issuer_private_key=mac["private_key"],
                issuer_id=mac["agent_id"],
                holder_id=nuc["agent_id"],
                action="ask",
            )
            req_a = build_req(
            from_private_key=mac["private_key"],
                from_id=mac["agent_id"],
                to_id=nuc["agent_id"],intent="task",
            payload={"action": "ask", "prompt": "hi"},
                cap_envelope=cap_mac_to_nuc.to_dict(),
            holder_proof_key=mac["private_key"],
            )
            res_a = send_message(nuc["url"], req_a)

            # NUC → Mac with FABRICATED refs[]
            fabricated = f"receipt:{uuid.uuid4()}"
            cap_nuc_to_mac = issue_capability(
                issuer_private_key=nuc["private_key"],
                issuer_id=nuc["agent_id"],
                holder_id=mac["agent_id"],
                action="ask",
            )
            req_b = build_req(
            from_private_key=nuc["private_key"],
                from_id=nuc["agent_id"],
                to_id=mac["agent_id"],intent="task",
            payload={"action": "ask", "prompt": "hi"},
                cap_envelope=cap_nuc_to_mac.to_dict(),
            holder_proof_key=nuc["private_key"],
                refs=[fabricated],
            )
            res_b = send_message(mac["url"], req_b)

            result["receipts"] = [res_a, res_b]
            result["observations"] = {
                "fabricated_ref": fabricated,
                "mac_accepted_fabricated_refs": res_b.get("status") == "ok",
                "fault_on_b": res_b.get("fault"),
            }
            # Expected: Mac ACCEPTS (confirming the C4 limitation cross-machine)
            result["outcome"] = (
                "pass" if res_b.get("status") == "ok" else "new_finding"
            )
            if result["outcome"] == "new_finding":
                result["notes"] = (
                    "C4 cross-machine result differs from loopback. Either a "
                    "receiver-side refs[] check grew, or the test setup is wrong."
                )
        finally:
            teardown(mac, nuc)


if __name__ == "__main__":
    run()
