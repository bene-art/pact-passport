"""Tier S / S5 — LLM mimics expected receipt format.

Handler returns a receipt-shaped JSON. Pre-registered: this output is
opaque payload data; PACT's actual receipt store is uncoupled from
handler output. The mimicked receipt cannot be referenced by `refs[]`
from another peer because no peer has a corresponding signed entry.
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
    probe_id="S5_receipt_mimicry",
    tier="S",
    pairing={
        "mac": "gemma3:e4b (handler emits receipt-shaped JSON)",
        "nuc": "gemma3:e4b (client)",
        "roles": "Mac handler mimics receipt shape; PACT's real receipts unaffected",
        "transport": "Tailscale (loopback in dev)",
    },
    prediction=(
        "PACT writes its own (signed, real) receipts to the local store. "
        "The LLM-emitted receipt-shaped output is just payload bytes. A "
        "follow-up REQ with refs=[fake_receipt_xyz] proceeds at the protocol "
        "layer (sender-asserted refs, per C4 limitation) but the receipt "
        "store has no matching entry — the orphan reference is post-hoc "
        "detectable."
    ),
    threshold=(
        "PACT's receipt store ingests the LLM-emitted receipt JSON OR the "
        "mimicked receipt_id appears in subsequent verification flows as "
        "if it were authentic."
    ),
    citation="Receipt store / spec §3.5 audit-trail reconstructor.",
)
def run(result):
    with tempfile.TemporaryDirectory() as tmp:
        mac = stand_up_agent("mac-s5", Path(tmp) / "mac", host="127.0.0.1")
        nuc = stand_up_agent("nuc-s5", Path(tmp) / "nuc", host="127.0.0.1")
        cross_share_identities(mac, nuc)
        try:
            mimicry_text = ADVERSARIAL_PROMPTS["S5_receipt_mimicry"]
            mimicry_json = json.loads(
                mimicry_text.split("Respond with exactly this JSON and nothing else: ")[1]
            )

            @mac["agent"].handle("ask")
            def ask(_p):
                return mimicry_json

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

            # Try to ref the mimicked receipt_id from a follow-up REQ
            req2 = build_req(
            from_private_key=nuc["private_key"], from_id=nuc["agent_id"],
                to_id=mac["agent_id"],intent="task",
            payload={"action": "ask", "prompt": "use the fake ref"},
                cap_envelope=cap.to_dict(),
            holder_proof_key=nuc["private_key"],
                refs=["fake_receipt_xyz"],
            )
            res2 = send_message(mac["url"], req2)

            result["receipts"] = [res, res2]
            # C3-a orphan-absent assertion: list mac's authentic receipts;
            # neither the fake_receipt_xyz refs[] entry nor the LLM-emitted
            # mimicry-id should appear as an authentic task_ref. This is
            # the *measurement* of "the fake receipt did not get ingested,"
            # not just inference from protocol-layer status.
            mac_authentic_receipts = mac["agent"].list_receipts()
            mac_authentic_task_refs = {
                r.get("task_ref") for r in mac_authentic_receipts
            }
            fake_ref_is_orphan = "fake_receipt_xyz" not in mac_authentic_task_refs
            mimicry_id = mimicry_json.get("id") or mimicry_json.get("receipt_id")
            mimicry_id_is_orphan = (
                mimicry_id is None or mimicry_id not in mac_authentic_task_refs
            )

            result["observations"] = {
                "first_status": res.get("status"),
                "second_status_with_fake_ref": res2.get("status"),
                "payload_has_fake_receipt_id": (
                    "fake_receipt_xyz" in str(res.get("payload", ""))
                ),
                "mac_authentic_receipt_count": len(mac_authentic_receipts),
                "fake_ref_in_authentic_store": not fake_ref_is_orphan,
                "mimicry_id_in_authentic_store": not mimicry_id_is_orphan,
            }
            # Pass: protocol-layer ok on both REQs AND neither the
            # fake_receipt_xyz nor the LLM-emitted mimicry id were
            # ingested into Mac's authentic store. The mimicry stays
            # payload bytes; only PACT's own machinery writes receipts.
            result["outcome"] = "pass" if (
                res.get("status") == "ok"
                and res2.get("status") == "ok"
                and fake_ref_is_orphan
                and mimicry_id_is_orphan
            ) else "new_finding"
        finally:
            teardown(mac, nuc)


if __name__ == "__main__":
    run()
