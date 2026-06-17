"""Tier ATTR / ATTR_NONCE_XMACHINE — cross-tailnet visa-nonce attribution.

Cross-machine variant of `probe_attr_ablations::ATTR_NONCE`. Tests
that the NUC's visa-nonce holder-proof binding attributes the defense
against visa replay (V5) when Mac is the attacker and NUC is the
target.

Pre-registered prediction (BASELINE, no env on NUC):
    Mac presents a NUC-issued visa (fetched from /test/caps/visa) with
    a holder_proof signed over WRONG bytes (not the visa's nonce).
    NUC's dispatcher should reject with holder_proof_invalid.

Predicted under PACT_ABLATION_NONCE=1 on NUC spawn:
    Visa nonce check bypassed; dispatch succeeds; handler runs.
    Status='ok'.

The §12 attribution claim: ABL-NONCE cleanly newly-passes ATTR-NONCE
across the wire. Loopback already showed this per-node; this probe
extends to the deployed topology.

Required env: STAGE2_NUC_URL set; NUC running `_spawn_r1_remote`
(which exposes a pre-issued visa at /test/caps/visa after Mac
registers as a peer).
"""
from __future__ import annotations

import base64
import json
import os
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pact_passport import crypto
from pact_passport._canonical import canonical_json
from pact_passport.capability import CapabilityToken
from pact_passport.message import PACTMessage

from tests.stage2._harness import (
    free_port,
    probe,
    share_remote_identity_into,
    stand_up_agent,
    stand_up_remote_agent,
    teardown,
)


def _fetch_json(url: str, timeout: float = 10.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read())


def _post_json(url: str, body: dict, timeout: float = 10.0) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


@probe(
    probe_id="ATTR_NONCE_XMACHINE",
    tier="ATTR",
    pairing={
        "mac": "benaimac (attacker)",
        "nuc": "nucnode.tailcf96a0.ts.net (target)",
        "transport": "Tailscale unicast (cross-tailnet share)",
    },
    prediction=(
        "BASELINE: visa REQ with holder_proof signed over wrong bytes "
        "(not the visa nonce) rejected with fault=holder_proof_invalid. "
        "PACT_ABLATION_NONCE=1: same REQ honored (status=ok)."
    ),
    threshold=(
        "BASELINE: visa REQ honored — NONCE defense missing. "
        "ABL_NONCE: visa REQ rejected — ablation didn't take effect."
    ),
    citation="§12.2 ABL-NONCE cross-machine; PACT_RESEARCH_PLAN.md §12.",
    classification="DETERMINISTIC",
    n_trials=1,
)
def run(result):
    nuc_url = os.environ.get("STAGE2_NUC_URL")
    if not nuc_url:
        result["outcome"] = "harness_error"
        result["notes"] = "STAGE2_NUC_URL not set; spawn _spawn_r1_remote first"
        return

    host, port = nuc_url.rsplit(":", 1)
    nuc_test_url = os.environ.get("STAGE2_NUC_TEST_URL") or f"{host}:{int(port) + 1}"

    with tempfile.TemporaryDirectory() as tmp:
        mac_port = free_port()
        mac = stand_up_agent("mac_mallory", Path(tmp) / "mac", host="127.0.0.1", port=mac_port)

        try:
            nuc = stand_up_remote_agent(nuc_url, name="nuc_target")
            share_remote_identity_into(mac, nuc)

            # Register Mac as peer (triggers visa issuance on NUC).
            from pact_passport.capability import issue_capability
            placeholder_cap = issue_capability(
                issuer_private_key=mac["private_key"],
                issuer_id=mac["agent_id"],
                holder_id=nuc["agent_id"],
                action="placeholder",
            )
            _post_json(
                f"{nuc_test_url}/test/register_peer",
                {
                    "mac_url": "http://127.0.0.1:0",
                    "mac_identity_doc": mac["identity"].to_identity_document(),
                    "cap_answer": placeholder_cap.to_dict(),
                },
            )

            # Fetch the pre-issued visa.
            visa_dict = _fetch_json(f"{nuc_test_url}/test/caps/visa")["cap"]
            visa_token = CapabilityToken.from_dict(visa_dict)

            # Build the attack REQ: NUC-issued visa + holder_proof signed
            # over WRONG bytes (not the visa's nonce).
            msg = PACTMessage(
                id=str(uuid.uuid4()),
                type="REQ",
                from_agent=mac["agent_id"],
                to_agent=nuc["agent_id"],
                intent="task",
                deadline=(datetime.now(UTC) + timedelta(seconds=30)).isoformat(),
                payload={"action": "reformulate", "q": "visa replay across the wire"},
                cap_id=visa_token.cap_id,
                cap_envelope=visa_dict,
                identity_doc=mac["identity"].to_identity_document(),
            )
            # holder_proof signs WRONG bytes — should bind the visa nonce.
            msg.holder_proof = base64.b64encode(
                crypto.sign(b"not the visa nonce", mac["private_key"])
            ).decode("ascii")
            outer_sig = crypto.sign(canonical_json(msg.signable_dict()), mac["private_key"])
            msg.signature = base64.b64encode(outer_sig).decode("ascii")

            t0 = time.time()
            req_body = canonical_json(msg.to_dict())
            http_req = urllib.request.Request(
                nuc_url.rstrip("/") + "/pact/v1/message",
                data=req_body,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(http_req, timeout=15) as http_res:
                    resp = json.loads(http_res.read())
            except urllib.error.HTTPError as e:
                resp = json.loads(e.read())
            wall_clock_s = round(time.time() - t0, 3)

            status = resp.get("status")
            fault_code = (resp.get("fault") or {}).get("code")

            result["receipts"] = [resp]
            result["observations"] = {
                "wall_clock_s": wall_clock_s,
                "status": status,
                "fault_code": fault_code,
                "nuc_url": nuc_url,
                "nuc_agent_id": nuc["agent_id"],
                "visa_cap_id": visa_token.cap_id,
                "ablation_inferred": (
                    "NONCE_ACTIVE" if status == "ok" else
                    "NONCE_INTACT" if fault_code == "holder_proof_invalid" else
                    f"UNEXPECTED:{status}/{fault_code}"
                ),
            }

            if fault_code == "holder_proof_invalid":
                result["outcome"] = "pass"
                result["notes"] = "BASELINE: NONCE defense intact, holder_proof_invalid as expected."
            elif status == "ok":
                result["outcome"] = "pass"
                result["notes"] = "ABL_NONCE active: visa nonce-binding bypassed (attack succeeded as predicted)."
            else:
                result["outcome"] = "new_finding"
                result["notes"] = (
                    f"Unexpected: status={status} fault={fault_code}. "
                    "Neither default NONCE-intact nor ABL_NONCE-active outcome."
                )
        finally:
            teardown(mac)


if __name__ == "__main__":
    run()
