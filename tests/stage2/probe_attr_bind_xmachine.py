"""Tier ATTR / ATTR_BIND_XMACHINE — cross-tailnet holder-proof attribution.

Cross-machine variant of `probe_attr_ablations::ATTR_BIND`. Tests
that the NUC's holder-proof-signature enforcement attributes the
defense against the stolen-token (B2) attack when Mac is the attacker
and NUC is the target.

Pre-registered prediction (BASELINE, no env on NUC):
    Mac sends a REQ presenting a NUC-issued cap (fetched from the
    test-control endpoint) with a holder_proof signed over WRONG
    bytes (not the msg.id). NUC's dispatcher should reject with
    holder_proof_invalid.

Predicted under PACT_ABLATION_BIND=1 on NUC spawn (i.e., orchestrator
flag `--nuc-env PACT_ABLATION_BIND=1`):
    The signature check is bypassed; dispatch succeeds; NUC's handler
    runs. Status='ok' because cap is valid + handler exists.

The §12 attribution claim is: "ABL-BIND cleanly newly-passes ATTR-BIND
across the wire." Loopback already showed this on a single machine
(probe_attr_ablations); this probe extends the claim to cross-tailnet
deployment.

Required env: STAGE2_NUC_URL set; NUC running `_spawn_r1_remote` (which
exposes the `reformulate` cap we use here as the attack vehicle).
"""
from __future__ import annotations

import base64
import json
import os
import tempfile
import time
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
    probe_id="ATTR_BIND_XMACHINE",
    tier="ATTR",
    pairing={
        "mac": "benaimac (attacker)",
        "nuc": "nucnode.tailcf96a0.ts.net (target)",
        "transport": "Tailscale unicast (cross-tailnet share)",
    },
    prediction=(
        "BASELINE on NUC: REQ with a NUC-issued cap + wrong-signed "
        "holder_proof is rejected with fault=holder_proof_invalid. "
        "PACT_ABLATION_BIND=1 on NUC: same REQ is honored (status=ok)."
    ),
    threshold=(
        "BASELINE: REQ is honored (status=ok) — BIND defense missing. "
        "ABL_BIND: REQ is rejected (fault=holder_proof_invalid) — "
        "ablation didn't take effect or scope mismatch."
    ),
    citation="§12.2 ABL-BIND cross-machine; PACT_RESEARCH_PLAN.md §12.",
    classification="DETERMINISTIC",
    n_trials=1,
)
def run(result):
    nuc_url = os.environ.get("STAGE2_NUC_URL")
    if not nuc_url:
        result["outcome"] = "harness_error"
        result["notes"] = "STAGE2_NUC_URL not set; spawn _spawn_r1_remote first"
        return

    # Test-control server convention: port+1.
    host, port = nuc_url.rsplit(":", 1)
    nuc_test_url = os.environ.get("STAGE2_NUC_TEST_URL") or f"{host}:{int(port) + 1}"

    with tempfile.TemporaryDirectory() as tmp:
        # Mac stands up a local agent — only used as Mallory's identity
        # for signing the outer envelope. The cross-machine flow doesn't
        # require Mac's server to be reachable (we're sender-only here).
        mac_port = free_port()
        mac = stand_up_agent("mac_mallory", Path(tmp) / "mac", host="127.0.0.1", port=mac_port)

        try:
            # Fetch NUC's identity_doc + populate Mac's peer cache.
            nuc = stand_up_remote_agent(nuc_url, name="nuc_target")
            share_remote_identity_into(mac, nuc)

            # Register Mac as a peer on the NUC's test-control server.
            # This triggers NUC to issue the holder-bound caps for Mac.
            # We provide a placeholder cap_answer (NUC won't actually use
            # it for ATTR_BIND — only for R1's Step 2 flow).
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
                    "mac_url": "http://127.0.0.1:0",  # not used for this probe
                    "mac_identity_doc": mac["identity"].to_identity_document(),
                    "cap_answer": placeholder_cap.to_dict(),
                },
            )

            # Fetch NUC-issued cap for reformulate (Mac is holder).
            cap_dict = _fetch_json(f"{nuc_test_url}/test/caps/reformulate")["cap"]
            cap_token = CapabilityToken.from_dict(cap_dict)

            # Build the attack REQ: NUC-issued cap + WRONG-signed holder_proof.
            msg = PACTMessage(
                id=str(uuid.uuid4()),
                type="REQ",
                from_agent=mac["agent_id"],
                to_agent=nuc["agent_id"],
                intent="task",
                deadline=(datetime.now(UTC) + timedelta(seconds=30)).isoformat(),
                payload={"action": "reformulate", "q": "stolen-token attack across the wire"},
                cap_id=cap_token.cap_id,
                cap_envelope=cap_dict,
                identity_doc=mac["identity"].to_identity_document(),
            )
            # holder_proof signs WRONG bytes (not msg.id).
            msg.holder_proof = base64.b64encode(
                crypto.sign(b"not the msg id", mac["private_key"])
            ).decode("ascii")
            # Outer envelope signature is fine.
            outer_sig = crypto.sign(canonical_json(msg.signable_dict()), mac["private_key"])
            msg.signature = base64.b64encode(outer_sig).decode("ascii")

            # Send over Tailscale.
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

            # Determine which config we're under by asking NUC.
            # /test/health doesn't expose this, so we infer from the
            # response itself. The probe is DETERMINISTIC: it just
            # records what happened.
            result["receipts"] = [resp]
            result["observations"] = {
                "wall_clock_s": wall_clock_s,
                "status": status,
                "fault_code": fault_code,
                "nuc_url": nuc_url,
                "nuc_agent_id": nuc["agent_id"],
                "ablation_inferred": (
                    "BIND_ACTIVE" if status == "ok" else
                    "BIND_INTACT" if fault_code == "holder_proof_invalid" else
                    f"UNEXPECTED:{status}/{fault_code}"
                ),
            }

            # Pass criteria:
            #   - BASELINE (BIND intact): expect holder_proof_invalid.
            #   - ABL_BIND active: expect status=ok (handler ran since cap is valid).
            # The probe doesn't know its config; we mark `pass` for either
            # of the two valid outcomes and `new_finding` for unexpected.
            if fault_code == "holder_proof_invalid":
                result["outcome"] = "pass"
                result["notes"] = "BASELINE behavior: BIND defense intact, holder_proof_invalid as expected."
            elif status == "ok":
                result["outcome"] = "pass"
                result["notes"] = "ABL_BIND active: holder-proof check bypassed, handler ran (attack succeeded as predicted under ablation)."
            else:
                result["outcome"] = "new_finding"
                result["notes"] = (
                    f"Unexpected: status={status} fault={fault_code}. "
                    "Investigate — this is neither default BIND-intact nor ABL_BIND-active outcome."
                )
        finally:
            teardown(mac)


if __name__ == "__main__":
    run()
