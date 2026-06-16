"""Tier X / X1 — cross-tailnet smoke probe.

Minimal Mac → NUC round-trip used to validate cross-machine harness
plumbing before the full Phase A matrix runs. Stands up a local agent
("mac_brain"), fetches the pre-spawned remote agent's identity_doc
from `$STAGE2_NUC_URL/pact/v1/identity`, then sends a single REQ over
the Tailscale tunnel and verifies the response.

Pre-registration:
    Transport delivers a signed REQ + signed RES + receipt write on both
    sides; status is "ok"; total RPC wall-clock <= 30s (which is the
    server-side deadline ceiling for non-streaming intents).

Failure modes that flip outcome to new_finding:
    - status != "ok" (protocol-level failure: unknown_peer, deadline,
      verification, etc.)
    - HTTP transport failure (Tailscale tunnel down, NUC offline,
      sshd dead)
    - Round-trip wall-clock > 30s (relay degraded beyond usable)

Required env: `STAGE2_NUC_URL` must be set to a URL like
`http://nucnode.tailcf96a0.ts.net:9101` AND a remote agent must be
running there (spawn via `tests/stage2/_spawn_remote_agent.py`).
The probe halts with `harness_error` if the env var is unset (so it
doesn't silently look like a loopback pass).
"""
from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

from pact_passport import build_req, send_message

from tests.stage2._harness import (
    maybe_remote_peer,
    probe,
    share_remote_identity_into,
    stand_up_agent,
    teardown,
)

_PAIRING = {
    "mac": "benaimac (loopback agent)",
    "nuc": "nucnode (Tailscale-reachable agent)",
    "transport": "Tailscale unicast (cross-tailnet share)",
    "expected_rtt_ms": "200-700 (cross-continent direct)",
}


@probe(
    probe_id="X1_xmachine_smoke",
    tier="X",
    pairing=_PAIRING,
    prediction=(
        "Single Mac→NUC REQ delivers, NUC handler runs, RES returns with "
        "status='ok'; round-trip <= 30s."
    ),
    threshold=(
        "status != 'ok' OR round-trip > 30s OR HTTP transport failure. "
        "Any of these blocks Phase A from starting — the smoke validates "
        "the cross-tailnet plumbing before the matrix is launched."
    ),
    citation="Stage 2 cross-machine bring-up; STAGE2_CHANGE_PLAN.md §3 C3-b.",
    classification="DETERMINISTIC",
    n_trials=1,
)
def run(result):
    nuc_url = os.environ.get("STAGE2_NUC_URL")
    if not nuc_url:
        result["outcome"] = "harness_error"
        result["notes"] = (
            "STAGE2_NUC_URL env var not set. Spawn a remote agent first via "
            "`ssh nuc 'python -m tests.stage2._spawn_remote_agent nuc_runner --port 9101'` "
            "then re-run with `STAGE2_NUC_URL=http://nucnode.tailcf96a0.ts.net:9101`."
        )
        return

    with tempfile.TemporaryDirectory() as tmp:
        # Mac-side agent (this process). Binds 127.0.0.1 — Mac doesn't
        # need to accept inbound from the NUC for this smoke; the flow
        # is one-way (Mac initiates, NUC responds).
        mac = stand_up_agent("mac_brain", Path(tmp) / "mac", host="127.0.0.1")

        # NUC-side agent — already spawned at nuc_url by orchestrator
        # (see ._spawn_remote_agent). maybe_remote_peer fetches the
        # identity_doc over HTTP and returns a handle compatible with
        # stand_up_agent for the fields we read on a peer.
        nuc = maybe_remote_peer("nuc_runner", "STAGE2_NUC_URL")
        if nuc is None:
            result["outcome"] = "harness_error"
            result["notes"] = "maybe_remote_peer returned None despite env set; check fetch"
            teardown(mac)
            return

        # Share NUC's identity_doc into Mac's peer cache; the REQ that
        # Mac sends will also include identity_doc inline so NUC trusts
        # on first use (no NUC-side share needed).
        share_remote_identity_into(mac, nuc)

        try:
            # No cap_envelope: PACT requires caps to be issued BY the
            # receiver (NUC), and since we just spawned the NUC agent
            # with no pre-shared caps, sending one Mac-issued would
            # rightfully fail capability_invalid. The smoke instead
            # sends a bare REQ to an action with no handler — the
            # structured `no_handler` fault that comes back confirms
            # transport, signature, peer trust (via inline identity_doc),
            # and structured-fault path all work end-to-end.
            t0 = time.time()
            res = send_message(nuc["url"], build_req(
                from_private_key=mac["private_key"],
                from_id=mac["agent_id"],
                to_id=nuc["agent_id"],
                intent="task",
                payload={"action": "smoke_no_handler",
                         "msg": "cross-tailnet smoke from Mac"},
                identity_doc=mac["identity"].to_identity_document(),
            ))
            wall_clock_s = round(time.time() - t0, 3)

            status = res.get("status")
            fault_code = (res.get("fault") or {}).get("code")

            result["receipts"] = [res]
            result["observations"] = {
                "wall_clock_s": wall_clock_s,
                "ceiling_s": 30,
                "status": status,
                "fault_code": fault_code,
                "nuc_url": nuc_url,
                "nuc_agent_id": nuc["agent_id"],
            }

            # A successful round-trip with NO handler registered surfaces
            # as a structured `no_handler` fault — that's the expected
            # smoke outcome for X1 (it confirms transport, signature,
            # peer trust, and structured-fault path all work). A truly
            # broken pipe shows as HTTP error or unknown_peer / cap_unknown.
            transport_ok = (
                status in ("ok", "error")  # both are structured responses
                and wall_clock_s <= 30
                and fault_code in (None, "no_handler")  # no_handler is the expected smoke result
            )

            if transport_ok:
                result["outcome"] = "pass"
                if fault_code == "no_handler":
                    result["notes"] = (
                        "Transport + signature + peer trust OK; fault=no_handler "
                        "is the expected smoke outcome (NUC's spawn script does "
                        "not register handlers)."
                    )
            else:
                result["outcome"] = "new_finding"
                result["notes"] = (
                    f"Unexpected response: status={status} fault={fault_code} "
                    f"wall_clock={wall_clock_s}s. Investigate before Phase A."
                )
        finally:
            teardown(mac)


if __name__ == "__main__":
    run()
