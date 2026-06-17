"""Tier R / R1 — v0.1.3 baseline replay, cross-tailnet edition.

Faithful to the original R1 loopback semantics but with Mac and NUC
as separately-hosted agents talking over Tailscale. The three-step
round-trip:

    Step 1: Mac → NUC `reformulate`     (Mac drives)
    Step 2: NUC → Mac `answer`          (NUC drives, asynchronously
                                         triggered by its `reformulate`
                                         handler returning to Step 1)
    Step 3: Mac → NUC `synthesize`      (Mac drives)

is preserved exactly. Each step uses a holder-bound, issuer-signed
capability presented inline as `cap_envelope`. The bidirectional flow
exercises:

  - Mac's PACTServer listening on its Tailscale IP (`100.109.184.125`)
  - NUC's PACTServer listening on `nucnode.tailcf96a0.ts.net`
  - cap issuance + verification in both directions
  - peer trust (NUC fetches Mac's identity_doc; Mac fetches NUC's)
  - signed receipts on each side

Required env: `STAGE2_NUC_URL` set to `http://nucnode.tailcf96a0.ts.net:9101`
AND the NUC must be running `_spawn_r1_remote` (not the plain
`_spawn_remote_agent`). The orchestrator wires this when invoked with
`--xmachine-probe probe_r1_xmachine_replay`.

Pre-registered prediction: total wall-clock ≤ 2× the v0.1.3 baseline
of 227s (so ≤ 454s). Each step's status is "ok". Step 2 lands on
Mac's server within 30s of Step 1's reply.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
import threading
import time
import urllib.request
import urllib.error
from pathlib import Path

from pact_passport import build_req, send_message
from pact_passport.capability import issue_capability, CapabilityToken

from tests.stage2._harness import (
    cross_share_identities,
    free_port,
    probe,
    stand_up_agent,
    stand_up_remote_agent,
    teardown,
)


V013_BASELINE_S = 227
PASS_CEILING_S = 454
STEP2_WAIT_S = 30


def _mac_tailscale_ip() -> str | None:
    """Return this Mac's Tailscale IPv4 if available, else None.
    The NUC needs an IP reachable from its own side; localhost won't work."""
    for cmd in (
        ["/Applications/Tailscale.app/Contents/MacOS/Tailscale", "ip", "-4"],
        ["tailscale", "ip", "-4"],
    ):
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=3).decode().strip()
            if out and "." in out:
                return out.split()[0]
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


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
    probe_id="R1_xmachine_replay",
    tier="R",
    pairing={
        "mac": "benaimac (Tailscale 100.109.184.125)",
        "nuc": "nucnode.tailcf96a0.ts.net:9101",
        "roles": "reformulate(NUC) → answer(Mac) → synthesize(NUC), bidirectional",
        "transport": "Tailscale unicast (cross-tailnet share, DERP relay possible)",
    },
    prediction=(
        f"3-step bidirectional round-trip completes; total wall-clock "
        f"≤ {PASS_CEILING_S}s (2× v0.1.3 baseline {V013_BASELINE_S}s). "
        f"Each step's RES status='ok'. Step 2 (NUC→Mac) arrives within "
        f"{STEP2_WAIT_S}s of Step 1's reply."
    ),
    threshold=(
        f"status != 'ok' on any step, OR Step 2 doesn't arrive within "
        f"{STEP2_WAIT_S}s, OR total wall-clock > 2× baseline, OR cap "
        f"verification fails any direction."
    ),
    citation="v0.1.3 case study Demo §3 three-step round-trip; cross-tailnet variant.",
    classification="DETERMINISTIC",
    n_trials=1,
)
def run(result):
    nuc_url = os.environ.get("STAGE2_NUC_URL")
    if not nuc_url:
        result["outcome"] = "harness_error"
        result["notes"] = "STAGE2_NUC_URL env var not set; spawn _spawn_r1_remote first."
        return

    # Test-control server convention: same host, port+1. STAGE2_NUC_TEST_URL
    # override is honored for environments where ports differ.
    nuc_test_url = os.environ.get("STAGE2_NUC_TEST_URL")
    if not nuc_test_url:
        # Default: parse nuc_url + add 1 to port.
        host, port = nuc_url.rsplit(":", 1)
        nuc_test_url = f"{host}:{int(port) + 1}"

    mac_ts_ip = _mac_tailscale_ip()
    if not mac_ts_ip:
        result["outcome"] = "harness_error"
        result["notes"] = "Could not determine Mac Tailscale IP; ensure Tailscale is up."
        return

    with tempfile.TemporaryDirectory() as tmp:
        # Stand up Mac's agent on the Tailscale-reachable interface.
        mac_port = free_port()
        mac = stand_up_agent("mac_brain", Path(tmp) / "mac", host="0.0.0.0", port=mac_port)
        mac_tailscale_url = f"http://{mac_ts_ip}:{mac_port}"

        # Mac handles Step 2 (`answer`) when NUC sends it inbound.
        step2_received = threading.Event()
        step2_payload_box: dict = {}

        @mac["agent"].handle("answer")
        def answer_handler(payload):
            step2_payload_box["q"] = payload.get("q", "")
            step2_received.set()
            time.sleep(0.05)  # mirrors v0.1.3 timing
            return {"text": "The capital of France is Paris."}

        try:
            # 1. Fetch NUC's identity_doc + register Mac peer (this also
            #    triggers NUC to issue the 2 NUC-receives caps).
            nuc = stand_up_remote_agent(nuc_url, name="nuc_runner")
            mac["agent"]._store.save_peer(nuc["agent_id"], nuc["identity_doc"])

            # 2. Mac issues cap_answer (for Step 2; NUC will be holder).
            cap_answer = issue_capability(
                issuer_private_key=mac["private_key"],
                issuer_id=mac["agent_id"],
                holder_id=nuc["agent_id"],
                action="answer",
            )

            # 3. Register Mac with NUC's test-control server.
            _post_json(
                f"{nuc_test_url}/test/register_peer",
                {
                    "mac_url": mac_tailscale_url,
                    "mac_identity_doc": mac["identity"].to_identity_document(),
                    "cap_answer": cap_answer.to_dict(),
                },
            )

            # 4. Fetch the 2 NUC-issued caps (reformulate, synthesize).
            cap_reformulate_dict = _fetch_json(f"{nuc_test_url}/test/caps/reformulate")["cap"]
            cap_synthesize_dict  = _fetch_json(f"{nuc_test_url}/test/caps/synthesize")["cap"]
            cap_reformulate = CapabilityToken.from_dict(cap_reformulate_dict)
            cap_synthesize  = CapabilityToken.from_dict(cap_synthesize_dict)

            # 5. The actual R1 flow.
            t0 = time.time()

            # Step 1: Mac → NUC reformulate.
            r1 = send_message(nuc["url"], build_req(
                from_private_key=mac["private_key"], from_id=mac["agent_id"],
                to_id=nuc["agent_id"], intent="task",
                payload={"action": "reformulate",
                         "q": "What is the capital of France?"},
                cap_envelope=cap_reformulate.to_dict(),
                holder_proof_key=mac["private_key"],
                identity_doc=mac["identity"].to_identity_document(),
            ))

            # Step 2: NUC will autonomously fire this to Mac's server.
            # Wait for Mac's handler to receive it.
            step2_arrived = step2_received.wait(STEP2_WAIT_S)

            # Step 3: Mac → NUC synthesize.
            # Use whatever Step 2 carried as `context`; if Step 2 didn't
            # arrive, use the Step 1 reformulated text as a fallback so
            # Step 3 still exercises the wire.
            context = step2_payload_box.get("q", (r1.get("payload") or {}).get("text", ""))
            r3 = send_message(nuc["url"], build_req(
                from_private_key=mac["private_key"], from_id=mac["agent_id"],
                to_id=nuc["agent_id"], intent="task",
                payload={"action": "synthesize", "context": context},
                cap_envelope=cap_synthesize.to_dict(),
                holder_proof_key=mac["private_key"],
                identity_doc=mac["identity"].to_identity_document(),
            ))

            total_s = time.time() - t0

            result["receipts"] = [r1, r3]
            result["observations"] = {
                "total_wall_clock_s": round(total_s, 3),
                "baseline_v013_s": V013_BASELINE_S,
                "ceiling_2x_s": PASS_CEILING_S,
                "step1_status": r1.get("status"),
                "step2_arrived": step2_arrived,
                "step2_wait_ceiling_s": STEP2_WAIT_S,
                "step3_status": r3.get("status"),
                "mac_url": mac_tailscale_url,
                "nuc_url": nuc_url,
            }

            step1_ok = r1.get("status") == "ok"
            step3_ok = r3.get("status") == "ok"
            under_ceiling = total_s <= PASS_CEILING_S

            if step1_ok and step2_arrived and step3_ok and under_ceiling:
                result["outcome"] = "pass"
            else:
                result["outcome"] = "new_finding"
                reasons = []
                if not step1_ok:    reasons.append(f"step1.status={r1.get('status')}")
                if not step2_arrived: reasons.append("step2 did not arrive within deadline")
                if not step3_ok:    reasons.append(f"step3.status={r3.get('status')}")
                if not under_ceiling: reasons.append(f"total={total_s}s > {PASS_CEILING_S}s")
                result["notes"] = "; ".join(reasons)
        finally:
            teardown(mac)


if __name__ == "__main__":
    run()
