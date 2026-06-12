"""Tier P / P3 — MITM tampering cross-machine.

Mac issues visa with advertisement. An adversary in the Tailscale path
mutates the advertisement bytes mid-flight. NUC verifies the outer
envelope signature: tamper detected at the protocol layer.

TODO (NUC-bridge time): the MITM proxy requires either a `mitmproxy`
inline script in the Tailscale path or a local proxy intercepting
the HTTPS connection. The loopback orchestration below validates the
signature-tamper-detection mechanism; the cross-machine MITM is
deferred to run-time.
"""
from __future__ import annotations

import base64
import copy
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pact_passport import (
    HandlerCost, PACTAgent, PACTMessage, ProtocolAdvertisement, crypto,
)
from pact_passport._canonical import canonical_json
from pact_passport.message import verify_message

from tests.stage2._harness import probe

_LOOPBACK = ("127.0.0.1", 55555)


def _build_request_visa(stranger_id, pub_b64, priv, action):
    msg = PACTMessage(
        id=str(uuid.uuid4()), type="REQ",
        from_agent=stranger_id, to_agent="",
        intent="request_visa",
        deadline=(datetime.now(UTC) + timedelta(seconds=30)).isoformat(),
        payload={"action": action},
        identity_doc={"agent_id": stranger_id, "public_key": pub_b64, "alg": crypto.ALG},
    )
    sig = crypto.sign(canonical_json(msg.signable_dict()), priv)
    msg.signature = base64.b64encode(sig).decode("ascii")
    return msg.to_dict()


@probe(
    probe_id="P3_mitm",
    tier="P",
    pairing={
        "mac": "gemma3:e4b (visa issuer; advertisement set)",
        "nuc": "gemma3:e4b (receiver, verifies outer envelope)",
        "roles": "MITM mutates advertisement bytes; receiver detects tamper at signature layer",
        "transport": "Tailscale path with mitmproxy inline (TODO: NUC-time)",
    },
    prediction=(
        "Mutating the advertisement field of an in-flight visa-grant "
        "response invalidates the outer envelope signature. Receiver's "
        "verify_message returns False; the message is rejected at the "
        "protocol layer before any handler dispatch."
    ),
    threshold=(
        "Mutated message verifies cleanly (envelope signature decoupled "
        "from advertisement bytes), OR receiver consumes the mutated "
        "advertisement despite signature failure."
    ),
    citation="§16.5 + spec §2 outer envelope canonical signature.",
    classification="DETERMINISTIC",
    n_trials=1,
)
def run(result):
    with tempfile.TemporaryDirectory() as tmp:
        advert = ProtocolAdvertisement(
            protocol="PACT/1.3",
            spec_uri="https://example.invalid/spec",
        )
        gk = PACTAgent("p3", store_dir=Path(tmp), advertise_protocol=advert)
        gk._ensure_identity()

        @gk.handle("ping", visa_eligible=True,
                   cost=HandlerCost(payload_bytes=64, compute_ms=10, idempotent=True))
        def ping(_p): return {"pong": True}

        priv, pub = crypto.generate_keypair()
        pub_b64 = base64.b64encode(pub).decode("ascii")
        sid = crypto.sha256_digest(f"{crypto.ALG}{pub_b64}".encode())

        res = gk._dispatch(_build_request_visa(sid, pub_b64, priv, "ping"),
                           remote_addr=_LOOPBACK)

        # Simulate MITM mutation on the advertisement payload field.
        mutated = copy.deepcopy(res)
        if (mutated.get("payload") or {}).get("protocol_advertisement"):
            mutated["payload"]["protocol_advertisement"]["spec_uri"] = (
                "https://attacker.invalid/MITM"
            )

        # Re-construct as a PACTMessage and verify against the gatekeeper key
        try:
            msg = PACTMessage.from_dict(mutated)
            verified = verify_message(msg, gk._ensure_identity().public_key)
        except Exception as e:
            verified = False
            result["notes"] = f"verify_message raised: {type(e).__name__}: {e}"

        result["receipts"] = [res, mutated]
        result["observations"] = {
            "original_advertisement": (res.get("payload") or {}).get("protocol_advertisement"),
            "mutated_advertisement": (mutated.get("payload") or {}).get("protocol_advertisement"),
            "verify_after_mutation": verified,
            "TODO_real_mitm": (
                "Replace this in-process mutation with a mitmproxy inline "
                "script in the Tailscale path at NUC-bridge time."
            ),
        }
        # Pass: signature verification fails after mutation (tamper detected).
        result["outcome"] = "pass" if not verified else "new_finding"


if __name__ == "__main__":
    run()
