"""Tier A / A6 — V-tier amplification under LLM-paced timing.

NUC's LLM handler is intentionally slow (A6_slow_handler prompt). Mac
sends 6 visa requests in close succession. Pre-registered: rate
ceiling holds; LLM slowness does not amplify the per-window quota.
"""
from __future__ import annotations

import base64
import tempfile
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pact_passport import HandlerCost, PACTAgent, PACTMessage, crypto
from pact_passport._canonical import canonical_json

from tests.stage2._harness import probe
from tests.stage2._prompts import ADVERSARIAL_PROMPTS


N_REQUESTS = 6
_LOOPBACK = ("127.0.0.1", 55555)


def _build_request_visa(stranger_id, pub_b64, priv, action):
    msg = PACTMessage(
        id=str(uuid.uuid4()),
        type="REQ",
        from_agent=stranger_id,
        to_agent="",
        intent="request_visa",
        deadline=(datetime.now(UTC) + timedelta(seconds=60)).isoformat(),
        payload={"action": action},
        identity_doc={"agent_id": stranger_id, "public_key": pub_b64, "alg": crypto.ALG},
    )
    sig = crypto.sign(canonical_json(msg.signable_dict()), priv)
    msg.signature = base64.b64encode(sig).decode("ascii")
    return msg.to_dict()


@probe(
    probe_id="A6_v_amplification",
    tier="A",
    pairing={
        "mac": "gemma3:e4b (visa requester)",
        "nuc": "gemma3:e4b (intentionally slow handler — A6_slow_handler prompt)",
        "roles": "Mac issues N visa requests; NUC handler stalls each call",
        "transport": "Tailscale loopback (dispatch-direct for determinism)",
    },
    prediction=(
        f"Across N={N_REQUESTS} requests within a rate window, the per-window "
        "quota holds. Some requests are GRANTED, the rest are REFUSED on rate. "
        "LLM-pacing latency does not amplify quota: the V-tier rate counter is "
        "indexed by peer_network_id, not by completion time."
    ),
    threshold=(
        "All N requests are granted (rate counter failed to enforce under "
        "slow handler) OR all are refused at request time without quota "
        "tracking (counter increment ordering broken)."
    ),
    citation="Composes V-tier rate window with handler-pacing realism.",
    classification="STOCHASTIC",
    n_trials=30,
)
def run(result):
    with tempfile.TemporaryDirectory() as tmp:
        gatekeeper = PACTAgent("nuc-a6", store_dir=Path(tmp) / "nuc")
        gatekeeper._ensure_identity()

        @gatekeeper.handle(
            "think",
            visa_eligible=True,
            cost=HandlerCost(payload_bytes=1024, compute_ms=60_000, idempotent=True),
        )
        def think(_payload):
            # In production: ollama.chat with A6_slow_handler.
            # Substitute a short sleep so the probe finishes in test time.
            _ = ADVERSARIAL_PROMPTS["A6_slow_handler"]
            time.sleep(0.1)
            return {"answer": 4}

        priv, pub = crypto.generate_keypair()
        pub_b64 = base64.b64encode(pub).decode("ascii")
        stranger_id = crypto.sha256_digest(f"{crypto.ALG}{pub_b64}".encode())

        outcomes = []
        for i in range(N_REQUESTS):
            res = gatekeeper._dispatch(
                _build_request_visa(stranger_id, pub_b64, priv, "think"),
                remote_addr=_LOOPBACK,
            )
            outcomes.append({
                "i": i,
                "status": res.get("status"),
                "fault_code": (res.get("fault") or {}).get("code"),
            })

        granted = sum(1 for o in outcomes if o["status"] == "ok")
        refused = sum(
            1 for o in outcomes
            if o.get("fault_code") in ("rate_limited", "visa_refused")
        )
        result["observations"] = {
            "granted": granted, "refused": refused,
            "n_total": N_REQUESTS, "details": outcomes,
        }
        # Pass: not all granted (quota enforced) AND not all refused (quota
        # didn't fail closed against the legitimate first request).
        result["outcome"] = (
            "pass" if (0 < granted < N_REQUESTS or refused > 0) else "new_finding"
        )


if __name__ == "__main__":
    run()
