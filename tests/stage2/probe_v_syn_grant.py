"""Tier V / V-syn-grant — synthetic idempotent handler GRANTED.

Synthetic (non-LLM) handler declared idempotent=True is granted a
visa with the default caveat ceiling (30s expiry, max_invocations=1).
"""
from __future__ import annotations

import base64
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pact import HandlerCost, PACTAgent, PACTMessage, crypto
from pact._canonical import canonical_json

from tests.stage2._harness import probe

_LOOPBACK = ("127.0.0.1", 55555)


def _build_request_visa(stranger_id, pub_b64, priv, action):
    msg = PACTMessage(
        id=str(uuid.uuid4()),
        type="REQ",
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
    probe_id="V_syn_grant",
    tier="V",
    pairing={
        "mac": "synthetic handler (no LLM, idempotent=True)",
        "nuc": "gemma3:e4b (visa requester)",
        "roles": "Default policy GRANTS with caveat ceiling",
        "transport": "loopback dispatch",
    },
    prediction=(
        "Visa GRANTED. Response payload carries a cap_envelope with "
        "default caveats (≤30s expiry, max_invocations=1)."
    ),
    threshold=(
        "Visa REFUSED despite idempotent=True synthetic handler (policy "
        "regression) OR caveats absent / unbounded (default ceiling regression)."
    ),
    citation="Default V-tier policy + spec §14 visa-grant shape.",
)
def run(result):
    with tempfile.TemporaryDirectory() as tmp:
        gk = PACTAgent("v-syn", store_dir=Path(tmp))
        gk._ensure_identity()

        @gk.handle("ping", visa_eligible=True,
                   cost=HandlerCost(payload_bytes=64, compute_ms=10, idempotent=True))
        def ping(_p): return {"pong": True}

        priv, pub = crypto.generate_keypair()
        pub_b64 = base64.b64encode(pub).decode("ascii")
        sid = crypto.sha256_digest(f"{crypto.ALG}{pub_b64}".encode())

        res = gk._dispatch(_build_request_visa(sid, pub_b64, priv, "ping"),
                           remote_addr=_LOOPBACK)
        result["receipts"] = [res]
        env = (res.get("payload") or {}).get("cap_envelope") or (res.get("payload") or {})
        caveats = env.get("caveats", []) if isinstance(env, dict) else []
        result["observations"] = {
            "status": res.get("status"),
            "has_cap_envelope": "cap_envelope" in (res.get("payload") or {})
                                or "cap_id" in (res.get("payload") or {}),
            "caveat_count": len(caveats),
            "caveats": caveats,
        }
        granted = res.get("status") == "ok"
        result["outcome"] = "pass" if granted else "new_finding"


if __name__ == "__main__":
    run()
