"""Tier V / V-LLM-refuse — visa refused when handler is non-idempotent LLM.

Default V-tier policy requires idempotent=True. An LLM-backed handler
that declares idempotent=False is refused at the policy hook.
"""
from __future__ import annotations

import base64
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pact_passport import HandlerCost, PACTAgent, PACTMessage, crypto
from pact_passport._canonical import canonical_json

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
    probe_id="V_llm_refuse",
    tier="V",
    pairing={
        "mac": "gemma3:e4b (handler, idempotent=False)",
        "nuc": "gemma3:e4b (visa requester)",
        "roles": "Default policy must REFUSE a non-idempotent LLM handler",
        "transport": "loopback dispatch (deterministic)",
    },
    prediction="Visa REFUSED with structured refusal (status='error', fault.code mentions idempotency).",
    threshold="Visa GRANTED for non-idempotent handler — default policy regression.",
    citation="Default V-tier policy + HandlerCost(idempotent=False).",
)
def run(result):
    with tempfile.TemporaryDirectory() as tmp:
        gk = PACTAgent("v-refuse", store_dir=Path(tmp))
        gk._ensure_identity()

        @gk.handle("ask", visa_eligible=True,
                   cost=HandlerCost(payload_bytes=4096, compute_ms=30_000,
                                    idempotent=False))
        def ask(_p): return {"text": "ok"}

        priv, pub = crypto.generate_keypair()
        pub_b64 = base64.b64encode(pub).decode("ascii")
        sid = crypto.sha256_digest(f"{crypto.ALG}{pub_b64}".encode())

        res = gk._dispatch(_build_request_visa(sid, pub_b64, priv, "ask"),
                           remote_addr=_LOOPBACK)
        result["receipts"] = [res]
        result["observations"] = {
            "status": res.get("status"),
            "fault_code": (res.get("fault") or {}).get("code"),
            "fault_detail": (res.get("fault") or {}).get("detail"),
        }
        refused = res.get("status") != "ok"
        result["outcome"] = "pass" if refused else "new_finding"


if __name__ == "__main__":
    run()
