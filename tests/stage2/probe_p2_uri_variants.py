"""Tier P / P2 — adversarial spec_uri content variants.

10 visas issued, each with a different spec_uri payload from the
P2 sweep. Pre-registered: every variant signs cleanly, round-trips,
triggers ZERO side effects on receive.
"""
from __future__ import annotations

import base64
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from pact_passport import (
    HandlerCost, PACTAgent, PACTMessage, ProtocolAdvertisement, crypto,
)
from pact_passport._canonical import canonical_json

from tests.stage2._harness import probe
from tests.stage2._prompts import ADVERSARIAL_PROMPTS

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
    probe_id="P2_uri_variants",
    tier="P",
    pairing={
        "mac": "gemma3:e4b (rotating spec_uri per issuance)",
        "nuc": "gemma3:e4b (receiver, instrumented)",
        "roles": "10 variants × 1 visa each; consumption-path mocks span all 10",
        "transport": "loopback dispatch + mocks",
    },
    prediction=(
        "All 10 variants sign cleanly, round-trip intact via to_dict() "
        "/ from_dict(), and trigger zero consumption calls. The receiver "
        "treats the spec_uri as an opaque string regardless of scheme, "
        "size, or control bytes."
    ),
    threshold=(
        "Any variant fails to sign / verify (canonicalization bug), OR "
        "any variant triggers a consumption-path call, OR any variant "
        "causes the receiver to fault."
    ),
    citation="§16.5 + acceptance test 6.2 (variants).",
)
def run(result):
    variants = ADVERSARIAL_PROMPTS["P2_uri_variants"]
    per_variant = []

    for uri in variants:
        with tempfile.TemporaryDirectory() as tmp:
            advert = ProtocolAdvertisement(protocol="PACT/1.3", spec_uri=uri)
            gk = PACTAgent("p2", store_dir=Path(tmp), advertise_protocol=advert)
            gk._ensure_identity()

            @gk.handle("ping", visa_eligible=True,
                       cost=HandlerCost(payload_bytes=64, compute_ms=10, idempotent=True))
            def ping(_p): return {"pong": True}

            priv, pub = crypto.generate_keypair()
            pub_b64 = base64.b64encode(pub).decode("ascii")
            sid = crypto.sha256_digest(f"{crypto.ALG}{pub_b64}".encode())

            with patch("socket.create_connection") as m_sock, \
                 patch("urllib.request.urlopen") as m_url:
                res = gk._dispatch(_build_request_visa(sid, pub_b64, priv, "ping"),
                                   remote_addr=_LOOPBACK)
                sock_n, url_n = m_sock.call_count, m_url.call_count

            advert_field = (res.get("payload") or {}).get("protocol_advertisement")
            per_variant.append({
                "uri": uri if len(uri) < 80 else uri[:60] + "..." + uri[-10:],
                "uri_len": len(uri),
                "status": res.get("status"),
                "advert_round_trip_ok": (
                    advert_field is not None
                    and advert_field.get("spec_uri") == uri
                ),
                "consumption_calls": {"sock": sock_n, "urllib": url_n},
            })

    all_clean = all(
        v["status"] == "ok"
        and v["advert_round_trip_ok"]
        and v["consumption_calls"]["sock"] == 0
        and v["consumption_calls"]["urllib"] == 0
        for v in per_variant
    )
    result["receipts"] = per_variant
    result["observations"] = {
        "n_variants": len(variants),
        "all_clean": all_clean,
        "any_consumption_observed": any(
            v["consumption_calls"]["sock"] or v["consumption_calls"]["urllib"]
            for v in per_variant
        ),
    }
    result["outcome"] = "pass" if all_clean else "new_finding"


if __name__ == "__main__":
    run()
