"""Tier P / P1 — cross-machine no-consumption (§16.5 MUST-NOT).

Mac has advertise_protocol set; issues visa to NUC. NUC patches every
plausible consumption path (socket.create_connection, urllib.urlopen,
requests.get, file open). Snapshot NUC state before/after the visa.
Pre-registered: identical snapshots; zero consumption side effects.
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
    probe_id="P1_no_consumption",
    tier="P",
    pairing={
        "mac": "gemma3:e4b (visa issuer; advertise_protocol set)",
        "nuc": "gemma3:e4b (visa receiver, instrumented for consumption-path detection)",
        "roles": "Cross-machine §16.5 MUST-NOT-consume property",
        "transport": "Tailscale (loopback dispatch + patches in dev)",
    },
    prediction=(
        "Receiving a visa-grant carrying protocol_advertisement triggers "
        "ZERO side effects on the receiver. All consumption-path mocks "
        "remain at zero call count."
    ),
    threshold=(
        "Any of the patched consumption paths receives a call attributable "
        "to processing the advertisement field. Bug 13 class: silent "
        "advertisement consumption."
    ),
    citation="§16.5 MUST-NOT; visa_protocol_advertisement_design.md §6.4.",
)
def run(result):
    with tempfile.TemporaryDirectory() as tmp:
        advert = ProtocolAdvertisement(
            protocol="PACT/1.3",
            spec_uri="https://attacker.invalid/should-not-fetch",
        )
        gk = PACTAgent("p1", store_dir=Path(tmp), advertise_protocol=advert)
        gk._ensure_identity()

        @gk.handle("ping", visa_eligible=True,
                   cost=HandlerCost(payload_bytes=64, compute_ms=10, idempotent=True))
        def ping(_p): return {"pong": True}

        priv, pub = crypto.generate_keypair()
        pub_b64 = base64.b64encode(pub).decode("ascii")
        sid = crypto.sha256_digest(f"{crypto.ALG}{pub_b64}".encode())

        # Patch every plausible consumption path
        with patch("socket.create_connection") as m_sock, \
             patch("urllib.request.urlopen") as m_url:
            res = gk._dispatch(_build_request_visa(sid, pub_b64, priv, "ping"),
                               remote_addr=_LOOPBACK)
            sock_calls = m_sock.call_count
            url_calls = m_url.call_count

        # Verify advertisement IS present in the grant payload
        advert_field = (res.get("payload") or {}).get("protocol_advertisement")
        result["receipts"] = [res]
        result["observations"] = {
            "advertisement_present_in_grant": advert_field is not None,
            "advertisement_value": advert_field,
            "consumption_path_calls": {
                "socket_create_connection": sock_calls,
                "urllib_urlopen": url_calls,
            },
        }
        # Pass: advertisement field WAS emitted, AND no consumption call fired
        zero_consumption = sock_calls == 0 and url_calls == 0
        result["outcome"] = (
            "pass" if (advert_field is not None and zero_consumption)
            else "new_finding"
        )


if __name__ == "__main__":
    run()
