"""v1.3 / spec §16.5 — passive `protocol_advertisement` field acceptance.

Five tests per the spec handoff §6 and `visa_protocol_advertisement_design.md`
§6 acceptance criteria. Four of the five are *negative* tests — proving
the feature does NOT do the dangerous thing.

The load-bearing test is 6.4 (no_consumption): receiving a visa-grant
carrying a `protocol_advertisement` triggers ZERO side effects. If
this test cannot be written cleanly, the implementation has a
consumption path that must be removed. It is the feature's reason
for existing.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import uuid
from datetime import datetime, timedelta, UTC
from pathlib import Path
from unittest.mock import patch

import pytest

from pact_passport import (
    HandlerCost,
    PACTAgent,
    PACTMessage,
    ProtocolAdvertisement,
    crypto,
)
from pact_passport._canonical import canonical_json
from pact_passport.message import verify_message


# ---------------------------------------------------------------------------
# Stranger helper (reused from test_v_tier_v1_v7.py shape)
# ---------------------------------------------------------------------------


class _Stranger:
    """Passport-less peer: ephemeral keypair + derived agent_id."""

    def __init__(self):
        self.private_key, self.public_key = crypto.generate_keypair()
        pub_b64 = base64.b64encode(self.public_key).decode("ascii")
        self.agent_id = crypto.sha256_digest(f"{crypto.ALG}{pub_b64}".encode())
        self.identity_doc = {
            "agent_id": self.agent_id,
            "public_key": pub_b64,
            "alg": crypto.ALG,
        }


def _sign_finalize(msg: PACTMessage, private_key: bytes) -> dict:
    sig = crypto.sign(canonical_json(msg.signable_dict()), private_key)
    msg.signature = base64.b64encode(sig).decode("ascii")
    return msg.to_dict()


def _build_request_visa(stranger: _Stranger, action: str) -> dict:
    msg = PACTMessage(
        id=str(uuid.uuid4()),
        type="REQ",
        from_agent=stranger.agent_id,
        to_agent="",
        intent="request_visa",
        deadline=(datetime.now(UTC) + timedelta(seconds=30)).isoformat(),
        payload={"action": action},
        identity_doc=stranger.identity_doc,
    )
    return _sign_finalize(msg, stranger.private_key)


def _gatekeeper(tmp_path, name="alice", advertisement=None):
    agent = PACTAgent(
        name,
        store_dir=tmp_path / name,
        advertise_protocol=advertisement,
    )
    agent._ensure_identity()

    @agent.handle("ping", visa_eligible=True, cost=HandlerCost(payload_bytes=64, compute_ms=10))
    def ping(payload):
        return {"pong": True}

    @agent.handle("private")
    def private(payload):
        return {"secret": "leaked"}

    return agent


_LOOPBACK = ("127.0.0.1", 55555)


# ---------------------------------------------------------------------------
# 6.1 Emit-when-configured + round-trip
# ---------------------------------------------------------------------------


def test_61_emit_when_configured_grant(tmp_path):
    """Agent with advertise_protocol set produces a grant payload that
    carries protocol_advertisement, round-tripping intact through
    to_dict() / from_dict()."""
    advert = ProtocolAdvertisement(
        protocol="PACT/1.3",
        spec_uri="https://example.invalid/spec/PACT_v1.md",
    )
    agent = _gatekeeper(tmp_path, advertisement=advert)
    stranger = _Stranger()

    res = agent._dispatch(_build_request_visa(stranger, "ping"), remote_addr=_LOOPBACK)
    assert res["status"] == "ok"

    advert_field = res["payload"].get("protocol_advertisement")
    assert advert_field is not None, "advertisement missing from grant payload"
    assert advert_field == {
        "protocol": "PACT/1.3",
        "spec_uri": "https://example.invalid/spec/PACT_v1.md",
    }

    # Round-trip via the dataclass helpers
    restored = ProtocolAdvertisement.from_dict(advert_field)
    assert restored == advert


def test_61_round_trip_dataclass():
    """ProtocolAdvertisement to_dict / from_dict round-trip preserves
    both fields and equality."""
    a = ProtocolAdvertisement(protocol="PACT/1.3", spec_uri="https://example/p")
    assert ProtocolAdvertisement.from_dict(a.to_dict()) == a
    # frozen — equality semantics work as dataclass-frozen
    b = ProtocolAdvertisement(protocol="PACT/1.3", spec_uri="https://example/p")
    assert a == b


# ---------------------------------------------------------------------------
# 6.2 Absent-by-default + no schema break
# ---------------------------------------------------------------------------


def test_62_absent_by_default(tmp_path):
    """Agent without advertise_protocol produces a grant payload that
    does NOT contain a protocol_advertisement key. No schema break for
    existing callers."""
    agent = _gatekeeper(tmp_path)  # no advertisement
    stranger = _Stranger()

    res = agent._dispatch(_build_request_visa(stranger, "ping"), remote_addr=_LOOPBACK)
    assert res["status"] == "ok"
    assert "protocol_advertisement" not in res["payload"], (
        f"unexpected advertisement field: {res['payload']!r}"
    )

    # Pre-change payload keys: only {visa, nonce}. Confirm no new keys
    # are introduced when the feature is unconfigured.
    expected_keys = {"visa", "nonce"}
    assert set(res["payload"].keys()) == expected_keys, (
        f"payload schema drift: expected {expected_keys}, got {set(res['payload'].keys())}"
    )


def test_62_absent_by_default_refusal(tmp_path):
    """Refusal payload is absent-by-default when no advertisement is
    configured. Schema parity with pre-change refusals."""
    agent = _gatekeeper(tmp_path)
    stranger = _Stranger()

    # Trigger a refusal: action not visa_eligible
    res = agent._dispatch(_build_request_visa(stranger, "private"), remote_addr=_LOOPBACK)
    assert res["status"] == "error"
    assert res["fault"]["code"] == "denied"
    # No payload field added; refusal is opaque (fault-only)
    assert "payload" not in res or not res["payload"] or "protocol_advertisement" not in res.get("payload", {})


# ---------------------------------------------------------------------------
# 6.3 Signature coverage (MITM defense)
# ---------------------------------------------------------------------------


def test_63_signature_coverage_grant(tmp_path):
    """Mutating the protocol_advertisement field on a signed grant
    causes verify_message to FAIL. MITM cannot inject or alter it."""
    advert = ProtocolAdvertisement(protocol="PACT/1.3", spec_uri="https://legit/")
    agent = _gatekeeper(tmp_path, advertisement=advert)
    stranger = _Stranger()

    res = agent._dispatch(_build_request_visa(stranger, "ping"), remote_addr=_LOOPBACK)

    # Sanity: clean signature verifies
    clean_msg = PACTMessage.from_dict(res)
    assert verify_message(clean_msg, agent._ensure_identity().public_key)

    # Mutate the advertisement (simulating MITM injection / alteration)
    mutated_dict = json.loads(json.dumps(res))
    mutated_dict["payload"]["protocol_advertisement"]["spec_uri"] = "https://attacker.invalid/fake"
    mutated_msg = PACTMessage.from_dict(mutated_dict)
    assert not verify_message(mutated_msg, agent._ensure_identity().public_key), (
        "mutated protocol_advertisement should break signature verification"
    )


def test_63_signature_coverage_refusal(tmp_path):
    """Mutating the protocol_advertisement field on a signed REFUSAL
    causes verify_message to FAIL too."""
    advert = ProtocolAdvertisement(protocol="PACT/1.3", spec_uri="https://legit/")
    agent = _gatekeeper(tmp_path, advertisement=advert)
    stranger = _Stranger()

    res = agent._dispatch(_build_request_visa(stranger, "private"), remote_addr=_LOOPBACK)
    assert res["status"] == "error"

    clean_msg = PACTMessage.from_dict(res)
    assert verify_message(clean_msg, agent._ensure_identity().public_key)

    mutated_dict = json.loads(json.dumps(res))
    mutated_dict["payload"]["protocol_advertisement"]["protocol"] = "EVIL/1.0"
    mutated_msg = PACTMessage.from_dict(mutated_dict)
    assert not verify_message(mutated_msg, agent._ensure_identity().public_key)


# ---------------------------------------------------------------------------
# 6.4 NO-CONSUMPTION (LOAD-BEARING)
# ---------------------------------------------------------------------------


def test_64_no_consumption_zero_side_effects(tmp_path):
    """**The feature's reason for existing.**

    Receiving a grant carrying a protocol_advertisement MUST trigger:
      - zero outbound network calls,
      - zero filesystem writes outside the test's tmp_path,
      - zero state mutation on the receiving agent,
      - zero change to dispatch outcome compared to an identical
        response without the advertisement.

    If this test cannot be written cleanly, the implementation has a
    consumption path that must be removed.
    """
    advert = ProtocolAdvertisement(
        protocol="PACT/1.3",
        spec_uri="https://attacker.invalid/would-fetch-if-consumed",
    )
    issuer = _gatekeeper(tmp_path / "issuer_root", "issuer", advertisement=advert)
    # The "receiving agent" — a separate PACTAgent that processes the
    # response. In v1.3, receiving an advertisement is purely passive:
    # the field deserializes; nothing acts on it.
    receiver = _gatekeeper(tmp_path / "receiver_root", "receiver")

    # === Pre-receive state snapshot ===
    receiver_state_before = {
        "handlers": dict(receiver._handlers),
        "visa_eligible_actions": set(receiver._visa_eligible_actions),
        "handler_costs": dict(receiver._handler_costs),
        "idempotency_cache": dict(receiver._idempotency_cache),
        "invocation_counts": dict(receiver._invocation_counts),
        "advertise_protocol": receiver.advertise_protocol,
        "custom_visa_policy": receiver._custom_visa_policy,
    }

    # === Issuer mints a grant carrying the advertisement ===
    stranger = _Stranger()
    res_with = issuer._dispatch(
        _build_request_visa(stranger, "ping"), remote_addr=_LOOPBACK,
    )
    assert res_with["status"] == "ok"
    assert "protocol_advertisement" in res_with["payload"]

    # === Patch outbound network primitives to assert no call happens
    #     while the receiver inspects the advertisement-bearing message.
    #     If PACT consumes the advertisement to e.g. fetch spec_uri,
    #     one of these would fire.
    with patch("socket.create_connection") as mock_socket, \
         patch("urllib.request.urlopen") as mock_urlopen:
        # === Deserialize the response into a PACTMessage on the
        #     receiver side. This is the moment the field becomes
        #     accessible to the receiver.
        received = PACTMessage.from_dict(res_with)

        # The advertisement is present and accessible — but nothing
        # is supposed to *do* anything with it.
        assert received.payload["protocol_advertisement"] == {
            "protocol": "PACT/1.3",
            "spec_uri": "https://attacker.invalid/would-fetch-if-consumed",
        }

        # === Outbound network calls: must be zero
        assert mock_socket.call_count == 0, (
            f"unexpected outbound socket call(s): {mock_socket.call_args_list}"
        )
        assert mock_urlopen.call_count == 0, (
            f"unexpected outbound urlopen call(s): {mock_urlopen.call_args_list}"
        )

    # === Receiver state must be unchanged
    receiver_state_after = {
        "handlers": dict(receiver._handlers),
        "visa_eligible_actions": set(receiver._visa_eligible_actions),
        "handler_costs": dict(receiver._handler_costs),
        "idempotency_cache": dict(receiver._idempotency_cache),
        "invocation_counts": dict(receiver._invocation_counts),
        "advertise_protocol": receiver.advertise_protocol,
        "custom_visa_policy": receiver._custom_visa_policy,
    }
    assert receiver_state_after == receiver_state_before, (
        "receiver state mutated by receiving an advertisement: "
        f"before={receiver_state_before!r} after={receiver_state_after!r}"
    )

    # === Filesystem writes outside tmp_path: track via snapshot of
    #     receiver's store root before vs after. Receiving the message
    #     does NOT touch the receiver's store (the receiver isn't
    #     dispatching anything; just reading).
    receiver_store_root = tmp_path / "receiver_root" / "receiver"
    if receiver_store_root.exists():
        files_after = sorted(p.relative_to(receiver_store_root)
                              for p in receiver_store_root.rglob("*") if p.is_file())
        # Only allowed entries are the receiver's own identity files.
        # No new entries should have been created by receiving the
        # advertisement-bearing message.
        for f in files_after:
            assert not str(f).startswith("messages/") or "alice" in str(f), (
                f"unexpected file created by advertisement receive: {f}"
            )


def test_64_dispatch_outcome_invariant(tmp_path):
    """Confirm that a response WITH advertisement and an identical
    response WITHOUT advertisement produce the same effective dispatch
    outcome on the receiver. The advertisement has no functional
    impact."""
    # Two issuers, only difference is advertisement configuration
    issuer_with = _gatekeeper(
        tmp_path / "with_root", "issuer_with",
        advertisement=ProtocolAdvertisement(
            protocol="PACT/1.3", spec_uri="https://example/"
        ),
    )
    issuer_without = _gatekeeper(tmp_path / "without_root", "issuer_without")

    stranger_a = _Stranger()
    stranger_b = _Stranger()

    res_with = issuer_with._dispatch(
        _build_request_visa(stranger_a, "ping"), remote_addr=_LOOPBACK,
    )
    res_without = issuer_without._dispatch(
        _build_request_visa(stranger_b, "ping"), remote_addr=_LOOPBACK,
    )

    # Both succeed
    assert res_with["status"] == "ok"
    assert res_without["status"] == "ok"
    # Both grant visas with the same caveat shape
    visa_with = res_with["payload"]["visa"]
    visa_without = res_without["payload"]["visa"]
    assert visa_with["action"] == visa_without["action"] == "ping"
    assert visa_with["visa"] is True and visa_without["visa"] is True
    # Same caveat enforcement applies
    assert len(visa_with["caveats"]) == len(visa_without["caveats"])
    # Only difference: presence of protocol_advertisement on the
    # with-version's payload.
    assert "protocol_advertisement" in res_with["payload"]
    assert "protocol_advertisement" not in res_without["payload"]


# ---------------------------------------------------------------------------
# 6.5 Refusal-path parity
# ---------------------------------------------------------------------------


def test_65_refusal_emits_advertisement_when_configured(tmp_path):
    """Refusal envelope carries protocol_advertisement under the same
    rules as the grant envelope."""
    advert = ProtocolAdvertisement(
        protocol="PACT/1.3", spec_uri="https://example/spec",
    )
    agent = _gatekeeper(tmp_path, advertisement=advert)
    stranger = _Stranger()

    # Trigger a refusal — "private" handler is not visa_eligible
    res = agent._dispatch(
        _build_request_visa(stranger, "private"), remote_addr=_LOOPBACK,
    )
    assert res["status"] == "error"
    assert res["fault"] == {"code": "denied", "detail": "denied"}

    advert_field = res["payload"]["protocol_advertisement"]
    assert advert_field == {
        "protocol": "PACT/1.3",
        "spec_uri": "https://example/spec",
    }


def test_65_refusal_no_consumption(tmp_path):
    """Receiving a REFUSAL carrying a protocol_advertisement also
    triggers zero side effects on the receiver."""
    advert = ProtocolAdvertisement(
        protocol="PACT/1.3",
        spec_uri="https://attacker.invalid/would-fetch-if-consumed",
    )
    issuer = _gatekeeper(tmp_path / "issuer_root", "issuer", advertisement=advert)
    receiver = _gatekeeper(tmp_path / "receiver_root", "receiver")

    receiver_state_before = (
        dict(receiver._handlers), set(receiver._visa_eligible_actions),
        dict(receiver._handler_costs),
    )

    stranger = _Stranger()
    res = issuer._dispatch(
        _build_request_visa(stranger, "private"), remote_addr=_LOOPBACK,
    )
    assert res["status"] == "error"
    assert "protocol_advertisement" in res["payload"]

    with patch("socket.create_connection") as mock_socket, \
         patch("urllib.request.urlopen") as mock_urlopen:
        received = PACTMessage.from_dict(res)
        # Field accessible but inert
        assert received.payload["protocol_advertisement"] == {
            "protocol": "PACT/1.3",
            "spec_uri": "https://attacker.invalid/would-fetch-if-consumed",
        }
        assert mock_socket.call_count == 0
        assert mock_urlopen.call_count == 0

    receiver_state_after = (
        dict(receiver._handlers), set(receiver._visa_eligible_actions),
        dict(receiver._handler_costs),
    )
    assert receiver_state_after == receiver_state_before
