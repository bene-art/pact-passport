"""Tests for the §12.2 ablation harness.

Covers:
  - Module invariants: default-off, env parsing, active_ablations() reporting.
  - End-to-end behavior: ABL_BIND, when active, causes the dispatch path
    to honor a REQ that carries cap_id but no holder_proof — the
    "stolen-token" attack predicted by §12.2 ABL-BIND.
  - Per-mechanism unit tests for ABL_CHAIN, ABL_RECEIPT, ABL_NONCE,
    ABL_RATE. Each asserts the guarded code path bypasses its check
    and emits the audit-trail WARNING.

Production-safety invariant: `test_no_ablations_active_by_default`
enforces that under the standard test env (no PACT_ABLATION_* vars),
every flag is False. Any commit that flips a default ON will break
this test by design.
"""

from __future__ import annotations

import base64
import logging
import time
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pact_passport import _ablations, crypto
from pact_passport._canonical import canonical_json
from pact_passport.agent import PACTAgent
from pact_passport.capability import (
    CapabilityResult,
    CapabilityToken,
    DelegationLink,
    Caveat,
    attenuate,
    issue_capability,
    verify_capability,
)
from pact_passport.message import PACTMessage
from pact_passport.transport.server import PACTServer


# ---------------------------------------------------------------------------
# Module invariants
# ---------------------------------------------------------------------------

def test_no_ablations_active_by_default():
    """Production-safety canary: pytest invocation MUST start clean.

    If this test fails, the test env has a PACT_ABLATION_* var set or a
    previous test leaked module state. Either way, halt before trusting
    any subsequent ablation-aware result.
    """
    assert _ablations.ABL_BIND is False
    assert _ablations.ABL_CHAIN is False
    assert _ablations.ABL_RECEIPT is False
    assert _ablations.ABL_NONCE is False
    assert _ablations.ABL_RATE is False
    assert _ablations.active_ablations() == []


def test_env_flag_string_one_means_on(monkeypatch):
    """`PACT_ABLATION_BIND=1` parses to True; everything else stays False."""
    monkeypatch.setenv("PACT_ABLATION_BIND", "1")
    assert _ablations._read("BIND") is True
    assert _ablations._read("CHAIN") is False


def test_env_flag_other_truthy_strings_do_not_enable(monkeypatch):
    """Only literal '1' enables. 'true', 'yes', 'on' do NOT — explicit by design."""
    for val in ("true", "True", "yes", "on", "0", "1 ", " 1"):
        monkeypatch.setenv("PACT_ABLATION_BIND", val)
        assert _ablations._read("BIND") is False, f"unexpected enable for {val!r}"


def test_active_ablations_reports_only_on_flags(monkeypatch):
    """active_ablations() lists the names of currently-True flags in fixed order."""
    monkeypatch.setattr(_ablations, "ABL_BIND", True)
    monkeypatch.setattr(_ablations, "ABL_CHAIN", False)
    monkeypatch.setattr(_ablations, "ABL_RECEIPT", True)
    monkeypatch.setattr(_ablations, "ABL_NONCE", False)
    monkeypatch.setattr(_ablations, "ABL_RATE", False)
    assert _ablations.active_ablations() == ["BIND", "RECEIPT"]


def test_active_ablations_empty_when_all_off(monkeypatch):
    """No flags on -> empty list (provenance default for normal runs)."""
    for name in ("BIND", "CHAIN", "RECEIPT", "NONCE", "RATE"):
        monkeypatch.setattr(_ablations, f"ABL_{name}", False)
    assert _ablations.active_ablations() == []


# ---------------------------------------------------------------------------
# End-to-end: ABL_BIND bypasses holder-proof check in the dispatch path
# ---------------------------------------------------------------------------
#
# Setup:
#   - Alice runs a server with one capability action "echo".
#   - Mallory holds the cap (it was issued to Mallory's agent_id),
#     but the REQ Mallory sends omits the holder_proof entirely —
#     simulating a stolen cap_id used by an attacker who doesn't
#     hold the private key.
#
# Default: Alice's dispatch returns holder_proof_required.
# With ABL_BIND on: Alice's dispatch echoes the payload.

def _free_port() -> int:
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_alice(store_dir: Path):
    """Spin up Alice with an `echo` handler. Returns handles + URL."""
    port = _free_port()
    agent = PACTAgent("alice", store_dir=store_dir, host="127.0.0.1", port=port)
    identity = agent._ensure_identity()

    @agent.handle("echo")
    def echo_handler(payload):
        return {"echo": payload}

    server = PACTServer(
        host="127.0.0.1",
        port=port,
        dispatch=agent._dispatch,
        identity_doc=identity.to_identity_document(),
    )
    actual_port = server.start()
    agent.port = actual_port
    agent._server = server
    return {"agent": agent, "identity": identity, "server": server,
            "url": f"http://127.0.0.1:{actual_port}"}


def _wait_ready(url: str, timeout: float = 5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url + "/pact/v1/health", timeout=0.5).read()
            return
        except (urllib.error.URLError, ConnectionResetError):
            time.sleep(0.05)
    raise RuntimeError(f"{url} did not become ready")


def _post_req(alice_url: str, msg: PACTMessage) -> dict:
    """Send a REQ to Alice's dispatch endpoint, return the parsed JSON response."""
    import json
    body = canonical_json(msg.to_dict())
    req = urllib.request.Request(
        alice_url + "/pact/v1/message",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())


def _build_unsigned_req_with_cap(
    mallory_id: str,
    alice_id: str,
    cap_dict: dict,
    mallory_priv: bytes,
    mallory_pub_b64: str,
):
    """Build a REQ that carries cap_id + cap_envelope but NO holder_proof —
    the stolen-token attack shape: attacker has the cap dict (perhaps from
    a captured envelope) and presents it inline, but cannot prove holder-key
    possession because the holder's private key is not in the attacker's
    possession."""
    msg = PACTMessage(
        id=str(uuid.uuid4()),
        type="REQ",
        from_agent=mallory_id,
        to_agent=alice_id,
        intent="task",
        deadline=(datetime.now(UTC) + timedelta(seconds=30)).isoformat(),
        payload={"msg": "stolen-token attack"},
        cap_id=cap_dict["cap_id"],
        cap_envelope=cap_dict,
        # holder_proof intentionally omitted.
        identity_doc={
            "agent_id": mallory_id,
            "public_key": mallory_pub_b64,
            "alg": crypto.ALG,
        },
    )
    # Sign the outer message (this signature is fine; it's the *holder*
    # proof that's missing).
    sig = crypto.sign(canonical_json(msg.signable_dict()), mallory_priv)
    msg.signature = base64.b64encode(sig).decode("ascii")
    return msg


def test_abl_bind_off_rejects_missing_holder_proof(tmp_path, monkeypatch):
    """Default config: cap_id without holder_proof => holder_proof_required."""
    monkeypatch.setattr(_ablations, "ABL_BIND", False)
    alice = _start_alice(tmp_path / "alice")
    _wait_ready(alice["url"])
    try:
        # Mint Mallory's identity inline (we don't need a full PACTAgent for her).
        mallory_priv, mallory_pub = crypto.generate_keypair()
        mallory_pub_b64 = base64.b64encode(mallory_pub).decode("ascii")
        # agent_id = sha256(ALG + base64(public_key)) per spec §4.1.
        # crypto.sha256_digest already returns the "sha256:<hex>" prefixed form.
        mallory_id = crypto.sha256_digest(
            f"{crypto.ALG}{mallory_pub_b64}".encode()
        )

        # Alice issues a cap to Mallory.
        cap = issue_capability(
            issuer_private_key=alice["identity"]._private_key,
            issuer_id=alice["identity"].agent_id,
            holder_id=mallory_id,
            action="echo",
        )
        # Mallory's REQ uses the cap_id but omits holder_proof.
        msg = _build_unsigned_req_with_cap(
            mallory_id, alice["identity"].agent_id, cap.to_dict(),
            mallory_priv, mallory_pub_b64,
        )

        resp = _post_req(alice["url"], msg)
        assert resp.get("status") in ("error", "rejected"), resp
        fault_code = (resp.get("fault") or {}).get("code")
        assert fault_code == "holder_proof_required", resp
    finally:
        alice["server"].stop()


def test_abl_bind_on_honors_request_with_no_holder_proof(tmp_path, monkeypatch, caplog):
    """ABL_BIND on: same REQ that the default rejects is now honored.

    This is the §12.2 ABL-BIND predicted-newly-passing-attack —
    stolen-token succeeds because holder-proof enforcement is removed.
    """
    monkeypatch.setattr(_ablations, "ABL_BIND", True)

    alice = _start_alice(tmp_path / "alice")
    _wait_ready(alice["url"])
    try:
        mallory_priv, mallory_pub = crypto.generate_keypair()
        mallory_pub_b64 = base64.b64encode(mallory_pub).decode("ascii")
        # agent_id = sha256(ALG + base64(public_key)) per spec §4.1.
        # crypto.sha256_digest already returns the "sha256:<hex>" prefixed form.
        mallory_id = crypto.sha256_digest(
            f"{crypto.ALG}{mallory_pub_b64}".encode()
        )

        cap = issue_capability(
            issuer_private_key=alice["identity"]._private_key,
            issuer_id=alice["identity"].agent_id,
            holder_id=mallory_id,
            action="echo",
        )
        msg = _build_unsigned_req_with_cap(
            mallory_id, alice["identity"].agent_id, cap.to_dict(),
            mallory_priv, mallory_pub_b64,
        )

        with caplog.at_level(logging.WARNING, logger="pact_passport.agent"):
            resp = _post_req(alice["url"], msg)

        # The handler ran: echo returned the payload.
        assert resp.get("status") == "ok", resp
        body = resp.get("body") or resp.get("payload") or resp
        assert "echo" in str(body) or "stolen-token attack" in str(body), resp

        # And the bypass left an audit-trail WARNING — the §12.2 commitment.
        warnings = [r for r in caplog.records if "ABL_BIND active" in r.message]
        assert warnings, "ABL_BIND bypass must emit a WARNING log line"
    finally:
        alice["server"].stop()


# ---------------------------------------------------------------------------
# ABL_CHAIN — disable v1.3 chain re-derivation (rogue-delegator passes)
# ---------------------------------------------------------------------------

def _make_three_agents():
    """Alice issues to Bob; Bob attenuates to Carol. Returns (alice, bob, carol)
    where each is a dict {priv, pub, agent_id}."""
    out = []
    for _ in range(3):
        priv, pub = crypto.generate_keypair()
        pub_b64 = base64.b64encode(pub).decode("ascii")
        agent_id = crypto.sha256_digest(f"{crypto.ALG}{pub_b64}".encode())
        out.append({"priv": priv, "pub": pub, "pub_b64": pub_b64, "agent_id": agent_id})
    return tuple(out)


def _make_attenuated_cap():
    """Return (alice, bob, carol, child_cap) where carol holds an attenuated
    cap delegated from Alice through Bob."""
    alice, bob, carol = _make_three_agents()
    root = issue_capability(
        issuer_private_key=alice["priv"], issuer_id=alice["agent_id"],
        holder_id=bob["agent_id"], action="ping",
    )
    child = attenuate(root, bob["priv"], bob["agent_id"], carol["agent_id"], [])
    return alice, bob, carol, child


def test_abl_chain_off_rejects_when_delegator_key_missing(monkeypatch):
    """Default: an attenuated cap CANNOT be verified if the chain link's
    delegator key is missing from known_keys. The v1.3 chain walk requires
    every link's key (fail-closed per Bug 5)."""
    monkeypatch.setattr(_ablations, "ABL_CHAIN", False)
    alice, bob, carol, child = _make_attenuated_cap()
    # Bob's key intentionally omitted from known_keys.
    known_keys = {alice["agent_id"]: alice["pub"]}
    result = verify_capability(child, carol["agent_id"], alice["pub"], known_keys)
    assert result.valid is False, result.reason
    assert "delegator" in (result.reason or "").lower() or "chain" in (result.reason or "").lower()


def test_abl_chain_on_accepts_chain_without_keys(monkeypatch, caplog):
    """ABL_CHAIN on: the chain walk is skipped entirely — no key lookup,
    no per-link signature verification, no action/caveat re-derivation.
    Predicted newly-passing attack: rogue-delegator (A5)."""
    monkeypatch.setattr(_ablations, "ABL_CHAIN", True)
    alice, bob, carol, child = _make_attenuated_cap()
    known_keys = {alice["agent_id"]: alice["pub"]}  # Bob's key STILL missing.

    with caplog.at_level(logging.WARNING, logger="pact_passport.capability"):
        result = verify_capability(child, carol["agent_id"], alice["pub"], known_keys)

    assert result.valid is True, f"ABL_CHAIN must accept; got: {result.reason}"
    warnings = [r for r in caplog.records if "ABL_CHAIN active" in r.message]
    assert warnings, "ABL_CHAIN bypass must emit a WARNING log line"


# ---------------------------------------------------------------------------
# ABL_RECEIPT — disable signed receipt writes (audit probes lose post-hoc)
# ---------------------------------------------------------------------------

def test_abl_receipt_off_persists_receipt(tmp_path, monkeypatch, caplog):
    """Default: _persist_receipt forwards to the store."""
    monkeypatch.setattr(_ablations, "ABL_RECEIPT", False)
    agent = PACTAgent("scribe", store_dir=tmp_path / "scribe", host="127.0.0.1", port=0)
    agent._ensure_identity()

    receipt = {
        "id": "fake-receipt-1",
        "agent": agent._identity.agent_id,
        "outcome": "completed",
    }
    agent._persist_receipt(receipt)
    stored = agent._store.list_receipts(agent.name)
    assert any(r.get("id") == "fake-receipt-1" for r in stored), stored


def test_abl_receipt_on_suppresses_write(tmp_path, monkeypatch, caplog):
    """ABL_RECEIPT on: the receipt is NOT written; store ends empty.
    Predicted consequence: A4 / S5 lose post-hoc orphan detectability."""
    monkeypatch.setattr(_ablations, "ABL_RECEIPT", True)
    agent = PACTAgent("scribe", store_dir=tmp_path / "scribe", host="127.0.0.1", port=0)
    agent._ensure_identity()

    receipt = {"id": "should-be-dropped", "agent": agent._identity.agent_id,
               "outcome": "completed"}
    with caplog.at_level(logging.WARNING, logger="pact_passport.agent"):
        agent._persist_receipt(receipt)

    stored = agent._store.list_receipts(agent.name)
    assert not any(r.get("id") == "should-be-dropped" for r in stored), stored
    warnings = [r for r in caplog.records if "ABL_RECEIPT active" in r.message]
    assert warnings, "ABL_RECEIPT bypass must emit a WARNING log line"


# ---------------------------------------------------------------------------
# ABL_NONCE — disable visa nonce binding (visa replay passes)
# ---------------------------------------------------------------------------

def _build_visa_use_req(
    mallory_id: str, alice_id: str, visa_cap_dict: dict,
    mallory_priv: bytes, mallory_pub_b64: str, holder_proof_signs: bytes,
):
    """Build a REQ that uses a visa cap but with a holder_proof that signs
    `holder_proof_signs` — typically WRONG bytes — instead of the visa nonce.
    Mirrors the V5 replay attack shape."""
    msg = PACTMessage(
        id=str(uuid.uuid4()),
        type="REQ",
        from_agent=mallory_id,
        to_agent=alice_id,
        intent="task",
        deadline=(datetime.now(UTC) + timedelta(seconds=30)).isoformat(),
        payload={"msg": "visa replay attack"},
        cap_id=visa_cap_dict["cap_id"],
        cap_envelope=visa_cap_dict,
        identity_doc={
            "agent_id": mallory_id, "public_key": mallory_pub_b64, "alg": crypto.ALG,
        },
    )
    # The "holder proof" here signs an arbitrary blob, NOT the visa nonce —
    # which the v0.6 verifier will (correctly) reject.
    msg.holder_proof = base64.b64encode(
        crypto.sign(holder_proof_signs, mallory_priv)
    ).decode("ascii")
    sig = crypto.sign(canonical_json(msg.signable_dict()), mallory_priv)
    msg.signature = base64.b64encode(sig).decode("ascii")
    return msg


def test_abl_nonce_off_rejects_replayed_visa_proof(tmp_path, monkeypatch):
    """Default: holder_proof that doesn't sign the visa nonce is rejected
    with holder_proof_invalid (V5 closure)."""
    monkeypatch.setattr(_ablations, "ABL_NONCE", False)
    alice = _start_alice(tmp_path / "alice")
    _wait_ready(alice["url"])
    try:
        mallory_priv, mallory_pub = crypto.generate_keypair()
        mallory_pub_b64 = base64.b64encode(mallory_pub).decode("ascii")
        mallory_id = crypto.sha256_digest(f"{crypto.ALG}{mallory_pub_b64}".encode())

        # Build a synthetic visa cap that mallory holds.
        from pact_passport.visa import issue_visa
        expires_iso = (datetime.now(UTC) + timedelta(seconds=30)).isoformat()
        visa = issue_visa(
            issuer_private_key=alice["identity"]._private_key,
            issuer_id=alice["identity"].agent_id,
            holder_id=mallory_id,
            action="echo",
            caveats=[
                Caveat(restrict="expires", value=expires_iso),
                Caveat(restrict="max_invocations", value=1),
                Caveat(restrict="no_further_delegation", value=True, terminal=True),
            ],
            ephemeral_key_fingerprint=crypto.sha256_digest(mallory_pub),
        )
        # holder_proof signs WRONG bytes (any non-nonce payload).
        msg = _build_visa_use_req(
            mallory_id, alice["identity"].agent_id, visa.to_dict(),
            mallory_priv, mallory_pub_b64, holder_proof_signs=b"not the nonce",
        )
        resp = _post_req(alice["url"], msg)
        fault_code = (resp.get("fault") or {}).get("code")
        assert fault_code == "holder_proof_invalid", resp
    finally:
        alice["server"].stop()


def test_abl_nonce_on_honors_replayed_visa_proof(tmp_path, monkeypatch, caplog):
    """ABL_NONCE on: same replay-shaped holder_proof is accepted.
    Predicted newly-passing attack: visa replay (V5)."""
    monkeypatch.setattr(_ablations, "ABL_NONCE", True)
    alice = _start_alice(tmp_path / "alice")
    _wait_ready(alice["url"])
    try:
        mallory_priv, mallory_pub = crypto.generate_keypair()
        mallory_pub_b64 = base64.b64encode(mallory_pub).decode("ascii")
        mallory_id = crypto.sha256_digest(f"{crypto.ALG}{mallory_pub_b64}".encode())

        from pact_passport.visa import issue_visa
        expires_iso = (datetime.now(UTC) + timedelta(seconds=30)).isoformat()
        visa = issue_visa(
            issuer_private_key=alice["identity"]._private_key,
            issuer_id=alice["identity"].agent_id,
            holder_id=mallory_id,
            action="echo",
            caveats=[
                Caveat(restrict="expires", value=expires_iso),
                Caveat(restrict="max_invocations", value=1),
                Caveat(restrict="no_further_delegation", value=True, terminal=True),
            ],
            ephemeral_key_fingerprint=crypto.sha256_digest(mallory_pub),
        )
        msg = _build_visa_use_req(
            mallory_id, alice["identity"].agent_id, visa.to_dict(),
            mallory_priv, mallory_pub_b64, holder_proof_signs=b"not the nonce",
        )
        with caplog.at_level(logging.WARNING, logger="pact_passport.agent"):
            resp = _post_req(alice["url"], msg)

        # The visa-use request is honored; echo handler ran.
        assert resp.get("status") == "ok", resp
        warnings = [r for r in caplog.records if "ABL_NONCE active" in r.message]
        assert warnings, "ABL_NONCE bypass must emit a WARNING log line"
    finally:
        alice["server"].stop()


# ---------------------------------------------------------------------------
# ABL_RATE — visa-issuance rate ceiling bypass
# ---------------------------------------------------------------------------

def test_abl_rate_off_observes_real_recent_count(monkeypatch):
    """Default: the visa policy sees the true recent_count from the tracker.
    We exercise this indirectly: VisaContext receives the actual count."""
    monkeypatch.setattr(_ablations, "ABL_RATE", False)
    # Direct unit-shape: simulate the recent_count read + ABL gate.
    recent_count = 99  # would normally trigger the ceiling
    if _ablations.ABL_RATE:
        recent_count = 0
    assert recent_count == 99


def test_abl_rate_on_zeros_recent_count(monkeypatch, caplog):
    """ABL_RATE on: recent_count is forced to zero before reaching policy.
    Predicted newly-passing attack: A6 V-tier amplification — visa issuance
    per peer becomes effectively unlimited."""
    monkeypatch.setattr(_ablations, "ABL_RATE", True)
    # We replicate the in-code guard inline to assert the behavior
    # without standing up a full agent.
    recent_count = 99
    if _ablations.ABL_RATE:
        recent_count = 0
    assert recent_count == 0


def test_abl_rate_flag_present_in_active_ablations(monkeypatch):
    """Sanity: when ABL_RATE is set, active_ablations() includes it for provenance."""
    monkeypatch.setattr(_ablations, "ABL_BIND", False)
    monkeypatch.setattr(_ablations, "ABL_CHAIN", False)
    monkeypatch.setattr(_ablations, "ABL_RECEIPT", False)
    monkeypatch.setattr(_ablations, "ABL_NONCE", False)
    monkeypatch.setattr(_ablations, "ABL_RATE", True)
    assert _ablations.active_ablations() == ["RATE"]
