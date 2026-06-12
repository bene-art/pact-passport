"""A1: Cryptographic Line Integrity.

Tests signature invariance under transport serialization.

Adversarial vector: single-bit mutations in the Ed25519 signature
(applied to the decoded signature bytes, then re-encoded). N=10,000
trials at the verify_message level (fast); plus N=100 trials over the
HTTP dispatch path to confirm end-to-end integration.

Pre-registered prediction: 100% detection — every mutated signature
must be rejected by verify_message returning False (no exception
propagation; v0.5.3 honesty patch confirmed fail-closed behavior).
"""

from __future__ import annotations

import base64
import json
import random
import urllib.error
import urllib.request

import pytest

from pact_passport import crypto
from pact_passport.identity import Identity
from pact_passport.message import build_req, verify_message

from tests.integration.conftest import post_message


# ---------------------------------------------------------------------------
# A1 — direct verify_message bit-flip (N=10,000 trials)
# ---------------------------------------------------------------------------


def _build_signed_req():
    """Build a valid REQ with a fresh keypair. Returns (msg_dict, public_key_bytes)."""
    priv, pub = crypto.generate_keypair()
    pub_b64 = base64.b64encode(pub).decode()
    agent_id = crypto.sha256_digest(f"Ed25519{pub_b64}".encode())

    msg = build_req(
        from_private_key=priv,
        from_id=agent_id,
        to_id=agent_id,  # self-addressed; we're only testing verify_message
        intent="task",
        payload={"action": "echo", "msg": "hello"},
        deadline_seconds=30,
    )
    return msg, pub


def _flip_one_bit_in_signature(msg) -> None:
    """Mutate the message's signature field by flipping a single bit in
    the decoded signature bytes. Re-encodes and stores back."""
    sig_bytes = bytearray(base64.b64decode(msg.signature))
    byte_idx = random.randrange(len(sig_bytes))
    bit_idx = random.randrange(8)
    sig_bytes[byte_idx] ^= (1 << bit_idx)
    msg.signature = base64.b64encode(bytes(sig_bytes)).decode()


def test_a1_signature_bit_flip_detection_rate(capsys):
    """N=10,000 trials of single-bit mutations on the signature field.
    Every mutation must be detected (verify_message returns False).
    """
    N = 10_000
    rejected = 0
    accepted_after_mutation = 0

    # Build one valid REQ; sanity-check verify_message accepts it
    msg, pub = _build_signed_req()
    assert verify_message(msg, pub), "control: unmutated valid signature must verify"

    original_sig = msg.signature

    for _ in range(N):
        # Reset to a known-good signature
        msg.signature = original_sig
        # Mutate one bit
        _flip_one_bit_in_signature(msg)
        # Verify must reject
        if verify_message(msg, pub):
            accepted_after_mutation += 1
        else:
            rejected += 1

    detection_rate = rejected / N
    print(f"\n[A1] N={N} trials | rejected={rejected} accepted={accepted_after_mutation}")
    print(f"[A1] detection_rate={detection_rate:.6f}")

    # Pre-registered: 100% detection
    assert accepted_after_mutation == 0, (
        f"detection rate {detection_rate:.6f}; "
        f"{accepted_after_mutation}/{N} mutated signatures were ACCEPTED — "
        f"FINDING_LINE_INTEGRITY_VIOLATED"
    )
    assert rejected == N


def test_a1_signature_bit_flip_via_http_dispatch(sandbox, capsys):
    """N=100 trials sending bit-flipped signatures over HTTP to the sandbox
    server. Confirms the end-to-end dispatch path also rejects (not just
    verify_message in isolation).
    """
    alice = sandbox["alice"]
    bob = sandbox["bob"]
    bob_id = bob["agent"]._ensure_identity()

    # Register a handler on Alice
    @alice["agent"].handle("echo")
    def _h(payload):
        return {"echoed": payload}

    cap = alice["agent"].grant(bob["agent_id"], "echo")
    bob["agent"]._store.save_capability(bob["name"], cap.to_dict())

    N = 100
    rejected = 0
    dispatched = 0

    for _ in range(N):
        msg = build_req(
            from_private_key=bob_id._private_key,
            from_id=bob["agent_id"],
            to_id=alice["agent_id"],
            intent="task",
            payload={"action": "echo", "msg": "x"},
            cap_id=cap.cap_id,
            holder_proof_key=bob_id._private_key,
            deadline_seconds=30,
        )
        _flip_one_bit_in_signature(msg)
        result = post_message(alice["url"], msg.to_dict())
        if result.get("status") == "ok":
            dispatched += 1
        else:
            rejected += 1

    print(f"\n[A1-HTTP] N={N} | rejected={rejected} dispatched={dispatched}")

    # Pre-registered: every mutated signature rejected end-to-end
    assert dispatched == 0, (
        f"{dispatched}/{N} bit-flipped REQs were DISPATCHED end-to-end — "
        f"FINDING_DISPATCH_PATH_LEAKS_INVALID_SIGNATURE"
    )
    assert rejected == N
