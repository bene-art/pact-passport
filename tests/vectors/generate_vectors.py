#!/usr/bin/env python3
"""Generate deterministic test vectors for PACT protocol interop testing.

Uses fixed seeds so the output is reproducible across runs.
Run: python tests/vectors/generate_vectors.py > tests/vectors/pact_v1_vectors.json
"""

import base64
import json
import sys
import os

# Ensure pact is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from nacl.signing import SigningKey
from pact import crypto
from pact._canonical import canonical_json


def keypair_from_seed(seed_hex: str) -> tuple[bytes, bytes]:
    """Generate a deterministic keypair from a 32-byte hex seed."""
    seed = bytes.fromhex(seed_hex)
    sk = SigningKey(seed)
    return bytes(sk), bytes(sk.verify_key)


def main():
    vectors = {"version": "1", "generated_by": "pact-protocol reference implementation"}

    # --- 1. Known keypairs ---
    # Fixed seeds for reproducibility
    seed_a = "a" * 64  # 32 bytes of 0xaa
    seed_b = "b" * 64  # 32 bytes of 0xbb
    seed_c = "c" * 64  # 32 bytes of 0xcc

    priv_a, pub_a = keypair_from_seed(seed_a)
    priv_b, pub_b = keypair_from_seed(seed_b)
    priv_c, pub_c = keypair_from_seed(seed_c)

    pub_a_b64 = base64.b64encode(pub_a).decode()
    pub_b_b64 = base64.b64encode(pub_b).decode()
    pub_c_b64 = base64.b64encode(pub_c).decode()

    agent_id_a = crypto.sha256_digest(f"{crypto.ALG}{pub_a_b64}".encode())
    agent_id_b = crypto.sha256_digest(f"{crypto.ALG}{pub_b_b64}".encode())
    agent_id_c = crypto.sha256_digest(f"{crypto.ALG}{pub_c_b64}".encode())

    vectors["keypairs"] = {
        "agent_a": {
            "seed_hex": seed_a,
            "public_key_b64": pub_a_b64,
            "agent_id": agent_id_a,
        },
        "agent_b": {
            "seed_hex": seed_b,
            "public_key_b64": pub_b_b64,
            "agent_id": agent_id_b,
        },
        "agent_c": {
            "seed_hex": seed_c,
            "public_key_b64": pub_c_b64,
            "agent_id": agent_id_c,
        },
    }

    # --- 2. Canonical JSON ---
    test_obj = {"z_last": 1, "a_first": 2, "m_middle": "hello"}
    canonical = canonical_json(test_obj)

    vectors["canonical_json"] = {
        "input": test_obj,
        "expected_bytes_hex": canonical.hex(),
        "expected_string": canonical.decode(),
    }

    # --- 3. Signature ---
    message = b"PACT test vector message"
    sig_a = crypto.sign(message, priv_a)

    vectors["signature"] = {
        "message_hex": message.hex(),
        "signer": "agent_a",
        "signature_b64": base64.b64encode(sig_a).decode(),
        "verify_with_public_key": pub_a_b64,
    }

    # --- 4. SHA-256 digest ---
    digest_input = b"pact-digest-test"
    digest = crypto.sha256_digest(digest_input)

    vectors["sha256_digest"] = {
        "input_hex": digest_input.hex(),
        "expected": digest,
    }

    # --- 5. Agent ID derivation ---
    vectors["agent_id_derivation"] = {
        "algorithm": crypto.ALG,
        "formula": "sha256(ALG + base64(public_key))",
        "input_string": f"{crypto.ALG}{pub_a_b64}",
        "expected_agent_id": agent_id_a,
    }

    # --- 6. Inception event ---
    next_key_digest = crypto.sha256_digest(pub_b)  # using B as "next" key for A

    inception = {
        "agent_id": agent_id_a,
        "event_type": "inception",
        "sequence": 0,
        "current_keys": [pub_a_b64],
        "next_keys_digest": next_key_digest,
        "alg": crypto.ALG,
    }
    inception_canonical = canonical_json(inception)
    inception_sig = crypto.sign(inception_canonical, priv_a)
    inception_signed = dict(inception)
    inception_signed["signature"] = base64.b64encode(inception_sig).decode()

    vectors["inception_event"] = {
        "unsigned": inception,
        "canonical_bytes_hex": inception_canonical.hex(),
        "signature_b64": base64.b64encode(inception_sig).decode(),
        "signed": inception_signed,
    }

    # --- 7. Capability token ---
    cap_dict = {
        "cap_id": "test-cap-001",
        "issuer": agent_id_a,
        "holder": agent_id_b,
        "action": "read_data",
        "caveats": [
            {"restrict": "expires", "value": "2099-12-31T23:59:59+00:00"},
            {"restrict": "max_invocations", "value": 10},
        ],
        "alg": crypto.ALG,
    }
    cap_canonical = canonical_json(cap_dict)
    cap_sig = crypto.sign(cap_canonical, priv_a)

    cap_signed = dict(cap_dict)
    cap_signed["signature"] = base64.b64encode(cap_sig).decode()

    vectors["capability_token"] = {
        "unsigned": cap_dict,
        "canonical_bytes_hex": cap_canonical.hex(),
        "signature_b64": base64.b64encode(cap_sig).decode(),
        "signed": cap_signed,
    }

    # --- 8. REQ message ---
    req_dict = {
        "id": "test-msg-001",
        "type": "REQ",
        "from_agent": agent_id_b,
        "to_agent": agent_id_a,
        "refs": [],
        "intent": "task",
        "cap_id": "test-cap-001",
        "deadline": "2099-12-31T23:59:59+00:00",
        "idempotency_key": "test-idem-001",
        "payload": {"action": "read_data", "query": "all"},
        "alg": crypto.ALG,
    }

    # Holder proof: sign message ID with holder's key
    holder_proof_sig = crypto.sign(req_dict["id"].encode(), priv_b)
    req_dict["holder_proof"] = base64.b64encode(holder_proof_sig).decode()

    req_canonical = canonical_json(req_dict)
    req_sig = crypto.sign(req_canonical, priv_b)

    req_signed = dict(req_dict)
    req_signed["signature"] = base64.b64encode(req_sig).decode()

    vectors["req_message"] = {
        "unsigned": req_dict,
        "holder_proof_b64": req_dict["holder_proof"],
        "canonical_bytes_hex": req_canonical.hex(),
        "signature_b64": base64.b64encode(req_sig).decode(),
        "signed": req_signed,
    }

    # --- 9. RES message ---
    res_dict = {
        "id": "test-msg-002",
        "type": "RES",
        "from_agent": agent_id_a,
        "to_agent": agent_id_b,
        "refs": ["test-msg-001"],
        "intent": "task",
        "payload": {"data": "secret_value"},
        "status": "ok",
        "alg": crypto.ALG,
    }
    res_canonical = canonical_json(res_dict)
    res_sig = crypto.sign(res_canonical, priv_a)

    res_signed = dict(res_dict)
    res_signed["signature"] = base64.b64encode(res_sig).decode()

    vectors["res_message"] = {
        "unsigned": res_dict,
        "canonical_bytes_hex": res_canonical.hex(),
        "signature_b64": base64.b64encode(res_sig).decode(),
        "signed": res_signed,
    }

    # --- 10. Receipt ---
    receipt_dict = {
        "type": "receipt",
        "agent": agent_id_b,
        "task_ref": "test-msg-001",
        "refs": ["test-msg-001", "test-msg-002"],
        "outcome": "completed",
        "timestamp": "2099-01-01T00:00:00+00:00",
        "alg": crypto.ALG,
    }
    receipt_canonical = canonical_json(receipt_dict)
    receipt_sig = crypto.sign(receipt_canonical, priv_b)

    receipt_signed = dict(receipt_dict)
    receipt_signed["signature"] = base64.b64encode(receipt_sig).decode()

    vectors["receipt"] = {
        "unsigned": receipt_dict,
        "canonical_bytes_hex": receipt_canonical.hex(),
        "signature_b64": base64.b64encode(receipt_sig).decode(),
        "signed": receipt_signed,
    }

    print(json.dumps(vectors, indent=2))


if __name__ == "__main__":
    main()
