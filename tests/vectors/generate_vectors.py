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

    # ============================================================
    # v0.2 — v0.5 vectors (added 2026-05-03, see spec/PACT_v1.md §12)
    # ============================================================

    # --- 11. Rotation event (post-inception, sequence=1) ---
    # Agent A's pre-rotation commitment is in the inception event;
    # for the test vector we use a fresh "next" key derived from a
    # different fixed seed.
    seed_a_next = "1" * 64  # 32 bytes of 0x11
    seed_a_fresh_next = "2" * 64  # 32 bytes of 0x22
    priv_a_next, pub_a_next = keypair_from_seed(seed_a_next)
    _, pub_a_fresh_next = keypair_from_seed(seed_a_fresh_next)
    pub_a_next_b64 = base64.b64encode(pub_a_next).decode()

    # Re-derive inception with a known next_keys_digest for chaining
    inception_with_next = {
        "agent_id": agent_id_a,
        "event_type": "inception",
        "sequence": 0,
        "current_keys": [pub_a_b64],
        "next_keys_digest": crypto.sha256_digest(pub_a_next),
        "alg": crypto.ALG,
    }
    inception_with_next_canonical = canonical_json(inception_with_next)
    inception_with_next_sig = crypto.sign(inception_with_next_canonical, priv_a)
    inception_with_next["signature"] = base64.b64encode(inception_with_next_sig).decode()
    prior_signable = {k: v for k, v in inception_with_next.items() if k != "signature"}
    prior_digest = crypto.sha256_digest(canonical_json(prior_signable))

    rotation = {
        "agent_id": agent_id_a,
        "event_type": "rotation",
        "sequence": 1,
        "prior_event_digest": prior_digest,
        "current_keys": [pub_a_next_b64],
        "next_keys_digest": crypto.sha256_digest(pub_a_fresh_next),
        "alg": crypto.ALG,
    }
    rotation_canonical = canonical_json(rotation)
    # Rotation event is signed with the NEW key (pre-rotated), not old
    rotation_sig = crypto.sign(rotation_canonical, priv_a_next)
    rotation_signed = dict(rotation)
    rotation_signed["signature"] = base64.b64encode(rotation_sig).decode()

    vectors["rotation_event"] = {
        "prior_inception": inception_with_next,
        "unsigned": rotation,
        "canonical_bytes_hex": rotation_canonical.hex(),
        "signature_b64": base64.b64encode(rotation_sig).decode(),
        "signed": rotation_signed,
        "note": "rotation event is signed by the NEW current key (pre-rotated commitment)",
    }

    # --- 12. Attenuated capability token (delegation chain length 1) ---
    # Alice issues to Bob (root, in vectors[capability_token] above).
    # Bob attenuates and grants to Charlie with tighter max_invocations.
    chain_link_sig = crypto.sign("test-cap-001".encode(), priv_b)

    attenuated_cap = {
        "cap_id": "test-cap-002-attenuated",
        "issuer": agent_id_a,  # root issuer preserved
        "holder": agent_id_c,
        "action": "read_data",
        "caveats": [
            {"restrict": "expires", "value": "2099-12-31T23:59:59+00:00"},
            {"restrict": "max_invocations", "value": 10},
            {"restrict": "max_invocations", "value": 3},  # tighter than parent
        ],
        "parent": "test-cap-001",
        "delegation_chain": [
            {"from": agent_id_b, "sig": base64.b64encode(chain_link_sig).decode()},
        ],
        "alg": crypto.ALG,
    }
    attenuated_canonical = canonical_json(attenuated_cap)
    attenuated_sig = crypto.sign(attenuated_canonical, priv_b)  # signed by delegator
    attenuated_signed = dict(attenuated_cap)
    attenuated_signed["signature"] = base64.b64encode(attenuated_sig).decode()

    vectors["attenuated_capability"] = {
        "unsigned": attenuated_cap,
        "canonical_bytes_hex": attenuated_canonical.hex(),
        "signature_b64": base64.b64encode(attenuated_sig).decode(),
        "signed": attenuated_signed,
        "note": "attenuated cap signed by the last delegator (Bob), not the root issuer",
    }

    # --- 13. REQ with identity_doc (TOFU handshake, v0.2.0) ---
    identity_doc_for_b = {
        "agent_id": agent_id_b,
        "alg": crypto.ALG,
        "public_key": pub_b_b64,
        "next_key_digest": crypto.sha256_digest(pub_a_next),  # arbitrary commitment
    }
    req_with_doc = {
        "id": "test-msg-tofu-001",
        "type": "REQ",
        "from_agent": agent_id_b,
        "to_agent": agent_id_a,
        "refs": [],
        "intent": "task",
        "deadline": "2099-12-31T23:59:59+00:00",
        "idempotency_key": "test-idem-tofu-001",
        "payload": {"action": "ping"},
        "identity_doc": identity_doc_for_b,
        "alg": crypto.ALG,
    }
    req_doc_canonical = canonical_json(req_with_doc)
    req_doc_sig = crypto.sign(req_doc_canonical, priv_b)
    req_doc_signed = dict(req_with_doc)
    req_doc_signed["signature"] = base64.b64encode(req_doc_sig).decode()

    vectors["req_with_identity_doc"] = {
        "unsigned": req_with_doc,
        "canonical_bytes_hex": req_doc_canonical.hex(),
        "signature_b64": base64.b64encode(req_doc_sig).decode(),
        "signed": req_doc_signed,
        "note": "TOFU handshake — receiver verifies agent_id derives from doc.public_key",
    }

    # --- 14. REQ with cap_envelope (cross-machine delegation, v0.4.0) ---
    req_with_envelope = {
        "id": "test-msg-env-001",
        "type": "REQ",
        "from_agent": agent_id_c,
        "to_agent": agent_id_a,
        "refs": [],
        "intent": "task",
        "cap_id": "test-cap-002-attenuated",
        "deadline": "2099-12-31T23:59:59+00:00",
        "idempotency_key": "test-idem-env-001",
        "payload": {"action": "read_data"},
        "cap_envelope": attenuated_signed,
        "alg": crypto.ALG,
    }
    holder_proof_c = crypto.sign(req_with_envelope["id"].encode(), priv_c)
    req_with_envelope["holder_proof"] = base64.b64encode(holder_proof_c).decode()
    req_env_canonical = canonical_json(req_with_envelope)
    req_env_sig = crypto.sign(req_env_canonical, priv_c)
    req_env_signed = dict(req_with_envelope)
    req_env_signed["signature"] = base64.b64encode(req_env_sig).decode()

    vectors["req_with_cap_envelope"] = {
        "unsigned": req_with_envelope,
        "canonical_bytes_hex": req_env_canonical.hex(),
        "signature_b64": base64.b64encode(req_env_sig).decode(),
        "signed": req_env_signed,
        "note": "Carol presents Bob-attenuated cap to Alice, including full envelope",
    }

    # --- 15. RES_CHUNK messages (streaming, v0.5.0) ---
    chunks = []
    for i in range(3):
        chunk = {
            "id": f"test-chunk-{i:03d}",
            "type": "RES_CHUNK",
            "from_agent": agent_id_a,
            "to_agent": agent_id_b,
            "refs": ["test-msg-stream-001"],
            "intent": "task",
            "payload": {"text": f"chunk {i}"},
            "status": "ok",
            "chunk_seq": i,
            "chunk_final": i == 2,
            "alg": crypto.ALG,
        }
        chunk_canonical = canonical_json(chunk)
        chunk_sig = crypto.sign(chunk_canonical, priv_a)
        chunk_signed = dict(chunk)
        chunk_signed["signature"] = base64.b64encode(chunk_sig).decode()
        chunks.append({
            "unsigned": chunk,
            "canonical_bytes_hex": chunk_canonical.hex(),
            "signature_b64": base64.b64encode(chunk_sig).decode(),
            "signed": chunk_signed,
        })

    vectors["res_chunks"] = {
        "stream": chunks,
        "note": "each chunk independently signed; tampering with chunk_seq or chunk_final invalidates that chunk only",
    }

    # --- 16. Error RES with fault (v0.2.0+ standard codes) ---
    error_res = {
        "id": "test-msg-err-001",
        "type": "RES",
        "from_agent": agent_id_a,
        "to_agent": agent_id_b,
        "refs": ["test-msg-001"],
        "intent": "task",
        "payload": {},
        "status": "error",
        "fault": {
            "code": "holder_proof_required",
            "detail": "holder_proof is mandatory when cap_id is present",
        },
        "alg": crypto.ALG,
    }
    error_canonical = canonical_json(error_res)
    error_sig = crypto.sign(error_canonical, priv_a)
    error_signed = dict(error_res)
    error_signed["signature"] = base64.b64encode(error_sig).decode()

    vectors["error_res"] = {
        "unsigned": error_res,
        "canonical_bytes_hex": error_canonical.hex(),
        "signature_b64": base64.b64encode(error_sig).decode(),
        "signed": error_signed,
        "note": "v0.2.0+ standard fault codes: unknown_peer, holder_proof_required, cap_unknown, handler_error",
    }

    print(json.dumps(vectors, indent=2))


if __name__ == "__main__":
    main()
