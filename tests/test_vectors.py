"""Test vectors: verify implementation matches known-good outputs.

These vectors are the interop contract. If another implementation
produces the same outputs for the same inputs, it is PACT-compatible.
"""

import base64
import json
from pathlib import Path

import pytest

from nacl.signing import SigningKey
from pact_passport import crypto
from pact_passport._canonical import canonical_json


VECTORS_PATH = Path(__file__).parent / "vectors" / "pact_v1_vectors.json"


@pytest.fixture(scope="module")
def vectors():
    return json.loads(VECTORS_PATH.read_text())


@pytest.fixture(scope="module")
def keys(vectors):
    """Load known keypairs from vectors."""
    result = {}
    for name, kp in vectors["keypairs"].items():
        seed = bytes.fromhex(kp["seed_hex"])
        sk = SigningKey(seed)
        result[name] = {
            "priv": bytes(sk),
            "pub": bytes(sk.verify_key),
            "pub_b64": kp["public_key_b64"],
            "agent_id": kp["agent_id"],
        }
    return result


# --- Keypair derivation ---

class TestKeypairs:
    def test_public_key_derivation(self, vectors, keys):
        """Public keys derived from seeds match vectors."""
        for name, kp in vectors["keypairs"].items():
            assert keys[name]["pub_b64"] == kp["public_key_b64"]

    def test_agent_id_derivation(self, vectors, keys):
        """Agent IDs derived from public keys match vectors."""
        for name, kp in vectors["keypairs"].items():
            pub_b64 = kp["public_key_b64"]
            expected_id = kp["agent_id"]
            computed_id = crypto.sha256_digest(f"{crypto.ALG}{pub_b64}".encode())
            assert computed_id == expected_id, f"Agent ID mismatch for {name}"


# --- Canonical JSON ---

class TestCanonicalJSON:
    def test_canonical_bytes(self, vectors):
        """Canonical JSON produces expected byte output."""
        v = vectors["canonical_json"]
        result = canonical_json(v["input"])
        assert result.hex() == v["expected_bytes_hex"]

    def test_canonical_string(self, vectors):
        """Canonical JSON produces expected string (sorted keys, no whitespace)."""
        v = vectors["canonical_json"]
        result = canonical_json(v["input"]).decode()
        assert result == v["expected_string"]


# --- SHA-256 ---

class TestSHA256:
    def test_digest(self, vectors):
        v = vectors["sha256_digest"]
        result = crypto.sha256_digest(bytes.fromhex(v["input_hex"]))
        assert result == v["expected"]


# --- Signatures ---

class TestSignatures:
    def test_sign_known_message(self, vectors, keys):
        """Signing a known message with a known key produces the expected signature."""
        v = vectors["signature"]
        message = bytes.fromhex(v["message_hex"])
        priv = keys["agent_a"]["priv"]
        sig = crypto.sign(message, priv)
        assert base64.b64encode(sig).decode() == v["signature_b64"]

    def test_verify_known_signature(self, vectors, keys):
        """Known signature verifies against known public key."""
        v = vectors["signature"]
        message = bytes.fromhex(v["message_hex"])
        sig = base64.b64decode(v["signature_b64"])
        pub = base64.b64decode(v["verify_with_public_key"])
        assert crypto.verify(message, sig, pub)


# --- Inception event ---

class TestInceptionEvent:
    def test_canonical_form(self, vectors):
        """Inception event canonical bytes match."""
        v = vectors["inception_event"]
        result = canonical_json(v["unsigned"])
        assert result.hex() == v["canonical_bytes_hex"]

    def test_signature(self, vectors, keys):
        """Inception event signature matches."""
        v = vectors["inception_event"]
        canonical = bytes.fromhex(v["canonical_bytes_hex"])
        sig = crypto.sign(canonical, keys["agent_a"]["priv"])
        assert base64.b64encode(sig).decode() == v["signature_b64"]

    def test_verify(self, vectors, keys):
        """Inception event signature verifies."""
        v = vectors["inception_event"]
        canonical = bytes.fromhex(v["canonical_bytes_hex"])
        sig = base64.b64decode(v["signature_b64"])
        assert crypto.verify(canonical, sig, keys["agent_a"]["pub"])


# --- Capability token ---

class TestCapabilityToken:
    def test_canonical_form(self, vectors):
        v = vectors["capability_token"]
        result = canonical_json(v["unsigned"])
        assert result.hex() == v["canonical_bytes_hex"]

    def test_signature(self, vectors, keys):
        v = vectors["capability_token"]
        canonical = bytes.fromhex(v["canonical_bytes_hex"])
        sig = crypto.sign(canonical, keys["agent_a"]["priv"])
        assert base64.b64encode(sig).decode() == v["signature_b64"]

    def test_verify(self, vectors, keys):
        v = vectors["capability_token"]
        canonical = bytes.fromhex(v["canonical_bytes_hex"])
        sig = base64.b64decode(v["signature_b64"])
        assert crypto.verify(canonical, sig, keys["agent_a"]["pub"])


# --- REQ message ---

class TestREQMessage:
    def test_canonical_form(self, vectors):
        v = vectors["req_message"]
        result = canonical_json(v["unsigned"])
        assert result.hex() == v["canonical_bytes_hex"]

    def test_signature(self, vectors, keys):
        v = vectors["req_message"]
        canonical = bytes.fromhex(v["canonical_bytes_hex"])
        sig = crypto.sign(canonical, keys["agent_b"]["priv"])
        assert base64.b64encode(sig).decode() == v["signature_b64"]

    def test_holder_proof(self, vectors, keys):
        """Holder proof signs the message ID with holder's key."""
        v = vectors["req_message"]
        msg_id = v["unsigned"]["id"].encode()
        proof = crypto.sign(msg_id, keys["agent_b"]["priv"])
        assert base64.b64encode(proof).decode() == v["holder_proof_b64"]

    def test_verify(self, vectors, keys):
        v = vectors["req_message"]
        canonical = bytes.fromhex(v["canonical_bytes_hex"])
        sig = base64.b64decode(v["signature_b64"])
        assert crypto.verify(canonical, sig, keys["agent_b"]["pub"])


# --- RES message ---

class TestRESMessage:
    def test_canonical_form(self, vectors):
        v = vectors["res_message"]
        result = canonical_json(v["unsigned"])
        assert result.hex() == v["canonical_bytes_hex"]

    def test_signature(self, vectors, keys):
        v = vectors["res_message"]
        canonical = bytes.fromhex(v["canonical_bytes_hex"])
        sig = crypto.sign(canonical, keys["agent_a"]["priv"])
        assert base64.b64encode(sig).decode() == v["signature_b64"]

    def test_verify(self, vectors, keys):
        v = vectors["res_message"]
        canonical = bytes.fromhex(v["canonical_bytes_hex"])
        sig = base64.b64decode(v["signature_b64"])
        assert crypto.verify(canonical, sig, keys["agent_a"]["pub"])


# --- Receipt ---

class TestReceipt:
    def test_canonical_form(self, vectors):
        v = vectors["receipt"]
        result = canonical_json(v["unsigned"])
        assert result.hex() == v["canonical_bytes_hex"]

    def test_signature(self, vectors, keys):
        v = vectors["receipt"]
        canonical = bytes.fromhex(v["canonical_bytes_hex"])
        sig = crypto.sign(canonical, keys["agent_b"]["priv"])
        assert base64.b64encode(sig).decode() == v["signature_b64"]

    def test_verify(self, vectors, keys):
        v = vectors["receipt"]
        canonical = bytes.fromhex(v["canonical_bytes_hex"])
        sig = base64.b64decode(v["signature_b64"])
        assert crypto.verify(canonical, sig, keys["agent_b"]["pub"])


# --- Cross-check: determinism ---

class TestDeterminism:
    def test_vectors_are_reproducible(self, vectors):
        """Re-running the generator produces identical output."""
        import subprocess, sys
        result = subprocess.run(
            [sys.executable, str(Path(__file__).parent / "vectors" / "generate_vectors.py")],
            capture_output=True, text=True,
        )
        regenerated = json.loads(result.stdout)
        assert regenerated == vectors, "Vectors are not deterministic across runs"
