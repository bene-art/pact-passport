"""All cryptography in one file.

No other module in pact imports nacl directly. This isolates the
cryptographic dependency so a post-quantum swap is a single-file change.
"""

from __future__ import annotations

import hashlib

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
from nacl.encoding import RawEncoder

ALG = "Ed25519"


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair.

    Returns (private_key_seed_32bytes, public_key_32bytes).
    """
    sk = SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


def sign(message: bytes, private_key: bytes) -> bytes:
    """Sign a message with an Ed25519 private key.

    Returns the 64-byte signature.
    """
    sk = SigningKey(private_key)
    signed = sk.sign(message, encoder=RawEncoder)
    return signed.signature


def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify an Ed25519 signature.

    Returns True if valid, False otherwise. Never raises.
    """
    try:
        vk = VerifyKey(public_key)
        vk.verify(message, signature, encoder=RawEncoder)
        return True
    except (BadSignatureError, Exception):
        return False


def sha256_digest(data: bytes) -> str:
    """Compute SHA-256 and return as 'sha256:<hex>' string."""
    h = hashlib.sha256(data).hexdigest()
    return f"sha256:{h}"
