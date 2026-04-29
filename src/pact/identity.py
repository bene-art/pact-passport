"""Agent identity: Ed25519 keypair, agent_id derivation, key event log with pre-rotation."""

from __future__ import annotations

import base64
from pathlib import Path

from pact import crypto
from pact._canonical import canonical_json
from pact.store import PACTStore


class Identity:
    """A PACT agent identity backed by Ed25519 keys with pre-rotation commitment."""

    def __init__(
        self,
        name: str,
        agent_id: str,
        private_key: bytes,
        public_key: bytes,
        next_private_key: bytes,
        next_public_key: bytes,
        store: PACTStore,
    ):
        self.name = name
        self.agent_id = agent_id
        self._private_key = private_key
        self.public_key = public_key
        self._next_private_key = next_private_key
        self._next_public_key = next_public_key
        self._store = store

    @classmethod
    def create(cls, name: str, store: PACTStore | None = None) -> Identity:
        """Generate a new identity with inception event and pre-rotation commitment."""
        store = store or PACTStore()

        # Generate current and next (pre-rotated) keypairs
        priv, pub = crypto.generate_keypair()
        next_priv, next_pub = crypto.generate_keypair()

        # agent_id = sha256(alg + base64(public_key))
        pub_b64 = base64.b64encode(pub).decode("ascii")
        agent_id = crypto.sha256_digest(f"{crypto.ALG}{pub_b64}".encode())

        # Build inception event
        next_key_digest = crypto.sha256_digest(next_pub)
        inception = {
            "agent_id": agent_id,
            "event_type": "inception",
            "sequence": 0,
            "current_keys": [pub_b64],
            "next_keys_digest": next_key_digest,
            "alg": crypto.ALG,
        }
        sig = crypto.sign(canonical_json(inception), priv)
        inception["signature"] = base64.b64encode(sig).decode("ascii")

        # Persist
        store.save_private_key(name, priv, "current")
        store.save_private_key(name, next_priv, "next")
        store.append_event(name, inception)

        identity = cls(
            name=name,
            agent_id=agent_id,
            private_key=priv,
            public_key=pub,
            next_private_key=next_priv,
            next_public_key=next_pub,
            store=store,
        )

        # Save public identity document
        store.save_identity(name, identity.to_identity_document())

        return identity

    @classmethod
    def load(cls, name: str, store: PACTStore | None = None) -> Identity:
        """Load an existing identity from store."""
        store = store or PACTStore()

        priv = store.load_private_key(name, "current")
        next_priv = store.load_private_key(name, "next")

        # Derive public keys from private seeds
        from nacl.signing import SigningKey
        pub = bytes(SigningKey(priv).verify_key)
        next_pub = bytes(SigningKey(next_priv).verify_key)

        # Derive agent_id from inception event
        events = store.load_event_log(name)
        if not events:
            raise ValueError(f"No event log found for agent '{name}'")
        agent_id = events[0]["agent_id"]

        return cls(
            name=name,
            agent_id=agent_id,
            private_key=priv,
            public_key=pub,
            next_private_key=next_priv,
            next_public_key=next_pub,
            store=store,
        )

    def sign(self, data: bytes) -> bytes:
        """Sign data with the current private key."""
        return crypto.sign(data, self._private_key)

    def public_key_b64(self) -> str:
        """Base64-encoded public key."""
        return base64.b64encode(self.public_key).decode("ascii")

    def to_identity_document(self) -> dict:
        """Public identity document (no private keys)."""
        next_key_digest = crypto.sha256_digest(self._next_public_key)
        return {
            "agent_id": self.agent_id,
            "alg": crypto.ALG,
            "public_key": self.public_key_b64(),
            "next_key_digest": next_key_digest,
        }

    def to_service_endpoint(self, host: str, port: int, capabilities: list[str]) -> dict:
        """Service endpoint document for discovery."""
        return {
            "agent_id": self.agent_id,
            "endpoints": [
                {"transport": "https", "uri": f"http://{host}:{port}/pact/v1"},
            ],
            "capabilities": capabilities,
        }
