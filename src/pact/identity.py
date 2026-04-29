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

    def rotate(self) -> dict:
        """Rotate keys using pre-rotation.

        Activates the pre-committed next key as the new current key,
        generates a fresh next key, and appends a rotation event to the log.

        Returns the rotation event dict.
        """
        # The pre-committed next key becomes current
        old_pub_b64 = self.public_key_b64()
        new_priv = self._next_private_key
        from nacl.signing import SigningKey as _SK
        new_pub = bytes(_SK(new_priv).verify_key)

        # Generate a fresh next key
        fresh_next_priv, fresh_next_pub = crypto.generate_keypair()

        # Get the prior event for chaining
        events = self._store.load_event_log(self.name)
        prior_event = events[-1]
        prior_signable = {k: v for k, v in prior_event.items() if k != "signature"}
        prior_digest = crypto.sha256_digest(canonical_json(prior_signable))

        # Verify that our next key matches the commitment in the prior event
        expected_digest = prior_event.get("next_keys_digest", "")
        actual_digest = crypto.sha256_digest(new_pub)
        if expected_digest != actual_digest:
            raise ValueError(
                "Pre-rotation check failed: next key does not match committed digest. "
                "This identity may be compromised."
            )

        # Build rotation event
        new_pub_b64 = base64.b64encode(new_pub).decode("ascii")
        next_key_digest = crypto.sha256_digest(fresh_next_pub)
        sequence = len(events)

        rotation = {
            "agent_id": self.agent_id,
            "event_type": "rotation",
            "sequence": sequence,
            "prior_event_digest": prior_digest,
            "current_keys": [new_pub_b64],
            "next_keys_digest": next_key_digest,
            "alg": crypto.ALG,
        }
        # Sign with the NEW key (proves possession of pre-committed key)
        sig = crypto.sign(canonical_json(rotation), new_priv)
        rotation["signature"] = base64.b64encode(sig).decode("ascii")

        # Update in-memory state
        self._private_key = new_priv
        self.public_key = new_pub
        self._next_private_key = fresh_next_priv
        self._next_public_key = fresh_next_pub

        # Persist
        self._store.save_private_key(self.name, new_priv, "current")
        self._store.save_private_key(self.name, fresh_next_priv, "next")
        self._store.append_event(self.name, rotation)
        self._store.save_identity(self.name, self.to_identity_document())

        return rotation

    def verify_event_log(self) -> list[str]:
        """Verify the integrity of the key event log.

        Returns a list of error strings (empty = valid).
        """
        events = self._store.load_event_log(self.name)
        errors = []

        if not events:
            errors.append("No events in log")
            return errors

        # Check inception
        inception = events[0]
        if inception.get("event_type") != "inception":
            errors.append("First event is not an inception event")
        if inception.get("sequence") != 0:
            errors.append("Inception event sequence is not 0")

        # Verify inception signature
        inc_sig = base64.b64decode(inception.get("signature", ""))
        inc_pub_b64 = inception.get("current_keys", [""])[0]
        if inc_pub_b64:
            inc_pub = base64.b64decode(inc_pub_b64)
            inc_signable = {k: v for k, v in inception.items() if k != "signature"}
            if not crypto.verify(canonical_json(inc_signable), inc_sig, inc_pub):
                errors.append("Inception event signature is invalid")

        # Verify each rotation
        for i in range(1, len(events)):
            event = events[i]
            prev = events[i - 1]

            if event.get("event_type") != "rotation":
                errors.append(f"Event {i}: expected rotation, got {event.get('event_type')}")

            if event.get("sequence") != i:
                errors.append(f"Event {i}: sequence mismatch (got {event.get('sequence')})")

            # Verify the prior_event_digest chains to previous event
            prev_signable = {k: v for k, v in prev.items() if k != "signature"}
            expected_prior = crypto.sha256_digest(canonical_json(prev_signable))
            if event.get("prior_event_digest") != expected_prior:
                errors.append(f"Event {i}: prior_event_digest does not match event {i-1}")

            # Verify that the current key matches the next_keys_digest from previous event
            cur_pub_b64 = event.get("current_keys", [""])[0]
            if cur_pub_b64:
                cur_pub = base64.b64decode(cur_pub_b64)
                actual_digest = crypto.sha256_digest(cur_pub)
                expected = prev.get("next_keys_digest", "")
                if actual_digest != expected:
                    errors.append(f"Event {i}: current key does not match prior pre-rotation commitment")

                # Verify signature with the current key
                evt_sig = base64.b64decode(event.get("signature", ""))
                evt_signable = {k: v for k, v in event.items() if k != "signature"}
                if not crypto.verify(canonical_json(evt_signable), evt_sig, cur_pub):
                    errors.append(f"Event {i}: signature is invalid")

        return errors

    def to_service_endpoint(self, host: str, port: int, capabilities: list[str]) -> dict:
        """Service endpoint document for discovery."""
        return {
            "agent_id": self.agent_id,
            "endpoints": [
                {"transport": "https", "uri": f"http://{host}:{port}/pact/v1"},
            ],
            "capabilities": capabilities,
        }
