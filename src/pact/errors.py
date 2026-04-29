"""PACT error hierarchy."""

from __future__ import annotations


class PACTError(Exception):
    """Base error for all PACT operations."""


class IdentityNotFound(PACTError):
    """Agent identity not found in store."""


class InvalidSignature(PACTError):
    """Cryptographic signature verification failed."""


class CapabilityExpired(PACTError):
    """Capability token has expired."""


class CapabilityInvalid(PACTError):
    """Capability token failed verification."""


class DeadlineExceeded(PACTError):
    """Request deadline has passed."""


class DuplicateIdempotencyKey(PACTError):
    """Idempotency key already seen for this agent."""


class PeerUnreachable(PACTError):
    """Could not reach the target agent."""


class AttenuationViolation(PACTError):
    """Attempted to widen a capability during attenuation."""
