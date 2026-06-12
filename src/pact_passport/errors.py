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


class HandlerFailure(PACTError):
    """Handler explicitly signalled failure with a custom fault.

    Apps that wrap remote calls (e.g. peer delegation) should raise this
    rather than returning an error dict, so the failure produces a signed
    error response and a `outcome=failed` receipt instead of a misleading
    `outcome=completed` one.

    Example:
        if peer_res.get("status") != "ok":
            raise HandlerFailure("peer_rejected", str(peer_res.get("fault")))
    """

    def __init__(self, code: str = "handler_failure", detail: str = ""):
        super().__init__(detail or code)
        self.code = code
        self.detail = detail
