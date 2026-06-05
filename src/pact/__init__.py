"""PACT Passport — agent ID for agent-to-agent systems.

Self-certifying identity (Ed25519 + KERI-style pre-rotation), holder-bound
capability tokens (Macaroons-style attenuable), three message types
(REQ / RES / RES_CHUNK), unilateral audit receipts. Built at the edges.
"""

from pact._version import __version__
from pact.agent import PACTAgent
from pact.errors import HandlerFailure
from pact.capability import (
    CapabilityToken,
    Caveat,
    attenuate,
    issue_capability,
    verify_capability,
)
from pact.identity import Identity
from pact.message import (
    PACTMessage,
    build_req,
    build_res,
    build_res_chunk,
    verify_holder_proof,
    verify_message,
)
from pact.receipt import create_receipt, verify_receipt
from pact.transport.client import (
    fetch_identity,
    send_message,
    send_message_streaming,
)

__all__ = [
    # Capabilities
    "CapabilityToken",
    "Caveat",
    "HandlerFailure",
    "Identity",
    # Core agent
    "PACTAgent",
    # Messages
    "PACTMessage",
    # Version
    "__version__",
    "attenuate",
    "build_req",
    "build_res",
    "build_res_chunk",
    # Receipts
    "create_receipt",
    "fetch_identity",
    "issue_capability",
    # Transport client
    "send_message",
    "send_message_streaming",
    "verify_capability",
    "verify_holder_proof",
    "verify_message",
    "verify_receipt",
]
