"""PACT Passport — agent ID for agent-to-agent systems.

Self-certifying identity (Ed25519 + KERI-style pre-rotation), holder-bound
capability tokens (Macaroons-style attenuable), three message types
(REQ / RES / RES_CHUNK), unilateral audit receipts. Built at the edges.
"""

from pact_passport._version import __version__
from pact_passport.agent import PACTAgent
from pact_passport.errors import HandlerFailure
from pact_passport.capability import (
    CapabilityToken,
    Caveat,
    attenuate,
    issue_capability,
    verify_capability,
)
from pact_passport.identity import Identity
from pact_passport.message import (
    HOLDER_PROOF_DOMAIN_V1,
    PACTMessage,
    VISA_USE_DOMAIN_V1,
    build_req,
    build_res,
    build_res_chunk,
    holder_proof_payload,
    verify_holder_proof,
    verify_message,
    visa_use_payload,
)
from pact_passport.receipt import create_receipt, verify_receipt
from pact_passport.transport.client import (
    fetch_identity,
    send_message,
    send_message_streaming,
)
from pact_passport.visa import (
    HandlerCost,
    ProtocolAdvertisement,
    VisaContext,
    VisaGrant,
    VisaRefuse,
    derive_peer_network_id,
    issue_visa,
    make_default_visa_policy,
    sign_visa_holder_proof,
    verify_visa_holder_proof,
)

__all__ = [
    # v1.4 / v0.8 domain separation (spec §18.1)
    "HOLDER_PROOF_DOMAIN_V1",
    "VISA_USE_DOMAIN_V1",
    # Capabilities
    "CapabilityToken",
    "Caveat",
    "HandlerFailure",
    # V-tier visas (v0.6)
    "HandlerCost",
    "Identity",
    # Core agent
    "PACTAgent",
    # Messages
    "PACTMessage",
    "ProtocolAdvertisement",
    "VisaContext",
    "VisaGrant",
    "VisaRefuse",
    # Version
    "__version__",
    "attenuate",
    "build_req",
    "build_res",
    "build_res_chunk",
    # Receipts
    "create_receipt",
    "derive_peer_network_id",
    "fetch_identity",
    "holder_proof_payload",  # v1.4 / spec §18.1
    "issue_capability",
    "issue_visa",
    "make_default_visa_policy",
    # Transport client
    "send_message",
    "send_message_streaming",
    "sign_visa_holder_proof",  # v1.4 / spec §18.1
    "verify_capability",
    "verify_holder_proof",
    "verify_message",
    "verify_receipt",
    "verify_visa_holder_proof",
    "visa_use_payload",  # v1.4 / spec §18.1
]
