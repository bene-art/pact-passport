"""PACT — Protocol for Agent Capability and Trust.

Two message types, holder-bound capabilities, and self-certifying identity.
Everything else is built at the edges.
"""

from pact._version import __version__
from pact.agent import PACTAgent
from pact.identity import Identity
from pact.capability import CapabilityToken, Caveat, attenuate

__all__ = ["PACTAgent", "Identity", "CapabilityToken", "Caveat", "attenuate", "__version__"]
