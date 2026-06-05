"""Deterministic serialization for signing.

Two agents must produce identical bytes for the same logical object.
Supports JSON (required) and CBOR (optional, via cbor2).
"""

from __future__ import annotations

import json


def canonical_json(obj: dict) -> bytes:
    """Serialize a dict to deterministic JSON bytes.

    Sorted keys, no whitespace, ASCII-safe. This is what gets signed.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def canonical_json_str(obj: dict) -> str:
    """Serialize a dict to deterministic JSON string."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def canonical_cbor(obj: dict) -> bytes:
    """Serialize a dict to deterministic CBOR bytes.

    Uses canonical=True for deterministic key ordering.
    Requires: pip install pact-passport[cbor]
    """
    try:
        import cbor2
    except ImportError:
        raise ImportError(
            "CBOR support requires cbor2. Install with: pip install pact-passport[cbor]"
        )
    return cbor2.dumps(obj, canonical=True)


def decode_cbor(data: bytes) -> dict:
    """Decode CBOR bytes to a dict.

    Requires: pip install pact-passport[cbor]
    """
    try:
        import cbor2
    except ImportError:
        raise ImportError(
            "CBOR support requires cbor2. Install with: pip install pact-passport[cbor]"
        )
    return cbor2.loads(data)


CBOR_CONTENT_TYPE = "application/cbor"
JSON_CONTENT_TYPE = "application/json"


def encode_message(obj: dict, content_type: str = JSON_CONTENT_TYPE) -> tuple[bytes, str]:
    """Encode a message dict to bytes with the specified content type.

    Returns (body_bytes, content_type).
    """
    if content_type == CBOR_CONTENT_TYPE:
        return canonical_cbor(obj), CBOR_CONTENT_TYPE
    return json.dumps(obj).encode("utf-8"), JSON_CONTENT_TYPE


def decode_message(data: bytes, content_type: str = JSON_CONTENT_TYPE) -> dict:
    """Decode message bytes based on content type."""
    if content_type == CBOR_CONTENT_TYPE:
        return decode_cbor(data)
    return json.loads(data)
