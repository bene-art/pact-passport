"""Deterministic JSON serialization for signing.

Two agents must produce identical bytes for the same logical object.
This module ensures that by sorting keys and removing whitespace.
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
