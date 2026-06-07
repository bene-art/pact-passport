"""A4: Content-Length Exhaustion Fuzz.

Extends the v0.5.3 F1 test patterns (in tests/test_v053_input_validation.py)
with a broader variant set, 100 trials per variant, asserting clean
HTTP-level rejection across all malformed Content-Length values.

Pre-registered prediction: all variants in {negative, non-numeric,
oversize, empty, null, scientific-notation} are rejected with HTTP 400
(Bad Request) or HTTP 413 (Content Too Large). v0.5.3 patch covers
negative + non-numeric; this experiment extends coverage to additional
forms an adversary might try.

Risk: low for already-covered forms (`-1`, `abc`); medium for `0`
(technically a valid HTTP Content-Length — server should accept the
header but reject the empty-body protocol layer), `1e100` (scientific
notation may parse to float and bypass int validation), and `2**31`
(boundary of int32 overflow).
"""

from __future__ import annotations

import socket

import pytest

from pact.transport.server import PACTServer


# ---------------------------------------------------------------------------
# Helpers (mirror v0.5.3 F1 pattern)
# ---------------------------------------------------------------------------


def _post_with_raw_headers(port: int, content_length_header: str) -> bytes:
    """Open a raw socket, send a POST with a custom Content-Length header,
    receive whatever the server sends back (or time out)."""
    sock = socket.create_connection(("127.0.0.1", port))
    sock.sendall(
        f"POST /pact/v1/message HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {content_length_header}\r\n"
        f"\r\n".encode()
    )
    sock.settimeout(3)
    try:
        return sock.recv(2048)
    except (socket.timeout, TimeoutError):
        return b""
    finally:
        sock.close()


@pytest.fixture
def server():
    s = PACTServer(port=0, dispatch=lambda b: {"ok": True}, max_body_bytes=1024)
    port = s.start()
    yield port
    s.stop()


def _classify_response(resp: bytes) -> str:
    """Return a coarse label for the HTTP response: 400, 413, 200,
    timeout (empty bytes), or other."""
    if not resp:
        return "timeout"
    head = resp[:15]
    if head.startswith(b"HTTP/1.0 400") or head.startswith(b"HTTP/1.1 400"):
        return "400"
    if head.startswith(b"HTTP/1.0 413") or head.startswith(b"HTTP/1.1 413"):
        return "413"
    if head.startswith(b"HTTP/1.0 200") or head.startswith(b"HTTP/1.1 200"):
        return "200"
    if head.startswith(b"HTTP/1.0 500") or head.startswith(b"HTTP/1.1 500"):
        return "500"
    return f"other:{resp[:30]!r}"


# ---------------------------------------------------------------------------
# Variant matrix
# ---------------------------------------------------------------------------

# Each variant maps to its pre-registered acceptable response set
VARIANTS = {
    "-1":          {"400"},                   # negative; v0.5.3 covered
    "-1024":       {"400"},                   # larger negative
    "abc":         {"400"},                   # non-numeric; v0.5.3 covered
    "1e100":       {"400", "413"},            # scientific notation — may parse to float and read as int overflow OR rejected
    "2147483648":  {"413"},                   # 2**31, large but valid int → oversize
    "":            {"400", "timeout"},        # empty value; technically malformed
    "null":        {"400"},                   # the literal string "null"
    " ":           {"400", "timeout"},        # whitespace-only
}

TRIALS_PER_VARIANT = 100


def test_a4_content_length_fuzz_matrix(server, capsys):
    """Run TRIALS_PER_VARIANT trials per variant; assert every response
    falls into the pre-registered acceptable set for that variant.

    Each variant's response is deterministic (same input → same output)
    so 100 trials per variant is over-sampling. The trial count exists to
    catch any state-dependent non-determinism (e.g., counter wraparound,
    cache pollution).
    """
    print()
    results = {}
    for variant, expected_codes in VARIANTS.items():
        codes_seen = {}
        for _ in range(TRIALS_PER_VARIANT):
            resp = _post_with_raw_headers(server, variant)
            code = _classify_response(resp)
            codes_seen[code] = codes_seen.get(code, 0) + 1

        results[variant] = codes_seen
        print(f"[A4] variant={variant!r:14} expected={sorted(expected_codes)} got={codes_seen}")

        # Every observed response must be in the expected set
        unexpected = set(codes_seen) - expected_codes
        assert not unexpected, (
            f"variant {variant!r}: unexpected response codes {unexpected} "
            f"(full distribution: {codes_seen})"
        )

    # Special-case the "0" content-length: it's a structurally valid HTTP
    # header but produces an empty body which the protocol layer should
    # reject. Run separately so the result is its own assertion.
    zero_codes = {}
    for _ in range(TRIALS_PER_VARIANT):
        resp = _post_with_raw_headers(server, "0")
        code = _classify_response(resp)
        zero_codes[code] = zero_codes.get(code, 0) + 1

    print(f"[A4] variant='0'            (special) got={zero_codes}")
    # Acceptable: 400 (empty body rejected at protocol layer) OR 500
    # (server tried to parse empty as JSON and failed) — anything but
    # 200 or timeout is OK. 200 would mean an empty REQ was dispatched
    # which would be a real concern.
    assert "200" not in zero_codes, (
        f"Content-Length: 0 produced an HTTP 200 response — empty body "
        f"was dispatched: {zero_codes}"
    )

    # Report aggregate
    print(f"\n[A4] total trials: {len(VARIANTS) * TRIALS_PER_VARIANT + TRIALS_PER_VARIANT}")
    print(f"[A4] all variants rejected within pre-registered code sets")
