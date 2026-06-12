"""C3 Stage 1: Unilateral Flight Logging Protection (Mac-only synthetic).

Tests post-hoc audit trail accountability under stream partition. Stage 1
uses synthetic client-side socket close to simulate network partition
mid-stream; Stage 2 (NUC cross-machine) is pending NUC availability.

HISTORICAL FINDING (2026-06-07, against v0.5.5):
-------------------------------------------------
The server wrote ZERO receipts on stream partition. ``BrokenPipeError``
in the transport's ``_send_stream`` caused the streaming generator to
be garbage-collected; the ``GeneratorExit`` raised at the suspended
``yield`` is a ``BaseException`` (not ``Exception``), so the existing
``except Exception`` in ``_run_streaming_handler`` did not catch it,
and the receipt-write block below the try/except was unreachable.
This violated the §3.5 unilateral-receipt claim — *a receipt exists
on the side that wrote it regardless of the other party's cooperation,
network partition, or crash*.

FIX (2026-06-08, v0.6, see ``bug7_fix_design.md`` and GH #30):
--------------------------------------------------------------
``_run_streaming_handler`` was restructured to a ``try / finally`` with
an ``outcome`` state variable defaulting to ``cancelled``; completed
and failed paths overwrite it. The transport's ``BrokenPipeError``
handler now explicitly calls ``chunks_iter.close()`` so cleanup runs
synchronously rather than waiting for GC. Stream partitions now
produce exactly one signed receipt with ``outcome=cancelled``
referencing the chunks emitted before the disconnect.

Pre-registered prediction: when the stream is interrupted at chunk K,
each side independently records its terminal chunk_seq. The server
should write a single ``outcome=cancelled`` receipt referencing the
chunks it managed to emit. Stage 1 focuses on the SERVER-SIDE receipt
because the client-side receipt depends on the client implementation.
"""

from __future__ import annotations

import json
import socket
import time
import urllib.request

import pytest

from pact_passport.message import build_req


def _send_streaming_and_abort_at_chunk(url: str, req_dict: dict, abort_at: int):
    """Open a streaming connection to the server, read `abort_at` chunks,
    then forcibly close the socket. Returns the list of chunks read
    before abort."""
    data = json.dumps(req_dict).encode("utf-8")
    req = urllib.request.Request(
        f"{url}/pact/v1/message",
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/x-ndjson",
        },
        method="POST",
    )
    chunks_read = []
    resp = urllib.request.urlopen(req, timeout=30)
    try:
        for raw_line in resp:
            if not raw_line.strip():
                continue
            chunk = json.loads(raw_line)
            chunks_read.append(chunk)
            if len(chunks_read) >= abort_at:
                break
    finally:
        # Forcibly close the connection mid-stream
        resp.close()
    return chunks_read


def test_c3_stage1_partition_writes_cancelled_receipt(sandbox, capsys):
    """Stream partition writes exactly one ``outcome=cancelled``
    receipt server-side (post-v0.6 fix; closes Bug 7 / GH #30).

    Pre-v0.6 the server wrote zero receipts because the streaming
    generator's receipt-write block was unreachable on GeneratorExit.
    v0.6 restructured ``_run_streaming_handler`` to a ``try / finally``
    with an ``outcome`` state variable; the transport now explicitly
    closes the iterator so the finally block runs synchronously.
    """
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    receipt_count_before = len(bob["agent"]._store.list_receipts(bob["name"]))

    @bob["agent"].handle("slow_stream")
    def slow_stream(payload):
        for i in range(20):
            time.sleep(0.1)
            yield {"n": i}

    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "slow_stream"},
        stream=True,
    )

    chunks_read = _send_streaming_and_abort_at_chunk(
        bob["url"], req.to_dict(), abort_at=5
    )
    print(f"\n[C3] client read {len(chunks_read)} chunks before abort")
    assert len(chunks_read) == 5
    for i, c in enumerate(chunks_read):
        assert c["chunk_seq"] == i

    time.sleep(2.0)

    receipts_after = bob["agent"]._store.list_receipts(bob["name"])
    new_receipts = receipts_after[receipt_count_before:]
    print(f"[C3] new receipts on server side: {len(new_receipts)}")

    assert len(new_receipts) == 1, (
        f"expected exactly 1 cancelled receipt; got {len(new_receipts)}"
    )
    receipt = new_receipts[0]
    assert receipt.get("outcome") == "cancelled", (
        f"expected outcome=cancelled; got {receipt.get('outcome')!r}"
    )
    # The receipt refs should include the original task_ref plus at
    # least one chunk message id (whatever was emitted before the
    # disconnect). The exact count depends on disconnect timing.
    refs = receipt.get("refs", [])
    assert receipt.get("task_ref") in refs, "task_ref must be in receipt.refs"
    assert len(refs) >= 2, (
        f"expected receipt to reference task + at least one chunk; got refs={refs}"
    )


def test_c3_stage1_cancelled_stream_does_not_cache_for_retry(sandbox, capsys):
    """A partitioned stream MUST NOT populate the idempotency cache.
    A retry with the same idempotency_key re-executes the handler;
    the second dispatch is independent of the first cancellation."""
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    handler_calls = [0]

    @bob["agent"].handle("retry_stream")
    def retry_stream(payload):
        handler_calls[0] += 1
        for i in range(20):
            time.sleep(0.05)
            yield {"call": handler_calls[0], "n": i}

    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "retry_stream"},
        stream=True,
    )

    # First attempt — partition mid-stream.
    chunks_first = _send_streaming_and_abort_at_chunk(
        bob["url"], req.to_dict(), abort_at=3
    )
    print(f"\n[C3-retry] first attempt: read {len(chunks_first)} chunks before abort")
    assert handler_calls[0] == 1
    time.sleep(1.0)

    # Retry with the same REQ (same idempotency_key) — should re-execute
    # the handler because the cancelled stream did not populate the cache.
    chunks_second = _send_streaming_and_abort_at_chunk(
        bob["url"], req.to_dict(), abort_at=100
    )
    print(f"[C3-retry] second attempt: read {len(chunks_second)} chunks")
    assert handler_calls[0] == 2, (
        f"cancelled stream must re-execute on retry; handler ran "
        f"{handler_calls[0]} times (expected 2)"
    )


def test_c3_stage1_control_clean_stream_writes_receipt(sandbox, capsys):
    """Control: when the stream completes normally (no partition), the
    server writes a receipt with outcome=completed. Confirms the test
    machinery is sound and the v0.5.0 streaming receipt path works for
    the happy path — the bug surfaced in test_c3_stage1_FINDING above
    is specifically the partition path."""
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    receipt_count_before = len(bob["agent"]._store.list_receipts(bob["name"]))

    @bob["agent"].handle("clean_stream")
    def clean_stream(payload):
        for i in range(5):
            time.sleep(0.02)
            yield {"n": i}

    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "clean_stream"},
        stream=True,
    )

    # Read ALL chunks (no abort)
    chunks_read = _send_streaming_and_abort_at_chunk(
        bob["url"], req.to_dict(), abort_at=100  # past end, so we read all
    )
    print(f"\n[C3-control] read {len(chunks_read)} chunks (no abort)")
    assert len(chunks_read) == 5

    time.sleep(0.5)

    receipt_count_after = len(bob["agent"]._store.list_receipts(bob["name"]))
    new_receipts = receipt_count_after - receipt_count_before
    print(f"[C3-control] new receipts: {new_receipts}")
    assert new_receipts == 1
    last_receipt = bob["agent"]._store.list_receipts(bob["name"])[-1]
    assert last_receipt.get("outcome") == "completed"
