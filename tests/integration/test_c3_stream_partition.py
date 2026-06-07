"""C3 Stage 1: Unilateral Flight Logging Protection (Mac-only synthetic).

Tests post-hoc audit trail accountability under stream partition. Stage 1
uses synthetic client-side socket close to simulate network partition
mid-stream; Stage 2 (NUC cross-machine) is pending NUC availability.

Pre-registered prediction: when the stream is interrupted at chunk K,
each side independently records its terminal chunk_seq. Both sides
should have a receipt with outcome != "completed" (cancelled or partial)
indicating the stream did not finish. The receipts can disagree on the
exact terminal chunk_seq by ≤ 1 (one chunk may be in flight when the
socket closes).

Stage 1 focuses on the SERVER-SIDE receipt because the client-side
receipt depends on the client implementation. For the wire-protocol
property, what matters is: does the server detect the partition and
write some kind of audit record?
"""

from __future__ import annotations

import json
import socket
import time
import urllib.request

import pytest

from pact.message import build_req


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


def test_c3_stage1_FINDING_server_skips_receipt_on_partition(sandbox, capsys):
    """C3 FINDING: when the client disconnects mid-stream, the server
    writes ZERO receipts. This violates the §3.4 unilateral receipt
    claim ("a receipt exists on the side that wrote it regardless of
    the other party's cooperation, network partition, or crash").

    Root cause: src/pact/agent.py:_run_streaming_handler writes the
    receipt AFTER yielding all chunks to the HTTP layer. If the HTTP
    layer's wfile.write raises BrokenPipeError, the exception propagates
    up and the receipt-write line is never reached.

    Tracked as v0.6 bug #30. This test asserts the empirical (buggy)
    state; invert the assertion when the bug is fixed.
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
    print(f"\n[C3-FINDING] client read {len(chunks_read)} chunks before abort")
    assert len(chunks_read) == 5

    for i, c in enumerate(chunks_read):
        assert c["chunk_seq"] == i

    time.sleep(2.0)

    receipt_count_after = len(bob["agent"]._store.list_receipts(bob["name"]))
    new_receipts = receipt_count_after - receipt_count_before
    print(f"[C3-FINDING] new receipts on server side: {new_receipts} (expected by §3.4: ≥1; actual: 0)")

    # Empirical state: ZERO receipts written. Invert this assertion when
    # the bug is fixed and the server writes outcome=cancelled receipts.
    assert new_receipts == 0, (
        f"unexpected: stream partition produced {new_receipts} receipts. "
        f"v0.5.5 baseline behavior is 0; the receipt-write-on-partition "
        f"bug (#30) may have been fixed — invert this assertion."
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
