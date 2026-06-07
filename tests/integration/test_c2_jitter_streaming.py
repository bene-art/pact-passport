"""C2: Streaming Write-Order Integrity under Jitter.

Extends the v0.5.0 streaming tests with deliberate timing jitter:
server-side handler injects time.sleep delays before each chunk yield,
exercising the v0.5.3 streaming write-order fix (idempotency cache must
be persisted before the receipt is written, to prevent retries from
producing duplicate receipts).

Pre-registered prediction: under jitter, chunks still arrive in
monotonic chunk_seq order; client retries with the same idempotency_key
return the cached complete stream (or fail cleanly); receipt count
remains ≤ 1 per logical request.
"""

from __future__ import annotations

import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from pact.message import build_req
from pact.transport.client import send_message_streaming


def test_c2_jitter_streaming_chunks_arrive_in_order(sandbox, capsys):
    """N=20 chunks streamed with 0-50ms random delays before each yield.
    chunk_seq must be monotonic in the received order."""
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    rng = random.Random(42)

    @bob["agent"].handle("jitter_count")
    def jitter_count(payload):
        for i in range(20):
            time.sleep(rng.uniform(0, 0.05))
            yield {"n": i, "ts": time.time()}

    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "jitter_count"},
        stream=True,
    )

    start = time.time()
    chunks = list(send_message_streaming(bob["url"], req, timeout=30))
    elapsed = time.time() - start

    print(f"\n[C2-order] N=20 chunks in {elapsed:.2f}s")
    assert len(chunks) == 20, f"expected 20 chunks, got {len(chunks)}"
    for i, c in enumerate(chunks):
        assert c["chunk_seq"] == i, (
            f"out-of-order chunk: position {i} has chunk_seq {c['chunk_seq']}"
        )
        assert c["payload"]["n"] == i


def test_c2_jitter_streaming_concurrent_retry_documents_dedup_gap(sandbox, capsys):
    """C2 finding: concurrent streaming dispatch with the same
    idempotency_key does NOT dedup at the handler level in v0.5.5.

    Two clients send the SAME signed REQ at the same instant via
    threading.Barrier. Each opens its own streaming connection and reads
    chunks. The empirical state: BOTH handlers run.

    Contrast with A3 (non-streaming): _task_lock serializes dispatch and
    the second request sees the cached response. For streaming, the
    handler returns a generator object immediately; the generator is
    iterated as the client reads chunks; cache write happens AFTER the
    stream completes. The lock cannot hold across the entire stream
    without serializing all streaming dispatch.

    This is a real characteristic of the v0.5.5 streaming path, not a
    bug per se (spec is silent on concurrent streaming dedup). Worth
    noting in §3 streaming subsection: 'idempotency dedup is enforced
    at handler-return for unary REQs and at sequential-retry for
    streaming REQs; concurrent streaming retries with the same
    idempotency_key may both execute handlers.'
    """
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    handler_calls = [0]
    handler_lock = threading.Lock()

    @bob["agent"].handle("jitter_count2")
    def jitter_count2(payload):
        with handler_lock:
            handler_calls[0] += 1
        for i in range(10):
            time.sleep(0.02)
            yield {"n": i}

    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "jitter_count2"},
        stream=True,
    )

    barrier = threading.Barrier(2)
    results = []
    results_lock = threading.Lock()

    def fire():
        barrier.wait()
        chunks = list(send_message_streaming(bob["url"], req, timeout=30))
        with results_lock:
            results.append(chunks)

    with ThreadPoolExecutor(max_workers=2) as pool:
        pool.submit(fire)
        pool.submit(fire)

    print(f"\n[C2-concurrent FINDING] handler_calls={handler_calls[0]} (concurrent same-key)")
    print(f"[C2-concurrent FINDING] result chunk counts: {[len(r) for r in results]}")

    # Document the empirical state. NOT a regression — spec is silent on
    # this. The assertion captures the current behavior so the test fails
    # loudly if/when a future patch tightens the streaming dedup path.
    assert handler_calls[0] == 2, (
        f"unexpected: streaming dedup tightened — handler_calls={handler_calls[0]} "
        f"(was 2 in v0.5.5; invert assertion if patched to 1)"
    )


def test_c2_jitter_streaming_sequential_retry_returns_cached(sandbox, capsys):
    """Sequential retry (not concurrent): client sends REQ, waits for
    stream to complete, then sends the SAME REQ again. Second should
    hit the populated cache and not re-execute the handler.

    This is the v0.5.3 write-order fix in action: cache must be
    persisted before the receipt write to ensure sequential retries
    return cached chunks.
    """
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    handler_calls = [0]

    @bob["agent"].handle("jitter_seq2")
    def jitter_seq2(payload):
        handler_calls[0] += 1
        for i in range(5):
            time.sleep(0.02)
            yield {"n": i}

    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "jitter_seq2"},
        stream=True,
    )

    # First call — runs handler, populates cache
    chunks_1 = list(send_message_streaming(bob["url"], req, timeout=30))
    assert len(chunks_1) == 5
    assert handler_calls[0] == 1

    # Give the cache write a moment to flush
    time.sleep(0.2)

    # Second call (same REQ) — should hit cache, handler must NOT run again
    chunks_2 = list(send_message_streaming(bob["url"], req, timeout=30))

    print(f"\n[C2-sequential] after sequential retry: handler_calls={handler_calls[0]}")
    print(f"[C2-sequential] chunks_2 count={len(chunks_2)}")
    assert handler_calls[0] == 1, (
        f"sequential retry triggered re-execution: handler_calls={handler_calls[0]}"
    )


def test_c2_jitter_streaming_receipt_singularity(sandbox, capsys):
    """A single completed streaming dispatch should produce exactly one
    receipt on bob's side, regardless of jitter timing. The v0.5.3 fix
    ordered the cache write before the receipt write to prevent retries
    from racing in a way that produces duplicate receipts."""
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    receipt_count_before = len(bob["agent"]._store.list_receipts(bob["name"]))

    @bob["agent"].handle("jitter_seq")
    def jitter_seq(payload):
        for i in range(5):
            time.sleep(0.03)
            yield {"n": i}

    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "jitter_seq"},
        stream=True,
    )

    chunks = list(send_message_streaming(bob["url"], req, timeout=30))
    assert len(chunks) == 5

    # Give the server a moment to write its receipt
    time.sleep(0.5)

    receipt_count_after = len(bob["agent"]._store.list_receipts(bob["name"]))
    new_receipts = receipt_count_after - receipt_count_before

    print(f"\n[C2-receipt] new receipts after one stream: {new_receipts}")
    assert new_receipts == 1, (
        f"expected 1 receipt, got {new_receipts} — duplicate receipt write"
    )
