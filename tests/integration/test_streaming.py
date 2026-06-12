"""v0.5.0 — RES_CHUNK streaming response tests (issue #11).

Pre-v0.5.0: PACT was one-shot. The handler returned a dict; the receiver
got the full response only after handler completion. For LLM workflows
this meant 30-second waits before any bytes arrived.

Post-v0.5.0: handlers can yield dicts. The dispatcher signs each yielded
payload as a RES_CHUNK and the HTTP layer streams them as NDJSON over
chunked transfer encoding. Each chunk is independently signed and
verifiable.
"""

from __future__ import annotations

from pact_passport.message import build_req, PACTMessage, verify_message
from pact_passport.transport.client import send_message_streaming


def test_streaming_round_trip(sandbox):
    """Handler that yields multiple chunks; receiver collects them all."""
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    @bob["agent"].handle("count_stream")
    def count_stream(payload):
        for i in range(5):
            yield {"n": i}

    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "count_stream"},
        stream=True,
    )

    chunks = list(send_message_streaming(bob["url"], req))
    assert len(chunks) == 5, f"expected 5 chunks, got {len(chunks)}"

    # chunk_seq monotonic
    for i, c in enumerate(chunks):
        assert c["type"] == "RES_CHUNK"
        assert c["chunk_seq"] == i
        assert c["payload"]["n"] == i

    # Only the LAST chunk should be final
    finals = [c for c in chunks if c.get("chunk_final")]
    assert len(finals) == 1
    assert finals[0]["chunk_seq"] == 4


def test_each_chunk_is_independently_signed(sandbox):
    """Each chunk verifies cryptographically against bob's pubkey."""
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    @bob["agent"].handle("three_chunks")
    def three_chunks(payload):
        yield {"text": "first"}
        yield {"text": "second"}
        yield {"text": "third"}

    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "three_chunks"},
        stream=True,
    )
    chunks = list(send_message_streaming(bob["url"], req))

    for c in chunks:
        msg = PACTMessage.from_dict(c)
        assert verify_message(msg, bob["public_key"]), (
            f"chunk seq={c.get('chunk_seq')} signature did not verify"
        )


def test_tampered_chunk_signature_fails(sandbox):
    """Mutating a chunk after signing breaks its signature — independent
    of other chunks in the stream."""
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    @bob["agent"].handle("two_chunks")
    def two_chunks(payload):
        yield {"text": "alpha"}
        yield {"text": "beta"}

    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "two_chunks"},
        stream=True,
    )
    chunks = list(send_message_streaming(bob["url"], req))
    assert len(chunks) == 2

    # First chunk verifies fine.
    msg0 = PACTMessage.from_dict(chunks[0])
    assert verify_message(msg0, bob["public_key"])

    # Tamper the second: change payload.
    tampered = chunks[1].copy()
    tampered["payload"] = {"text": "FORGED"}
    msg1 = PACTMessage.from_dict(tampered)
    assert not verify_message(msg1, bob["public_key"])


def test_streaming_replay_returns_same_chunks(sandbox):
    """An idempotent replay of a streaming REQ returns the same chunks
    from cache without re-running the handler."""
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    handler_calls = {"n": 0}

    @bob["agent"].handle("counter_stream")
    def counter_stream(payload):
        handler_calls["n"] += 1
        for i in range(3):
            yield {"call": handler_calls["n"], "i": i}

    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "counter_stream"},
        stream=True,
    )
    msg_dict = req.to_dict()

    # First call — handler runs, produces 3 chunks
    chunks_1 = list(send_message_streaming(bob["url"], req))
    assert handler_calls["n"] == 1
    assert all(c["payload"]["call"] == 1 for c in chunks_1)

    # Replay (same idempotency_key, same signed bytes) — handler should NOT run again
    import json, urllib.request
    data = json.dumps(msg_dict).encode("utf-8")
    http_req = urllib.request.Request(
        f"{bob['url']}/pact/v1/message",
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/x-ndjson"},
        method="POST",
    )
    chunks_2 = []
    with urllib.request.urlopen(http_req, timeout=10) as resp:
        for line in resp:
            line = line.strip()
            if line:
                chunks_2.append(json.loads(line))

    assert handler_calls["n"] == 1, (
        f"handler ran {handler_calls['n']} times — streaming idempotency broke"
    )
    # Chunk content is the same as first call (call=1)
    assert all(c["payload"]["call"] == 1 for c in chunks_2)
    assert len(chunks_2) == 3


def test_handler_returning_list_is_not_streamed(sandbox):
    """Regression: pre-v0.5.1 dispatch detected streaming via __iter__
    which matched lists, strings, tuples, etc. A handler returning a
    list was mistakenly streamed. v0.5.1 narrows to inspect.isgenerator
    so only true generators stream.

    A handler returning a list should be treated as a one-shot result
    and wrapped in {"result": [...]} like any non-dict return.
    """
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    @bob["agent"].handle("returns_list")
    def returns_list(payload):
        return ["a", "b", "c"]  # list, NOT a generator

    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "returns_list"},
    )
    chunks = list(send_message_streaming(bob["url"], req))
    # Should be exactly one item — the one-shot RES wrapping the list
    assert len(chunks) == 1
    res = chunks[0]
    assert res["type"] == "RES"
    assert res["payload"] == {"result": ["a", "b", "c"]}


def test_streaming_one_shot_handler_still_works(sandbox):
    """A handler that returns a dict (not generator) under stream=True
    still works — the receiver gets the one-shot response. Streaming
    is opt-in on both sides."""
    alice = sandbox["alice"]
    bob = sandbox["bob"]

    @bob["agent"].handle("oneshot")
    def oneshot(payload):
        return {"answer": "done"}

    req = build_req(
        from_private_key=alice["identity"]._private_key,
        from_id=alice["agent_id"],
        to_id=bob["agent_id"],
        intent="task",
        payload={"action": "oneshot"},
        stream=True,  # asked for stream, but handler doesn't yield
    )
    chunks = list(send_message_streaming(bob["url"], req))
    # We get one item back — the one-shot RES dict.
    assert len(chunks) == 1
    assert chunks[0].get("type") == "RES" or chunks[0].get("payload", {}).get("answer") == "done"
