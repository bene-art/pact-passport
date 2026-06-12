"""Tests for store module."""

import os
import sys

import pytest

from pact_passport.store import PACTStore


def test_save_load_private_key(tmp_pact_home):
    store = PACTStore(tmp_pact_home)
    key = os.urandom(32)
    store.save_private_key("alice", key, "current")
    loaded = store.load_private_key("alice", "current")
    assert loaded == key


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX permission semantics not applicable on Windows NTFS (issue #6)",
)
def test_key_permissions(tmp_pact_home):
    store = PACTStore(tmp_pact_home)
    store.save_private_key("alice", os.urandom(32))
    path = tmp_pact_home / "agents" / "alice" / "private_key.bin"
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600


def test_has_agent(tmp_pact_home):
    store = PACTStore(tmp_pact_home)
    assert not store.has_agent("alice")
    store.save_private_key("alice", os.urandom(32))
    assert store.has_agent("alice")


def test_identity_round_trip(tmp_pact_home):
    store = PACTStore(tmp_pact_home)
    doc = {"agent_id": "sha256:abc", "alg": "Ed25519"}
    store.save_identity("alice", doc)
    loaded = store.load_identity("alice")
    assert loaded == doc


def test_event_log_append(tmp_pact_home):
    store = PACTStore(tmp_pact_home)
    store.append_event("alice", {"event_type": "inception", "sequence": 0})
    store.append_event("alice", {"event_type": "rotation", "sequence": 1})
    events = store.load_event_log("alice")
    assert len(events) == 2
    assert events[1]["sequence"] == 1


def test_capabilities(tmp_pact_home):
    store = PACTStore(tmp_pact_home)
    cap = {"cap_id": "c-001", "action": "test"}
    store.save_capability("alice", cap)
    loaded = store.load_capability("alice", "c-001")
    assert loaded == cap
    assert len(store.list_capabilities("alice")) == 1


def test_receipts(tmp_pact_home):
    store = PACTStore(tmp_pact_home)
    r = {"timestamp": "2026-01-01T00:00:00", "task_ref": "m-001", "outcome": "completed"}
    store.save_receipt("alice", r)
    receipts = store.list_receipts("alice")
    assert len(receipts) == 1


def test_messages(tmp_pact_home):
    store = PACTStore(tmp_pact_home)
    msg = {"id": "m-001", "type": "REQ"}
    store.save_message("alice", msg)
    loaded = store.load_message("alice", "m-001")
    assert loaded == msg


def test_peers(tmp_pact_home):
    store = PACTStore(tmp_pact_home)
    doc = {"agent_id": "sha256:peer1", "alg": "Ed25519"}
    store.save_peer("sha256:peer1", doc)
    loaded = store.load_peer("sha256:peer1")
    assert loaded == doc
    assert len(store.list_peers()) == 1


def test_list_agents(tmp_pact_home):
    store = PACTStore(tmp_pact_home)
    store.save_private_key("alice", os.urandom(32))
    store.save_private_key("bob", os.urandom(32))
    agents = store.list_agents()
    assert "alice" in agents
    assert "bob" in agents
