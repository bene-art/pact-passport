"""Tests for key rotation (Phase 3)."""

from pact.identity import Identity
from pact import crypto


def test_rotate_basic(store):
    """Rotate keys and verify identity survives."""
    ident = Identity.create("rot_test", store)
    old_agent_id = ident.agent_id
    old_pub = ident.public_key

    event = ident.rotate()

    assert ident.agent_id == old_agent_id  # stable
    assert ident.public_key != old_pub     # key changed
    assert event["event_type"] == "rotation"
    assert event["sequence"] == 1


def test_rotate_event_log(store):
    """Event log has inception + rotation after rotate."""
    ident = Identity.create("evlog_rot", store)
    ident.rotate()

    events = store.load_event_log("evlog_rot")
    assert len(events) == 2
    assert events[0]["event_type"] == "inception"
    assert events[1]["event_type"] == "rotation"
    assert events[1]["sequence"] == 1


def test_rotate_multiple(store):
    """Multiple rotations maintain chain integrity."""
    ident = Identity.create("multi_rot", store)
    ident.rotate()
    ident.rotate()
    ident.rotate()

    events = store.load_event_log("multi_rot")
    assert len(events) == 4
    for i, e in enumerate(events):
        assert e["sequence"] == i


def test_rotate_sign_verify(store):
    """Can sign and verify after rotation."""
    ident = Identity.create("sign_rot", store)
    ident.rotate()

    data = b"post-rotation message"
    sig = ident.sign(data)
    assert crypto.verify(data, sig, ident.public_key)


def test_rotate_load_after(store):
    """Can load identity after rotation."""
    ident = Identity.create("load_rot", store)
    ident.rotate()
    expected_id = ident.agent_id
    expected_pub = ident.public_key

    reloaded = Identity.load("load_rot", store)
    assert reloaded.agent_id == expected_id
    assert reloaded.public_key == expected_pub


def test_verify_event_log_valid(store):
    """Event log verification passes for valid chain."""
    ident = Identity.create("valid_log", store)
    ident.rotate()
    ident.rotate()

    errors = ident.verify_event_log()
    assert errors == [], f"Unexpected errors: {errors}"


def test_verify_event_log_inception_only(store):
    """Event log verification passes for inception-only."""
    ident = Identity.create("inc_only", store)
    errors = ident.verify_event_log()
    assert errors == []


def test_verify_event_log_tampered(store):
    """Event log verification catches tampered event."""
    ident = Identity.create("tampered", store)
    ident.rotate()

    # Tamper with the event log
    events = store.load_event_log("tampered")
    events[1]["sequence"] = 99  # tamper
    # Write tampered log back
    import json
    path = store._agent_dir("tampered") / "event_log.json"
    path.write_text(json.dumps(events))

    errors = ident.verify_event_log()
    assert len(errors) > 0
    assert any("sequence" in e for e in errors)


def test_identity_document_updates_after_rotation(store):
    """Identity document reflects new key after rotation."""
    ident = Identity.create("doc_rot", store)
    doc_before = store.load_identity("doc_rot")
    ident.rotate()
    doc_after = store.load_identity("doc_rot")

    assert doc_before["agent_id"] == doc_after["agent_id"]  # stable
    assert doc_before["public_key"] != doc_after["public_key"]  # key changed
    assert doc_before["next_key_digest"] != doc_after["next_key_digest"]  # new commitment
