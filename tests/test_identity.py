"""Tests for identity module."""

from pact_passport.identity import Identity
from pact_passport import crypto


def test_create_identity(store):
    ident = Identity.create("test_agent", store)
    assert ident.agent_id.startswith("sha256:")
    assert ident.name == "test_agent"
    assert len(ident.public_key) == 32


def test_load_identity(store):
    created = Identity.create("test_agent", store)
    loaded = Identity.load("test_agent", store)
    assert loaded.agent_id == created.agent_id
    assert loaded.public_key == created.public_key


def test_agent_id_is_stable(store):
    ident = Identity.create("stable", store)
    reloaded = Identity.load("stable", store)
    assert ident.agent_id == reloaded.agent_id


def test_sign_verify(store):
    ident = Identity.create("signer", store)
    data = b"test data"
    sig = ident.sign(data)
    assert crypto.verify(data, sig, ident.public_key)


def test_identity_document(store):
    ident = Identity.create("doc_test", store)
    doc = ident.to_identity_document()
    assert doc["agent_id"] == ident.agent_id
    assert doc["alg"] == "Ed25519"
    assert "public_key" in doc
    assert "next_key_digest" in doc


def test_event_log_created(store):
    Identity.create("evlog", store)
    events = store.load_event_log("evlog")
    assert len(events) == 1
    assert events[0]["event_type"] == "inception"
    assert events[0]["sequence"] == 0


def test_service_endpoint(store):
    ident = Identity.create("ep_test", store)
    ep = ident.to_service_endpoint("192.168.1.1", 9100, ["weather"])
    assert ep["agent_id"] == ident.agent_id
    assert ep["capabilities"] == ["weather"]
    assert "endpoints" in ep
