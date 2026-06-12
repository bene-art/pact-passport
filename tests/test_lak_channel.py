"""Tests for LAK channel integration (Phase 5)."""

from pact_passport.contrib.lak_channel import PACTChannel, _LAKMessage


def test_lak_message_creation():
    """LAK-compatible message has text and thread_id."""
    msg = _LAKMessage("hello", "thread-1")
    assert msg.text == "hello"
    assert msg.thread_id == "thread-1"


def test_pact_channel_init(store):
    """PACTChannel initializes with a PACTAgent."""
    from pact_passport.agent import PACTAgent

    agent = PACTAgent("lak_test", store_dir=store.base, capabilities=["chat"])
    channel = PACTChannel(agent)
    assert channel._pact is agent
    assert channel._pending_req is None
