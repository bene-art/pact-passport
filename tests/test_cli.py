"""Smoke tests for the `pact` CLI subcommands.

Targets local-state-only commands. Network-dependent commands (serve, discover,
ask) require integration-style harnesses and live in tests/integration/.

The pattern: redirect the PACT store root via the PACT_HOME env var so that
both cli._get_store() and any PACTAgent instantiated inside a cmd_X function
share the same tmp-path-backed store. Each cmd_X is then called with a
SimpleNamespace mimicking argparse.Namespace.
"""

from __future__ import annotations

import json
import sys
import types

import pytest

from pact import cli
from pact.store import PACTStore


@pytest.fixture
def isolated_store(tmp_path, monkeypatch):
    """Redirect ~/.pact/ to tmp_path for the duration of the test.

    Setting PACT_HOME means PACTStore() (with no explicit arg) and PACTAgent
    instantiation inside cmd_X both land on the same isolated tmp directory.
    """
    monkeypatch.setenv("PACT_HOME", str(tmp_path))
    return PACTStore()


def _args(**kwargs) -> types.SimpleNamespace:
    """Mimic an argparse.Namespace for direct cmd_X invocation."""
    return types.SimpleNamespace(**kwargs)


# ---------------------------------------------------------------------------
# pact init
# ---------------------------------------------------------------------------


def test_init_creates_identity(isolated_store, capsys):
    cli.cmd_init(_args(name="alice"))
    out = capsys.readouterr().out
    assert "Identity created." in out
    assert "Agent ID: sha256:" in out
    assert isolated_store.has_agent("alice")


def test_init_idempotent_on_existing_agent(isolated_store, capsys):
    cli.cmd_init(_args(name="alice"))
    capsys.readouterr()  # drain
    cli.cmd_init(_args(name="alice"))
    out = capsys.readouterr().out
    assert "already exists" in out


# ---------------------------------------------------------------------------
# pact identity
# ---------------------------------------------------------------------------


def test_identity_prints_signed_document(isolated_store, capsys):
    cli.cmd_init(_args(name="alice"))
    capsys.readouterr()
    cli.cmd_identity(_args(name="alice"))
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["alg"] == "Ed25519"
    assert doc["agent_id"].startswith("sha256:")
    assert "public_key" in doc
    assert "next_key_digest" in doc


def test_identity_missing_agent_reports(isolated_store, capsys):
    cli.cmd_identity(_args(name="ghost"))
    out = capsys.readouterr().out
    assert "not found" in out.lower() or "No agents" in out


# ---------------------------------------------------------------------------
# pact caps / pact grant / pact revoke
# ---------------------------------------------------------------------------


def test_caps_empty_after_init(isolated_store, capsys):
    cli.cmd_init(_args(name="alice"))
    capsys.readouterr()
    cli.cmd_caps(_args(agent="alice"))
    out = capsys.readouterr().out
    assert "No capabilities" in out


def test_grant_creates_capability_and_caps_lists_it(isolated_store, capsys):
    cli.cmd_init(_args(name="alice"))
    cli.cmd_init(_args(name="bob"))
    bob_doc = isolated_store.load_identity("bob")
    capsys.readouterr()

    cli.cmd_grant(_args(
        holder=bob_doc["agent_id"],
        action="echo",
        agent="alice",
        expires=None,
        max_invocations=None,
        no_delegation=False,
    ))
    out = capsys.readouterr().out
    assert "Capability issued." in out
    assert "cap_id:" in out
    assert "action:  echo" in out

    cli.cmd_caps(_args(agent="alice"))
    caps_out = capsys.readouterr().out
    assert "echo" in caps_out


def test_grant_with_caveats_records_them(isolated_store, capsys):
    cli.cmd_init(_args(name="alice"))
    cli.cmd_init(_args(name="bob"))
    bob_doc = isolated_store.load_identity("bob")
    capsys.readouterr()

    cli.cmd_grant(_args(
        holder=bob_doc["agent_id"],
        action="echo",
        agent="alice",
        expires="2099-12-31T23:59:59+00:00",
        max_invocations=5,
        no_delegation=True,
    ))
    out = capsys.readouterr().out
    assert "max_invocations = 5" in out
    assert "expires" in out
    assert "no_further_delegation" in out


def test_revoke_marks_cap_revoked(isolated_store, capsys):
    cli.cmd_init(_args(name="alice"))
    cli.cmd_init(_args(name="bob"))
    bob_doc = isolated_store.load_identity("bob")
    cli.cmd_grant(_args(
        holder=bob_doc["agent_id"], action="echo", agent="alice",
        expires=None, max_invocations=None, no_delegation=False,
    ))
    caps = isolated_store.list_capabilities("alice")
    assert len(caps) == 1
    cap_id = caps[0]["cap_id"]
    capsys.readouterr()

    cli.cmd_revoke(_args(cap_id=cap_id, agent="alice"))
    out = capsys.readouterr().out
    assert "revoked" in out


def test_revoke_unknown_cap_reports_not_found(isolated_store, capsys):
    cli.cmd_init(_args(name="alice"))
    capsys.readouterr()
    cli.cmd_revoke(_args(cap_id="does-not-exist", agent="alice"))
    out = capsys.readouterr().out
    assert "not found" in out


# ---------------------------------------------------------------------------
# pact receipts
# ---------------------------------------------------------------------------


def test_receipts_empty(isolated_store, capsys):
    cli.cmd_init(_args(name="alice"))
    capsys.readouterr()
    cli.cmd_receipts(_args(agent="alice"))
    out = capsys.readouterr().out
    assert "No receipts" in out


# ---------------------------------------------------------------------------
# pact peers
# ---------------------------------------------------------------------------


def test_peers_empty(isolated_store, capsys):
    cli.cmd_init(_args(name="alice"))
    capsys.readouterr()
    cli.cmd_peers(_args())
    out = capsys.readouterr().out
    assert "No known peers" in out


# ---------------------------------------------------------------------------
# pact doctor
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="doctor's POSIX permission check (0o600) fails on Windows; "
           "Windows filesystem reports 0o666 regardless of chmod. "
           "Matches the existing skip pattern in tests/test_doctor.py::test_doctor_bad_permissions.",
)
def test_doctor_clean_identity_reports_passes(isolated_store, capsys):
    cli.cmd_init(_args(name="alice"))
    capsys.readouterr()
    cli.cmd_doctor(_args(name="alice"))
    out = capsys.readouterr().out
    assert "Checking agent 'alice'" in out
    # Key existence + permission checks should pass on a freshly-created agent
    assert "Private key file exists" in out or "private_key" in out.lower()


# ---------------------------------------------------------------------------
# Auto-resolve when only one agent exists
# ---------------------------------------------------------------------------


def test_caps_auto_resolves_single_agent(isolated_store, capsys):
    """Commands that accept --agent should default to the sole agent if only one exists."""
    cli.cmd_init(_args(name="alice"))
    capsys.readouterr()
    cli.cmd_caps(_args(agent=None))
    out = capsys.readouterr().out
    assert "No capabilities" in out or "alice" in out.lower()


def test_caps_no_agents_reports(isolated_store, capsys):
    cli.cmd_caps(_args(agent=None))
    out = capsys.readouterr().out
    assert "No agents found" in out or "no agents" in out.lower()
