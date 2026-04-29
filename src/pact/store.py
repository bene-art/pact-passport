"""Filesystem-based storage for PACT keys, events, capabilities, receipts, and messages.

Default location: ~/.pact/
Override with PACT_HOME environment variable.

Directory layout:
    ~/.pact/
        agents/<name>/
            private_key.bin          # 32-byte Ed25519 seed, mode 0o600
            next_private_key.bin     # Pre-rotated next key seed, mode 0o600
            identity.json            # Public identity document
            event_log.json           # Array of KeyEvent objects (append-only)
            capabilities/<cap_id>.json
            receipts/<timestamp>-<msg_id>.json
            messages/<msg_id>.json
        peers/<agent_id_hash>.json   # Cached peer identity documents
        config.json                  # Global config
"""

from __future__ import annotations

import json
import os
import tempfile
import warnings
from pathlib import Path


def _default_base() -> Path:
    env = os.environ.get("PACT_HOME")
    if env:
        return Path(env)
    return Path.home() / ".pact"


def _write_atomic(path: Path, data: bytes | str) -> None:
    """Write to a temp file then atomically replace target."""
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = data if isinstance(data, bytes) else data.encode("utf-8")
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        os.write(fd, raw)
        os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        os.close(fd) if not os.get_inheritable(fd) else None
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _write_key(path: Path, data: bytes) -> None:
    """Write key material with restrictive permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def _read_key(path: Path) -> bytes:
    """Read key material, warn if permissions are too open."""
    mode = path.stat().st_mode & 0o777
    if mode != 0o600:
        warnings.warn(
            f"Key file {path} has permissions {oct(mode)}, expected 0o600",
            stacklevel=2,
        )
    return path.read_bytes()


class PACTStore:
    """Filesystem storage for PACT agent data."""

    def __init__(self, base_dir: Path | None = None):
        self.base = base_dir or _default_base()

    def _agent_dir(self, name: str) -> Path:
        return self.base / "agents" / name

    # --- Keys ---

    def save_private_key(self, name: str, key: bytes, key_type: str = "current") -> None:
        filename = "private_key.bin" if key_type == "current" else "next_private_key.bin"
        _write_key(self._agent_dir(name) / filename, key)

    def load_private_key(self, name: str, key_type: str = "current") -> bytes:
        filename = "private_key.bin" if key_type == "current" else "next_private_key.bin"
        return _read_key(self._agent_dir(name) / filename)

    def has_agent(self, name: str) -> bool:
        return (self._agent_dir(name) / "private_key.bin").exists()

    # --- Identity document ---

    def save_identity(self, name: str, doc: dict) -> None:
        path = self._agent_dir(name) / "identity.json"
        _write_atomic(path, json.dumps(doc, indent=2))

    def load_identity(self, name: str) -> dict:
        path = self._agent_dir(name) / "identity.json"
        return json.loads(path.read_text())

    # --- Key event log ---

    def append_event(self, name: str, event: dict) -> None:
        path = self._agent_dir(name) / "event_log.json"
        if path.exists():
            events = json.loads(path.read_text())
        else:
            events = []
        events.append(event)
        _write_atomic(path, json.dumps(events, indent=2))

    def load_event_log(self, name: str) -> list[dict]:
        path = self._agent_dir(name) / "event_log.json"
        if not path.exists():
            return []
        return json.loads(path.read_text())

    # --- Capabilities ---

    def save_capability(self, name: str, cap: dict) -> None:
        cap_dir = self._agent_dir(name) / "capabilities"
        cap_dir.mkdir(parents=True, exist_ok=True)
        path = cap_dir / f"{cap['cap_id']}.json"
        _write_atomic(path, json.dumps(cap, indent=2))

    def load_capability(self, name: str, cap_id: str) -> dict | None:
        path = self._agent_dir(name) / "capabilities" / f"{cap_id}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text())

    def list_capabilities(self, name: str) -> list[dict]:
        cap_dir = self._agent_dir(name) / "capabilities"
        if not cap_dir.exists():
            return []
        caps = []
        for f in sorted(cap_dir.glob("*.json")):
            caps.append(json.loads(f.read_text()))
        return caps

    # --- Receipts ---

    def save_receipt(self, name: str, receipt: dict) -> None:
        rcpt_dir = self._agent_dir(name) / "receipts"
        rcpt_dir.mkdir(parents=True, exist_ok=True)
        ts = receipt.get("timestamp", "unknown")
        ref = receipt.get("task_ref", "unknown")[:8]
        path = rcpt_dir / f"{ts}-{ref}.json"
        _write_atomic(path, json.dumps(receipt, indent=2))

    def list_receipts(self, name: str) -> list[dict]:
        rcpt_dir = self._agent_dir(name) / "receipts"
        if not rcpt_dir.exists():
            return []
        receipts = []
        for f in sorted(rcpt_dir.glob("*.json")):
            receipts.append(json.loads(f.read_text()))
        return receipts

    # --- Messages ---

    def save_message(self, name: str, msg: dict) -> None:
        msg_dir = self._agent_dir(name) / "messages"
        msg_dir.mkdir(parents=True, exist_ok=True)
        path = msg_dir / f"{msg['id']}.json"
        _write_atomic(path, json.dumps(msg, indent=2))

    def load_message(self, name: str, msg_id: str) -> dict | None:
        path = self._agent_dir(name) / "messages" / f"{msg_id}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text())

    # --- Peers ---

    def save_peer(self, agent_id: str, doc: dict) -> None:
        peer_dir = self.base / "peers"
        peer_dir.mkdir(parents=True, exist_ok=True)
        safe_id = agent_id.replace(":", "_")
        path = peer_dir / f"{safe_id}.json"
        _write_atomic(path, json.dumps(doc, indent=2))

    def load_peer(self, agent_id: str) -> dict | None:
        safe_id = agent_id.replace(":", "_")
        path = self.base / "peers" / f"{safe_id}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text())

    def list_peers(self) -> list[dict]:
        peer_dir = self.base / "peers"
        if not peer_dir.exists():
            return []
        peers = []
        for f in sorted(peer_dir.glob("*.json")):
            peers.append(json.loads(f.read_text()))
        return peers

    # --- Agent listing ---

    def list_agents(self) -> list[str]:
        agents_dir = self.base / "agents"
        if not agents_dir.exists():
            return []
        return [d.name for d in sorted(agents_dir.iterdir()) if d.is_dir()]
