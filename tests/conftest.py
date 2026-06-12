"""Shared test fixtures."""

import os
import pytest
import tempfile
from pathlib import Path

from pact_passport.store import PACTStore
from pact_passport.identity import Identity
from pact_passport import crypto


@pytest.fixture
def tmp_pact_home(tmp_path):
    """Set PACT_HOME to a temp directory for test isolation."""
    old = os.environ.get("PACT_HOME")
    os.environ["PACT_HOME"] = str(tmp_path)
    yield tmp_path
    if old:
        os.environ["PACT_HOME"] = old
    else:
        os.environ.pop("PACT_HOME", None)


@pytest.fixture
def store(tmp_pact_home):
    return PACTStore(tmp_pact_home)


@pytest.fixture
def alice(store):
    return Identity.create("alice", store)


@pytest.fixture
def bob(store):
    return Identity.create("bob", store)


@pytest.fixture
def keypair():
    return crypto.generate_keypair()
