"""Tests for pact doctor (Phase 3)."""

import subprocess
import sys
import os

import pytest

# Doctor checks POSIX-style 0o600 file permissions. NTFS reports 0o666 for
# user files regardless of actual ACLs, so doctor always reports a
# permissions issue on Windows. Tracked as issue #6.
windows_only_skip = pytest.mark.skipif(
    sys.platform == "win32",
    reason="doctor's POSIX permission check is not applicable on Windows (issue #6)",
)


@windows_only_skip
def test_doctor_healthy(tmp_pact_home):
    """Doctor passes on a healthy agent."""
    env = {**os.environ, "PACT_HOME": str(tmp_pact_home)}
    py = sys.executable or "/Library/Frameworks/Python.framework/Versions/3.13/bin/python3"

    # Create agent
    result = subprocess.run(
        [py, "-m", "pact_passport.cli", "init", "healthy"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0

    # Run doctor
    result = subprocess.run(
        [py, "-m", "pact_passport.cli", "doctor", "healthy"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "All checks passed" in result.stdout


@windows_only_skip
def test_doctor_after_rotation(tmp_pact_home):
    """Doctor passes after key rotation."""
    env = {**os.environ, "PACT_HOME": str(tmp_pact_home)}
    py = sys.executable or "/Library/Frameworks/Python.framework/Versions/3.13/bin/python3"

    subprocess.run([py, "-m", "pact_passport.cli", "init", "rotated"], env=env, capture_output=True)
    subprocess.run([py, "-m", "pact_passport.cli", "rotate", "rotated"], env=env, capture_output=True)

    result = subprocess.run(
        [py, "-m", "pact_passport.cli", "doctor", "rotated"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "All checks passed" in result.stdout


@windows_only_skip
def test_doctor_bad_permissions(tmp_pact_home):
    """Doctor catches bad key permissions."""
    env = {**os.environ, "PACT_HOME": str(tmp_pact_home)}
    py = sys.executable or "/Library/Frameworks/Python.framework/Versions/3.13/bin/python3"

    subprocess.run([py, "-m", "pact_passport.cli", "init", "badperms"], env=env, capture_output=True)

    # Make key world-readable
    key_path = tmp_pact_home / "agents" / "badperms" / "private_key.bin"
    key_path.chmod(0o644)

    result = subprocess.run(
        [py, "-m", "pact_passport.cli", "doctor", "badperms"],
        env=env, capture_output=True, text=True,
    )
    assert result.returncode == 1
    assert "should be 0o600" in result.stdout
