"""Target allowlist tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.toolbox.safety import (
    SafetyError,
    TargetAllowlist,
    UnauthorizedTargetError,
    parse_host_from_target,
)


def test_localhost_allowed_by_default() -> None:
    allowlist = TargetAllowlist()
    allowlist.require_network("http://127.0.0.1:8000/health")
    allowlist.require_network("https://localhost/login")
    allowlist.require_network("http://[::1]/")


def test_remote_host_rejected_until_authorized() -> None:
    allowlist = TargetAllowlist()
    with pytest.raises(UnauthorizedTargetError):
        allowlist.require_network("https://example.com/login")
    entry = allowlist.authorize("example.com")
    assert entry.kind.value == "host"
    allowlist.require_network("https://example.com/admin")


def test_wildcard_does_not_auto_authorize_other_tlds() -> None:
    allowlist = TargetAllowlist()
    allowlist.authorize("*.example.com")
    allowlist.require_network("https://api.example.com")
    with pytest.raises(UnauthorizedTargetError):
        allowlist.require_network("https://example.org")


def test_discovered_host_not_implicit() -> None:
    allowlist = TargetAllowlist()
    allowlist.authorize("https://app.test")
    names = {item.value for item in allowlist.list_targets()}
    assert "evil.test" not in names
    with pytest.raises(UnauthorizedTargetError):
        allowlist.require_network("https://evil.test")


def test_path_authorize(tmp_path: Path) -> None:
    allowlist = TargetAllowlist()
    entry = allowlist.authorize(str(tmp_path))
    assert entry.kind.value == "path"
    assert allowlist.is_path_allowed(tmp_path / "a.txt")


def test_invalid_scheme() -> None:
    allowlist = TargetAllowlist()
    with pytest.raises(SafetyError):
        allowlist.authorize("ftp://example.com")


def test_parse_host() -> None:
    assert parse_host_from_target("https://API.Example.COM:8443/x") == "api.example.com"


def test_cannot_revoke_implicit() -> None:
    allowlist = TargetAllowlist()
    implicit = next(item for item in allowlist.list_targets() if item.implicit)
    with pytest.raises(SafetyError):
        allowlist.revoke(implicit.id)
