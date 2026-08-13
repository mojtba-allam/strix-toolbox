"""Explicit target allowlisting for active network tests."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from strix.toolbox.models import AuthorizedTarget, TargetKind


_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "host.docker.internal"})
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9-]{1,63}$"
)
_UNSAFE_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class SafetyError(ValueError):
    """Invalid or unauthorized target."""


class UnauthorizedTargetError(SafetyError):
    """A network target was not explicitly authorized."""


def _clean(value: str) -> str:
    text = value.strip()
    if not text:
        raise SafetyError("target must not be empty")
    if _UNSAFE_CHARS.search(text):
        raise SafetyError("target contains control characters")
    if "\n" in text or "\r" in text:
        raise SafetyError("target must be a single line")
    return text


def parse_host_from_target(value: str) -> str:
    """Extract a hostname or IP from a URL, host:port, or bare host."""
    text = _clean(value)
    if "://" in text:
        parsed = urlparse(text)
        if parsed.scheme not in {"http", "https"}:
            raise SafetyError(f"unsupported URL scheme: {parsed.scheme!r}")
        host = parsed.hostname
        if not host:
            raise SafetyError("URL is missing a host")
        return host.lower()
    if text.startswith("[") and "]" in text:
        return text[1 : text.index("]")].lower()
    if text.count(":") == 1 and not text.startswith(":"):
        host, _port = text.rsplit(":", 1)
        return host.lower()
    return text.lower().rstrip(".")


def is_local_host(host: str) -> bool:
    candidate = host.strip("[]").lower().rstrip(".")
    if candidate in _LOCAL_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return bool(ip.is_loopback or (ip.is_private and str(ip).startswith("127.")))


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def normalize_target_spec(spec: str) -> tuple[TargetKind, str]:
    text = _clean(spec)
    path = Path(text).expanduser()
    if text.startswith(("/", "./", "../")) or path.exists():
        resolved = path.resolve()
        if not resolved.exists():
            raise SafetyError(f"local path does not exist: {text}")
        return TargetKind.PATH, str(resolved)
    if "/" in text and not text.startswith("http") and _looks_like_cidr(text):
        network = ipaddress.ip_network(text, strict=False)
        return TargetKind.CIDR, str(network)
    if "://" in text:
        parsed = urlparse(text)
        if parsed.scheme not in {"http", "https"}:
            raise SafetyError(f"unsupported URL scheme: {parsed.scheme!r}")
        if not parsed.hostname:
            raise SafetyError("URL is missing a host")
        return TargetKind.URL, text
    host = parse_host_from_target(text)
    _validate_host(host)
    return TargetKind.HOST, host


def _looks_like_cidr(text: str) -> bool:
    return "/" in text and any(ch.isdigit() for ch in text.split("/", 1)[0])


def _validate_host(host: str) -> None:
    if _is_ip(host):
        return
    if host.startswith("*."):
        rest = host[2:]
        if not _HOST_RE.match(rest):
            raise SafetyError(f"invalid wildcard host: {host}")
        return
    if not _HOST_RE.match(host) and host not in _LOCAL_HOSTS:
        raise SafetyError(f"invalid host: {host}")


def _host_matches(pattern: str, host: str) -> bool:
    host_n = host.strip("[]").lower().rstrip(".")
    pattern_n = pattern.strip("[]").lower().rstrip(".")
    if pattern_n == host_n:
        return True
    if pattern_n.startswith("*."):
        suffix = pattern_n[1:]  # .example.com
        return host_n.endswith(suffix) and host_n != pattern_n[2:]
    return False


class TargetAllowlist:
    """Process-local allowlist. Discovered recon hosts are never added automatically."""

    def __init__(self) -> None:
        self._entries: dict[str, AuthorizedTarget] = {}
        for host in ("localhost", "127.0.0.1", "::1"):
            self._add(
                AuthorizedTarget(
                    id=f"implicit-{host}",
                    kind=TargetKind.HOST,
                    value=host,
                    implicit=True,
                    note="loopback default",
                )
            )

    def _add(self, entry: AuthorizedTarget) -> AuthorizedTarget:
        key = f"{entry.kind}:{entry.value}"
        existing = next((e for e in self._entries.values() if f"{e.kind}:{e.value}" == key), None)
        if existing is not None:
            return existing
        self._entries[entry.id] = entry
        return entry

    def authorize(self, spec: str, *, note: str = "") -> AuthorizedTarget:
        kind, value = normalize_target_spec(spec)
        if kind in {TargetKind.HOST, TargetKind.URL}:
            host = parse_host_from_target(value)
            _validate_host(host)
        entry = AuthorizedTarget(
            id=str(uuid4()),
            kind=kind,
            value=value,
            implicit=False,
            note=note,
        )
        return self._add(entry)

    def revoke(self, target_id: str) -> bool:
        entry = self._entries.get(target_id)
        if entry is None:
            return False
        if entry.implicit:
            raise SafetyError("cannot revoke implicit loopback targets")
        del self._entries[target_id]
        return True

    def list_targets(self) -> list[AuthorizedTarget]:
        return list(self._entries.values())

    def is_path_allowed(self, path: Path) -> bool:
        resolved = path.expanduser().resolve()
        for entry in self._entries.values():
            if entry.kind != TargetKind.PATH:
                continue
            root = Path(entry.value)
            try:
                resolved.relative_to(root)
            except ValueError:
                continue
            else:
                return True
        return False

    def is_network_allowed(self, target: str) -> bool:
        host = parse_host_from_target(target)
        if is_local_host(host):
            return True
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            ip = None
        for entry in self._entries.values():
            if entry.kind == TargetKind.HOST and _host_matches(entry.value, host):
                return True
            if entry.kind == TargetKind.URL and parse_host_from_target(entry.value) == host:
                return True
            if entry.kind == TargetKind.CIDR and ip is not None:
                network = ipaddress.ip_network(entry.value, strict=False)
                if ip in network:
                    return True
        return False

    def require_network(self, target: str) -> None:
        if not self.is_network_allowed(target):
            raise UnauthorizedTargetError(
                "target is not authorized. Call strix_authorize_target with an explicit "
                f"host/URL first. Received: {target!r}"
            )


def active_testing_warning(*, tool: str, classification: str) -> str:
    return (
        f"{tool} is classified {classification}. It performs an active test against an "
        "explicitly authorized target only. Do not scan hosts discovered incidentally."
    )


def dump_allowlist(allowlist: TargetAllowlist) -> list[dict[str, Any]]:
    return [entry.model_dump(mode="json") for entry in allowlist.list_targets()]
