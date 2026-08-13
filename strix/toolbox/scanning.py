"""Allowlisted recon and scanning wrappers (ACTIVE)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from strix.toolbox.exec import run_sandbox
from strix.toolbox.models import Classification, ToolResult
from strix.toolbox.parsers import (
    parse_ffuf,
    parse_httpx,
    parse_katana,
    parse_naabu,
    parse_nmap_xml,
    parse_nuclei,
    parse_subfinder,
    parse_wafw00f,
)
from strix.toolbox.safety import TargetAllowlist, UnauthorizedTargetError, active_testing_warning
from strix.toolbox.session import SandboxError, require_sandbox


_DEFAULT_FFUF_WORDS = (
    "admin",
    "api",
    "login",
    "logout",
    "dashboard",
    "debug",
    "config",
    "backup",
    "test",
    "dev",
    "internal",
    "status",
    "health",
    "metrics",
    "graphql",
    "swagger",
    "docs",
    "uploads",
    "static",
    "assets",
    "robots.txt",
    ".env",
    ".git",
    "wp-admin",
    "phpinfo",
    "server-status",
    "actuator",
    "console",
)


def _unavailable(tool: str, error: str) -> ToolResult:
    return ToolResult(
        success=False,
        classification=Classification.ACTIVE,
        unavailable=True,
        error=error,
        data={"tool": tool},
    )


def _require_target(allowlist: TargetAllowlist, target: str) -> ToolResult | None:
    try:
        allowlist.require_network(target)
    except UnauthorizedTargetError as exc:
        return ToolResult(success=False, classification=Classification.ACTIVE, error=str(exc))
    return None


def _run(
    argv: list[str],
    *,
    timeout: int,
    parser: Any,
    tool: str,
    extra: dict[str, Any] | None = None,
) -> ToolResult:
    try:
        handle = require_sandbox()
    except SandboxError as exc:
        return _unavailable(tool, str(exc))
    result = run_sandbox(handle, argv, timeout=timeout)
    parsed = parser(result.stdout) if result.stdout else parser(result.stderr)
    return ToolResult(
        success=result.success or bool(parsed),
        classification=Classification.ACTIVE,
        warning=active_testing_warning(tool=tool, classification="ACTIVE"),
        error=None if (result.success or parsed) else result.error,
        data={
            "tool": tool,
            "parsed": parsed,
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "truncated": result.truncated,
            "raw_output": result.stdout[:8000],
            "stderr": result.stderr[:2000],
            **(extra or {}),
        },
    )


def recon_subfinder(allowlist: TargetAllowlist, domain: str, *, timeout: int = 90) -> ToolResult:
    blocked = _require_target(allowlist, domain)
    if blocked:
        return blocked
    return _run(
        ["subfinder", "-d", domain, "-silent", "-json"],
        timeout=timeout,
        parser=parse_subfinder,
        tool="strix_recon_subfinder",
        extra={"note": "Discovered hosts are NOT authorized automatically."},
    )


def recon_httpx(allowlist: TargetAllowlist, target: str, *, timeout: int = 90) -> ToolResult:
    blocked = _require_target(allowlist, target)
    if blocked:
        return blocked
    return _run(
        ["httpx", "-u", target, "-silent", "-json", "-title", "-tech-detect", "-status-code"],
        timeout=timeout,
        parser=parse_httpx,
        tool="strix_recon_httpx",
    )


def recon_naabu(
    allowlist: TargetAllowlist,
    target: str,
    *,
    ports: str = "top-100",
    timeout: int = 120,
) -> ToolResult:
    blocked = _require_target(allowlist, target)
    if blocked:
        return blocked
    argv = ["naabu", "-host", target, "-silent", "-json"]
    if ports == "top-100":
        argv.extend(["-top-ports", "100"])
    elif ports == "top-1000":
        argv.extend(["-top-ports", "1000"])
    else:
        argv.extend(["-p", ports])
    return _run(argv, timeout=timeout, parser=parse_naabu, tool="strix_recon_naabu")


def recon_nmap(
    allowlist: TargetAllowlist,
    target: str,
    *,
    ports: str | None = None,
    scan_type: str = "connect",
    version_detect: bool = False,
    timeout: int = 180,
) -> ToolResult:
    blocked = _require_target(allowlist, target)
    if blocked:
        return blocked
    if scan_type not in {"connect", "syn"}:
        return ToolResult(
            success=False,
            classification=Classification.ACTIVE,
            error="scan_type must be 'connect' or 'syn'",
        )
    argv = ["nmap", "-Pn", "-oX", "-"]
    argv.append("-sS" if scan_type == "syn" else "-sT")
    if version_detect:
        argv.append("-sV")
    if ports:
        argv.extend(["-p", ports])
    argv.append(target)
    return _run(argv, timeout=timeout, parser=parse_nmap_xml, tool="strix_recon_nmap")


def recon_katana(allowlist: TargetAllowlist, url: str, *, timeout: int = 120) -> ToolResult:
    blocked = _require_target(allowlist, url)
    if blocked:
        return blocked
    return _run(
        ["katana", "-u", url, "-silent", "-jsonl", "-depth", "2"],
        timeout=timeout,
        parser=parse_katana,
        tool="strix_recon_katana",
        extra={"note": "Crawled URLs on other hosts are NOT authorized automatically."},
    )


def detect_waf(allowlist: TargetAllowlist, url: str, *, timeout: int = 60) -> ToolResult:
    blocked = _require_target(allowlist, url)
    if blocked:
        return blocked
    return _run(
        ["wafw00f", url],
        timeout=timeout,
        parser=parse_wafw00f,
        tool="strix_detect_waf",
    )


def scan_nuclei(
    allowlist: TargetAllowlist,
    target: str,
    *,
    severity: str | None = None,
    timeout: int = 180,
) -> ToolResult:
    blocked = _require_target(allowlist, target)
    if blocked:
        return blocked
    argv = ["nuclei", "-u", target, "-jsonl", "-silent"]
    if severity:
        argv.extend(["-severity", severity])
    return _run(argv, timeout=timeout, parser=parse_nuclei, tool="strix_scan_nuclei")


def fuzz_ffuf(
    allowlist: TargetAllowlist,
    url: str,
    *,
    wordlist: list[str] | None = None,
    timeout: int = 120,
) -> ToolResult:
    blocked = _require_target(allowlist, url)
    if blocked:
        return blocked
    if "FUZZ" not in url:
        return ToolResult(
            success=False,
            classification=Classification.ACTIVE,
            error="url must contain the FUZZ keyword (e.g. https://127.0.0.1/FUZZ)",
        )
    try:
        handle = require_sandbox()
    except SandboxError as exc:
        return _unavailable("strix_fuzz_ffuf", str(exc))
    words = wordlist or list(_DEFAULT_FFUF_WORDS)
    cleaned: list[str] = []
    for word in words:
        token = word.strip()
        if not token or len(token) > 128:
            continue
        if any(ch in token for ch in ("\n", "\r", "\x00")):
            continue
        cleaned.append(token)
    if not cleaned:
        return ToolResult(
            success=False,
            classification=Classification.ACTIVE,
            error="wordlist is empty after validation",
        )
    import base64

    payload = base64.b64encode("\n".join(cleaned).encode("utf-8")).decode("ascii")
    staged = run_sandbox(
        handle,
        [
            "python3",
            "-c",
            (
                "import base64, pathlib; "
                f"pathlib.Path('/tmp/strix-toolbox-ffuf.txt').write_bytes(base64.b64decode('{payload}'))"
            ),
        ],
        timeout=10,
    )
    if not staged.success:
        return ToolResult(
            success=False,
            classification=Classification.ACTIVE,
            error=f"failed to stage wordlist: {staged.error}",
        )
    return _run(
        [
            "ffuf",
            "-u",
            url,
            "-w",
            "/tmp/strix-toolbox-ffuf.txt",
            "-of",
            "json",
            "-o",
            "/tmp/strix-toolbox-ffuf.json",
            "-s",
        ],
        timeout=timeout,
        parser=lambda _stdout: _read_ffuf_json(handle),
        tool="strix_fuzz_ffuf",
    )


def _read_ffuf_json(handle: Any) -> list[dict[str, Any]]:
    outcome = handle.exec(["cat", "/tmp/strix-toolbox-ffuf.json"], timeout=10)
    return parse_ffuf(outcome.stdout)


def sandbox_project_path() -> str:
    from strix.toolbox.session import current_sandbox

    handle = current_sandbox()
    if handle and handle.project_host:
        return "/workspace/project"
    return "/workspace"


def default_wordlist_path() -> Path:
    return Path(__file__).resolve().parent / "wordlists" / "common.txt"
