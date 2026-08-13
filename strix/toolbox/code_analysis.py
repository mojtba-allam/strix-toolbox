"""SAST, secrets, and dependency scanners (PASSIVE)."""

from __future__ import annotations

from pathlib import Path

from strix.toolbox.exec import run_host, run_sandbox, which_host
from strix.toolbox.filesystem import default_project_root
from strix.toolbox.models import Classification, CommandResult, ToolResult
from strix.toolbox.parsers import (
    parse_bandit,
    parse_gitleaks,
    parse_semgrep,
    parse_trivy,
    parse_trufflehog,
)
from strix.toolbox.session import SandboxError, current_sandbox, require_sandbox


def _resolve_scan_path(path: str | None) -> tuple[Path, str]:
    """Return (host_path, sandbox_path)."""
    root = default_project_root()
    host = root if not path else (root / path).resolve()
    try:
        host.relative_to(root)
    except ValueError as exc:
        raise ValueError("scan path escapes project root") from exc
    handle = current_sandbox()
    if handle and handle.project_host:
        sandbox = "/workspace/project"
        if path and path not in {".", "./"}:
            sandbox = f"/workspace/project/{path.lstrip('./')}"
    else:
        sandbox = "/workspace"
    return host, sandbox


def _unavailable(tool: str, error: str) -> ToolResult:
    return ToolResult(
        success=False,
        classification=Classification.PASSIVE,
        unavailable=True,
        error=error,
        data={"tool": tool},
    )


def _prefer_sandbox_or_host(
    *,
    binary: str,
    host_argv: list[str],
    sandbox_argv: list[str],
    timeout: int,
) -> tuple[CommandResult, str] | ToolResult:
    handle = current_sandbox()
    if handle is not None:
        result = run_sandbox(handle, sandbox_argv, timeout=timeout)
        return result, "sandbox"
    if which_host(binary):
        result = run_host(host_argv, timeout=timeout)
        return result, "host"
    try:
        require_sandbox()
    except SandboxError as exc:
        return _unavailable(
            binary,
            f"{binary} is not installed on the host and no sandbox is running ({exc})",
        )
    return _unavailable(binary, f"{binary} is not available")


def _finish(
    *,
    tool: str,
    result: CommandResult,
    parsed: list[dict[str, object]],
    source: str,
) -> ToolResult:
    # Many SAST tools exit non-zero when they find issues.
    success = result.timed_out is False and result.error != f"binary not found: {tool}"
    if result.timed_out:
        success = False
    return ToolResult(
        success=success or bool(parsed),
        classification=Classification.PASSIVE,
        error=None if (success or parsed) else result.error,
        data={
            "tool": tool,
            "source": source,
            "findings": parsed,
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "truncated": result.truncated,
            "raw_output": result.stdout[:8000],
            "stderr": result.stderr[:2000],
        },
    )


def sast_semgrep(path: str | None = None, *, timeout: int = 180) -> ToolResult:
    try:
        host, sandbox = _resolve_scan_path(path)
    except ValueError as exc:
        return ToolResult(success=False, classification=Classification.PASSIVE, error=str(exc))
    outcome = _prefer_sandbox_or_host(
        binary="semgrep",
        host_argv=["semgrep", "scan", "--json", "--quiet", "--metrics=off", str(host)],
        sandbox_argv=["semgrep", "scan", "--json", "--quiet", "--metrics=off", sandbox],
        timeout=timeout,
    )
    if isinstance(outcome, ToolResult):
        return outcome
    result, source = outcome
    return _finish(
        tool="semgrep", result=result, parsed=parse_semgrep(result.stdout), source=source
    )


def sast_bandit(path: str | None = None, *, timeout: int = 120) -> ToolResult:
    try:
        host, sandbox = _resolve_scan_path(path)
    except ValueError as exc:
        return ToolResult(success=False, classification=Classification.PASSIVE, error=str(exc))
    outcome = _prefer_sandbox_or_host(
        binary="bandit",
        host_argv=["bandit", "-r", str(host), "-f", "json", "-q"],
        sandbox_argv=["bandit", "-r", sandbox, "-f", "json", "-q"],
        timeout=timeout,
    )
    if isinstance(outcome, ToolResult):
        return outcome
    result, source = outcome
    return _finish(tool="bandit", result=result, parsed=parse_bandit(result.stdout), source=source)


def find_secrets_gitleaks(path: str | None = None, *, timeout: int = 120) -> ToolResult:
    try:
        host, sandbox = _resolve_scan_path(path)
    except ValueError as exc:
        return ToolResult(success=False, classification=Classification.PASSIVE, error=str(exc))
    outcome = _prefer_sandbox_or_host(
        binary="gitleaks",
        host_argv=[
            "gitleaks",
            "detect",
            "--source",
            str(host),
            "--report-format",
            "json",
            "--no-banner",
            "--exit-code",
            "0",
        ],
        sandbox_argv=[
            "gitleaks",
            "detect",
            "--source",
            sandbox,
            "--report-format",
            "json",
            "--no-banner",
            "--exit-code",
            "0",
        ],
        timeout=timeout,
    )
    if isinstance(outcome, ToolResult):
        return outcome
    result, source = outcome
    parsed = parse_gitleaks(result.stdout)
    return _finish(tool="gitleaks", result=result, parsed=parsed, source=source)


def find_secrets_trufflehog(path: str | None = None, *, timeout: int = 180) -> ToolResult:
    try:
        host, sandbox = _resolve_scan_path(path)
    except ValueError as exc:
        return ToolResult(success=False, classification=Classification.PASSIVE, error=str(exc))
    outcome = _prefer_sandbox_or_host(
        binary="trufflehog",
        host_argv=["trufflehog", "filesystem", str(host), "--json", "--no-update"],
        sandbox_argv=["trufflehog", "filesystem", sandbox, "--json", "--no-update"],
        timeout=timeout,
    )
    if isinstance(outcome, ToolResult):
        return outcome
    result, source = outcome
    return _finish(
        tool="trufflehog",
        result=result,
        parsed=parse_trufflehog(result.stdout),
        source=source,
    )


def dependency_trivy(path: str | None = None, *, timeout: int = 180) -> ToolResult:
    try:
        host, sandbox = _resolve_scan_path(path)
    except ValueError as exc:
        return ToolResult(success=False, classification=Classification.PASSIVE, error=str(exc))
    outcome = _prefer_sandbox_or_host(
        binary="trivy",
        host_argv=["trivy", "fs", "--format", "json", "--quiet", str(host)],
        sandbox_argv=["trivy", "fs", "--format", "json", "--quiet", sandbox],
        timeout=timeout,
    )
    if isinstance(outcome, ToolResult):
        return outcome
    result, source = outcome
    return _finish(tool="trivy", result=result, parsed=parse_trivy(result.stdout), source=source)
