"""Allowlisted agent-browser verbs inside the sandbox (ACTIVE)."""

from __future__ import annotations

from typing import Literal

from strix.toolbox.exec import run_sandbox
from strix.toolbox.models import Classification, ToolResult
from strix.toolbox.safety import TargetAllowlist, UnauthorizedTargetError, active_testing_warning
from strix.toolbox.session import SandboxError, require_sandbox


InteractAction = Literal["click", "type", "js", "snapshot"]
_SESSION = "strix-toolbox"


def _browser(argv: list[str], *, timeout: int = 60) -> ToolResult:
    try:
        handle = require_sandbox()
    except SandboxError as exc:
        return ToolResult(
            success=False,
            classification=Classification.ACTIVE,
            unavailable=True,
            error=str(exc),
        )
    result = run_sandbox(handle, ["agent-browser", "--session", _SESSION, *argv], timeout=timeout)
    return ToolResult(
        success=result.success,
        classification=Classification.ACTIVE,
        warning=active_testing_warning(tool="strix_browser", classification="ACTIVE"),
        error=result.error if not result.success else None,
        data={
            "stdout": result.stdout[:8000],
            "stderr": result.stderr[:2000],
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
        },
    )


def browser_open(allowlist: TargetAllowlist, url: str, *, timeout: int = 60) -> ToolResult:
    try:
        allowlist.require_network(url)
    except UnauthorizedTargetError as exc:
        return ToolResult(success=False, classification=Classification.ACTIVE, error=str(exc))
    return _browser(["open", url], timeout=timeout)


def browser_screenshot(*, timeout: int = 60) -> ToolResult:
    return _browser(["screenshot"], timeout=timeout)


def browser_interact(
    *,
    action: InteractAction,
    target: str | None = None,
    text: str | None = None,
    timeout: int = 60,
) -> ToolResult:
    if action == "snapshot":
        return _browser(["snapshot", "-i"], timeout=timeout)
    if action == "click":
        if not target:
            return ToolResult(
                success=False,
                classification=Classification.ACTIVE,
                error="click requires target (e.g. @e3 or a CSS selector)",
            )
        return _browser(["click", target], timeout=timeout)
    if action == "type":
        if not target or text is None:
            return ToolResult(
                success=False,
                classification=Classification.ACTIVE,
                error="type requires target and text",
            )
        return _browser(["fill", target, text], timeout=timeout)
    if action == "js":
        if not text:
            return ToolResult(
                success=False,
                classification=Classification.ACTIVE,
                error="js requires text containing JavaScript to evaluate",
            )
        return _browser(["eval", text], timeout=timeout)
    return ToolResult(
        success=False,
        classification=Classification.ACTIVE,
        error=f"unsupported action: {action}",
    )
