"""Runtime self-test that never requires LLM credentials."""

from __future__ import annotations

import os
import sys
import tempfile
from importlib import import_module, metadata
from pathlib import Path
from typing import Any

from strix.toolbox.filesystem import list_files, project_info
from strix.toolbox.session import docker_available, image_present


LLM_ENV_VARS = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "LLM_API_KEY",
    "OPENROUTER_API_KEY",
    "STRIX_LLM",
    "PERPLEXITY_API_KEY",
)


def _status(ok: bool, *, skip: bool = False, detail: str = "") -> dict[str, Any]:
    if skip:
        label = "SKIP"
    elif ok:
        label = "PASS"
    else:
        label = "FAIL"
    return {"status": label, "ok": ok, "skip": skip, "detail": detail}


def run_self_test() -> dict[str, Any]:
    checks: dict[str, dict[str, Any]] = {}

    py_ok = sys.version_info >= (3, 12)
    checks["Runtime"] = _status(
        py_ok,
        detail=f"Python {sys.version.split()[0]} (requires >= 3.12)",
    )

    mcp_ok = False
    mcp_detail = ""
    try:
        import mcp

        mcp_ok = True
        mcp_detail = f"mcp {getattr(mcp, '__version__', 'unknown')}"
    except Exception as exc:  # noqa: BLE001
        mcp_detail = str(exc)
    checks["MCP"] = _status(mcp_ok, detail=mcp_detail)

    docker_ok, docker_detail = docker_available()
    if docker_ok:
        img = image_present()
        docker_detail = "daemon reachable" + (
            "; sandbox image present" if img else "; sandbox image not pulled"
        )
        checks["Docker"] = _status(True, detail=docker_detail)
    else:
        checks["Docker"] = _status(False, skip=True, detail=docker_detail)

    browser_detail = "requires sandbox image (agent-browser)"
    if docker_ok and image_present():
        checks["Browser"] = _status(
            True, detail="sandbox image present; browser available after strix_sandbox_start"
        )
    else:
        checks["Browser"] = _status(False, skip=True, detail=browser_detail)

    try:
        import requests

        http_ok = True
        http_detail = f"requests {requests.__version__}"
    except Exception as exc:  # noqa: BLE001
        http_ok = False
        http_detail = str(exc)
    checks["HTTP tools"] = _status(http_ok, detail=http_detail)

    fs_ok = False
    fs_detail = ""
    try:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "hello.txt"
            sample.write_text("ok\n", encoding="utf-8")
            info = project_info(Path(tmp))
            listed = list_files(root=Path(tmp))
            fs_ok = info.success and listed.success
            fs_detail = f"writable temp dir {tmp}"
    except OSError as exc:
        fs_detail = str(exc)
    checks["Filesystem tools"] = _status(fs_ok, detail=fs_detail)

    llm_present = [name for name in LLM_ENV_VARS if os.environ.get(name)]
    checks["LLM dependency"] = {
        "status": "NOT REQUIRED",
        "ok": True,
        "skip": False,
        "detail": (
            "toolbox does not use LLM credentials"
            + (f" (ignored present: {', '.join(llm_present)})" if llm_present else "")
        ),
    }

    required = ["Runtime", "MCP", "HTTP tools", "Filesystem tools"]
    overall_ok = all(checks[name]["ok"] for name in required)
    return {
        "checks": checks,
        "overall": "PASS" if overall_ok else "FAIL",
        "ok": overall_ok,
        "version": _toolbox_version(),
    }


def _toolbox_version() -> str:
    for name in ("strix-toolbox", "strix-agent"):
        try:
            return metadata.version(name)
        except metadata.PackageNotFoundError:
            continue
    return "dev"


def format_self_test(report: dict[str, Any]) -> str:
    lines = ["Strix Toolbox Self-Test", ""]
    for name, check in report["checks"].items():
        extra = f"  ({check['detail']})" if check.get("detail") else ""
        lines.append(f"{name}: {check['status']}{extra}")
    lines.append("")
    lines.append(f"Overall: {report['overall']}")
    return "\n".join(lines)


def assert_no_llm_imports() -> None:
    """Raise if toolbox import pulled the agent loop."""
    forbidden = ("strix.agents.factory", "strix.interface.main", "strix.llm.compaction")
    loaded = set(sys.modules)
    for name in forbidden:
        if name in loaded:
            raise RuntimeError(f"forbidden module imported: {name}")
    import_module("strix.toolbox")
