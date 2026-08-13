"""Toolbox must start without LLM credentials or agent-loop imports."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]

LLM_VARS = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "LLM_API_KEY",
    "OPENROUTER_API_KEY",
    "STRIX_LLM",
)


def test_import_does_not_load_agent_loop() -> None:
    env = os.environ.copy()
    for name in LLM_VARS:
        env.pop(name, None)
    script = (
        "import sys\n"
        "from strix.toolbox import cli, selftest\n"
        "forbidden = {'strix.agents.factory', 'strix.interface.main'}\n"
        "loaded = forbidden.intersection(sys.modules)\n"
        "assert not loaded, loaded\n"
        "print('ok')\n"
    )
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "ok" in completed.stdout


def test_cli_help_without_keys() -> None:
    env = os.environ.copy()
    for name in LLM_VARS:
        env.pop(name, None)
    completed = subprocess.run(
        [sys.executable, "-m", "strix.toolbox.cli", "--help"],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "strix-toolbox" in completed.stdout
    assert "mcp" in completed.stdout
