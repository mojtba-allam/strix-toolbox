"""Process-local toolbox state for the MCP server."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from strix.toolbox.filesystem import default_project_root
from strix.toolbox.reporting import FindingStore
from strix.toolbox.safety import TargetAllowlist


@dataclass
class ToolboxState:
    allowlist: TargetAllowlist = field(default_factory=TargetAllowlist)
    findings: FindingStore = field(default_factory=FindingStore)
    project_root: Path = field(default_factory=default_project_root)


_STATE: ToolboxState | None = None


def get_state() -> ToolboxState:
    global _STATE  # noqa: PLW0603
    if _STATE is None:
        _STATE = ToolboxState()
    return _STATE


def reset_state() -> ToolboxState:
    global _STATE  # noqa: PLW0603
    _STATE = ToolboxState()
    return _STATE
