"""Host filesystem inspection (PASSIVE)."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from strix.toolbox.models import Classification, ToolResult


_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "vendor",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
    }
)
_MAX_LIST = 500
_MAX_FILE_BYTES = 200_000
_MAX_HITS = 100


def default_project_root() -> Path:
    override = os.environ.get("STRIX_TOOLBOX_PROJECT_ROOT")
    if override:
        return Path(override).expanduser().resolve()
    return Path.cwd().resolve()


def _resolve_under_root(root: Path, rel: str | None) -> Path:
    base = root.resolve()
    if not rel or rel in {".", "./"}:
        return base
    candidate = (base / rel).resolve()
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"path escapes project root: {rel}") from exc
    return candidate


def _fail_passive(error: str) -> ToolResult:
    return ToolResult(success=False, classification=Classification.PASSIVE, error=error)


def project_info(root: Path | None = None) -> ToolResult:
    project = (root or default_project_root()).resolve()
    return ToolResult(
        success=True,
        classification=Classification.PASSIVE,
        data={
            "root": str(project),
            "exists": project.exists(),
            "is_dir": project.is_dir(),
            "name": project.name,
        },
    )


def list_files(
    *,
    root: Path | None = None,
    path: str = ".",
    max_entries: int = _MAX_LIST,
) -> ToolResult:
    project = (root or default_project_root()).resolve()
    try:
        target = _resolve_under_root(project, path)
    except ValueError as exc:
        return _fail_passive(str(exc))
    if not target.exists():
        return ToolResult(
            success=False,
            classification=Classification.PASSIVE,
            error=f"path not found: {path}",
        )
    entries: list[dict[str, Any]] = []
    truncated = False
    if target.is_file():
        stat = target.stat()
        entries.append(
            {
                "path": str(target.relative_to(project)),
                "type": "file",
                "size": stat.st_size,
            }
        )
    else:
        for dirpath, dirnames, filenames in os.walk(target):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            rel_dir = Path(dirpath).resolve()
            for name in sorted(dirnames):
                rel = (rel_dir / name).relative_to(project).as_posix()
                entries.append({"path": rel, "type": "directory"})
                if len(entries) >= max_entries:
                    truncated = True
                    break
            if truncated:
                break
            for name in sorted(filenames):
                file_path = rel_dir / name
                rel = file_path.relative_to(project).as_posix()
                try:
                    size = file_path.stat().st_size
                except OSError:
                    size = None
                entries.append({"path": rel, "type": "file", "size": size})
                if len(entries) >= max_entries:
                    truncated = True
                    break
            if truncated:
                break
    return ToolResult(
        success=True,
        classification=Classification.PASSIVE,
        data={"root": str(project), "entries": entries, "truncated": truncated},
    )


def read_file(
    *,
    path: str,
    root: Path | None = None,
    max_bytes: int = _MAX_FILE_BYTES,
) -> ToolResult:
    project = (root or default_project_root()).resolve()
    try:
        target = _resolve_under_root(project, path)
    except ValueError as exc:
        return _fail_passive(str(exc))
    if not target.is_file():
        return ToolResult(
            success=False,
            classification=Classification.PASSIVE,
            error=f"not a file: {path}",
        )
    data = target.read_bytes()
    truncated = len(data) > max_bytes
    payload = data[:max_bytes]
    try:
        text = payload.decode("utf-8")
        binary = False
    except UnicodeDecodeError:
        text = payload.decode("utf-8", errors="replace")
        binary = True
    return ToolResult(
        success=True,
        classification=Classification.PASSIVE,
        data={
            "path": str(target.relative_to(project)),
            "content": text,
            "truncated": truncated,
            "binary": binary,
            "size": len(data),
        },
    )


def search_code(
    *,
    pattern: str,
    root: Path | None = None,
    path: str = ".",
    glob: str | None = None,
    max_hits: int = _MAX_HITS,
) -> ToolResult:
    project = (root or default_project_root()).resolve()
    try:
        target = _resolve_under_root(project, path)
    except ValueError as exc:
        return _fail_passive(str(exc))
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        return ToolResult(
            success=False,
            classification=Classification.PASSIVE,
            error=f"invalid regex: {exc}",
        )
    hits: list[dict[str, Any]] = []
    truncated = False
    files: list[Path]
    if target.is_file():
        files = [target]
    else:
        files = []
        for dirpath, dirnames, filenames in os.walk(target):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for name in filenames:
                file_path = Path(dirpath) / name
                if glob and not file_path.match(glob):
                    continue
                files.append(file_path)
    for file_path in files:
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if regex.search(line):
                hits.append(
                    {
                        "file": str(file_path.resolve().relative_to(project)),
                        "line": lineno,
                        "text": line[:500],
                    }
                )
                if len(hits) >= max_hits:
                    truncated = True
                    break
        if truncated:
            break
    return ToolResult(
        success=True,
        classification=Classification.PASSIVE,
        data={"pattern": pattern, "hits": hits, "truncated": truncated},
    )
