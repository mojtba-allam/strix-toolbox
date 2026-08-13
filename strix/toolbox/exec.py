"""Host and sandbox command execution with timeouts and truncation."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from typing import TYPE_CHECKING

from strix.toolbox.models import CommandResult


if TYPE_CHECKING:
    from collections.abc import Sequence

    from strix.toolbox.session import SandboxHandle


logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 60
MAX_OUTPUT_BYTES = 200_000
SANDBOX_PATH = (
    "/home/pentester/go/bin:/home/pentester/.local/bin:"
    "/home/pentester/.npm-global/bin:/usr/local/sbin:/usr/local/bin:"
    "/usr/sbin:/usr/bin:/sbin:/bin"
)


def which_host(binary: str) -> str | None:
    return shutil.which(binary)


def _truncate(text: str) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_OUTPUT_BYTES:
        return text, False
    clipped = encoded[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
    return clipped + "\n...[truncated]...", True


def run_host(
    argv: Sequence[str],
    *,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    cwd: str | os.PathLike[str] | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    if not argv:
        return CommandResult(success=False, error="command is empty", argv=[])
    merged = os.environ.copy()
    if env:
        merged.update(env)
    started = time.monotonic()
    try:
        completed = subprocess.run(  # noqa: S603
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=merged,
            check=False,
        )
    except FileNotFoundError:
        return CommandResult(
            success=False,
            argv=list(argv),
            error=f"binary not found: {argv[0]}",
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        stdout, trunc_out = _truncate(stdout)
        stderr, trunc_err = _truncate(stderr)
        return CommandResult(
            success=False,
            argv=list(argv),
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
            truncated=trunc_out or trunc_err,
            duration_ms=int((time.monotonic() - started) * 1000),
            error=f"timed out after {timeout}s",
        )
    stdout, trunc_out = _truncate(completed.stdout or "")
    stderr, trunc_err = _truncate(completed.stderr or "")
    duration_ms = int((time.monotonic() - started) * 1000)
    return CommandResult(
        success=completed.returncode == 0,
        exit_code=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        truncated=trunc_out or trunc_err,
        argv=list(argv),
        duration_ms=duration_ms,
        error=None if completed.returncode == 0 else f"exit {completed.returncode}",
    )


def run_sandbox(
    handle: SandboxHandle,
    argv: Sequence[str],
    *,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    workdir: str = "/workspace",
) -> CommandResult:
    """Run an argv list inside the sandbox via ``timeout`` + docker exec."""
    if not argv:
        return CommandResult(success=False, error="command is empty", argv=[])
    wrapped = ["timeout", "--kill-after=5", str(timeout), *argv]
    started = time.monotonic()
    try:
        result = handle.exec(wrapped, workdir=workdir, timeout=timeout + 10)
    except Exception as exc:  # noqa: BLE001
        logger.debug("sandbox exec failed", exc_info=True)
        return CommandResult(
            success=False,
            argv=list(argv),
            duration_ms=int((time.monotonic() - started) * 1000),
            error=str(exc),
        )
    stdout, trunc_out = _truncate(result.stdout)
    stderr, trunc_err = _truncate(result.stderr)
    timed_out = result.exit_code in {124, 137}
    return CommandResult(
        success=result.exit_code == 0 and not timed_out,
        exit_code=result.exit_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        truncated=trunc_out or trunc_err,
        argv=list(argv),
        duration_ms=int((time.monotonic() - started) * 1000),
        error=None if result.exit_code == 0 else (result.error or f"exit {result.exit_code}"),
    )
