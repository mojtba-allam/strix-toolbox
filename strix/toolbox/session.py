"""Docker sandbox lifecycle without the openai-agents SDK."""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from strix.toolbox.exec import SANDBOX_PATH
from strix.toolbox.models import CommandResult


logger = logging.getLogger(__name__)

DEFAULT_IMAGE = "ghcr.io/usestrix/strix-sandbox:1.3.0"
CAIDO_PORT = 48080
_LOGIN_BODY = b'{"query":"mutation { loginAsGuest { token { accessToken } } }"}'


def run_async(coro: Any) -> Any:
    """Run a coroutine even if the caller already has an event loop (MCP)."""
    import asyncio

    result: dict[str, Any] = {}
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            result["value"] = asyncio.run(coro)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join()
    if errors:
        raise errors[0]
    return result.get("value")


class SandboxError(RuntimeError):
    """Sandbox is missing or failed."""


@dataclass
class ExecOutcome:
    exit_code: int
    stdout: str
    stderr: str
    error: str | None = None


@dataclass
class SandboxHandle:
    session_id: str
    container_id: str
    image: str
    workspace_host: str
    project_host: str | None
    caido_host_url: str | None = None
    caido_client: Any = None
    started_at: float = field(default_factory=time.time)

    def exec(
        self,
        argv: list[str],
        *,
        workdir: str = "/workspace",
        timeout: int = 70,
    ) -> ExecOutcome:
        import docker

        client = docker.from_env()
        try:
            container = client.containers.get(self.container_id)
            exec_result = container.exec_run(
                argv,
                user="pentester",
                workdir=workdir,
                environment={
                    "PATH": SANDBOX_PATH,
                    "PYTHONUNBUFFERED": "1",
                    "http_proxy": f"http://127.0.0.1:{CAIDO_PORT}",
                    "https_proxy": f"http://127.0.0.1:{CAIDO_PORT}",
                    "HTTP_PROXY": f"http://127.0.0.1:{CAIDO_PORT}",
                    "HTTPS_PROXY": f"http://127.0.0.1:{CAIDO_PORT}",
                    "ALL_PROXY": f"http://127.0.0.1:{CAIDO_PORT}",
                    "NO_PROXY": "localhost,127.0.0.1",
                },
                demux=True,
            )
        finally:
            client.close()
        exit_code = int(exec_result.exit_code or 0)
        stdout_b, stderr_b = exec_result.output or (b"", b"")
        stdout = (stdout_b or b"").decode("utf-8", errors="replace")
        stderr = (stderr_b or b"").decode("utf-8", errors="replace")
        return ExecOutcome(exit_code=exit_code, stdout=stdout, stderr=stderr)

    def logs(self, tail: int = 200) -> str:
        import docker

        client = docker.from_env()
        try:
            container = client.containers.get(self.container_id)
            raw = container.logs(tail=tail)
        finally:
            client.close()
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        return str(raw)

    def status(self) -> dict[str, Any]:
        import docker

        client = docker.from_env()
        try:
            container = client.containers.get(self.container_id)
            container.reload()
            state = container.attrs.get("State", {})
            running = bool(state.get("Running"))
        except Exception as exc:  # noqa: BLE001
            return {
                "running": False,
                "session_id": self.session_id,
                "error": str(exc),
            }
        finally:
            client.close()
        return {
            "running": running,
            "session_id": self.session_id,
            "container_id": self.container_id[:12],
            "image": self.image,
            "caido_url": self.caido_host_url,
            "project_mount": self.project_host,
            "uptime_s": int(time.time() - self.started_at),
        }


_LOCK = threading.Lock()
_CURRENT: SandboxHandle | None = None


def current_sandbox() -> SandboxHandle | None:
    return _CURRENT


def require_sandbox() -> SandboxHandle:
    handle = _CURRENT
    if handle is None:
        raise SandboxError(
            "sandbox is not running. Call strix_sandbox_start first "
            "(requires Docker and the Strix sandbox image)."
        )
    return handle


def docker_available() -> tuple[bool, str]:
    try:
        import docker
        from docker.errors import DockerException
    except ImportError:
        return False, "docker Python package is not installed"
    try:
        client = docker.from_env()
        client.ping()
        client.close()
    except DockerException as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
    return True, "ok"


def image_present(image: str | None = None) -> bool:
    import docker
    from docker.errors import ImageNotFound

    name = image or _default_image()
    client = docker.from_env()
    try:
        client.images.get(name)
    except ImageNotFound:
        return False
    finally:
        client.close()
    return True


def _default_image() -> str:
    return os.environ.get("STRIX_IMAGE", DEFAULT_IMAGE)


def start_sandbox(
    *,
    project_path: str | None = None,
    image: str | None = None,
    pull: bool = False,
) -> SandboxHandle:
    """Start (or reuse) the toolbox sandbox container."""
    global _CURRENT  # noqa: PLW0603
    with _LOCK:
        if _CURRENT is not None:
            status = _CURRENT.status()
            if status.get("running"):
                return _CURRENT
            _CURRENT = None

        ok, reason = docker_available()
        if not ok:
            raise SandboxError(f"Docker is not available: {reason}")

        import docker
        from docker.types import Mount

        image_name = image or _default_image()
        client = docker.from_env()
        if pull or not image_present(image_name):
            logger.info("Pulling sandbox image %s", image_name)
            client.images.pull(image_name)

        workspace_host = tempfile.mkdtemp(prefix="strix-toolbox-ws-")
        mounts = [
            Mount(target="/workspace", source=workspace_host, type="bind"),
        ]
        project_host: str | None = None
        if project_path:
            resolved = Path(project_path).expanduser().resolve()
            if not resolved.is_dir():
                raise SandboxError(f"project_path is not a directory: {resolved}")
            project_host = str(resolved)
            mounts.append(
                Mount(target="/workspace/project", source=project_host, type="bind"),
            )

        environment = {
            "PYTHONUNBUFFERED": "1",
            "HOST_GATEWAY": "host.docker.internal",
        }
        if os.name == "posix":
            environment["STRIX_HOST_UID"] = str(os.getuid())
            environment["STRIX_HOST_GID"] = str(os.getgid())

        session_id = uuid4().hex[:10]
        container = client.containers.run(
            image_name,
            command=["tail", "-f", "/dev/null"],
            detach=True,
            cap_add=["NET_ADMIN", "NET_RAW"],
            extra_hosts={"host.docker.internal": "host-gateway"},
            ports={f"{CAIDO_PORT}/tcp": ("127.0.0.1", None)},
            environment=environment,
            mounts=mounts,
            labels={"strix-toolbox": "1", "strix-toolbox-session": session_id},
            name=f"strix-toolbox-{session_id}",
        )
        caido_url = _mapped_caido_url(container)
        client.close()

        handle = SandboxHandle(
            session_id=session_id,
            container_id=container.id,
            image=image_name,
            workspace_host=workspace_host,
            project_host=project_host,
            caido_host_url=caido_url,
        )
        handle.caido_client = _bootstrap_caido(handle)
        _CURRENT = handle
        return handle


def _mapped_caido_url(container: Any) -> str:
    container.reload()
    ports = container.attrs.get("NetworkSettings", {}).get("Ports", {})
    binding = ports.get(f"{CAIDO_PORT}/tcp") or []
    if not binding:
        raise SandboxError("Caido port was not published on the host")
    host_ip = binding[0].get("HostIp") or "127.0.0.1"
    host_port = binding[0].get("HostPort")
    if not host_port:
        raise SandboxError("Caido host port missing")
    return f"http://{host_ip}:{host_port}"


def _bootstrap_caido(handle: SandboxHandle) -> Any | None:
    if not handle.caido_host_url:
        return None
    token = _login_as_guest(handle.caido_host_url)
    try:
        from caido_sdk_client import Client, TokenAuthOptions
        from caido_sdk_client.types import CreateProjectOptions
    except ImportError:
        logger.warning("caido-sdk-client is not installed; proxy tools unavailable")
        return None

    async def _connect() -> Any:
        client = Client(handle.caido_host_url, auth=TokenAuthOptions(token=token))
        await client.connect()
        try:
            project = await client.project.create(
                CreateProjectOptions(name="toolbox", temporary=True),
            )
            await client.project.select(project.id)
        except BaseException:
            await client.aclose()
            raise
        return client

    return run_async(_connect())


def _login_as_guest(host_url: str, attempts: int = 20) -> str:
    url = f"{host_url.rstrip('/')}/graphql"
    last_err = "unknown"
    for i in range(1, attempts + 1):
        try:
            req = urllib.request.Request(
                url,
                data=_LOGIN_BODY,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            token = (
                payload.get("data", {}).get("loginAsGuest", {}).get("token", {}).get("accessToken")
            )
            if token:
                return str(token)
            last_err = f"no token in {payload!r}"
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            last_err = str(exc)
        time.sleep(min(1.5 * i, 6.0))
    raise SandboxError(f"Caido guest login failed: {last_err}")


def stop_sandbox() -> dict[str, Any]:
    global _CURRENT  # noqa: PLW0603
    with _LOCK:
        handle = _CURRENT
        _CURRENT = None
    if handle is None:
        return {"stopped": False, "error": "no sandbox session"}
    if handle.caido_client is not None:
        with _ignore():
            run_async(handle.caido_client.aclose())
    import docker
    from docker.errors import NotFound

    client = docker.from_env()
    try:
        container = client.containers.get(handle.container_id)
        container.kill()
        container.remove(force=True)
    except NotFound:
        pass
    finally:
        client.close()
    return {"stopped": True, "session_id": handle.session_id}


class _ignore:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *args: object) -> bool:
        return True


def sandbox_command_result(
    outcome: ExecOutcome, argv: list[str], duration_ms: int
) -> CommandResult:
    return CommandResult(
        success=outcome.exit_code == 0,
        exit_code=outcome.exit_code,
        stdout=outcome.stdout,
        stderr=outcome.stderr,
        argv=argv,
        duration_ms=duration_ms,
        error=outcome.error,
    )
