"""Caido proxy helpers using strix.tools.proxy.caido_api (no function_tool wrappers)."""

from __future__ import annotations

from typing import Any

from strix.toolbox.models import Classification, ToolResult
from strix.toolbox.safety import TargetAllowlist, UnauthorizedTargetError, active_testing_warning
from strix.toolbox.session import SandboxError, require_sandbox, run_async


def _client() -> Any:
    handle = require_sandbox()
    if handle.caido_client is None:
        raise SandboxError("Caido client is not available on this sandbox session")
    return handle.caido_client


def _fail(error: str, *, unavailable: bool = False) -> ToolResult:
    return ToolResult(
        success=False,
        classification=Classification.ACTIVE,
        unavailable=unavailable,
        error=error,
    )


def _ok(data: dict[str, Any], *, warning: str | None = None) -> ToolResult:
    return ToolResult(
        success=True,
        classification=Classification.ACTIVE,
        warning=warning,
        data=data,
    )


def proxy_list_requests(
    *,
    httpql_filter: str | None = None,
    first: int = 50,
) -> ToolResult:
    try:
        client = _client()
    except SandboxError as exc:
        return _fail(str(exc), unavailable=True)
    from strix.tools.proxy import caido_api

    try:
        connection = run_async(
            caido_api.list_requests_with_client(
                client,
                httpql_filter=httpql_filter,
                first=first,
            )
        )
    except Exception as exc:  # noqa: BLE001
        return _fail(str(exc))
    entries = []
    for edge in connection.edges:
        req = edge.node.request
        resp = edge.node.response
        entries.append(
            {
                "request_id": req.id,
                "host": req.host,
                "method": req.method,
                "path": req.path,
                "query": req.query,
                "status": None if resp is None else resp.status_code,
            }
        )
    return _ok({"entries": entries})


def proxy_view_request(*, request_id: str, part: str = "request") -> ToolResult:
    try:
        client = _client()
    except SandboxError as exc:
        return _fail(str(exc), unavailable=True)
    from strix.tools.proxy import caido_api

    try:
        result = run_async(caido_api.get_request_with_client(client, request_id, part=part))
    except Exception as exc:  # noqa: BLE001
        return _fail(str(exc))
    if result is None:
        return _fail(f"request not found: {request_id}")
    raw_bytes = (
        result.request.raw
        if part == "request"
        else (result.response.raw if result.response is not None else None)
    )
    content = (raw_bytes or b"").decode("utf-8", errors="replace")
    return _ok(
        {
            "request_id": request_id,
            "part": part,
            "content": content[:20_000],
            "truncated": len(content) > 20_000,
        }
    )


def proxy_repeat_request(
    allowlist: TargetAllowlist,
    *,
    request_id: str,
    modifications: dict[str, Any] | None = None,
) -> ToolResult:
    try:
        client = _client()
    except SandboxError as exc:
        return _fail(str(exc), unavailable=True)
    from strix.tools.proxy import caido_api

    mods = modifications or {}
    if "url" in mods:
        try:
            allowlist.require_network(str(mods["url"]))
        except UnauthorizedTargetError as exc:
            return _fail(str(exc))

    async def _do() -> dict[str, Any] | None:
        result = await caido_api.get_request_with_client(client, request_id, part="request")
        if result is None or result.request.raw is None:
            return None
        original = result.request
        try:
            allowlist.require_network(original.host)
        except UnauthorizedTargetError as exc:
            return {"unauthorized": str(exc)}
        raw_str = result.request.raw.decode("utf-8", errors="replace")
        components = caido_api.parse_raw_request(raw_str)
        full_url = caido_api.full_url_from_components(original, components, mods)
        try:
            allowlist.require_network(full_url)
        except UnauthorizedTargetError as exc:
            return {"unauthorized": str(exc)}
        modified = caido_api.apply_modifications(components, mods, full_url)
        connection, raw = caido_api.build_raw_request(
            method=modified["method"],
            url=modified["url"],
            headers=modified["headers"],
            body=modified["body"],
        )
        return await caido_api.replay_send_raw(client, raw=raw, connection=connection)

    try:
        replay = run_async(_do())
    except Exception as exc:  # noqa: BLE001
        return _fail(str(exc))
    if replay is None:
        return _fail(f"request not found: {request_id}")
    if isinstance(replay, dict) and replay.get("unauthorized"):
        return _fail(str(replay["unauthorized"]))
    return _ok(
        {
            "status": replay.get("status"),
            "elapsed_ms": replay.get("elapsed_ms"),
            "error": replay.get("error"),
        },
        warning=active_testing_warning(tool="strix_proxy_repeat_request", classification="ACTIVE"),
    )


def proxy_list_sitemap(*, page: int = 1) -> ToolResult:
    try:
        client = _client()
    except SandboxError as exc:
        return _fail(str(exc), unavailable=True)
    from strix.tools.proxy import caido_api

    try:
        payload = run_async(caido_api.list_sitemap_with_client(client, page=page))
    except Exception as exc:  # noqa: BLE001
        return _fail(str(exc))
    return _ok(payload if isinstance(payload, dict) else {"payload": payload})


def proxy_scope_rules(
    *,
    action: str,
    allowlist_patterns: list[str] | None = None,
    denylist: list[str] | None = None,
    scope_id: str | None = None,
    scope_name: str | None = None,
) -> ToolResult:
    try:
        client = _client()
    except SandboxError as exc:
        return _fail(str(exc), unavailable=True)
    from strix.tools.proxy import caido_api

    try:
        if action == "list":
            scopes = run_async(caido_api.scope_list(client))
            return _ok({"scopes": [str(s) for s in scopes]})
        if action == "get":
            if not scope_id:
                return _fail("scope_id is required")
            scope = run_async(caido_api.scope_get(client, scope_id))
            return _ok({"scope": str(scope)})
        if action == "create":
            if not scope_name:
                return _fail("scope_name is required")
            scope = run_async(
                caido_api.scope_create(
                    client,
                    name=scope_name,
                    allowlist=allowlist_patterns,
                    denylist=denylist,
                )
            )
            return _ok({"scope": str(scope)})
        if action == "update":
            if not scope_id or not scope_name:
                return _fail("scope_id and scope_name are required")
            scope = run_async(
                caido_api.scope_update(
                    client,
                    scope_id,
                    name=scope_name,
                    allowlist=allowlist_patterns,
                    denylist=denylist,
                )
            )
            return _ok({"scope": str(scope)})
        if action == "delete":
            if not scope_id:
                return _fail("scope_id is required")
            run_async(caido_api.scope_delete(client, scope_id))
            return _ok({"deleted": scope_id})
    except Exception as exc:  # noqa: BLE001
        return _fail(str(exc))
    return _fail("action must be get, list, create, update, or delete")
