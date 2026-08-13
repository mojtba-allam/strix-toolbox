"""Host HTTP client with authorized-target and redirect checks (ACTIVE)."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from strix.toolbox.models import Classification, ToolResult
from strix.toolbox.safety import TargetAllowlist, UnauthorizedTargetError, active_testing_warning


_MAX_BODY = 100_000
_DEFAULT_TIMEOUT = 30


def http_request(
    *,
    allowlist: TargetAllowlist,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: int = _DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    max_redirects: int = 5,
) -> ToolResult:
    method_u = method.upper().strip()
    if method_u not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        return ToolResult(
            success=False,
            classification=Classification.ACTIVE,
            error=f"unsupported HTTP method: {method}",
        )
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return ToolResult(
            success=False,
            classification=Classification.ACTIVE,
            error="only http/https URLs are allowed",
        )
    try:
        allowlist.require_network(url)
    except UnauthorizedTargetError as exc:
        return ToolResult(success=False, classification=Classification.ACTIVE, error=str(exc))

    hops: list[dict[str, Any]] = []
    current = url
    session = requests.Session()
    started = time.monotonic()
    try:
        for _ in range(max_redirects + 1):
            allowlist.require_network(current)
            hop_start = time.monotonic()
            response = session.request(
                method_u,
                current,
                headers=headers,
                data=body,
                timeout=timeout,
                allow_redirects=False,
            )
            elapsed_ms = int((time.monotonic() - hop_start) * 1000)
            location = response.headers.get("Location")
            hops.append(
                {
                    "url": current,
                    "status": response.status_code,
                    "elapsed_ms": elapsed_ms,
                    "location": location,
                }
            )
            if follow_redirects and response.is_redirect and location:
                current = urljoin(current, location)
                body = None
                if method_u not in {"GET", "HEAD"}:
                    method_u = "GET"
                continue
            raw = response.content or b""
            truncated = len(raw) > _MAX_BODY
            snippet = raw[:_MAX_BODY]
            try:
                text = snippet.decode(response.encoding or "utf-8")
            except (LookupError, UnicodeDecodeError):
                text = snippet.decode("utf-8", errors="replace")
            headers_out = {k: v for k, v in response.headers.items()}
            return ToolResult(
                success=True,
                classification=Classification.ACTIVE,
                warning=active_testing_warning(tool="strix_http_request", classification="ACTIVE"),
                data={
                    "status": response.status_code,
                    "reason": response.reason,
                    "url": response.url,
                    "headers": headers_out,
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "body": text,
                    "body_bytes": len(raw),
                    "truncated": truncated,
                    "hops": hops,
                },
            )
    except UnauthorizedTargetError as exc:
        return ToolResult(
            success=False,
            classification=Classification.ACTIVE,
            error=f"redirect target is not authorized: {exc}",
            data={"hops": hops},
        )
    except requests.RequestException as exc:
        return ToolResult(
            success=False,
            classification=Classification.ACTIVE,
            error=str(exc),
            data={"hops": hops},
        )
    finally:
        session.close()
    return ToolResult(
        success=False,
        classification=Classification.ACTIVE,
        error="too many redirects",
        data={"hops": hops},
    )
