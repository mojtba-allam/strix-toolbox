"""MCP server discovery and schema tests."""

from __future__ import annotations

from strix.toolbox.context import reset_state
from strix.toolbox.mcp_server import create_server, list_registered_tool_names
from strix.toolbox.safety import TargetAllowlist


EXPECTED_TOOLS = {
    "strix_self_test",
    "strix_authorize_target",
    "strix_list_authorized_targets",
    "strix_revoke_target",
    "strix_project_info",
    "strix_list_files",
    "strix_read_file",
    "strix_search_code",
    "strix_sandbox_start",
    "strix_sandbox_status",
    "strix_sandbox_logs",
    "strix_sandbox_stop",
    "strix_http_request",
    "strix_proxy_list_requests",
    "strix_proxy_view_request",
    "strix_proxy_repeat_request",
    "strix_proxy_list_sitemap",
    "strix_proxy_scope_rules",
    "strix_recon_subfinder",
    "strix_recon_httpx",
    "strix_recon_naabu",
    "strix_recon_nmap",
    "strix_recon_katana",
    "strix_detect_waf",
    "strix_sast_semgrep",
    "strix_sast_bandit",
    "strix_find_secrets_gitleaks",
    "strix_find_secrets_trufflehog",
    "strix_dependency_trivy",
    "strix_scan_nuclei",
    "strix_fuzz_ffuf",
    "strix_browser_open",
    "strix_browser_screenshot",
    "strix_browser_interact",
    "strix_report_create_finding",
    "strix_report_list_findings",
    "strix_report_get_finding",
}


def test_create_server() -> None:
    server = create_server()
    assert server is not None
    names = set(list_registered_tool_names(server))
    missing = EXPECTED_TOOLS - names
    assert not missing, f"missing tools: {sorted(missing)}"


def test_tool_schemas_have_descriptions() -> None:
    server = create_server()
    manager = server._tool_manager
    for tool in manager.list_tools():
        assert tool.name.startswith("strix_")
        description = getattr(tool, "description", "") or ""
        assert len(description) > 40, tool.name
        schema = getattr(tool, "parameters", None) or getattr(tool, "inputSchema", None) or {}
        assert isinstance(schema, dict)


def test_http_invalid_and_unauthorized_via_tools() -> None:
    reset_state()
    from strix.toolbox.http import http_request

    allowlist = TargetAllowlist()
    missing = http_request(allowlist=allowlist, url="")
    assert missing.success is False
    unauthorized = http_request(allowlist=allowlist, url="https://example.com/login")
    assert unauthorized.success is False
    assert "not authorized" in (unauthorized.error or "")


def test_report_roundtrip() -> None:
    state = reset_state()
    from strix.toolbox.reporting import (
        create_finding_result,
        get_finding_result,
        list_findings_result,
    )

    created = create_finding_result(
        state.findings,
        title="Potential SQL Injection",
        severity="high",
        evidence="unsanitized query",
        recommendation="use parameterized queries",
        confidence="high",
        file="app/Http/Controllers/UserController.php",
        line=42,
        tool="manual",
    )
    assert created.success
    finding_id = created.data["finding"]["id"]
    listed = list_findings_result(state.findings)
    assert listed.data["findings"]
    fetched = get_finding_result(state.findings, finding_id)
    assert fetched.data["finding"]["title"] == "Potential SQL Injection"


async def test_mcp_stdio_lists_tools() -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command="uv",
        args=["run", "strix-toolbox", "mcp"],
        cwd=str(__import__("pathlib").Path(__file__).resolve().parents[2]),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
    names = {tool.name for tool in tools.tools}
    assert "strix_self_test" in names
    assert "strix_http_request" in names
    assert len(names) >= 30
