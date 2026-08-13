"""MCP stdio server. Cursor is the reasoning layer; this process only executes tools."""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from strix.toolbox.browser import browser_interact, browser_open, browser_screenshot
from strix.toolbox.code_analysis import (
    dependency_trivy,
    find_secrets_gitleaks,
    find_secrets_trufflehog,
    sast_bandit,
    sast_semgrep,
)
from strix.toolbox.context import get_state
from strix.toolbox.filesystem import list_files, project_info, read_file, search_code
from strix.toolbox.http import http_request
from strix.toolbox.models import Classification, ToolResult
from strix.toolbox.proxy import (
    proxy_list_requests,
    proxy_list_sitemap,
    proxy_repeat_request,
    proxy_scope_rules,
    proxy_view_request,
)
from strix.toolbox.reporting import create_finding_result, get_finding_result, list_findings_result
from strix.toolbox.safety import SafetyError, dump_allowlist
from strix.toolbox.scanning import (
    detect_waf,
    fuzz_ffuf,
    recon_httpx,
    recon_katana,
    recon_naabu,
    recon_nmap,
    recon_subfinder,
    scan_nuclei,
)
from strix.toolbox.selftest import format_self_test, run_self_test
from strix.toolbox.session import SandboxError, current_sandbox, start_sandbox, stop_sandbox


logger = logging.getLogger(__name__)

INSTRUCTIONS = (
    "Strix Toolbox executes security tests and returns structured evidence. "
    "It does not reason about vulnerabilities and does not call an LLM. "
    "You (the host agent) must choose tools, interpret results, and decide next steps. "
    "Network tools require an explicit authorized target. Localhost is allowed by default. "
    "Never scan a host merely because it appeared in reconnaissance output."
)


def _dump(result: ToolResult) -> dict[str, Any]:
    return result.to_json_dict()


def create_server() -> FastMCP:
    mcp = FastMCP(
        "strix-toolbox",
        instructions=INSTRUCTIONS,
    )

    @mcp.tool(
        name="strix_self_test",
        description=(
            "Run a local self-test of the Strix Toolbox runtime, MCP package, "
            "filesystem, HTTP client, and optional Docker/browser. Classification: PASSIVE. "
            "Network: no. Authorization: not required. Does not use or require any LLM API key."
        ),
    )
    def strix_self_test() -> dict[str, Any]:
        report = run_self_test()
        return {
            "success": True,
            "classification": "PASSIVE",
            "report": format_self_test(report),
            "data": report,
        }

    @mcp.tool(
        name="strix_authorize_target",
        description=(
            "Explicitly authorize a host, URL, CIDR, or local path for later active tests. "
            "Call this before scanning any non-loopback network target. Classification: PASSIVE. "
            "Network: no. This does not scan the target; it only records user authorization. "
            "Discovered recon hosts are never authorized automatically."
        ),
    )
    def strix_authorize_target(target: str, note: str = "") -> dict[str, Any]:
        state = get_state()
        try:
            entry = state.allowlist.authorize(target, note=note)
        except SafetyError as exc:
            return _dump(
                ToolResult(success=False, classification=Classification.PASSIVE, error=str(exc))
            )
        return _dump(
            ToolResult(
                success=True,
                classification=Classification.PASSIVE,
                data={"target": entry.model_dump(mode="json")},
            )
        )

    @mcp.tool(
        name="strix_list_authorized_targets",
        description=(
            "List currently authorized targets including implicit loopback defaults. "
            "Classification: PASSIVE. Network: no."
        ),
    )
    def strix_list_authorized_targets() -> dict[str, Any]:
        return _dump(
            ToolResult(
                success=True,
                classification=Classification.PASSIVE,
                data={"targets": dump_allowlist(get_state().allowlist)},
            )
        )

    @mcp.tool(
        name="strix_revoke_target",
        description=(
            "Remove a previously authorized non-implicit target by id. Classification: PASSIVE. "
            "Network: no. Implicit localhost entries cannot be revoked."
        ),
    )
    def strix_revoke_target(target_id: str) -> dict[str, Any]:
        try:
            removed = get_state().allowlist.revoke(target_id)
        except SafetyError as exc:
            return _dump(
                ToolResult(success=False, classification=Classification.PASSIVE, error=str(exc))
            )
        return _dump(
            ToolResult(
                success=removed,
                classification=Classification.PASSIVE,
                error=None if removed else "target id not found",
                data={"revoked": target_id} if removed else {},
            )
        )

    @mcp.tool(
        name="strix_project_info",
        description=(
            "Return the local project root used for filesystem tools "
            "(cwd or STRIX_TOOLBOX_PROJECT_ROOT). Classification: PASSIVE. "
            "Network: no. Does not modify files."
        ),
    )
    def strix_project_info() -> dict[str, Any]:
        return _dump(project_info(get_state().project_root))

    @mcp.tool(
        name="strix_list_files",
        description=(
            "List files under the local project root. Use for source-aware inspection. "
            "Classification: PASSIVE. Network: no. Does not modify files. "
            "path is relative to the project root."
        ),
    )
    def strix_list_files(path: str = ".", max_entries: int = 500) -> dict[str, Any]:
        return _dump(list_files(root=get_state().project_root, path=path, max_entries=max_entries))

    @mcp.tool(
        name="strix_read_file",
        description=(
            "Read a text file under the local project root and return content (truncated). "
            "Classification: PASSIVE. Network: no. Does not modify files."
        ),
    )
    def strix_read_file(path: str) -> dict[str, Any]:
        return _dump(read_file(root=get_state().project_root, path=path))

    @mcp.tool(
        name="strix_search_code",
        description=(
            "Regex-search local project files. Use to find security-relevant patterns. "
            "Classification: PASSIVE. Network: no. Does not modify files. "
            "pattern is a Python regular expression."
        ),
    )
    def strix_search_code(
        pattern: str,
        path: str = ".",
        glob: str | None = None,
    ) -> dict[str, Any]:
        return _dump(
            search_code(root=get_state().project_root, pattern=pattern, path=path, glob=glob)
        )

    @mcp.tool(
        name="strix_sandbox_start",
        description=(
            "Start the Strix Docker sandbox (Kali image with Caido, scanners, and agent-browser). "
            "Classification: ACTIVE (starts a container). Network: may pull an image on first use. "
            "Optional project_path bind-mounts a local directory at /workspace/project. "
            "No LLM API key is required. Reuses an already-running toolbox sandbox."
        ),
    )
    def strix_sandbox_start(project_path: str | None = None, pull: bool = False) -> dict[str, Any]:
        try:
            handle = start_sandbox(
                project_path=project_path or str(get_state().project_root),
                pull=pull,
            )
        except SandboxError as exc:
            return _dump(
                ToolResult(
                    success=False,
                    classification=Classification.ACTIVE,
                    unavailable=True,
                    error=str(exc),
                )
            )
        return _dump(
            ToolResult(
                success=True,
                classification=Classification.ACTIVE,
                data=handle.status(),
                warning="Sandbox can reach authorized targets and localhost via host.docker.internal.",
            )
        )

    @mcp.tool(
        name="strix_sandbox_status",
        description=(
            "Return whether the toolbox Docker sandbox is running. Classification: PASSIVE. "
            "Network: no."
        ),
    )
    def strix_sandbox_status() -> dict[str, Any]:
        handle = current_sandbox()
        if handle is None:
            return _dump(
                ToolResult(
                    success=True, classification=Classification.PASSIVE, data={"running": False}
                )
            )
        return _dump(
            ToolResult(success=True, classification=Classification.PASSIVE, data=handle.status())
        )

    @mcp.tool(
        name="strix_sandbox_logs",
        description=(
            "Return recent Docker logs from the toolbox sandbox. Classification: PASSIVE. "
            "Network: no."
        ),
    )
    def strix_sandbox_logs(tail: int = 200) -> dict[str, Any]:
        handle = current_sandbox()
        if handle is None:
            return _dump(
                ToolResult(
                    success=False,
                    classification=Classification.PASSIVE,
                    error="sandbox is not running",
                )
            )
        return _dump(
            ToolResult(
                success=True,
                classification=Classification.PASSIVE,
                data={"logs": handle.logs(tail=tail)},
            )
        )

    @mcp.tool(
        name="strix_sandbox_stop",
        description=(
            "Stop and remove the toolbox Docker sandbox container. Classification: ACTIVE. "
            "Does not modify the target application; only the local sandbox."
        ),
    )
    def strix_sandbox_stop() -> dict[str, Any]:
        return _dump(
            ToolResult(success=True, classification=Classification.ACTIVE, data=stop_sandbox())
        )

    @mcp.tool(
        name="strix_http_request",
        description=(
            "Send an HTTP request to an explicitly authorized target and return status, headers, "
            "timing, redirect hops, and a truncated body. Use this when validating API behavior "
            "or security findings. Classification: ACTIVE. Network: yes. "
            "Requires authorization except for localhost/127.0.0.1/::1. "
            "Redirects to unauthorized hosts are rejected. Does not follow recon-discovered hosts."
        ),
    )
    def strix_http_request(
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | None = None,
        timeout: int = 30,
        follow_redirects: bool = True,
    ) -> dict[str, Any]:
        return _dump(
            http_request(
                allowlist=get_state().allowlist,
                url=url,
                method=method,
                headers=headers,
                body=body,
                timeout=timeout,
                follow_redirects=follow_redirects,
            )
        )

    @mcp.tool(
        name="strix_proxy_list_requests",
        description=(
            "List HTTP requests captured by the sandbox Caido proxy. Requires strix_sandbox_start. "
            "Classification: PASSIVE relative to the target (reads proxy history). Network: local Caido only. "
            "Optional httpql_filter uses Caido HTTPQL."
        ),
    )
    def strix_proxy_list_requests(
        httpql_filter: str | None = None, first: int = 50
    ) -> dict[str, Any]:
        return _dump(proxy_list_requests(httpql_filter=httpql_filter, first=first))

    @mcp.tool(
        name="strix_proxy_view_request",
        description=(
            "View a captured Caido request or response body by request_id. Classification: PASSIVE "
            "relative to the target. Requires sandbox. part is 'request' or 'response'."
        ),
    )
    def strix_proxy_view_request(request_id: str, part: str = "request") -> dict[str, Any]:
        return _dump(proxy_view_request(request_id=request_id, part=part))

    @mcp.tool(
        name="strix_proxy_repeat_request",
        description=(
            "Replay a captured Caido request, optionally patching url/headers/body/params/cookies. "
            "Classification: ACTIVE. May change application state. The replay URL host must already "
            "be authorized. Never use this to attack a newly discovered host."
        ),
    )
    def strix_proxy_repeat_request(
        request_id: str,
        modifications: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return _dump(
            proxy_repeat_request(
                get_state().allowlist,
                request_id=request_id,
                modifications=modifications,
            )
        )

    @mcp.tool(
        name="strix_proxy_list_sitemap",
        description=(
            "Browse the Caido sitemap of proxied traffic. Classification: PASSIVE relative to the "
            "target. Requires sandbox. Discovered hosts are not auto-authorized."
        ),
    )
    def strix_proxy_list_sitemap(page: int = 1) -> dict[str, Any]:
        return _dump(proxy_list_sitemap(page=page))

    @mcp.tool(
        name="strix_proxy_scope_rules",
        description=(
            "Create/list/update/delete Caido scope allow/deny patterns. Classification: PASSIVE "
            "relative to the target (proxy config only). action: get, list, create, update, delete."
        ),
    )
    def strix_proxy_scope_rules(
        action: str,
        allowlist_patterns: list[str] | None = None,
        denylist: list[str] | None = None,
        scope_id: str | None = None,
        scope_name: str | None = None,
    ) -> dict[str, Any]:
        return _dump(
            proxy_scope_rules(
                action=action,
                allowlist_patterns=allowlist_patterns,
                denylist=denylist,
                scope_id=scope_id,
                scope_name=scope_name,
            )
        )

    @mcp.tool(
        name="strix_recon_subfinder",
        description=(
            "Enumerate subdomains of an authorized domain via subfinder in the sandbox. "
            "Classification: ACTIVE. Network: yes. Results are evidence only — do not scan "
            "discovered names until the user authorizes them."
        ),
    )
    def strix_recon_subfinder(domain: str, timeout: int = 90) -> dict[str, Any]:
        return _dump(recon_subfinder(get_state().allowlist, domain, timeout=timeout))

    @mcp.tool(
        name="strix_recon_httpx",
        description=(
            "Probe an authorized HTTP target with httpx (status, title, tech). Classification: ACTIVE. "
            "Network: yes. Requires sandbox."
        ),
    )
    def strix_recon_httpx(target: str, timeout: int = 90) -> dict[str, Any]:
        return _dump(recon_httpx(get_state().allowlist, target, timeout=timeout))

    @mcp.tool(
        name="strix_recon_naabu",
        description=(
            "Port-scan an authorized host with naabu. Classification: ACTIVE. Network: yes. "
            "ports: 'top-100' (default), 'top-1000', or an explicit port list like '80,443,8000'."
        ),
    )
    def strix_recon_naabu(
        target: str, ports: str = "top-100", timeout: int = 120
    ) -> dict[str, Any]:
        return _dump(recon_naabu(get_state().allowlist, target, ports=ports, timeout=timeout))

    @mcp.tool(
        name="strix_recon_nmap",
        description=(
            "Service-scan an authorized host with nmap. Classification: ACTIVE. Network: yes. "
            "scan_type is 'connect' (default, safer) or 'syn'. Does not run NSE exploit scripts."
        ),
    )
    def strix_recon_nmap(
        target: str,
        ports: str | None = None,
        scan_type: str = "connect",
        version_detect: bool = False,
        timeout: int = 180,
    ) -> dict[str, Any]:
        return _dump(
            recon_nmap(
                get_state().allowlist,
                target,
                ports=ports,
                scan_type=scan_type,
                version_detect=version_detect,
                timeout=timeout,
            )
        )

    @mcp.tool(
        name="strix_recon_katana",
        description=(
            "Crawl an authorized URL with katana (depth 2). Classification: ACTIVE. Network: yes. "
            "URLs on other hosts are not auto-authorized."
        ),
    )
    def strix_recon_katana(url: str, timeout: int = 120) -> dict[str, Any]:
        return _dump(recon_katana(get_state().allowlist, url, timeout=timeout))

    @mcp.tool(
        name="strix_detect_waf",
        description=(
            "Fingerprint a WAF in front of an authorized URL with wafw00f. Classification: ACTIVE. "
            "Network: yes. Requires sandbox."
        ),
    )
    def strix_detect_waf(url: str, timeout: int = 60) -> dict[str, Any]:
        return _dump(detect_waf(get_state().allowlist, url, timeout=timeout))

    @mcp.tool(
        name="strix_sast_semgrep",
        description=(
            "Run Semgrep SAST on the local project (host binary or sandbox). Classification: PASSIVE. "
            "Network: no (unless Semgrep would fetch rules; metrics are disabled). path is relative "
            "to the project root. Returns structured findings, not a verdict."
        ),
    )
    def strix_sast_semgrep(path: str | None = None, timeout: int = 180) -> dict[str, Any]:
        return _dump(sast_semgrep(path, timeout=timeout))

    @mcp.tool(
        name="strix_sast_bandit",
        description=(
            "Run Bandit on Python sources under the project root. Classification: PASSIVE. "
            "Network: no. Returns structured findings for you to interpret."
        ),
    )
    def strix_sast_bandit(path: str | None = None, timeout: int = 120) -> dict[str, Any]:
        return _dump(sast_bandit(path, timeout=timeout))

    @mcp.tool(
        name="strix_find_secrets_gitleaks",
        description=(
            "Detect hardcoded secrets with Gitleaks. Classification: PASSIVE. Network: no. "
            "Does not modify the repository."
        ),
    )
    def strix_find_secrets_gitleaks(path: str | None = None, timeout: int = 120) -> dict[str, Any]:
        return _dump(find_secrets_gitleaks(path, timeout=timeout))

    @mcp.tool(
        name="strix_find_secrets_trufflehog",
        description=(
            "Detect secrets with TruffleHog filesystem scan. Classification: PASSIVE. Network: no "
            "(--no-update). Does not modify files."
        ),
    )
    def strix_find_secrets_trufflehog(
        path: str | None = None, timeout: int = 180
    ) -> dict[str, Any]:
        return _dump(find_secrets_trufflehog(path, timeout=timeout))

    @mcp.tool(
        name="strix_dependency_trivy",
        description=(
            "Scan the project filesystem with Trivy for vulns/secrets/misconfig. Classification: PASSIVE. "
            "Network: Trivy may refresh DBs if installed on the host; sandbox image is preloaded. "
            "Does not modify the application."
        ),
    )
    def strix_dependency_trivy(path: str | None = None, timeout: int = 180) -> dict[str, Any]:
        return _dump(dependency_trivy(path, timeout=timeout))

    @mcp.tool(
        name="strix_scan_nuclei",
        description=(
            "Run Nuclei templates against an authorized URL/host. Classification: ACTIVE. Network: yes. "
            "Requires sandbox. Optional severity filter (e.g. 'critical,high'). "
            "This is an active scanner — only use on systems you are authorized to test."
        ),
    )
    def strix_scan_nuclei(
        target: str,
        severity: str | None = None,
        timeout: int = 180,
    ) -> dict[str, Any]:
        return _dump(scan_nuclei(get_state().allowlist, target, severity=severity, timeout=timeout))

    @mcp.tool(
        name="strix_fuzz_ffuf",
        description=(
            "Directory/parameter fuzz an authorized URL containing FUZZ using ffuf and a small "
            "built-in wordlist (or a provided list). Classification: ACTIVE. Network: yes. "
            "Requires sandbox. Can generate significant request volume. Not destructive by default "
            "but may trigger application errors."
        ),
    )
    def strix_fuzz_ffuf(
        url: str,
        wordlist: list[str] | None = None,
        timeout: int = 120,
    ) -> dict[str, Any]:
        return _dump(fuzz_ffuf(get_state().allowlist, url, wordlist=wordlist, timeout=timeout))

    @mcp.tool(
        name="strix_browser_open",
        description=(
            "Open a URL in the sandbox agent-browser (Chromium). Traffic goes through Caido. "
            "Classification: ACTIVE. Network: yes. Requires sandbox and an authorized target."
        ),
    )
    def strix_browser_open(url: str, timeout: int = 60) -> dict[str, Any]:
        return _dump(browser_open(get_state().allowlist, url, timeout=timeout))

    @mcp.tool(
        name="strix_browser_screenshot",
        description=(
            "Capture a screenshot of the current sandbox browser session. Classification: ACTIVE "
            "(uses the live browser). Network: only if the page itself loads resources. Requires sandbox."
        ),
    )
    def strix_browser_screenshot(timeout: int = 60) -> dict[str, Any]:
        return _dump(browser_screenshot(timeout=timeout))

    @mcp.tool(
        name="strix_browser_interact",
        description=(
            "Interact with the sandbox browser. action: snapshot (list interactive refs), click, type, js. "
            "click/type use agent-browser refs like @e3 from snapshot. Classification: ACTIVE. "
            "May submit forms or change application state. Requires sandbox. No free-form shell."
        ),
    )
    def strix_browser_interact(
        action: str,
        target: str | None = None,
        text: str | None = None,
        timeout: int = 60,
    ) -> dict[str, Any]:
        if action not in {"click", "type", "js", "snapshot"}:
            return _dump(
                ToolResult(
                    success=False,
                    classification=Classification.ACTIVE,
                    error="action must be snapshot, click, type, or js",
                )
            )
        return _dump(
            browser_interact(action=action, target=target, text=text, timeout=timeout)  # type: ignore[arg-type]
        )

    @mcp.tool(
        name="strix_report_create_finding",
        description=(
            "Record a structured security finding in the toolbox store. Classification: PASSIVE. "
            "Network: no. Does not exploit anything. You (the host agent) decide title/severity "
            "from evidence. severity: critical|high|medium|low|info."
        ),
    )
    def strix_report_create_finding(
        title: str,
        severity: str = "info",
        evidence: str = "",
        recommendation: str = "",
        confidence: str = "medium",
        file: str | None = None,
        line: int | None = None,
        url: str | None = None,
        raw_output: str = "",
        tool: str = "",
    ) -> dict[str, Any]:
        return _dump(
            create_finding_result(
                get_state().findings,
                title=title,
                severity=severity,
                evidence=evidence,
                recommendation=recommendation,
                confidence=confidence,
                file=file,
                line=line,
                url=url,
                raw_output=raw_output,
                tool=tool,
            )
        )

    @mcp.tool(
        name="strix_report_list_findings",
        description=(
            "List findings recorded in this MCP session. Classification: PASSIVE. Network: no."
        ),
    )
    def strix_report_list_findings() -> dict[str, Any]:
        return _dump(list_findings_result(get_state().findings))

    @mcp.tool(
        name="strix_report_get_finding",
        description=("Get one recorded finding by id. Classification: PASSIVE. Network: no."),
    )
    def strix_report_get_finding(finding_id: str) -> dict[str, Any]:
        return _dump(get_finding_result(get_state().findings, finding_id))

    return mcp


def list_registered_tool_names(server: FastMCP | None = None) -> list[str]:
    mcp = server or create_server()
    manager = getattr(mcp, "_tool_manager", None)
    if manager is not None and hasattr(manager, "list_tools"):
        tools = manager.list_tools()
        names = []
        for tool in tools:
            name = getattr(tool, "name", None)
            if name:
                names.append(name)
        return sorted(names)
    if hasattr(mcp, "list_tools"):
        listed = mcp.list_tools()
        if isinstance(listed, list):
            return sorted(str(getattr(item, "name", item)) for item in listed)
    return []


def run_stdio() -> None:
    logger.info("Starting Strix Toolbox MCP server on stdio (no LLM required)")
    create_server().run(transport="stdio")
