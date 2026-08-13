# Tools

Every MCP tool returns a structured object:

```json
{
  "success": true,
  "classification": "PASSIVE",
  "error": null,
  "unavailable": false,
  "warning": null,
  "data": {}
}
```

Findings recorded via `strix_report_create_finding` look like:

```json
{
  "severity": "high",
  "title": "Potential SQL Injection",
  "location": {
    "file": "app/Http/Controllers/UserController.php",
    "line": 42
  },
  "evidence": "...",
  "confidence": "high",
  "recommendation": "...",
  "raw_output": "..."
}
```

The toolbox does **not** decide whether something is exploitable. Cursor does.

## Classification

| Class | Meaning |
| --- | --- |
| PASSIVE | Local inspection or config; no attack traffic |
| ACTIVE | Network or sandbox execution; may change remote state |
| DESTRUCTIVE | Not exposed (no generic shell, sqlmap, apply_patch, file writes) |

## Catalog

### Meta / safety — PASSIVE

| Tool | When to use |
| --- | --- |
| `strix_self_test` | Check runtime, MCP, Docker/browser availability |
| `strix_authorize_target` | User-explicit host/URL/CIDR/path before active tests |
| `strix_list_authorized_targets` | Show the allowlist |
| `strix_revoke_target` | Remove a non-implicit authorization |

### Project inspection — PASSIVE

| Tool | When to use |
| --- | --- |
| `strix_project_info` | See the local project root |
| `strix_list_files` | Enumerate source files |
| `strix_read_file` | Read a file (truncated) |
| `strix_search_code` | Regex search |

### Sandbox — ACTIVE (container lifecycle)

| Tool | When to use |
| --- | --- |
| `strix_sandbox_start` | Start Kali sandbox + Caido; optional project bind-mount |
| `strix_sandbox_status` | Is it running? |
| `strix_sandbox_logs` | Container logs |
| `strix_sandbox_stop` | Tear down |

### HTTP / proxy — ACTIVE (localhost allowed by default)

| Tool | When to use |
| --- | --- |
| `strix_http_request` | One authorized HTTP request |
| `strix_proxy_list_requests` | Caido history |
| `strix_proxy_view_request` | Full captured request/response |
| `strix_proxy_repeat_request` | Replay with patches (may change app state) |
| `strix_proxy_list_sitemap` | Discovered sitemap (hosts not auto-authorized) |
| `strix_proxy_scope_rules` | Caido allow/deny lists |

### Recon — ACTIVE

| Tool | Binary |
| --- | --- |
| `strix_recon_subfinder` | subfinder |
| `strix_recon_httpx` | httpx |
| `strix_recon_naabu` | naabu |
| `strix_recon_nmap` | nmap (`connect` or `syn`; no NSE exploits) |
| `strix_recon_katana` | katana |
| `strix_detect_waf` | wafw00f |

### Source analysis — PASSIVE

| Tool | Binary |
| --- | --- |
| `strix_sast_semgrep` | semgrep |
| `strix_sast_bandit` | bandit |
| `strix_find_secrets_gitleaks` | gitleaks |
| `strix_find_secrets_trufflehog` | trufflehog |
| `strix_dependency_trivy` | trivy |

Host binaries are used if present; otherwise the sandbox is required.

### Scanning — ACTIVE

| Tool | Binary |
| --- | --- |
| `strix_scan_nuclei` | nuclei |
| `strix_fuzz_ffuf` | ffuf (URL must contain `FUZZ`) |

### Browser — ACTIVE

| Tool | Notes |
| --- | --- |
| `strix_browser_open` | `agent-browser open` |
| `strix_browser_screenshot` | screenshot |
| `strix_browser_interact` | `snapshot` / `click` / `type` / `js` only |

### Reporting — PASSIVE

| Tool | When to use |
| --- | --- |
| `strix_report_create_finding` | Store a structured finding you inferred |
| `strix_report_list_findings` | List session findings |
| `strix_report_get_finding` | Fetch one finding |

## Not exposed

- `run_strix()` / autonomous agent loop
- generic `exec_command` / shell
- sqlmap, apply_patch, file write/delete
- web_search (Perplexity)
- multi-agent spawn / think / finish
