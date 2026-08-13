# Architecture

This document describes the **upstream Strix architecture** as it exists in
this repository, and the **Strix Toolbox** architecture added by this
independent fork.

This is **not** the official Strix project. It is a fork of
[usestrix/strix](https://github.com/usestrix/strix) that exposes Strix security
capabilities to Cursor (and other MCP clients) without requiring an LLM inside
Strix.

## Current upstream architecture

Strix is an autonomous LLM-driven penetration testing agent. The CLI
(`strix`) validates LLM configuration, starts a Docker sandbox, and runs a
multi-agent loop that *decides* which tools to call.

```text
strix CLI
  -> validate_environment()   # requires STRIX_LLM (and usually an API key)
  -> strix.core.runner
  -> SandboxAgent (openai-agents + LiteLLM)
       |-- host function tools (proxy, reporting, notes, todo, web_search, agents_graph)
       |-- SDK Shell  -> exec_command inside Docker (nuclei, nmap, semgrep, agent-browser, ...)
       |-- SDK Filesystem
       `-- Caido sidecar in the sandbox (HTTP intercept / replay)
```

### Layout (source of truth)

| Area | Path | Role |
| --- | --- | --- |
| CLI | `strix/interface/main.py`, `cli.py`, `cli_args.py` | Entry point `strix = strix.interface.main:main` |
| LLM gate | `strix/interface/environment.py` | Refuses to start without `STRIX_LLM` |
| Agent loop | `strix/agents/factory.py`, `strix/core/execution.py`, `strix/core/runner.py` | LLM tool-calling loop |
| LLM config | `strix/config/settings.py`, `strix/config/codex.py`, `strix/llm/` | LiteLLM / OpenAI / ChatGPT subscription |
| Sandbox | `strix/runtime/session_manager.py`, `docker_client.py`, `containers/Dockerfile` | Kali image + Caido + security binaries |
| Host tools | `strix/tools/` | Proxy, reporting, notes, todo, thinking, agents_graph |
| Shell / browser / FS | openai-agents SDK capabilities + sandbox `agent-browser` CLI | Not first-class Python APIs |
| Reports | `strix/tools/reporting/tool.py`, `strix/report/` | Findings; dedupe can call an LLM |
| Tests | `tests/` | Mostly agent, LLM, TUI, proxy, and report tests |

### LLM-coupled vs LLM-independent

**LLM-only (not required by the toolbox):**

- `openai-agents[litellm]`, `openai`, `litellm`
- `STRIX_LLM`, `LLM_API_KEY`, provider keys, Ollama / LM Studio, ChatGPT login
- `strix/agents/*`, `strix/llm/*`, `strix/core/execution.py`
- `strix/tools/agents_graph`, `thinking`, `respond`, `load_skill`, `web_search`
- LLM finding dedupe in `strix/report/dedupe.py`
- `validate_environment()` in the original CLI

**Reusable without an LLM:**

- Docker sandbox image and Caido sidecar
- Host Caido helpers in `strix/tools/proxy/caido_api.py` (does not import `agents` at module level)
- Sandbox binaries: nuclei, nmap, subfinder, httpx, naabu, katana, ffuf, wafw00f, semgrep, bandit, gitleaks, trufflehog, trivy, agent-browser
- Host filesystem inspection and HTTP via `requests`
- Deterministic finding records (without LLM dedupe)

**Important:** scanners are **not** Python libraries. Upstream agents invoke them
through `exec_command` inside Docker. The toolbox adds typed wrappers around
those binaries.

The original `strix` CLI **still requires an LLM**. That is intentional.
`strix-toolbox` does not.

## Proposed toolbox architecture

Cursor Agent is the only reasoning layer. Strix Toolbox is an execution layer
exposed over MCP stdio.

```text
Cursor Agent (reasoning)
  |  MCP / stdio
  v
strix-toolbox mcp
  |-- safety / explicit target allowlist
  |-- host filesystem + HTTP
  |-- allowlisted sandbox CLIs (recon, SAST, nuclei, ffuf, browser verbs)
  |-- Caido proxy helpers
  `-- deterministic findings store
        |
        v
Local machine / Docker sandbox / authorized target
```

### Import isolation

`strix-toolbox --help`, `--self-test`, and `mcp` must:

- not call `validate_environment()`
- not import `strix.agents.factory` or `strix.interface.main`
- start with LLM environment variables unset
- not require any API key

Sandbox lifecycle in the toolbox uses the **Docker SDK directly** (`docker`
package) against the same Strix sandbox image. It does **not** import
`strix.runtime.session_manager`, because that module depends on
`agents.sandbox` from openai-agents.

Proxy helpers call `strix.tools.proxy.caido_api` with an explicit client.
They do not use the `@function_tool` wrappers in `strix/tools/proxy/tools.py`.

### MCP tools

Tools are small and composable. There is no `run_strix()` mega-tool.
Each tool has typed input/output, timeouts, structured errors, and a
classification:

- **PASSIVE** — local inspection, no network side effects
- **ACTIVE** — network or sandbox execution; may change remote state
- **DESTRUCTIVE** — not exposed (no generic shell, sqlmap, apply_patch, file writes)

Network tools require an **explicit** authorized target. Localhost, `127.0.0.1`,
and `::1` are allowed by default. Hosts discovered during reconnaissance are
**never** auto-authorized.

### Package layout added by this fork

```text
strix/toolbox/
  cli.py            # strix-toolbox entry
  mcp_server.py     # MCP stdio server
  selftest.py
  safety.py         # allowlist + classification
  models.py         # pydantic I/O
  session.py        # Docker sandbox (no agents SDK)
  exec.py           # timeouts + structured command results
  filesystem.py
  http.py
  proxy.py
  scanning.py       # recon + nuclei + ffuf
  code_analysis.py
  browser.py
  reporting.py
  parsers.py
```

See [MCP.md](MCP.md), [TOOLS.md](TOOLS.md), [SECURITY.md](SECURITY.md), and
[DEVELOPMENT.md](DEVELOPMENT.md) for usage details.
