# Strix Toolbox

**Strix Toolbox is a fork of Strix designed to expose Strix security capabilities to AI agents such as Cursor through MCP. The toolbox does not require an LLM or LLM API key. Cursor provides the reasoning layer.**

This is an **independent fork/customization**. It is **not** the official [Strix](https://github.com/usestrix/strix) project.

## Based on Strix

Upstream: [https://github.com/usestrix/strix](https://github.com/usestrix/strix)

Licensed under the Apache License 2.0. Original copyright: Copyright 2025 OmniSecure Inc. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The original `strix` CLI is an autonomous LLM pentest agent and **still requires** `STRIX_LLM` / an API key. The new `strix-toolbox` CLI does **not**.

```text
Cursor Agent (reasoning)
        |
        | MCP stdio
        v
strix-toolbox mcp   (no API keys)
        |
        +-- filesystem, HTTP, recon, SAST, Nuclei, browser, Caido, Docker
        v
Local machine / Docker sandbox / authorized target
```

## Requirements

- Python 3.12+
- Ubuntu / Debian-like Linux (also works on other platforms with Docker)
- Optional: Docker (for sandbox scanners, Caido, and `agent-browser`)
- Optional: the Strix sandbox image `ghcr.io/usestrix/strix-sandbox:1.3.0`

No OpenAI, Anthropic, Google, OpenRouter, Ollama, or other LLM credentials.

## Installation (Ubuntu)

```bash
sudo apt update
sudo apt install -y python3.12 python3.12-venv git docker.io
sudo systemctl enable --now docker

# Install uv (https://docs.astral.sh/uv/)
curl -LsSf https://astral.sh/uv/install.sh | sh

git clone https://github.com/mojtba-allam/strix-toolbox.git
cd strix-toolbox
uv sync
```

Install the CLI onto your PATH from this checkout:

```bash
uv pip install -e .
# or:
uv run strix-toolbox --help
```

First sandbox use pulls the Docker image (needs network once):

```bash
docker pull ghcr.io/usestrix/strix-sandbox:1.3.0
```

Browser automation uses Chromium via `agent-browser` **inside that image**, not a host Playwright install.

## CLI

```bash
strix-toolbox --help
strix-toolbox --version
strix-toolbox --self-test
strix-toolbox mcp
```

`strix-toolbox mcp` starts the MCP stdio server. **No API key.**

Verify without LLM environment variables:

```bash
env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY -u GOOGLE_API_KEY \
    -u GEMINI_API_KEY -u LLM_API_KEY -u OPENROUTER_API_KEY -u STRIX_LLM \
    uv run strix-toolbox --self-test
```

## Cursor MCP setup

Copy [`.cursor/mcp.json.example`](.cursor/mcp.json.example). **Zero API keys.**

**Project** (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "strix-toolbox": {
      "command": "strix-toolbox",
      "args": ["mcp"]
    }
  }
}
```

**Global** (`~/.cursor/mcp.json`): same JSON.

If `strix-toolbox` is not on `PATH`, use an absolute command:

```json
{
  "mcpServers": {
    "strix-toolbox": {
      "command": "/absolute/path/to/uv",
      "args": ["run", "--directory", "/absolute/path/to/strix-toolbox", "strix-toolbox", "mcp"]
    }
  }
}
```

Restart Cursor after changing MCP config. Tools appear under MCP / Agent tools as `strix_*`.

## Examples

Passive local inspection (no network):

> Use the Strix Toolbox to inspect this project for security issues. Do not modify anything.

Active local HTTP (localhost is allowed by default):

> Call `strix_http_request` against `http://127.0.0.1:8000/`.

Active remote testing requires `strix_authorize_target` first.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — current vs toolbox architecture
- [docs/MCP.md](docs/MCP.md) — Cursor MCP configuration
- [docs/TOOLS.md](docs/TOOLS.md) — tool catalog and classifications
- [docs/SECURITY.md](docs/SECURITY.md) — allowlist, authorized-use warning
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) — tests, lint, updating from upstream

## Security model and limitations

- Authorized testing only. You are responsible for permission and scope.
- Network tools require an explicit target. Recon hits are not auto-authorized.
- No generic shell, sqlmap, or file-write/exploit-runner tools.
- Sandbox scanners need Docker; if a binary is missing the tool returns `unavailable`.
- The toolbox returns **evidence**. Cursor decides whether something is a vulnerability.
- Original `strix` CLI remains LLM-based and is unchanged in purpose.

## Testing

```bash
uv run pytest tests/toolbox -q
make toolbox-selftest
```

## Updating

```bash
git fetch upstream
git merge upstream/main   # resolve conflicts; keep strix/toolbox/
uv sync
uv run strix-toolbox --self-test
```

`origin` is this fork; `upstream` is [usestrix/strix](https://github.com/usestrix/strix).
