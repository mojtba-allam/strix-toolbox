# MCP and Cursor setup

Strix Toolbox speaks MCP over **stdio**. Cursor launches the process and the
toolbox never calls an LLM.

## Start command

```bash
strix-toolbox mcp
```

Help / version / self-test also require **no API keys**:

```bash
strix-toolbox --help
strix-toolbox --version
strix-toolbox --self-test
```

## Project config

Create `.cursor/mcp.json` in the project you want Cursor to test (or copy
[`.cursor/mcp.json.example`](../.cursor/mcp.json.example)):

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

Do **not** put API keys, tokens, or `env` LLM variables in this file.

## Global config

`~/.cursor/mcp.json` uses the same JSON. Global install is convenient when
`strix-toolbox` is on your `PATH`.

## Absolute path (when PATH is empty)

From a uv checkout:

```json
{
  "mcpServers": {
    "strix-toolbox": {
      "command": "/home/YOU/.local/bin/uv",
      "args": [
        "run",
        "--directory",
        "/media/panda/D/work/Fino/strix-toolbox",
        "strix-toolbox",
        "mcp"
      ]
    }
  }
}
```

Adjust the `uv` and checkout paths to your machine.

Optional project root for filesystem tools:

```bash
export STRIX_TOOLBOX_PROJECT_ROOT=/path/to/target/app
```

Cursor typically starts the MCP server with the workspace as cwd, which is
enough for `strix_list_files` / `strix_search_code`.

## Verify the server

```bash
# 1. CLI
env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY -u GOOGLE_API_KEY \
    -u GEMINI_API_KEY -u LLM_API_KEY -u OPENROUTER_API_KEY -u STRIX_LLM \
    uv run strix-toolbox --self-test

# 2. Process starts (stdio; it will wait for MCP messages)
uv run strix-toolbox mcp
```

In Cursor: reload MCP / restart Cursor, then confirm tools named `strix_*`
appear under MCP / Agent tools.

## Original Strix CLI

`strix` (the upstream entry point) still requires `STRIX_LLM` and is **not**
the MCP server. Use `strix-toolbox mcp` for Cursor.
