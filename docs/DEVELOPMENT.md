# Development

This repository is a fork of [usestrix/strix](https://github.com/usestrix/strix).
Keep `strix/toolbox/` maintainable and avoid rewriting the upstream agent loop.

## Setup

Python 3.12+, [uv](https://docs.astral.sh/uv/), Docker optional.

```bash
uv sync
uv run strix-toolbox --self-test
```

## Layout added by this fork

```text
strix/toolbox/     # no-LLM execution + MCP
tests/toolbox/     # toolbox tests
docs/ARCHITECTURE.md MCP.md TOOLS.md SECURITY.md DEVELOPMENT.md
```

Do not import `strix.agents.factory` or `strix.interface.main` from toolbox
code. Sandbox control uses the Docker SDK, not `strix.runtime.session_manager`
(that module pulls openai-agents).

## Tests

```bash
uv run pytest tests/toolbox -q
make toolbox-test
make toolbox-selftest
```

Docker/browser tests skip when the daemon or sandbox image is missing.

No-LLM gate:

```bash
env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY -u GOOGLE_API_KEY \
    -u GEMINI_API_KEY -u LLM_API_KEY -u OPENROUTER_API_KEY -u STRIX_LLM \
    uv run strix-toolbox --self-test
```

Upstream `tests/` still cover the original LLM agent. They may need API keys
or extra fixtures. Toolbox success is defined by `tests/toolbox` plus
`strix-toolbox --self-test`.

## Lint

```bash
uv run ruff check strix/toolbox tests/toolbox
uv run ruff format strix/toolbox tests/toolbox
```

`make check-all` runs upstream ruff/mypy/bandit across the whole tree.

## Updating from upstream

```bash
git remote -v
# origin   = your fork (strix-toolbox)
# upstream = usestrix/strix

git fetch upstream
git merge upstream/main
```

Keep toolbox files on conflict. Re-run toolbox tests after merge.

Do not open a pull request to usestrix/strix unless you intend to contribute
upstream-compatible changes separately.
