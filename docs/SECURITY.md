# Security model

Strix Toolbox is a **security testing** toolbox. Use it only against systems
you own or have **explicit, written permission** to test.

Unauthorized testing is illegal in most jurisdictions. You are responsible
for authorization, scope, and compliance. This software is provided "as is"
with no warranty.

This fork does **not** silently become an unrestricted internet exploitation
framework.

## Default allowlist

Allowed without `strix_authorize_target`:

- local filesystem under the project root (cwd or `STRIX_TOOLBOX_PROJECT_ROOT`)
- `localhost`, `127.0.0.1`, `::1`
- Docker sandbox / `host.docker.internal` (loopback-style host gateway)

Any other network host, URL, or CIDR must be authorized explicitly.

## Explicit authorization

Call `strix_authorize_target` with the host, URL, CIDR, or path the **user**
supplied. Do not copy hosts out of tool output and authorize them yourself
unless the user asked you to.

Reconnaissance tools return discovered names as **evidence only**. They are
never added to the allowlist automatically.

Redirects from an authorized URL to an unauthorized host are rejected.

## Classifications

- **PASSIVE** — read-only local inspection
- **ACTIVE** — network or sandbox; may change application state (HTTP, fuzzing,
  browser, Nuclei, nmap)
- **DESTRUCTIVE** — not exposed. No generic shell, sqlmap, or patch/write tools.

Active tools include a warning in their MCP description and result payload.

## What Cursor must not do

- Ask the toolbox to "decide if this is vulnerable" via an internal LLM
- Auto-attack domains found during recon
- Hide the target inside unstructured scanner dumps and have the toolbox
  extract-and-attack it

Cursor reasons. The toolbox executes.

## Secrets

Do not commit `.env`, API keys, tokens, or scan dumps. `.gitignore` already
ignores `.env`, `strix_runs/`, and `.strix-toolbox/`.
