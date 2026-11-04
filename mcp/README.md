# compliance-knowledge (MCP server)

First slice of the **compliance-knowledge** server from the "Claude for Compliance" architecture slide. Hackathon concept demo.

## Run

From the repo root:

```bash
python3 -m venv .venv && .venv/bin/pip install -r mcp/requirements.txt && .venv/bin/python mcp/server.py
```

`.mcp.json` launches the server with `.venv/bin/python`, so Claude Code picks it up when started from the repo root (approve the server when it asks). On Windows, change the command to `.venv\\Scripts\\python.exe`.

Tests: `cd mcp && ../.venv/bin/python -m pytest -q`

`mcp` is pinned below 2.0 because the 2.x SDK renamed FastMCP to MCPServer.

## Tools

| Tool | What it does |
|---|---|
| `scope_obligations(processes_eu_personal_data, people_talk_to_ai, high_risk_ai)` | Obligations that apply (GDPR Art. 30, Art. 32, EU AI Act Art. 50) |
| `get_control(control_id)` | Control with its mapped obligations and ISO/IEC 27001 control IDs |
| `get_recipe(recipe_id)` | detect / fix / verify / evidence / gate for a recipe |
| `run_check(recipe_id, path)` | Runs **only** the recipe's detect command → `pass` / `fail` / `not_checked` + raw output |
| `record_evidence(recipe_id, status, output)` | Appends a JSON line with timestamp + sha256 of the output to `mcp/evidence.jsonl` |

## Scope note

- `route_goal` and `check_updates` are deliberately left out of this slice.
- `high_risk_ai` is accepted but no seeded obligation uses it yet (placeholder for EU AI Act high-risk duties).
- **`run_check` is a stand-in for the separate scanner server's `scanner.run`.** In the full architecture, knowledge and execution live in different servers.

## Safety rules

- Never applies a fix. Recipes describe fixes; a human applies them after the approval gate.
- Only runs the `detect` argv from `data/recipes.yaml`. No shell, `{path}` is the only substitution, 60 s timeout, paths that look like flags are rejected.
- Exit 0 = pass, 1 = fail; anything else, a timeout, or a missing binary = `not_checked` (never a guessed pass).
- Seed data is plain-language summary only — no quoted legal or ISO text.

## Scanner setup (before the demo)

- Install `gitleaks` and `trivy`.
- `trivy fs --download-db-only` once, so the first real scan doesn't hit the 60 s timeout.
- gitleaks uses `--no-git` (scan files on disk, catches uncommitted keys) and `--redact` (raw key stays out of output/evidence).

## Demo line (Claude Code)

> Use compliance-knowledge to scope Acme (EU personal data yes, AI chat yes, high-risk no), then run the secret-in-repo check on this repo and record the evidence.

Expected: 3 obligations; `secret-in-repo` → `fail` on `sample-repo/` (fake key); one new hashed line in `mcp/evidence.jsonl`.
