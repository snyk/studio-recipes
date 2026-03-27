# Snyk Studio Recipes — Installer

Self-contained shell installer that copies recipes from this repo into **your user home** so **Cursor**, **Claude Code**, and/or **GitHub Copilot** (hooks, commands/prompts, skills, MCP) can use them globally. It is driven by [`manifest.json`](manifest.json).

## What it installs

Paths are resolved under `$HOME`. The installer **detects** which ADEs you use (Cursor, Claude, Copilot) or you can target one with `--ade`.

| Recipe type (in manifest) | Typical outcome |
|---------------------------|-----------------|
| **hooks** | Hook scripts + JSON merge into Cursor `~/.cursor/hooks.json`, Claude `~/.claude/settings.json`, or Copilot `~/.copilot/hooks/hooks.json` |
| **command** | Cursor/Claude: slash commands under `.cursor/commands/` or `.claude/commands/`; Copilot: prompt files under `.copilot/prompts/` (`.prompt.md`) |
| **skill** | Cursor: `.cursor/skills/snyk/...`; Claude: skill as a command `.md`; Copilot: `.copilot/skills/...` |
| **mcp** | Cursor & Claude: merge into `~/.mcp.json`; Copilot: merge into `~/.copilot/mcp-config.json` (sources differ per ADE in the manifest) |

Source layout and destinations are defined per recipe in `manifest.json`.

## Prerequisites

The manifest documents expectations; the bundled script checks at run time:

- **Python 3.8+** (required)
- **Snyk CLI** and **Snyk auth** (warned if missing; hooks/scans need them)

## Build the distributable

From this directory:

```bash
cd installer
./build.sh
```

This reads `manifest.json`, collects all referenced files from the **repository root**, embeds them in `template.sh`, and writes:

- **`dist/snyk-studio-install.sh`** — single file you can copy or ship; it extracts its payload and runs.

Rebuild after changing `manifest.json` or any packaged sources.

## Run the installer

```bash
chmod +x dist/snyk-studio-install.sh
./dist/snyk-studio-install.sh [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--profile <name>` | `default` or `minimal` |
| `--ade <cursor\|claude\|copilot>` | Install only for one ADE (otherwise auto-detect / prompt) |
| `--dry-run` | Show actions without writing files |
| `--uninstall` | Remove installed Snyk recipe artifacts from detected ADEs |
| `--verify` | Check that installed files and merged configs match the manifest (read-only) |
| `--list` | List recipes and profiles from the embedded manifest |
| `-y`, `--yes` | Skip confirmation prompts |
| `-h`, `--help` | Help |

### Verification

After a successful install **without** `--dry-run`, the script runs the same checks as `--verify` automatically. If any check fails, the summary shows a warning and suggests re-running with `--verify` for full output.

**`--verify`** (standalone) re-checks the current **profile** and **ADE** selection (same flags as install):

- **Files**: Each path from the manifest exists under `$HOME` (commands, hook scripts, skills, prompts, etc.).
- **Merged JSON**: For recipes that use `config_merge`, the live files still contain the Snyk entries expected from the embedded manifest—for example Cursor `hooks.json`, Claude `settings.json`, Copilot `~/.copilot/hooks/hooks.json`, MCP in `~/.mcp.json` or `~/.copilot/mcp-config.json` (hook commands per event, MCP server names, and for Claude, matcher groups).

It does not start your IDE or run Snyk scans—only filesystem and JSON structure checks. Exit code **1** if something is missing or drifted; re-run the installer to repair.

```bash
./dist/snyk-studio-install.sh --verify
./dist/snyk-studio-install.sh --ade cursor --profile default --verify
./dist/snyk-studio-install.sh --ade copilot --verify
```

Implementation: `lib/merge_json.py` (`verify_cursor_hooks`, `verify_claude_settings`, `verify_copilot_hooks`, `verify_mcp_servers`, `verify_copilot_mcp`).

### Profiles (current manifest)

| Profile | What gets selected |
|---------|--------------------|
| **default** | Secure-at-inception hooks, `/snyk-fix` + `/snyk-batch-fix` (or Copilot prompt equivalents), secure dependency health check skill, MCP config |
| **minimal** | Hooks + MCP only |

### Develop without rebuilding

For quick iteration you can run **`template.sh`** from a git checkout **only if** you manually mirror what `build.sh` does (payload + `manifest.json` beside the script). For distribution, prefer `build.sh` → `dist/snyk-studio-install.sh`.

## Repository layout (this folder)

| Path | Role |
|------|------|
| `manifest.json` | Declares recipes, files, merges, transforms, and profiles |
| `template.sh` | Installer source; embeds tarball after build |
| `build.sh` | Produces `dist/snyk-studio-install.sh` |
| `lib/merge_json.py` | JSON merge strategies (Cursor/Claude/Copilot hooks, MCP, Copilot MCP file) |
| `lib/transform.py` | e.g. skill → command, `.mdc` → `.md` |
| `dist/` | Generated `snyk-studio-install.sh` (after build) — not hand-edited |

## Customization

- Edit **`manifest.json`** to add/remove recipes, change profiles, or point at different sources.
- Re-run **`./build.sh`** to refresh `dist/snyk-studio-install.sh`.

For behavior details (merge strategies, uninstall paths, ADE detection), see comments in `template.sh`.
