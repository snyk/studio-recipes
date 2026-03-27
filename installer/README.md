# Snyk Studio Recipes — Installer

Cross-platform installer that copies recipes from this repo into **your user home** so **Cursor**, **Claude Code**, and/or **GitHub Copilot** can use them globally (hooks, commands/prompts, skills, MCP merge). Driven by [`manifest.json`](manifest.json).


| File | Platform | Role |
|------|----------|------|
| `build_installer.py` | — | Creates installers |
| `dist/snyk-studio-install.sh` | macOS / Linux | Installs recipes |
| `dist/snyk-studio-install.ps1` | Windows | Installs recipes |
| `dist/snyk-studio-install.py` | macOS / Linux / Windows | Installs recipes |

## What it installs

Paths are resolved under `$HOME`. The installer **detects** which ADEs you use (Cursor, Claude, Copilot) or you can target one with `--ade`.

| Recipe type (in manifest) | Typical outcome |
|---------------------------|-----------------|
| **hooks** | Hook scripts + JSON merge into Cursor `~/.cursor/hooks.json`, Claude `~/.claude/settings.json`, or Copilot `~/.copilot/hooks/hooks.json` |
| **command** | Cursor/Claude: slash commands under `.cursor/commands/` or `.claude/commands/`; Copilot: prompt files under `.copilot/prompts/` (`.prompt.md`) |
| **skill** | Cursor: `.cursor/skills/snyk/...`; Claude: skill as a command `.md`; Copilot: `.copilot/skills/...` |
| **mcp** | Cursor & Claude: merge into `~/.mcp.json`; Copilot: merge into `~/.copilot/mcp-config.json` (sources differ per ADE in the manifest) |

## Prerequisites

- **Python 3.8+** (for running `snyk-studio-installer.py` after the bundle is extracted; not required for the extract step itself)
- **Snyk CLI** recommended (installer warns if missing; authenticate with `snyk auth` when you run scans)

## Build the distributables

```bash
cd installer
python3 build_installer.py
```


Rebuild after changing `manifest.json` or any packaged sources.

## Run the installer

**macOS / Linux**

```shell
bash ./dist/snyk-studio-install.sh [options]
```

**Windows**

```shell
pwsh .\dist\snyk-studio-install.ps1 [options]
```

**Develop from a git checkout** (no build)

```shell
python3 snyk-studio-installer.py [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--profile <name>` | `default` or `minimal` |
| `--ade <cursor\|claude\|copilot>` | Install only for one ADE (otherwise auto-detect / prompt) |
| `--dry-run` | Show what would be installed without making changes |
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

Exit code **1** if something is missing or drifted; re-run the installer to repair.

```bash
bash ./dist/snyk-studio-install.sh --verify
bash ./dist/snyk-studio-install.sh --ade cursor --profile default --verify
bash ./dist/snyk-studio-install.sh --ade copilot --verify
```

Implementation: `lib/merge_json.py` (`verify_cursor_hooks`, `verify_claude_settings`, `verify_copilot_hooks`, `verify_mcp_servers`, `verify_copilot_mcp`).

### Profiles (current manifest)

| Profile | What gets selected |
|---------|---------------------|
| **default** | Secure-at-inception hooks, `/snyk-fix` + `/snyk-batch-fix` (or Copilot prompt equivalents), secure dependency health check skill, MCP config |
| **minimal** | Hooks + MCP only |

### Develop from a git checkout

Run `python3 snyk-studio-installer.py` from this directory (payload is read from the repo: `manifest.json` and `lib/` beside the script; recipe sources are resolved from `../` relative to this folder’s parent). Run **`python3 build_installer.py`** when you want to refresh **`dist/`** self-extracting scripts.

## Repository layout (this folder)

| Path | Role |
|------|------|
| `manifest.json` | Declares recipes, files, merges, transforms, and profiles |
| `snyk-studio-installer.py` | Core installer logic; copied into the bundle and run with `SNYK_STUDIO_BUNDLE_ROOT` after extraction |
| `build_installer.py` | Builds `dist/snyk-studio-install.sh`, `dist/snyk-studio-install.ps1`, and `dist/snyk-studio-install.py` from the templates below |
| `templates/install.sh.template` | Template for the macOS / Linux installer |
| `templates/install.ps1.template` | Template for the Windows installer |
| `templates/install.py.template` | Python installer kept for backwards compatibility |
| `lib/merge_json.py` | JSON merge strategies (Cursor/Claude/Copilot hooks, Claude settings, MCP, Copilot MCP file) |
| `lib/transform.py` | e.g. skill → command, `.mdc` → `.md` |
| `dist/` | Generated installers (not hand-edited); safe to delete and recreate with `build_installer.py` |
| `tests/` | pytest suite (`pytest.ini` at repo root of this folder configures discovery) |

## Customization

- Edit **`manifest.json`** to add/remove recipes, change profiles, or point at different sources.
- Re-run **`python3 build_installer.py`** to refresh `dist/`.

For behavior details (merge strategies, uninstall paths, ADE detection), see `snyk-studio-installer.py` and `lib/`.
