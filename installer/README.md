# Snyk Studio Recipes — Installer

Cross-platform installer that copies recipes from this repo into **your user home** so **Cursor** and/or **Claude Code** can use them globally (hooks, commands, skills, MCP merge). It is driven by [`manifest.json`](manifest.json).

Two installer variants are available:

| Variant | File | Platform | Build tool |
|---------|------|----------|------------|
| **Shell** | `dist/snyk-studio-install.sh` | macOS / Linux | `build.sh` |
| **Python** | `dist/snyk-studio-install.py` | macOS / Linux / Windows | `build_installer.py` |

Both read the same `manifest.json` and produce identical results.

## What it installs

Paths are resolved under `$HOME` (e.g. `~/.cursor/...`, `~/.claude/...`, `~/.mcp.json`). The installer **detects** which ADEs you use or you can target one with `--ade`.

| Recipe type (in manifest) | Typical outcome |
|---------------------------|-----------------|
| **hooks** | Hook scripts + JSON merge into Cursor `hooks.json` or Claude `settings.json` |
| **command** | Slash commands under `.cursor/commands/` or `.claude/commands/` |
| **skill** | Cursor: skills under `.cursor/skills/snyk/...`; Claude: often transformed into a command `.md` |
| **mcp** | Merge of Snyk MCP server entries into `~/.mcp.json` (source: `mcp/.mcp.json` in the repo) |

Source layout and destinations are defined per recipe in `manifest.json`.

## Prerequisites

The installer checks these at run time:

- **Python 3.8+** (required)
- **Snyk CLI** (offered for install/upgrade via npm if missing or outdated; use `--disable-upgrades` to skip)

## Build the distributable

### Shell installer (macOS / Linux)

```bash
cd installer
./build.sh
```

This reads `manifest.json`, collects all referenced files from the **repository root**, embeds them as a base64 tarball in `template.sh`, and writes `dist/snyk-studio-install.sh`.

### Python installer (cross-platform)

```bash
cd installer
python3 build_installer.py
```

This reads `manifest.json`, collects all referenced files, embeds them as a base64 zip in `snyk-studio-installer.py`, and writes `dist/snyk-studio-install.py`.

Rebuild after changing `manifest.json` or any packaged sources.

## Run the installer

### macOS / Linux

```bash
chmod +x dist/snyk-studio-install.sh
./dist/snyk-studio-install.sh [options]
```

### Windows (or any platform with Python)

```bash
python dist/snyk-studio-install.py [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--profile <name>` | `default` or `minimal` |
| `--ade <cursor\|claude>` | Install only for one ADE (otherwise auto-detect / prompt) |
| `--dry-run` | Show actions without writing files |
| `--uninstall` | Remove installed Snyk recipe artifacts from detected ADEs |
| `--verify` | Check that installed files and merged configs match the manifest (read-only) |
| `--list` | List recipes and profiles from the embedded manifest |
| `-y`, `--yes` | Skip confirmation prompts |
| `--disable-upgrades` | Skip Snyk CLI install/upgrade checks |
| `-h`, `--help` | Help |

### Verification

After a successful install **without** `--dry-run`, the script runs the same checks as `--verify` automatically. If any check fails, the summary shows a warning and suggests re-running with `--verify` for full output.

**`--verify`** (standalone) re-checks the current **profile** and **ADE** selection (same flags as install):

- **Files**: Each path from the manifest exists under `$HOME` (commands, hook scripts, skills, etc.).
- **Merged JSON**: For recipes that use `config_merge`, the live files (`~/.cursor/hooks.json`, Claude `settings.json`, `~/.mcp.json`) still contain the Snyk entries expected from the embedded manifest (hook commands per event, MCP server names, and for Claude, matcher groups).

It does not start your IDE or run Snyk scans—only filesystem and JSON structure checks. Exit code **1** if something is missing or drifted; re-run the installer to repair.

```bash
./dist/snyk-studio-install.sh --verify
./dist/snyk-studio-install.sh --ade cursor --profile default --verify
```

Implementation: `lib/merge_json.py` (`verify_cursor_hooks`, `verify_claude_settings`, `verify_mcp_servers`).

### Profiles (current manifest)

| Profile | What gets selected |
|---------|--------------------|
| **default** | Secure-at-inception hooks, `/snyk-fix` + `/snyk-batch-fix` commands, secure dependency health check skill, MCP config |
| **minimal** | Hooks + MCP only |

### Develop without rebuilding

For quick iteration you can run **`template.sh`** (shell) or **`snyk-studio-installer.py`** (Python) from a git checkout **only if** you manually mirror what the build scripts do (payload + `manifest.json` beside the script). For distribution, prefer the build output in `dist/`.

## Repository layout (this folder)

| Path | Role |
|------|------|
| `manifest.json` | Declares recipes, files, merges, transforms, and profiles |
| `template.sh` | Shell installer source; embeds tarball after build |
| `build.sh` | Produces `dist/snyk-studio-install.sh` |
| `snyk-studio-installer.py` | Python installer source; embeds zip after build |
| `build_installer.py` | Produces `dist/snyk-studio-install.py` |
| `lib/merge_json.py` | JSON merge strategies (hooks, MCP, Claude settings) |
| `lib/transform.py` | e.g. skill → command, `.mdc` → `.md` |
| `dist/` | Generated installers (after build) — not hand-edited |
| `tests/` | pytest test suite |

## Customization

- Edit **`manifest.json`** to add/remove recipes, change profiles, or point at different sources.
- Re-run **`./build.sh`** and/or **`python3 build_installer.py`** to refresh the distributable(s).

For behavior details (merge strategies, uninstall paths, ADE detection), see comments in `template.sh` and `snyk-studio-installer.py`.
