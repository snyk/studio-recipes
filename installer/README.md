# Snyk Studio Recipes — Installer

Self-contained shell installer that copies recipes from this repo into **your user home** so **Cursor** and/or **Claude Code** can use them globally (hooks, commands, skills, MCP merge). It is driven by [`manifest.json`](manifest.json).

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
| `--ade <cursor\|claude>` | Install only for one ADE (otherwise auto-detect / prompt) |
| `--dry-run` | Show actions without writing files |
| `--uninstall` | Remove installed Snyk recipe artifacts from detected ADEs |
| `--list` | List recipes and profiles from the embedded manifest |
| `-y`, `--yes` | Skip confirmation prompts |
| `-h`, `--help` | Help |

### Profiles (current manifest)

| Profile | What gets selected |
|---------|--------------------|
| **default** | Secure-at-inception hooks, `/snyk-fix` + `/snyk-batch-fix` commands, secure dependency health check skill, MCP config |
| **minimal** | Hooks + MCP only |

### Develop without rebuilding

For quick iteration you can run **`template.sh`** from a git checkout **only if** you manually mirror what `build.sh` does (payload + `manifest.json` beside the script). For distribution, prefer `build.sh` → `dist/snyk-studio-install.sh`.

## Repository layout (this folder)

| Path | Role |
|------|------|
| `manifest.json` | Declares recipes, files, merges, transforms, and profiles |
| `template.sh` | Installer source; embeds tarball after build |
| `build.sh` | Produces `dist/snyk-studio-install.sh` |
| `lib/merge_json.py` | JSON merge strategies (hooks, MCP, Claude settings) |
| `lib/transform.py` | e.g. skill → command, `.mdc` → `.md` |
| `dist/` | Generated `snyk-studio-install.sh` (after build) — not hand-edited |

## Customization

- Edit **`manifest.json`** to add/remove recipes, change profiles, or point at different sources.
- Re-run **`./build.sh`** to refresh `dist/snyk-studio-install.sh`.

For behavior details (merge strategies, uninstall paths, ADE detection), see comments in `template.sh`.
