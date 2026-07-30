# Snyk Studio Recipes — `snyk-studio-install.sh`

Single-file installer for Snyk Studio recipes. It unpacks an embedded payload and installs assistant-scoped recipes into your **home directory** (or, for VS Code Copilot, the platform-specific user data directory). Workspace-scoped pre-commit hooks install into the target Git repository when requested. **Cursor**, **Claude Code**, **Gemini Code**, **Kiro**, **Codex**, **Windsurf**, **GitHub Copilot CLI**, and/or **GitHub Copilot in VS Code** can use the bundled hooks, slash commands, skills, and MCP configuration. Kiro and Windsurf install commands, skills, and MCP only — SAI hooks are not configured for them. GitHub Copilot SAI hooks install once under `~/.copilot/hooks/` and apply to **both** Copilot CLI and Copilot in VS Code (both surfaces read from that directory). Copilot CLI does not yet support custom slash commands so only skills + MCP + SAI hooks are installed there. Codex does not support user-defined slash commands.

No separate download is required beyond this script.

## Prerequisites

- **Python 3.8+** (required)
- **Snyk CLI** and **Snyk authentication** (recommended; the installer warns if they are missing—hooks and scans need them)

## Get the script on your machine

Pick one:

1. **Clone the repository** and use the file from your checkout:
   ```bash
   cd /path/to/studio-recipes/installer/dist
   chmod +x snyk-studio-install.sh
   ```

2. **Pipe from `curl`**:
   ```bash
   curl -fsSL 'https://raw.githubusercontent.com/snyk/studio-recipes/main/installer/dist/snyk-studio-install.sh' -o snyk-studio-install.sh
   chmod +x snyk-studio-install.sh
   ```

## Run

```bash
./snyk-studio-install.sh [options]
```

Assistant-scoped recipes install into paths under `$HOME` (for example `~/.cursor/`, `~/.claude/`, `~/.gemini/`, `~/.kiro/`, `~/.codex/`, `~/.codeium/windsurf/`, `~/.copilot/`, and `~/.agents/skills/` for Windsurf and Codex skills). VS Code Copilot installs under the platform-specific user data directory: `~/Library/Application Support/Code/User/` (macOS), `~/.config/Code/User/` (Linux), `%APPDATA%\Code\User\` (Windows). Workspace-scoped pre-commit hooks install into the Git repository selected by `--workspace` or the current directory's enclosing Git repository. The installer can **auto-detect** Cursor / Claude Code / Gemini Code / Kiro / Codex / Windsurf / Copilot CLI / Copilot in VS Code, or you can target one environment with `--ade`.

> **Codex notes.** Codex stores its hooks and MCP servers in a single TOML file at `~/.codex/config.toml` (the installer merges into both `[hooks.*]` and `[mcp_servers.*]` blocks and sets `[features] hooks = true`). Skills install to `~/.agents/skills/snyk/...` per Codex's documented convention. Codex does **not** support user-defined slash commands, so `/snyk-fix` and `/snyk-batch-fix` are skipped for the codex ADE.

### Options

| Option | Description |
|--------|-------------|
| `--profile <name>` | Installation profile: `default`, `minimal`, or `experimental` |
| `--ade <cursor\|claude\|gemini\|kiro\|codex\|windsurf\|copilot-cli\|copilot-vscode>` | Install only for that ADE (otherwise auto-detect or prompt) |
| `--workspace <path>` | Choose the repo for workspace-scoped commit-time hooks |
| `--dry-run` | Show what would happen without writing files |
| `--uninstall` | Remove Snyk recipe artifacts installed by this installer; add `--workspace <path>` for workspace-scoped hooks |
| `--verify` | Verify the install: files on disk and merged JSON match the manifest. Also checks Node.js/Snyk CLI versions and, like a normal install, may offer to upgrade them |
| `--read-only` | With `--verify`, only report prerequisite versions instead of offering to install/upgrade them — guarantees no changes are made |
| `--secrets-precommit-hook` | Install the Secrets At Commit hook |
| `--list` | List recipes and profiles bundled in the script |
| `-y`, `--yes` | Skip confirmation prompts |
| `-h`, `--help` | Show built-in help |

### Verification

After a normal install (not `--dry-run`), the script **runs these checks automatically** at the end. If something fails, you see a warning; use **`--verify`** anytime to print the same checks in full.

**`./snyk-studio-install.sh --verify`** walks the recipes for your current **profile** and **ADE** (respects `--profile` and `--ade` if you pass them) and:

- Confirms each **file** from the manifest exists in its expected install location.
- Confirms **merged configs and hook entries** still contain the expected Snyk content: Cursor `hooks.json`, Claude `settings.json` hook entries, Gemini `settings.json` hook entries, workspace pre-commit integrations, and MCP server entries in `~/.cursor/.mcp.json`, `~/.claude/.mcp.json`, `~/.gemini/settings.json`, `~/.kiro/settings/mcp.json`, `~/.codeium/windsurf/mcp_config.json`, `~/.copilot/mcp-config.json`, and `<vscode-user>/mcp.json`, plus (for Codex) the `[features].hooks`, `[hooks.*]`, and `[mcp_servers.*]` blocks in `~/.codex/config.toml`.

This does not launch the IDE or run `snyk` scans—it only validates paths and JSON. Exit code **1** means a mismatch or missing piece; run the installer again to fix.

By default `--verify` also checks Node.js/Snyk CLI versions the same way a normal install does, and may prompt to upgrade them. Pass **`--read-only`** alongside `--verify` to only report those versions without ever installing or upgrading anything.

### Profiles (typical bundle)

| Profile | Contents (high level) |
|---------|-------------------------|
| **default** | Secure-at-inception hooks, `/snyk-fix` and `/snyk-batch-fix` commands (Cursor/Claude), secure dependency health skill, MCP config |
| **minimal** | Hooks and MCP only |
| **experimental** | Secure-at-commit hooks (SAST + SCA), `/snyk-fix` and `/snyk-batch-fix` commands (Cursor/Claude), secure dependency health skill, MCP config |

Secrets At Commit is opt-in and installs into a target repository. Run the installer inside that repository or pass `--workspace <path>`, and add `--secrets-precommit-hook`.

### Examples

```bash
# Install for whatever ADEs are detected, default profile, no extra prompts
./snyk-studio-install.sh -y

# Only Cursor, minimal profile
./snyk-studio-install.sh --ade cursor --profile minimal -y

# Preview changes
./snyk-studio-install.sh --dry-run

# Default profile with Secrets At Commit for a specific repo
./snyk-studio-install.sh --workspace /path/to/repo --secrets-precommit-hook -y

# Remove assistant-scoped recipes
./snyk-studio-install.sh --uninstall -y

# Remove workspace-scoped hooks from a specific repo too
./snyk-studio-install.sh --workspace /path/to/repo --uninstall -y

# Re-check install without changing anything (same profile/ADE as you use for install)
./snyk-studio-install.sh --verify
./snyk-studio-install.sh --ade cursor --profile default --verify
```

After install, open your IDE and confirm recipes are active. Run `snyk auth` if the installer warned about authentication.
