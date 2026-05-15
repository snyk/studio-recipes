# Snyk Studio Recipes — `snyk-studio-install.sh`

Single-file installer for Snyk Studio recipes. It unpacks an embedded payload and installs into your **home directory** (or, for VS Code Copilot, the platform-specific user data directory) so **Cursor**, **Claude Code**, **Gemini Code**, **Kiro**, the **Codex CLI**, **Windsurf**, **GitHub Copilot CLI**, and/or **GitHub Copilot in VS Code** can use the bundled hooks, slash commands, skills, and MCP configuration. Kiro, Windsurf, and Copilot install commands, skills, and MCP only — SAI hooks are not configured for them. Copilot CLI does not yet support custom slash commands so only skills + MCP are installed there. Codex CLI does not support user-defined slash commands.

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

Installs into paths under `$HOME` (for example `~/.cursor/`, `~/.claude/`, `~/.gemini/`, `~/.kiro/`, `~/.codex/`, `~/.codeium/windsurf/`, `~/.copilot/`, and `~/.agents/skills/` for Windsurf and Codex skills). VS Code Copilot installs under the platform-specific user data directory: `~/Library/Application Support/Code/User/` (macOS), `~/.config/Code/User/` (Linux), `%APPDATA%\Code\User\` (Windows). The installer can **auto-detect** Cursor / Claude Code / Gemini Code / Kiro / Windsurf / Copilot CLI / Copilot in VS Code, or you can target one environment with `--ade`.

> **Codex notes.** Codex stores its hooks and MCP servers in a single TOML file at `~/.codex/config.toml` (the installer merges into both `[hooks.*]` and `[mcp_servers.*]` blocks and sets `[features] hooks = true`). Skills install to `~/.agents/skills/snyk/...` per Codex's documented convention. Codex CLI does **not** support user-defined slash commands, so `/snyk-fix` and `/snyk-batch-fix` are skipped for the codex ADE.

### Options

| Option | Description |
|--------|-------------|
| `--profile <name>` | Installation profile: `default` or `minimal` |
| `--ade <cursor\|claude\|gemini\|kiro\|codex\|windsurf\|copilot-cli\|copilot-vscode>` | Install only for that ADE (otherwise auto-detect or prompt) |
| `--dry-run` | Show what would happen without writing files |
| `--uninstall` | Remove Snyk recipe artifacts installed by this installer |
| `--verify` | Verify the install: files on disk and merged JSON match the manifest (read-only) |
| `--list` | List recipes and profiles bundled in the script |
| `-y`, `--yes` | Skip confirmation prompts |
| `-h`, `--help` | Show built-in help |

### Verification

After a normal install (not `--dry-run`), the script **runs these checks automatically** at the end. If something fails, you see a warning; use **`--verify`** anytime to print the same checks in full.

**`./snyk-studio-install.sh --verify`** walks the recipes for your current **profile** and **ADE** (respects `--profile` and `--ade` if you pass them) and:

- Confirms each **file** from the manifest exists under your home directory.
- Confirms **merged configs** still contain the expected Snyk content: Cursor `hooks.json`, Claude `settings.json` hook entries, Gemini `settings.json` hook entries, and MCP server entries in `~/.cursor/.mcp.json`, `~/.claude/.mcp.json`, `~/.gemini/settings.json`, `~/.kiro/settings/mcp.json`, `~/.codeium/windsurf/mcp_config.json`, `~/.copilot/mcp-config.json`, and `<vscode-user>/mcp.json`, plus (for Codex) the `[features].hooks`, `[hooks.*]`, and `[mcp_servers.*]` blocks in `~/.codex/config.toml`.

This does not launch the IDE or run `snyk` scans—it only validates paths and JSON. Exit code **1** means a mismatch or missing piece; run the installer again to fix.

### Profiles (typical bundle)

| Profile | Contents (high level) |
|---------|-------------------------|
| **default** | Secure-at-inception hooks, `/snyk-fix` and `/snyk-batch-fix` commands (Cursor/Claude), secure dependency health skill, MCP config |
| **minimal** | Hooks and MCP only |

### Examples

```bash
# Install for whatever ADEs are detected, default profile, no extra prompts
./snyk-studio-install.sh -y

# Only Cursor, minimal profile
./snyk-studio-install.sh --ade cursor --profile minimal -y

# Preview changes
./snyk-studio-install.sh --dry-run

# Remove what this installer added
./snyk-studio-install.sh --uninstall -y

# Re-check install without changing anything (same profile/ADE as you use for install)
./snyk-studio-install.sh --verify
./snyk-studio-install.sh --ade cursor --profile default --verify
```

After install, open your IDE and confirm recipes are active. Run `snyk auth` if the installer warned about authentication.
