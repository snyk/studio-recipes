# Snyk Studio Recipes — `snyk-studio-install.sh`

Single-file installer for Snyk Studio recipes. It unpacks an embedded payload and installs into your **home directory** so **Cursor**, **Claude Code**, and/or **Gemini Code** can use the bundled hooks, slash commands, skills, and MCP configuration.

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

Installs into paths under `$HOME` (for example `~/.cursor/`, `~/.claude/`, and `~/.gemini/`). The installer can **auto-detect** Cursor / Claude Code / Gemini Code, or you can target one environment with `--ade`.

### Options

| Option | Description |
|--------|-------------|
| `--profile <name>` | Installation profile: `default` or `minimal` |
| `--ade <cursor\|claude\|gemini>` | Install only for that ADE (otherwise auto-detect or prompt) |
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
- Confirms **merged configs** still contain the expected Snyk content: Cursor `hooks.json`, Claude `settings.json` hook entries, Gemini `settings.json` hook entries, and MCP server entries in `~/.cursor/.mcp.json`, `~/.claude/.mcp.json`, and `~/.gemini/settings.json`, as defined in the bundled manifest.

This does not launch the IDE or run `snyk` scans—it only validates paths and JSON. Exit code **1** means a mismatch or missing piece; run the installer again to fix.

### Profiles (typical bundle)

| Profile | Contents (high level) |
|---------|-------------------------|
| **default** | Secure-at-inception hooks, `/snyk-fix` and `/snyk-batch-fix` commands, secure dependency health skill, MCP config |
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