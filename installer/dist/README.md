# Snyk Studio Recipes — `snyk-studio-install.sh`

Single-file installer for Snyk Studio recipes. It unpacks an embedded payload and installs into your **home directory** so **Cursor** and/or **Claude Code** can use the bundled hooks, slash commands, skills, and MCP configuration.

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

2. **Copy the file** from a teammate, release bundle, or internal share—e.g. save `snyk-studio-install.sh` into a folder on your machine, then `chmod +x` it.

3. **Download from Git hosting** (if the repo is online): open the file in the browser, use “Raw”, and save as `snyk-studio-install.sh`, or use `curl`/`wget` against the raw URL your team documents (branch and path may vary).

4. **Pipe from `curl`**:
   ```bash
   curl -fsSL 'https://github.com/snyk/studio-recipes/tree/main/installer/distsnyk-studio-install.sh' -o snyk-studio-install.sh
   chmod +x snyk-studio-install.sh
   ```

The script must stay **one self-contained file**—do not split it or strip the payload section at the bottom.

## Run

```bash
./snyk-studio-install.sh [options]
```

Installs into paths under `$HOME` (for example `~/.cursor/`, `~/.claude/`, `~/.mcp.json`). The installer can **auto-detect** Cursor / Claude Code, or you can target one environment with `--ade`.

### Options

| Option | Description |
|--------|-------------|
| `--profile <name>` | Installation profile: `default` or `minimal` |
| `--ade <cursor\|claude>` | Install only for that ADE (otherwise auto-detect or prompt) |
| `--dry-run` | Show what would happen without writing files |
| `--uninstall` | Remove Snyk recipe artifacts installed by this installer |
| `--list` | List recipes and profiles bundled in the script |
| `-y`, `--yes` | Skip confirmation prompts (e.g. when Snyk CLI is missing) |
| `-h`, `--help` | Show built-in help |

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
```

After install, open your IDE and confirm recipes are active. Run `snyk auth` if the installer warned about authentication.
