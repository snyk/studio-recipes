# Snyk Studio Recipes — Installer

One command to embed Snyk's [Secure at Inception](https://snyk.io/product/studio/) recipes into your AI coding assistant. The installer detects which assistants you have, installs any missing dependencies (Snyk CLI, Node.js, Python tooling), and merges assistant-scoped hooks, slash commands, skills, and MCP configuration into each assistant's user directory. Workspace-scoped pre-commit hooks install into the target Git repository when requested.

**Supported assistants:** Cursor • Claude Code • Gemini • Kiro • Codex • Windsurf • GitHub Copilot CLI • GitHub Copilot in VS Code

---

## Prerequisites

- A supported AI coding assistant
- A [Snyk account](https://app.snyk.io)

The installer bootstraps everything else for you (`uv`, Python, Node.js, npm, the Snyk CLI), prompting before each install step.

---

## Install

**macOS / Linux**

```bash
curl -fsSL 'https://raw.githubusercontent.com/snyk/studio-recipes/main/installer/dist/snyk-studio-install.sh' -o snyk-studio-install.sh
bash ./snyk-studio-install.sh
```

**Windows**

```bat
powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/snyk/studio-recipes/main/installer/dist/snyk-studio-install.ps1' -OutFile snyk-studio-install.ps1"
powershell -ExecutionPolicy Bypass -File .\snyk-studio-install.ps1
```

After install, the script automatically verifies that files landed correctly and merged config or hook entries still contain the expected Snyk entries.

## Authenticate

Once installed, authenticate the Snyk CLI so the recipes can scan:

```bash
snyk auth
```

For non-interactive setups (CI, containers, shared workstations), set the `SNYK_TOKEN` environment variable from your [Snyk account](https://app.snyk.io/account).

---

## Profiles

| Profile | What gets installed |
|---|---|
| **default** *(used if `--profile` is omitted)* | Secure at Inception guardrails, on-demand fix commands (`/snyk-fix`, `/snyk-batch-fix`), secure dependency health-check skill, and MCP configuration. |
| **minimal** | Secure at Inception guardrails and MCP configuration only |
| **experimental** *(early access)* | [Secure at **Commit**](../guardrail_directives/secure_at_commit/) (SAST + SCA) guardrails, on-demand fix commands (`/snyk-fix`, `/snyk-batch-fix`), secure dependency health-check skill, and MCP configuration — run inside the target repo or pass `--workspace`. |

Choose with `--profile <name>`. [Secrets At Commit](../guardrail_directives/secrets_at_commit/) is opt-in and installs into a target repository. Run the installer inside that repository or pass `--workspace <path>`, and add `--secrets-precommit-hook`.

---

## Common operations

| Goal | Flag |
|---|---|
| Preview without writing files | `--dry-run` |
| Install for one assistant only | `--ade <cursor\|claude\|gemini\|kiro\|codex\|windsurf\|copilot-cli\|copilot-vscode>` |
| Choose the repo for workspace-scoped commit-time hooks | `--workspace <path>` |
| Install the Secrets At Commit hook | `--secrets-precommit-hook` |
| Skip confirmation prompts | `-y`, `--yes` |
| Re-verify a previous install | `--verify` |
| Verify without installing/upgrading prerequisites | `--verify --read-only` |
| Remove what was installed | `--uninstall` (add `--workspace <path>` for workspace-scoped hooks) |
| List available recipes | `--list` |

Examples:

```bash
# Install for whatever the installer detects, default profile, no prompts
bash ./snyk-studio-install.sh -y

# Cursor only, minimal profile
bash ./snyk-studio-install.sh --ade cursor --profile minimal -y

# Preview changes
bash ./snyk-studio-install.sh --dry-run

# Experimental: Secure at Commit into a specific repo
bash ./snyk-studio-install.sh --profile experimental --workspace /path/to/repo -y

# Default profile with Secrets At Commit for a specific repo
bash ./snyk-studio-install.sh --workspace /path/to/repo --secrets-precommit-hook -y

# Cleanly remove assistant-scoped recipes
bash ./snyk-studio-install.sh --uninstall -y

# Remove workspace-scoped hooks from a specific repo too
bash ./snyk-studio-install.sh --workspace /path/to/repo --uninstall -y
```

---

## Diagnostics

If something isn't working, share a diagnostic bundle with your Snyk account team. The bundle captures your environment, installed recipes, assistant versions, and recent Snyk Studio logs — no source files or credentials are included.

**macOS / Linux**

```bash
snyk-studio diag dump
```

**Windows** — the installer does not add `snyk-studio` to PATH. Use the Go binary directly or the Python fallback:

```powershell
# Go binary (if you downloaded it)
.\snyk-studio-windows-x86_64.exe diag dump

# Python fallback (works after any install method)
uv run snyk-studio-installer.py --diag-dump
```

**Python fallback (all platforms)** — if `snyk-studio` is not on PATH, you can always invoke the Python layer directly:

```bash
uv run snyk-studio-installer.py --diag-dump
```

The zip is created in the current directory and the path is printed on completion. Options:

| Flag | Default | Description |
|---|---|---|
| `--out-file <path>` | `snyk-studio-diag-<ts>.zip` in cwd | Write the zip to a specific path |
| `--days N` | `1` | Collect logs from the last N days (minimum 1) |

```bash
snyk-studio diag dump --out-file ~/Desktop/snyk-studio-diag.zip --days 7
```

The zip contains:

| File | Contents |
|---|---|
| `machine_id.txt` | Device ID from `~/.snyk-studio/device-id` |
| `ade_versions.json` | Detected assistants and their versions |
| `dependency_versions.json` | Versions of `node`, `uv`, `snyk`, `nvm` |
| `logs/<ade>/<workspace>/`, `logs/git-hooks/<hook>/<workspace>/` | Snyk Studio ADE and git-hook logs within the collection window |
| `installed_recipes.json` | Snyk-named files found in each assistant's hook/command/rules dirs |
| `env.json` | OS, Python, PATH, and key environment variables |
| `verify.txt` | Output of a `--read-only --verify` run at collection time |

---

## Coverage by assistant

The installer adapts each recipe to the assistant's native mechanism (slash commands, skills, hooks, MCP):

### Tier 1
| Secure At Inception Hooks | Commands and/or skills  |
|---|---|
| ✓ | ✓ |

Codex  
Claude Code  
Cursor  
Gemini  
GitHub Copilot (CLI)  
GitHub Copilot (VS Code)

### Tier 2
| Secure At Inception Hooks | Commands and/or skills  |
|---|---|
| ✗ | ✓ |

Kiro  
Windsurf 

---

## Building the installer

Most teams should use the pre-built installer above. Build from source when you need to:

- **Tailor the bundle to your organization** — pin a custom default profile, add internal recipes, or remove ones you don't need.
- **Audit before deploying** — review the exact installer behavior, then ship the artifact you reviewed.
- **Run in restricted environments** — produce an installer your team can host internally instead of pulling from `raw.githubusercontent.com`.

See [`BUILDING.md`](BUILDING.md) for build instructions.

---

## Need help?

Reach out to your Snyk account team, or open an issue in this repository.
