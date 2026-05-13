# Snyk Studio Recipes — Installer

One command to embed Snyk's [Secure at Inception](https://snyk.io/product/studio/) recipes into your AI coding assistant. The installer detects which assistants you have, installs any missing dependencies (Snyk CLI, Node.js, Python tooling), and merges hooks, slash commands, skills, and MCP configuration into each assistant's user directory.

**Supported assistants:** Cursor • Claude Code • Gemini • Kiro • Windsurf • GitHub Copilot CLI • GitHub Copilot in VS Code

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

After install, the script automatically verifies that files landed correctly and merged config still contains the expected Snyk entries.

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
| **default** *(used if `--profile` is omitted)* | Secure at Inception guardrails, on-demand fix commands (`/snyk-fix`, `/snyk-batch-fix`), secure dependency health-check skill, and MCP configuration |
| **minimal** | Secure at Inception guardrails and MCP configuration only |

Choose with `--profile <name>`.

---

## Common operations

| Goal | Flag |
|---|---|
| Preview without writing files | `--dry-run` |
| Install for one assistant only | `--ade <cursor\|claude\|gemini\|kiro\|windsurf\|copilot-cli\|copilot-vscode>` |
| Skip confirmation prompts | `-y`, `--yes` |
| Re-verify a previous install | `--verify` |
| Remove what was installed | `--uninstall` |
| List available recipes | `--list` |

Examples:

```bash
# Install for whatever the installer detects, default profile, no prompts
bash ./snyk-studio-install.sh -y

# Cursor only, minimal profile
bash ./snyk-studio-install.sh --ade cursor --profile minimal -y

# Preview changes
bash ./snyk-studio-install.sh --dry-run

# Cleanly remove what was installed
bash ./snyk-studio-install.sh --uninstall -y
```

---

## Coverage by assistant

The installer adapts each recipe to the assistant's native mechanism (slash commands, skills, hooks, MCP):

| Assistant | Guardrails | Commands | Skills | MCP |
|---|---|---|---|---|
| Cursor | ✓ | ✓ | ✓ | ✓ |
| Claude Code | ✓ | ✓ | ✓ | ✓ |
| Gemini | ✓ | ✓ | ✓ | ✓ |
| Kiro | — | ✓ | ✓ | ✓ |
| Windsurf | — | ✓ | ✓ | ✓ |
| GitHub Copilot in VS Code | — | ✓ | ✓ | ✓ |
| GitHub Copilot CLI | — | — *(not yet supported by Copilot CLI)* | ✓ | ✓ |

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
