# Snyk Secure at Inception -- Codex CLI Hooks

Automatically scans for security vulnerabilities as Codex writes code. Runs `snyk code test` in the background, tracks which lines the agent modified (including via `apply_patch` envelopes), and blocks Codex from finishing if it introduced new vulnerabilities -- prompting it to fix them first.

> **Status:** Codex hooks are an experimental feature. Behaviour and field names may shift as Codex evolves. See <https://developers.openai.com/codex/hooks>.

## Features
- **Session start verification**: Checks Snyk auth and CLI presence on session start; reports issues
via `additionalContext` so Codex can inform the user immediately
- **Cache-warming scan**: Launches a background `snyk code test` at session start to prime Snyk's
internal analysis cache, making subsequent scans faster
- **Background SAST scanning**: Launches `snyk code test` in the background after every file
edit -- non-blocking, Codex keeps working
- **`apply_patch` aware**: Parses Codex's apply_patch envelope so per-file modified-line tracking
works on the same envelopes Codex actually emits
- **New-only filtering**: Tracks which lines the agent modified and filters scan results to only
report vulnerabilities on those lines
- **Automatic fix loop**: When new vulnerabilities are found, Codex is blocked from stopping and
given a detailed vuln table to fix. After fixing, the cycle repeats until clean
- **Per-file state management**: Clean files are removed from tracking; only files with unresolved
vulns stay tracked
- **MCP fallback**: If the CLI scan times out or fails, falls back to prompting Codex to use the
`snyk_code_scan` MCP tool
- **Manifest tracking**: Detects changes to dependency manifests (package.json, requirements.txt,
etc.) and prompts for SCA scanning
- **Loop prevention**: Caps scan-fix cycles at 3 to prevent infinite loops

## Quick Start

**Prerequisites:** Python 3.8+, [Snyk CLI](https://docs.snyk.io/snyk-cli/install-the-snyk-cli) (`npm install -g snyk && snyk auth`), Codex CLI with hooks support.

**1. Copy files to your home directory:**

```bash
mkdir -p ~/.codex/hooks/lib
cp path/to/async_cli_version/snyk_secure_at_inception.py ~/.codex/hooks/
cp path/to/async_cli_version/lib/*.py ~/.codex/hooks/lib/
chmod +x ~/.codex/hooks/snyk_secure_at_inception.py
```

For project-scoped install, replace `~/.codex/hooks/` with `<repo>/.codex/hooks/` and run `codex trust` on the workspace before starting a session -- Codex only loads project-level configs from trusted workspaces.

**2. Merge `config.toml` into `~/.codex/config.toml`:**

```toml
[features]
codex_hooks = true

[[hooks.SessionStart]]

[[hooks.SessionStart.hooks]]
type = "command"
command = 'python3 "$HOME/.codex/hooks/snyk_secure_at_inception.py"'
statusMessage = "Initializing Snyk security scanning..."

[[hooks.PostToolUse]]
matcher = "^(apply_patch|Edit|Write)$"

[[hooks.PostToolUse.hooks]]
type = "command"
command = 'python3 "$HOME/.codex/hooks/snyk_secure_at_inception.py"'
statusMessage = "Tracking code changes for security scan..."

[[hooks.Stop]]

[[hooks.Stop.hooks]]
type = "command"
command = 'python3 "$HOME/.codex/hooks/snyk_secure_at_inception.py"'
statusMessage = "Evaluating security scan results..."
```

**3. Verify the feature flag.** Without `[features] codex_hooks = true` in the same file, Codex silently ignores the hook section. Restart Codex / start a fresh session afterwards.

## How It Works

```
Session starts
  → SessionStart hook checks Snyk auth + CLI presence
  → Issues found?   → inject additionalContext warning for Codex
  → All checks pass → launch cache-warming background scan

Codex emits apply_patch (or Edit / Write)
  → PostToolUse hook parses the envelope and records which lines changed
  → Peeks at scan.done for cached errors (auth_required, snyk_not_found)
  → Error found? → block immediately with actionable fix instructions
  → No error?   → launch background scan, Codex keeps working (non-blocking)

Codex finishes responding
  → Stop hook waits for scan results
  → Filters to only vulns on lines Codex modified (ignores pre-existing issues)
  → New vulns found?  → block with fix instructions (repeats up to 3 cycles)
  → No new vulns?     → pass silently
  → Scan failed?      → fall back to MCP snyk_code_scan prompt
```

The cache-warming scan launched at session start primes Snyk's internal analysis cache. When the first apply_patch triggers a PostToolUse scan, Snyk can reuse cached analysis results for unchanged files, making the scan faster.

Changes to dependency manifests (package.json, requirements.txt, etc.) trigger a prompt to run `snyk_sca_scan`.

### `apply_patch` parsing

Codex's `apply_patch` tool ships changes as an envelope of the form `*** Begin Patch ... *** End Patch` containing one of `*** Add File: <path>`, `*** Update File: <path>`, or `*** Delete File: <path>` per file. The hook:

- **Add File** -> treats every line of the new content as agent-modified.
- **Update File** -> extracts contiguous `+` runs and locates them in the post-edit file to compute precise modified line ranges.
- **Delete File** -> ignored (nothing to scan).
- **Move to:** -> tracks the destination path for the surrounding update.

If the envelope can't be parsed cleanly (e.g., whitespace drift between the patch and the on-disk file), the hook falls back to treating the whole file as modified. This errs toward catching more rather than fewer vulnerabilities.

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `CODEX_HOOK_DEBUG` env var | `0` | Set to `1` for verbose stderr logging |
| `MAX_STOP_CYCLES` | `3` | Max fix cycles before allowing stop |
| `SCAN_WAIT_TIMEOUT` | `90s` | How long the Stop hook waits for a scan |

## Files

```
~/.codex/hooks/
├── snyk_secure_at_inception.py   # Entry point, line tracking, vuln filtering
└── lib/
    ├── platform_utils.py         # Cross-platform abstractions (Windows/Unix)
    ├── scan_runner.py            # Scan lifecycle, SARIF parsing
    └── scan_worker.py            # Background subprocess
```

State is kept in `{tempdir}/codex-sai-{hash}/` (not in your project). To reset: delete that directory.

## Troubleshooting

**Hooks never fire** -- Confirm `[features] codex_hooks = true` is present in the same `config.toml`. Without it, Codex parses the `[[hooks.*]]` blocks but does nothing with them.

**Project-level config ignored** -- Codex only loads `<repo>/.codex/` configs from trusted workspaces. Run `codex trust` once on the project, then start a new session.

**Snyk CLI not found** -- `npm install -g snyk && snyk auth`.

**Scan always times out** -- Check `{tempdir}/codex-sai-{hash}/scan.log`. Find your path with:

```bash
python3 -c "import hashlib,os,tempfile; h=hashlib.sha256(os.getcwd().encode()).hexdigest()[:8]; print(f'{tempfile.gettempdir()}/codex-sai-{h}')"
```

**apply_patch envelope not recognized** -- Set `CODEX_HOOK_DEBUG=1` and look for the `apply_patch with no recoverable envelope` line; it dumps the keys present on `tool_input`. The hook accepts the envelope under `input`, `patch`, `patch_text`, `command`, or `arguments`, and falls back to scanning all string values for the `*** Begin Patch` marker. If your Codex build uses a different shape, file an issue with the tool_input dump.

**Debug mode** -- `export CODEX_HOOK_DEBUG=1` before starting a session.

## Windows Installation / Compatibility

The hook scripts use a cross-platform `lib/platform_utils.py` module that handles OS differences automatically. The Python code works on Windows without modification. Only the **hook command** in `config.toml` needs adjusting.

### Installation on Windows

```powershell
mkdir -Force $HOME\.codex\hooks\lib
copy path\to\async_cli_version\snyk_secure_at_inception.py $HOME\.codex\hooks\
copy path\to\async_cli_version\lib\*.py $HOME\.codex\hooks\lib\
```

### Hook command in `config.toml`

The Unix command uses `python3` and `$HOME`, which may not work on Windows. Use the `py` launcher instead:

```toml
[[hooks.SessionStart.hooks]]
type = "command"
command = 'py -3 "%USERPROFILE%\\.codex\\hooks\\snyk_secure_at_inception.py"'

[[hooks.PostToolUse.hooks]]
type = "command"
command = 'py -3 "%USERPROFILE%\\.codex\\hooks\\snyk_secure_at_inception.py"'

[[hooks.Stop.hooks]]
type = "command"
command = 'py -3 "%USERPROFILE%\\.codex\\hooks\\snyk_secure_at_inception.py"'
```

### Snyk CLI on Windows

The Snyk CLI can be installed via any of these methods:

- **npm**: `npm install -g snyk` (installs as `snyk.cmd`)
- **Scoop**: `scoop install snyk`
- **Chocolatey**: `choco install snyk`
- **Standalone**: Download from [snyk.io/download](https://snyk.io/download)

After installing, authenticate with `snyk auth`.
