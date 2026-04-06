# Snyk Secure at Inception -- Claude Code Hooks

Automatically scans for security vulnerabilities as Claude writes code. Runs `snyk code test` in the background, tracks which lines the agent modified, and blocks Claude from finishing if it introduced new vulnerabilities -- prompting it to fix them first.

## Features
- **Session start verification**: Checks Snyk auth and CLI presence on session start; reports issues
via `additionalContext` so Claude can inform the user immediately
- **Cache-warming scan**: Launches a background `snyk code test` at session start to prime Snyk's
internal analysis cache, making subsequent scans faster
- **Background SAST scanning**: Launches `snyk code test` in the background on every file edit/write
-- non-blocking, Claude keeps working
- **New-only filtering**: Tracks which lines the agent modified and filters scan results to only
report vulnerabilities on those lines
- **Automatic fix loop**: When new vulnerabilities are found, Claude is blocked from stopping and
given a detailed vuln table to fix. After fixing, the cycle repeats until clean
- **Per-file state management**: Clean files are removed from tracking; only files with unresolved
vulns stay tracked
- **MCP fallback**: If the CLI scan times out, falls back to prompting Claude to use the
`snyk_code_scan` MCP tool
- **Manifest tracking**: Detects changes to dependency manifests (package.json, requirements.txt,
etc.) and prompts for SCA scanning
- **Loop prevention**: Caps scan-fix cycles at 3 to prevent infinite loops

## Quick Start

**Prerequisites:** Python 3.8+, [Snyk CLI](https://docs.snyk.io/snyk-cli/install-the-snyk-cli) (`npm install -g snyk && snyk auth`), Claude Code with hooks support.

**1. Copy files to your project:**

```bash
mkdir -p .claude/hooks/lib
cp path/to/async_cli_version/snyk_secure_at_inception.py .claude/hooks/
cp path/to/async_cli_version/lib/*.py .claude/hooks/lib/
chmod +x .claude/hooks/snyk_secure_at_inception.py
```

**2. Add to `.claude/settings.json`:**

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/snyk_secure_at_inception.py",
            "statusMessage": "Initializing Snyk security scanning..."
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/snyk_secure_at_inception.py",
            "statusMessage": "Tracking code changes for security scan..."
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/snyk_secure_at_inception.py",
            "statusMessage": "Evaluating security scan results..."
          }
        ]
      }
    ]
  }
}
```

## How It Works

```
Session starts
  → SessionStart hook checks Snyk auth + CLI presence
  → Issues found?   → inject additionalContext warning for Claude
  → All checks pass → launch cache-warming background scan

Claude edits a file
  → PostToolUse hook records which lines changed
  → Peeks at scan.done for cached errors (auth_required, snyk_not_found)
  → Error found? → block immediately with actionable fix instructions
  → No error?   → launch background scan, Claude keeps working (non-blocking)

Claude finishes responding
  → Stop hook waits for scan results
  → Filters to only vulns on lines Claude modified (ignores pre-existing issues)
  → New vulns found?  → block with fix instructions (repeats up to 3 cycles)
  → No new vulns?     → pass silently
  → Scan failed?      → fall back to MCP snyk_code_scan prompt
```

The cache-warming scan launched at session start primes Snyk's internal analysis cache. When the first file edit triggers a PostToolUse scan, Snyk can reuse cached analysis results for unchanged files, making the scan faster.

Changes to dependency manifests (package.json, requirements.txt, etc.) trigger a prompt to run `snyk_sca_scan`.

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `CLAUDE_HOOK_DEBUG` env var | `0` | Set to `1` for verbose stderr logging |
| `MAX_STOP_CYCLES` | `3` | Max fix cycles before allowing stop |
| `SCAN_WAIT_TIMEOUT` | `90s` | How long the Stop hook waits for a scan |

## Files

```
.claude/hooks/
├── snyk_secure_at_inception.py   # Entry point, line tracking, vuln filtering
└── lib/
    ├── platform_utils.py         # Cross-platform abstractions (Windows/Unix)
    ├── scan_runner.py            # Scan lifecycle, SARIF parsing
    └── scan_worker.py            # Background subprocess
```

State is kept in `{tempdir}/claude-sai-{hash}/` (not in your project). To reset: delete that directory.

## Troubleshooting

**Snyk CLI not found** -- `npm install -g snyk && snyk auth`

**Scan always times out** -- Check `{tempdir}/claude-sai-{hash}/scan.log`. Find your path with:

```bash
python3 -c "import hashlib,os,tempfile; h=hashlib.sha256(os.getcwd().encode()).hexdigest()[:8]; print(f'{tempfile.gettempdir()}/claude-sai-{h}')"
```

**Hook not firing** -- Verify `.claude/settings.json` has the hook config, script is executable, and hooks are enabled in Claude Code's `/hooks` menu.

**Debug mode** -- `export CLAUDE_HOOK_DEBUG=1` before starting a session.

## Windows Installation / Compatibility

The hook scripts use a cross-platform `lib/platform_utils.py` module that handles OS differences automatically. The Python code works on Windows without modification. However, the **hook command** in `settings.json` and the **installation steps** need adjusting.

### Installation on Windows

**1. Copy files to your project:**

```powershell
mkdir -Force .claude\hooks\lib
copy path\to\async_cli_version\snyk_secure_at_inception.py .claude\hooks\
copy path\to\async_cli_version\lib\*.py .claude\hooks\lib\
```

Note: `chmod +x` is not needed on Windows -- executability is determined by file extension.

### Hook command in `settings.json`

The Unix hook command uses `python3` and `$HOME`, which may not work on Windows. Use one of these alternatives depending on your Python installation:

**Option A -- Using `py` launcher (recommended, ships with Python for Windows):**

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "py -3 \"%USERPROFILE%\\.claude\\hooks\\snyk_secure_at_inception.py\""
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "py -3 \"%USERPROFILE%\\.claude\\hooks\\snyk_secure_at_inception.py\""
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "py -3 \"%USERPROFILE%\\.claude\\hooks\\snyk_secure_at_inception.py\""
          }
        ]
      }
    ]
  }
}
```

**Option B -- Using `python` directly (if `python` points to Python 3 on your PATH):**

Replace `py -3` with `python` in the commands above.


### Snyk CLI on Windows

The Snyk CLI can be installed via any of these methods:

- **npm**: `npm install -g snyk` (installs as `snyk.cmd`)
- **Scoop**: `scoop install snyk`
- **Chocolatey**: `choco install snyk`
- **Standalone**: Download from [snyk.io/download](https://snyk.io/download)

After installing, authenticate with `snyk auth`.
