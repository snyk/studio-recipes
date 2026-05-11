# Snyk Secure at Inception -- Gemini Code Hooks

Automatically scans for security vulnerabilities as Gemini writes code. Runs `snyk code test` in the background, tracks which lines the agent modified, and blocks Gemini from finishing if it introduced new vulnerabilities -- prompting it to fix them first.

## Features
- **Session start verification**: Checks Snyk auth and CLI presence on session start; reports issues
via `additionalContext` so Gemini can inform the user immediately
- **Cache-warming scan**: Launches a background `snyk code test` at session start to prime Snyk's
internal analysis cache, making subsequent scans faster
- **Background SAST scanning**: Launches `snyk code test` in the background on every file edit/write
-- non-blocking, Gemini keeps working
- **New-only filtering**: Tracks which lines the agent modified and filters scan results to only
report vulnerabilities on those lines
- **Automatic fix loop**: When new vulnerabilities are found, Gemini is blocked from stopping and
given a detailed vuln table to fix. After fixing, the cycle repeats until clean
- **Per-file state management**: Clean files are removed from tracking; only files with unresolved
vulns stay tracked
- **MCP fallback**: If the CLI scan times out, falls back to prompting Gemini to use the
`snyk_code_scan` MCP tool
- **Manifest tracking**: Detects changes to dependency manifests (package.json, requirements.txt,
etc.) and prompts for SCA scanning
- **Loop prevention**: Caps scan-fix cycles at 3 to prevent infinite loops

## Quick Start

**Prerequisites:** Python 3.8+, [Snyk CLI](https://docs.snyk.io/snyk-cli/install-the-snyk-cli) (`npm install -g snyk && snyk auth`), Gemini Code with hooks support.

**1. Copy files to your project:**

```bash
mkdir -p .gemini/hooks/lib
cp path/to/async_cli_version/snyk_secure_at_inception.py .gemini/hooks/
cp path/to/async_cli_version/lib/*.py .gemini/hooks/lib/
chmod +x .gemini/hooks/snyk_secure_at_inception.py
```

**2. Merge to current `.gemini/settings.json`:**

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "startup",
        "hooks": [
          {
            "name": "snyk_secure_at_inception_session_start",
            "type": "command",
            "command": "uv run $GEMINI_PROJECT_DIR/.gemini/hooks/snyk_secure_at_inception.py >> $GEMINI_PROJECT_DIR/.gemini/hooks/snyk_secure_at_inception.log",
            "description": "Run initial scan on session start"
          }
        ]
      }
    ],
    "AfterTool": [
      {
        "matcher": "write_file|replace",
        "hooks": [
          {
            "name": "snyk_secure_at_inception_after_tool_edit",
            "type": "command",
            "command": "uv run $GEMINI_PROJECT_DIR/.gemini/hooks/snyk_secure_at_inception.py >> $GEMINI_PROJECT_DIR/.gemini/hooks/snyk_secure_at_inception.log",
            "description": "Scans code changes for vulnerabilities using Snyk"
          }
        ]
      }
    ],
    "AfterAgent": [
      {
        "matcher": "*",
        "hooks": [
          {
            "name": "snyk_secure_at_inception_after_agent",
            "type": "command",
            "command": "uv run $GEMINI_PROJECT_DIR/.gemini/hooks/snyk_secure_at_inception.py >> $GEMINI_PROJECT_DIR/.gemini/hooks/snyk_secure_at_inception.log",
            "description": "Scans code changes for vulnerabilities using Snyk",
            "timeout": 300000
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
  → Issues found?   → inject additionalContext warning for Gemini
  → All checks pass → launch cache-warming background scan

Gemini edits a file
  → PostToolUse hook records which lines changed
  → Peeks at scan.done for cached errors (auth_required, snyk_not_found)
  → Error found? → block immediately with actionable fix instructions
  → No error?   → launch background scan, Gemini keeps working (non-blocking)

Gemini finishes responding
  → Stop hook waits for scan results
  → Filters to only vulns on lines Gemini modified (ignores pre-existing issues)
  → New vulns found?  → block with fix instructions (repeats up to 3 cycles)
  → No new vulns?     → pass silently
  → Scan failed?      → fall back to MCP snyk_code_scan prompt
```

The cache-warming scan launched at session start primes Snyk's internal analysis cache. When the first file edit triggers a PostToolUse scan, Snyk can reuse cached analysis results for unchanged files, making the scan faster.

Changes to dependency manifests (package.json, requirements.txt, etc.) trigger a prompt to run `snyk_sca_scan`.

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `GEMINI_HOOK_DEBUG` env var | `0` | Set to `1` for verbose stderr logging |
| `MAX_STOP_CYCLES` | `3` | Max fix cycles before allowing stop |
| `SCAN_WAIT_TIMEOUT` | `90s` | How long the Stop hook waits for a scan |

## Files

```
.gemini/hooks/
├── snyk_secure_at_inception.py   # Entry point, line tracking, vuln filtering
└── lib/
    ├── platform_utils.py         # Cross-platform abstractions (Windows/Unix)
    ├── scan_runner.py            # Scan lifecycle, SARIF parsing
    └── scan_worker.py            # Background subprocess
```

State is kept in `{tempdir}/Gemini-sai-{hash}/` (not in your project). To reset: delete that directory.

## Troubleshooting

**Snyk CLI not found** -- `npm install -g snyk && snyk auth`

**Scan always times out** -- Check `{tempdir}/gemini-sai-{hash}/scan.log`. Find your path with:

```bash
python3 -c "import hashlib,os,tempfile; h=hashlib.sha256(os.getcwd().encode()).hexdigest()[:8]; print(f'{tempfile.gettempdir()}/gemini-sai-{h}')"
```

**Hook not firing** -- Verify `.gemini/settings.json` has the hook config, script is executable, and hooks are enabled in Gemini Code's `/hooks` menu.

**Debug mode** -- `export GEMINI_HOOK_DEBUG=1` before starting a session.

## Windows Installation / Compatibility

The hook scripts use a cross-platform `lib/platform_utils.py` module that handles OS differences automatically. The Python code works on Windows without modification. However, the **hook commands** in `.gemini/settings.json` and the **installation steps** need adjusting for path style and `uv` on `PATH`.

### Installation on Windows

**1. Copy files to your project:**

```powershell
mkdir -Force .gemini\hooks\lib
copy path\to\async_cli_version\snyk_secure_at_inception.py .gemini\hooks\
copy path\to\async_cli_version\lib\*.py .gemini\hooks\lib\
```

Note: `chmod +x` is not needed on Windows — executability is determined by file association.

### Hook commands in `.gemini/settings.json`

On Unix, examples use `uv run` with `$GEMINI_PROJECT_DIR` (install [uv](https://docs.astral.sh/uv/getting-started/installation/) and ensure it is on your `PATH`). On Windows, use `%GEMINI_PROJECT_DIR%` and backslashes for paths inside the command string, as below.

**`uv run` on Windows (aligned with Snyk Studio installer output when paths are normalized):**

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "startup",
        "hooks": [
          {
            "name": "snyk_secure_at_inception_session_start",
            "type": "command",
            "command": "uv run \"%GEMINI_PROJECT_DIR%\\.gemini\\hooks\\snyk_secure_at_inception.py\" >> \"%GEMINI_PROJECT_DIR%\\.gemini\\hooks\\snyk_secure_at_inception.log\""
          }
        ]
      }
    ]
  }
}
```

Repeat the same path pattern for **AfterTool** and **AfterAgent** hooks as in the Unix quick start.

**Using `py -3` instead of `uv run`:** replace the `uv run` prefix with `py -3` if you are not using uv (keep the script path and redirect the same).

### Snyk CLI on Windows

The Snyk CLI can be installed via any of these methods:

- **npm**: `npm install -g snyk` (installs as `snyk.cmd`)
- **Scoop**: `scoop install snyk`
- **Chocolatey**: `choco install snyk`
- **Standalone**: Download from [snyk.io/download](https://snyk.io/download)

After installing, authenticate with `snyk auth`.

