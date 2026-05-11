# Snyk Secure at Inception -- Cursor Hooks

Automatically scans for security vulnerabilities as the agent writes code. Runs `snyk code test` in the background, tracks which lines the agent modified, and blocks the agent from finishing if it introduced new vulnerabilities -- prompting it to fix them first.

## Features
- **Session start verification**: Checks Snyk auth and CLI presence on session start; reports issues
via `followup_message` so the agent can inform the user immediately
- **Cache-warming scan**: Launches a background `snyk code test` at session start to prime Snyk's
internal analysis cache, making subsequent scans faster
- **Background SAST scanning**: Launches `snyk code test` in the background on every file edit
-- non-blocking, the agent keeps working
- **New-only filtering**: Tracks which lines the agent modified and filters scan results to only
report vulnerabilities on those lines
- **Automatic fix loop**: When new vulnerabilities are found, the agent is blocked from stopping and
given a detailed vuln table to fix. After fixing, the cycle repeats until clean
- **Per-file state management**: Clean files are removed from tracking; only files with unresolved
vulns stay tracked
- **MCP fallback**: If the CLI scan times out, falls back to prompting the agent to use the
`snyk_code_scan` MCP tool
- **Manifest tracking**: Detects changes to dependency manifests (package.json, requirements.txt,
etc.) and prompts for SCA scanning
- **Loop prevention**: Caps scan-fix cycles at 3 to prevent infinite loops
- **Stale scan detection**: Re-scans automatically if edits happen after the running scan started

## Quick Start

**Prerequisites:** Python 3.8+, [Snyk CLI](https://docs.snyk.io/snyk-cli/install-the-snyk-cli) (`npm install -g snyk && snyk auth`), Cursor IDE with hooks support.

**1. Copy files to your project:**

```bash
mkdir -p .cursor/hooks/lib
cp path/to/cursor-async/snyk_secure_at_inception.py .cursor/hooks/
cp path/to/cursor-async/lib/*.py .cursor/hooks/lib/
chmod +x .cursor/hooks/snyk_secure_at_inception.py
```

**2. Add to `.cursor/hooks.json`:**

```json
{
  "version": 1,
  "hooks": {
    "sessionStart": [
      {
        "command": "uv run \"$HOME/.cursor/hooks/snyk_secure_at_inception.py\""
      }
    ],
    "afterFileEdit": [
      {
        "command": "uv run \"$HOME/.cursor/hooks/snyk_secure_at_inception.py\""
      }
    ],
    "stop": [
      {
        "command": "uv run \"$HOME/.cursor/hooks/snyk_secure_at_inception.py\""
      }
    ]
  }
}
```

## How It Works

```
Session starts
  → sessionStart hook checks Snyk auth + CLI presence
  → Issues found?   → send followup_message warning the agent
  → All checks pass → launch cache-warming background scan

Agent edits a file
  → afterFileEdit hook records which lines changed
  → Peeks at scan.done for cached errors (auth_required, snyk_not_found)
  → Error found? → block immediately with actionable fix instructions
  → No error?   → launch background scan, agent keeps working (non-blocking)

Agent finishes responding
  → stop hook waits for scan results
  → Filters to only vulns on lines the agent modified (ignores pre-existing issues)
  → New vulns found?  → block with fix instructions (repeats up to 3 cycles)
  → No new vulns?     → pass silently
  → Scan failed?      → fall back to MCP snyk_code_scan prompt
```

The cache-warming scan launched at session start primes Snyk's internal analysis cache. When the first file edit triggers an afterFileEdit scan, Snyk can reuse cached analysis results for unchanged files, making the scan faster.

Changes to dependency manifests (package.json, requirements.txt, etc.) trigger a prompt to run `snyk_sca_scan`.

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `CURSOR_HOOK_DEBUG` env var | `0` | Set to `1` for verbose stderr logging |
| `MAX_STOP_CYCLES` | `3` | Max fix cycles before allowing stop |
| `SCAN_WAIT_TIMEOUT` | `90s` | How long the stop hook waits for a scan |

## Files

```
.cursor/hooks/
├── snyk_secure_at_inception.py   # Entry point, line tracking, vuln filtering
└── lib/
    ├── platform_utils.py         # Cross-platform abstractions (Windows/Unix)
    ├── scan_runner.py            # Scan lifecycle, SARIF parsing
    └── scan_worker.py            # Background subprocess
```

State is kept in `{tempdir}/cursor-sai-{hash}/` (not in your project). To reset: delete that directory.

## Troubleshooting

**Snyk CLI not found** -- `npm install -g snyk && snyk auth`

**Scan always times out** -- Check `{tempdir}/cursor-sai-{hash}/scan.log`. Find your path with:

```bash
python3 -c "import hashlib,os,tempfile; h=hashlib.sha256(os.getcwd().encode()).hexdigest()[:8]; print(f'{tempfile.gettempdir()}/cursor-sai-{h}')"
```

**Hook not firing** -- Verify `.cursor/hooks.json` has the hook config, script is executable, and hooks are enabled in Cursor.

**Debug mode** -- `export CURSOR_HOOK_DEBUG=1` before starting a session.

## Windows Installation / Compatibility

The hook scripts use a cross-platform `lib/platform_utils.py` module that handles OS differences automatically. The Python code works on Windows without modification. However, the **hook command** in `hooks.json` and the **installation steps** need adjusting.

### Installation on Windows

**1. Copy files to your project:**

```powershell
mkdir -Force .cursor\hooks\lib
copy path\to\cursor-async\snyk_secure_at_inception.py .cursor\hooks\
copy path\to\cursor-async\lib\*.py .cursor\hooks\lib\
```

Note: `chmod +x` is not needed on Windows -- executability is determined by file extension.

### Hook command in `hooks.json`

Hook commands use `uv run` with `$HOME` on Unix (install [uv](https://docs.astral.sh/uv/getting-started/installation/) and ensure it is on your PATH). On Windows, use Windows-style paths and `%USERPROFILE%` as in the example below.

**Option A -- `uv run` on Windows (matches installer output):**

```json
{
  "version": 1,
  "hooks": {
    "sessionStart": [
      {
        "command": "uv run \"%USERPROFILE%\\.cursor\\hooks\\snyk_secure_at_inception.py\""
      }
    ],
    "afterFileEdit": [
      {
        "command": "uv run \"%USERPROFILE%\\.cursor\\hooks\\snyk_secure_at_inception.py\""
      }
    ],
    "stop": [
      {
        "command": "uv run \"%USERPROFILE%\\.cursor\\hooks\\snyk_secure_at_inception.py\""
      }
    ]
  }
}
```

**Option B -- Using `py -3` instead of `uv run`:** replace the `uv run` prefix with `py -3` if you are not using uv.


### Snyk CLI on Windows

The Snyk CLI can be installed via any of these methods:

- **npm**: `npm install -g snyk` (installs as `snyk.cmd`)
- **Scoop**: `scoop install snyk`
- **Chocolatey**: `choco install snyk`
- **Standalone**: Download from [snyk.io/download](https://snyk.io/download)

After installing, authenticate with `snyk auth`.
