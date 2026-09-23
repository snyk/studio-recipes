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
- **Graceful degradation**: A scan that can't run no longer hands the work to the Snyk MCP tools
-- the MCP server *is* the Snyk CLI (`snyk mcp -t stdio`), so it would re-run the same binary that
just failed, in the user's chat context, at the user's token expense. Instead the stop is allowed,
the user gets a one-line warning, and the scan is retried on the next Stop
- **Auth recovery**: Authentication is the one exception worth interrupting for -- it repairs the
configstore every later scan reads -- so an unauthenticated scan blocks **once per session** with
an auth-only prompt. The prompt hands `snyk auth` to the user rather than naming an MCP tool:
`snyk auth` is an interactive browser flow, so neither the hook nor the agent can complete it.
Everything scanning-related stays in the background
- **Manifest tracking**: Detects changes to dependency manifests (package.json, requirements.txt,
etc.) and runs a background SCA scan
- **Loop prevention**: Caps scan-fix cycles at 3 to prevent infinite loops. A failed scan does not
consume a cycle

## Quick Start

**Prerequisites:** [uv](https://docs.astral.sh/uv/getting-started/installation/) (`curl -LsSf https://astral.sh/uv/install.sh | sh`), [Snyk CLI](https://docs.snyk.io/snyk-cli/install-the-snyk-cli) (`npm install -g snyk && snyk auth`), Claude Code with hooks support.

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
            "command": "uv run \"$HOME/.claude/hooks/snyk_secure_at_inception.py\"",
            "statusMessage": "Initializing Snyk security scanning..."
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Edit|Write|Bash",
        "hooks": [
          {
            "type": "command",
            "command": "uv run \"$HOME/.claude/hooks/snyk_secure_at_inception.py\"",
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
            "command": "uv run \"$HOME/.claude/hooks/snyk_secure_at_inception.py\"",
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
  → New vulns found?   → block with fix instructions (repeats up to 3 cycles)
  → No new vulns?      → pass silently
  → Not authenticated? → block once per session: tell the user to run `snyk auth`
  → Scan failed?       → allow the stop, warn the user via systemMessage,
                         clear the stale result so the next Stop re-scans
```

The failure path deliberately trades guarantee for experience: the agent may finish a turn whose
code was never scanned. The CLI has already spent up to 3 network retries plus one auth retry
before Stop ever sees a failure, and re-running the same binary through MCP in the chat window
costs the user time, tokens, and context for a scan that will usually fail the same way.

A repeatedly failing scan keeps warning and keeps re-arming; nothing switches scanning off for
the session. Giving up after N expensive failures is deliberately **not** implemented here --
classifying a failure as expensive by its error code proved brittle, and the replacement measures
actual CLI duration. See `design-docs/secure-at-inception-retire-mcp-fallback.md` for that design;
the Go extension is its intended home. The cases that would stall worst are already cheap:
`auth_required` and `snyk_not_found` are planted as a finished `scan.done` at SessionStart, and
the Stop hook returns from a finished result immediately rather than waiting.

The cache-warming scan launched at session start primes Snyk's internal analysis cache. When the first file edit triggers a PostToolUse scan, Snyk can reuse cached analysis results for unchanged files, making the scan faster.

Changes to dependency manifests (package.json, requirements.txt, etc.) trigger a background `snyk test`, diffed against the session-start baseline so only newly introduced dependency vulns block.

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `CLAUDE_HOOK_DEBUG` env var | `0` | Set to `1` for verbose stderr logging |
| `MAX_STOP_CYCLES` | `3` | Max fix cycles before allowing stop |
| `SCAN_WAIT_TIMEOUT` | `90s` | How long the Stop hook waits for a scan |
| `SAI_MIN_BLOCK_SEVERITY` env var | `medium` | Lowest dependency severity that blocks |

## Files

```
.claude/hooks/
├── snyk_secure_at_inception.py   # Entry point, line tracking, vuln filtering
└── lib/
    ├── platform_utils.py         # Cross-platform abstractions, CLI retry/error classification
    ├── scan_runner.py            # Scan lifecycle, SARIF parsing, manifest hashing
    ├── scan_worker.py            # Background SAST subprocess (snyk code test)
    └── sca_scan_worker.py        # Background SCA subprocess (snyk test)
```

State is kept in `{tempdir}/claude-sai-{hash}/` (not in your project). To reset: delete that directory.

## Troubleshooting

**Snyk CLI not found** -- `npm install -g snyk && snyk auth`

**Scan always times out** -- Check the persistent log at
`~/.snyk-studio/ades/claude/ws/<workspace-name>/log.txt`. Scan state (PID and result files) lives
separately under a temp dir; find it with:

```bash
python3 -c "import hashlib,os,tempfile; h=hashlib.sha256(os.getcwd().encode()).hexdigest()[:8]; print(f'{tempfile.gettempdir()}/claude-sai-{h}')"
```

**Hook not firing** -- Verify `.claude/settings.json` has the hook config, script is executable, and hooks are enabled in Claude Code's `/hooks` menu.

**Debug mode** -- `export CLAUDE_HOOK_DEBUG=1` before starting a session.

## Windows Installation / Compatibility

The hook scripts use a cross-platform `lib/platform_utils.py` module, so the Python code itself works on Windows without modification.

### Installation on Windows

**1. Copy files to your project:**

```powershell
mkdir -Force .claude\hooks\lib
copy path\to\async_cli_version\snyk_secure_at_inception.py .claude\hooks\
copy path\to\async_cli_version\lib\*.py .claude\hooks\lib\
```

### Snyk CLI on Windows

The Snyk CLI can be installed via any of these methods:

- **npm**: `npm install -g snyk` (installs as `snyk.cmd`)
- **Scoop**: `scoop install snyk`
- **Chocolatey**: `choco install snyk`
- **Standalone**: Download from [snyk.io/download](https://snyk.io/download)

After installing, authenticate with `snyk auth`.
