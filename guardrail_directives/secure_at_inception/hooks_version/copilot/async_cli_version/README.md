# Snyk Secure at Inception -- GitHub Copilot Hooks

Automatically scans for security vulnerabilities as Copilot writes code. Runs `snyk code test` in the background, tracks which lines the agent modified, and blocks Copilot from finishing the turn if it introduced new vulnerabilities -- prompting it to fix them first.

Applies to both **GitHub Copilot CLI** and **GitHub Copilot in VS Code** -- both surfaces read hooks from `~/.copilot/`, so a single install covers both.

## Features
- **Background SAST scanning**: Launches `snyk code test` in the background on every file edit/create -- non-blocking, Copilot keeps working
- **New-only filtering**: Tracks which lines the agent modified and filters scan results to only report vulnerabilities on those lines
- **Automatic fix loop**: When new vulnerabilities are found at session end, Copilot is blocked from stopping and given a detailed vuln table to fix. After fixing, the cycle repeats until clean
- **Per-file state management**: Clean files are removed from tracking; only files with unresolved vulns stay tracked
- **MCP fallback**: If the CLI scan fails, times out, or auth is missing, the block message prompts Copilot to use the `snyk_auth` / `snyk_code_scan` MCP tools (and `snyk_sca_scan` when manifests changed)
- **Manifest tracking**: Detects changes to dependency manifests (package.json, requirements.txt, etc.) and includes SCA findings in the block reason
- **Stale scan detection**: Re-scans automatically if edits happen after the running scan started
- **Loop prevention**: Caps scan-fix cycles at 3 to prevent infinite loops

## Quick Start

**Prerequisites:** [uv](https://docs.astral.sh/uv/getting-started/installation/) (`curl -LsSf https://astral.sh/uv/install.sh | sh`), [Snyk CLI](https://docs.snyk.io/snyk-cli/install-the-snyk-cli) (`npm install -g snyk && snyk auth`), GitHub Copilot CLI or Copilot in VS Code with hooks support.

**1. Copy files:**

```bash
mkdir -p ~/.copilot/hooks/lib
cp path/to/async_cli_version/snyk_secure_at_inception.py ~/.copilot/hooks/
cp path/to/async_cli_version/lib/*.py ~/.copilot/hooks/lib/
chmod +x ~/.copilot/hooks/snyk_secure_at_inception.py
```

**2. Merge `hooks.json` into `~/.copilot/hooks.json`:**

```json
{
  "version": 1,
  "hooks": {
    "sessionStart": [
      {
        "type": "command",
        "bash": "uv run \"$HOME/.copilot/hooks/snyk_secure_at_inception.py\" sessionStart",
        "timeoutSec": 10
      }
    ],
    "postToolUse": [
      {
        "type": "command",
        "bash": "uv run \"$HOME/.copilot/hooks/snyk_secure_at_inception.py\" postToolUse",
        "timeoutSec": 10
      }
    ],
    "agentStop": [
      {
        "type": "command",
        "bash": "uv run \"$HOME/.copilot/hooks/snyk_secure_at_inception.py\" agentStop",
        "timeoutSec": 120
      }
    ]
  }
}
```



## How It Works

```
Session starts (sessionStart)
  -> Check Snyk auth + CLI; write early status if missing
  -> Launch cache-warming SAST + SCA scans
  -> Snapshot manifest hashes for hash-diff SCA triggering at agentStop
  -> On source=startup|new, clear stale state from any prior session

Copilot edits a file (postToolUse)
  -> Track which lines changed
  -> Lazily run sessionStart init if it hasn't run yet (resume / -p / hook bugs)
  -> Peek at scan.done for cached errors (auth_required, snyk_not_found)
     -> Error?  -> block immediately with actionable fix instructions
     -> No error -> launch background scan, Copilot keeps working

Copilot finishes the turn (agentStop)
  -> Wait for scan results
  -> Filter to only vulns on lines Copilot modified (ignores pre-existing issues)
  -> New vulns? -> block with fix instructions (repeats up to 3 cycles)
  -> No new vulns? -> pass silently
  -> Scan failed? -> fall back to MCP snyk_code_scan prompt
```

Changes to dependency manifests (package.json, requirements.txt, etc.) trigger a new SCA scan, with results included in the block reason.

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `COPILOT_HOOK_DEBUG` env var | `0` | Set to `1` for verbose stderr logging |
| `MAX_STOP_CYCLES` | `3` | Max fix cycles before allowing stop |
| `SCAN_WAIT_TIMEOUT` | `90s` | How long agentStop waits for a scan |
| `SAI_MIN_BLOCK_SEVERITY` | `medium` | Minimum SCA severity that triggers a block (`critical`/`high`/`medium`/`low`) |

## Files

```
~/.copilot/hooks/
├── snyk_secure_at_inception.py   # Entry point, line tracking, vuln filtering
└── lib/
    ├── platform_utils.py         # Cross-platform abstractions
    ├── scan_runner.py            # Scan lifecycle, SARIF parsing
    ├── scan_worker.py            # Background SAST subprocess
    └── sca_scan_worker.py        # Background SCA subprocess
```

State is kept in `{tempdir}/copilot-sai-{hash}/` (not in your project). To reset: delete that directory.

## Troubleshooting

**Snyk CLI not found** -- `npm install -g snyk && snyk auth`

**Hook not firing** -- Verify `~/.copilot/hooks.json` exists, the script is executable, and hooks are enabled in your Copilot version. In particular, confirm the `bash` command in `hooks.json` ends with the event name (`postToolUse` or `agentStop`) -- without that argv, the script no-ops.

**Scan always times out** -- Check `{tempdir}/copilot-sai-{hash}/scan.log`. Find your path with:

```bash
python3 -c "import hashlib,os,tempfile; h=hashlib.sha256(os.getcwd().encode()).hexdigest()[:8]; print(f'{tempfile.gettempdir()}/copilot-sai-{h}')"
```

**Debug mode** -- `export COPILOT_HOOK_DEBUG=1` before starting a session.

## Windows Installation

The Python code is cross-platform; only the hook command needs adjusting.

**1. Copy files:**

```powershell
mkdir -Force $env:USERPROFILE\.copilot\hooks\lib
copy path\to\async_cli_version\snyk_secure_at_inception.py $env:USERPROFILE\.copilot\hooks\
copy path\to\async_cli_version\lib\*.py $env:USERPROFILE\.copilot\hooks\lib\
```

**2. Hook command in `hooks.json` (Windows):**

```json
{
  "version": 1,
  "hooks": {
    "sessionStart": [
      {
        "type": "command",
        "bash": "uv run \"%USERPROFILE%\\.copilot\\hooks\\snyk_secure_at_inception.py\" sessionStart",
        "timeoutSec": 10
      }
    ],
    "postToolUse": [
      {
        "type": "command",
        "bash": "uv run \"%USERPROFILE%\\.copilot\\hooks\\snyk_secure_at_inception.py\" postToolUse",
        "timeoutSec": 10
      }
    ],
    "agentStop": [
      {
        "type": "command",
        "bash": "uv run \"%USERPROFILE%\\.copilot\\hooks\\snyk_secure_at_inception.py\" agentStop",
        "timeoutSec": 120
      }
    ]
  }
}
```

Replace `uv run` with `py -3` if you are not using uv.
