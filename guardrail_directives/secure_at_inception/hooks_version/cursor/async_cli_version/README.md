# Snyk Secure at Inception -- Cursor Hooks

Automatically scans for security vulnerabilities as the agent writes code. Runs `snyk code test` (SAST) and `snyk test` (SCA) in the background, tracks which lines and packages the agent modified, and blocks the agent from finishing if it introduced new vulnerabilities -- prompting it to fix them first.

## Features
- **Background SAST scanning**: Launches `snyk code test` in the background on every file edit 
-- non-blocking, the agent keeps working
- **Background SCA scanning**: Launches `snyk test` in the background when dependency manifests 
change, filters results to only the changed packages
- **New-only filtering**: Tracks which lines the agent modified and filters scan results to only 
report vulnerabilities on those lines
- **Changed-package-only SCA**: Tracks which packages changed (old vs new version) and only 
evaluates those packages in SCA results, applying worse-vulns criteria
- **Automatic fix loop**: When new vulnerabilities are found, the agent is blocked from stopping and 
given a detailed vuln table to fix. After fixing, the cycle repeats until clean
- **Per-file state management**: Clean files are removed from tracking; only files with unresolved 
vulns stay tracked
- **MCP fallback**: If the CLI scan times out or fails, falls back to prompting the agent to use the 
`snyk_code_scan` or `snyk_sca_scan` MCP tools
- **Manifest tracking**: Detects changes to dependency manifests (package.json, requirements.txt, 
etc.) with per-package version tracking
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
    "afterFileEdit": [
      {
        "command": "python3 .cursor/hooks/snyk_secure_at_inception.py"
      }
    ],
    "stop": [
      {
        "command": "python3 .cursor/hooks/snyk_secure_at_inception.py"
      }
    ]
  }
}
```

## How It Works

```
Agent edits a code file
  → afterFileEdit hook records which lines changed, launches background code scan
  → Agent keeps working (non-blocking)

Agent edits a manifest file (package.json, requirements.txt, etc.)
  → afterFileEdit hook records which packages changed (old vs new version)
  → Launches background SCA scan (snyk test)
  → Agent keeps working (non-blocking)

Agent finishes responding
  → stop hook waits for code scan results (up to 30s)
  → Filters to only vulns on lines the agent modified (ignores pre-existing issues)
  → If manifests changed: polls SCA scan (up to 30s)
    → SCA ready?  → filters to changed packages only, applies worse-vulns criteria
    → SCA not ready? → falls back to MCP snyk_sca_scan prompt
  → New vulns found?  → block with fix instructions (repeats up to 3 cycles)
  → No new vulns?     → pass silently
  → Scan failed?      → fall back to MCP snyk_code_scan/snyk_sca_scan prompt
```

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `CURSOR_HOOK_DEBUG` env var | `0` | Set to `1` for verbose stderr logging |
| `MAX_STOP_CYCLES` | `3` | Max fix cycles before allowing stop |
| `SCAN_WAIT_TIMEOUT` | `30s` | How long the stop hook waits for a code scan |
| `SCA_WAIT_TIMEOUT` | `30s` | How long the stop hook waits for an SCA scan before falling back to MCP |

## Files

```
.cursor/hooks/
├── snyk_secure_at_inception.py   # Entry point, line tracking, vuln filtering, SCA evaluation
└── lib/
    ├── scan_runner.py            # Scan lifecycle (code + SCA), SARIF/SCA parsing
    └── scan_worker.py            # Background subprocess (code or SCA mode)
```

State is kept in `{tempdir}/cursor-sai-{hash}/` (not in your project). Scan state files use type prefixes (`code.pid`, `code.done`, `sca.pid`, `sca.done`). To reset: delete that directory.

## Troubleshooting

**Snyk CLI not found** -- `npm install -g snyk && snyk auth`

**Scan always times out** -- Check `{tempdir}/cursor-sai-{hash}/code.log` or `sca.log`. Find your path with:

```bash
python3 -c "import hashlib,os,tempfile; h=hashlib.sha256(os.getcwd().encode()).hexdigest()[:8]; print(f'{tempfile.gettempdir()}/cursor-sai-{h}')"
```

**Hook not firing** -- Verify `.cursor/hooks.json` has the hook config, script is executable, and hooks are enabled in Cursor.

**Debug mode** -- `export CURSOR_HOOK_DEBUG=1` before starting a session.
