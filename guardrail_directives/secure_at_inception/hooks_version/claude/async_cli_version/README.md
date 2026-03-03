# Snyk Secure at Inception -- Claude Code Hooks

Automatically scans for security vulnerabilities as Claude writes code. Runs `snyk code test` in the background, tracks which lines the agent modified, and blocks Claude from finishing if it introduced new vulnerabilities -- prompting it to fix them first.

## Features
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
    "PostToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/snyk_secure_at_inception.py"
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/snyk_secure_at_inception.py"
          }
        ]
      }
    ]
  }
}
```

## How It Works

```
Claude edits a file
  → PostToolUse hook records which lines changed, launches background scan
  → Claude keeps working (non-blocking)

Claude finishes responding
  → Stop hook waits for scan results
  → Filters to only vulns on lines Claude modified (ignores pre-existing issues)
  → New vulns found?  → block with fix instructions (repeats up to 3 cycles)
  → No new vulns?     → pass silently
  → Scan failed?      → fall back to MCP snyk_code_scan prompt
```

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
