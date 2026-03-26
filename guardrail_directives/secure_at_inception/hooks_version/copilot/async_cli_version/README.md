# Snyk Secure at Inception -- GitHub Copilot Hooks

Automatically scans for security vulnerabilities as the Copilot agent writes code. Runs `snyk code test` in the background, tracks which lines the agent modified, and gates git commit/push operations if new vulnerabilities were introduced -- giving the user the choice to fix or proceed.

## Features
- **Background SAST scanning**: Launches `snyk code test` in the background on file edit/create when the Snyk CLI is authenticated—non-blocking at edit time; the agent keeps working
- **New-only filtering**: Tracks which lines the agent modified and filters scan results to only report vulnerabilities on those lines
- **Early bash notification**: On non-git `bash` tool calls, peeks at a completed scan and **denies once** per vulnerability set with `/snyk-batch-fix` and the original command to re-run after fixes (subsequent bash with the same result set is allowed)
- **Notify-then-allow on git**: On the first gated git operation with vulns, denies with a detailed table; the user can fix or **retry the same commit** to proceed anyway
- **Git operation gating**: Enforces at commit/push/PR time via `preToolUse` (`git commit`, `git push`, `gh pr create`, `gh pr merge`)
- **Per-file state management**: Clean files are removed from tracking; only files with unresolved vulns stay tracked
- **MCP fallback**: If the CLI scan fails, is missing, or auth is missing, git operations are denied with instructions to use `snyk_auth` / `snyk_code_scan` (and `snyk_sca_scan` when manifests changed)
- **Manifest tracking**: Detects changes to dependency manifests (package.json, requirements.txt, etc.) and surfaces SCA guidance on deny paths
- **Stale scan detection**: Re-scans automatically if edits happen after the running scan started

## Quick Start

**Prerequisites:** Python 3.8+, [Snyk CLI](https://docs.snyk.io/snyk-cli/install-the-snyk-cli) (`npm install -g snyk && snyk auth`), GitHub Copilot with hooks support.

**1. Copy files to your project:**

```bash
mkdir -p .github/hooks/lib
cp path/to/async_cli_version/snyk_secure_at_inception.py .github/hooks/
cp path/to/async_cli_version/lib/*.py .github/hooks/lib/
chmod +x .github/hooks/snyk_secure_at_inception.py
```

**2. Add hook config to `.github/hooks/hooks.json`:**

```json
{
  "version": 1,
  "hooks": {
    "postToolUse": [
      {
        "type": "command",
        "bash": "python3 .github/hooks/snyk_secure_at_inception.py",
        "timeoutSec": 10
      }
    ],
    "preToolUse": [
      {
        "type": "command",
        "bash": "python3 .github/hooks/snyk_secure_at_inception.py",
        "timeoutSec": 30
      }
    ],
    "agentStop": [
      {
        "type": "command",
        "bash": "python3 .github/hooks/snyk_secure_at_inception.py",
        "timeoutSec": 5
      }
    ]
  }
}
```

## Authentication (Snyk CLI)

- **Before a background scan** (`postToolUse` on code edits), the hook calls `check_snyk_auth()`. If the CLI is **not** authenticated (no API key / OAuth token in the usual config), it **skips** launching `snyk code test`, writes an `auth_required` status for later hooks, and logs to stderr. **Edits are not blocked** at this stage.
- **Git VCS `preToolUse`**: If a scan never completed successfully because of **auth** (or other failure), the hook **denies** the commit/push/PR with text that tells the agent to run **`snyk_auth`** (MCP), then **`snyk_code_scan`** on the workspace (and **`snyk_sca_scan`** if dependency manifests changed). Clear state is reset so a follow-up attempt can succeed after auth.
- **Non-git bash** early notification only runs when `scan.done` reports **`success`**; if you are not authenticated, there is no successful scan, so you will not get the early `/snyk-batch-fix` interrupt on arbitrary bash—only the git path (or fixing auth and scanning) applies.

**Prerequisite:** `npm install -g snyk` and `snyk auth` (or equivalent OAuth) so background scans run.

## How It Works

```
Agent edits a file
  -> postToolUse: track lines; if Snyk authenticated -> launch background scan
     If not authenticated -> skip scan, record auth_required (still non-blocking)

Agent runs a non-git bash command
  -> preToolUse: if scan finished successfully and new vulns on modified lines:
     first time for this vuln set -> deny with /snyk-batch-fix + re-run hint (interrupts that bash)
     same vuln set again -> allow (already notified)

Agent runs git commit / git push / gh pr create / gh pr merge
  -> preToolUse: wait up to ~25s for scan (see Configuration)
  -> Filters to vulns on lines the agent modified
  -> New vulns or manifest-only pending work? -> deny with /snyk-batch-fix; retry same op to proceed
  -> Scan still running (timeout)? -> deny: wait and retry commit
  -> auth_required / CLI missing / other scan failure? -> deny with MCP snyk_auth + snyk_code_scan (+ SCA if needed)

Agent finishes responding
  -> agentStop: audit log only (output ignored by Copilot — does not block or prompt)
```

Changes to dependency manifests are included in denial reasons and MCP fallback text for **`snyk_sca_scan`**.

## Enforcement Model

Unlike Claude Code and Cursor, which can block at session end (`Stop`/`stop`), Copilot **ignores `agentStop` hook output**. Enforcement is **`preToolUse` on `bash` only**:

| Situation | What happens |
|-----------|----------------|
| First **non-git** bash after vulns appear (successful scan) | That bash call is **denied** once with `/snyk-batch-fix` and the command to re-run later |
| Later non-git bash, same vuln fingerprint | **Allowed** (already notified) |
| First **git** op with new vulns or pending manifests | **Denied** with `/snyk-batch-fix` (+ SCA section if needed) |
| **Retry** same git op without fixing (same vuln fingerprint) | **Allowed** (notify-then-allow) |
| Commit after fixing / clean scan | **Allowed**; stale edits trigger re-scan |
| Scan **timeout** on git op | **Denied**: “wait and retry” (scan still in progress) |
| **Not authenticated** / scan failed on git op | **Denied** with MCP `snyk_auth` + `snyk_code_scan` (+ `snyk_sca_scan` if manifests changed) |

This keeps insecure code out of version control unless the user explicitly retries after seeing the denial.

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `COPILOT_HOOK_DEBUG` env var | `0` | Set to `1` for verbose stderr logging |
| `PRE_TOOL_SCAN_WAIT_TIMEOUT` | `25s` | How long preToolUse waits for a scan |

## Files

```
.github/hooks/
├── hooks.json                       # Hook configuration
├── snyk_secure_at_inception.py      # Entry point, line tracking, vuln filtering
└── lib/
    ├── scan_runner.py               # Scan lifecycle, SARIF parsing
    └── scan_worker.py               # Background subprocess
```

State is kept in `{tempdir}/copilot-sai-{hash}/` (not in your project). To reset: delete that directory.

## Troubleshooting

**Snyk CLI not found** — `npm install -g snyk && snyk auth`

**Not authenticated / git ops denied with snyk_auth** — Run `snyk auth` in a terminal (or complete OAuth in the CLI). Until then, background scans are skipped and git operations with pending changes are denied with MCP instructions instead of a SARIF-based result.

**Scan always times out** -- Check `{tempdir}/copilot-sai-{hash}/scan.log`. Find your path with:

```bash
python3 -c "import hashlib,os,tempfile; h=hashlib.sha256(os.getcwd().encode()).hexdigest()[:8]; print(f'{tempfile.gettempdir()}/copilot-sai-{h}')"
```

**Hook not firing** -- Verify `.github/hooks/hooks.json` exists on the default branch, script is executable, and hooks are enabled in Copilot.

**Debug mode** -- `export COPILOT_HOOK_DEBUG=1` before starting a session.
