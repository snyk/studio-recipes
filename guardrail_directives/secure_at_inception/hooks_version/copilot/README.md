# GitHub Copilot Hooks - Secure At Inception

This directory contains GitHub Copilot hook implementations for Secure At Inception. Hooks provide deterministic enforcement -- they fire at the appropriate lifecycle event regardless of what the AI decided to do during the session.

## Versions

| Version | Scanning Approach | Hook Events | Dependencies |
|---------|------------------|-------------|--------------|
| **[Async CLI](./async_cli_version/)** | Runs `snyk code test` in the background via CLI, filters results to agent-modified lines, blocks the turn from ending until new vulns are fixed | `sessionStart`, `postToolUse`, `agentStop` | Python 3.8+ (via [uv](https://docs.astral.sh/uv/)), Snyk CLI |

## Copilot Hook Architecture

Copilot fires `sessionStart` when an agent session begins, `postToolUse` after each tool call (`bash`, `str_replace_editor`, `write`, etc.), and `agentStop` when the agent tries to end its turn. A hook on `agentStop` that emits `{"decision":"block","reason":"..."}` keeps the turn open and feeds `reason` back to the model as a new prompt.

The Snyk SAI hook uses this to enforce the scan/fix loop:

- `sessionStart` initializes state and snapshots dependency manifest hashes.
- `postToolUse` records which lines the agent modified on each edit and launches a background `snyk code test`.
- `agentStop` waits for the scan, filters findings to the agent-modified ranges, and either lets the turn end (no new vulns) or blocks with a fix-it prompt (one or more new vulns).

## Authentication

The hook checks Snyk CLI authentication before starting a background scan in `postToolUse`. If the user is not logged in, the scan is skipped and an `auth_required` status is recorded; edits are not blocked at that moment. At `agentStop` the hook then blocks with an **MCP fallback** message that prompts Copilot to use the `snyk_auth` and `snyk_code_scan` MCP tools (and `snyk_sca_scan` when dependency manifests changed). Operators should run `snyk auth` once so subsequent scans run automatically.

## How It Works

### Async CLI Version

```
Session starts
  -> sessionStart: initialize state, snapshot manifest hashes

Agent edits a file
  -> postToolUse: track modified line ranges; if authenticated, launch background scan
     If not authenticated, skip scan (non-blocking for the agent)

Agent tries to end the turn
  -> agentStop: wait for the background scan (bounded timeout)
  -> New vulns in modified ranges? -> block with /snyk-batch-fix and a vuln table
  -> Manifest changes since session start? -> include SCA findings in the block reason
  -> Scan timed out or never ran? -> block with the MCP fallback prompt
  -> Loop cap reached (3 scan-fix cycles)? -> let the turn end; recorded for audit
  -> Otherwise: let the turn end
```

See **[async_cli_version/README.md](./async_cli_version/README.md)** for install steps, hook JSON, configuration, and troubleshooting.
