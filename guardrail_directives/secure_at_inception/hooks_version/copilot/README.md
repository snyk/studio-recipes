# GitHub Copilot Hooks - Secure At Inception

This directory contains GitHub Copilot hook implementations for Secure At Inception. Hooks provide deterministic enforcement -- they fire at the appropriate lifecycle event regardless of what the AI decided to do during the session.

## Versions

| Version | Scanning Approach | Hook Events | Dependencies |
|---------|------------------|-------------|--------------|
| **[Async CLI](./async_cli_version/)** | Runs `snyk code test` in the background via CLI, filters results to agent-modified lines, gates git operations | `postToolUse`, `preToolUse`, `agentStop` | Python 3.8+, Snyk CLI |

## Copilot Hook Architecture

Copilot hooks differ from Claude Code and Cursor in a key way: **only `preToolUse` can influence agent behavior** (approve/deny tool calls). The `agentStop` hook output is **ignored**—it is used for **audit logging only**, not to block or prompt the user.

Enforcement is therefore split between **early notification** on ordinary `bash` commands and **hard gating** on **git** operations (commit, push, `gh pr create` / `gh pr merge`).

## Authentication

The async CLI hook checks **Snyk CLI authentication before starting a background scan** (`postToolUse`). If the user is not logged in, the scan is skipped and an `auth_required` status is recorded; **edits are not blocked**. When the agent later tries a **git** operation with pending tracked changes, **`preToolUse` denies** the tool call and instructs the agent to run **`snyk_auth`** and **`snyk_code_scan`** (and **`snyk_sca_scan`** when dependency manifests changed). Operators should run `snyk auth` once so scans run automatically.

## How It Works

### Async CLI Version

```
Agent edits a file
  -> postToolUse: track modified line ranges; if authenticated, launch background scan
     If not authenticated, skip scan (non-blocking for the agent)

Agent runs a non-git bash command
  -> preToolUse: if scan succeeded and new vulns exist, deny once per vuln fingerprint
     with /snyk-batch-fix (subsequent bash with same fingerprint allowed)

Agent runs git commit / git push / gh pr create / gh pr merge
  -> preToolUse: wait for scan (bounded timeout)
  -> New vulns or manifest follow-up? -> deny with /snyk-batch-fix; retry to proceed anyway
  -> Scan timeout? -> deny, ask to retry commit
  -> auth / CLI failure? -> deny with MCP fallback (snyk_auth, snyk_code_scan, snyk_sca_scan)

Agent finishes responding
  -> agentStop: stderr audit only (no interrupt)
```

See **[async_cli_version/README.md](./async_cli_version/README.md)** for install steps, hook JSON, configuration, and troubleshooting.
