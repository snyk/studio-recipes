# Claude Code Hooks - Secure At Inception

This directory contains two Claude Code hook implementations for Secure At Inception. Both automatically enforce security scanning when Claude modifies code, but they differ in scanning strategy.

## Versions

| Version | Scanning Approach | Hook Events | Dependencies |
|---------|------------------|-------------|--------------|
| **[Async CLI](./async_cli_version/)** | Verifies auth/CLI on start, runs `snyk code test` in the background via CLI, filters results to agent-modified lines | `SessionStart`, `PostToolUse` (Edit\|Write), `Stop` | Python 3.8+, Snyk CLI |
| **[Sync MCP](./sync_mcp_version/)** | Injects `additionalContext` prompting Claude to invoke Snyk MCP tools after every code file edit | `PostToolUse` (Edit\|Write) | bash, jq, Snyk MCP server |

## Choosing a Version

**Async CLI** is best when you want:
- Scans running in the background while Claude keeps working
- Vulnerability filtering to only agent-modified lines (ignores pre-existing issues)
- Direct CLI-based scanning with no MCP dependency
- Automatic blocking that prevents Claude from stopping until issues are resolved
- Manifest tracking for SCA scans on dependency file changes

**Sync MCP** is best when you want:
- A single shell script with zero Python dependencies
- Scanning delegated to the Snyk MCP server (already connected to Claude Code)
- Immediate scan prompting after every edit (no batching)
- Simpler setup with no state files or background processes

## How They Work

### Async CLI Version

```
Session starts
  → SessionStart hook checks Snyk auth + CLI presence
  → Issues found?   → inject additionalContext warning for Claude
  → All checks pass → launch cache-warming background scan

Claude edits a file
  → PostToolUse hook tracks modified line ranges
  → Checks for cached errors (auth/CLI) → blocks immediately if found
  → Launches background scan (non-blocking)

Claude finishes responding
  → Stop hook waits for scan results
  → Filters to only vulns on lines Claude modified
  → New vulns found?  → block with fix instructions (up to 3 cycles)
  → No new vulns?     → pass silently
  → Scan failed?      → fall back to MCP snyk_code_scan prompt
```

### Sync MCP Version

```
Claude edits a code file
  → PostToolUse hook fires
  → Checks file extension against supported languages
  → Injects additionalContext: "run snyk_code_scan..."

Claude reads the context and runs snyk_code_scan
  → Fixes any newly introduced issues
  → Fix edits trigger the hook again
  → Cycle repeats until clean
```