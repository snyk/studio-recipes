# Cursor Hooks - Secure At Inception

This directory contains two Cursor IDE hook implementations for Secure At Inception. Both automatically enforce security scanning when the AI agent modifies code, but they differ in scanning strategy.

## Versions

| Version | Scanning Approach | Hook Events | Dependencies |
|---------|------------------|-------------|--------------|
| **[Async CLI](./async_cli_version/)** | Verifies auth/CLI on start, runs `snyk code test` in the background via CLI, filters results to agent-modified lines | `sessionStart`, `afterFileEdit`, `stop` | Python 3.8+, Snyk CLI |
| **[Sync MCP](./sync_mcp_version/)** | Tracks file changes, prompts the agent to invoke Snyk MCP tools at session end | `afterFileEdit`, `beforeMCPExecution`, `stop` | Python 3.8+, Snyk MCP server |

## Choosing a Version

**Async CLI** is best when you want:
- Scans running in the background while the agent keeps working
- Vulnerability filtering to only agent-modified lines (ignores pre-existing issues)
- Direct CLI-based scanning with no MCP dependency
- Automatic fix loops that block the agent until issues are resolved

**Sync MCP** is best when you want:
- A lightweight, single-file setup with no `lib/` dependencies
- Scanning delegated to the Snyk MCP server (already connected to Cursor)
- State tracking that clears automatically when the agent invokes scan tools
- Simpler configuration with no Snyk CLI installation required

## How They Work

### Async CLI Version

```
Session starts
  → sessionStart hook checks Snyk auth + CLI presence
  → Issues found?   → send followup_message warning the agent
  → All checks pass → launch cache-warming background scan

Agent edits a file
  → afterFileEdit tracks modified line ranges
  → Checks for cached errors (auth/CLI) → blocks immediately if found
  → Launches background scan (non-blocking)

Agent finishes responding
  → stop hook waits for scan results
  → Filters to only vulns on lines the agent modified
  → New vulns found?  → block with fix instructions (up to 3 cycles)
  → No new vulns?     → pass silently
  → Scan failed?      → fall back to MCP snyk_code_scan prompt
```

### Sync MCP Version

```
Agent edits a code file
  → afterFileEdit records it as needing SAST scan

Agent edits a manifest file
  → afterFileEdit records it as needing SCA scan

Agent runs snyk_code_scan or snyk_sca_scan
  → beforeMCPExecution clears the corresponding tracked state

Agent finishes responding
  → stop hook checks for unscanned changes
  → Pending changes?  → send followup_message prompting scans
  → All scanned?      → pass silently
```
