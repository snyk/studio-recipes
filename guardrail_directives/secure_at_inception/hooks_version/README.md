# Hooks Version - Secure At Inception

This directory contains hook-based implementations of Secure At Inception for multiple coding assistants. Hooks provide deterministic enforcement -- they always fire at the appropriate lifecycle event regardless of what the AI decided to do during the session.

## Overview

The hooks approach uses coding assistant lifecycle events to prompt the AI agent to run security scans. This provides a safety net that catches any vulnerabilities missed during inline code generation.

## Available Implementations

| Implementation | Coding Assistant | Hook Events | How It Works |
|----------------|-----------------|-------------|--------------|
| **[Cursor - Async CLI](./cursor/async_cli_version/)** | Cursor IDE | `sessionStart`, `afterFileEdit`, `stop` | Verifies auth/CLI on start, runs `snyk code test` in the background, filters results to agent-modified lines, blocks agent if new vulns found |
| **[Cursor - Sync MCP](./cursor/sync_mcp_version/)** | Cursor IDE | `afterFileEdit`, `beforeMCPExecution`, `stop` | Tracks file changes, prompts agent to invoke Snyk MCP tools at session end |
| **[Claude Code - Async CLI](./claude/async_cli_version/)** | Claude Code | `SessionStart`, `PostToolUse` (Edit\|Write), `Stop` | Verifies auth/CLI on start, runs `snyk code test` in the background, filters results to agent-modified lines, blocks Claude if new vulns found |
| **[Claude Code - Sync MCP](./claude/sync_mcp_version/)** | Claude Code | `PostToolUse` (Edit\|Write) | Injects `additionalContext` prompting Claude to run Snyk MCP tools after every code file edit |
| **[Copilot - Async CLI](./copilot/async_cli_version/)** | GitHub Copilot | `postToolUse`, `preToolUse`, `agentStop` | Runs `snyk code test` in the background, filters results to agent-modified lines, gates git commit/push with notify-then-allow |


## Coding Assistant Documentation

Consult your coding assistant's official documentation for how to implement hooks:

- [Cursor](https://cursor.com/docs/agent/hooks)
- [GitHub Copilot](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/use-hooks)
- [Windsurf](https://docs.windsurf.com/windsurf/cascade/hooks)
- [Claude Code](https://code.claude.com/docs/en/hooks)
- [Gemini CLI](https://geminicli.com/docs/hooks/)

## Advantages

1. **Deterministic** - Always fires at the lifecycle event
2. **Comprehensive** - Catches anything missed during the session
3. **Safety Net** - Works regardless of inline rule compliance
4. **Auditable** - Can log all sessions for compliance

## Limitations

1. **Timing varies** - Async CLI versions scan in the background and evaluate at session end; Cursor Sync MCP prompts at session end; Claude Code Sync MCP injects context after every edit
2. **Extra Turn** - May require additional AI turn for fixes
3. **User Experience** - Session may "extend" beyond initial completion


## See Also

- [Cursor Hooks Overview](cursor/) - Comparison of both Cursor versions
- [Cursor Async CLI](cursor/async_cli_version/) - Background CLI scanning with line-level filtering
- [Cursor Sync MCP](cursor/sync_mcp_version/) - Lightweight MCP-based scan prompting
- [Claude Code Hooks Overview](claude/) - Comparison of both Claude Code versions
- [Claude Code Async CLI](claude/async_cli_version/) - Background CLI scanning with line-level filtering
- [Claude Code Sync MCP](claude/sync_mcp_version/) - Post-edit context injection for MCP scans
- [Copilot Hooks Overview](copilot/) - Copilot hook implementation
- [Copilot Async CLI](copilot/async_cli_version/) - Background CLI scanning with git-operation gating
- [Rule Version](../rule_version/) - Inline scanning alternative
- [Kiro/Git Hooks](../kiro_hooks/) - Git pre-commit hook approach
- [Secure At Inception Overview](../) - Comparison of all approaches
