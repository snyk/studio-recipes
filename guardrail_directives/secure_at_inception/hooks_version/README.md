# Hooks Version - Secure At Inception

This directory contains hook-based implementations of Secure At Inception for multiple coding assistants. Hooks provide deterministic enforcement -- they always fire at the appropriate lifecycle event regardless of what the AI decided to do during the session.

## Overview

The hooks approach uses coding assistant lifecycle events to prompt the AI agent to run security scans. This provides a safety net that catches any vulnerabilities missed during inline code generation.

## Available Implementations

| Implementation | Coding Assistant | Hook Event | How It Works |
|----------------|-----------------|------------|--------------|
| **[Cursor](./cursor/)** | Cursor IDE | `stop` (task completion) | Sends follow-up message prompting scans at session end |
| **[Claude Code](./claude/sync_mcp_version/)** | Claude Code | `PostToolUse` (after file edits) | Injects scan context after every code file write |

## How It Works

### Cursor (Session-End Hook)

```
    AI generates code during session
          │
          ▼
    AI completes task
          │
          ▼
    ┌───────────────────────────────────┐
    │  stop hook fires                  │
    │  "If you changed code, run       │
    │   snyk_code_scan..."             │
    └───────────────────────────────────┘
          │
          ▼
    AI runs security scans and fixes issues
```

### Claude Code (Post-Edit Hook)

```
    AI edits a source code file
          │
          ▼
    ┌───────────────────────────────────┐
    │  PostToolUse hook fires           │
    │  Checks file extension            │
    │  Injects scan context             │
    └───────────────────────────────────┘
          │
          ▼
    AI runs snyk_code_scan immediately
          │
          ▼
    Fixes issues, re-edit triggers hook again
    Cycle repeats until clean
```

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

1. **Timing varies** - Cursor fires at session end; Claude Code fires after each edit
2. **Extra Turn** - May require additional AI turn for fixes
3. **User Experience** - Session may "extend" beyond initial completion

## Combining with Rules

For maximum coverage, use both hooks and rules:

```
┌─────────────────────────────────────────────┐
│  SAI Rule (inline)                          │
│  - Real-time scanning during generation     │
│  - Immediate fix before presenting code     │
└─────────────────────────────────────────────┘
                    +
┌─────────────────────────────────────────────┐
│  SAI Hook (lifecycle event)                 │
│  - Catch anything missed by rule            │
│  - Guaranteed final check                   │
└─────────────────────────────────────────────┘
```

## See Also

- [Cursor Implementation](cursor/) - Cursor hooks installation guide
- [Claude Code Implementation](claude/sync_mcp_version/) - Claude Code hooks setup
- [Rule Version](../rule_version/) - Inline scanning alternative
- [Kiro/Git Hooks](../kiro_hooks/) - Git pre-commit hook approach
- [Secure At Inception Overview](../) - Comparison of all approaches
