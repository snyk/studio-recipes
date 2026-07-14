# Cursor Package Enforcement

This directory contains package enforcement implementations for the Cursor IDE. These use Cursor's hooks system to intercept and gate package installation commands.

## Overview

Cursor hooks allow scripts to run at specific lifecycle events during AI agent operation. This implementation uses hooks to:

1. **Detect** when package manifests are modified
2. **Block** install commands until a security scan runs
3. **Clear** the block when `snyk_sca_scan` is executed
4. **Remind** if session ends with unscanned changes

## Hook Events Used

| Event | Timing | Purpose |
|-------|--------|---------|
| `afterFileEdit` | After AI edits a file | Detect manifest changes |
| `beforeShellExecution` | Before AI runs shell command | Block install commands |
| `beforeMCPExecution` | Before AI calls MCP tool | Log scan start (does not clear) |
| `afterMCPExecution` | After AI's MCP tool returns | Clear block only on a successful, authenticated scan |
| `stop` | When agent task ends | Final reminder |

## Workflow Diagram

```
         ┌─────────────────┐
         │  AI edits file  │
         └────────┬────────┘
                  │
                  ▼
         ┌─────────────────┐
         │ afterFileEdit   │
         │ Is it           │
         │ package.json?   │
         └────────┬────────┘
                  │
        ┌─────────┴─────────┐
        │ Yes               │ No
        ▼                   ▼
┌───────────────┐    ┌──────────────┐
│ Record state  │    │   Continue   │
│ (scan needed) │    └──────────────┘
└───────┬───────┘
        │
        ▼
┌─────────────────────────────────────────┐
│          AI runs shell command          │
└────────────────────┬────────────────────┘
                     │
                     ▼
         ┌─────────────────────┐
         │ beforeShellExecution│
         │ Is it npm/yarn/pnpm │
         │ install command?    │
         └──────────┬──────────┘
                    │
          ┌─────────┴─────────┐
          │ Yes               │ No
          ▼                   ▼
   ┌──────────────┐    ┌──────────────┐
   │ Pending      │    │   Allow      │
   │ scan exists? │    └──────────────┘
   └──────┬───────┘
          │
    ┌─────┴─────┐
    │ Yes       │ No
    ▼           ▼
┌────────┐  ┌────────┐
│ BLOCK! │  │ Allow  │
└────────┘  └────────┘
```

## Installation

See [hooks/README.md](hooks/README.md) for detailed installation instructions.

## Requirements

- Cursor IDE
- Python 3.8+
- Snyk MCP server configured

## See Also

- [Hooks Implementation](hooks/) - The actual Python script
- [Package Enforcement Overview](../) - Parent directory
