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
| `beforeMCPExecution` | Before AI calls MCP tool | Clear block on scan |
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
         │                 │
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
         │                     │
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

## Use Cases

### Successful Scan-Then-Install
```
1. AI adds "lodash": "^4.17.21" to package.json
   → afterFileEdit records pending scan

2. AI runs: npm install
   → beforeShellExecution BLOCKS
   → Agent message: "Run snyk_sca_scan first"

3. AI calls snyk_sca_scan
   → beforeMCPExecution clears pending state
   → Scan completes (no issues found)

4. AI runs: npm install
   → beforeShellExecution allows (no pending scan)
   → Package installed successfully
```

### Vulnerable Package Detected
```
1. AI adds "lodash": "^4.17.15" to package.json
   → afterFileEdit records pending scan

2. AI runs: npm install
   → BLOCKED

3. AI calls snyk_sca_scan
   → Finds prototype pollution vulnerability
   → AI updates lodash to 4.17.21

4. AI runs: npm install
   → Allowed (scan was run)
   → Safe version installed
```

### Session Ends Without Scan
```
1. AI adds dependencies to package.json
   → afterFileEdit records pending scan

2. User ends session (or AI completes task)
   → stop hook triggers
   → Warning: "Dependency manifests modified but not scanned"
```

## Mock Example: Hook Response Formats

```python
# Allow an action
{"exit_code": 0}

# Block an action with message to AI
{
    "permission": "deny",
    "agent_message": "Run snyk_sca_scan before npm install"
}

# Block with both AI and user messages
{
    "permission": "deny",
    "agent_message": "BLOCKED: Security scan required",
    "user_message": "Install blocked - security scan needed"
}

# Session-end reminder
{
    "followup_message": "SECURITY: Unscanned dependency changes detected"
}
```

## Installation

See [hooks/README.md](hooks/README.md) for detailed installation instructions.

## Requirements

- Cursor IDE 2.2.x or later
- Python 3.8+
- Snyk MCP server configured

## See Also

- [Hooks Implementation](hooks/) - The actual Python script
- [Package Enforcement Overview](../) - Parent directory

