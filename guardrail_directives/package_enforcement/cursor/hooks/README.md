# Package Enforcement Hook

This directory contains a Python hook script that enforces security scanning before package installation in Cursor IDE.

## Overview

The `enforce_security_scan_on_new_packages.py` script implements a security gate that:

1. Detects when package manifest files are modified
2. Blocks `npm install`, `yarn add`, `pnpm install` until scanned
3. Clears the block when `snyk_sca_scan` is executed
4. Provides reminders if session ends with unscanned changes

## File

| File | Purpose |
|------|---------|
| `enforce_security_scan_on_new_packages.py` | Multi-event hook script |

## Installation

### Step 1: Copy the Hook Script

```bash
# Create hooks directory in your project
mkdir -p /path/to/project/.cursor/hooks

# Copy the script
cp enforce_security_scan_on_new_packages.py /path/to/project/.cursor/hooks/

# Make executable
chmod +x /path/to/project/.cursor/hooks/enforce_security_scan_on_new_packages.py
```

### Step 2: Configure hooks.json

Create or update `.cursor/hooks.json` in your project:

```json
{
  "version": 1,
  "hooks": {
    "afterFileEdit": [
      {"command": "python3 .cursor/hooks/enforce_security_scan_on_new_packages.py"}
    ],
    "beforeShellExecution": [
      {"command": "python3 .cursor/hooks/enforce_security_scan_on_new_packages.py"}
    ],
    "beforeMCPExecution": [
      {"command": "python3 .cursor/hooks/enforce_security_scan_on_new_packages.py"}
    ],
    "stop": [
      {"command": "python3 .cursor/hooks/enforce_security_scan_on_new_packages.py"}
    ]
  }
}
```

### Step 3: Verify Installation

Test the hook is working:

1. Open a project in Cursor
2. Have the AI add a package to package.json
3. Have the AI try to run `npm install`
4. Verify the command is blocked with a message about scanning

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CURSOR_HOOK_STATE_DIR` | `/tmp` | Directory for state files |
| `CURSOR_HOOK_DEBUG` | `0` | Set to `1` for verbose logging |

### Monitored Files

The hook watches these files:
- `package.json`
- `package-lock.json`
- `yarn.lock`
- `pnpm-lock.yaml`

### Blocked Commands

The hook blocks these patterns:
- `npm install`, `npm i`, `npm ci`
- `yarn install`, `yarn add`, `yarn`
- `pnpm install`, `pnpm add`, `pnpm i`

## How It Works

### State Management

The hook uses a state file to track pending scans:

```
/tmp/cursor-pkg-scan-{workspace_hash}.state
```

This file contains timestamps and paths of modified manifests. The file is:
- **Created** when a manifest is edited (afterFileEdit)
- **Checked** before install commands (beforeShellExecution)
- **Cleared** when a scan runs (beforeMCPExecution)

### Hook Event Flow

```
┌─────────────────────────────────────────────────────────────┐
│  afterFileEdit                                              │
│                                                             │
│  Input:  {"hook_event_name": "afterFileEdit",              │
│           "file_path": "/project/package.json"}            │
│                                                             │
│  Action: Append to state file                              │
│  Output: {"exit_code": 0}                                  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  beforeShellExecution                                       │
│                                                             │
│  Input:  {"hook_event_name": "beforeShellExecution",       │
│           "command": "npm install"}                        │
│                                                             │
│  Check:  State file exists? → Yes                          │
│  Action: Block command                                      │
│  Output: {"permission": "deny",                            │
│           "agent_message": "Run snyk_sca_scan first"}      │
│  Exit:   2 (signals block to Cursor)                       │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  beforeMCPExecution                                         │
│                                                             │
│  Input:  {"hook_event_name": "beforeMCPExecution",         │
│           "tool_name": "snyk_sca_scan"}                    │
│                                                             │
│  Action: Delete state file (clear pending scan)            │
│  Output: {"exit_code": 0}                                  │
└─────────────────────────────────────────────────────────────┘
```

## Use Cases

### Normal Flow: Scan Then Install
```
Developer: "Add axios to the project"

AI: Edits package.json
    [afterFileEdit] → State file created

AI: npm install
    [beforeShellExecution] → BLOCKED
    → "Run snyk_sca_scan on /project first"

AI: Calls snyk_sca_scan
    [beforeMCPExecution] → State file deleted
    → Scan shows axios is safe

AI: npm install
    [beforeShellExecution] → No state file, ALLOWED
    → Package installed
```

### Vulnerability Found
```
Developer: "Add lodash@4.17.15"

AI: Edits package.json
    [afterFileEdit] → State recorded

AI: npm install
    [beforeShellExecution] → BLOCKED

AI: Calls snyk_sca_scan
    [beforeMCPExecution] → State cleared
    → Scan finds prototype pollution
    → AI upgrades to 4.17.21

AI: npm install
    → Safe version installed
```

## Debugging

Enable debug logging:

```bash
export CURSOR_HOOK_DEBUG=1
```

Check the Cursor Hooks output panel for messages like:
```
[DEBUG] Hook event: beforeShellExecution
[DEBUG] Command 'npm install' is an install command
[DEBUG] Pending scans exist, blocking
```

## Troubleshooting

### Hook Not Firing
1. Verify `hooks.json` is valid JSON
2. Check script has execute permissions
3. Confirm Python 3.8+ is available

### State File Issues
1. Check `CURSOR_HOOK_STATE_DIR` is writable
2. Look for state files in `/tmp/cursor-pkg-scan-*.state`

### False Positives
If legitimate installs are blocked:
1. Manually delete state files in `/tmp`
2. Check if manifest was edited outside of Cursor

## See Also

- [Cursor Hooks Documentation](https://docs.cursor.com/hooks)
- [Package Enforcement Overview](../../)
- [Guardrail Directives](../../../)

