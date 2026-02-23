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
mkdir -p /path/to/project/.cursor/hooks

cp enforce_security_scan_on_new_packages.py /path/to/project/.cursor/hooks/

chmod +x /path/to/project/.cursor/hooks/enforce_security_scan_on_new_packages.py
```

### Step 2: Configure hooks.json

Create or update `.cursor/hooks.json` in your project:

```json
{
  "version": 1,
  "hooks": {
    "afterFileEdit": [
      {"command": "python3 ./hooks/enforce_security_scan_on_new_packages.py"}
    ],
    "beforeShellExecution": [
      {"command": "python3 ./hooks/enforce_security_scan_on_new_packages.py"}
    ],
    "beforeMCPExecution": [
      {"command": "python3 ./hooks/enforce_security_scan_on_new_packages.py"}
    ],
    "stop": [
      {"command": "python3 ./hooks/enforce_security_scan_on_new_packages.py"}
    ]
  }
}
```

### Step 3: Verify Installation

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

This file is:
- **Created** when a manifest is edited (afterFileEdit)
- **Checked** before install commands (beforeShellExecution)
- **Cleared** when a scan runs (beforeMCPExecution)

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
