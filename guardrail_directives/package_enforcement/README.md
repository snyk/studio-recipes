# Package Enforcement

This directory contains guardrails that enforce security scanning before package installation. They implement a "scan-before-install" security gate that prevents vulnerable dependencies from being added without review.

## Overview

When an AI agent adds new dependencies to a project, these guardrails ensure:

1. The package manifest change is detected and recorded
2. Install commands (npm, yarn, pnpm) are blocked until scanned
3. Only after running `snyk_sca_scan` are installs allowed
4. Session-end reminders if changes weren't scanned

## How It Works

```
┌────────────────────────────────────────────────────────────┐
│  AI Agent: "I'll add lodash to your project"              │
│                                                            │
│  → Edits package.json                                      │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│  afterFileEdit Hook                                        │
│                                                            │
│  Detects: package.json modified                           │
│  Action: Records pending scan requirement                  │
│  Output: "Dependency manifest modified - scan required"   │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│  AI Agent: "Running npm install..."                       │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│  beforeShellExecution Hook                                 │
│                                                            │
│  Detects: npm install command                             │
│  Check: Pending scan exists? YES                          │
│  Action: BLOCK with message                               │
│                                                            │
│  "INSTALL BLOCKED: Run snyk_sca_scan first"              │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│  AI Agent: "I need to run a security scan first"         │
│                                                            │
│  → Calls snyk_sca_scan                                    │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│  beforeMCPExecution Hook                                   │
│                                                            │
│  Detects: snyk_sca_scan tool call                         │
│  Action: Clears pending scan state                        │
│  Output: "Security scan initiated - installs now allowed" │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│  AI Agent: "Now I can install the package"               │
│                                                            │
│  → npm install succeeds                                   │
└────────────────────────────────────────────────────────────┘
```

## Supported Package Managers

| Package Manager | Install Commands Blocked |
|-----------------|-------------------------|
| **npm** | `npm install`, `npm i`, `npm ci` |
| **yarn** | `yarn install`, `yarn add`, `yarn` |
| **pnpm** | `pnpm install`, `pnpm add`, `pnpm i` |

## Monitored Files

| File | Purpose |
|------|---------|
| `package.json` | npm/yarn/pnpm manifest |
| `package-lock.json` | npm lockfile |
| `yarn.lock` | Yarn lockfile |
| `pnpm-lock.yaml` | pnpm lockfile |

## Use Cases

### Adding a New Dependency
```
User: "Add axios for HTTP requests"

AI: Edits package.json to add axios
    [Hook records change]

AI: Attempts npm install
    [Hook BLOCKS]
    → "Must run snyk_sca_scan first"

AI: Runs snyk_sca_scan
    [Hook clears block]
    → Scan shows axios is safe

AI: npm install succeeds
    → axios installed
```

### Adding a Vulnerable Package
```
User: "Add lodash@4.17.15"

AI: Edits package.json
    [Hook records change]

AI: Attempts npm install
    [Hook BLOCKS]

AI: Runs snyk_sca_scan
    → Finds Prototype Pollution in lodash@4.17.15
    → AI upgrades to lodash@4.17.21 (fixed version)

AI: npm install succeeds
    → Safe version installed
```

### Session Ending Without Scan
```
User: "Add express to the project" then closes session

AI: Edits package.json
    [Hook records change]

Session ends without install
    [stop hook triggers]
    → "SECURITY ALERT: Dependency manifests were modified 
        but not scanned. Run snyk_sca_scan before deploying."
```

## Mock Example: Hook Script

```python
#!/usr/bin/env python3
"""
Conceptual implementation of the package enforcement hook.
"""

import json
import sys
import os

# State file tracks pending scans
STATE_FILE = "/tmp/cursor-pkg-scan.state"

def main():
    data = json.loads(sys.stdin.read())
    event = data.get("hook_event_name")
    
    if event == "afterFileEdit":
        file_path = data.get("file_path", "")
        if "package.json" in file_path:
            # Record that we need a scan
            with open(STATE_FILE, "w") as f:
                f.write(file_path)
            print(json.dumps({"exit_code": 0}))
    
    elif event == "beforeShellExecution":
        command = data.get("command", "")
        if "npm install" in command and os.path.exists(STATE_FILE):
            # Block until scanned
            print(json.dumps({
                "permission": "deny",
                "agent_message": "Run snyk_sca_scan before npm install"
            }))
            sys.exit(2)  # Exit code 2 = block
    
    elif event == "beforeMCPExecution":
        tool = data.get("tool_name", "")
        if "snyk_sca_scan" in tool and os.path.exists(STATE_FILE):
            # Clear the block
            os.remove(STATE_FILE)
    
    print(json.dumps({"exit_code": 0}))

if __name__ == "__main__":
    main()
```

## Installation

See [cursor/hooks/README.md](cursor/hooks/README.md) for detailed installation instructions.

## Configuration

Environment variables (optional):
- `CURSOR_HOOK_STATE_DIR` - Directory for state files (default: `/tmp`)
- `CURSOR_HOOK_DEBUG` - Set to "1" for verbose logging

## See Also

- [Cursor Hooks Implementation](cursor/hooks/) - The actual hook script
- [Secure At Inception](../secure_at_inception/) - Scan new code automatically
- [Guardrail Directives](../) - Overview of all guardrails

