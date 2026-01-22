# Cursor Command Definitions

This directory contains the actual command definition files for Cursor IDE. Commands are markdown files that define structured workflows for the AI agent to follow.

## Command Types

### Composite Commands
A modular architecture where specialized commands handle different aspects:

| Command | Purpose | When Used |
|---------|---------|-----------|
| `snyk-fix` | Orchestrator | Entry point, routes to specialized commands |
| `snyk-code-fix` | SAST fixes | Code vulnerabilities (XSS, SQLi, Path Traversal) |
| `snyk-sca-fix` | SCA fixes | Dependency vulnerabilities |
| `create-security-pr` | PR workflow | Branch, commit, push, create PR |

### Single All-in-One
One comprehensive command that handles the entire workflow internally without delegation.

## Use Cases

### Using Composite Commands
```bash
# Main entry - auto-detects and routes
/snyk-fix

# Direct code scanning
/snyk-code-fix

# Direct dependency scanning
/snyk-sca-fix

# Standalone PR creation (after manual fix)
/create-security-pr
```

### Using All-in-One Command
```bash
# Handles everything in one command
/snyk-fix
/snyk-fix code
/snyk-fix sca
/snyk-fix CVE-2021-44228
```

## Mock Example: Composite Command Chain

```
┌──────────────────────────────────────────────────────────┐
│                     /snyk-fix                            │
│                                                          │
│  Input: "fix security issues"                           │
│  Parsed: scan_type=both, target=none                    │
│                                                          │
│  Discovery:                                              │
│  - Code scan → 2 High XSS in src/api/handler.ts         │
│  - SCA scan → 1 Critical in lodash                      │
│                                                          │
│  Decision: Route to /snyk-sca-fix (Critical > High)     │
└─────────────────────┬────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────────┐
│                   /snyk-sca-fix                          │
│                                                          │
│  Target: lodash@4.17.15 → 4.17.21                       │
│  Action: Edit package.json, run npm install             │
│  Validate: Re-scan confirms fix                          │
│                                                          │
│  Returns to /snyk-fix with success                      │
└─────────────────────┬────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────────┐
│                     /snyk-fix                            │
│                                                          │
│  Summary displayed to user                               │
│  Prompt: "Should I create a PR? (yes/no)"               │
│                                                          │
│  User: "yes"                                            │
└─────────────────────┬────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────────┐
│                /create-security-pr                       │
│                                                          │
│  git checkout -b fix/security-lodash-upgrade            │
│  git add package.json package-lock.json                 │
│  git commit -m "fix(security): upgrade lodash"          │
│  git push -u origin fix/security-lodash-upgrade         │
│  gh pr create --title "Security: Upgrade lodash"        │
│                                                          │
│  Output: PR URL and next steps                          │
└──────────────────────────────────────────────────────────┘
```

## Choosing Between Approaches

| Consideration | Composite | All-in-One |
|--------------|-----------|------------|
| Setup complexity | 4 files | 1 file |
| Customization | High | Medium |
| Direct sub-command access | Yes | No |
| Maintenance | Update individual files | Update one file |
| Team workflows | Better | Simpler |

## Installation

Copy the desired command files to your Cursor rules directory:

```bash
# Composite approach
cp composit_commands/*.md /path/to/project/.cursor/rules/

# All-in-one approach  
cp single_all_in_one_command/snyk-fix.md /path/to/project/.cursor/rules/
```

