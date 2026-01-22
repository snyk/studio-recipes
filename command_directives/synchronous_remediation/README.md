# Synchronous Remediation

This directory contains command definitions that enable real-time, interactive security vulnerability remediation. "Synchronous" means the AI agent performs the fix immediately during the conversation, with user oversight at each step.

## Overview

Synchronous remediation commands guide AI agents through a complete security fix lifecycle:

1. **Scan** - Run Snyk security scans (SAST and/or SCA)
2. **Analyze** - Identify and prioritize vulnerabilities
3. **Fix** - Apply code changes or dependency upgrades
4. **Validate** - Re-scan to confirm resolution
5. **PR** - Optionally create a pull request

## Implementations

### Claude Code Skills
Skills are Claude Code's mechanism for extending agent capabilities. The `snyk-fix` skill provides:
- Automatic invocation when users mention security fixes
- Access to Snyk MCP tools for scanning
- Full remediation workflow in a single skill

### Cursor Commands
Cursor supports two approaches:

| Approach | Files | Best For |
|----------|-------|----------|
| **Composite** | 4 separate commands | Teams wanting granular control |
| **All-in-One** | 1 combined command | Simpler setup, single file |

## Use Cases

### Fix Any Security Issue
```
User: "fix security issues"

Agent workflow:
1. Runs both code and SCA scans
2. Selects highest priority vulnerability
3. Routes to appropriate fix handler
4. Applies fix and validates
5. Offers to create PR
```

### Fix Specific Vulnerability Type
```
User: "fix XSS vulnerabilities"

Agent workflow:
1. Runs code scan
2. Finds all XSS instances in highest-priority file
3. Fixes ALL instances together
4. Validates no XSS remains
5. Offers to create PR
```

### Fix Vulnerable Dependency
```
User: "fix vulnerabilities in lodash"

Agent workflow:
1. Runs SCA scan
2. Identifies vulnerable lodash version
3. Upgrades to minimum secure version
4. Regenerates lockfile
5. Validates fix and offers PR
```

## Mock Example: Composite Command Flow

```
┌─────────────────┐
│   /snyk-fix     │  ← Entry point: parses intent, runs discovery
└────────┬────────┘
         │
         ▼
    ┌────────────┐
    │ Code vuln? │───Yes───▶ /snyk-code-fix
    └────────────┘                 │
         │ No                      ▼
         ▼                   Fix code issues
    ┌────────────┐                 │
    │ SCA vuln?  │───Yes───▶ /snyk-sca-fix
    └────────────┘                 │
                                   ▼
                            Upgrade packages
                                   │
                                   ▼
                          ┌────────────────┐
                          │ User wants PR? │
                          └───────┬────────┘
                                  │ Yes
                                  ▼
                          /create-security-pr
```

## Key Features

- **Multi-instance fixing** - Fixes ALL instances of a vulnerability type in one pass
- **Validation loop** - Re-scans after fix to confirm resolution
- **Safe rollback** - Reverts changes if fix introduces new issues
- **Minimal changes** - Only modifies what's necessary for the fix
- **PR automation** - Creates well-formatted security PRs

## Getting Started

1. Choose your AI assistant (Claude Code or Cursor)
2. Navigate to the appropriate subdirectory
3. Follow the installation instructions in that README
4. Ensure Snyk CLI is installed and authenticated

