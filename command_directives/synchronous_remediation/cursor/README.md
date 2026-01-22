# Cursor Commands

This directory contains security remediation command definitions for the Cursor IDE. These commands enable AI-assisted vulnerability scanning and fixing through Cursor's agent capabilities.

## Overview

Cursor commands are instruction sets that guide the AI agent through specific workflows. When a user invokes a command (e.g., `/snyk-fix`), the agent follows the defined phases to complete the security remediation task.

## Two Approaches

### 1. Composite Commands (Recommended)
A modular architecture where the main command dispatches to specialized sub-commands:

```
/snyk-fix
    ├── /snyk-code-fix    (for SAST issues)
    ├── /snyk-sca-fix     (for dependency issues)
    └── /create-security-pr (for PR creation)
```

**Advantages:**
- Granular control over each phase
- Can invoke sub-commands independently
- Easier to customize individual workflows
- Better for teams with specific requirements

### 2. Single All-in-One Command
A self-contained command with all logic in one file:

**Advantages:**
- Simpler installation (one file)
- No dependencies between commands
- Easier to understand complete flow

## Installation

### Option 1: As Cursor Rules (Recommended)

Copy command files to your project's `.cursor/rules/` directory:

```bash
# For composite commands
mkdir -p .cursor/rules
cp composit_commands/*.md .cursor/rules/

# OR for all-in-one
cp single_all_in_one_command/snyk-fix.md .cursor/rules/
```

### Option 2: As Custom Commands

Configure in Cursor settings or reference in your project's command configuration.

## Prerequisites

- **Snyk MCP Server** - Must be configured in Cursor's MCP settings
- **Snyk CLI** - Installed and accessible (`snyk` command)
- **Snyk Authentication** - Either `snyk auth` or `SNYK_TOKEN` environment variable
- **GitHub CLI** (optional) - For PR creation (`gh` command)

## Use Cases

### Quick Fix
```
/snyk-fix
```
Scans both code and dependencies, fixes the highest priority issue.

### Code-Only Scan
```
/snyk-fix code
```
Only scans for SAST issues and fixes the highest priority code vulnerability.

### Specific Vulnerability
```
/snyk-fix CVE-2021-44228
```
Finds and fixes a specific CVE across code and dependencies.

### Package-Specific
```
/snyk-fix lodash
```
Fixes vulnerabilities in a specific package.

## Mock Example: Command Execution

```markdown
## User invokes: /snyk-fix

### Phase 1: Input Parsing
- Detected scan type: BOTH (no specific hint)
- Target: None specified → will fix highest priority

### Phase 2: Discovery
Running scans...
- Code scan: 3 issues (1 High, 2 Medium)
- SCA scan: 5 issues (1 Critical, 2 High, 2 Low)

Selected: Critical SCA vulnerability
- Package: lodash@4.17.15
- Issue: Prototype Pollution
- Fix: Upgrade to 4.17.21

### Phase 3: Remediation
- Updated package.json: lodash ^4.17.15 → ^4.17.21
- Running npm install...
- Lockfile updated

### Phase 4: Validation
- Re-running SCA scan...
- ✅ Vulnerability resolved
- Running tests... ✅ Pass

### Summary
| Fixed | lodash Prototype Pollution |
|-------|---------------------------|
| Package | lodash@4.17.15 → 4.17.21 |
| Severity | Critical → Resolved |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Should I create a PR for this fix? (yes/no)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Configuration

The commands use these Snyk MCP tools:
- `mcp_snyk_snyk_code_scan` - SAST scanning
- `mcp_snyk_snyk_sca_scan` - Dependency scanning
- `mcp_snyk_snyk_auth` - Authentication
- `mcp_snyk_snyk_send_feedback` - Metrics reporting

Ensure your Cursor MCP configuration includes the Snyk server.

