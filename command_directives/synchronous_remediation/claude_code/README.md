# Claude Code Skills

This directory contains security remediation skill definitions for Claude Code (Anthropic's AI coding assistant). Skills extend Claude's capabilities to handle specialized workflows like security scanning and vulnerability fixing.

## Overview

Claude Code skills are YAML-frontmatter markdown files that define:
- **When** the skill should be invoked (triggers)
- **What tools** the skill can use
- **How** to execute the workflow (detailed instructions)

When a user's request matches the skill's description, Claude automatically applies the skill's workflow.

## How Skills Work

```
┌─────────────────────────────────────────────────────────┐
│                    User Request                         │
│         "fix security vulnerabilities"                  │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                   Claude Code                           │
│                                                         │
│  1. Parses user intent                                  │
│  2. Matches to snyk-fix skill (based on description)   │
│  3. Loads skill instructions                            │
│  4. Executes workflow with allowed tools               │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                   Skill Execution                       │
│                                                         │
│  - Runs Snyk scans via MCP tools                       │
│  - Analyzes vulnerabilities                            │
│  - Applies fixes                                        │
│  - Validates results                                    │
│  - Creates PR if requested                             │
└─────────────────────────────────────────────────────────┘
```

## Available Skills

### snyk-fix
Complete security remediation workflow that handles both code (SAST) and dependency (SCA) vulnerabilities.

**Triggers on:**
- "fix security vulnerabilities"
- "snyk fix"
- "remediate vulnerabilities"
- "fix CVE-XXX" or "fix SNYK-XXX"
- "fix XSS/SQLi/path traversal/etc."

**Tools Used:**
- `mcp_snyk_snyk_code_scan` - SAST scanning
- `mcp_snyk_snyk_sca_scan` - Dependency scanning
- `mcp_snyk_snyk_auth` - Authentication
- `mcp_snyk_snyk_send_feedback` - Metrics
- `Read`, `Write`, `Edit`, `Bash`, `Grep` - File operations

## Mock Example: Skill Definition Structure

```yaml
---
name: snyk-fix
description: |
  Complete security remediation workflow. Use when:
  - User asks to fix security vulnerabilities
  - User mentions specific CVEs or Snyk IDs
  - User wants to fix vulnerability types (XSS, SQLi)
allowed-tools:
  - mcp_snyk_snyk_code_scan
  - mcp_snyk_snyk_sca_scan
  - Read
  - Write
  - Edit
  - Bash
---

# Skill Instructions

## Phase 1: Parse Input
Determine scan type (code, sca, both) and target...

## Phase 2: Discovery
Run security scans...

## Phase 3: Remediation
Apply fixes...

## Phase 4: Validation
Verify fix worked...

## Phase 5: Summary
Report results and offer PR creation...
```

## Installation

### Project-Level (Recommended)
```bash
mkdir -p /path/to/project/.claude/skills/snyk-fix
cp skills/snyk-fix/SKILL.md /path/to/project/.claude/skills/snyk-fix/
```

### Global Installation
```bash
mkdir -p ~/.claude/skills/snyk-fix
cp skills/snyk-fix/SKILL.md ~/.claude/skills/snyk-fix/
```

## Prerequisites

- **Snyk MCP Server** - Configured in Claude Code's MCP settings
- **Snyk Authentication** - Either `snyk auth` or `SNYK_TOKEN` environment variable
- **GitHub CLI** (optional) - For PR creation feature

## Use Cases

### Automatic Security Fix
```
User: "fix security issues in this project"
Claude: [Invokes snyk-fix skill automatically]
        → Scans code and dependencies
        → Fixes highest priority vulnerability
        → Validates and offers PR
```

### Specific Vulnerability
```
User: "fix CVE-2021-44228"
Claude: [Invokes snyk-fix skill]
        → Searches for CVE in scan results
        → Applies targeted fix
        → Validates resolution
```

### Code-Only Scanning
```
User: "fix code vulnerabilities"
Claude: [Invokes snyk-fix skill with code hint]
        → Runs SAST scan only
        → Fixes code issues (XSS, SQLi, etc.)
```

## See Also

- [snyk-fix README](skills/snyk-fix/README.md) - Detailed installation guide
- [Cursor Commands](../cursor/) - Alternative for Cursor IDE users

