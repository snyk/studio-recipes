# Snyk Fix - Claude Code Skill

A Claude Code skill that provides complete security remediation workflow: scan → fix → validate → PR.

## Installation

### Option 1: Project-level (Recommended)

Copy the skill to your project's `.claude/skills/` directory:

```bash
# From your project root
mkdir -p .claude/skills/snyk-fix
cp SKILL.md .claude/skills/snyk-fix/
```

### Option 2: Global Installation

Copy to your home directory for use across all projects:

```bash
mkdir -p ~/.claude/skills/snyk-fix
cp SKILL.md ~/.claude/skills/snyk-fix/
```

## Prerequisites

- **Snyk CLI**: Must be installed and accessible
- **Snyk Authentication**: Run `snyk auth` or have `SNYK_TOKEN` environment variable set
- **GitHub CLI** (optional): Required for PR creation feature (`gh auth login`)

## Usage

This skill is **automatically invoked** when Claude detects relevant requests. Examples:

| What You Say | What Happens |
|--------------|--------------|
| "fix security issues" | Scans both code and dependencies, fixes highest priority |
| "fix code vulnerabilities" | SAST scan only |
| "fix dependency vulnerabilities" | SCA scan only |
| "fix CVE-2021-44228" | Finds and fixes specific CVE |
| "fix SNYK-JS-LODASH-1018905" | Fixes specific Snyk issue |
| "fix XSS vulnerabilities" | Fixes all XSS issues |
| "fix vulnerabilities in lodash" | Fixes issues in specific package |

## Workflow

1. **Parse** - Determines scan type and target from your request
2. **Scan** - Runs Snyk code and/or SCA scans
3. **Analyze** - Identifies highest priority vulnerability (or specific target)
4. **Fix** - Applies remediation (code fix or dependency upgrade)
5. **Validate** - Re-scans to confirm fix, runs tests
6. **Summary** - Reports what was fixed
7. **PR** (optional) - Creates a pull request if you confirm

## Features

- **Auto-detection**: Figures out if you need code scan, dependency scan, or both
- **Multi-instance fixes**: Fixes ALL instances of a vulnerability type in the same file
- **Validation loop**: Re-scans after fix to ensure resolution
- **Safe rollback**: Reverts changes if fix introduces new issues
- **PR automation**: Creates branch, commits, pushes, and opens PR

## Configuration

The skill uses these Snyk MCP tools:
- `mcp_snyk_snyk_code_scan` - SAST scanning
- `mcp_snyk_snyk_sca_scan` - Dependency scanning  
- `mcp_snyk_snyk_auth` - Authentication
- `mcp_snyk_snyk_send_feedback` - Metrics reporting

Ensure your Snyk MCP server is configured in Claude Code.

