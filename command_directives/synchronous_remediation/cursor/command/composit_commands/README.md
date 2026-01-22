# Composite Commands

This directory contains a modular set of security remediation commands for Cursor IDE. The composite architecture separates concerns into specialized commands that can be chained together or used independently.

## Overview

The composite approach divides the security fix workflow into discrete, focused commands:

| Command | File | Purpose |
|---------|------|---------|
| `/snyk-fix` | `snyk-fix.md` | Main entry point, dispatcher, and orchestrator |
| `/snyk-code-fix` | `snyk-code-fix.md` | Fixes SAST/code vulnerabilities |
| `/snyk-sca-fix` | `snyk-sca-fix.md` | Fixes dependency vulnerabilities |
| `/create-security-pr` | `create-security-pr.md` | Creates PR for security fixes |

## Command Flow

```
                    ┌─────────────────┐
                    │   /snyk-fix     │
                    │   (dispatcher)  │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
       ┌─────────────┐ ┌──────────┐ ┌───────────────┐
       │/snyk-code-  │ │/snyk-sca-│ │   Either      │
       │    fix      │ │   fix    │ │   returns     │
       └──────┬──────┘ └────┬─────┘ │   control     │
              │             │       └───────────────┘
              └──────┬──────┘
                     │
                     ▼
              ┌─────────────────┐
              │   /snyk-fix     │
              │   (summary)     │
              └────────┬────────┘
                       │ user confirms
                       ▼
              ┌─────────────────┐
              │/create-security-│
              │       pr        │
              └─────────────────┘
```

## Use Cases

### 1. Automatic Detection and Fix
```
/snyk-fix
```
Runs both SAST and SCA scans, selects the highest priority issue, routes to the appropriate handler.

### 2. Code-Only Scanning
```
/snyk-fix code
# or directly:
/snyk-code-fix
```
Only scans for and fixes code vulnerabilities (XSS, SQL injection, path traversal, etc.).

### 3. Dependency-Only Scanning
```
/snyk-fix sca
# or directly:
/snyk-sca-fix
```
Only scans for and fixes vulnerable dependencies.

### 4. Targeted Fixes
```
/snyk-fix CVE-2021-44228
/snyk-fix SNYK-JS-LODASH-1018905
/snyk-fix XSS
/snyk-fix lodash
```
Finds and fixes specific vulnerabilities by CVE, Snyk ID, type, or package name.

### 5. Standalone PR Creation
```
/create-security-pr
```
Creates a PR for already-applied security changes (useful after manual fixes).

## Mock Example: Full Workflow

```markdown
## User: /snyk-fix

### snyk-fix: Phase 1 - Input Parsing
- No explicit type specified → will scan both
- No target vulnerability → will select highest priority

### snyk-fix: Phase 2 - Discovery  
Running parallel scans...

**Code Scan Results:**
| Severity | Type | Location |
|----------|------|----------|
| High | Path Traversal | src/api/files.ts:45 |
| High | Path Traversal | src/api/files.ts:112 |
| Medium | XSS | src/ui/render.ts:89 |

**SCA Scan Results:**
| Severity | Package | Issue |
|----------|---------|-------|
| High | express@4.17.1 | Open Redirect |
| Medium | lodash@4.17.15 | Prototype Pollution |

**Selected:** Path Traversal (High, Code) - 2 instances
**Routing to:** /snyk-code-fix

---

### snyk-code-fix: Remediation

**Target Vulnerabilities:**
- javascript/PT at src/api/files.ts:45
- javascript/PT at src/api/files.ts:112

**Fix Plan:**
- Root Cause: User input used directly in file path
- Fix: Canonicalize path + validate against allowed base directory

**Applying fixes...**
- Fixed line 112 (bottom-up order)
- Fixed line 45

**Validation:**
- Re-scan: ✅ Both instances resolved
- Tests: ✅ Pass
- Lint: ✅ Pass

---

### snyk-fix: Phase 4 - Summary

## Remediation Summary

| Remediated Vulnerability | Path Traversal (CWE-22) |
|--------------------------|------------------------|
| **Snyk ID** | javascript/PT |
| **Severity** | High |
| **Instances Fixed** | 2 |

| # | File | Line | Status |
|---|------|------|--------|
| 1 | src/api/files.ts | 45 | ✅ Fixed |
| 2 | src/api/files.ts | 112 | ✅ Fixed |

### What Was Fixed
User-controlled file paths were being used without validation, allowing attackers to access files outside the intended directory. Added path canonicalization and base directory validation.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## Should I create a PR for this fix? (yes / no)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## User: yes

---

### create-security-pr: Creating PR

git checkout -b fix/security-cwe-22-path-traversal
git add src/api/files.ts
git commit -m "fix(security): validate file paths to prevent traversal

Resolves: javascript/PT
Severity: High"
git push -u origin fix/security-cwe-22-path-traversal
gh pr create --title "Security: Fix Path Traversal vulnerability"

## PR Created Successfully
- **PR URL**: https://github.com/org/repo/pull/123
- **Branch**: fix/security-cwe-22-path-traversal
```

## Installation

Copy all files to your project's Cursor rules directory:

```bash
mkdir -p .cursor/rules
cp *.md /path/to/project/.cursor/rules/
```

## Advantages of Composite Approach

1. **Modularity** - Each command has a single responsibility
2. **Direct Access** - Can invoke sub-commands directly when needed
3. **Easier Testing** - Test individual commands in isolation
4. **Flexible Customization** - Modify one command without affecting others
5. **Clear Separation** - Code fixes vs dependency fixes vs PR creation

