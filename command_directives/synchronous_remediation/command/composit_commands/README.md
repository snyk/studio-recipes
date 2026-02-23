# Composite Commands

This directory contains a modular set of security remediation commands. The composite architecture separates concerns into specialized commands that can be chained together or used independently.

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

## Installation

Copy all files to your project's rules directory:

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
