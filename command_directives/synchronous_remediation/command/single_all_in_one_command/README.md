# Single All-in-One Command

This directory contains a self-contained security remediation command that handles the complete workflow in a single file. No external command dependencies required.

## Overview

The all-in-one `snyk-fix` command combines all security remediation logic into one comprehensive instruction set:

- **Input parsing** - Detects scan type and target
- **Discovery** - Runs SAST and/or SCA scans
- **Code remediation** - Fixes code vulnerabilities (XSS, SQLi, Path Traversal, etc.)
- **SCA remediation** - Upgrades vulnerable dependencies
- **Validation** - Re-scans and runs tests
- **PR creation** - Full git workflow included

## File

| File | Purpose |
|------|---------|
| `snyk-fix.md` | Complete security fix workflow |

## Use Cases

### Basic Usage
```
/snyk-fix                    # Auto-detect, fix highest priority
/snyk-fix code               # SAST only
/snyk-fix sca                # Dependencies only
```

### Targeted Fixes
```
/snyk-fix CVE-2021-44228     # Specific CVE
/snyk-fix SNYK-JS-LODASH-123 # Specific Snyk ID
/snyk-fix XSS                # Vulnerability type
/snyk-fix lodash             # Package name
/snyk-fix server.ts          # Specific file
```

## Installation

Copy the command file to your project's rules directory:

```bash
mkdir -p .cursor/rules
cp snyk-fix.md /path/to/project/.cursor/rules/
```

## Advantages of All-in-One Approach

1. **Simple Setup** - One file to copy
2. **No Dependencies** - Self-contained logic
3. **Easy to Understand** - Complete flow in one place
4. **Quick Start** - Minimal configuration
5. **Portable** - Easy to share and replicate

## When to Use

Choose the all-in-one command when:
- You want the simplest possible setup
- Your team doesn't need granular control over individual phases
- You prefer having the complete workflow documented in one place
- You're evaluating or prototyping before committing to a more complex setup
