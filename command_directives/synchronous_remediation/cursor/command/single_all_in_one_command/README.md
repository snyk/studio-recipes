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

## Mock Example: Complete Workflow

```markdown
## User: /snyk-fix sca

### Phase 1: Input Parsing
- Explicit type: SCA
- Target: None (highest priority)

### Phase 2: Discovery
Running SCA scan on /project/root...

**Vulnerabilities Found:**
| Severity | Package | Vulnerability | Fix Version |
|----------|---------|---------------|-------------|
| Critical | log4j@2.14.1 | Remote Code Execution | 2.17.0 |
| High | express@4.17.1 | Open Redirect | 4.18.2 |
| Medium | lodash@4.17.15 | Prototype Pollution | 4.17.21 |

**Selected:** log4j@2.14.1 - Critical RCE

### Phase 4: Remediation (SCA)

**Analysis:**
- Package: log4j
- Current: 2.14.1
- Fix: 2.17.0
- Type: Direct dependency
- Manifest: pom.xml

**Checking for breaking changes:**
grep -r "import.*log4j" → Found 12 imports

**Applying upgrade:**
```xml
<!-- Before -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version>
</dependency>

<!-- After -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.17.0</version>
</dependency>
```

**Regenerating dependencies:**
mvn dependency:resolve → Success

### Phase 5: Validation

**Re-scan Results:**
- log4j RCE: ✅ Resolved
- No new vulnerabilities introduced

**Additional Issues Fixed:**
| ID | Severity | Title |
|----|----------|-------|
| SNYK-JAVA-LOG4J-2314720 | Critical | RCE via JNDI |
| SNYK-JAVA-LOG4J-2320014 | High | DoS via recursive lookup |

**Total Fixed:** 2

**Tests:** ✅ Pass
**Build:** ✅ Pass

### Phase 6: Summary

## Remediation Summary

| Remediated Vulnerability | Log4j Remote Code Execution |
|--------------------------|---------------------------|
| **Snyk ID** | SNYK-JAVA-LOG4J-2314720 |
| **Severity** | Critical |
| **Package** | log4j@2.14.1 → log4j@2.17.0 |

### Additional Issues Fixed by This Upgrade
| ID | Severity | Title |
|----|----------|-------|
| SNYK-JAVA-LOG4J-2320014 | High | DoS via recursive lookup |

**Total issues fixed:** 2

### What Was Fixed
Upgraded log4j from 2.14.1 to 2.17.0 to address the Log4Shell vulnerability (CVE-2021-44228) which allowed remote code execution through JNDI injection in log messages.

### Validation
| Check | Result |
|-------|--------|
| Snyk Re-scan | ✅ Resolved |
| Build | ✅ Pass |
| Tests | ✅ Pass |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## Should I create a PR for this fix? (yes / no)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## User: yes

### Phase 7: Create PR

git checkout -b fix/security-SNYK-JAVA-LOG4J-2314720
git add pom.xml
git commit -m "fix(security): upgrade log4j to 2.17.0

Resolves: SNYK-JAVA-LOG4J-2314720
Severity: Critical"
git push -u origin fix/security-SNYK-JAVA-LOG4J-2314720

gh pr create \
  --title "Security: Upgrade log4j to fix RCE vulnerability" \
  --body "## Security Fix..."

## PR Created Successfully
- **PR URL**: https://github.com/org/repo/pull/456
- **Branch**: fix/security-SNYK-JAVA-LOG4J-2314720
- **Status**: Ready for review
```

## Installation

Copy the command file to your project's Cursor rules directory:

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

