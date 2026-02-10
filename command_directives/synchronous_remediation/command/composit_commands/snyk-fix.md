# Snyk Fix

## Overview
Unified entry point for Snyk security remediation. Parses input, runs discovery, and routes to the appropriate specialized fix command.

**Workflow**: Parse → Discover → Route → Fix → Summary → (Optional) PR

## Example Usage

| Command | Behavior |
|---------|----------|
| `/snyk-fix` | Auto-detect scan type, fix highest priority issue (all instances) |
| `/snyk-fix code` | SAST scan only, fix highest priority code issue (all instances in file) |
| `/snyk-fix sca` | SCA scan only, fix highest priority dependency issue |
| `/snyk-fix SNYK-JS-LODASH-1018905` | Fix specific Snyk issue by ID |
| `/snyk-fix CVE-2021-44228` | Find and fix specific CVE |
| `/snyk-fix lodash` | Fix highest priority issue in lodash package |
| `/snyk-fix server.ts` | Code scan on file, fix highest priority issue (all instances) |
| `/snyk-fix sca express` | Fix highest priority issue in express package |
| `/snyk-fix XSS` | Fix all XSS vulnerabilities in highest priority file |

---

## Phase 1: Input Parsing

Parse user input to extract:
- **scan_type**: Explicit (`code`, `sca`, `both`) or infer from context
- **target_vulnerability**: Specific issue ID, CVE, package name, file reference, or vulnerability type
- **target_path**: File or directory to focus on (defaults to project root)

### Scan Type Detection Rules (in priority order)

1. **Explicit code**: User says "code", "sast", "static" → route to `/snyk-code-fix`
2. **Explicit sca**: User says "sca", "dependency", "package", "npm", "pip", "maven" → route to `/snyk-sca-fix`
3. **Vulnerability ID provided**: 
   - Starts with `SNYK-` → run both scans to locate it, then route based on result
   - Contains `CVE-` → run both scans to find it
4. **Vulnerability type provided**: User mentions type like "XSS", "SQL injection", "path traversal" → route to `/snyk-code-fix`
5. **File reference**: User mentions `.ts`, `.js`, `.py`, etc. file → route to `/snyk-code-fix` on that file
6. **Package reference**: User mentions known package name (e.g., "lodash", "express") → route to `/snyk-sca-fix`
7. **Default (no hints)**: Run BOTH scans, select highest priority issue, route accordingly

---

## Phase 2: Discovery

**Goal**: Run scan(s) and identify the vulnerability type to fix, including ALL instances of that type in the same file (for code vulnerabilities)

### Step 2.1: Run Security Scan(s)

Based on scan type detection:
- **Code only**: Run `snyk_code_scan` with `path` set to project root or specific file
- **SCA only**: Run `snyk_sca_scan` with `path` set to project root
- **Both**: Run both scans in parallel

### Step 2.2: Select Target Vulnerability Type

**If user specified a vulnerability:**
- Search scan results for matching issue (by ID, CVE, package name, vulnerability type, or description)
- If NOT found: Report "Vulnerability not found in scan results" and STOP
- If found: Note whether it's a Code or SCA issue

**If user did NOT specify a vulnerability:**
- From ALL scan results, select the highest priority vulnerability TYPE using this priority:
  1. Critical severity with known exploit
  2. Critical severity
  3. High severity with known exploit  
  4. High severity
  5. Medium severity
  6. Low severity
- Within same priority: prefer issues with available fixes/upgrades

### Step 2.3: Group All Instances (Code Vulnerabilities Only)

**⚠️ IMPORTANT for Code vulnerabilities**: After selecting the vulnerability type, find ALL instances of that same vulnerability type in the same file:

- Same vulnerability ID (e.g., `javascript/PT`, `javascript/XSS`, `python/SQLi`)
- In the same file

**Example**: If scan finds:
```
High    Path Traversal    src/api/files.ts:45    javascript/PT
High    Path Traversal    src/api/files.ts:112   javascript/PT  
High    XSS               src/api/files.ts:78    javascript/XSS
```

And Path Traversal is selected as highest priority, target BOTH lines 45 and 112.

### Step 2.4: Document Target and Route

**For single instance or SCA vulnerabilities:**
```
## Target Vulnerability
- **ID**: [Snyk Issue ID or CVE]
- **Type**: [SCA | Code]
- **Severity**: [Critical | High | Medium | Low]
- **Package/File**: [affected package@version OR file:line]
- **Title**: [vulnerability title]
- **Fix Available**: [Yes/No - upgrade to X.Y.Z OR code change required]

Routing to: [/snyk-code-fix | /snyk-sca-fix]
```

**For multiple instances of same code vulnerability:**
```
## Target Vulnerability
- **ID**: [Snyk Issue ID] (e.g., javascript/PT)
- **Type**: Code
- **Severity**: [Critical | High | Medium | Low]
- **Title**: [vulnerability title]
- **CWE**: [CWE-XXX if available]
- **Instances to Fix**: [count]

| # | File | Line | Description |
|---|------|------|-------------|
| 1 | [file] | [line] | [brief context] |
| 2 | [file] | [line] | [brief context] |

Routing to: /snyk-code-fix
```

---

## Phase 3: Route to Specialized Command

Based on the vulnerability type:

### If Code Vulnerability:
Execute the workflow defined in `/snyk-code-fix` with the target vulnerability details.
- Pass ALL instances of the vulnerability type to be fixed together
- `/snyk-code-fix` will fix all instances in a single operation

### If SCA Vulnerability:
Execute the workflow defined in `/snyk-sca-fix` with the target vulnerability details.

**⚠️ IMPORTANT**: After the specialized command outputs its Summary, you MUST continue to Phase 4 below. Do NOT stop at the specialized command's summary.

---

## Phase 4: Summary & PR Prompt

**This phase runs AFTER the specialized fix command completes successfully.**

### Step 4.1: Display Remediation Summary

Use this compact format (must fit in one screen):

**For single instance:**
```
## Remediation Summary

| Remediated Vulnerability | [Title] ([CWE-XXX]) |
|---------------|---------------------|
| **Snyk ID** | [javascript/PT, python/XSS, SNYK-JS-XXX, etc.] |
| **Severity** | [Critical/High/Medium/Low] |
| **File** | `[filename:lines]` |

### What Was Fixed
[2-3 sentence plain-English explanation of the vulnerability and how it was fixed. No code snippets.]

### Validation

| Check | Result |
|-------|--------|
| Snyk Re-scan | ✅ Resolved / ❌ Still present |
| TypeScript/Build | ✅ Pass / ❌ Fail |
| Linting | ✅ Pass / ❌ Fail |
| Tests | ✅ Pass / ⚠️ Skipped (reason) / ❌ Fail |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## Should I create a PR for this fix? (yes / no)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**For multiple instances fixed:**
```
## Remediation Summary

| Remediated Vulnerability | [Title] ([CWE-XXX]) |
|---------------|---------------------|
| **Snyk ID** | [javascript/PT, python/XSS, etc.] |
| **Severity** | [Critical/High/Medium/Low] |
| **Instances Fixed** | [count] |

| # | File | Line | Status |
|---|------|------|--------|
| 1 | [file] | [line] | ✅ Fixed |
| 2 | [file] | [line] | ✅ Fixed |

### What Was Fixed
[2-3 sentence plain-English explanation of the vulnerability and how it was fixed. No code snippets.]

### Validation

| Check | Result |
|-------|--------|
| Snyk Re-scan | ✅ Resolved ([count] instances) / ❌ Still present |
| TypeScript/Build | ✅ Pass / ❌ Fail |
| Linting | ✅ Pass / ❌ Fail |
| Tests | ✅ Pass / ⚠️ Skipped (reason) / ❌ Fail |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## Should I create a PR for this fix? (yes / no)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Rules for this summary:**
- Do NOT include code snippets (before/after)
- Do NOT list remaining issues in codebase
- Keep "What Was Fixed" to 2-3 sentences max
- Use visual separator (━) around PR prompt to make it stand out

### Step 4.2: Wait for User Response

**⚠️ IMPORTANT**: Do NOT proceed until the user explicitly confirms.

### Step 4.3: Create PR (if confirmed)

If user says "yes", execute the workflow defined in `/create-security-pr`.

---

## Error Handling

### Authentication Errors
- Run `snyk_auth` and retry once
- If still failing: STOP and ask user to authenticate manually

### Scan Timeout/Failure
- Retry once
- If still failing: STOP and report the error

### Vulnerability Not Found
- If user specified a vulnerability that doesn't appear in scan results
- Report clearly and STOP (don't guess or fix something else)

---

## Constraints

1. **One vulnerability TYPE per run** - Select and fix ONE vulnerability type (but ALL instances of that type in the same file for code vulnerabilities)
2. **Clear routing** - Always document which specialized command is being invoked
3. **User confirmation for PR** - Never auto-create PRs
4. **Always prompt for PR** - Every successful fix MUST end with the PR prompt question

---

## Completion Checklist

Before ending the conversation, verify ALL are complete:

- [ ] Vulnerability type identified and documented (including all instances for code vulns)
- [ ] Routed to correct specialized command
- [ ] Fix applied and validated (re-scan shows ALL instances resolved)
- [ ] Tests pass (or failures documented)
- [ ] Summary displayed to user (with instance count if multiple)
- [ ] **PR prompt asked** ← Do NOT skip this step
