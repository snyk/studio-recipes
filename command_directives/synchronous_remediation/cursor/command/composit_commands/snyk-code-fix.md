# Snyk Code Fix (SAST)

## Overview
Fixes code vulnerabilities identified by Snyk SAST scanning. Can be invoked directly or via `/snyk-fix`.

**Workflow**: Scan → Analyze → Fix All Instances → Validate → Summary

## Example Usage

| Command | Behavior |
|---------|----------|
| `/snyk-code-fix` | Scan project, fix highest priority code issue (all instances in file) |
| `/snyk-code-fix server.ts` | Scan specific file, fix highest priority issue (all instances) |
| `/snyk-code-fix SNYK-CODE-1234` | Fix specific code vulnerability by ID |
| `/snyk-code-fix XSS` | Fix all XSS vulnerabilities in highest priority file |

---

## Phase 1: Discovery

**Skip if target vulnerability was provided by `/snyk-fix` dispatcher.**

### Step 1.1: Run Code Scan
- Run `snyk_code_scan` with `path` set to project root or specific file
- Parse results for code vulnerabilities

### Step 1.2: Select Target Vulnerability Type

From scan results, select the highest priority **vulnerability type** using this priority:
1. Critical severity with known exploit
2. Critical severity
3. High severity with known exploit  
4. High severity
5. Medium severity
6. Low severity

### Step 1.3: Group All Instances

**⚠️ IMPORTANT**: After selecting the vulnerability type, find ALL instances of that same vulnerability type:
- Same vulnerability ID (e.g., `javascript/PT`, `javascript/XSS`, `python/SQLi`)
- In the same file

**Example**: If scan finds:
```
High    Path Traversal    src/api/files.ts:45    javascript/PT
High    Path Traversal    src/api/files.ts:112   javascript/PT  
High    XSS               src/api/files.ts:78    javascript/XSS
```

And Path Traversal is selected as highest priority, target BOTH lines 45 and 112.

### Step 1.4: Document Targets

```
## Target Code Vulnerabilities
- **Vulnerability Type**: [Title] ([Snyk ID])
- **Severity**: [Critical | High | Medium | Low]
- **CWE**: [CWE-XXX if available]
- **Instances to Fix**: [count]

| # | File | Line | Description |
|---|------|------|-------------|
| 1 | [file] | [line] | [brief context] |
| 2 | [file] | [line] | [brief context] |
```

---

## Phase 2: Remediation

### Step 2.1: Understand the Vulnerability
- Read the affected file and ALL vulnerable locations
- Identify the vulnerability type:
  - **Injection** (SQL, Command, LDAP, etc.)
  - **XSS** (Cross-Site Scripting)
  - **Path Traversal**
  - **Sensitive Data Exposure**
  - **Insecure Deserialization**
  - **Security Misconfiguration**
  - **Cryptographic Issues**
  - Other (check Snyk description)
- Review Snyk's remediation guidance if provided
- Look for patterns across instances (often the same fix approach applies)

### Step 2.2: Plan the Fix

Before implementing, document the approach:
```
## Fix Plan
- **Vulnerability Type**: [type]
- **Root Cause**: [why the code is vulnerable]
- **Fix Approach**: [what will be changed]
- **Security Mechanism**: [what protection is being added]
- **Instances Affected**: [count] locations in [file]
```

Common fix patterns:
| Vulnerability | Fix Pattern |
|---------------|-------------|
| SQL Injection | Parameterized queries / prepared statements |
| Command Injection | Input validation + shell escaping or avoid shell |
| Path Traversal | Canonicalize path + validate against allowed base |
| XSS | Output encoding / sanitization appropriate to context |
| Sensitive Data Exposure | Remove/mask data, use secure headers |
| Hardcoded Secrets | Move to environment variables / secrets manager |

### Step 2.3: Apply the Fix to ALL Instances

- Fix ALL identified instances of the vulnerability type in the file
- Apply consistent fix pattern across all instances
- Make the minimal code change needed at each location
- Prefer standard library/framework security features over custom solutions
- Consider creating a shared helper function if:
  - 3+ instances exist with identical fix pattern
  - The helper improves readability without over-engineering
- Add comments explaining security-relevant changes if non-obvious
- Do NOT refactor unrelated code
- Do NOT change business logic

**Order of fixes**: Fix from bottom of file to top (highest line number first) to avoid line number shifts affecting subsequent fixes.

---

## Phase 3: Validation

### Step 3.1: Re-run Code Scan
- Run `snyk_code_scan` on the same target
- Verify ALL targeted vulnerability instances are NO LONGER reported

**If any vulnerability instances still present:**
- Review the fix attempt for that specific instance
- Try alternative approach
- Maximum 3 total attempts per instance, then STOP and report partial success/failure

**If NEW vulnerabilities introduced:**
- Code fixes must be clean — no new vulnerabilities allowed
- Attempt to fix any new issues introduced by your fix
- Iterate until clean (max 3 total attempts)
- If unable to produce clean fix: Revert ALL changes and report failure

### Step 3.2: Run Tests
- Execute project tests (`npm test`, `pytest`, etc.)
- If tests fail due to the fix:
  - Prefer adjusting the fix over changing tests
  - Only modify tests if the fix legitimately changes expected behavior
  - Maximum 2 attempts to resolve test failures

### Step 3.3: Run Linting
- Run project linter if configured
- Fix any formatting issues introduced

---

## Phase 4: Summary

Output the remediation summary:

```
## Code Fix Summary

### Vulnerabilities Fixed
- **Type**: [Vulnerability Title] ([Snyk ID])
- **Severity**: [severity] → **Resolved**
- **CWE**: [CWE-XXX]
- **Instances Fixed**: [count]

| # | File | Line | Status |
|---|------|------|--------|
| 1 | [file] | [line] | ✅ Fixed |
| 2 | [file] | [line] | ✅ Fixed |

### Fix Applied
[Description of the fix pattern applied across all instances]

### Files Changed
- [list of files modified]

### Validation Results
- **Re-scan**: PASS ([count] vulnerabilities no longer detected)
- **Tests**: [PASS | FAIL - details]
- **Lint**: [PASS | FAIL - details]

### Remaining Work
- [Any TODOs added]
- [Any manual review needed]
- [Other code vulnerabilities still present - count by severity]
```

### Step 4.2: Send Feedback to Snyk
After successful fix, report the remediation with the ACTUAL count of fixed instances:
```
snyk_send_feedback with:
- fixedExistingIssuesCount: [number of instances fixed]
- preventedIssuesCount: 0
- path: [absolute project path]
```

---

## Error Handling

### Unfixable Vulnerability
If the vulnerability cannot be fixed automatically:
1. Document why it cannot be fixed (complex refactoring needed, unclear fix, etc.)
2. Add TODO comment in the affected file with context
3. Report to user with manual remediation suggestions
4. Do NOT leave partial/broken fixes

### Partial Success
If some instances are fixed but others fail:
1. Keep the successful fixes
2. Document which instances remain unfixed and why
3. Add TODO comments for unfixed instances
4. Report partial success in summary with clear breakdown

### Rollback Trigger
Revert ALL changes if:
- Unable to produce clean fix after 3 attempts (new vulnerabilities introduced)
- Tests fail and cannot be reasonably fixed
- Fix would require changing business logic

---

## Constraints

1. **One vulnerability TYPE per run** - Fix all instances of ONE vulnerability type in a file
2. **Minimal changes** - Only modify what's necessary at each location
3. **No new vulnerabilities** - Code fixes must be clean
4. **Preserve functionality** - Tests must pass
5. **No scope creep** - Don't refactor or "improve" other code
6. **Consistent fixes** - Apply the same fix pattern across all instances

---

## Phase 5: Handoff

**⚠️ CRITICAL**: After completing the Summary (Phase 4), you MUST continue with the PR prompt:

### If invoked via `/snyk-fix`:
Return control to `/snyk-fix` Phase 4.2 (PR Prompt).

### If invoked directly via `/snyk-code-fix`:
Execute the PR prompt inline:

> **Would you like me to create a Pull Request for this fix?**
> 
> This will:
> - Create a feature branch
> - Commit the changes
> - Push to remote
> - Open a PR for review
>
> Reply **yes** to proceed, or **no** to keep the changes local.

**Do NOT end the conversation without asking this question.**
