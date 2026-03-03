---
name: snyk-batch-fix
description: Batch fix vulnerabilities detected by the Secure at Inception hook
---

# Snyk Batch Fix

## Overview
Fixes a batch of code vulnerabilities that were pre-scanned by the Secure at Inception hook. No discovery scan is needed -- vulnerability data (file, line, type, description) is provided in the input. This command is designed for in-development code and does NOT prompt for a PR.

**Workflow**: Parse → Group → Fix → Validate → SCA (if applicable) → Summary

**Invocation**: This command is typically invoked automatically by the Secure at Inception stop hook via `followup_message`, not by the user directly. The stop hook passes a markdown table of pre-scanned vulnerabilities.

---

## Phase 1: Parse Input

**No scan is needed.** The vulnerability data is already provided in the input table.

### Step 1.1: Parse Vulnerability Table

Parse the markdown table from the input. Each row contains:
- **#**: Row number
- **Severity**: critical, high, medium, low
- **ID**: Snyk vulnerability ID (e.g., `javascript/PT`, `python/SQLi`)
- **Title**: Human-readable name (e.g., "Path Traversal")
- **CWE**: CWE identifier (e.g., `CWE-22`) or `-` if unavailable
- **File**: Relative path to the affected file
- **Line**: Starting line number of the vulnerability
- **Description**: Snyk's explanation of the issue

### Step 1.2: Group Vulnerabilities

Group the parsed vulnerabilities for efficient fixing:

1. **Group by file** -- fix all vulns in one file before moving to the next
2. **Within each file, group by vulnerability type** (ID) -- same vuln type gets the same fix pattern
3. **Sort files by highest severity** -- fix the most critical files first
4. **Within each file, sort by line number descending** -- fix from bottom to top to avoid line shifts

### Step 1.3: Document Targets

```
## Batch Fix Plan
- **Total vulnerabilities**: [count]
- **Files affected**: [count]
- **Vulnerability types**: [list of unique IDs]

| File | Vuln Types | Count | Highest Severity |
|------|-----------|-------|-----------------|
| [file1] | [IDs] | [n] | [severity] |
| [file2] | [IDs] | [n] | [severity] |
```

---

## Phase 2: Remediation

For each file (in severity-priority order):

### Step 2.1: Understand the Vulnerabilities
- Read the affected file
- Review ALL vulnerable locations for this file
- Identify the vulnerability types present:
  - **Injection** (SQL, Command, LDAP, etc.)
  - **XSS** (Cross-Site Scripting)
  - **Path Traversal**
  - **Sensitive Data Exposure**
  - **Insecure Deserialization**
  - **Security Misconfiguration**
  - **Cryptographic Issues**
  - Other (refer to the Description from the input table)

### Step 2.2: Plan the Fix

For each vulnerability type group in this file:
```
### Fix: [Vulnerability Title] ([count] instances)
- **Root Cause**: [why the code is vulnerable]
- **Fix Approach**: [what will be changed]
- **Security Mechanism**: [what protection is being added]
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

### Step 2.3: Apply Fixes

- **Fix from bottom to top** (highest line number first) to avoid line shifts
- Fix ALL instances of each vulnerability type using a consistent pattern
- Make the minimal code change needed at each location
- Prefer standard library/framework security features over custom solutions
- Consider creating a shared helper function if:
  - 3+ instances exist with identical fix pattern
  - The helper improves readability without over-engineering
- Add comments explaining security-relevant changes if non-obvious
- Do NOT refactor unrelated code
- Do NOT change business logic

**Repeat for each file** until all vulnerabilities are addressed.

---

## Phase 3: Validation

### Step 3.1: Re-run Code Scan
- Run `snyk_code_scan` with `path` set to the project root
- Check if the originally reported vulnerabilities are resolved

**If vulnerabilities still present:**
- Review the fix attempt for each remaining instance
- Try alternative approach
- Maximum 3 total attempts per vulnerability type, then document as unfixed

**If NEW vulnerabilities introduced:**
- Code fixes must be clean -- no new vulnerabilities allowed
- Attempt to fix any new issues introduced by the fix
- Iterate until clean (max 3 total attempts)
- If unable to produce clean fix: revert that specific fix and document

### Step 3.2: Run Tests
- Execute project tests (`npm test`, `pytest`, etc.)
- If tests fail due to the fix:
  - Prefer adjusting the fix over changing tests
  - Only modify tests if the fix legitimately changes expected behavior
  - Apply mechanical fixes only (renamed imports, etc.)
  - Maximum 2 attempts to resolve test failures

### Step 3.3: Run Linting
- Run project linter if configured
- Fix any formatting issues introduced

---

## Phase 4: SCA (If Applicable)

**Only execute if the input includes a "Manifest Files Changed" section.**

### Step 4.1: Run SCA Scan
- Run `snyk_sca_scan` with `path` set to the project root
- Review results for dependency vulnerabilities

### Step 4.2: Fix Highest Priority Dependency Issue
If SCA vulnerabilities are found:
- Select the highest priority issue (Critical > High > Medium > Low)
- Apply minimal upgrade to fix the vulnerability
- Use the LOWEST version that fixes the issue
- Regenerate lockfile

### Step 4.3: Validate SCA Fix
- Re-run `snyk_sca_scan`
- Verify the target vulnerability is resolved
- Check for regression (new vulns introduced by upgrade)

---

## Phase 5: Summary

### Step 5.1: Display Remediation Summary

```
## Batch Remediation Summary

### Code Vulnerabilities Fixed
| # | Severity | Title | File | Line | Status |
|---|----------|-------|------|------|--------|
| 1 | high | Path Traversal | src/api/files.ts | 45 | Fixed |
| 2 | high | Path Traversal | src/api/files.ts | 112 | Fixed |
| 3 | medium | XSS | src/views/render.ts | 33 | Fixed |

**Total fixed**: [count] / [total]

### What Was Fixed
[Brief summary of fix approaches applied, grouped by vulnerability type. 2-3 sentences per type.]

### SCA Results (if applicable)
- **Package**: [package@old] -> [package@new]
- **Issues Fixed**: [count]

### Validation
| Check | Result |
|-------|--------|
| Snyk Code Re-scan | Resolved ([count]) / Still present ([count]) |
| Snyk SCA Re-scan | Resolved / N/A |
| Tests | Pass / Fail / Skipped |
| Linting | Pass / Fail |
```

### Step 5.2: Send Feedback to Snyk
After successful fixes, report the remediation:
```
snyk_send_feedback with:
- fixedExistingIssuesCount: [total code + SCA issues fixed]
- preventedIssuesCount: 0
- path: [absolute project path]
```

### Step 5.3: End Cleanly

**Do NOT prompt for a PR.** This command is invoked during active development.
The developer will commit and create PRs through their normal workflow.

---

## Error Handling

### Unfixable Code Vulnerability
If a vulnerability cannot be fixed automatically:
1. Document why (complex refactoring needed, unclear fix, architectural issue)
2. Add a TODO comment at the affected location with context
3. Report as "unfixed" in the summary
4. Do NOT leave partial/broken fixes -- revert if incomplete

### Partial Success
If some vulnerabilities are fixed but others fail:
1. Keep the successful fixes
2. Document which remain unfixed and why
3. Add TODO comments for unfixed instances
4. Report partial success in summary with clear breakdown

### Rollback Triggers
Revert ALL changes for a specific file if:
- Unable to produce clean fix after 3 attempts (new vulnerabilities introduced)
- Tests fail and cannot be reasonably fixed
- Fix would require changing business logic

Do NOT revert fixes in other files that succeeded.

---

## Constraints

1. **No discovery scan** -- Vulnerabilities are provided in input, not discovered
2. **Batch processing** -- Fix all provided vulnerabilities in one pass
3. **No PR prompt** -- This is in-development code, not a standalone fix workflow
4. **Minimal changes** -- Only modify what's necessary at each location
5. **No new vulnerabilities** -- Code fixes must be clean
6. **Preserve functionality** -- Tests must pass
7. **No scope creep** -- Don't refactor or "improve" unrelated code
8. **Consistent fixes** -- Apply the same fix pattern across all instances of the same type
9. **Bottom-to-top** -- Fix highest line numbers first within each file

---

## Completion Checklist

Before ending, verify:

- [ ] All vulnerability locations from the input table have been addressed
- [ ] Re-scan confirms fixes (or partial success documented)
- [ ] Tests pass (or failures documented)
- [ ] Summary displayed with per-vulnerability status
- [ ] Snyk feedback sent with correct count
- [ ] SCA scan run if manifest files were listed
- [ ] **No PR prompt** -- end cleanly after summary
