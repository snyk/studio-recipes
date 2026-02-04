---
name: snyk-fix
description: |
  Complete security remediation workflow. Scans code for vulnerabilities using Snyk, 
  fixes them, validates the fix, and optionally creates a PR. Supports both single-issue
  and batch mode for multiple vulnerabilities. Use this skill when:
  - User asks to fix security vulnerabilities
  - User mentions "snyk fix", "security fix", or "remediate vulnerabilities"
  - User wants to fix a specific CVE, Snyk ID, or vulnerability type (XSS, SQL injection, path traversal, etc.)
  - User wants to upgrade a vulnerable dependency
  - User asks to "fix all" vulnerabilities or "fix all high/critical" issues (batch mode)
allowed-tools:
  - mcp_snyk_snyk_code_scan
  - mcp_snyk_snyk_sca_scan
  - mcp_snyk_snyk_auth
  - mcp_snyk_snyk_send_feedback
  - Read
  - Write
  - Edit
  - Bash
  - Grep
---

# Snyk Fix (All-in-One)

Complete security remediation workflow in a single command. Scans for vulnerabilities, fixes them, validates the fix, and optionally creates a PR.

**Workflow**: Parse → Scan → Analyze → Fix → Validate → Summary → (Optional) PR

**Modes**:
- **Single Mode** (default): Fix one vulnerability type at a time
- **Batch Mode**: Fix multiple vulnerabilities in priority order

## Example Triggers

### Single Mode (One Issue)

| User Request | Behavior |
|--------------|----------|
| "fix security issues" | Auto-detect scan type, fix highest priority issue (all instances) |
| "fix code vulnerabilities" | SAST scan only, fix highest priority code issue (all instances in file) |
| "fix dependency vulnerabilities" | SCA scan only, fix highest priority dependency issue |
| "fix SNYK-JS-LODASH-1018905" | Fix specific Snyk issue by ID |
| "fix CVE-2021-44228" | Find and fix specific CVE |
| "fix vulnerabilities in lodash" | Fix highest priority issue in lodash package |
| "fix security issues in server.ts" | Code scan on file, fix highest priority issue (all instances) |
| "fix XSS vulnerabilities" | Fix all XSS vulnerabilities in highest priority file |
| "fix path traversal" | Fix all path traversal vulnerabilities |

### Batch Mode (Multiple Issues)

| User Request | Behavior |
|--------------|----------|
| "fix all security issues" | Fix ALL vulnerabilities by priority (Critical → Low) |
| "fix all critical vulnerabilities" | Fix only Critical severity issues |
| "fix all high and critical" | Fix Critical and High severity issues |
| "fix all code vulnerabilities" | Fix all SAST issues in the project |
| "fix all dependency issues" | Fix all SCA issues in the project |
| "fix top 5 vulnerabilities" | Fix the 5 highest priority issues |
| "fix all issues in src/" | Fix all vulnerabilities in specified directory |

---

## Batch Mode Overview

Batch mode fixes multiple vulnerabilities in a single session. Use when the user says "all", "batch", or specifies a severity filter.

### Batch Mode Workflow

```
1. Scan entire project (SAST + SCA)
2. Filter by severity/type if specified
3. Group vulnerabilities by type and priority
4. For each group (in priority order):
   a. Fix all instances of that vulnerability type
   b. Validate the fix
   c. Track results
5. Generate comprehensive summary
6. Prompt for single PR with all fixes
```

### Batch Mode Limits

| Setting | Value | Notes |
|---------|-------|-------|
| Max vulnerabilities | 20 | To avoid overwhelming changes |
| Max files modified | 15 | To keep PRs reviewable |
| Timeout per fix | 3 attempts | Same as single mode |
| Stop on failure | Configurable | Can continue or stop |

### Batch Priority Order

1. Critical with known exploit
2. Critical without exploit
3. High with known exploit
4. High without exploit
5. Medium severity
6. Low severity

Within same priority: Code (SAST) issues before SCA issues (code fixes are typically more urgent).

---

## Phase 1: Input Parsing

Parse user input to extract:
- **mode**: Single (default) or Batch (if user says "all", "batch", or specifies count/severity filter)
- **scan_type**: Explicit (`code`, `sca`, `both`) or infer from context
- **target_vulnerability**: Specific issue ID, CVE, package name, file reference, or vulnerability type
- **target_path**: File or directory to focus on (defaults to project root)
- **severity_filter**: For batch mode - which severities to include
- **max_fixes**: For batch mode - maximum vulnerabilities to fix (default: 20)

### Mode Detection Rules

**Batch Mode Indicators**:
- User says "all" (e.g., "fix all vulnerabilities")
- User specifies severity filter (e.g., "fix all high and critical")
- User specifies count (e.g., "fix top 5")
- User says "batch" explicitly

**Single Mode** (default):
- User specifies a single vulnerability ID
- User mentions one vulnerability type
- User references a specific file
- No batch indicators present

### Scan Type Detection Rules (in priority order)

1. **Explicit code**: User says "code", "sast", "static" → Code scan
2. **Explicit sca**: User says "sca", "dependency", "package", "npm", "pip", "maven" → SCA scan
3. **Vulnerability ID provided**: 
   - Starts with `SNYK-` → run both scans to locate it
   - Contains `CVE-` → run both scans to find it
4. **Vulnerability type provided**: User mentions type like "XSS", "SQL injection", "path traversal" → Code scan
5. **File reference**: User mentions `.ts`, `.js`, `.py`, etc. file → Code scan on that file
6. **Package reference**: User mentions known package name (e.g., "lodash", "express") → SCA scan
7. **Default (no hints)**: Run BOTH scans, select highest priority issue

---

## Phase 1B: Batch Mode Planning (Skip if Single Mode)

**Only execute this phase if Batch Mode was detected in Phase 1.**

### Step 1B.1: Run Full Project Scan

Run comprehensive scans to discover all vulnerabilities:

```
Run both scans:
- mcp_snyk_snyk_code_scan with path = project root
- mcp_snyk_snyk_sca_scan with path = project root
```

### Step 1B.2: Filter Results

Apply user-specified filters:

| Filter | Example | Result |
|--------|---------|--------|
| Severity | "critical only" | Only Critical vulns |
| Severity | "high and critical" | Critical + High |
| Type | "code vulnerabilities" | Only SAST results |
| Type | "dependency issues" | Only SCA results |
| Path | "in src/" | Only vulns in src/ |
| Count | "top 5" | First 5 by priority |

### Step 1B.3: Group and Prioritize

Group vulnerabilities for efficient fixing:

1. **Group by type**: Same vulnerability ID in same file (code) or same package (SCA)
2. **Sort by priority**: Critical > High > Medium > Low
3. **Within priority**: Prefer issues with available fixes

### Step 1B.4: Generate Fix Plan

Display the batch fix plan to user:

```
## Batch Fix Plan

**Mode**: Batch Remediation
**Filter**: [severity/type/path filter if any]
**Total Vulnerabilities**: [count]

### Fix Order

| # | Type | Severity | Target | Instances |
|---|------|----------|--------|-----------|
| 1 | Code | High | SQL Injection in db.ts | 3 |
| 2 | SCA | Critical | log4j-core@2.14.1 | 1 |
| 3 | Code | High | XSS in api/render.ts | 2 |
| 4 | SCA | High | lodash@4.17.15 | 1 |
| 5 | Code | High | Path Traversal in files.ts | 4 |

**Estimated Changes**: [X files, Y packages]

### Proceed with batch fix? (yes/no/adjust)
```

**Wait for user confirmation before proceeding.**

If user says "adjust", allow them to modify the plan (exclude items, change order, etc.).

### Step 1B.5: Execute Batch Fixes

For each vulnerability group in the plan:

1. Execute the appropriate fix phase (Phase 3 for Code, Phase 4 for SCA)
2. Validate the fix (Phase 5)
3. Track result (success/failure/partial)
4. If failure and `stop_on_failure=true`: Stop and report
5. If failure and `stop_on_failure=false`: Continue to next item

**After all fixes attempted, proceed to Phase 6B (Batch Summary).**

---

## Phase 2: Discovery

**Goal**: Run scan(s) and identify the vulnerability type to fix, including ALL instances of that type in the same file (for code vulnerabilities)

### Step 2.1: Run Security Scan(s)

Based on scan type detection:
- **Code only**: Run `mcp_snyk_snyk_code_scan` with `path` set to project root or specific file
- **SCA only**: Run `mcp_snyk_snyk_sca_scan` with `path` set to project root
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

**IMPORTANT for Code vulnerabilities**: After selecting the vulnerability type, find ALL instances of that same vulnerability type in the same file:

- Same vulnerability ID (e.g., `javascript/PT`, `javascript/XSS`, `python/SQLi`)
- In the same file

**Example**: If scan finds:
```
High    Path Traversal    src/api/files.ts:45    javascript/PT
High    Path Traversal    src/api/files.ts:112   javascript/PT  
High    XSS               src/api/files.ts:78    javascript/XSS
```

And Path Traversal is selected as highest priority, target BOTH lines 45 and 112.

### Step 2.4: Document Target

**For Code vulnerabilities:**
```
## Target Vulnerability
- **Type**: Code (SAST)
- **ID**: [Snyk ID] (e.g., javascript/PT)
- **Severity**: [Critical | High | Medium | Low]
- **Title**: [vulnerability title]
- **CWE**: [CWE-XXX if available]
- **Instances to Fix**: [count]

| # | File | Line | Description |
|---|------|------|-------------|
| 1 | [file] | [line] | [brief context] |
| 2 | [file] | [line] | [brief context] |
```

**For SCA vulnerabilities:**
```
## Target Vulnerability
- **Type**: SCA (Dependency)
- **ID**: [Snyk Issue ID]
- **Severity**: [Critical | High | Medium | Low]
- **Package**: [package@current_version]
- **Title**: [vulnerability title]
- **Fix Version**: [minimum version that fixes]
- **Dependency Path**: [direct | transitive via X → Y → Z]
```

---

## Phase 3: Remediation (Code Vulnerabilities)

**Skip to Phase 4 if this is an SCA vulnerability.**

### Step 3.1: Understand the Vulnerability
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

### Step 3.2: Plan the Fix

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

### Step 3.3: Apply the Fix to ALL Instances

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

**Continue to Phase 5 (Validation).**

---

## Phase 4: Remediation (SCA Vulnerabilities)

**Skip to Phase 5 if this is a Code vulnerability (already handled in Phase 3).**

### Step 4.1: Analyze Dependency Path
- Document the full dependency path (direct → transitive → vulnerable)
- Identify manifest files to modify (`package.json`, `requirements.txt`, etc.)
- Determine if vulnerable package is direct or transitive

**For transitive dependencies:**
- Identify which direct dependency pulls in the vulnerable transitive
- Check if upgrading the direct dependency will pull in the fixed transitive
- If app directly imports the transitive: note this for breaking change analysis

### Step 4.2: Check for Breaking Changes
Search codebase for potential impact:
```bash
# Search for imports of the package
grep -r "from 'package'" --include="*.ts" --include="*.js"
grep -r "require('package')" --include="*.ts" --include="*.js"
```

If complex breaking changes detected:
- Add TODO comments with migration notes
- Note in summary that manual review is needed

### Step 4.3: Apply Minimal Upgrade
- Edit ONLY the necessary dependency in the manifest
- Use the LOWEST version that fixes the vulnerability
- Preserve file formatting and comments

**Example (package.json):**
```json
// Before
"lodash": "^4.17.15"

// After - minimal fix
"lodash": "^4.17.21"
```

### Step 4.4: Regenerate Lockfile

Run the appropriate install command:

| Package Manager | Command |
|-----------------|---------|
| npm (major upgrade) | `npm install <pkg>@<version>` |
| npm (minor/patch) | `npm install` |
| yarn | `yarn install` or `yarn upgrade <pkg>@<version>` |
| pip | `pip install -r requirements.txt` |
| maven | `mvn dependency:resolve` |

**If installation fails:**
- If sandbox/permission issue: retry with elevated permissions
- If dependency conflict: try a different version or note as unfixable
- Revert manifest changes if resolution completely fails
- Document the failure reason

---

## Phase 5: Validation

### Step 5.1: Re-run Security Scan
- Run `mcp_snyk_snyk_code_scan` or `mcp_snyk_snyk_sca_scan` on the same target
- Verify ALL targeted vulnerability instances are NO LONGER reported

**For Code vulnerabilities - If any instances still present:**
- Review the fix attempt for that specific instance
- Try alternative approach
- Maximum 3 total attempts per instance, then report partial success/failure

**For SCA vulnerabilities - If vulnerability still present:**
- Check if lockfile was properly updated
- Try explicit version install: `npm install <pkg>@<exact_version>`
- Maximum 3 attempts, then STOP and report failure

**If NEW vulnerabilities introduced:**

*For Code:*
- Code fixes must be clean — no new vulnerabilities allowed
- Attempt to fix any new issues introduced by your fix
- Iterate until clean (max 3 total attempts)
- If unable to produce clean fix: Revert ALL changes and report failure

*For SCA:*
- Check severity trade-off:
  - **New severity LOWER than fixed**: Accept (net security improvement)
  - **New severity EQUAL OR HIGHER**: Try higher version (up to 3 iterations)
  - If no clean version exists: Revert and report as unfixable

### Step 5.1a: Identify Additional Issues Fixed (SCA Only)
A single upgrade often fixes multiple vulnerabilities:
- Compare pre-fix and post-fix scan results
- Identify ALL vulnerabilities resolved by this upgrade
- Record each: ID, severity, title

### Step 5.2: Run Tests
- Execute project tests (`npm test`, `pytest`, etc.)
- If tests fail due to the fix:
  - Prefer adjusting the fix over changing tests
  - Only modify tests if the fix legitimately changes expected behavior
  - Apply mechanical fixes only (renamed imports, etc.)
  - Maximum 2 attempts to resolve test failures

### Step 5.3: Run Linting
- Run project linter if configured
- Fix any formatting issues introduced

---

## Phase 6: Summary & PR Prompt

### Step 6.1: Display Remediation Summary

**For Code vulnerabilities (single or multiple instances):**
```
## Remediation Summary

| Remediated Vulnerability | [Title] ([CWE-XXX]) |
|--------------------------|---------------------|
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

**For SCA vulnerabilities:**
```
## Remediation Summary

| Remediated Vulnerability | [Title] |
|--------------------------|---------|
| **Snyk ID** | [SNYK-JS-XXX / CVE-XXX] |
| **Severity** | [Critical/High/Medium/Low] |
| **Package** | [package@old] → [package@new] |

### Additional Issues Fixed by This Upgrade
| ID | Severity | Title |
|----|----------|-------|
| [Snyk ID] | [severity] | [title] |

**Total issues fixed**: [count]

### What Was Fixed
[2-3 sentence plain-English explanation of the vulnerability and how it was fixed.]

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

**Rules for this summary:**
- Do NOT include code snippets (before/after)
- Do NOT list remaining issues in codebase
- Keep "What Was Fixed" to 2-3 sentences max
- Use visual separator (━) around PR prompt to make it stand out

### Step 6.2: Send Feedback to Snyk
After successful fix, report the remediation using `mcp_snyk_snyk_send_feedback`:
- fixedExistingIssuesCount: [total issues fixed]
- preventedIssuesCount: 0
- path: [absolute project path]

### Step 6.3: Wait for User Response

**IMPORTANT**: Do NOT proceed until the user explicitly confirms.

---

## Phase 6B: Batch Summary (Batch Mode Only)

**Only execute this phase after completing all batch fixes.**

### Step 6B.1: Generate Comprehensive Summary

```
## Batch Remediation Summary

### Overall Results
| Metric | Count |
|--------|-------|
| Vulnerabilities Attempted | [total] |
| Successfully Fixed | [count] |
| Partially Fixed | [count] |
| Failed | [count] |
| Skipped | [count] |

### Issues Fixed by Severity
| Severity | Fixed | Remaining |
|----------|-------|-----------|
| Critical | X/Y | Z |
| High | X/Y | Z |
| Medium | X/Y | Z |
| Low | X/Y | Z |

### Detailed Results

#### Code Vulnerabilities Fixed
| # | Vulnerability | File | Instances | Status |
|---|---------------|------|-----------|--------|
| 1 | SQL Injection | db.ts | 3/3 | ✅ Fixed |
| 2 | XSS | api/render.ts | 2/2 | ✅ Fixed |
| 3 | Path Traversal | files.ts | 3/4 | ⚠️ Partial |

#### Dependency Vulnerabilities Fixed
| # | Package | Old → New | CVEs Fixed | Status |
|---|---------|-----------|------------|--------|
| 1 | log4j-core | 2.14.1 → 2.17.1 | 3 | ✅ Fixed |
| 2 | lodash | 4.17.15 → 4.17.21 | 2 | ✅ Fixed |

### Files Modified
- src/db.ts
- src/api/render.ts
- src/files.ts
- package.json
- package-lock.json

### Validation Results
| Check | Result |
|-------|--------|
| Snyk Code Re-scan | ✅ [X] issues resolved |
| Snyk SCA Re-scan | ✅ [Y] issues resolved |
| Build | ✅ Pass |
| Tests | ✅ Pass |
| Lint | ✅ Pass |

### Issues NOT Fixed
| Vulnerability | Reason |
|---------------|--------|
| SSRF in external.ts | Complex refactoring required |
| minimist@1.2.5 | No fix version available |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## Should I create a single PR for all these fixes? (yes / no)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Step 6B.2: Send Batch Feedback

Report all fixes to Snyk:

```
Run mcp_snyk_snyk_send_feedback with:
- path: [project root]
- fixedExistingIssuesCount: [total issues fixed across all vulns]
- preventedIssuesCount: 0
```

### Step 6B.3: Batch PR Handling

If user confirms PR for batch fixes:

**Branch naming for batch**:
- `fix/security-batch-YYYYMMDD`
- `fix/security-critical-high-batch`

**Commit strategy**:
- **Option 1**: Single commit with all changes
- **Option 2**: One commit per vulnerability type (cleaner history)

Default to Option 1 unless user prefers separate commits.

**PR Body for Batch**:
```markdown
## Security Fixes (Batch)

This PR addresses multiple security vulnerabilities identified by Snyk.

### Summary
- **Code vulnerabilities fixed**: [count]
- **Dependency vulnerabilities fixed**: [count]
- **Total CVEs resolved**: [count]

### Code Fixes

| Vulnerability | File | CWE | Severity |
|---------------|------|-----|----------|
| SQL Injection | db.ts | CWE-89 | Critical |
| XSS | render.ts | CWE-79 | High |
| Path Traversal | files.ts | CWE-22 | High |

### Dependency Upgrades

| Package | Old | New | CVEs Fixed |
|---------|-----|-----|------------|
| log4j-core | 2.14.1 | 2.17.1 | 3 |
| lodash | 4.17.15 | 4.17.21 | 2 |

### Validation
- [x] Snyk scans pass
- [x] Tests pass
- [x] No new vulnerabilities introduced

### Review Notes
Each fix was validated independently before inclusion in this batch.
```

---

## Phase 7: Create PR (If Confirmed)

**Only execute if user says "yes" to PR prompt.**

### Step 7.1: Check Git Status
```bash
git status
```

**Verify:**
- There are uncommitted changes (staged or unstaged)
- The changes are related to the security fix

**If no changes found:** Report "No uncommitted changes to commit" and STOP

### Step 7.2: Create Branch

**Format**: `fix/security-<identifier>`

**Examples:**
- `fix/security-SNYK-JS-LODASH-1018905`
- `fix/security-cwe-79-xss`
- `fix/security-path-traversal-server`
- `fix/security-lodash-upgrade`

```bash
git checkout -b fix/security-<identifier>
```

### Step 7.3: Stage and Commit

Stage only files related to the security fix:
```bash
git add <files>
```

**Do NOT stage:**
- Unrelated changes
- IDE/editor files
- Build artifacts

Create commit:
```bash
git commit -m "fix(security): <description>

Resolves: [Snyk ID or CVE]
Severity: [Critical/High/Medium/Low]"
```

### Step 7.4: Push Branch
```bash
git push -u origin fix/security-<identifier>
```

### Step 7.5: Create Pull Request
```bash
gh pr create \
  --title "Security: <title>" \
  --body "<body>" \
  --base main
```

**PR Body Template:**
```markdown
## Security Fix

### Vulnerability Details
- **ID**: [Snyk ID or CVE]
- **Severity**: [Critical | High | Medium | Low]
- **Type**: [SCA | Code]

### Changes Made
[Description of the fix]

### Files Changed
- [list files]

### Validation
- [x] Snyk scan passes
- [x] Tests pass
- [x] No new vulnerabilities introduced
```

**IMPORTANT**: 
- Do NOT use `--label` flags (labels may not exist in repo)

### Step 7.6: Output Confirmation

```
## PR Created Successfully

- **PR URL**: [URL]
- **Branch**: fix/security-<identifier>
- **Title**: [PR title]
- **Status**: Ready for review

### Next Steps
1. Review the PR at the URL above
2. Request reviews from team members
3. Merge when approved
```

---

## Error Handling

### Authentication Errors
- Run `mcp_snyk_snyk_auth` and retry once
- If still failing: STOP and ask user to authenticate manually

### Scan Timeout/Failure
- Retry once
- If still failing: STOP and report the error

### Vulnerability Not Found
- If user specified a vulnerability that doesn't appear in scan results
- Report clearly and STOP (don't guess or fix something else)

### Unfixable Code Vulnerability
If the vulnerability cannot be fixed automatically:
1. Document why it cannot be fixed (complex refactoring needed, unclear fix, etc.)
2. Add TODO comment in the affected file with context
3. Report to user with manual remediation suggestions
4. Do NOT leave partial/broken fixes

### SCA - No Fix Available
If no upgrade path exists:
1. Document this clearly
2. Suggest alternatives (replace package, patch, accept risk)
3. Do NOT make changes

### Partial Success (Code)
If some instances are fixed but others fail:
1. Keep the successful fixes
2. Document which instances remain unfixed and why
3. Add TODO comments for unfixed instances
4. Report partial success in summary with clear breakdown

### Rollback Triggers
Revert ALL changes if:
- Unable to produce clean fix after 3 attempts (new vulnerabilities introduced)
- Tests fail and cannot be reasonably fixed
- Fix would require changing business logic
- Dependency resolution completely fails

### Git/PR Errors
| Error | Resolution |
|-------|------------|
| Not a git repository | STOP - cannot create PR |
| Branch already exists | Generate unique branch name with timestamp |
| SSH key error | Retry command |
| Not authenticated (gh) | Suggest `gh auth login` |

---

## Constraints

### Single Mode
1. **One vulnerability TYPE per run** - Fix all instances of ONE vulnerability type (Code) or ONE dependency issue (SCA)
2. **Minimal changes** - Only modify what's necessary
3. **No new vulnerabilities** - Fixes must be clean (or net improvement for SCA)
4. **Preserve functionality** - Tests must pass
5. **No scope creep** - Don't refactor or "improve" other code
6. **Consistent fixes** - Apply the same fix pattern across all instances (Code)
7. **User confirmation for PR** - Never auto-create PRs
8. **Always prompt for PR** - Every successful fix MUST end with the PR prompt question

### Batch Mode Additional Constraints
9. **User approval required** - Must confirm batch plan before starting
10. **Max 20 vulnerabilities** - Keep batch fixes manageable
11. **Max 15 files** - Keep PRs reviewable
12. **Validate each fix** - Each vulnerability fix is validated before proceeding to next
13. **Partial success allowed** - Can complete batch even if some fixes fail
14. **Single PR for batch** - All batch fixes go into one PR (unless user requests otherwise)
15. **Detailed tracking** - Track success/failure for each item in batch

---

## Completion Checklist

### Single Mode Checklist

Before ending the conversation, verify ALL are complete:

- [ ] Vulnerability type identified and documented (including all instances for code vulns)
- [ ] Fix applied successfully
- [ ] Re-scan shows ALL instances resolved (or net improvement for SCA)
- [ ] Tests pass (or failures documented)
- [ ] Summary displayed to user (with instance count if multiple)
- [ ] Snyk feedback sent with correct count
- [ ] **PR prompt asked** ← Do NOT skip this step
- [ ] PR created (if user confirmed)

### Batch Mode Checklist

Before ending the conversation, verify ALL are complete:

- [ ] Full project scan completed (SAST + SCA)
- [ ] Batch plan generated and shown to user
- [ ] User approved the batch plan
- [ ] Each vulnerability in plan was attempted
- [ ] Each fix was validated before proceeding to next
- [ ] Results tracked for all items (success/partial/failed)
- [ ] Comprehensive batch summary displayed
- [ ] Total fix count sent to Snyk feedback
- [ ] **PR prompt asked** with all batch changes
- [ ] Single PR created with all fixes (if user confirmed)

