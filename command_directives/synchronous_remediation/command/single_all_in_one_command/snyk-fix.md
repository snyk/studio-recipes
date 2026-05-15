# Snyk Fix (All-in-One)

## Overview
Complete security remediation workflow in a single command. Scans for vulnerabilities, fixes them, validates the fix, and optionally creates a PR.

**Workflow**: Parse → Scan → Analyze → Fix → Validate → Summary → (Optional) PR

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
| `/snyk-fix path traversal` | Fix all path traversal vulnerabilities |

---

## Phase 1: Input Parsing

Parse user input to extract:
- **scan_type**: Explicit (`code`, `sca`, `both`) or infer from context
- **target_vulnerability**: Specific issue ID, CVE, package name, file reference, or vulnerability type
- **target_path**: File or directory to focus on (defaults to project root)

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

### Step 2.5: Check for Fix Path (SCA Only)

**⚠️ If the scan results do not report any fix version or upgrade path for the selected SCA vulnerability, do NOT proceed to Phase 4.** The agent must not attempt to discover or invent a fix on its own when Snyk has no recommended remediation.

Instead, produce a **No Fix Available Report** and STOP:

```
## No Fix Available

| Vulnerability | [Title] |
|---------------|---------|
| **ID** | [Snyk Issue ID] |
| **Severity** | [Critical / High / Medium / Low] |
| **Package** | [package@current_version] |
| **Dependency Path** | [direct / transitive via X → Y → Z] |

### Why No Fix Was Applied
Snyk does not report a fix version or upgrade path for this vulnerability.
The agent will not attempt to resolve issues where no known fix exists.

### Alternatives to Consider
- Monitor for a future fix release from the package maintainer
- Evaluate replacing the package with a maintained alternative
- Apply a manual workaround if the vulnerability context allows it
- Accept the risk and document in your security policy
```

After producing this report:
- Send `snyk_send_feedback` with `fixedExistingIssuesCount: 0`
- Do NOT make any file changes
- STOP

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

### Step 4.1: Determine Remediation Strategy

Analyze the dependency path and determine which strategy applies. Exactly one of these three strategies must be selected before proceeding:

**Strategy A — Direct Upgrade**
The vulnerable package is a direct dependency in the project manifest. Upgrade it to a version where the vulnerability is fixed.

**Strategy B — Parent Upgrade**
The vulnerable package is a transitive dependency. A newer version of the direct (parent) dependency pulls in a fixed version of the transitive. Upgrade the parent.

**Strategy C — Transitive Fix**
The vulnerable package is a transitive dependency, but no available version of the parent pulls in a fixed transitive. Resolve the transitive to a fixed version using the lowest-impact mechanism available in the ecosystem.

#### How to choose:

1. Is the vulnerable package declared directly in the project manifest?
   - **Yes** → **Strategy A**
   - **No** → Continue to step 2

2. Identify the direct dependency (parent) that pulls in the vulnerable transitive. Does any available version of the parent resolve the vulnerable transitive to a fixed version?
   - **Yes** → **Strategy B** (upgrade the parent)
   - **No** → **Strategy C** (transitive fix)

If the application directly imports or uses the transitive dependency (not just via the parent), note this — it affects breaking change analysis for Strategy C.

Document the chosen strategy:
```
## Remediation Strategy
- **Strategy**: [A: Direct Upgrade | B: Parent Upgrade | C: Transitive Fix]
- **Target package to change**: [package@current → package@target]
- **Parent dependency** (if B/C): [parent@current]
- **Manifest file**: [path to manifest]
```

### Step 4.2: Breaking Change Assessment

**⚠️ ALWAYS run `snyk_breakability_check` BEFORE applying any changes.** If the tool is unavailable, errors out, or does not return a LOW/MEDIUM/HIGH risk level, proceed to Step 4.2a.

Call `snyk_breakability_check` with the package that will actually change in the manifest:

| Strategy | Check breakability on |
|----------|----------------------|
| A (Direct Upgrade) | The direct dependency being upgraded |
| B (Parent Upgrade) | The parent dependency being upgraded |
| C (Transitive Fix) | The transitive dependency being resolved to a new version |

#### Breakability Decision Tree

The breakability result (LOW / MEDIUM / HIGH) is a general likelihood assessment — it is not a confirmation of actual breakage in this specific project. Use the result to determine the next action.

**Interactive vs. autonomous execution**: when a human is in the loop (interactive session), present trade-offs and ask for confirmation at HIGH risk. When running autonomously (background agent, no human available), the agent must evaluate the same evidence a human would — vulnerability severity, breaking change risk, breaking change details — make the decision itself, and **document its reasoning** in the output. An autonomous agent must never block waiting for input that will not come.

**Strategy A (Direct Upgrade) and Strategy B (Parent Upgrade):**

| Risk | Action |
|------|--------|
| **LOW** | Auto-apply the upgrade. Proceed to Step 4.4. |
| **MEDIUM** | Auto-apply the upgrade. Document the breaking change summary and reasoning in the remediation summary. |
| **HIGH** | **Interactive**: present the full trade-off (vulnerability details, breaking change summary, exact proposed changes) and ask the user whether to proceed. **Autonomous**: evaluate the full trade-off, decide whether to apply or produce a Full Advisory (Phase 4a), and document the reasoning. |

**Strategy B → fallback to C:** If Strategy B gets a HIGH breakability result and the decision (user or agent) is to not proceed, fall back to Strategy C. Re-run `snyk_breakability_check` on the transitive version jump and follow the Strategy C decision tree below.

**Strategy C (Transitive Fix):**

| Risk | Action |
|------|--------|
| **LOW** | Auto-apply the fix. Proceed to Step 4.4. |
| **MEDIUM** | Auto-apply the upgrade. Document the breaking change summary and reasoning in the remediation summary. |
| **HIGH** | **Interactive**: present the full trade-off and ask the user whether to proceed. If the vulnerability is **Critical severity with a known exploit**, emphasize the urgency. **Autonomous**: evaluate the full trade-off, decide whether to apply or produce a Full Advisory (Phase 4a), and document the reasoning. |

### Step 4.2a: Breakability Fallback — Semver + Usage Analysis

**This step activates when `snyk_breakability_check` is unavailable (tool not found, errors out, times out) OR returns a response without a LOW/MEDIUM/HIGH risk level** (e.g., "no additional breakability context available"). If breakability returned a valid risk level, skip this step entirely.

When breakability data is unavailable, derive a substitute risk level by combining **semver distance** and **codebase usage**:

1. **Determine the semver distance** between the current version and the target version:
   - **Patch** bump (e.g., 1.2.3 → 1.2.5): lowest inherent risk
   - **Minor** bump (e.g., 1.2.3 → 1.3.0): moderate inherent risk
   - **Major** bump (e.g., 1.2.3 → 2.0.0): highest inherent risk

2. **Search the codebase for direct usages of the package being upgraded.** Look for imports, requires, includes, or other dependency references using patterns appropriate to the project's language and ecosystem. The agent determines the correct search patterns based on the ecosystem — do not use hardcoded patterns.

3. **Combine both signals to derive a substitute risk level:**

| Semver Distance | No direct usage | Light usage | Heavy / complex usage |
|-----------------|-----------------|-------------|----------------------|
| **Patch** | LOW | LOW | LOW |
| **Minor** | LOW | MEDIUM | MEDIUM |
| **Major** | HIGH | HIGH | HIGH |

4. **Feed the substitute risk level into the same Breakability Decision Tree from Step 4.2.** No separate code path — the same thresholds and actions apply.

**Important**: when a substitute risk level is used, note this in the remediation summary (Phase 6) so the user knows the risk assessment was derived from codebase analysis, not from breakability data.

### Step 4.3: Version Selection

When multiple versions fix the vulnerability, do NOT blindly pick the lowest version number. Optimize for:

1. Fixes the target vulnerability
2. Lowest breakability risk (run `snyk_breakability_check` on candidates if needed)
3. Lowest version number (tiebreaker only)

### Step 4.4: Apply Fix

**Only reach this step if the breakability decision allows it (auto-apply or user/agent confirmed).**

**Strategy A (Direct Upgrade):**
Update the version in the manifest and run the ecosystem's install command (`npm install pkg@version`, `yarn upgrade`, `go get`, `pip install`, `mvn dependency:resolve`, etc.). Preserve file formatting and comments.

**Strategy B (Parent Upgrade):**
Update the parent dependency version in the manifest and run the ecosystem's install command. After installation, verify that the resolved transitive is now the fixed version.

**Strategy C (Transitive Fix):**
Use the lowest-impact mechanism that makes the resolver choose a fixed version of the transitive. The exact mechanism is ecosystem-dependent — do not assume one universal ordering.

1. **Resolver-only update first**: Refresh the lockfile or run the ecosystem's update/resolve command for the vulnerable package. This is appropriate when the fixed version is already allowed by the existing constraints.
2. **If that fails**, inspect the ecosystem and repo layout, then choose the appropriate native resolver-control mechanism: top-level constraint/declaration, central dependency-management entry, force/override/resolution, exclusion, or replacement.
3. **Prefer the narrowest effective scope.** Use a stronger override/force/replace only when a normal declaration or narrower exclusion cannot make the resolver choose the fixed version.
4. **Hard pin only as a last resort.**

#### Reference: common install/resolve commands

| Package Manager | Command |
|-----------------|---------|
| npm (major upgrade) | `npm install <pkg>@<version>` |
| npm (minor/patch) | `npm install` |
| yarn | `yarn install` or `yarn upgrade <pkg>@<version>` |
| pip | `pip install -r requirements.txt` |
| maven | `mvn dependency:resolve` |

This table is not exhaustive — use the appropriate command for the project's ecosystem.

**IMPORTANT**: Use `required_permissions: ["all"]` for package manager commands.

**If installation fails:**
- If sandbox/permission issue: retry with elevated permissions
- If dependency conflict: try a different version or note as unfixable
- Revert manifest changes if resolution completely fails
- Document the failure reason

---

## Phase 4a: Full Advisory — SCA No-Apply Path

**Enter this phase when the decision is to NOT apply an SCA fix** — whether because the user declined, or because the agent (in autonomous mode) determined the risk outweighs the benefit.

Produce an advisory instead of making changes.

### Advisory Output Format

```
## Security Advisory — Manual Action Required

### Vulnerability
- **ID**: [Snyk Issue ID]
- **Severity**: [Critical | High | Medium | Low]
- **Package**: [vulnerable_package@current_version]
- **Title**: [vulnerability title]

### Why This Was Not Auto-Applied
[1-2 sentences: e.g., "The required transitive fix from pkg@1.0 to pkg@2.0 has a HIGH
breaking change risk. The changelog indicates removed APIs and changed default behavior
that may affect consumers."]

### Breaking Change Details
[Summary from snyk_breakability_check — what changed between versions, which APIs were
removed/renamed/modified, migration notes if available]

### Exact Changes Required
To apply this fix manually, make the following changes:

**1. Manifest change** ([path/to/manifest]):
[Exact content to add or modify — the override/resolution entry or version bump]

**2. Regenerate lockfile**:
[Exact command to run]

**3. Validate**:
[Command to re-run SCA scan and tests]

### Alternatives
- Wait for [parent_package] to release a version that includes the fixed transitive
- Evaluate replacing [vulnerable_package] with an alternative
- Accept the risk and document in your security policy
```

**After producing the advisory:**
- Do NOT make any file changes
- Do NOT proceed to Phase 5
- Send `snyk_send_feedback` with `fixedExistingIssuesCount: 0`
- STOP

---

## Phase 5: Validation

### Step 5.1: Re-run Security Scan
- Run `snyk_code_scan` or `snyk_sca_scan` on the same target
- Verify ALL targeted vulnerability instances are NO LONGER reported

**For Code vulnerabilities - If any instances still present:**
- Review the fix attempt for that specific instance
- Try alternative approach
- Maximum 3 total attempts per instance, then report partial success/failure

**For SCA vulnerabilities - If vulnerability still present:**
- Check if lockfile was properly updated
- Try explicit version install using the package manager's exact-version syntax
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
  - **New severity EQUAL OR HIGHER**: Try an alternative version. Run `snyk_breakability_check` on each candidate before attempting — do not blindly try higher versions without assessing their risk. Up to 3 iterations.
  - If no clean version exists: Revert and report as unfixable

### Step 5.1a: Identify Additional Issues Fixed (SCA Only)
A single upgrade often fixes multiple vulnerabilities:
- Compare pre-fix and post-fix scan results
- Identify ALL vulnerabilities resolved by this upgrade
- Record each: ID, severity, title

### Step 5.2: Run Tests
- Execute the project's test suite using the appropriate test runner
- If tests fail due to the fix:

  *For Code vulnerabilities:*
  - Prefer adjusting the fix over changing tests
  - Only modify tests if the fix legitimately changes expected behavior
  - Apply mechanical fixes only (renamed imports, etc.)
  - Maximum 2 attempts to resolve test failures

  *For SCA vulnerabilities:*
  - Prefer adjusting code to match the new API over downgrading
  - Apply mechanical fixes only (renamed imports, signature changes)
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
| **Strategy** | [Direct Upgrade / Parent Upgrade / Transitive Fix] |
| **Breaking Change Risk** | [LOW / MEDIUM / HIGH] |
| **Risk Source** | [Breakability Check / Codebase Usage Analysis] |

### Breaking Change Summary
[1-2 sentence summary from the breakability check — what changed between the versions.
If risk was derived from codebase usage analysis: note that breakability data was unavailable
and describe the usage pattern that informed the risk level.]

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
| Build | ✅ Pass / ❌ Fail |
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
After successful fix, report the remediation:
```
snyk_send_feedback with:
- fixedExistingIssuesCount: [total issues fixed]
- preventedIssuesCount: 0
- path: [absolute project path]
```

### Step 6.3: Wait for User Response

**⚠️ IMPORTANT**: Do NOT proceed until the user explicitly confirms.

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

**IMPORTANT**: Use `required_permissions: ["all"]` for all git operations.

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

**IMPORTANT**: Use `required_permissions: ["all"]` to avoid SSH/signing failures.

### Step 7.4: Push Branch
```bash
git push -u origin fix/security-<identifier>
```

**IMPORTANT**: Use `required_permissions: ["all"]` for network access.

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
- Use `required_permissions: ["all"]` for network access
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
- Run `snyk_auth` and retry once
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
Follow Step 2.5. Produce the No Fix Available Report and STOP.

### SCA - Fix Declined or Skipped
Clean exit — produce the Full Advisory (Phase 4a) if not already shown, send `snyk_send_feedback` with `fixedExistingIssuesCount: 0`, and STOP.

### Partial Success (Code)
If some instances are fixed but others fail:
1. Keep the successful fixes
2. Document which instances remain unfixed and why
3. Add TODO comments for unfixed instances
4. Report partial success in summary with clear breakdown

### Rollback Triggers
Revert ALL changes if:
- Unable to produce clean fix after 3 attempts (new vulnerabilities introduced)
- Tests fail and cannot be reasonably fixed after 2 mechanical fix attempts
- Fix would require changing business logic
- Dependency resolution completely fails

### Git/PR Errors
| Error | Resolution |
|-------|------------|
| Not a git repository | STOP - cannot create PR |
| Branch already exists | Generate unique branch name with timestamp |
| SSH key error | Retry with `required_permissions: ["all"]` |
| Not authenticated (gh) | Suggest `gh auth login` |

---

## Constraints

1. **One vulnerability TYPE per run** — Fix all instances of ONE vulnerability type (Code) or ONE dependency issue (SCA)
2. **Minimal changes** — Only modify what's necessary
3. **No new vulnerabilities** — Fixes must be clean (or net improvement for SCA)
4. **Preserve functionality** — Tests must pass
5. **No scope creep** — Don't refactor or "improve" other code
6. **Consistent fixes** — Apply the same fix pattern across all instances (Code)
7. **User confirmation for PR** — Never auto-create PRs
8. **Always prompt for PR** — Every successful fix MUST end with the PR prompt question
9. **Breakability gates all SCA fixes** — The agent MUST NOT apply any SCA upgrade without first running `snyk_breakability_check` and following the risk-based decision tree
10. **Confirmation for HIGH risk (SCA)** — In interactive sessions, HIGH risk SCA fixes require explicit user confirmation. MEDIUM risk fixes auto-apply with documented reasoning. See Step 4.2's Breakability Decision Tree.
11. **Version selection considers breakability (SCA)** — When multiple versions fix an SCA vulnerability, prefer the one with the lowest breakability risk, not just the lowest version number
12. **Ecosystem-agnostic intent (SCA)** — SCA remediation steps describe what to do conceptually (e.g., "resolve the transitive to a fixed version using the lowest-impact mechanism"). Ecosystem-specific commands appear only as reference examples.
13. **No fix path means no fix attempt (SCA)** — See Step 2.5

---

## Completion Checklist

Before ending the conversation, verify ALL are complete:

- [ ] Vulnerability type identified and documented (including all instances for code vulns)
- [ ] Fix path verified for SCA (if no fix exists: No Fix Available Report produced and STOP)
- [ ] Remediation strategy determined for SCA (A, B, or C)
- [ ] Breaking change assessment performed for SCA
- [ ] Fix applied successfully (or Full Advisory produced if not applying)
- [ ] Re-scan shows ALL instances resolved (or net improvement for SCA)
- [ ] Tests pass (or failures documented)
- [ ] Summary displayed to user (with instance count if multiple)
- [ ] Snyk feedback sent with correct count
- [ ] **PR prompt asked** ← Do NOT skip this step (only if fix was applied)
- [ ] PR created (if user confirmed)
