# Snyk SCA Fix (Dependencies)

## Overview
Fixes dependency vulnerabilities identified by Snyk SCA scanning. Can be invoked directly or via `/snyk-fix`.

**Workflow**: Scan → Analyze → Assess Risk → Fix (or Advise) → Validate → Summary

## Example Usage

| Command | Behavior |
|---------|----------|
| `/snyk-sca-fix` | Scan project, fix highest priority dependency issue |
| `/snyk-sca-fix lodash` | Fix highest priority issue in lodash package |
| `/snyk-sca-fix SNYK-JS-LODASH-1018905` | Fix specific vulnerability by ID |
| `/snyk-sca-fix CVE-2021-44228` | Fix specific CVE |

---

## Phase 1: Discovery

**Skip if target vulnerability was provided by `/snyk-fix` dispatcher.**

### Step 1.1: Run SCA Scan
- Run `snyk_sca_scan` with `path` set to project root
- Parse results for dependency vulnerabilities

### Step 1.2: Select Target
From scan results, select ONE issue using this priority:
1. Critical severity with known exploit
2. Critical severity
3. High severity with known exploit  
4. High severity
5. Medium severity
6. Low severity

Within same priority: prefer issues with available upgrade paths.

### Step 1.3: Document Target
```
## Target Dependency Vulnerability
- **ID**: [Snyk Issue ID]
- **Severity**: [Critical | High | Medium | Low]
- **Package**: [package@current_version]
- **Title**: [vulnerability title]
- **Fix Version**: [minimum version that fixes]
- **Dependency Path**: [direct | transitive via X → Y → Z]
```

### Step 1.4: Check for Fix Path

**⚠️ If the scan results do not report any fix version or upgrade path for the selected vulnerability, do NOT proceed to Phase 2.** The agent must not attempt to discover or invent a fix on its own when Snyk has no recommended remediation.

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

## Phase 2: Remediation

### Step 2.1: Determine Remediation Strategy

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

### Step 2.2: Breaking Change Assessment

**⚠️ ALWAYS run `snyk_breakability_check` BEFORE applying any changes.** If the tool is unavailable, errors out, or does not return a LOW/MEDIUM/HIGH risk level, proceed to Step 2.2a.

Call `snyk_breakability_check` with the package that will actually change in the manifest:

| Strategy | Check breakability on |
|----------|----------------------|
| A (Direct Upgrade) | The direct dependency being upgraded |
| B (Parent Upgrade) | The parent dependency being upgraded |
| C (Transitive Fix) | The transitive dependency being resolved to a new version |

#### Breakability Decision Tree

The breakability result (LOW / MEDIUM / HIGH) is a general likelihood assessment — it is not a confirmation of actual breakage in this specific project. Use the result to determine the next action.

**Interactive vs. autonomous execution**: when a human is in the loop (interactive session), present trade-offs and ask for confirmation at MEDIUM and HIGH risk. When running autonomously (background agent, no human available), the agent must evaluate the same evidence a human would — vulnerability severity, breaking change risk, breaking change details — make the decision itself, and **document its reasoning** in the output. An autonomous agent must never block waiting for input that will not come.

**Strategy A (Direct Upgrade) and Strategy B (Parent Upgrade):**

| Risk | Action |
|------|--------|
| **LOW** | Auto-apply the upgrade. Proceed to Step 2.4. |
| **MEDIUM** | **Interactive**: present the breaking change summary and recommend applying; ask the user to confirm. **Autonomous**: evaluate the vulnerability severity against the breaking change details, decide whether to apply or produce an advisory, and document the reasoning. |
| **HIGH** | **Interactive**: present the full trade-off (vulnerability details, breaking change summary, exact proposed changes) and ask the user whether to proceed. **Autonomous**: evaluate the full trade-off, decide whether to apply or produce a Full Advisory (Phase 2a), and document the reasoning. |

**Strategy B → fallback to C:** If Strategy B gets a HIGH breakability result and the decision (user or agent) is to not proceed, fall back to Strategy C. Re-run `snyk_breakability_check` on the transitive version jump and follow the Strategy C decision tree below.

**Strategy C (Transitive Fix):**

| Risk | Action |
|------|--------|
| **LOW** | Auto-apply the fix. Proceed to Step 2.4. |
| **MEDIUM** | **Interactive**: present the breaking change summary and recommend applying; ask the user to confirm. **Autonomous**: evaluate the vulnerability severity against the breaking change details, decide whether to apply or produce an advisory, and document the reasoning. |
| **HIGH** | **Interactive**: present the full trade-off and ask the user whether to proceed. If the vulnerability is **Critical severity with a known exploit**, emphasize the urgency. **Autonomous**: evaluate the full trade-off, decide whether to apply or produce a Full Advisory (Phase 2a), and document the reasoning. |

### Step 2.2a: Breakability Fallback — Semver + Usage Analysis

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

4. **Feed the substitute risk level into the same Breakability Decision Tree from Step 2.2.** No separate code path — the same thresholds and actions apply.

**Important**: when a substitute risk level is used, note this in the remediation summary (Phase 4) so the user knows the risk assessment was derived from codebase analysis, not from breakability data.

### Step 2.3: Version Selection

When multiple versions fix the vulnerability, do NOT blindly pick the lowest version number. Optimize for:

1. Fixes the target vulnerability
2. Lowest breakability risk (run `snyk_breakability_check` on candidates if needed)
3. Lowest version number (tiebreaker only)

### Step 2.4: Apply Fix

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

## Phase 2a: Full Advisory (No-Apply Path)

**Enter this phase when the decision is to NOT apply the fix** — whether because the user declined, or because the agent (in autonomous mode) determined the risk outweighs the benefit.

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
- Do NOT proceed to Phase 3
- Send `snyk_send_feedback` with `fixedExistingIssuesCount: 0`
- STOP

---

## Phase 3: Validation

### Step 3.1: Re-run SCA Scan
- Run `snyk_sca_scan` on the project
- Verify the target vulnerability is NO LONGER reported

**If vulnerability still present:**
- Check if lockfile was properly updated
- Try explicit version install using the package manager's exact-version syntax
- Maximum 3 attempts, then STOP and report failure

**If NEW vulnerabilities introduced by the upgrade:**

Check severity trade-off:
- **New severity LOWER than fixed**: Accept (net security improvement)
- **New severity EQUAL OR HIGHER**: Try an alternative version. Run `snyk_breakability_check` on each candidate before attempting — do not blindly try higher versions without assessing their risk. Up to 3 iterations.
- If no clean version exists: Revert and report as unfixable

### Step 3.1a: Identify Additional Issues Fixed
A single upgrade often fixes multiple vulnerabilities:
- Compare pre-fix and post-fix scan results
- Identify ALL vulnerabilities resolved by this upgrade
- Record each: ID, severity, title

### Step 3.2: Run Tests
- Execute the project's test suite using the appropriate test runner
- If tests fail due to the upgrade:
  - **If breakability was LOW**: prefer adjusting code to match the new API over downgrading. Apply mechanical fixes only (renamed imports, signature changes). Maximum 2 attempts.
  - **If breakability was MEDIUM or HIGH**: test failures likely confirm real breaking changes. Do NOT attempt mechanical fixes — revert immediately and present the situation to the user with the test failure details and breaking change summary.

### Step 3.3: Run Linting
- Run project linter if configured
- Fix any formatting issues introduced

---

## Phase 4: Summary

Output the remediation summary:

```
## SCA Fix Summary

### Primary Vulnerability Fixed
- **ID**: [Snyk ID]
- **Severity**: [severity] → **Resolved**
- **Package**: [package@old] → [package@new]
- **Strategy**: [Direct Upgrade / Parent Upgrade / Transitive Fix]
- **Breaking Change Risk**: [LOW / MEDIUM / HIGH]
- **Risk Source**: [Breakability Check / Codebase Usage Analysis]

### Breaking Change Summary
[1-2 sentence summary from the breakability check — what changed between the versions.
If risk was derived from codebase usage analysis: note that breakability data was unavailable
and describe the usage pattern that informed the risk level.]

### Additional Vulnerabilities Fixed
| ID | Severity | Title |
|----|----------|-------|
| [Snyk ID] | [severity] | [title] |
| ... | ... | ... |

**Total issues fixed**: [count]

### Files Changed
- [manifest file]
- [lockfile]

### Validation

| Check | Result |
|-------|--------|
| Snyk Re-scan | ✅ Resolved / ❌ Still present |
| Build | ✅ Pass / ❌ Fail |
| Linting | ✅ Pass / ❌ Fail |
| Tests | ✅ Pass / ⚠️ Skipped (reason) / ❌ Fail |
```

### Step 4.2: Send Feedback to Snyk
After successful fix, report the remediation:
```
snyk_send_feedback with:
- fixedExistingIssuesCount: [total issues fixed - include additional issues from Step 3.1a]
- preventedIssuesCount: 0
- path: [absolute project path]
```

**Note**: For SCA, if upgrading a package fixed multiple vulnerabilities (e.g., 3 CVEs in lodash), report the TOTAL count.

---

## Error Handling

### No Fix Available
If Snyk does not report a fix version or upgrade path:
1. Produce the No Fix Available Report (see Step 1.4)
2. Send `snyk_send_feedback` with `fixedExistingIssuesCount: 0`
3. Do NOT make any changes — the agent must not attempt to discover or invent a fix on its own
4. STOP

### Fix Declined or Skipped
If the user declines a recommended fix, or the agent (in autonomous mode) decides not to apply:
- This is a clean exit, not an error
- Produce the Full Advisory (Phase 2a) if not already shown
- Send `snyk_send_feedback` with `fixedExistingIssuesCount: 0`
- STOP

### Dependency Conflicts
If upgrade causes dependency resolution failure:
1. Try alternative versions
2. If no compatible version exists: report as unfixable
3. Document the conflict details

### Rollback Triggers
Revert ALL changes if:
- Upgrade introduces equal-or-higher severity issues that cannot be resolved within 3 attempts
- Tests fail when breakability was MEDIUM or HIGH (do not attempt mechanical fixes)
- Tests fail after 2 mechanical fix attempts when breakability was LOW
- Fix would require changing business logic
- Dependency resolution completely fails

---

## Constraints

1. **One target per run** — Target ONE vulnerability, but report all issues fixed by that upgrade
2. **Minimal upgrades** — Only modify the targeted dependency
3. **Net improvement required** — Only accept trade-offs that improve overall security
4. **No unrelated changes** — Don't upgrade packages not in the vulnerability path
5. **Preserve compatibility** — Lockfile must resolve successfully
6. **Breakability gates all fixes** — The agent MUST NOT apply any upgrade without first running `snyk_breakability_check` and following the risk-based decision tree
7. **Confirmation for MEDIUM and HIGH risk** — In interactive sessions, MEDIUM and HIGH risk fixes require explicit user confirmation before manifest changes. In autonomous mode, the agent evaluates the same evidence and decides — it must never block waiting for input, and must document its reasoning.
8. **Version selection considers breakability** — When multiple versions fix a vulnerability, prefer the one with the lowest breakability risk, not just the lowest version number
9. **No fix path means no fix attempt** — If Snyk does not report a fix version or upgrade path, the agent MUST NOT attempt to discover or invent a fix. Produce the No Fix Available Report and STOP.

---

## Phase 5: Handoff

**⚠️ CRITICAL**: After completing the Summary (Phase 4), you MUST continue with the PR prompt:

### If invoked via `/snyk-fix`:
Return control to `/snyk-fix` Phase 4.2 (PR Prompt).

### If invoked directly via `/snyk-sca-fix`:
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
