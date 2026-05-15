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
allowed-tools: "mcp_snyk_snyk_code_scan mcp_snyk_snyk_sca_scan mcp_snyk_snyk_breakability_check mcp_snyk_snyk_auth mcp_snyk_snyk_send_feedback Read Write Edit Bash Grep"
license: Apache-2.0
compatibility: |
  Requires Snyk MCP server connection and authenticated Snyk account.
  GitHub CLI (gh) required for PR creation. Git repository required.
  Supports SAST for 20+ languages and SCA for all major package managers.
metadata:
  author: Snyk
  version: 1.1.0
---

# Snyk Fix (All-in-One)

Complete security remediation workflow: Parse → Scan → Analyze → Fix → Validate → Summary → (Optional) PR

**Modes**:
- **Single Mode** (default): Fix one vulnerability type at a time (all instances in same file)
- **Batch Mode**: Fix multiple vulnerabilities in priority order (triggered by "all", "batch", severity filter, or count)

---

## Phase 1: Input Parsing

Parse user input to extract:
- **mode**: Single (default) or Batch
- **scan_type**: `code`, `sca`, or `both` (inferred from context)
- **target_vulnerability**: Specific issue ID, CVE, package name, file, or vuln type
- **target_path**: File or directory (defaults to project root)
- **severity_filter** / **max_fixes**: For batch mode (default max: 20)

### Mode & Scan Type Detection

| Signal | Mode | Scan Type |
|--------|------|-----------|
| "all", severity filter, count ("top 5"), or "batch" | Batch | both |
| Specific vuln ID, single type, file reference, or no batch indicators | Single (default) | — |
| Explicit "code"/"sast"/"static" | — | code |
| Explicit "sca"/"dependency"/"package"/package manager name | — | sca |
| `SNYK-` or `CVE-` ID provided | — | both |
| Vulnerability type (XSS, SQL injection, path traversal, etc.) or file reference | — | code |
| Package name reference | — | sca |
| No hints | — | both (highest priority issue) |

---

## Phase 1B: Batch Mode Planning (Skip if Single Mode)

1. Run both `mcp_snyk_snyk_code_scan` and `mcp_snyk_snyk_sca_scan` on project root.
2. Filter by user-specified severity, type, path, or count.
3. Group by vulnerability type (same ID + file for code; same package for SCA). Sort Critical → High → Medium → Low; within same priority, prefer issues with available fixes.
4. Display fix plan as a numbered table (index, type, severity, target, instance count) with estimated file/package changes. **Wait for user confirmation before proceeding.**
   - If user says "adjust": allow plan modification.
5. Execute fixes in order (Phase 3 or 4 per item → Phase 5 validate → track result). On failure: stop if `stop_on_failure=true`, else continue.
6. Proceed to Phase 6B after all attempts.

**Batch limits**: max 20 vulnerabilities, max 15 files modified, max 3 fix attempts per item.

---

## Phase 2: Discovery

### Step 2.1: Run Scan(s)

Invoke scans with the target path. Examples:

```
# Code scan
mcp_snyk_snyk_code_scan:
  path: "/absolute/path/to/project"   # or subdirectory for targeted scans

# SCA scan
mcp_snyk_snyk_sca_scan:
  path: "/absolute/path/to/project"   # always project root (manifest location)
```

- Code: `mcp_snyk_snyk_code_scan` on target path
- SCA: `mcp_snyk_snyk_sca_scan` on project root
- Both: run in parallel

### Step 2.2: Select Target
- If user specified: find matching issue. If not found: report and STOP.
- If not specified: select highest priority type using: Critical+exploit > Critical > High+exploit > High > Medium > Low. Prefer issues with available fixes.

### Step 2.3: Group Instances (Code Only)
After selecting vulnerability type, collect ALL instances of that same Snyk ID in the same file. Fix all of them together.

### Step 2.4: Document Target
Display a brief summary: type (Code/SCA), ID, severity, title, and for Code — instance count + file/line table; for SCA — package, fix version, dependency path.

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
- Send `mcp_snyk_snyk_send_feedback` with `fixedExistingIssuesCount: 0`
- Do NOT make any file changes
- STOP

---

## Phase 3: Remediation (Code Vulnerabilities)

### Step 3.1: Understand
Read all vulnerable locations. Identify type (SQL injection, XSS, path traversal, command injection, sensitive data exposure, hardcoded secrets, crypto issues, etc.). Review Snyk's remediation guidance.

### Step 3.2: Plan
Document: vulnerability type, root cause, fix approach, security mechanism, instance count.

Common patterns:
- SQL Injection → parameterized queries
- Command Injection → input validation + escaping or avoid shell
- Path Traversal → canonicalize + validate against allowed base
- XSS → output encoding/sanitization for context
- Hardcoded Secrets → move to env vars / secrets manager

### Step 3.3: Apply Fix to ALL Instances
- Fix from bottom to top of file (avoid line number shifts)
- Minimal change; use standard library/framework security features
- Create shared helper if 3+ instances share identical fix pattern
- Add security-relevant comments where non-obvious
- Do NOT refactor unrelated code or change business logic

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

**⚠️ ALWAYS run `mcp_snyk_snyk_breakability_check` BEFORE applying any changes.** If the tool is unavailable, errors out, or does not return a LOW/MEDIUM/HIGH risk level, proceed to Step 4.2a.

Call `mcp_snyk_snyk_breakability_check` with the package that will actually change in the manifest:

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

**Strategy B → fallback to C:** If Strategy B gets a HIGH breakability result and the decision (user or agent) is to not proceed, fall back to Strategy C. Re-run `mcp_snyk_snyk_breakability_check` on the transitive version jump and follow the Strategy C decision tree below.

**Strategy C (Transitive Fix):**

| Risk | Action |
|------|--------|
| **LOW** | Auto-apply the fix. Proceed to Step 4.4. |
| **MEDIUM** | Auto-apply the upgrade. Document the breaking change summary and reasoning in the remediation summary. |
| **HIGH** | **Interactive**: present the full trade-off and ask the user whether to proceed. If the vulnerability is **Critical severity with a known exploit**, emphasize the urgency. **Autonomous**: evaluate the full trade-off, decide whether to apply or produce a Full Advisory (Phase 4a), and document the reasoning. |

### Step 4.2a: Breakability Fallback — Semver + Usage Analysis

**This step activates when `mcp_snyk_snyk_breakability_check` is unavailable (tool not found, errors out, times out) OR returns a response without a LOW/MEDIUM/HIGH risk level** (e.g., "no additional breakability context available"). If breakability returned a valid risk level, skip this step entirely.

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
2. Lowest breakability risk (run `mcp_snyk_snyk_breakability_check` on candidates if needed)
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
[Summary from mcp_snyk_snyk_breakability_check — what changed between versions, which APIs were
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
- Send `mcp_snyk_snyk_send_feedback` with `fixedExistingIssuesCount: 0`
- STOP

---

## Phase 5: Validation

### Step 5.1: Re-run Scan
Run same scan as Phase 2 (using identical `path` parameter). Verify ALL targeted instances are resolved.

**For Code vulnerabilities - If any instances still present:**
- Review the fix attempt for that specific instance
- Try alternative approach
- Maximum 3 total attempts per instance, then report partial success/failure
- If new vulnerabilities introduced: fix them (iterate, max 3 total). If unable to produce clean fix: revert ALL changes and report failure

**For SCA vulnerabilities - If vulnerability still present:**
- Check if lockfile was properly updated
- Try explicit version install using the package manager's exact-version syntax
- Maximum 3 attempts, then STOP and report failure

**If NEW vulnerabilities introduced by an SCA upgrade:**
- **New severity LOWER than fixed**: Accept (net security improvement)
- **New severity EQUAL OR HIGHER**: Try an alternative version. Run `mcp_snyk_snyk_breakability_check` on each candidate before attempting — do not blindly try higher versions without assessing their risk. Up to 3 iterations.
- If no clean version exists: Revert and report as unfixable

### Step 5.1a: Additional Issues Fixed (SCA Only)
Compare pre/post scan. Record all additional vulnerabilities resolved by the upgrade (ID, severity, title).

### Step 5.2: Run Tests
Run project tests (`npm test`, `pytest`, etc.).

*For Code vulnerabilities:*
- On failure: prefer adjusting fix over changing tests; only modify tests for legitimate behavioral changes. Max 2 attempts.

*For SCA vulnerabilities:*
- On failure: prefer adjusting code to match the new API over downgrading. Apply mechanical fixes only (renamed imports, signature changes). Max 2 attempts.

### Step 5.3: Run Linting
Run project linter if configured; fix any formatting issues introduced.

---

## Phase 6: Summary & PR Prompt

### Step 6.1: Display Summary

Display a concise remediation summary including:
- Vulnerability ID, severity, title, CWE (code) or package upgrade (SCA)
- Instance/fix count and per-instance status (✅ Fixed / ⚠️ Partial / ❌ Failed)
- "What Was Fixed": 2–3 plain-English sentences, no code snippets
- Validation table: Snyk re-scan, build, lint, tests (✅/⚠️/❌)
- For SCA: strategy (Direct/Parent/Transitive), breaking change risk (LOW/MEDIUM/HIGH), risk source (Breakability Check / Codebase Usage Analysis), breaking change summary, and list additional issues fixed by the upgrade

End with a visually separated PR prompt:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## Should I create a PR for this fix? (yes / no)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Step 6.2: Send Feedback
```
mcp_snyk_snyk_send_feedback:
  fixedExistingIssuesCount: [total issues fixed]
  preventedIssuesCount: 0
  path: [absolute project path]
```

### Step 6.3: Wait for User Response
**IMPORTANT**: Do NOT proceed until the user explicitly confirms.

---

## Phase 6B: Batch Summary (Batch Mode Only)

### Step 6B.1: Summary
Display overall results (attempted/fixed/partial/failed/skipped), breakdown by severity (fixed vs remaining), detailed per-item results for code and SCA vulns, files modified, validation results, and a table of issues NOT fixed with reasons.

End with:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## Should I create a single PR for all these fixes? (yes / no)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Step 6B.2: Send Batch Feedback
```
mcp_snyk_snyk_send_feedback:
  path: [project root]
  fixedExistingIssuesCount: [total across all vulns]
  preventedIssuesCount: 0
```

### Step 6B.3: Batch PR
Branch: `fix/security-batch-YYYYMMDD` or `fix/security-critical-high-batch`.
Default: single commit with all changes (offer per-vuln commits if user prefers).
PR body: summary table of code fixes (vuln, file, CWE, severity), dependency upgrades (package, old→new, CVEs fixed), validation checklist, note that each fix was validated independently.

---

## Phase 7: Create PR (If Confirmed)

### Step 7.1: Check Git Status
```bash
git status
```
Verify uncommitted changes exist and are security-fix related. If none: report and STOP.

### Step 7.2: Create Branch
Format: `fix/security-<identifier>` (e.g., `fix/security-SNYK-JS-LODASH-1018905`, `fix/security-cwe-79-xss`, `fix/security-path-traversal-server`).
```bash
git checkout -b fix/security-<identifier>
```

### Step 7.3: Stage and Commit
Stage only security-fix related files. Do NOT stage unrelated changes, IDE files, or build artifacts.
```bash
git add <files>
git commit -m "fix(security): <description>

Resolves: [Snyk ID or CVE]
Severity: [Critical/High/Medium/Low]"
```

### Step 7.4: Push and Create PR
```bash
git push -u origin fix/security-<identifier>
gh pr create --title "Security: <title>" --body "<body>" --base main
```
Do NOT use `--label` flags.

PR body should include: vulnerability details (ID, severity, type), changes made, files changed, and validation checklist (Snyk scan passes, tests pass, no new vulnerabilities introduced).

### Step 7.5: Output Confirmation
Display PR URL, branch, title, and next steps (review, request reviews, merge when approved).

---

## Error Handling

| Situation | Action |
|-----------|--------|
| Auth error | Run `mcp_snyk_snyk_auth`, retry once; if still failing STOP |
| Scan timeout/failure | Retry once; if still failing STOP and report |
| Vulnerability not found | Report clearly and STOP — do not guess or fix something else |
| Unfixable code vuln | Add TODO comment with context; report with manual remediation suggestions; no partial/broken fixes |
| SCA — no fix available | Follow Step 2.5. Produce the No Fix Available Report and STOP |
| SCA — fix declined or skipped | Clean exit — produce Full Advisory (Phase 4a) if not already shown, send feedback with `fixedExistingIssuesCount: 0`, STOP |
| Partial success (code) | Keep successful fixes; add TODO for unfixed instances; report partial success with breakdown |
| Not a git repo | STOP — cannot create PR |
| Branch already exists | Generate unique branch name with timestamp |
| gh not authenticated | Suggest `gh auth login` |

**Rollback triggers** (revert ALL changes if):
- Cannot produce clean code fix after 3 attempts (or new vulnerabilities introduced)
- Tests fail and cannot be reasonably fixed after 2 mechanical fix attempts
- Fix would require changing business logic
- Dependency resolution completely fails

---

## Constraints

**Single Mode**: Fix one vulnerability TYPE per run (all instances). Minimal changes only. No new vulnerabilities. Tests must pass. No scope creep or refactoring. Always prompt for PR.

**SCA-specific (Single and Batch)**:
- **Breakability gates all SCA fixes** — Do NOT apply any SCA upgrade without first running `mcp_snyk_snyk_breakability_check` and following the risk-based decision tree
- **Confirmation for HIGH risk** — In interactive sessions, HIGH risk fixes require explicit user confirmation. MEDIUM auto-applies with documented reasoning. See Step 4.2.
- **Version selection considers breakability** — When multiple versions fix a vulnerability, prefer lowest breakability risk, not just lowest version number
- **No fix path means no fix attempt** — See Step 2.5

**Batch Mode adds**: User must approve plan before starting. Max 20 vulnerabilities, 15 files. Validate each fix before proceeding. Partial success allowed. Single PR for all batch fixes (unless user requests otherwise).

---

## Completion Checklist

**Single Mode**: vulnerability documented → fix path verified for SCA (or No Fix Available Report) → remediation strategy determined for SCA (A/B/C) → breaking change assessment for SCA → fix applied (or Full Advisory) → re-scan clean → tests pass → summary shown → Snyk feedback sent → **PR prompt asked** (if fix applied) → PR created if confirmed.

**Batch Mode**: full scan done → plan shown and approved → all items attempted → each fix validated → results tracked → batch summary shown → Snyk feedback sent → **PR prompt asked** → single PR created if confirmed.
