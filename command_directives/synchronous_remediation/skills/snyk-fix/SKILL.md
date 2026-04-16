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
allowed-tools: "mcp_snyk_snyk_code_scan mcp_snyk_snyk_sca_scan mcp_snyk_snyk_auth mcp_snyk_snyk_send_feedback Read Write Edit Bash Grep"
license: Apache-2.0
compatibility: |
  Requires Snyk MCP server connection and authenticated Snyk account.
  GitHub CLI (gh) required for PR creation. Git repository required.
  Supports SAST for 20+ languages and SCA for all major package managers.
metadata:
  author: Snyk
  version: 1.0.0
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

### Step 4.1: Analyze Dependency Path
Identify manifest files, whether dependency is direct or transitive, and which direct dep pulls in the vulnerable transitive.

### Step 4.2: Check for Breaking Changes
```bash
grep -r "from 'package'" --include="*.ts" --include="*.js"
grep -r "require('package')" --include="*.ts" --include="*.js"
```
Add TODO comments with migration notes if complex breaking changes detected.

### Step 4.3: Apply Minimal Upgrade
Edit ONLY the necessary dependency to the LOWEST version that fixes the vulnerability. Preserve file formatting.

### Step 4.4: Regenerate Lockfile
Run appropriate install command (`npm install`, `yarn install`, `pip install -r requirements.txt`, `mvn dependency:resolve`, etc.).
- On conflict: try alternate version or mark unfixable
- On complete failure: revert manifest changes and document reason

---

## Phase 5: Validation

### Step 5.1: Re-run Scan
Run same scan as Phase 2 (using identical `path` parameter). Verify ALL targeted instances are resolved.

- **Code**: If instances remain, retry with alternative approach. Max 3 attempts. If new vulnerabilities introduced: fix them (iterate, max 3 total). If unable to produce clean fix: revert ALL changes and report failure.
- **SCA**: If still present, try explicit version install. Max 3 attempts. For new vulns introduced: accept if new severity is lower; try higher version if equal/higher (max 3 iterations); revert if no clean version exists.

### Step 5.1a: Additional Issues Fixed (SCA Only)
Compare pre/post scan. Record all additional vulnerabilities resolved by the upgrade (ID, severity, title).

### Step 5.2: Run Tests
Run project tests (`npm test`, `pytest`, etc.). On failure: prefer adjusting fix over changing tests; only modify tests for legitimate behavioral changes. Max 2 attempts.

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
- For SCA: list additional issues fixed by the upgrade

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
| SCA — no fix available | Document clearly; suggest alternatives (replace package, patch, accept risk); no changes |
| Partial success (code) | Keep successful fixes; add TODO for unfixed instances; report partial success with breakdown |
| Not a git repo | STOP — cannot create PR |
| Branch already exists | Generate unique branch name with timestamp |
| gh not authenticated | Suggest `gh auth login` |

**Rollback triggers** (revert ALL changes if):
- Cannot produce clean fix after 3 attempts
- Tests fail and cannot be reasonably fixed
- Fix would require changing business logic
- Dependency resolution completely fails

---

## Constraints

**Single Mode**: Fix one vulnerability TYPE per run (all instances). Minimal changes only. No new vulnerabilities. Tests must pass. No scope creep or refactoring. Always prompt for PR.

**Batch Mode adds**: User must approve plan before starting. Max 20 vulnerabilities, 15 files. Validate each fix before proceeding. Partial success allowed. Single PR for all batch fixes (unless user requests otherwise).

---

## Completion Checklist

**Single Mode**: vulnerability documented → fix applied → re-scan clean → tests pass → summary shown → Snyk feedback sent → **PR prompt asked** → PR created if confirmed.

**Batch Mode**: full scan done → plan shown and approved → all items attempted → each fix validated → results tracked → batch summary shown → Snyk feedback sent → **PR prompt asked** → single PR created if confirmed.
