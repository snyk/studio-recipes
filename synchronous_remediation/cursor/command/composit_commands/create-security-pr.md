# Create Security PR

## Overview
Creates a Pull Request for security fixes. Can be invoked after `/snyk-code-fix` or `/snyk-sca-fix`, or standalone for any security-related changes.

**Workflow**: Verify → Branch → Commit → Push → PR

## Example Usage

| Command | Behavior |
|---------|----------|
| `/create-security-pr` | Create PR for current uncommitted security changes |
| `/create-security-pr SNYK-JS-LODASH-1018905` | Create PR with issue ID in branch name |
| `/create-security-pr "upgrade lodash"` | Create PR with custom description |

---

## Prerequisites

Before invoking this command:
- Security fix should already be applied (code changes or dependency upgrade)
- Changes should be validated (scans pass, tests pass)
- Changes should NOT be committed yet

---

## Phase 1: Verify State

### Step 1.1: Check Git Status
```bash
git status
```

**Verify:**
- There are uncommitted changes (staged or unstaged)
- The changes are related to the security fix
- We are NOT on a protected branch (main, master)

**If no changes found:**
- Report "No uncommitted changes to commit" and STOP

**If on protected branch:**
- Proceed (we'll create a feature branch)

### Step 1.2: Identify Changed Files
Document which files were modified:
- Manifest files (`package.json`, `requirements.txt`, etc.)
- Lockfiles (`package-lock.json`, `yarn.lock`, etc.)
- Source code files (for code fixes)

---

## Phase 2: Create Branch

### Step 2.1: Generate Branch Name
Create a descriptive branch name:

**Format**: `fix/security-<identifier>`

**Examples:**
- `fix/security-SNYK-JS-LODASH-1018905`
- `fix/security-cwe-79-xss`
- `fix/security-path-traversal-server`
- `fix/security-lodash-upgrade`

If no specific identifier provided, derive from the fix:
- For SCA: use package name or Snyk ID
- For Code: use CWE or vulnerability type

### Step 2.2: Create and Checkout Branch
```bash
git checkout -b fix/security-<identifier>
```

**IMPORTANT**: Use `required_permissions: ["all"]` for all git operations.

---

## Phase 3: Commit Changes

### Step 3.1: Stage Files
Stage only files related to the security fix:
```bash
git add <manifest> <lockfile>  # For SCA
git add <source-file>          # For Code
```

**Do NOT stage:**
- Unrelated changes
- IDE/editor files
- Build artifacts

### Step 3.2: Create Commit
```bash
git commit -m "fix: (security) <description> [<ID>]"
```

**Commit message format:**
- `fix: (security) upgrade lodash to 4.17.21 [SNYK-JS-LODASH-1018905]`
- `fix: (security) sanitize user input to prevent XSS [CWE-79]`
- `fix: (security) validate file paths to prevent traversal`

**IMPORTANT**: Use `required_permissions: ["all"]` to avoid SSH/signing failures.

---

## Phase 4: Push Branch

### Step 4.1: Push to Remote
```bash
git push -u origin fix/security-<identifier>
```

**IMPORTANT**: Use `required_permissions: ["all"]` for network access.

**If push fails:**
- Check authentication (may need `gh auth login`)
- Retry with elevated permissions
- Report failure if still unsuccessful

---

## Phase 5: Create Pull Request

### Step 5.1: Open PR
```bash
gh pr create \
  --title "Security: <title>" \
  --body "<body>"
```

**PR Title Examples:**
- `Security: Upgrade lodash to fix prototype pollution`
- `Security: Fix XSS vulnerability in user input handling`
- `Security: Resolve path traversal in file upload`

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

### Additional Notes
[Any trade-offs, TODOs, or manual review needed]
```

**IMPORTANT**: 
- Use `required_permissions: ["all"]` for network access
- Do NOT use `--label` flags (labels may not exist in repo)

### Step 5.2: Handle PR Creation Errors

**If authentication fails:**
- Suggest user run `gh auth login`
- STOP and report

---

## Phase 6: Confirmation

Output final status:
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

### Git Errors
| Error | Resolution |
|-------|------------|
| Not a git repository | STOP - cannot create PR |
| Uncommitted changes conflict | Stash or commit unrelated changes first |
| Branch already exists | Generate unique branch name with timestamp |
| SSH key error | Retry with `required_permissions: ["all"]` |

### GitHub CLI Errors
| Error | Resolution |
|-------|------------|
| Not authenticated | Suggest `gh auth login` |
| Label not found | Retry without labels |
| No upstream | Set upstream with push |

### Rollback
If PR creation fails after commit:
- The local branch and commit remain
- User can manually push/create PR later
- Report the failure clearly with manual steps

---

## Standalone Usage

This command can be used independently (not chained from `/snyk-fix`):

1. Make your security fix manually
2. Run `/create-security-pr "description of fix"`
3. Command will create branch, commit, push, and open PR

**Requirements for standalone:**
- Changes must be uncommitted
- Provide a description for branch/commit naming

---

## Constraints

1. **Never commit to main** - Always create feature branch
2. **Only stage relevant files** - No unrelated changes
3. **Descriptive naming** - Branch and commit should indicate security fix
