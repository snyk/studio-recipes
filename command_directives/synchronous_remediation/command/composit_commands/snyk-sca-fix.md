# Snyk SCA Fix (Dependencies)

## Overview
Fixes dependency vulnerabilities identified by Snyk SCA scanning. Can be invoked directly or via `/snyk-fix`.

**Workflow**: Scan → Analyze → Upgrade → Validate → Summary

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

---

## Phase 2: Remediation

### Step 2.1: Analyze Dependency Path
- Document the full dependency path (direct → transitive → vulnerable)
- Identify manifest files to modify (`package.json`, `requirements.txt`, etc.)
- Determine if vulnerable package is direct or transitive

**For transitive dependencies:**
- Identify which direct dependency pulls in the vulnerable transitive
- Check if upgrading the direct dependency will pull in the fixed transitive
- If app directly imports the transitive: note this for breaking change analysis

### Step 2.2: Check for Breaking Changes
Search codebase for potential impact:
```bash
# Search for imports of the package
grep -r "from 'package'" --include="*.ts" --include="*.js"
grep -r "require('package')" --include="*.ts" --include="*.js"
```

If complex breaking changes detected:
- Add TODO comments with migration notes
- Note in summary that manual review is needed

### Step 2.3: Apply Minimal Upgrade
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

### Step 2.4: Regenerate Lockfile

Run the appropriate install command:

| Package Manager | Command |
|-----------------|---------|
| npm (major upgrade) | `npm install <pkg>@<version>` |
| npm (minor/patch) | `npm install` |
| yarn | `yarn install` or `yarn upgrade <pkg>@<version>` |
| pip | `pip install -r requirements.txt` |
| maven | `mvn dependency:resolve` |

**IMPORTANT**: Use `required_permissions: ["all"]` for package manager commands.

**Verify lockfile updated:**
```bash
# Example for npm
grep -A2 '"lodash":' package-lock.json
```

**If installation fails:**
- If sandbox/permission issue: retry with elevated permissions
- If dependency conflict: try a different version or note as unfixable
- Revert manifest changes if resolution completely fails
- Document the failure reason

---

## Phase 3: Validation

### Step 3.1: Re-run SCA Scan
- Run `snyk_sca_scan` on the project
- Verify the target vulnerability is NO LONGER reported

**If vulnerability still present:**
- Check if lockfile was properly updated
- Try explicit version install: `npm install <pkg>@<exact_version>`
- Maximum 3 attempts, then STOP and report failure

**If NEW vulnerabilities introduced by the upgrade:**

Check severity trade-off:
- **New severity LOWER than fixed**: Accept (net security improvement)
  - Example: Fixed Critical, introduced Low → ✅ Continue, note in summary
- **New severity EQUAL OR HIGHER**: Try higher version
  - Check if newer version fixes both original AND new issue
  - Try up to 3 version iterations
  - If no clean version exists: Revert and report as unfixable

### Step 3.1a: Identify Additional Issues Fixed
A single upgrade often fixes multiple vulnerabilities:
- Compare pre-fix and post-fix scan results
- Identify ALL vulnerabilities resolved by this upgrade
- Record each: ID, severity, title

### Step 3.2: Run Tests
- Execute project tests (`npm test`, `pytest`, etc.)
- If tests fail:
  - Check if failure is due to breaking API changes
  - Apply mechanical fixes only (renamed imports, etc.)
  - Do NOT perform large refactors
  - Note unresolved test failures in summary

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
- **Fix Applied**: Upgraded to minimum secure version

### Additional Vulnerabilities Fixed
| ID | Severity | Title |
|----|----------|-------|
| [Snyk ID] | [severity] | [title] |
| ... | ... | ... |

**Total issues fixed**: [count]

### Files Changed
- [manifest file]
- [lockfile]
- [any code files with import fixes]

### Commands Executed
| Command | Result |
|---------|--------|
| npm install lodash@4.17.21 | PASS |
| npm test | PASS |

### Trade-offs (if applicable)
If upgrade introduced lower-severity issues:
- **New Issue**: [Snyk ID] - [severity] - [title]
- **Net Improvement**: [Fixed severity] → [New severity]

### Remaining Work
- [Any TODOs added for breaking changes]
- [Any manual review needed]
- [Other SCA vulnerabilities still present - count by severity]
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
If no upgrade path exists:
1. Document this clearly
2. Suggest alternatives (replace package, patch, accept risk)
3. Do NOT make changes

### Dependency Conflicts
If upgrade causes dependency resolution failure:
1. Try alternative versions
2. If no compatible version exists: report as unfixable
3. Document the conflict details

### Rollback Trigger
Revert ALL changes if:
- Unable to find version with net security improvement after 3 attempts
- Dependency resolution completely fails
- Core tests fail and cannot be reasonably fixed

---

## Constraints

1. **One target per run** - Target ONE vulnerability, but report all issues fixed by that upgrade
2. **Minimal upgrades** - Use lowest secure version
3. **Net improvement required** - Only accept trade-offs that improve overall security
4. **No unrelated changes** - Don't upgrade packages not in the vulnerability path
5. **Preserve compatibility** - Lockfile must resolve successfully

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

