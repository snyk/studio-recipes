---
name: secure-at-inception
description: |
  Proactive security scanning for newly generated or modified code. Intelligently detects changes,
  runs appropriate scans (SAST, SCA, IaC), filters to only NEW issues, and prevents vulnerabilities
  at the source. Use this skill when:
  - Agent generates new code files
  - Agent modifies existing code
  - User asks to "scan for security issues" or "check my changes"
  - Before committing changes
  - User mentions "secure at inception", "proactive scan", or "security check"
allowed-tools: "mcp_snyk_snyk_code_scan mcp_snyk_snyk_sca_scan mcp_snyk_snyk_iac_scan mcp_snyk_snyk_send_feedback Read Bash Grep"
license: Apache-2.0
compatibility: |
  Requires Snyk MCP server connection and authenticated Snyk account.
  Git repository recommended for change detection (git diff).
  Supports 20+ programming languages for SAST, all major package managers for SCA,
  and Terraform/Kubernetes/CloudFormation/ARM for IaC scanning.
metadata:
  author: Snyk
  version: 1.0.0
---

# Secure At Inception

Proactively scan all newly generated or modified code to prevent security vulnerabilities before they enter the codebase. Provides intelligent scanning decisions, caching, and filtering to focus only on NEW issues.

---

## File Type → Scan Type Reference

| Scan Type | Trigger Files | MCP Tool |
|-----------|--------------|----------|
| SAST (Code) | Source files: `.js`, `.ts`, `.py`, `.java`, `.go`, `.rb`, `.php`, `.cs`, `.swift`, `.kt`, `.scala`, `.rs`, `.c`, `.cpp`, `.dart`, and more | `snyk_code_scan` |
| SCA (Dependencies) | Manifests: `package.json`, `requirements.txt`, `pom.xml`, `build.gradle`, `Gemfile`, `go.mod`, `Cargo.toml`, `*.csproj`, `composer.json`, and more | `snyk_sca_scan` |
| IaC | Infrastructure: `.tf`, `.tfvars`, K8s YAML (with `apiVersion`/`kind`), `template.json`/`.yaml`, ARM JSON, `serverless.yml` | `snyk_iac_scan` |

**Skip**: binary files, non-IaC JSON/YAML, documentation (`.md`, `.txt`, `.rst`), assets, test fixtures.

---

## Phase 1: Change Detection

### Step 1.1: Gather Changed Files

Check for changes using one of these methods (in order of preference):

1. **Git diff** (if in a git repo):
   ```bash
   git diff --name-only HEAD
   git diff --name-only --cached  # staged files
   git status --porcelain
   ```
2. **Session context**: Track files created/modified during the current session
3. **User-specified path**: If user provides a specific file or directory

### Step 1.2: Categorize Files by Scan Type

Use the File Type → Scan Type Reference table above to map each changed file to the appropriate scan. IaC YAML is distinguished from generic YAML by the presence of `apiVersion`/`kind` (Kubernetes) or `AWSTemplateFormatVersion` (CloudFormation).

---

## Phase 2: Execute Scans

Run SAST, SCA, and IaC scans in **parallel** — they are independent of each other. Use the parameters below for each applicable scan type (determined by the File Type → Scan Type Reference table).

### Step 2.1: SAST Scan (`snyk_code_scan`)
- `path`: directory containing changed source files (or project root); scan each file individually if < 5 files changed, otherwise scan the parent directory
- `severity_threshold`: `"medium"` (default) or as configured

### Step 2.2: SCA Scan (`snyk_sca_scan`)
- `path`: project root or directory containing the manifest
- `all_projects`: `true` (for monorepos)
- `severity_threshold`: `"medium"` (default) or as configured
- Note: SCA scans the entire dependency tree, not just direct changes.

### Step 2.3: IaC Scan (`snyk_iac_scan`)
- `path`: directory containing IaC files
- `severity_threshold`: `"medium"` (default) or as configured

---

## Phase 3: Filter to New Issues

Apply these filters before reporting to surface only issues introduced by the current changes.

**SAST**: Include a finding only if its file+line falls within a modified line range from `git diff -U0`. Parse `@@ -X,Y +A,B @@` hunks to determine changed ranges; exclude findings outside those ranges as pre-existing.

**SCA**: Include only if a new or updated package now has MORE vulnerabilities or higher severity than before. Apply the **Net Improvement Rule** — if the change reduces overall vulnerability count or severity, do NOT block.

**IaC**: Include only if the misconfiguration is in a newly added or modified resource block.

---

## Phase 4: Report & Decision

### Step 4.1: Severity Threshold Configuration

| Mode | Block On | Warn On | Allow |
|------|----------|---------|-------|
| Strict | Low+ | - | - |
| Standard | High+ | Medium | Low |
| Relaxed | Critical only | High | Medium, Low |

### Step 4.2: Generate Report

```
## Secure At Inception Scan Results

### Summary
| Scan Type            | New Issues | Blocked |
|----------------------|------------|---------|
| Code (SAST)          | X          | Yes/No  |
| Dependencies (SCA)   | Y          | Yes/No  |
| Infrastructure (IaC) | Z          | Yes/No  |

### New Code Vulnerabilities (SAST)
| Severity | Type          | File       | Line | Description           |
|----------|---------------|------------|------|-----------------------|
| High     | SQL Injection | src/db.ts  | 45   | User input in query   |

### New Dependency Vulnerabilities (SCA)
| Severity | Package          | Vulnerability        | Fix Version |
|----------|------------------|----------------------|-------------|
| Critical | lodash@4.17.15   | Prototype Pollution  | 4.17.21     |

### New Infrastructure Issues (IaC)
| Severity | Resource       | Issue                 | Recommendation           |
|----------|----------------|-----------------------|--------------------------|
| High     | aws_s3_bucket  | Public access enabled | Set block_public_access  |

### Recommended Actions
1. `/snyk-fix SNYK-JS-LODASH-1234` - Fix lodash vulnerability
2. Review `src/db.ts:45` for SQL injection fix

### Decision: [BLOCKED / ALLOWED]
[Reason based on severity threshold]
```

### Step 4.3: Block Decision Logic

```
If any NEW issue severity >= threshold:
  BLOCKED - do not proceed until fixed
  Provide specific fix commands
Else:
  ALLOWED - safe to proceed
  Note any warnings for future attention
```

---

## Phase 5: Track Metrics

After each scan that finds and helps fix issues, run `snyk_send_feedback` with:
- `path`: project root (absolute path)
- `preventedIssuesCount`: count of NEW issues found (delta, not cumulative)
- `fixedExistingIssuesCount`: `0` (this skill prevents, doesn't fix existing issues)

Only count issues found in NEW code that would have been committed without this scan.

---

## Best Practices

- **Run automatically** after generating or modifying code, and before suggesting a commit; also on request for explicit security checks.
- **Cache results** keyed by `file + content_hash` with a 12-hour TTL; only rescan changed files and batch by directory.
- **False positives**: Use a `.snyk` policy file to suppress confirmed false positives, then re-run to verify:
  ```yaml
  ignore:
    SNYK-JS-EXAMPLE-12345:
      - '*':
          reason: 'False positive - input is validated upstream'
          expires: 2025-12-31
  ```
- **Threshold tuning**: Start with Standard mode; switch to Relaxed if blocks are too frequent, or Strict after low/medium severity incidents.
- **CI/CD integration**: Invoke on pull request creation or pushes to feature branches; block merge if threshold is exceeded.

---

## Error Handling

| Situation | Action |
|-----------|--------|
| Authentication error | Run `snyk_auth` and retry; prompt user for manual authentication if still failing |
| Scan timeout | Retry once with smaller scope; report partial results if still failing |
| No changes detected | Report "No code changes detected - nothing to scan"; offer full project scan on request |
| Unsupported files only | Report "No scannable files in changes" with a list of skipped file types and reasons |

---

## Constraints

1. **New Issues Only**: Never block on pre-existing issues (that's remediation's job)
2. **Minimal Noise**: Filter aggressively to avoid alert fatigue
3. **Fast Feedback**: Complete scan within 30 seconds for typical changes
4. **Non-Destructive**: Never modify code, only report findings
5. **Actionable Output**: Every finding must have a clear fix path
