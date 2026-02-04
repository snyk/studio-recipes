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
---

# Secure At Inception

Proactively scan all newly generated or modified code to prevent security vulnerabilities before they enter the codebase. This skill provides intelligent scanning decisions, caching, and filtering to focus only on NEW issues.

**Core Principle**: Catch vulnerabilities at the moment of creation, not after they've been committed.

---

## Quick Reference

| Scan Type | Files | MCP Tool |
|-----------|-------|----------|
| SAST (Code) | `.js`, `.ts`, `.py`, `.java`, `.go`, `.rb`, `.php`, `.cs`, `.swift`, `.kt`, `.scala`, `.rs` | `snyk_code_scan` |
| SCA (Dependencies) | `package.json`, `requirements.txt`, `pom.xml`, `build.gradle`, `Gemfile`, `go.mod`, `Cargo.toml` | `snyk_sca_scan` |
| IaC | `.tf`, `.yaml`/`.yml` (K8s), `template.json` (CloudFormation) | `snyk_iac_scan` |

---

## Phase 1: Change Detection

**Goal**: Identify what files have been created or modified that need scanning.

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

For each changed file, categorize:

**First-Party Code (SAST)**:
- JavaScript/TypeScript: `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`
- Python: `.py`
- Java/Kotlin: `.java`, `.kt`
- Go: `.go`
- Ruby: `.rb`
- PHP: `.php`
- C#/.NET: `.cs`, `.vb`
- Swift/Objective-C: `.swift`, `.m`
- Scala: `.scala`
- Rust: `.rs`
- C/C++: `.c`, `.cpp`, `.cc`, `.h`, `.hpp`
- Apex: `.cls`, `.trigger`
- Elixir: `.ex`, `.exs`
- Groovy: `.groovy`
- Dart: `.dart`

**Package Manifests (SCA)**:
- Node.js: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- Python: `requirements.txt`, `Pipfile`, `Pipfile.lock`, `setup.py`, `pyproject.toml`
- Java: `pom.xml`, `build.gradle`, `build.gradle.kts`
- Ruby: `Gemfile`, `Gemfile.lock`
- Go: `go.mod`, `go.sum`
- Rust: `Cargo.toml`, `Cargo.lock`
- .NET: `*.csproj`, `packages.config`, `*.sln`
- PHP: `composer.json`, `composer.lock`

**Infrastructure as Code (IaC)**:
- Terraform: `.tf`, `.tf.json`, `*.tfvars`
- Kubernetes: YAML files with `apiVersion` and `kind` fields
- CloudFormation: `template.json`, `template.yaml` with `AWSTemplateFormatVersion`
- Azure ARM: `*.json` with `$schema` containing `deploymentTemplate`
- Serverless: `serverless.yml`

### Step 1.3: Filter Unsupported Files

Skip files that Snyk cannot scan:
- Binary files
- Configuration files (`.json`, `.yaml` that aren't IaC)
- Documentation (`.md`, `.txt`, `.rst`)
- Assets (images, fonts, etc.)
- Test fixtures and mock data

---

## Phase 2: Execute Scans

**Goal**: Run appropriate scans for each category of changed files.

### Step 2.1: SAST Scan (Code Vulnerabilities)

For first-party code files:

```
Run snyk_code_scan with:
- path: directory containing changed code files (or project root)
- severity_threshold: "medium" (default) or as configured
```

**Scan Scope Decision**:
- If < 5 files changed: scan each file individually for precise results
- If >= 5 files changed: scan the parent directory for efficiency

### Step 2.2: SCA Scan (Dependency Vulnerabilities)

For package manifest changes:

```
Run snyk_sca_scan with:
- path: project root or directory containing manifest
- all_projects: true (for monorepos)
- severity_threshold: "medium" (default) or as configured
```

**Important**: SCA scans the entire dependency tree, not just direct changes.

### Step 2.3: IaC Scan (Infrastructure Misconfigurations)

For infrastructure files:

```
Run snyk_iac_scan with:
- path: directory containing IaC files
- severity_threshold: "medium" (default) or as configured
```

### Step 2.4: Parallel Execution

When multiple scan types are needed, run them in parallel:
- SAST and SCA scans are independent
- IaC scans are independent of code scans

---

## Phase 3: Filter to New Issues

**Goal**: Only report issues that exist in NEW or MODIFIED code, not pre-existing issues.

### Step 3.1: SAST Issue Filtering

For each SAST finding:
1. Get the vulnerability's file and line number
2. Check if that line falls within the modified line ranges from git diff
3. **Include** only if the vulnerability line is in a changed region

```
For vulnerability at file:line
  Get modified ranges from: git diff -U0 <file>
  Parse @@ -X,Y +A,B @@ to get line ranges
  If vulnerability_line is within any modified range:
    INCLUDE (this is a new issue)
  Else:
    EXCLUDE (pre-existing issue)
```

### Step 3.2: SCA Issue Filtering

For dependency vulnerabilities:
1. Compare package versions before and after the change
2. **Include** only if:
   - A new package was added that has vulnerabilities
   - A package was upgraded/downgraded and the new version has MORE vulnerabilities
   - The vulnerability severity increased

**Net Improvement Rule**: If the change reduces overall vulnerability count or severity, do NOT block.

### Step 3.3: IaC Issue Filtering

For IaC misconfigurations:
1. Check if the misconfiguration is in a newly added or modified resource block
2. **Include** only if the resource definition was added or modified

---

## Phase 4: Report & Decision

**Goal**: Present findings clearly and make a block/allow decision.

### Step 4.1: Severity Threshold Configuration

Default thresholds (configurable):

| Mode | Block On | Warn On | Allow |
|------|----------|---------|-------|
| Strict | Low+ | - | - |
| Standard | High+ | Medium | Low |
| Relaxed | Critical only | High | Medium, Low |

### Step 4.2: Generate Report

```
## Secure At Inception Scan Results

### Summary
| Scan Type | New Issues | Blocked |
|-----------|------------|---------|
| Code (SAST) | X | Yes/No |
| Dependencies (SCA) | Y | Yes/No |
| Infrastructure (IaC) | Z | Yes/No |

### New Code Vulnerabilities (SAST)
| Severity | Type | File | Line | Description |
|----------|------|------|------|-------------|
| High | SQL Injection | src/db.ts | 45 | User input in query |

### New Dependency Vulnerabilities (SCA)
| Severity | Package | Vulnerability | Fix Version |
|----------|---------|---------------|-------------|
| Critical | lodash@4.17.15 | Prototype Pollution | 4.17.21 |

### New Infrastructure Issues (IaC)
| Severity | Resource | Issue | Recommendation |
|----------|----------|-------|----------------|
| High | aws_s3_bucket | Public access enabled | Set block_public_access |

---

### Recommended Actions

[For each issue, provide a ready-to-use fix command:]

1. `/snyk-fix SNYK-JS-LODASH-1234` - Fix lodash vulnerability
2. Review `src/db.ts:45` for SQL injection fix

---

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

**Goal**: Report prevented issues for tracking and improvement.

### Step 5.1: Send Feedback

After each scan that finds and helps fix issues:

```
Run snyk_send_feedback with:
- path: project root (absolute path)
- preventedIssuesCount: count of NEW issues found (delta, not cumulative)
- fixedExistingIssuesCount: 0 (this skill prevents, doesn't fix existing)
```

**Important**: Only count issues that were:
1. Found in NEW code (not pre-existing)
2. Would have been committed without this scan

---

## Best Practices

### When to Run This Skill

- **Automatically**: After generating new code files
- **Automatically**: After modifying existing code
- **Automatically**: Before suggesting a commit
- **On Request**: When user asks for security check

### Performance Optimization

1. **Cache Results**: Store scan results keyed by `file + content_hash`
2. **Incremental Scanning**: Only rescan changed files
3. **Batch Similar Files**: Group files by directory for efficient scanning
4. **TTL**: Cache results for 12 hours (configurable)

### False Positive Handling

If a finding is a false positive:
1. Document why it's a false positive
2. Use `.snyk` policy file to ignore:
   ```yaml
   ignore:
     SNYK-JS-EXAMPLE-12345:
       - '*':
           reason: 'False positive - input is validated upstream'
           expires: 2025-12-31
   ```
3. Re-run scan to verify it's properly ignored

### Integration with CI/CD

This skill can be invoked from CI/CD by:
1. Running on pull request creation
2. Running on push to feature branches
3. Blocking merge if threshold exceeded

### Severity Threshold Tuning

Start with "Standard" mode and adjust based on:
- **Too many blocks**: Consider "Relaxed" mode
- **Security incidents from low/medium**: Consider "Strict" mode
- **Specific vulnerability types**: Use `.snyk` policy for granular control

---

## Error Handling

### Authentication Errors
- Run `snyk_auth` and retry
- If still failing, report to user for manual authentication

### Scan Timeout
- Retry once with smaller scope
- If still failing, report partial results

### No Changes Detected
- Report "No code changes detected - nothing to scan"
- Optionally run full project scan if user requests

### Unsupported Files Only
- Report "No scannable files in changes"
- List the file types that were skipped and why

---

## Constraints

1. **New Issues Only**: Never block on pre-existing issues (that's remediation's job)
2. **Minimal Noise**: Filter aggressively to avoid alert fatigue
3. **Fast Feedback**: Complete scan within 30 seconds for typical changes
4. **Non-Destructive**: Never modify code, only report findings
5. **Actionable Output**: Every finding must have a clear fix path
