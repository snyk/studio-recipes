---
name: secure-dependency-health-check
description: |
  Helps choose secure, healthy open-source packages by evaluating vulnerability status, maintenance 
  health, popularity, community, and security posture. Use this skill when:
  - Agent needs to import a new dependency
  - User asks "which package should I use for X?"
  - User wants to compare packages (A vs B)
  - User asks "is this package safe?"
  - User asks for a "secure alternative" to a package
  - User mentions "dependency health", "package chooser", or "package security"
allowed-tools: "mcp_snyk_snyk_package_health_check Read Write Bash Grep"
license: Apache-2.0
compatibility: |
  Requires Snyk MCP server connection and authenticated Snyk account.
  Supported ecosystems: npm, pypi, maven, nuget, golang.
metadata:
  author: Snyk
  version: 1.1.0
---

# Secure Dependency Health Check

Help developers and AI agents make informed decisions when selecting open-source packages by evaluating security health, vulnerability history, popularity, community, and maintenance status.

**Core Principle**: Choose dependencies wisely to minimize supply chain risk.

---

## Quick Start

When asked to recommend a package:
1. Identify the functional requirement
2. Research candidate packages
3. Run `snyk_package_health_check` on each candidate
4. Compare and recommend the healthiest, most secure option

---

## Phase 1: Understand Requirements

**Goal**: Clarify what the user needs before recommending packages.

### Step 1.1: Identify Candidates

If user provided candidates:
- Note each package name and version (if specified)
- Identify the package ecosystem

If user needs suggestions:
- Search for packages that meet the functional requirement
- Select 2-4 top candidates based on popularity/relevance

---

## Phase 2: Security & Health Analysis

**Goal**: Evaluate each candidate package's security posture and overall health.

### Step 2.1: Run Package Health Check for Each Candidate

For each candidate package, run `snyk_package_health_check` with the package name, version, and ecosystem (`npm`, `pypi`, `maven`, `nuget`, or `golang`). Key fields returned:
- **`overall_rating`**: "Healthy" or "Review recommended" — use as the primary evaluation metric
- **`security`**: vulnerability counts by severity (critical/high/medium/low) and a security rating
- **`maintenance`**: lifecycle status, latest release date, `is_archived` flag, and a maintenance rating ("Healthy", "Sustainable", or "Inactive")
- **`popularity`**: download counts, dependent packages/repos, and a popularity rating
- **`community`**: stargazers count, community file presence, and a rating ("Active" or "Sustainable")
- **`latest_version`**: the most recent published version
- **`recommendation`**: a human-readable summary of the overall assessment

### Step 2.2: Review Tool Results

Surface the following from the tool response for comparison:
- Overall rating ("Healthy" vs "Review recommended")
- Security rating and vulnerability breakdown by severity
- Maintenance rating and lifecycle status (check `is_archived`, `latest_release_published_at`)
- Popularity and community ratings

### Step 2.3: Disqualifiers

**Immediately disqualify packages regardless of overall rating if**:
- Security issues found with critical or high severity vulnerabilities
- Maintenance rating is "Inactive" or package is archived (`is_archived: true`)
- No releases in 3+ years (check `latest_release_published_at`)
- Known malicious package (supply chain attack)
- Typosquatting indicators (similar name to popular package)

---

## Phase 3: Generate Recommendation

**Goal**: Present a clear, actionable comparison.

### Step 3.1: Comparison Table

```
## Package Comparison: [Use Case]

| Criteria | Package A | Package B | Package C |
|----------|-----------|-----------|-----------|
| **Overall Rating** | Healthy | Review recommended | Healthy |
| **Security Rating** | Security issues found | Security issues found | No known security issues |
| **Critical CVEs** | 0 | 1 | 0 |
| **High CVEs** | 1 | 2 | 0 |
| **Maintenance** | Healthy | Inactive | Healthy |
| **Last Release** | 2 weeks ago | 8 months ago | 1 month ago |
| **Downloads** | 500K | 2M | 300K |
| **Popularity** | Influential project | Influential project | Influential project |

### Recommendation: **Package C**

**Reasons**:
1. "Healthy" overall rating with no known security issues
2. Healthy maintenance rating - actively maintained with recent release
3. Fewest vulnerabilities across all severity levels

**Trade-offs**:
- Fewer downloads than Package B (less battle-tested)
- Consider if specific features of Package A/B are required

**Recommended version**: Use the `latest_version` from the tool response to pin an exact version.
```

### Step 3.2: Alternative Scenarios

If no package meets the security threshold:

```
## Warning: No Secure Option Available

All evaluated packages have significant security concerns:
- Package A: 2 Critical CVEs (actively exploited)
- Package B: Abandoned - no updates in 3 years
- Package C: Multiple high-severity vulnerabilities with no fix available

### Alternatives:
1. **Implement in-house**: For simple functionality
2. **Fork and fix**: If one package is close but has fixable issues
3. **Wait**: If updates are expected soon
4. **Accept risk**: With documented justification and monitoring
```

---

## Phase 4: Integration Guidance

**Goal**: Help the user safely add the recommended package.

### Step 4.1: Post-Installation Scan

Recommend running `snyk_sca_scan` after installation to verify the full dependency tree doesn't introduce unexpected vulnerabilities.

### Step 4.2: Monitoring Recommendation

Advise committing lock files, enabling vulnerability notifications, and checking for security updates regularly.

---

## Error Handling

### Package Not Found
- Verify package name and ecosystem
- Check for typos
- Search for alternative names

### Scan Fails or Insufficient Data
- The tool may return "Snyk doesn't have sufficient information about this package" for some packages
- Retry once; if still no data, fall back to manual research
- Report partial results with disclaimer that the tool could not assess this package

### No Candidates Meet Threshold
- Report why each failed
- Suggest alternatives (in-house, fork, wait)
- Document risk if user proceeds anyway

---

## Constraints

1. **Never recommend packages with known exploits**
2. **Always specify exact version** in recommendations
3. **Disclose limitations** if full analysis isn't possible
4. **Update recommendations** if user provides new constraints
