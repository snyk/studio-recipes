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

## Phase 1: Understand Requirements & Identify Candidates

If user provided candidates, note each package name, version (if specified), and ecosystem. If no candidates are specified, search for packages that meet the functional requirement and select 2–4 top candidates based on popularity/relevance.

---

## Phase 2: Security & Health Analysis

### Step 2.1: Run Package Health Check for Each Candidate

For each candidate package, run `snyk_package_health_check` with the package name, version, and ecosystem (`npm`, `pypi`, `maven`, `nuget`, or `golang`). The tool returns a comprehensive assessment including:
- **`overall_rating`**: "Healthy" or "Review recommended"
- **`security`**: vulnerability counts by severity (critical/high/medium/low), whether direct vulnerabilities exist, and a security rating
- **`maintenance`**: lifecycle status, latest release date, whether the package is archived or forked, and a maintenance rating ("Healthy", "Sustainable", or "Inactive")
- **`popularity`**: download counts, dependent packages/repos, and a popularity rating
- **`community`**: stargazers count, presence of README/contributing/code of conduct/funding files, and a community rating ("Active" or "Sustainable")
- **`latest_version`**: the most recent published version
- **`recommendation`**: a human-readable summary of the overall assessment

### Step 2.2: Review Tool Results

Use the `overall_rating` as the primary evaluation metric. Surface the following for comparison:
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

### Step 3.1: Comparison Table

```
## Package Comparison: [Use Case]

| Criteria | Package A | Package B | Package C |
|----------|-----------|-----------|-----------|
| **Overall Rating** | | | |
| **Security Rating** | | | |
| **Critical CVEs** | | | |
| **High CVEs** | | | |
| **Maintenance** | | | |
| **Last Release** | | | |
| **Downloads** | | | |
| **Popularity** | | | |

### Recommendation: **[Package Name]**

**Reasons**:
1. [Overall rating and security posture]
2. [Maintenance rating and release recency]
3. [Vulnerability comparison across candidates]

**Trade-offs**: [Note any relevant downsides vs. alternatives]

**Recommended version**: Use the `latest_version` from the tool response to pin an exact version.
```

### Step 3.2: Alternative Scenarios

If no package meets the security threshold:

```
## Warning: No Secure Option Available

All evaluated packages have significant security concerns:
- Package A: [reason]
- Package B: [reason]
- Package C: [reason]

### Alternatives:
1. **Implement in-house**: For simple functionality
2. **Fork and fix**: If one package is close but has fixable issues
3. **Wait**: If updates are expected soon
4. **Accept risk**: With documented justification and monitoring
```

---

## Phase 4: Integration Guidance

### Step 4.1: Post-Installation Scan

Recommend running `snyk_sca_scan` after installation to verify the full dependency tree doesn't introduce unexpected vulnerabilities.

### Step 4.2: Monitoring Recommendation

```
## Ongoing Security

1. **Lock file**: Ensure package-lock.json / yarn.lock is committed
2. **Monitoring**: Consider `snyk monitor` for continuous tracking
3. **Updates**: Check for security updates monthly
4. **Alerts**: Set up vulnerability notifications
```

---

## Error Handling

- **Package Not Found**: Verify package name and ecosystem; check for typos; search for alternative names.
- **Scan Fails or Insufficient Data**: The tool may return "Snyk doesn't have sufficient information about this package" for some packages. Retry once; if still no data, fall back to manual research and report partial results with a disclaimer.
- **No Candidates Meet Threshold**: Report why each failed, suggest alternatives (in-house, fork, wait), and document risk if user proceeds anyway.

---

## Constraints

1. **Never recommend packages with known exploits**
2. **Always specify exact version** in recommendations
3. **Disclose limitations** if full analysis isn't possible
4. **Update recommendations** if user provides new constraints
