---
name: secure-dependency-advisor
description: |
  Helps choose secure, healthy open-source packages by evaluating vulnerability status, maintenance 
  health, license compatibility, and security posture. Use this skill when:
  - User asks "which package should I use for X?"
  - User wants to compare packages (A vs B)
  - User asks "is this package safe?"
  - Agent needs to import a new dependency
  - User asks for a "secure alternative" to a package
  - User mentions "dependency advisor", "package chooser", or "package security"
allowed-tools:
  - mcp_snyk_snyk_sca_scan
  - Read
  - Write
  - Bash
  - Grep
license: Apache-2.0
compatibility: |
  Requires Snyk MCP server connection and authenticated Snyk account.
  Works with any package ecosystem supported by Snyk SCA (npm, pip, Maven, Gradle,
  RubyGems, Go modules, Cargo, NuGet, Composer, and more).
metadata:
  author: Snyk
  version: 1.0.0
---

# Secure Dependency Advisor

Help developers and AI agents make informed decisions when selecting open-source packages by evaluating security health, vulnerability history, and maintenance status.

**Core Principle**: Choose dependencies wisely to minimize supply chain risk.

---

## Quick Start

When asked to recommend a package:
1. Identify the functional requirement
2. Research candidate packages
3. Run security scans on candidates
4. Compare and recommend the most secure option

---

## Phase 1: Understand Requirements

**Goal**: Clarify what the user needs before recommending packages.

### Step 1.1: Parse User Request

Extract from user input:
- **Functionality needed**: What should the package do?
- **Ecosystem**: Node.js, Python, Java, etc.
- **Constraints**: Size limits, licensing requirements, compatibility needs
- **Current packages**: Are they replacing something?

### Step 1.2: Identify Candidates

If user provided candidates:
- Note each package name and version (if specified)
- Identify the package ecosystem

If user needs suggestions:
- Search for packages that meet the functional requirement
- Select 2-4 top candidates based on popularity/relevance

---

## Phase 2: Security Analysis

**Goal**: Evaluate each candidate package's security posture.

### Step 2.1: Run SCA Scan for Each Candidate

For each candidate package, create a temporary manifest and scan:

**Node.js (npm)**:
```json
{
  "name": "temp-scan",
  "dependencies": {
    "candidate-package": "latest"
  }
}
```

**Python (pip)**:
```
candidate-package
```

Run `snyk_sca_scan` on the temporary manifest to get:
- Direct vulnerabilities
- Transitive dependency vulnerabilities
- Total dependency count

### Step 2.2: Evaluate Security Metrics

For each candidate, gather:

| Metric | How to Evaluate | Weight |
|--------|-----------------|--------|
| **Critical CVEs** | Count from scan | Critical factor |
| **High CVEs** | Count from scan | High weight |
| **Medium CVEs** | Count from scan | Medium weight |
| **Known Exploits** | Check for "exploit available" flag | Critical factor |
| **Transitive Risk** | Total vulns in dependency tree | Medium weight |
| **Fix Available** | Check if upgrade path exists | Bonus points |

### Step 2.3: Calculate Security Score

```
Security Score = 100 - (Critical × 25) - (High × 10) - (Medium × 3) - (Low × 1)

If known exploit exists: Score = 0 (do not recommend)
If no vulnerabilities: Score = 100
```

Minimum viable score: **70** (configurable)

---

## Phase 3: Health Analysis

**Goal**: Evaluate package maintenance and community health.

### Step 3.1: Maintenance Indicators

Evaluate (when information is available):

| Indicator | Good Sign | Warning Sign |
|-----------|-----------|--------------|
| **Last update** | Within 6 months | Over 2 years |
| **Open issues** | Actively triaged | Hundreds unaddressed |
| **Contributors** | Multiple active | Single maintainer |
| **Releases** | Regular schedule | Sporadic or none |
| **Documentation** | Comprehensive | Missing or outdated |

### Step 3.2: Community Health

Consider:
- **Downloads/week**: Higher is generally better (more eyes, more testing)
- **GitHub stars**: Indicator of community interest
- **Dependent packages**: How many other packages rely on it
- **Security policy**: Does the project have SECURITY.md?
- **Funding**: Is the project sustainably funded?

### Step 3.3: Red Flags

**Immediately disqualify packages with**:
- No updates in 3+ years (likely abandoned)
- Known malicious package (supply chain attack)
- Single maintainer who has gone silent
- No license specified
- Typosquatting indicators (similar name to popular package)

---

## Phase 4: License Analysis

**Goal**: Ensure license compatibility with the user's project.

### Step 4.1: License Categories

| Category | Licenses | Compatibility |
|----------|----------|---------------|
| **Permissive** | MIT, BSD, Apache 2.0, ISC | Generally safe |
| **Weak Copyleft** | LGPL, MPL | Usually OK for dependencies |
| **Strong Copyleft** | GPL, AGPL | May require source disclosure |
| **Proprietary** | Custom, Commercial | Requires review |
| **None** | Unlicensed | Avoid - unclear rights |

### Step 4.2: License Compatibility Check

From `snyk_sca_scan` results, identify:
- Package's license
- Transitive dependencies' licenses

**Flag if**:
- GPL/AGPL in proprietary project
- License incompatibility in chain
- Unknown or missing license

---

## Phase 5: Generate Recommendation

**Goal**: Present a clear, actionable comparison.

### Step 5.1: Comparison Table

```
## Package Comparison: [Use Case]

| Criteria | Package A | Package B | Package C |
|----------|-----------|-----------|-----------|
| **Security Score** | 85/100 | 60/100 | 95/100 |
| **Critical CVEs** | 0 | 1 | 0 |
| **High CVEs** | 1 | 2 | 0 |
| **Total Dependencies** | 12 | 45 | 8 |
| **Last Update** | 2 weeks ago | 8 months ago | 1 month ago |
| **Weekly Downloads** | 500K | 2M | 300K |
| **License** | MIT | Apache 2.0 | MIT |
| **Bundle Size** | 15KB | 120KB | 10KB |

### Recommendation: **Package C**

**Reasons**:
1. Highest security score (95/100) - no known vulnerabilities
2. Smallest dependency footprint (8 deps) - less attack surface
3. Actively maintained - updated last month
4. MIT license - no compatibility concerns

**Trade-offs**:
- Fewer downloads than Package B (less battle-tested)
- Consider if specific features of Package A/B are required
```

### Step 5.2: Alternative Scenarios

If no package meets the security threshold:

```
## Warning: No Secure Option Available

All evaluated packages have significant security concerns:
- Package A: 2 Critical CVEs (actively exploited)
- Package B: Abandoned - no updates in 3 years
- Package C: GPL license incompatible with your project

### Alternatives:
1. **Implement in-house**: For simple functionality
2. **Fork and fix**: If one package is close but has fixable issues
3. **Wait**: If updates are expected soon
4. **Accept risk**: With documented justification and monitoring
```

---

## Phase 6: Integration Guidance

**Goal**: Help the user safely add the recommended package.

### Step 6.1: Installation Command

Provide the exact command to install:

```bash
# Node.js
npm install package-name@version

# Python
pip install package-name==version

# etc.
```

**Always specify version** to ensure reproducible security posture.

### Step 6.2: Post-Installation Scan

Recommend running Secure At Inception scan after installation:
```
After adding the package, run a security scan to verify the full 
dependency tree doesn't introduce unexpected vulnerabilities.
```

### Step 6.3: Monitoring Recommendation

```
## Ongoing Security

1. **Lock file**: Ensure package-lock.json / yarn.lock is committed
2. **Monitoring**: Consider `snyk monitor` for continuous tracking
3. **Updates**: Check for security updates monthly
4. **Alerts**: Set up vulnerability notifications
```

---

## Common Scenarios

### Scenario 1: "Which HTTP client should I use?"

```
User: Which HTTP client should I use for Node.js?

Process:
1. Identify candidates: axios, node-fetch, got, undici
2. Scan each for vulnerabilities
3. Compare maintenance and size
4. Recommend based on security + features needed
```

### Scenario 2: "Is lodash safe to use?"

```
User: Is lodash safe to use?

Process:
1. Scan lodash@latest for vulnerabilities
2. Check for historical security issues
3. Evaluate current fix availability
4. Provide yes/no with specific version recommendation
```

### Scenario 3: "Find a secure alternative to X"

```
User: I need a secure alternative to vulnerable-package

Process:
1. Identify what vulnerable-package does
2. Find packages with similar functionality
3. Scan and compare alternatives
4. Recommend most secure option with migration notes
```

---

## Decision Framework

### When to Recommend

| Security Score | Known Exploits | Maintenance | Recommendation |
|----------------|----------------|-------------|----------------|
| 90-100 | No | Active | **Strongly Recommend** |
| 70-89 | No | Active | **Recommend** with notes |
| 50-69 | No | Active | **Caution** - document risks |
| Any | Yes | Any | **Do Not Recommend** |
| Any | Any | Abandoned | **Do Not Recommend** |

### Tie-Breakers

When security scores are similar, prefer:
1. Fewer total dependencies (smaller attack surface)
2. More recent updates (active maintenance)
3. Larger community (more security review)
4. Simpler license (easier compliance)

---

## Error Handling

### Package Not Found
- Verify package name and ecosystem
- Check for typos
- Search for alternative names

### Scan Fails
- Retry once
- Fall back to manual research if needed
- Report partial results with disclaimer

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
5. **Respect license requirements** - flag incompatibilities clearly
