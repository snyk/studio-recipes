---
name: sbom-analyzer
description: |
  Software Bill of Materials (SBOM) security analysis for vulnerability assessment and third-party
  risk management. Validates SBOMs from vendors or generates SBOMs for internal projects. Use this skill when:
  - User asks to analyze an SBOM file
  - User mentions "third-party risk" or "vendor security"
  - User needs to validate a supplier's SBOM
  - User wants to check SBOM for vulnerabilities
  - User asks about CycloneDX or SPDX formats
allowed-tools: "mcp_snyk_snyk_sbom_scan Read Write Bash Grep"
license: Apache-2.0
compatibility: |
  Requires Snyk MCP server connection and authenticated Snyk account.
  SBOM must be in CycloneDX (1.4-1.6) or SPDX (2.3) JSON format.
  Components must include Package URLs (purls) for vulnerability identification.
metadata:
  author: Snyk
  version: 1.0.0
---

# SBOM Security Analyzer

Analyze Software Bill of Materials to identify vulnerabilities in declared components for third-party risk management and compliance workflows.

**Core Principle**: Know what's in your software supply chain.

---

## Quick Start

```
1. Receive or locate SBOM file (CycloneDX or SPDX)
2. Validate SBOM format and completeness
3. Run mcp_snyk_snyk_sbom_scan for vulnerability analysis
4. Generate risk report with prioritized findings
5. Provide remediation guidance
```

---

## Supported SBOM Formats

| Format | Versions | File Extension |
|--------|----------|----------------|
| **CycloneDX** | 1.4, 1.5, 1.6 | `.json` |
| **SPDX** | 2.3 | `.json` |

**Note**: `mcp_snyk_snyk_sbom_scan` requires Package URLs (purls) in the SBOM for component identification.

---

## Phase 1: SBOM Validation

**Goal**: Ensure the SBOM is valid and complete before analysis.

### Step 1.1: Identify SBOM Format

Check the file structure:

**CycloneDX Indicators**:
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [...]
}
```

**SPDX Indicators**:
```json
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "packages": [...]
}
```

### Step 1.2: Validate Completeness

Check for required elements:

| Element | CycloneDX | SPDX | Required |
|---------|-----------|------|----------|
| Format version | `specVersion` | `spdxVersion` | Yes |
| Component list | `components` | `packages` | Yes |
| Package URLs | `purl` in components | `externalRefs` | Yes* |
| Licenses | `licenses` | `licenseConcluded` | Recommended |
| Checksums | `hashes` | `checksums` | Recommended |

**\*** Package URLs are required for Snyk to identify vulnerabilities.

### Step 1.3: Report Validation Issues

If SBOM is incomplete, produce a report in this format:

```
## SBOM Validation Results

**File**: supplier-sbom.json
**Format**: CycloneDX 1.5

### Issues Found
| Issue | Severity | Count |
|-------|----------|-------|
| Missing purl | Error | 15 components |
| Missing license | Warning | 8 components |
| Missing checksum | Info | 23 components |

### Components Without purl (Cannot Scan)
- component-a (no package URL)
- component-b (no package URL)

**Recommendation**: Request updated SBOM from supplier with package URLs.
```

---

## Phase 2: Security Scan

**Goal**: Identify vulnerabilities in SBOM components.

### Step 2.1: Run SBOM Scan

Call the tool directly:

```
mcp_snyk_snyk_sbom_scan(file="path/to/sbom.json", severity_threshold="medium")
```

### Step 2.2: Organization-Scoped Scan

To apply org-specific policies:

```
mcp_snyk_snyk_sbom_scan(file="path/to/sbom.json", org="<org-id>", severity_threshold="high")
```

---

## Phase 3: Risk Analysis

**Goal**: Generate a comprehensive risk report from scan results.

Produce a single consolidated report covering summary, critical findings, and an overall risk score:

```
## SBOM Security Analysis

### Overview
| Metric | Value |
|--------|-------|
| Total Components | 156 |
| Components Scanned | 141 |
| Components Skipped | 15 (missing purl) |
| Vulnerable Components | 23 |
| Total Vulnerabilities | 47 |

### Severity Breakdown
| Severity | Count |
|----------|-------|
| Critical | 3 |
| High | 12 |
| Medium | 18 |
| Low | 14 |

### Critical Vulnerabilities
| Component | Version | CVE | CVSS | Exploited |
|-----------|---------|-----|------|-----------|
| log4j-core | 2.14.1 | CVE-2021-44228 | 10.0 | Yes |
| spring-core | 5.3.17 | CVE-2022-22965 | 9.8 | Yes |
| jackson-databind | 2.9.10 | CVE-2020-36518 | 9.8 | No |

### Risk Score: 78/100 (High Risk)
- ⚠️ 2 vulnerabilities with known exploits
- ⚠️ 3 critical severity issues
- ✓ Components from untrusted sources: 0

**Recommendation**: Do not integrate this software until critical vulnerabilities are addressed.
```

---

## Phase 4: Remediation Guidance

**Goal**: Provide actionable upgrade recommendations and vendor communication.

### Step 4.1: Upgrade Recommendations

```
## Recommended Actions

### Priority 1: Critical (Must Fix)
| Component | Current | Fixed Version | Notes |
|-----------|---------|---------------|-------|
| log4j-core | 2.14.1 | 2.17.1+ | Log4Shell |
| spring-core | 5.3.17 | 5.3.18+ | Spring4Shell |

### Priority 2: High (Should Fix)
| Component | Current | Fixed Version | Notes |
|-----------|---------|---------------|-------|
| lodash | 4.17.15 | 4.17.21 | Prototype pollution |
| axios | 0.21.1 | 1.6.0+ | SSRF vulnerability |

### Priority 3: Medium (Plan to Fix)
| Component | Current | Fixed Version | Notes |
|-----------|---------|---------------|-------|
| minimist | 1.2.5 | 1.2.8+ | Prototype pollution |
```

### Step 4.2: Vendor Communication

Draft a message to the vendor using this template (populate with actual findings):

```
Subject: Security Vulnerabilities in Software SBOM

Dear [Vendor],

During our security review of [Product Name], we identified the following
vulnerabilities in the provided SBOM:

**Critical Issues (Require Immediate Action)**:
1. [Component] [Version] - [CVE] ([Name])
2. [Component] [Version] - [CVE] ([Name])

**Request**:
1. Provide updated software with patched versions
2. Provide updated SBOM reflecting the changes
3. Confirm expected remediation timeline

We require resolution of critical issues before proceeding with integration.

Regards,
[Your Name]
```

---

## SBOM Generation (Internal Projects)

To generate an SBOM for your own project using the Snyk CLI, then scan it:

```bash
# Generate CycloneDX SBOM
snyk sbom --format=cyclonedx1.5+json > sbom.json

# Generate SPDX SBOM
snyk sbom --format=spdx2.3+json > sbom.json
```

Then scan the generated SBOM:

```
mcp_snyk_snyk_sbom_scan(file="sbom.json")
```

---

## Error Handling

### Invalid SBOM Format

```
Error: Unable to parse SBOM file

Solutions:
1. Verify file is valid JSON
2. Check SBOM format (CycloneDX/SPDX)
3. Validate against schema
4. Request corrected SBOM from source
```

### Missing Package URLs

```
Warning: X components missing purl - cannot scan

Solutions:
1. Request updated SBOM with purls
2. Manually add purls if components are known
3. Document risk of unscanned components
```

### Unsupported Version

```
Error: SBOM version not supported

Supported versions:
- CycloneDX: 1.4, 1.5, 1.6
- SPDX: 2.3

Convert SBOM to supported version if possible.
```

---

## Constraints

1. **Requires purls**: Components without package URLs cannot be scanned
2. **JSON only**: XML format not currently supported
3. **Version limits**: Only specific CycloneDX/SPDX versions supported
4. **Network required**: Vulnerability database lookup needs connectivity
5. **Point-in-time**: SBOM reflects a specific version — rescan on updates
