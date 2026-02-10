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
---

# SBOM Security Analyzer

Analyze Software Bill of Materials to identify vulnerabilities in declared components for third-party risk management and compliance workflows.

**Core Principle**: Know what's in your software supply chain.

---

## Quick Start

```
1. Receive or locate SBOM file (CycloneDX or SPDX)
2. Validate SBOM format and completeness
3. Run snyk_sbom_scan for vulnerability analysis
4. Generate risk report with prioritized findings
5. Provide remediation guidance
```

---

## Supported SBOM Formats

| Format | Versions | File Extension |
|--------|----------|----------------|
| **CycloneDX** | 1.4, 1.5, 1.6 | `.json` |
| **SPDX** | 2.3 | `.json` |

**Note**: `snyk_sbom_scan` requires Package URLs (purls) in the SBOM for component identification.

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

**\*** PackageURLs are required for Snyk to identify vulnerabilities.

### Step 1.3: Report Validation Issues

If SBOM is incomplete:

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

```
Run snyk_sbom_scan with:
- file: <path to SBOM file>
- severity_threshold: "medium" (or as configured)
```

### Step 2.2: Advanced Options

For organization-specific scans:

```
Run snyk_sbom_scan with:
- file: <path to SBOM file>
- org: <organization ID for policies>
- severity_threshold: "high"
```

---

## Phase 3: Risk Analysis

**Goal**: Generate comprehensive risk report.

### Step 3.1: Vulnerability Summary

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
| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 3 | 6% |
| High | 12 | 26% |
| Medium | 18 | 38% |
| Low | 14 | 30% |
```

### Step 3.2: Critical Findings

```
### Critical Vulnerabilities

| Component | Version | Vulnerability | CVSS | Exploited |
|-----------|---------|---------------|------|-----------|
| log4j-core | 2.14.1 | CVE-2021-44228 | 10.0 | Yes |
| spring-core | 5.3.17 | CVE-2022-22965 | 9.8 | Yes |
| jackson-databind | 2.9.10 | CVE-2020-36518 | 9.8 | No |

### Immediate Actions Required
1. **log4j-core**: Upgrade to 2.17.1+ or remove
2. **spring-core**: Upgrade to 5.3.18+ or 6.0.0+
3. **jackson-databind**: Upgrade to 2.13.0+
```

### Step 3.3: Risk Scoring

Calculate overall risk score:

```
## Risk Assessment

### Risk Score: 78/100 (High Risk)

**Calculation**:
- Critical vulns: 3 × 25 = 75 points deducted
- High vulns: 12 × 5 = 60 points deducted  
- (Capped at 100)

### Risk Factors
- ⚠️ 2 vulnerabilities with known exploits
- ⚠️ 3 critical severity issues
- ⚠️ Components from untrusted sources: 0
- ✓ All components have valid purls: No (15 missing)

### Recommendation
**Do not integrate** this software until critical vulnerabilities are addressed.
```

---

## Phase 4: Remediation Guidance

**Goal**: Provide actionable remediation steps.

### Step 4.1: Upgrade Recommendations

```
## Recommended Actions

### Priority 1: Critical (Must Fix)

| Component | Current | Fixed Version | Notes |
|-----------|---------|---------------|-------|
| log4j-core | 2.14.1 | 2.17.1+ | Log4Shell - critical |
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

### Step 4.2: Vendor Communication Template

```
## Communication Template for Vendor

Subject: Security Vulnerabilities in Software SBOM

Dear [Vendor],

During our security review of [Product Name], we identified the following 
vulnerabilities in the provided SBOM:

**Critical Issues (Require Immediate Action)**:
1. log4j-core 2.14.1 - CVE-2021-44228 (Log4Shell)
2. spring-core 5.3.17 - CVE-2022-22965 (Spring4Shell)

**Request**:
1. Please provide updated software with patched versions
2. Please provide updated SBOM reflecting the changes
3. Expected timeline for remediation

We require resolution of critical issues before proceeding with integration.

Regards,
[Your Name]
```

---

## Use Cases

### Use Case 1: Vendor SBOM Validation

```
User: Analyze this SBOM from our vendor

Process:
1. Validate SBOM format and completeness
2. Scan for vulnerabilities
3. Generate risk report
4. Prepare vendor communication if issues found
```

### Use Case 2: Compliance Check

```
User: We need to verify SBOM compliance for audit

Process:
1. Check SBOM completeness (all required fields)
2. Verify license information is present
3. Scan for known vulnerabilities
4. Generate compliance report
```

### Use Case 3: Software Supply Chain Assessment

```
User: Assess the risk of integrating this third-party software

Process:
1. Analyze SBOM for vulnerability exposure
2. Check for end-of-life components
3. Evaluate license compatibility
4. Calculate overall risk score
5. Provide go/no-go recommendation
```

---

## SBOM Generation (Internal Projects)

If you need to generate an SBOM for your own project:

### Using Snyk CLI

```bash
# Generate CycloneDX SBOM
snyk sbom --format=cyclonedx1.5+json > sbom.json

# Generate SPDX SBOM  
snyk sbom --format=spdx2.3+json > sbom.json
```

### Then Scan the Generated SBOM

```
Run snyk_sbom_scan with:
- file: sbom.json
```

---

## Compliance Standards

### SBOM Requirements by Standard

| Standard | SBOM Required | Format | Depth |
|----------|---------------|--------|-------|
| **EO 14028** | Yes | Any | All components |
| **NTIA Minimum** | Yes | Any | Direct + transitive |
| **CRA (EU)** | Yes | Preferred CycloneDX | All components |
| **NIST SP 800-218** | Recommended | Any | Direct |

### Minimum Elements (NTIA)

- Supplier name
- Component name
- Version
- Unique identifier (purl)
- Dependency relationship
- Author of SBOM data
- Timestamp

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

## Best Practices

### For Receiving SBOMs

1. **Require purls**: Without package URLs, vulnerabilities can't be identified
2. **Validate on receipt**: Check completeness before storing
3. **Regular updates**: Request updated SBOMs with each release
4. **Track history**: Maintain SBOM history for audit

### For Generating SBOMs

1. **Include all dependencies**: Direct and transitive
2. **Add metadata**: Licenses, checksums, suppliers
3. **Update regularly**: Generate with each build
4. **Sign SBOMs**: Use digital signatures for integrity

---

## Constraints

1. **Requires purls**: Components without package URLs cannot be scanned
2. **JSON only**: XML format not currently supported
3. **Version limits**: Only specific CycloneDX/SPDX versions
4. **Network required**: Vulnerability database lookup needs connectivity
5. **Point-in-time**: SBOM reflects a specific version - rescan on updates
