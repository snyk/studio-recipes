---
name: container-security
description: |
  Comprehensive container image security scanning and remediation. Analyzes Docker images for 
  OS package vulnerabilities, application dependencies, and Dockerfile best practices. Use when:
  - User asks to scan a Docker image or container
  - User mentions "container security" or "image vulnerabilities"
  - User wants to secure a Dockerfile
  - User asks about base image security
  - Agent is working with Docker, Kubernetes, or container deployments
allowed-tools: "mcp_snyk_snyk_container_scan Read Write Edit Bash Grep"
license: Apache-2.0
compatibility: |
  Requires Snyk MCP server connection and authenticated Snyk account.
  Docker must be installed for local image scanning.
  Registry authentication may be required for private images.
metadata:
  author: Snyk
  version: 1.0.0
---

# Container Security Scanner

Guide for comprehensive container image security analysis, covering OS vulnerabilities, application dependencies, and Dockerfile best practices.

**Core Principle**: Secure containers from the base up - secure base image, minimal packages, no vulnerabilities.

---

## Quick Start

```
1. Identify image to scan (local, registry, or archive)
2. Run snyk_container_scan with image name
3. Analyze results: OS packages + application deps
4. Provide remediation guidance
5. Optionally fix Dockerfile issues
```

---

## Phase 1: Image Identification

### Step 1.1: Parse User Input

Extract the image reference from the user's request (e.g., `myapp:latest`, `nginx:1.25`, `gcr.io/project/app:v1`, `sha256:abc123...`, or `./image.tar`).

### Step 1.2: Determine Scan Scope

Ask or infer:
- **App vulns**: Include application dependencies? (default: yes for v1.1090.0+)
- **Base image**: Separate base image vulns? (useful for understanding what you control)
- **Platform**: For multi-arch images, which platform? (linux/amd64, linux/arm64)

---

## Phase 2: Execute Scan

### Step 2.1: Basic Scan

Invoke `mcp_snyk_snyk_container_scan` with:
- `image`: the image name or path

### Step 2.2: Advanced Scan Options

For more comprehensive analysis, invoke `mcp_snyk_snyk_container_scan` with:
- `image`: the image name
- `file`: path to Dockerfile (enables better remediation advice)
- `app_vulns`: `true` (scan app dependencies)
- `severity_threshold`: `"high"` (filter to high/critical only)

### Step 2.3: Base Image Analysis

To isolate inherited vs. added vulnerabilities:

1. Invoke `mcp_snyk_snyk_container_scan` with `image` and `exclude_base_image_vulns: true` — shows only vulnerabilities your layers added.
2. Invoke again without that flag — shows the full picture including base OS.

---

## Phase 3: Analyze Results

### Step 3.1: Categorize Findings

| Source | Description | Your Control |
|--------|-------------|--------------|
| **Base OS packages** | Installed by base image | Change base image |
| **Additional OS packages** | Installed via apt/yum | Update or remove |
| **App dependencies** | Node modules, Python packages | Update versions |
| **Dockerfile issues** | Misconfigurations | Direct fix |

### Step 3.2: Generate Summary

```
## Container Scan Results: [image:tag]

### Overview
| Category | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| OS Packages | X | Y | Z | W |
| App Dependencies | A | B | C | D |
| **Total** | X+A | Y+B | Z+C | W+D |

### Base Image Analysis
- **Base**: [base image detected]
- **Vulnerabilities from base**: [count]
- **Vulnerabilities you added**: [count]

### Top Priority Issues

| Severity | Package | Vulnerability | Fix Available |
|----------|---------|---------------|---------------|
| Critical | openssl | CVE-2024-XXXX | Yes - 3.0.12 |
| High | libcurl | CVE-2024-YYYY | Yes - 8.5.0 |
```

### Step 3.3: Identify Fix Strategies

**OS Packages**: Update package in Dockerfile, upgrade base image, or use distroless/minimal base.

**App Dependencies**: Update in source manifest and rebuild image with updated dependencies.

**No Fix Available**: Document accepted risk, consider alternative package, or wait for upstream fix.

---

## Phase 4: Remediation Guidance

### Step 4.1: Base Image Upgrades

If base image has vulnerabilities:

```
## Base Image Recommendation

**Current**: node:16-alpine
**Vulnerabilities**: 15 (3 Critical, 5 High)

**Recommended**: node:20-alpine
**Vulnerabilities**: 2 (0 Critical, 1 High)

### Dockerfile Change
```dockerfile
# Before
FROM node:16-alpine

# After
FROM node:20-alpine
```

### Migration Notes
- Node 20 has breaking changes in [list]
- Test thoroughly before deploying
```

### Step 4.2: Package Updates

For individual package vulnerabilities:

```
## Package Fix: openssl

**Current**: 3.0.8
**Vulnerable to**: CVE-2024-XXXX (Critical)
**Fix Version**: 3.0.12

### Dockerfile Addition
```dockerfile
# Add before your application layer
RUN apk update && apk upgrade openssl
```
```

### Step 4.3: Application Dependency Fixes

```
## Application Dependency Fix

**Package**: lodash (via npm)
**Current**: 4.17.15
**Fix Version**: 4.17.21

### Steps
1. Update package.json: "lodash": "^4.17.21"
2. Rebuild image: docker build -t myapp:fixed .
3. Verify fix: snyk container test myapp:fixed
```

### Step 4.4: Dockerfile Best Practices

Key improvements to recommend:

```dockerfile
# 1. Pin specific tags (not latest)
FROM node:20.10.0-alpine3.19

# 2. Run as non-root
RUN addgroup -g 1001 appgroup && \
    adduser -u 1001 -G appgroup -D appuser
USER appuser

# 3. Multi-stage builds (smaller image, fewer vulns)
FROM node:20 AS builder
WORKDIR /app
COPY . .
RUN npm ci && npm run build

FROM node:20-alpine
COPY --from=builder /app/dist /app
CMD ["node", "/app/index.js"]

# 4. Minimize packages
RUN apt-get install -y --no-install-recommends curl
```

---

## Phase 5: Verification

### Step 5.1: Rebuild Image

```bash
# Rebuild with no cache to ensure fresh packages
docker build --no-cache -t myapp:fixed .
```

### Step 5.2: Re-scan

Invoke `mcp_snyk_snyk_container_scan` with:
- `image`: `myapp:fixed`
- `file`: `./Dockerfile`

### Step 5.3: Compare Results

```
## Fix Verification

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Critical | 3 | 0 | -3 ✅ |
| High | 5 | 1 | -4 ✅ |
| Medium | 12 | 8 | -4 ✅ |
| Total | 20 | 9 | -11 ✅ |

### Remaining Issues
- 1 High: No fix available upstream (document risk)
- 8 Medium: Low priority (schedule for next sprint)
```

---

## End-to-End Example

**User**: "Scan my app:latest image and help me fix it."

**Step 1** — Run the scan:

```
mcp_snyk_snyk_container_scan(image="app:latest", app_vulns=true)
```

**Step 2** — Tool returns (example output):
```json
{
  "summary": "Found 18 vulnerabilities (2 Critical, 6 High, 10 Medium)",
  "baseImage": "node:16-alpine",
  "vulnerabilities": [
    { "severity": "critical", "pkgName": "openssl", "version": "3.0.8",
      "fixedIn": "3.0.12", "id": "CVE-2024-0001" },
    { "severity": "high", "pkgName": "lodash", "version": "4.17.15",
      "fixedIn": "4.17.21", "id": "CVE-2021-23337" }
  ]
}
```

**Step 3** — Deliver structured response:
```
## Scan Results: app:latest
Base image: node:16-alpine | 2 Critical · 6 High · 10 Medium

### Immediate Actions
1. Upgrade base image → node:20-alpine (eliminates ~14 vulns)
2. Pin openssl ≥ 3.0.12 in Dockerfile (CVE-2024-0001, Critical)
3. Update lodash to ^4.17.21 in package.json (CVE-2021-23337, High)

### Dockerfile patch
FROM node:20-alpine        # was node:16-alpine
RUN apk add --no-cache openssl>=3.0.12
```

**Step 4** — After applying fixes, rebuild and re-scan to confirm resolution.

---

## Common Scenarios

### Scenario 1: "Scan my Docker image"

```
1. Invoke snyk_container_scan(image="app:latest")
2. Summarize findings by category
3. Recommend highest-priority fixes
4. Provide Dockerfile changes
```

### Scenario 2: "Secure my Dockerfile"

```
1. Review Dockerfile for best practices
2. Build image if not already built
3. Invoke snyk_container_scan(image=..., file="./Dockerfile")
4. Combine scan results with Dockerfile review
5. Provide unified remediation
```

### Scenario 3: "Find a more secure base image"

```
1. Identify current base image and vulnerabilities
2. Scan alternative base images
3. Compare vulnerability counts
4. Recommend best option with migration notes
```

---

## Base Image Quick Reference

| Runtime | Recommended Base | Notes |
|---------|------------------|-------|
| Node.js | `node:20-alpine` | Smallest, may lack some libs |
| Node.js | `node:20-slim` | Debian-based, more compatible |
| Python | `python:3.12-slim` | Good balance |
| Python | `python:3.12-alpine` | Smallest |
| Java | `eclipse-temurin:21-jre-alpine` | JRE only |
| Go | `gcr.io/distroless/static` | No shell, minimal attack surface |
| .NET | `mcr.microsoft.com/dotnet/aspnet:8.0-alpine` | Runtime only |

**Distroless options** (`gcr.io/distroless/`): `static` (Go/Rust), `base` (most languages), `java`, `nodejs` — all offer minimal attack surface with no shell.

---

## Error Handling

| Error | Solutions |
|-------|-----------|
| Image not found locally | `docker pull <image>` · check name spelling · verify registry access |
| Registry authentication required | `docker login <registry>` · verify credentials and permissions |
| Scan timed out | Retry · pull image locally first · scan a `.tar` archive instead |

---

## Constraints

1. **Scan before deploy**: Never deploy unscanned images
2. **Pin versions**: Use specific image tags, not `latest`
3. **Document exceptions**: If vulnerabilities can't be fixed, document why
4. **Regular rescans**: Images should be rescanned weekly for new CVEs
5. **Multi-stage builds**: Prefer smaller production images
