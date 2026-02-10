---
name: container-security
description: |
  Comprehensive container image security scanning and remediation. Analyzes Docker images for 
  OS package vulnerabilities, application dependencies, and Dockerfile best practices. Use this skill when:
  - User asks to scan a Docker image or container
  - User mentions "container security" or "image vulnerabilities"
  - User wants to secure a Dockerfile
  - User asks about base image security
  - Agent is working with Docker, Kubernetes, or container deployments
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

**Goal**: Determine what container image to scan.

### Step 1.1: Parse User Input

Identify the image reference:

| Format | Example | Notes |
|--------|---------|-------|
| Local image | `myapp:latest` | Must exist in Docker daemon |
| Registry image | `nginx:1.25` | Pulls from Docker Hub |
| Private registry | `gcr.io/project/app:v1` | May need auth |
| Image ID | `sha256:abc123...` | Exact image hash |
| Archive | `./image.tar` | Saved image archive |

### Step 1.2: Determine Scan Scope

Ask or infer:
- **App vulns**: Include application dependencies? (default: yes for v1.1090.0+)
- **Base image**: Separate base image vulns? (useful for understanding what you control)
- **Platform**: For multi-arch images, which platform? (linux/amd64, linux/arm64)

---

## Phase 2: Execute Scan

**Goal**: Run comprehensive container security scan.

### Step 2.1: Basic Scan

```
Run snyk_container_scan with:
- image: <image name or path>
```

### Step 2.2: Advanced Scan Options

For more comprehensive analysis:

```
Run snyk_container_scan with:
- image: <image name>
- file: <path to Dockerfile>  # Better remediation advice
- app_vulns: true             # Scan app dependencies
- severity_threshold: "high"   # Filter results
```

### Step 2.3: Base Image Analysis

To understand inherited vs. added vulnerabilities:

```
Run snyk_container_scan with:
- image: <image name>
- exclude_base_image_vulns: true  # See only what you added
```

Then run again without the flag to see full picture.

---

## Phase 3: Analyze Results

**Goal**: Understand and categorize vulnerabilities.

### Step 3.1: Categorize Findings

Container scan results include multiple vulnerability sources:

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

For each vulnerability category:

**OS Packages**:
- Update package in Dockerfile
- Upgrade base image
- Use distroless/minimal base

**App Dependencies**:
- Update in source manifest
- Rebuild image with updated dependencies

**No Fix Available**:
- Document accepted risk
- Consider alternative package
- Wait for upstream fix

---

## Phase 4: Remediation Guidance

**Goal**: Provide actionable fixes.

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

### Alternative (Alpine)
```dockerfile
# Update all packages
RUN apk update && apk upgrade --no-cache
```
```

### Step 4.3: Application Dependency Fixes

For vulnerabilities in app dependencies:

```
## Application Dependency Fix

**Package**: lodash (via npm)
**Current**: 4.17.15
**Fix Version**: 4.17.21

### Steps
1. Update package.json:
   "lodash": "^4.17.21"

2. Rebuild image:
   docker build -t myapp:fixed .

3. Verify fix:
   snyk container test myapp:fixed
```

### Step 4.4: Dockerfile Best Practices

Recommend improvements:

```
## Dockerfile Security Improvements

### 1. Use Specific Base Image Tags
```dockerfile
# Bad - unpredictable
FROM node:latest

# Good - specific version
FROM node:20.10.0-alpine3.19
```

### 2. Run as Non-Root
```dockerfile
# Add before CMD
RUN addgroup -g 1001 appgroup && \
    adduser -u 1001 -G appgroup -D appuser
USER appuser
```

### 3. Use Multi-Stage Builds
```dockerfile
# Build stage
FROM node:20 AS builder
WORKDIR /app
COPY . .
RUN npm ci && npm run build

# Production stage - smaller, fewer vulns
FROM node:20-alpine
COPY --from=builder /app/dist /app
CMD ["node", "/app/index.js"]
```

### 4. Minimize Installed Packages
```dockerfile
# Bad
RUN apt-get install -y curl wget vim nano

# Good - only what's needed
RUN apt-get install -y --no-install-recommends curl
```
```

---

## Phase 5: Verification

**Goal**: Confirm fixes were effective.

### Step 5.1: Rebuild Image

After making Dockerfile changes:

```bash
# Rebuild with no cache to ensure fresh packages
docker build --no-cache -t myapp:fixed .
```

### Step 5.2: Re-scan

```
Run snyk_container_scan with:
- image: myapp:fixed
- file: ./Dockerfile
```

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

## Base Image Recommendations

### By Language/Runtime

| Runtime | Recommended Base | Notes |
|---------|------------------|-------|
| Node.js | `node:20-alpine` | Smallest, but missing some libs |
| Node.js | `node:20-slim` | Debian-based, more compatible |
| Python | `python:3.12-slim` | Good balance |
| Python | `python:3.12-alpine` | Smallest |
| Java | `eclipse-temurin:21-jre-alpine` | JRE only |
| Go | `gcr.io/distroless/static` | No shell, minimal attack surface |
| .NET | `mcr.microsoft.com/dotnet/aspnet:8.0-alpine` | Runtime only |

### Distroless Options

For maximum security:

| Base | Use Case | Pros | Cons |
|------|----------|------|------|
| `gcr.io/distroless/static` | Go, Rust (static) | No OS, tiny | No shell, no debugging |
| `gcr.io/distroless/base` | Most languages | Minimal OS | Limited packages |
| `gcr.io/distroless/java` | Java apps | JRE only | No shell |
| `gcr.io/distroless/nodejs` | Node.js | Node only | No npm |

---

## Common Scenarios

### Scenario 1: "Scan my Docker image"

```
User: Scan my app:latest image

Process:
1. Run snyk_container_scan with image: "app:latest"
2. Summarize findings by category
3. Recommend highest-priority fixes
4. Provide Dockerfile changes
```

### Scenario 2: "Secure my Dockerfile"

```
User: Help me secure this Dockerfile

Process:
1. Review Dockerfile for best practices
2. Build image if not already built
3. Scan resulting image
4. Combine scan results with Dockerfile review
5. Provide unified remediation
```

### Scenario 3: "Find a more secure base image"

```
User: My base image has too many vulnerabilities

Process:
1. Identify current base image and vulnerabilities
2. Scan alternative base images
3. Compare vulnerability counts
4. Recommend best option with migration notes
```

---

## Error Handling

### Image Not Found

```
Error: Image not found locally

Solutions:
1. Pull from registry: docker pull <image>
2. Check image name spelling
3. Verify image exists in registry
```

### Registry Authentication

```
Error: Authentication required

Solutions:
1. Log in to registry: docker login <registry>
2. Check credentials are valid
3. Verify access permissions
```

### Scan Timeout

```
Error: Scan timed out

Solutions:
1. Image may be very large - retry
2. Pull image locally first, then scan
3. Scan archive instead of registry
```

---

## Constraints

1. **Scan before deploy**: Never deploy unscanned images
2. **Pin versions**: Use specific image tags, not `latest`
3. **Document exceptions**: If vulnerabilities can't be fixed, document why
4. **Regular rescans**: Images should be rescanned weekly for new CVEs
5. **Multi-stage builds**: Prefer smaller production images
