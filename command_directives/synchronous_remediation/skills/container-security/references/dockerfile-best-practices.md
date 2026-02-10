# Dockerfile Security Best Practices

Comprehensive guide for writing secure Dockerfiles.

## Layer 1: Base Image Security

### Use Minimal Base Images

```dockerfile
# Bad - full OS with unnecessary packages
FROM ubuntu:22.04

# Better - slim variant
FROM ubuntu:22.04-slim

# Best - minimal image
FROM alpine:3.19
# or
FROM gcr.io/distroless/static
```

### Pin Image Versions

```dockerfile
# Bad - unpredictable
FROM node:latest
FROM python

# Good - specific version
FROM node:20.10.0-alpine3.19
FROM python:3.12.1-slim-bookworm

# Best - include digest
FROM node:20.10.0-alpine3.19@sha256:abc123...
```

### Verify Image Authenticity

```dockerfile
# Use official images from trusted sources
FROM docker.io/library/node:20-alpine  # Official
FROM mcr.microsoft.com/dotnet/aspnet:8.0  # Microsoft
FROM gcr.io/distroless/static  # Google
```

---

## Layer 2: User Security

### Never Run as Root

```dockerfile
# Bad - runs as root by default
FROM node:20-alpine
COPY . /app
CMD ["node", "/app/index.js"]

# Good - create and use non-root user
FROM node:20-alpine
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup
WORKDIR /app
COPY --chown=appuser:appgroup . .
USER appuser
CMD ["node", "index.js"]
```

### Use Numeric UIDs

```dockerfile
# Avoid name lookups at runtime
USER 1001:1001
```

---

## Layer 3: Package Security

### Minimize Installed Packages

```dockerfile
# Bad - installs recommended packages
RUN apt-get update && apt-get install -y curl

# Good - no recommends, clean up
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*
```

### Update Packages

```dockerfile
# Update base packages for security fixes
RUN apt-get update && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*

# Alpine
RUN apk update && apk upgrade --no-cache
```

### Remove Unnecessary Tools

```dockerfile
# Remove package managers in production
RUN apt-get update && \
    apt-get install -y --no-install-recommends app-deps && \
    apt-get remove -y apt && \
    rm -rf /var/lib/apt/lists/*
```

---

## Layer 4: Build Security

### Use Multi-Stage Builds

```dockerfile
# Build stage - has build tools
FROM node:20-alpine AS builder
WORKDIR /build
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Production stage - minimal
FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
# Only copy what's needed
COPY --from=builder /build/dist ./dist
COPY --from=builder /build/node_modules ./node_modules
USER node
CMD ["node", "dist/index.js"]
```

### Don't Include Build Tools in Production

```dockerfile
# Bad - gcc and dev tools in production
FROM python:3.12
RUN pip install package-with-c-extension

# Good - build separately
FROM python:3.12 AS builder
RUN pip wheel --wheel-dir=/wheels package-with-c-extension

FROM python:3.12-slim
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*
```

---

## Layer 5: Secrets Security

### Never Store Secrets in Images

```dockerfile
# NEVER DO THIS
ENV API_KEY=secret123
COPY credentials.json /app/
ARG PASSWORD=secret

# Instead, use runtime injection
# docker run -e API_KEY=$API_KEY myapp
```

### Use Build Secrets (BuildKit)

```dockerfile
# syntax=docker/dockerfile:1
FROM python:3.12-slim

# Secret available only during build, not in final image
RUN --mount=type=secret,id=pip_conf,target=/etc/pip.conf \
    pip install private-package
```

### Use .dockerignore

```.dockerignore
# Exclude secrets and sensitive files
.env
*.pem
*.key
credentials.json
.git
node_modules
```

---

## Layer 6: Network Security

### Expose Only Required Ports

```dockerfile
# Only expose what's needed
EXPOSE 8080

# Don't expose debug ports in production
# EXPOSE 9229  # Node.js debugger
```

### Use Internal Networks

```yaml
# docker-compose.yml - use internal networks
services:
  app:
    networks:
      - internal
  db:
    networks:
      - internal
networks:
  internal:
    internal: true  # No external access
```

---

## Layer 7: Filesystem Security

### Use Read-Only Filesystem

```dockerfile
# Mark filesystem read-only where possible
# At runtime: docker run --read-only myapp
```

### Minimize Writable Locations

```dockerfile
# Create specific writable directories
RUN mkdir -p /app/tmp /app/logs && \
    chown -R appuser:appgroup /app/tmp /app/logs

VOLUME ["/app/tmp", "/app/logs"]
```

### Use COPY Instead of ADD

```dockerfile
# Bad - ADD has extra features that can be exploited
ADD https://example.com/file.tar.gz /app/
ADD app.tar.gz /app/

# Good - COPY is explicit
COPY app/ /app/
```

---

## Layer 8: Runtime Security

### Set Resource Limits

```dockerfile
# Use at runtime
# docker run --memory=512m --cpus=1 myapp

# Or in compose
# deploy:
#   resources:
#     limits:
#       memory: 512M
#       cpus: '1'
```

### Drop Capabilities

```dockerfile
# At runtime
# docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE myapp
```

### Use Security Options

```dockerfile
# At runtime - no new privileges
# docker run --security-opt=no-new-privileges myapp
```

---

## Common Vulnerabilities and Fixes

### CVE: Shell Injection via ENV

```dockerfile
# Vulnerable
ENV GREETING="Hello; rm -rf /"

# Safe - validate environment at runtime
# Don't use ENV for user input
```

### CVE: Path Traversal via COPY

```dockerfile
# Potentially vulnerable
COPY ${USER_INPUT} /app/

# Safe - use specific paths
COPY ./src/ /app/src/
```

### CVE: Secrets in Build Args

```dockerfile
# Vulnerable - visible in image history
ARG SECRET
RUN curl -H "Auth: $SECRET" https://api.example.com

# Safe - use BuildKit secrets
RUN --mount=type=secret,id=secret \
    curl -H "Auth: $(cat /run/secrets/secret)" https://api.example.com
```

---

## Security Scanning Integration

### Scan During Build

```dockerfile
# Add scanning as build step
FROM snyk/snyk:docker AS scanner
COPY . /app
RUN snyk test --docker myapp:latest

FROM myapp:latest
# Only proceeds if scan passes
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Build image
  run: docker build -t myapp:${{ github.sha }} .

- name: Scan image
  run: snyk container test myapp:${{ github.sha }}

- name: Push if clean
  run: docker push myapp:${{ github.sha }}
```

---

## Checklist

Before deploying any Dockerfile:

- [ ] Uses minimal base image
- [ ] Base image version is pinned
- [ ] Runs as non-root user
- [ ] No secrets in image
- [ ] .dockerignore configured
- [ ] Uses multi-stage build
- [ ] Only required ports exposed
- [ ] Packages are updated
- [ ] COPY used instead of ADD
- [ ] Security scanned
