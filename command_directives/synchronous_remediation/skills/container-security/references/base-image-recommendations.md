# Base Image Recommendations

Curated list of secure base images by use case.

## Selection Criteria

When choosing a base image, consider:
1. **Vulnerability count**: Fewer packages = fewer vulnerabilities
2. **Image size**: Smaller = faster deployment, less attack surface
3. **Maintenance**: Active updates and security patches
4. **Compatibility**: Required libraries for your application

---

## Recommended Base Images by Runtime

### Node.js

| Image | Size | Security | Use Case |
|-------|------|----------|----------|
| `node:20-alpine` | ~50MB | Best | Most apps, CLI tools |
| `node:20-slim` | ~80MB | Good | When Alpine misses libs |
| `node:20-bookworm` | ~350MB | Fair | Full Debian, dev tools |
| `gcr.io/distroless/nodejs20` | ~40MB | Best | Production, no shell |

**Recommendation**: Start with `node:20-alpine`, use `-slim` if you hit native module issues.

### Python

| Image | Size | Security | Use Case |
|-------|------|----------|----------|
| `python:3.12-alpine` | ~50MB | Best | Simple apps |
| `python:3.12-slim` | ~130MB | Good | Most apps |
| `python:3.12-bookworm` | ~900MB | Fair | Data science, C extensions |
| `gcr.io/distroless/python3` | ~50MB | Best | Production |

**Recommendation**: Use `python:3.12-slim` for most cases. Alpine can have issues with some packages (wheels).

### Java

| Image | Size | Security | Use Case |
|-------|------|----------|----------|
| `eclipse-temurin:21-jre-alpine` | ~90MB | Best | Production runtime |
| `eclipse-temurin:21-jre-jammy` | ~220MB | Good | Ubuntu-based |
| `amazoncorretto:21-alpine` | ~100MB | Best | AWS environments |
| `gcr.io/distroless/java21` | ~90MB | Best | Production |

**Recommendation**: `eclipse-temurin:21-jre-alpine` for most cases.

### Go

| Image | Size | Security | Use Case |
|-------|------|----------|----------|
| `golang:1.22-alpine` | ~260MB | Good | Build stage |
| `gcr.io/distroless/static` | ~2MB | Best | Static binaries |
| `alpine:3.19` | ~7MB | Good | If you need shell |
| `scratch` | ~0MB | Best | Pure static binaries |

**Recommendation**: Build with `golang:alpine`, deploy with `distroless/static` or `scratch`.

### .NET

| Image | Size | Security | Use Case |
|-------|------|----------|----------|
| `mcr.microsoft.com/dotnet/aspnet:8.0-alpine` | ~100MB | Best | ASP.NET apps |
| `mcr.microsoft.com/dotnet/runtime:8.0-alpine` | ~85MB | Best | Console apps |
| `mcr.microsoft.com/dotnet/aspnet:8.0-jammy-chiseled` | ~110MB | Best | Ubuntu, no shell |

**Recommendation**: Alpine variants for smallest size, chiseled for Ubuntu compatibility without shell.

### Rust

| Image | Size | Security | Use Case |
|-------|------|----------|----------|
| `rust:1.75-alpine` | ~700MB | Good | Build stage |
| `gcr.io/distroless/static` | ~2MB | Best | Musl binaries |
| `debian:bookworm-slim` | ~80MB | Good | Glibc binaries |

**Recommendation**: Build with `rust:alpine`, deploy with `distroless/static`.

---

## Distroless Deep Dive

Distroless images contain only your application and its runtime dependencies - no package manager, no shell.

### Available Distroless Images

| Image | Contents | Size |
|-------|----------|------|
| `gcr.io/distroless/static` | Just libc (musl) | ~2MB |
| `gcr.io/distroless/base` | Basic glibc | ~20MB |
| `gcr.io/distroless/cc` | libgcc, libstdc++ | ~25MB |
| `gcr.io/distroless/java21` | OpenJDK 21 | ~90MB |
| `gcr.io/distroless/nodejs20` | Node.js 20 | ~40MB |
| `gcr.io/distroless/python3` | Python 3 | ~50MB |

### Debugging Distroless

Since there's no shell, use debug variants for troubleshooting:

```dockerfile
# Production
FROM gcr.io/distroless/static

# Debug (has busybox shell)
FROM gcr.io/distroless/static:debug
```

---

## Alpine Considerations

### Pros
- Very small (~5MB base)
- Frequent security updates
- musl libc (smaller than glibc)

### Cons
- musl libc incompatibilities with some software
- Missing some GNU tools
- Some packages unavailable

### Common Alpine Issues

| Issue | Symptom | Solution |
|-------|---------|----------|
| Native modules | Segfault, crash | Use `-slim` instead |
| DNS resolution | Slow lookups | Add `options single-request` |
| Locale | Encoding errors | Install `musl-locales` |
| glibc apps | "not found" errors | Use gcompat or different base |

---

## Multi-Stage Build Patterns

### Node.js

```dockerfile
# Build stage
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Production stage
FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
USER node
CMD ["node", "dist/index.js"]
```

### Go

```dockerfile
# Build stage
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /app/server

# Production stage
FROM gcr.io/distroless/static
COPY --from=builder /app/server /server
USER nonroot
ENTRYPOINT ["/server"]
```

### Python

```dockerfile
# Build stage
FROM python:3.12-slim AS builder
WORKDIR /app
RUN pip install --user pipenv
COPY Pipfile* ./
RUN pipenv install --deploy --system

# Production stage
FROM python:3.12-slim
WORKDIR /app
COPY --from=builder /root/.local /root/.local
COPY . .
USER nobody
CMD ["python", "app.py"]
```

---

## Security Hardening Checklist

For any base image:

- [ ] Use specific tag (not `latest`)
- [ ] Run as non-root user
- [ ] Remove unnecessary packages
- [ ] Set read-only filesystem where possible
- [ ] Drop capabilities
- [ ] Use COPY instead of ADD
- [ ] Don't store secrets in image
- [ ] Scan before deployment

---

## Version Pinning

### Good Practices

```dockerfile
# Pin major.minor.patch
FROM node:20.10.0-alpine3.19

# Pin digest for reproducibility
FROM node:20.10.0-alpine3.19@sha256:abc123...
```

### Bad Practices

```dockerfile
# Never use latest
FROM node:latest

# Avoid floating tags
FROM node:20
FROM node:lts
```

---

## Update Strategy

1. **Weekly**: Check for new minor/patch versions
2. **Monthly**: Review security advisories
3. **Quarterly**: Evaluate major version upgrades
4. **Immediately**: Patch critical CVEs
