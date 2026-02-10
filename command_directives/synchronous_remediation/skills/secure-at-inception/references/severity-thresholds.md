# Severity Threshold Configuration

Guide for configuring when Secure At Inception should block vs warn vs allow.

## Severity Levels

| Level | Description | Typical Response |
|-------|-------------|------------------|
| **Critical** | Actively exploited, trivial to exploit, high impact | Always block |
| **High** | Exploitable with some effort, significant impact | Usually block |
| **Medium** | Requires specific conditions, moderate impact | Warn, consider blocking |
| **Low** | Difficult to exploit, minimal impact | Inform only |

---

## Preset Modes

### Strict Mode

Best for: High-security environments, regulated industries, production code

| Severity | Action |
|----------|--------|
| Critical | BLOCK |
| High | BLOCK |
| Medium | BLOCK |
| Low | BLOCK |

```
All issues must be fixed before proceeding.
```

### Standard Mode (Default)

Best for: Most development teams, balance of security and velocity

| Severity | Action |
|----------|--------|
| Critical | BLOCK |
| High | BLOCK |
| Medium | WARN |
| Low | ALLOW |

```
Critical and High issues block. Medium issues are warned but allowed.
```

### Relaxed Mode

Best for: Early development, prototyping, non-production environments

| Severity | Action |
|----------|--------|
| Critical | BLOCK |
| High | WARN |
| Medium | ALLOW |
| Low | ALLOW |

```
Only Critical issues block. High issues are warned.
```

### Audit Mode

Best for: Initial adoption, understanding baseline security posture

| Severity | Action |
|----------|--------|
| Critical | WARN |
| High | WARN |
| Medium | WARN |
| Low | ALLOW |

```
Nothing blocks. All issues are reported for awareness.
```

---

## Per-Scan-Type Thresholds

Different thresholds can apply to different scan types:

### Code (SAST) Thresholds

Code vulnerabilities are often more immediately exploitable.
Note: Snyk Code supports High, Medium, and Low severity only (no Critical).

- **Recommended**: Standard or Strict mode
- **High issues**: SQL Injection, Command Injection, Hardcoded Secrets, XSS, Path Traversal, Insecure Deserialization

### Dependency (SCA) Thresholds

Dependency vulnerabilities may require specific conditions:
- **Recommended**: Standard mode
- **Consider**: Reachability analysis to prioritize
- **Critical issues**: Actively exploited vulnerabilities with public PoC
- **High issues**: RCE vulnerabilities, even without known exploits

### Infrastructure (IaC) Thresholds

IaC issues are misconfigurations, not always immediately exploitable:
- **Recommended**: Relaxed or Standard mode for development
- **Production IaC**: Standard or Strict mode
- **Critical issues**: Public S3 buckets, open security groups to 0.0.0.0/0
- **High issues**: Missing encryption, excessive permissions

---
