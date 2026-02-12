# Package Evaluation Criteria

Detailed criteria for evaluating open-source package security and health.

## Security Criteria

### Overall Rating

Use the `overall_rating` returned by `snyk_package_health_check` as the primary evaluation metric. The tool returns "Healthy" or "Review recommended" based on an internal assessment of vulnerability severity, maintenance signals, and community health. Do not compute a manual score. Additionally review the per-category ratings: `security.rating`, `maintenance.rating`, `community.rating`, and `popularity.rating`.

### Dependency Tree Risk

| Factor | Risk Level | Notes |
|--------|------------|-------|
| < 10 direct deps | Low | Minimal attack surface |
| 10-30 direct deps | Medium | Standard for complex packages |
| > 30 direct deps | High | Large attack surface |
| > 100 transitive deps | High | Hard to track all vulns |

### Historical Security

Consider the package's security track record:
- **Frequent CVEs**: May indicate code quality issues
- **Slow response**: Long time-to-fix indicates poor security practices
- **No CVEs ever**: Could be good, or could mean no one is looking

---

## Maintenance Health Criteria

### Update Frequency

| Last Update | Status | Recommendation |
|-------------|--------|----------------|
| < 1 month | Active | Good choice |
| 1-6 months | Maintained | Usually safe |
| 6-12 months | Slow | Investigate further |
| 1-2 years | Stale | Caution advised |
| > 2 years | Abandoned | Avoid |

### Release Patterns

| Pattern | Interpretation |
|---------|----------------|
| Regular (weekly/monthly) | Actively maintained |
| Sporadic | May be under-resourced |
| None in year | Possibly abandoned |
| Only patches | Maintenance mode (may be OK) |

### Maintainer Health

| Factor | Good Sign | Warning Sign |
|--------|-----------|--------------|
| Maintainer count | 2+ active | Single person |
| Organization backing | Yes | No |
| Responsiveness | < 1 week for issues | Months to respond |
| PR merge rate | Regular merges | Backlog growing |

---

## Community Health Criteria

### Popularity Metrics

| Metric | Threshold | Notes |
|--------|-----------|-------|
| Weekly downloads | > 10K | Generally well-tested |
| GitHub stars | > 1K | Community interest |
| Dependent packages | > 100 | Widely trusted |
| Contributors | > 5 | Diverse input |

### Community Engagement

| Factor | Positive Indicator |
|--------|-------------------|
| Issues triaged | Labels, assignments, milestones |
| Documentation | README, docs folder, examples |
| Changelog | CHANGELOG.md with clear updates |
| Security policy | SECURITY.md with disclosure process |

---

## Supply Chain Criteria

### Package Authenticity

- **Verified publisher**: Official org account
- **Consistent naming**: Matches project name
- **No typosquatting**: Not similar to popular package
- **Source available**: GitHub/GitLab linked

### Build Integrity

- **Reproducible builds**: Can verify published matches source
- **Signed releases**: GPG or other signing
- **CI/CD visible**: Build process is transparent

---

## Size and Performance Criteria

### Bundle Size (for frontend packages)

| Size | Rating | Notes |
|------|--------|-------|
| < 10KB | Excellent | Minimal impact |
| 10-50KB | Good | Acceptable |
| 50-100KB | Fair | Consider tree-shaking |
| > 100KB | Poor | Look for alternatives |

### Dependency Weight

| Factor | Consideration |
|--------|--------------|
| Tree-shakeable | Can import only what's needed |
| Peer dependencies | May conflict with existing |
| Native modules | May have build requirements |
| Side effects | May affect bundle optimization |

---

## Decision Framework

### When to Recommend

| Overall Rating | Security Rating | Maintenance Rating | Recommendation |
|----------------|-----------------|---------------------|----------------|
| Healthy | No known security issues | Healthy | **Strongly Recommend** |
| Healthy | Security issues found (low/medium only) | Healthy/Sustainable | **Recommend** with notes |
| Review recommended | Security issues found | Sustainable | **Caution** - document risks |
| Any | Critical/High vulns present | Any | **Do Not Recommend** |
| Any | Any | Inactive | **Do Not Recommend** |

### Tie-Breakers

When overall ratings are the same, prefer:
1. Fewer total dependencies (smaller attack surface)
2. More recent updates (active maintenance)
3. Larger community (more security review)

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

## Red Flags Checklist

Immediately disqualify if:

- [ ] Known actively exploited vulnerability
- [ ] No updates in 3+ years
- [ ] Single maintainer who is unresponsive
- [ ] No license specified
- [ ] Typosquatting name pattern
- [ ] Malware detected
- [ ] Deprecated by maintainer
