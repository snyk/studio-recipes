# Package Evaluation Criteria

Detailed criteria for evaluating open-source package security and health.

## Security Criteria

### Vulnerability Scoring

| Factor | Points Deducted | Notes |
|--------|-----------------|-------|
| Critical CVE | -25 | Per vulnerability |
| High CVE | -10 | Per vulnerability |
| Medium CVE | -3 | Per vulnerability |
| Low CVE | -1 | Per vulnerability |
| Known Exploit | -100 | Automatic disqualification |
| No Fix Available | -5 | Additional for unfixable vulns |

**Formula**: `Score = 100 - (sum of deductions)`

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

## License Criteria

### License Compatibility Matrix

| Your Project | Compatible Deps | Incompatible Deps |
|--------------|-----------------|-------------------|
| MIT | MIT, BSD, Apache, ISC | GPL (maybe) |
| Apache 2.0 | MIT, BSD, Apache | GPL |
| GPL | MIT, BSD, Apache, GPL | Proprietary |
| Proprietary | MIT, BSD, Apache, ISC | GPL, AGPL |

### License Risk Levels

| License | Risk | Notes |
|---------|------|-------|
| MIT, ISC, BSD | Low | Very permissive |
| Apache 2.0 | Low | Permissive with patent grant |
| LGPL | Medium | OK if dynamically linked |
| MPL | Medium | File-level copyleft |
| GPL | High | Requires source disclosure |
| AGPL | High | Network use triggers copyleft |
| Unlicensed | Very High | No rights granted |
| Custom | Variable | Requires legal review |

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

## Scoring Weights

### Default Weights

| Criteria Category | Weight |
|-------------------|--------|
| Security | 40% |
| Maintenance | 25% |
| Community | 15% |
| License | 10% |
| Performance | 10% |

### Security-First Weights

For security-critical projects:

| Criteria Category | Weight |
|-------------------|--------|
| Security | 60% |
| Maintenance | 20% |
| Community | 10% |
| License | 5% |
| Performance | 5% |

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
- [ ] License incompatible with project
