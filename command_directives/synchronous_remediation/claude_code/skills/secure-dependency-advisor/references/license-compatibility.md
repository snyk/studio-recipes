# License Compatibility Guide

Quick reference for understanding open-source license compatibility.

## License Overview

### Permissive Licenses

Minimal restrictions on use, modification, and distribution.

| License | Key Terms | Commercial Use | Modification | Distribution |
|---------|-----------|----------------|--------------|--------------|
| **MIT** | Very permissive | Yes | Yes | Yes |
| **BSD-2-Clause** | Permissive | Yes | Yes | Yes |
| **BSD-3-Clause** | Permissive + no endorsement | Yes | Yes | Yes |
| **Apache 2.0** | Permissive + patent grant | Yes | Yes | Yes |
| **ISC** | Simplified MIT | Yes | Yes | Yes |
| **Unlicense** | Public domain dedication | Yes | Yes | Yes |
| **CC0** | Public domain | Yes | Yes | Yes |

### Copyleft Licenses

Require derivative works to use the same license.

| License | Strength | Key Terms |
|---------|----------|-----------|
| **GPL-2.0** | Strong | Derivatives must be GPL |
| **GPL-3.0** | Strong | Derivatives must be GPL + anti-tivoization |
| **AGPL-3.0** | Very Strong | Network use triggers copyleft |
| **LGPL-2.1** | Weak | Library use OK, derivatives must be LGPL |
| **LGPL-3.0** | Weak | Library use OK, derivatives must be LGPL |
| **MPL-2.0** | Weak | File-level copyleft only |

### Other Common Licenses

| License | Notes |
|---------|-------|
| **CC-BY-4.0** | Attribution required, typically for content |
| **WTFPL** | Essentially public domain |
| **Artistic-2.0** | Perl ecosystem |
| **EPL-2.0** | Eclipse ecosystem |
| **CDDL** | Oracle/Sun ecosystem |

---

## Compatibility Matrix

### Can I use this dependency in my project?

| Dependency License | MIT Project | Apache Project | GPL Project | Proprietary Project |
|-------------------|-------------|----------------|-------------|---------------------|
| MIT | Yes | Yes | Yes | Yes |
| BSD | Yes | Yes | Yes | Yes |
| Apache 2.0 | Yes | Yes | Yes | Yes |
| ISC | Yes | Yes | Yes | Yes |
| LGPL (linking) | Yes | Yes | Yes | Yes |
| LGPL (modifying) | LGPL | LGPL | Yes | LGPL |
| MPL | Yes* | Yes* | Yes | Yes* |
| GPL | No** | No** | Yes | No |
| AGPL | No** | No** | Yes*** | No |

**\*** MPL requires modified files to remain MPL  
**\*\*** Depends on interpretation - some argue dependencies don't infect  
**\*\*\*** AGPL has stronger requirements than GPL

---

## Decision Flowchart

```
Is your project open source?
├── Yes
│   ├── Is it GPL/AGPL licensed?
│   │   ├── Yes → Can use any open source license
│   │   └── No → Avoid GPL/AGPL dependencies (or relicense)
│   └── Is it permissively licensed?
│       └── Prefer permissive dependencies, be careful with copyleft
└── No (Proprietary)
    └── Can only use permissive licenses safely
        └── MIT, BSD, Apache, ISC = Safe
        └── GPL, AGPL = Avoid
        └── LGPL = Usually OK (linking only)
```

---

## Common Issues

### Issue 1: GPL Dependency in MIT Project

**Problem**: Your MIT project has a GPL dependency
**Risk**: May need to relicense entire project as GPL
**Solutions**:
1. Find alternative with permissive license
2. Relicense project as GPL
3. Isolate GPL code in separate process (controversial)

### Issue 2: AGPL in SaaS Application

**Problem**: Using AGPL library in a web service
**Risk**: May need to release entire application source
**Solutions**:
1. Find alternative library
2. Release source code under AGPL
3. Contact author for commercial license

### Issue 3: License Not Specified

**Problem**: Package has no license file
**Risk**: No rights to use (default copyright)
**Solutions**:
1. Contact maintainer to add license
2. Find alternative package
3. Do not use until licensed

### Issue 4: Multiple Licenses

**Problem**: Package offers multiple licenses (e.g., "MIT OR Apache-2.0")
**Solution**: Choose the one most compatible with your project

---

## License Detection

### Common File Names

- LICENSE
- LICENSE.md
- LICENSE.txt
- COPYING
- COPYING.txt

### Package.json Example

```json
{
  "license": "MIT",
  // or
  "license": "(MIT OR Apache-2.0)",
  // or
  "licenses": [
    { "type": "MIT", "url": "..." },
    { "type": "Apache-2.0", "url": "..." }
  ]
}
```

### SPDX Identifiers

Standard identifiers for licenses:
- `MIT`
- `Apache-2.0`
- `GPL-3.0-only`
- `GPL-3.0-or-later`
- `LGPL-2.1-only`
- `BSD-3-Clause`

---

## Recommendations by Project Type

### Open Source Library (MIT)

**Safe**: MIT, BSD, Apache, ISC  
**Caution**: LGPL (document linking)  
**Avoid**: GPL, AGPL

### Open Source Application (GPL)

**Safe**: All open source licenses  
**Caution**: None (GPL is highly permissive for derivatives)  
**Avoid**: Proprietary components

### Commercial SaaS

**Safe**: MIT, BSD, Apache, ISC  
**Caution**: LGPL (ensure dynamic linking)  
**Avoid**: GPL, AGPL

### Commercial Desktop/Mobile

**Safe**: MIT, BSD, Apache, ISC  
**Caution**: LGPL (may require dynamic linking)  
**Avoid**: GPL, AGPL

### Internal Enterprise

**Safe**: Most open source (no distribution)  
**Caution**: AGPL (network use may trigger)  
**Note**: License typically only applies to distribution

---

## Getting Help

### When in Doubt

1. Consult legal counsel for commercial projects
2. Check SPDX license list for details
3. Contact package maintainer for clarification
4. Default to more permissive alternatives

### Resources

- SPDX License List: https://spdx.org/licenses/
- Choose A License: https://choosealicense.com/
- TLDR Legal: https://tldrlegal.com/
- OSI Approved: https://opensource.org/licenses/
