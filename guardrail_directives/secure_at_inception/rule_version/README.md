# Rule Version - Secure At Inception

This directory contains Cursor rule files that embed security scanning instructions directly into the AI agent's context. Rules provide inline, real-time security feedback during code generation.

## Overview

The rule version works by adding security requirements to the AI's system instructions. When the AI generates or modifies code, it "sees" these rules and follows them as guidance—scanning code and fixing vulnerabilities in real-time.

## Files

| File | Purpose | Scanning |
|------|---------|----------|
| `snyk_sai_all_engines_rule.mdc` | Full security coverage | SAST + SCA |
| `snyk_sai_sast_rule.mdc` | Code-only scanning | SAST only |

## How Rules Work

```
┌──────────────────────────────────────────────────────────────┐
│                    AI Agent Context                          │
│                                                              │
│  System Prompt:                                              │
│  "You are a helpful coding assistant..."                    │
│                                                              │
│  Rules (from .mdc file):                                    │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ # Project security best practices                      │ │
│  │ - Always run snyk_code_scan for new code               │ │
│  │ - If issues found, fix them                            │ │
│  │ - Rescan until clean                                   │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  User: "Create a file upload handler"                       │
└────────────────────────────┬─────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────┐
│                    AI Response Flow                          │
│                                                              │
│  1. Generate code for file upload                           │
│  2. [Sees rule] Run snyk_code_scan                          │
│  3. Find Path Traversal vulnerability                       │
│  4. [Follows rule] Fix the vulnerability                    │
│  5. [Follows rule] Re-scan to verify                        │
│  6. Return secure code to user                              │
└──────────────────────────────────────────────────────────────┘
```

## Rule Content

### All Engines (SAST + SCA)

```markdown
---
alwaysApply: true
always_on: true
trigger: always_on
applyTo: "**"
description: Snyk Security At Inception
---

# Project security best practices

- Always run snyk_code_scan tool for new first party code 
  that is generated in a Snyk-supported language.
- Always run snyk_sca_scan when a new package is introduced or modified.
- If any security issues are found based on newly introduced or 
  modified code or dependencies, attempt to fix the issues using 
  the results context from Snyk.
- Rescan the code after fixing the issues to ensure that the issues 
  were fixed and that there are no newly introduced issues.
- Repeat this process until no new issues are found.
```

### SAST Only

```markdown
---
alwaysApply: true
always_on: true
trigger: always_on
applyTo: "**"
description: Snyk Security At Inception
---

# Project security best practices

- Always run snyk_code_scan tool for new first party code 
  that is generated in a Snyk-supported language.
- If any security issues are found based on newly introduced or 
  modified code or dependencies, attempt to fix the issues using 
  the results context from Snyk.
- Rescan the code after fixing the issues to ensure that the issues 
  were fixed and that there are no newly introduced issues.
- Repeat this process until no new issues are found.
```

## Installation

### Step 1: Create Rules Directory

```bash
mkdir -p /path/to/project/.cursor/rules
```

### Step 2: Copy Rule File

Choose the appropriate rule:

```bash
# For full coverage (SAST + SCA)
cp snyk_sai_all_engines_rule.mdc /path/to/project/.cursor/rules/

# OR for code-only (SAST)
cp snyk_sai_sast_rule.mdc /path/to/project/.cursor/rules/
```

### Step 3: Verify

The rule will be automatically loaded when you open the project in Cursor.

## Use Cases

### Creating New Code
```
User: "Create a login function"

AI (with SAI rule active):
  1. Creates login function code
  2. [Rule] Runs snyk_code_scan
  3. Finds SQL injection vulnerability
  4. [Rule] Fixes with parameterized query
  5. [Rule] Re-scans → Clean
  6. Returns secure login function
```

### Adding Dependencies
```
User: "Add a JWT library"

AI (with All Engines rule):
  1. Adds jsonwebtoken to package.json
  2. Creates JWT helper code
  3. [Rule] Runs snyk_sca_scan → Clean
  4. [Rule] Runs snyk_code_scan
  5. Finds hardcoded secret
  6. [Rule] Fixes with env variable
  7. [Rule] Re-scans → Clean
  8. Returns secure implementation
```

### Iterative Fixing
```
User: "Build a file API"

AI creates initial code
  [Rule] Scans → 2 issues found
  
AI fixes issue #1 (path traversal)
  [Rule] Re-scans → 1 issue remains
  
AI fixes issue #2 (missing auth)
  [Rule] Re-scans → Clean
  
AI returns secure code
```

## Rule Frontmatter Options

```yaml
---
alwaysApply: true      # Apply to all conversations
always_on: true        # Always active (redundant with alwaysApply)
trigger: always_on     # Trigger condition
applyTo: "**"          # Apply to all files
description: "..."     # Rule description
---
```

## Choosing Between Rules

| Rule File | Best For | Scans |
|-----------|----------|-------|
| `snyk_sai_all_engines_rule.mdc` | Full projects with dependencies | Code + Dependencies |
| `snyk_sai_sast_rule.mdc` | Code-focused projects, no new deps | Code only |

## Advantages

1. **Real-time** - Feedback during generation, not after
2. **Inline fixing** - Issues fixed before code is presented
3. **Simple setup** - Just copy a file
4. **Transparent** - User sees the scanning happen

## Limitations

1. **Non-deterministic** - AI may occasionally skip scanning
2. **Token usage** - Scanning adds to conversation length
3. **AI interpretation** - Depends on AI following the rule

## Combining with Hooks

For maximum coverage, use rules AND hooks:

- **Rules**: Real-time scanning during generation
- **Hooks**: Safety net at session end

```
┌─────────────────────────────────────┐
│  During Session: Rule triggers      │
│  - Immediate feedback               │
│  - Fix before presenting            │
└─────────────────────────────────────┘
              +
┌─────────────────────────────────────┐
│  Session End: Hook triggers         │
│  - Catch anything missed            │
│  - Guaranteed final check           │
└─────────────────────────────────────┘
```

## See Also

- [Hooks Version](../hooks_version/) - Deterministic alternative
- [Secure At Inception Overview](../) - Comparison of approaches
- [Cursor Rules Documentation](https://docs.cursor.com/rules)

