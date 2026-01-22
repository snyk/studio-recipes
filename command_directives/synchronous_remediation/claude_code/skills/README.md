# Claude Code Skills Directory

This directory contains skill definitions that extend Claude Code's capabilities for security workflows. Each skill is a self-contained module that can be installed into any Claude Code project.

## Overview

Skills are Claude Code's mechanism for teaching the AI agent specialized workflows. A skill consists of:

1. **SKILL.md** - The skill definition with YAML frontmatter and markdown instructions
2. **README.md** - Installation and usage documentation

## Available Skills

| Skill | Purpose | Triggers |
|-------|---------|----------|
| **snyk-fix** | Security vulnerability remediation | "fix security", "fix CVE", "snyk fix" |

## How Skills Are Invoked

Skills are automatically invoked when Claude detects a matching user intent:

```
User: "Can you fix the security vulnerabilities in this project?"
                    │
                    ▼
        ┌───────────────────────┐
        │  Intent Recognition   │
        │                       │
        │  Matches: snyk-fix    │
        │  (description match)  │
        └───────────┬───────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │  Load Skill           │
        │                       │
        │  • allowed-tools      │
        │  • instructions       │
        └───────────┬───────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │  Execute Workflow     │
        │                       │
        │  Phase 1: Scan        │
        │  Phase 2: Fix         │
        │  Phase 3: Validate    │
        │  Phase 4: PR          │
        └───────────────────────┘
```

## Mock Example: Skill File Structure

```markdown
---
name: example-skill
description: |
  Brief description of what this skill does and when it should be triggered.
  Claude uses this to match user requests to skills.
allowed-tools:
  - ToolName1
  - ToolName2
  - Read
  - Write
---

# Skill Name

Instructions that Claude follows when this skill is activated.

## Phase 1: First Step
What to do first...

## Phase 2: Second Step
What to do next...
```

## Installation Patterns

### Per-Project Installation
Best for project-specific customizations:
```bash
cp -r skills/snyk-fix /path/to/project/.claude/skills/
```

### Global Installation
Best for personal workflows across all projects:
```bash
cp -r skills/snyk-fix ~/.claude/skills/
```

## Creating New Skills

To create a new skill for this repository:

1. Create a directory under `skills/` with the skill name
2. Add `SKILL.md` with the skill definition
3. Add `README.md` with installation/usage instructions
4. Follow the YAML frontmatter format:

```yaml
---
name: skill-name
description: |
  When to use this skill...
allowed-tools:
  - required_tool_1
  - required_tool_2
---
```

## Use Cases

### Security Remediation (snyk-fix)
```
User: "fix security issues"
User: "fix CVE-2021-44228"
User: "fix XSS vulnerabilities"
User: "upgrade vulnerable dependencies"
```

### Future Skills (Potential)
- **snyk-monitor** - Continuous security monitoring
- **snyk-report** - Generate security reports
- **snyk-ignore** - Manage vulnerability ignores

## See Also

- [snyk-fix Skill](snyk-fix/) - Complete security fix workflow
- [Claude Code Documentation](https://docs.anthropic.com/) - Official Claude Code docs

