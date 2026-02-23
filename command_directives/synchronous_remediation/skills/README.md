# Skills

This directory contains skill definitions that extend AI coding assistant capabilities for security workflows. Each skill is a self-contained module that can be installed into any compatible project.

## Overview

Skills are a mechanism for teaching AI agents specialized workflows. A skill consists of:

1. **SKILL.md** - The skill definition with YAML frontmatter and markdown instructions
2. **README.md** (optional) - Installation and usage documentation
3. **references/** (optional) - Supporting reference material used by the skill

## Available Skills

| Skill | Purpose | Triggers |
|-------|---------|----------|
| **[snyk-fix](./snyk-fix/)** | Security vulnerability remediation | "fix security", "fix CVE", "snyk fix" |
| **[ai-inventory](./ai-inventory/)** | AI component inventory and analysis | AI asset discovery requests |
| **[container-security](./container-security/)** | Container/Dockerfile security scanning | Container security requests |
| **[drift-detector](./drift-detector/)** | Infrastructure drift detection | Drift detection requests |
| **[iac-security](./iac-security/)** | Infrastructure as Code security | IaC scanning requests |
| **[sbom-analyzer](./sbom-analyzer/)** | Software Bill of Materials analysis | SBOM generation requests |
| **[secure-at-inception](./secure-at-inception/)** | Real-time code security scanning | Code generation with security |
| **[secure-dependency-advisor](./secure-dependency-advisor/)** | Dependency security evaluation | Package evaluation requests |

## How Skills Are Invoked

Skills are automatically invoked when the AI agent detects a matching user intent based on the skill's `description` field:

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
        └───────────────────────┘
```

## Skill File Structure

```yaml
---
name: skill-name
description: |
  Brief description of what this skill does and when it should be triggered.
  The agent uses this to match user requests to skills.
allowed-tools:
  - ToolName1
  - ToolName2
  - Read
  - Write
---

# Skill Name

Instructions the agent follows when this skill is activated.

## Phase 1: First Step
What to do first...

## Phase 2: Second Step
What to do next...
```

## Installation

### Per-Project Installation (Recommended)
```bash
cp -r skills/<skill-name> /path/to/project/.claude/skills/
```

### Global Installation
```bash
cp -r skills/<skill-name> ~/.claude/skills/
```

## Prerequisites

- **Snyk MCP Server** - Configured in your coding assistant's MCP settings
- **Snyk Authentication** - Either `snyk auth` or `SNYK_TOKEN` environment variable
- **GitHub CLI** (optional) - For PR creation feature

## See Also

- [Commands](../command/) - Alternative command-based approach for Cursor and other assistants
