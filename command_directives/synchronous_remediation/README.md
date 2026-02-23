# Synchronous Remediation

This directory contains command and skill definitions that enable real-time, interactive security vulnerability remediation. "Synchronous" means the AI agent performs the fix immediately during the conversation, with user oversight at each step.

## Overview

Synchronous remediation directives guide AI agents through a complete security fix lifecycle:

1. **Scan** - Run Snyk security scans (SAST and/or SCA)
2. **Analyze** - Identify and prioritize vulnerabilities
3. **Fix** - Apply code changes or dependency upgrades
4. **Validate** - Re-scan to confirm resolution
5. **PR** - Optionally create a pull request

## Implementations

### Skills 
Skills are a mechanism for extending agent capabilities. Each skill is a self-contained SKILL.md file with YAML frontmatter defining triggers, allowed tools, and detailed instructions.

| Skill | Purpose |
|-------|---------|
| **[snyk-fix](./skills/snyk-fix/)** | Complete security remediation workflow (SAST + SCA) |
| **[ai-inventory](./skills/ai-inventory/)** | AI component inventory and analysis |
| **[container-security](./skills/container-security/)** | Container and Dockerfile security scanning |
| **[drift-detector](./skills/drift-detector/)** | Infrastructure drift detection and remediation |
| **[iac-security](./skills/iac-security/)** | Infrastructure as Code security scanning |
| **[sbom-analyzer](./skills/sbom-analyzer/)** | Software Bill of Materials analysis |
| **[secure-at-inception](./skills/secure-at-inception/)** | Real-time code security scanning during generation |
| **[secure-dependency-advisor](./skills/secure-dependency-advisor/)** | Dependency security and license evaluation |

### Commands 

Commands are markdown instruction sets that guide the AI agent through structured workflows. Two approaches are available:

| Approach | Files | Best For |
|----------|-------|----------|
| **[Composite Commands](./command/composit_commands/)** | 4 separate commands | Teams wanting granular control over each remediation phase |
| **[All-in-One Command](./command/single_all_in_one_command/)** | 1 combined command | Simpler setup, single file |

## Key Features

- **Multi-instance fixing** - Fixes ALL instances of a vulnerability type in one pass
- **Validation loop** - Re-scans after fix to confirm resolution
- **Safe rollback** - Reverts changes if fix introduces new issues
- **Minimal changes** - Only modifies what's necessary for the fix
- **PR automation** - Creates well-formatted security PRs

## See Also

- [Skills](./skills/) - Skill definitions for AI coding assistants
- [Commands](./command/) - Markdown command definitions
- [Guardrail Directives](../../guardrail_directives/) - Proactive security enforcement
