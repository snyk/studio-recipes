# Secure Dependency Health Check - Cursor / Claude Code Skill

A skill that evaluates and compares open-source packages using [`snyk_package_health_check`](https://docs.snyk.io/snyk-studio) to help AI agents make informed dependency decisions.

## Overview

The `snyk_package_health_check` directive evaluates open-source packages for security vulnerabilities, maintenance health, community engagement, and popularity. This reduces supply chain risk in agentic development workflows where AI agents autonomously select and install dependencies.

`snyk_package_health_check` is available for npm, pypi, nuget, maven, and golang.

When a developer requests a recommendation or an agent imports a dependency, the skill runs `snyk_package_health_check` on each candidate. The tool returns a structured comparison including:

- Overall health rating
- Vulnerability counts by severity
- Maintenance and community ratings
- Popularity metrics

The agent uses these signals to recommend packages with clear reasoning or flag packages to avoid because of security issues or inactive maintenance.

## Prerequisites

- **Snyk MCP Server**: Configured in your coding assistant's MCP settings
- **Snyk Authentication**: Run `snyk auth` or have `SNYK_TOKEN` environment variable set

## Usage

This skill is **automatically invoked** when the agent detects relevant requests. Examples:

| What You Say | What Happens |
|--------------|--------------|
| "which package should I use for X?" | Researches candidates, runs health checks, compares results |
| "is lodash safe?" | Runs health check on the package and reports findings |
| "compare axios vs node-fetch" | Evaluates both packages and presents a comparison table |
| "find a secure alternative to X" | Identifies alternatives, health-checks each, recommends the best |
| "check dependency health" | Evaluates existing project dependencies |

## Workflow

1. **Understand** - Parses the user request to identify the functional requirement and candidate packages
2. **Analyze** - Runs `snyk_package_health_check` on each candidate, collecting security, maintenance, community, and popularity data
3. **Compare** - Builds a structured comparison table with overall ratings and per-category breakdowns
4. **Recommend** - Selects the healthiest option with clear reasoning, or flags all candidates if none meet the security threshold
5. **Integrate** - Provides version pinning and post-installation guidance

## Files

| File | Purpose |
|------|---------|
| `SKILL.md` | Skill definition with evaluation workflow |
| `references/package-evaluation-criteria.md` | Detailed scoring criteria and decision framework |

## Configuration

The skill uses this Snyk MCP tool:
- `mcp_snyk_snyk_package_health_check` - Package health evaluation

## See Also

- [Skills Overview](../)
- [Package Enforcement Hook](../../../../guardrail_directives/package_enforcement/cursor/hooks/) - Enforce health checks as a security gate on package installations
