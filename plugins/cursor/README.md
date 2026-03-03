# Snyk Secure Development Plugin for Cursor

A Cursor plugin that bundles Snyk security scanning, automated remediation, and dependency health checking into your development workflow.

## What's Included

| Component | Description |
|-----------|-------------|
| **Snyk MCP Server** | Snyk's MCP server (experimental profile) providing security scanning tools |
| **Secure at Inception Hooks** | Automatic background SAST scanning on file edits, blocking the agent if new vulnerabilities are introduced |
| **`/snyk-fix` Command** | Scan for vulnerabilities, fix them, validate, and optionally create a PR |
| **`/snyk-batch-fix` Command** | Batch fix vulnerabilities detected by the Secure at Inception hooks |
| **Secure Dependency Health Check Skill** | Evaluate open-source package security and health before adoption |

## How It Works

### Secure at Inception (Hooks)

The hooks provide a background security safety net during AI-assisted coding:

1. **`afterFileEdit`** -- When the agent edits a file, the hook tracks modified line ranges and launches a background Snyk CLI scan
2. **`stop`** -- When the agent finishes, the hook waits for scan results, filters vulnerabilities to only those on agent-modified lines, and blocks the agent with fix instructions if new issues are found

The hooks automatically invoke `/snyk-batch-fix` when vulnerabilities are detected, creating a fix loop that continues until the code is clean (up to 3 cycles).

### `/snyk-fix` Command

An on-demand remediation workflow: scan, fix, validate, and optionally create a PR. Supports targeting by scan type, vulnerability ID, CVE, package name, or file.

### `/snyk-batch-fix` Command

Fixes a batch of pre-scanned vulnerabilities provided by the Secure at Inception hooks. Parses the vulnerability table from the hook's output, groups by file and type, and fixes bottom-to-top to avoid line shifts.

### Secure Dependency Health Check (Skill)

Activated when the agent needs to import a new dependency or the user asks about package security. Uses `snyk_package_health_check` to evaluate vulnerability status, maintenance health, popularity, and community before recommending packages.

## Prerequisites

- **Python 3.8+** -- Required for the Secure at Inception hook scripts
- **Snyk CLI** -- Required for background scanning (`npm install -g snyk` or available via `npx`)
- **Snyk Authentication** -- Run `snyk auth` or set the `SNYK_TOKEN` environment variable
- **Node.js / npx** -- Required for the Snyk MCP server
- **GitHub CLI (`gh`)** -- Optional, needed only for the PR creation feature in `/snyk-fix`

## MCP Profile

This plugin configures the Snyk MCP server with the **experimental** profile. This is required for the `snyk_package_health_check` tool used by the Secure Dependency Health Check skill. The experimental profile includes all tools from the full profile plus tools under evaluation. See [Snyk MCP profiles](https://docs.snyk.io/integrations/snyk-studio-agentic-integrations/getting-started-with-snyk-studio#configure-the-snyk-mcp-profile) for details.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CURSOR_HOOK_DEBUG` | `0` | Set to `1` to enable debug logging for the hooks |
| `MAX_STOP_CYCLES` | `3` | Maximum fix-loop cycles before allowing the agent to stop |
| `SCAN_WAIT_TIMEOUT` | `90` | Seconds to wait for a background scan to complete |

## Source Recipes

This plugin packages components from the [Snyk Studio Recipes](https://github.com/snyk/studio-recipes) repository:

- Hooks: `guardrail_directives/secure_at_inception/hooks_version/cursor/async_cli_version/`
- Commands: `command_directives/synchronous_remediation/command/`
- Skill: `command_directives/synchronous_remediation/skills/secure-dependency-health-check/`
