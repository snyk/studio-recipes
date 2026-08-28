# Package Enforcement

This directory contains guardrails that enforce security scanning before package installation. They implement a "scan-before-install" security gate that prevents vulnerable dependencies from being added without review.

## Overview

When an AI agent adds new dependencies to a project, these guardrails ensure:

1. The package manifest change is detected and recorded
2. Install commands (npm, yarn, pnpm) are blocked until scanned
3. Only after running `snyk_sca_scan` are installs allowed
4. Session-end reminders if changes weren't scanned

## How It Works

```
┌────────────────────────────────────────────────────────────┐
│  AI Agent: "I'll add lodash to your project"              │
│  → Edits package.json                                      │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│  afterFileEdit Hook                                        │
│  Detects: package.json modified                           │
│  Action: Records pending scan requirement                  │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│  AI Agent: "Running npm install..."                       │
│  beforeShellExecution Hook: BLOCKED                       │
│  "Run snyk_sca_scan first"                                │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│  AI Agent: Calls snyk_package_health_check                │
│  afterMCPExecution Hook: Clears pending scan state ONLY   │
│  if the scan completed (authenticated, no error)          │
└─────────────────────────────┬──────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────┐
│  AI Agent: npm install succeeds (now allowed)             │
└────────────────────────────────────────────────────────────┘
```

## Supported Package Managers

| Package Manager | Install Commands Blocked |
|-----------------|-------------------------|
| **npm** | `npm install`, `npm i`, `npm ci` |
| **yarn** | `yarn install`, `yarn add`, `yarn` |
| **pnpm** | `pnpm install`, `pnpm add`, `pnpm i` |

## Monitored Files

| File | Purpose |
|------|---------|
| `package.json` | npm/yarn/pnpm manifest |
| `package-lock.json` | npm lockfile |
| `yarn.lock` | Yarn lockfile |
| `pnpm-lock.yaml` | pnpm lockfile |

## Variants

Two complementary gates on dependency installation:

- **Scan-before-install** (this directory) — installs are blocked until a Snyk scan of the manifest changes passes.
- **[Malicious Code Defense registry enforcement](./mcd_registry/)** — installs are blocked unless they are served through the tenant's Snyk Malicious Code Defense registry proxy, which screens packages for malicious code before serving them. *Experimental Preview: requires a feature flag enabled for your tenant by Snyk.*

## Implementation

- **[Cursor Hooks](./cursor/hooks/)** - Python hook script that enforces the scan-before-install gate
- **[MCD Registry Enforcement](./mcd_registry/)** - Python hook script (Claude Code and Cursor) that enforces installation through the Malicious Code Defense registry

## See Also

- [Cursor Hooks Implementation](cursor/hooks/) - The actual hook script
- [Secure At Inception](../secure_at_inception/) - Scan new code automatically
- [Guardrail Directives](../) - Overview of all guardrails
