# Malicious Code Defense Registry Enforcement

Blocks package-install commands run by an AI coding assistant unless the
effective registry is the Snyk Malicious Code Defense registry proxy, which
screens npm and PyPI packages for malicious code before serving them.

> **Feature availability**
>
> Snyk Malicious Code Defense is in **Experimental Preview**. It requires a
> feature flag enabled for your tenant by Snyk — contact your Snyk account
> team to request access. Without access, the tenant registry URL this hook
> enforces is not available, and gated installs will be blocked.

## Overview

The other guardrails in this directory gate installs on a *scan*. This one
gates installs on the *source*: the package must be served through your
tenant's Malicious Code Defense registry, so screening happens before the
package ever reaches the machine.

```
AI Agent: "Running npm install..."
        │
        ▼
beforeShellExecution / PreToolUse hook
  Resolve the effective registry for the command's working directory
        │
   ┌────┴─────────────────────────────┐
   │ Matches the tenant MCD registry  │ Anything else
   ▼                                  ▼
ALLOW                            BLOCK, with a remediation
                                 message the agent can act on
```

The hook is stateless — a configuration check at intercept time, with no
scan step and no state files. It fails closed: if the effective registry
cannot be determined for an install command, the command is blocked.

## Agent-actionable remediation

The denial message tells the agent what it can fix itself, and when to stop
and hand off to the developer:

| Situation | Message to the agent |
|---|---|
| Command carries a `--registry` / `--index-url` override but the project configuration is compliant | Remove the override flag and retry |
| A project-level `.npmrc` overrides a compliant user-level configuration | Fix the registry line in the named project file; credentials are host-scoped in the user configuration and need no changes |
| An environment variable (`PIP_INDEX_URL`) overrides a compliant pip configuration | Unset the variable and retry |
| No Malicious Code Defense configuration exists on the machine | Stop; ask the developer to complete Snyk authentication and registry setup. The agent is told explicitly not to configure the registry itself, because setup requires a tenant-specific URL and an auth token it cannot obtain |

## Supported assistants

One script serves both assistants, detecting the payload format automatically.

| Coding Assistant | Hook event | Install |
|---|---|---|
| **Claude Code** | `PreToolUse` (matcher: `Bash`) | Copy [`hooks/enforce_mcd_registry.py`](./hooks/enforce_mcd_registry.py) to `.claude/hooks/` and merge [`claude/settings.json`](./claude/settings.json) into `.claude/settings.json` |
| **Cursor** | `beforeShellExecution` | Copy the script to `.cursor/hooks/` and merge [`cursor/hooks.json`](./cursor/hooks.json) into `.cursor/hooks.json`. Cursor resolves the hook command relative to the workspace root, hence the `.cursor/hooks/...` path |

## Supported package managers

| Ecosystem | Commands gated | Registry resolution |
|---|---|---|
| npm | `npm/pnpm/bun install`, `i`, `ci`, `add`; `yarn install`, `add` | `--registry` flag, then `npm config list` in the command's working directory (honors project and user `.npmrc`) |
| PyPI | `pip install`, `python -m pip install`, `uv pip install`, `uv add`, `uv sync` | `--index-url`/`-i` flag, then `PIP_INDEX_URL` / `UV_DEFAULT_INDEX` / `UV_INDEX_URL`, then `pip config get global.index-url` |

## Configuration

All optional, via environment variables:

| Variable | Purpose |
|---|---|
| `MCD_REGISTRY_PATTERN` | Regular expression the registry URL must match. Defaults to the tenant registry path shape (`/tenants/<tenant-id>/registry/npm` or `.../pypi`), tolerating npm 11's redaction of UUID path segments in `npm config list` output |
| `MCD_REGISTRY_URL` | The exact expected registry URL for this machine. When set (for example by a managed deployment), it is included in remediation messages so the handoff to the developer is precise |
| `MCD_HOOK_DEBUG` | Set to `1` for verbose logging on stderr |

## Limitations

- Scoped npm registries (`@scope:registry=`) are not checked. Private scopes
  routed to an internal registry are expected to bypass the proxy.
- Lockfile `resolved` URLs are not inspected. A lockfile generated against a
  different registry can still fetch from that registry.
- yarn berry (`.yarnrc.yml`), `bunfig.toml`, and Poetry source configuration
  are not resolved; these package managers are gated using the npm and pip
  configuration respectively.
- Commands that change directory before installing (`cd app && npm install`)
  are resolved against the original working directory.

## Verify

A self-check suite exercises every allow and deny branch using temporary
projects and a controlled `$HOME`:

```
python3 tests/test_enforce_mcd_registry.py
```

## See Also

- [Package Enforcement](../) - scan-before-install gates
- [Guardrail Directives](../../) - overview of all guardrails
