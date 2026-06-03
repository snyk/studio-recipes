# Guardrail Directives

**Always-on security controls for AI coding assistants.** Guardrails govern agent behavior automatically — they prevent vulnerabilities from being introduced rather than catching them after the fact.

This is the **Secure at Inception** half of [Snyk Studio Recipes](https://snyk.io/product/studio/). For on-demand remediation of existing issues, see [Command Directives](../command_directives/).

[Snyk documentation: Guardrail directives →](https://docs.snyk.io/integrations/snyk-studio-agentic-integrations/directives#guardrail-directives)

---

## Available controls

### Secure at Inception (SAI)

Automatically scans new or modified code for vulnerabilities the moment the assistant generates it — so risky code is caught and fixed before it shapes the design or lands in a commit.

| Coding Assistant | Enforcement options |
|---|---|
| **[Cursor](./secure_at_inception/hooks_version/cursor/)** | Deterministic (hooks), with optional non-deterministic [rules](./secure_at_inception/rule_version/) for inline feedback |
| **[Claude Code](./secure_at_inception/hooks_version/claude/)** | Deterministic (hooks) |
| **[Kiro / any Git client](./secure_at_inception/kiro_hooks/)** | Deterministic (Git pre-commit + Kiro background scanning) |

### Secure at Commit (SAC) — Experimental

Blocks `git commit` when staged code or dependencies introduce new vulnerabilities — a deterministic gate at commit time that catches risky code from any source, not just the AI assistant.

| Coding Assistant | Enforcement |
|---|---|
| **[Any Git client](./secure_at_commit/)** | Deterministic (Git pre-commit hook) |

### Package Enforcement

Blocks dependency installation until security scans pass.

| Coding Assistant | Enforcement |
|---|---|
| **[Cursor](./package_enforcement/cursor/)** | Deterministic (hooks) |

---

## Choosing the enforcement model

Guardrails come in a few forms. Most teams layer rules with one deterministic hook model.

| Consideration | Rules | SAI Hooks | SAC Hooks *(experimental)* |
|---|---|---|---|
| **Enforcement** | Non-deterministic — the AI may skip them | Deterministic — always run as code is written | Deterministic — always run at `git commit` |
| **Setup** | Drop-in instructions the AI reads as guidance | Scripts wired to assistant lifecycle events | One pre-commit hook per repository |
| **Visibility** | Inline in the conversation | Separate output panel | In your terminal at commit time |
| **Best for** | Real-time inline feedback during generation | Catching issues as the assistant writes | A final gate on everything staged, from any source |

[SAI](./secure_at_inception/) and [SAC](./secure_at_commit/) hooks are mutually exclusive — pick the moment you want the deterministic gate to fire (as code is written, or at commit).

**Recommendation:** Use SAI hooks where available for deterministic enforcement during generation, and add rules on top so developers see issues inline. Prefer SAC hooks when you want a single commit-time gate that also covers manual edits.

---

## Deploy

The fastest path is the [installer](../installer/) — the `default` profile provisions Secure at Inception guardrails for every supported assistant in one command. The `minimal` profile installs guardrails plus MCP configuration only.

For custom deployments, or for assistants the installer does not yet cover, every directive is a plain file under [`secure_at_inception/`](./secure_at_inception/) and [`package_enforcement/`](./package_enforcement/) — copy or fork into your assistant's configuration directory.

---

## See also

- [Command Directives](../command_directives/) — on-demand security workflows
- [Snyk Studio](https://snyk.io/product/studio/)
