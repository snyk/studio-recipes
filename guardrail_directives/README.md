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

### Package Enforcement

Blocks dependency installation until security scans pass.

| Coding Assistant | Enforcement |
|---|---|
| **[Cursor](./package_enforcement/cursor/)** | Deterministic (hooks) |

---

## Choosing the enforcement model

Guardrails come in two forms. Most teams benefit from layering both.

| Consideration | Rules | Hooks |
|---|---|---|
| **Enforcement** | Non-deterministic — the AI may skip them | Deterministic — always run on the configured event |
| **Setup** | Drop-in instructions the AI reads as guidance | Scripts wired to lifecycle events |
| **Visibility** | Inline in the conversation | Separate output panel |
| **Best for** | Real-time inline feedback during generation | Hard guarantees ("this scan must run before commit") |

**Recommendation:** Use hooks where available for deterministic enforcement. Add rules on top so developers see issues inline as the assistant writes code.

---

## Deploy

The fastest path is the [installer](../installer/) — the `default` profile provisions Secure at Inception guardrails for every supported assistant in one command. The `minimal` profile installs guardrails plus MCP configuration only.

For custom deployments, or for assistants the installer does not yet cover, every directive is a plain file under [`secure_at_inception/`](./secure_at_inception/) and [`package_enforcement/`](./package_enforcement/) — copy or fork into your assistant's configuration directory.

---

## See also

- [Command Directives](../command_directives/) — on-demand security workflows
- [Snyk Studio](https://snyk.io/product/studio/)
