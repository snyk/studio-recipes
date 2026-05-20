# Command Directives

**On-demand security workflows for AI coding assistants.** Command directives codify multi-step Snyk security playbooks — scan, fix, validate, PR — so developers and agents can trigger them with a single command.

This is the on-demand half of [Snyk Studio Recipes](https://snyk.io/product/studio/). For continuous, always-on enforcement, see [Guardrail Directives](../guardrail_directives/).

[Snyk documentation: Command directives →](https://docs.snyk.io/integrations/snyk-studio-agentic-integrations/directives#command-directives)

---

## Available commands and skills

### [Synchronous Remediation](./synchronous_remediation/)

End-to-end vulnerability scanning, fixing, validation, and pull request creation. Available capabilities:

| Capability | Purpose |
|---|---|
| **`/snyk-fix`** | Complete security remediation flow (SAST + SCA) — scan, fix, validate, PR |
| **`/snyk-batch-fix`** | Fix all instances of a vulnerability type in a single pass |
| **Secure dependency health check** | Evaluate package security and licensing posture before adoption |
| **AI inventory** | Discover and inventory AI components in the codebase |
| **Container security** | Scan containers and Dockerfiles for vulnerabilities |
| **IaC security** | Scan Infrastructure as Code for misconfigurations |
| **SBOM analyzer** | Generate and analyze Software Bills of Materials |
| **Drift detector** | Detect and remediate infrastructure drift |

The installer's `default` profile bundles `/snyk-fix`, `/snyk-batch-fix`, and the secure dependency health check. The remaining capabilities are available for manual deployment or custom profiles.

---

## How developers invoke these

Different assistants expose commands differently — slash commands in Cursor, Claude Code, Gemini, and Copilot in VS Code; workflows in Windsurf; steering files in Kiro; skills in Copilot CLI. The installer handles the per-assistant translation automatically, so the same `/snyk-fix` invocation works across the assistants that support slash commands.

Consult your assistant's documentation for invocation specifics:

- [Cursor](https://cursor.com/docs/context/commands)
- [Claude Code](https://code.claude.com/docs/en/skills#extend-claude-with-skills)
- [GitHub Copilot](https://docs.github.com/en/copilot/how-tos/chat-with-copilot/chat-in-ide#slash-commands)
- [Gemini CLI](https://geminicli.com/docs/cli/commands/)
- [Windsurf](https://docs.windsurf.com/windsurf/cascade/workflows)

---

## Deploy

The fastest path is the [installer](../installer/) — the `default` profile installs the most commonly used commands across every supported assistant.

For custom deployments, every command and skill is a plain file under [`synchronous_remediation/`](./synchronous_remediation/) — copy or fork into your assistant's configuration directory.

---

## See also

- [Guardrail Directives](../guardrail_directives/) — automatic, always-on enforcement
- [Snyk Studio](https://snyk.io/product/studio/)
