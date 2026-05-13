# Snyk Studio Recipes

**Innovate with AI. Securely.**

Drop-in security recipes that embed [Snyk](https://snyk.io/platform/) directly into the AI coding assistants your developers already use — so AI-generated code is **secure at inception**, not patched after the fact.

---

## Is this for me?

**Yes**, if any of these apply:

- Your developers use **Cursor, Claude Code, GitHub Copilot, Gemini, Windsurf, or Kiro** — and you want every line of AI-assisted code scanned, fixed, and governed automatically.
- You're already a Snyk customer and want a fast, concrete way to **apply Secure at Inception** to agentic development without writing custom integrations.
- You're evaluating how to keep AI velocity from outrunning your security posture.

If you're new to AI-assisted ("agentic") development or haven't heard the term *Secure at Inception*, the [What is Secure at Inception?](#what-is-secure-at-inception) section below is the 60-second primer.

---

## What you get

A curated catalog of **recipes** — security building blocks that snap into your AI coding assistant:

| Recipe type | What it does | When it fires |
|---|---|---|
| **Secure at Inception guardrails** | Auto-scan AI-generated code for vulnerabilities the moment it's written. | Continuously, as the assistant writes code. |
| **Package enforcement guardrails** | Block risky or vulnerable dependencies before they're installed. | At dependency-add time. |
| **Remediation commands & skills** | Find, fix, validate, and PR security issues in one guided flow (`/snyk-fix`, `/snyk-batch-fix`, secure dependency health checks, and more). | On demand from the developer or the agent. |
| **Snyk MCP integration** | Wires Snyk's CLI and scanners into the assistant via the [Snyk MCP server](https://docs.snyk.io/integrations/snyk-studio-agentic-integrations/getting-started-with-snyk-studio). | Automatically, once installed. |

All of it ships as one self-extracting installer. One command, every supported assistant configured.

---

## What is Secure at Inception?

AI coding assistants generate code at machine speed. Traditional security tooling — scanning at PR time, in CI, or at deploy — runs *after* the code is written and reviewed, which means risky code has already shaped the design, the tests, and the developer's mental model by the time anyone sees a finding.

**Secure at Inception** flips that: security checks run **at the moment of generation**, inside the assistant's loop, so vulnerabilities are caught and fixed before they ever land in a commit. It's Snyk's approach to keeping AI-driven development [fast *and* safe](https://snyk.io/product/studio/) — preventing new AI-generated risk while remediating existing security debt at the same speed your team is now writing code.

These recipes are the implementation. Snyk Studio is the platform.

---

## Quick start

**1. Prerequisites**

- A supported AI coding assistant (Cursor, Claude Code, GitHub Copilot CLI or VS Code, Gemini, Windsurf, or Kiro)
- A Snyk account — once installed, run `snyk auth` or set `SNYK_TOKEN` so the recipes can scan

The installer takes care of the rest: it bootstraps `uv` (Python), Node.js, npm, and the Snyk CLI for you, prompting before each step.

**2. Install**

Download and run the latest pre-built installer from [`snyk/studio-recipes`](https://github.com/snyk/studio-recipes):

**macOS / Linux**

```bash
curl -fsSL 'https://raw.githubusercontent.com/snyk/studio-recipes/main/installer/dist/snyk-studio-install.sh' -o snyk-studio-install.sh
bash ./snyk-studio-install.sh
```

**Windows**

```bat
powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/snyk/studio-recipes/main/installer/dist/snyk-studio-install.ps1' -OutFile snyk-studio-install.ps1"
powershell -ExecutionPolicy Bypass -File .\snyk-studio-install.ps1
```

The installer auto-detects your assistants and merges in the recipes. Use `--dry-run` to preview, `--ade <name>` to target a single tool, or `--uninstall` to remove cleanly. Full options in [`installer/README.md`](installer/README.md).

**3. Authenticate**

Authenticate the Snyk CLI so the installed recipes can scan:

```bash
snyk auth
```

Or set the `SNYK_TOKEN` environment variable from your [Snyk account](https://app.snyk.io/account) for non-interactive environments (CI, containers, shared workstations).

**4. Try it**

Open your assistant and ask it to write code that touches a database, a network call, or a new dependency. You should see Snyk run automatically. Then try `/snyk-fix` on an existing project to see remediation in action.

---

## Choose your path

**I'm a developer or tech lead** — start with the [installer](installer/) and the `default` profile. It gives you Secure at Inception guardrails plus on-demand fix commands across all detected assistants.

**I'm a security professional or platform owner** — review the recipe catalog under [`guardrail_directives/`](guardrail_directives/) and [`command_directives/`](command_directives/) to understand which controls deploy, then standardize the `default` (or a custom) profile across your org via your usual provisioning channel.

**I'm a technical decision maker evaluating Snyk** — read the [What is Secure at Inception?](#what-is-secure-at-inception) section, then read about [Snyk Studio](https://snyk.io/product/studio/) and the [Snyk Platform](https://snyk.io/platform/). These recipes are the developer-facing surface of that platform.

**I want fine-grained control** — every recipe is a plain file under [`guardrail_directives/`](guardrail_directives/), [`command_directives/`](command_directives/), and [`mcp/`](mcp/). Copy, fork, customize, and combine — they're designed to be layered.

---

## Supported AI development environments

Cursor • Claude Code • GitHub Copilot (CLI and VS Code) • Gemini • Windsurf • Kiro

Coverage varies slightly by tool (e.g. Copilot CLI has no custom slash commands yet, so it gets skills + MCP only). The [installer README](installer/README.md) has the exact matrix.

---

## Customize and extend

These are starting points, not rigid templates. Common customizations:

- Adjust scan thresholds and severity gates
- Add or remove workflow phases in remediation skills
- Compose multiple recipes into a workflow tuned to your team
- Adapt patterns to assistants not yet covered out of the box

Snyk Studio is built on an open, partner-first, tool-agnostic foundation — these recipes follow the same philosophy.

---

## Learn more

- [Snyk Studio product page](https://snyk.io/product/studio/) — the product these recipes plug into
- [Snyk Platform](https://snyk.io/platform/) — the broader AI-native security platform
- [Snyk Studio documentation](https://docs.snyk.io/integrations/snyk-studio-agentic-integrations/getting-started-with-snyk-studio) — setup, MCP server, and reference material
- [`guardrail_directives/`](guardrail_directives/) — automatic, always-on controls
- [`command_directives/`](command_directives/) — on-demand security workflows
- [`installer/README.md`](installer/README.md) — installer flags, profiles, and verification

---

## Need help?

Reach out to your Snyk account team, or open an issue in this repository.

> This repository is closed to public contributions.
