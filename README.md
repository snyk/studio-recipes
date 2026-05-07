# Snyk Studio Recipes

Security recipes for AI coding assistants, powered by Snyk.

## What Are Recipes?

Recipes combine Snyk's security ingredients -- Snyk's CLI & MCP server, along with Agentic skills, rules, hooks, and commands -- into ready-to-use security solutions for your development workflow.

Just like cooking, there's no single right way to combine these ingredients. A team that wants real-time inline feedback will reach for different recipes than one that needs a hard gate at commit time. This repository gives you a collection of recipes to pick from, combine, and customize to meet your security needs across your development environment and lifecycle.

## Mixing and Matching

These recipes are designed to be layered. For example, you might combine:

- A **rule** for real-time inline scanning as you code
- A **hook** as a safety net that fires at session end
- A **git pre-commit hook** as a final gate before code enters the repository
- A **secure-dependency-advisor skill** to evaluate package security before adoption
- A **/snyk-fix command** for on-demand remediation of existing issues

Start with the recipe that solves your most pressing need, then layer on more as your security posture matures.

## Customization

These are generic examples, not rigid templates. Every team's security requirements, tech stack, and workflow are different. Feel free to:

- Modify scan thresholds and severity filters
- Add or remove workflow phases
- Adapt the recipes to coding assistants not yet covered
- Combine multiple recipes into your own custom workflows

## Installation options

You can adopt recipes in two ways:

1. **Installer (recommended for Cursor / Claude Code / Gemini Code)** — Build with `python3 build_installer.py` in [`installer/`](installer/), then run **`dist/snyk-studio-install.sh`** or **`dist/snyk-studio-install.ps1`** (self-extracting scripts that unpack and run the Python installer). See [`installer/README.md`](installer/README.md) for profiles (`default`, `minimal`) and flags like `--dry-run` and `--uninstall`.

2. **Manual / copy from repo** — Pick files under `guardrail_directives/`, `command_directives/`, `mcp/`, etc., and wire them into your assistant yourself (useful for customization or IDEs not covered by the installer).

## Prerequisites

Before using any recipe, you'll need:

1. **Snyk MCP Server** -- [Set up the Snyk MCP server](https://docs.snyk.io/integrations/snyk-studio-agentic-integrations/getting-started-with-snyk-studio) in your coding assistant (the installer can merge a default `mcp/.mcp.json` into `~/.mcp.json` for supported setups)
2. **Snyk Authentication** -- Run `snyk auth` or set the `SNYK_TOKEN` environment variable

## Need Help?

If you have questions, need guidance choosing the right recipes for your team, or want to share feedback, reach out to your Snyk account team or open an issue in this repository.

> **Note:** This repository is closed to public contributions.
