# Command Directives

Command directives are manually invoked by human developers or agents. They codify and standardize complex, multi-step engineering and security playbooks.

[Learn more in Snyk's documentation](https://docs.snyk.io/integrations/snyk-studio-agentic-integrations/directives#command-directives)

## How Command Directives Work

Different coding assistants have different mechanisms for invoking commands. Common patterns include:
- Slash commands (e.g., `/snyk-fix`)
- Skills or workflows (e.g., SKILL.md files)
- Custom commands

## Coding Assistant Documentation

Consult your coding assistant's official documentation for how to implement commands:

- [Cursor](https://cursor.com/docs/context/commands)
- [GitHub Copilot](https://docs.github.com/en/copilot/how-tos/chat-with-copilot/chat-in-ide#slash-commands)
- [Windsurf](https://docs.windsurf.com/windsurf/cascade/workflows)
- [Claude Code](https://code.claude.com/docs/en/skills#extend-claude-with-skills)
- [Gemini CLI](https://geminicli.com/docs/cli/commands/)

## Available Command Directives

- [Synchronous Remediation](./synchronous_remediation/) - End-to-end security vulnerability scanning, fixing, and PR creation

## See Also

- [Guardrail Directives](../guardrail_directives/) - Proactive security enforcement that runs automatically
