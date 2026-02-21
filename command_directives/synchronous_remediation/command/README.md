# Command Definitions

This directory contains command definition files that define structured security remediation workflows for AI coding assistants. Commands are markdown files that can be installed as rules or custom commands.

## Two Approaches

### 1. Composite Commands (Recommended)
A modular architecture where the main command dispatches to specialized sub-commands:

```
/snyk-fix
    ├── /snyk-code-fix    (for SAST issues)
    ├── /snyk-sca-fix     (for dependency issues)
    └── /create-security-pr (for PR creation)
```

**Advantages:**
- Granular control over each phase
- Can invoke sub-commands independently
- Easier to customize individual workflows
- Better for teams with specific requirements

### 2. Single All-in-One Command
A self-contained command with all logic in one file:

**Advantages:**
- Simpler installation (one file)
- No dependencies between commands
- Easier to understand complete flow

## Choosing Between Approaches

| Consideration | Composite | All-in-One |
|--------------|-----------|------------|
| Setup complexity | 4 files | 1 file |
| Customization | High | Medium |
| Direct sub-command access | Yes | No |
| Maintenance | Update individual files | Update one file |
| Team workflows | Better | Simpler |

## Installation

Copy command files to your project's rules directory:

```bash
# Composite approach
mkdir -p .cursor/rules
cp composit_commands/*.md /path/to/project/.cursor/rules/

# All-in-one approach
cp single_all_in_one_command/snyk-fix.md /path/to/project/.cursor/rules/
```

## Prerequisites

- **Snyk MCP Server** - Must be configured in your IDE's MCP settings
- **Snyk CLI** - Installed and accessible (`snyk` command)
- **Snyk Authentication** - Either `snyk auth` or `SNYK_TOKEN` environment variable
- **GitHub CLI** (optional) - For PR creation (`gh` command)

## See Also

- [Composite Commands](composit_commands/) - Modular command set
- [Single All-in-One Command](single_all_in_one_command/) - Self-contained command
- [Skills](../skills/) - Alternative skill-based approach
