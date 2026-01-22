# Command Directives

This directory contains AI agent command definitions that enable security remediation workflows in different AI coding assistants. Commands are invokable instructions that guide AI agents through structured security scanning and fixing processes.

## Overview

Command directives define the behavior of AI assistants when users request security-related actions. They transform natural language requests like "fix security issues" into structured, repeatable workflows that scan for vulnerabilities, apply fixes, validate results, and optionally create pull requests.

## Use Cases

### 1. On-Demand Security Fixes
When a developer wants to fix vulnerabilities in their codebase:
```
User: "fix security issues"
Agent: Scans → Identifies highest priority issue → Fixes → Validates → Offers PR
```

### 2. Targeted Vulnerability Remediation
When fixing specific known issues:
```
User: "fix CVE-2021-44228"
Agent: Locates the CVE → Applies specific fix → Validates resolution
```

### 3. Dependency Updates
When addressing vulnerable packages:
```
User: "fix vulnerabilities in lodash"
Agent: Scans SCA → Identifies safe upgrade version → Updates → Validates
```

## Supported AI Assistants

| Assistant | Implementation Location | Configuration Method |
|-----------|------------------------|---------------------|
| **Claude Code** | `synchronous_remediation/claude_code/skills/` | SKILL.md files in `.claude/skills/` |
| **Cursor** | `synchronous_remediation/cursor/command/` | Custom commands or rules |

## Mock Example: Command Flow

```python
# Conceptual flow of a security fix command

def snyk_fix_command(user_input):
    # Phase 1: Parse user intent
    scan_type = detect_scan_type(user_input)  # "code", "sca", or "both"
    target = extract_target(user_input)        # CVE, package name, file, etc.
    
    # Phase 2: Discovery
    if scan_type in ["code", "both"]:
        code_results = snyk_code_scan(project_path)
    if scan_type in ["sca", "both"]:
        sca_results = snyk_sca_scan(project_path)
    
    vulnerability = select_highest_priority(code_results, sca_results)
    
    # Phase 3: Remediation
    if vulnerability.type == "code":
        apply_code_fix(vulnerability)
    else:
        upgrade_dependency(vulnerability)
    
    # Phase 4: Validation
    rescan_results = run_scan(vulnerability.type)
    assert vulnerability not in rescan_results
    
    # Phase 5: Summary & PR
    display_summary(vulnerability, fix_applied)
    if user_confirms_pr():
        create_pull_request(vulnerability)
```

## Getting Started

1. **Choose your AI assistant** - Navigate to the appropriate subdirectory
2. **Review the implementation** - Each has its own README with installation steps
3. **Copy to your project** - Follow the IDE-specific configuration instructions
4. **Configure Snyk** - Ensure Snyk CLI is installed and authenticated

## See Also

- [Guardrail Directives](../guardrail_directives/) - Proactive security enforcement
- [Synchronous Remediation](./synchronous_remediation/) - Detailed command implementations

