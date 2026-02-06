# Documentation Structure Plan for studio-recipes

## Overview

This plan reorganizes the repository documentation to be more maintainable by:
1. Reducing duplication
2. Creating clear hierarchy with specific purposes at each level
3. Providing generic implementations that work across coding assistants (callling out where consistency may not be possible)
4. Linking to coding assistant-specific implementations only where they exist and where approrpriate

---

## Root README (`/README.md`)

### Content:

**Title:** Snyk Studio Recipes - AI Coding Assistant Directives

**Introduction:**
Directives allow security and engineering teams to govern how AI coding assistants operate across your organization, ensuring adherence to security policy, code standards, and approved workflows.

For comprehensive information about directives, see [Snyk's Directives Documentation](https://docs.snyk.io/integrations/snyk-studio-agentic-integrations/directives).

**Repository Structure:**

This repository is organized hierarchically:

```
Root
  └─ Directive Types (command, guardrail)
      └─ Specific Outcome Directives (secure at inception, remediation, etc.)
          └─ Implementation Options (rules, hooks, etc.)
              └─ Coding Assistant Implementations (Cursor, Claude Code, etc.)
```

**How to Use This Repository:**

1. **Navigate by directive type** - Start with either Command or Guardrail directives
2. **Choose your use case** - Each directive type contains specific outcomes (e.g., "Remediation", "Secure at Inception")
3. **Select implementation approach** - Most outcomes offer multiple implementation options (rules, hooks, etc.)
4. **Find your coding assistant** - Where available, specific implementations are provided

**Important Notes:**

- Each directory level contains a README explaining that level's concepts
- Generic implementations are provided at the "Implementation Options" level
- These generic implementations can be adapted to most coding assistants
- Not all coding assistants have example implementations, but the generic examples serve as templates

**Directive Scope: Global vs Project-Level**

Directives can be configured at two levels:

- **Global/User Level** - Applied to all projects for a user
- **Project/Directory Level** - Applied only to a specific project

**Recommendation:** Install directives at the **global user level** to ensure consistent security policies across all your projects. Installing directives at the **project/directory level** can make these directives available to all contributors to that repository but require git management.

Each coding assistant has its own configuration locations for global and project-level directives. Consult your coding assistant's documentation (linked in the Command Directives and Guardrail Directives sections) for specific installation paths.

**Available Directive Types:**

- [Command Directives](./command_directives/) - Manually invoked workflows
- [Guardrail Directives](./guardrail_directives/) - Automatically applied policies

---

## Command Directives README (`/command_directives/README.md`)

### Content:

**Title:** Command Directives

**Definition:**
Command directives are manually invoked by human developers or agents. They codify and standardize complex, multi-step engineering and security playbooks.

[Learn more in Snyk's documentation](https://docs.snyk.io/integrations/snyk-studio-agentic-integrations/directives#command-directives)

**How Command Directives Work:**

Different coding assistants have different mechanisms for invoking commands. Common patterns include:
- Slash commands (e.g., `/snyk-fix`)
- Skills or workflows
- Custom commands

**Coding Assistant Documentation:**

Consult your coding assistant's official documentation for how to implement commands:

- [Cursor](https://cursor.com/docs/context/commands)
- [GitHub Copilot](https://docs.github.com/en/copilot/how-tos/chat-with-copilot/chat-in-ide#slash-commands)
- [Windsurf](https://docs.windsurf.com/windsurf/cascade/workflows)
- [Claude Code](https://code.claude.com/docs/en/skills#extend-claude-with-skills)
- [Gemini CLI](https://geminicli.com/docs/cli/commands/)

**Available Command Directives:**

- [Remediation](./remediation/) - End-to-end security vulnerability fixes

---

## Remediation README (`/command_directives/remediation/README.md`)

### Content:

**Title:** Remediation Directives

**Definition:**

Remediation directives trigger a security remediation playbook that results in a secure pull request.

**Generic Implementation:**

The following directive can be customized to fit your organization's specific needs and adapted to any coding assistant that supports command directives.

This directive guides the agent to:
- Execute one or more security tests
- Filter the results if any parameters are provided
- Apply fixes to vulnerabilities
- Rescan to validate the security fix resolved the issues and did not introduce new ones
- Optionally create a pull request

**Implementation Approaches:**

This directory contains two implementation patterns:

1. **[Composite Commands](./composite_commands/)** - Modular approach with separate commands for each phase
2. **[Single All-in-One Command](./single_all_in_one_command/)** - Complete workflow in one command

**Coding Assistant Implementations:**

Specific implementations for particular coding assistants can be found within each implementation approach directory.

---

## Composite Commands README (`/command_directives/remediation/composite_commands/README.md`)

### Content:

**Title:** Composite Remediation Commands

**Overview:**

The composite approach breaks the remediation workflow into discrete, specialized commands that can be invoked individually or chained together. This provides:

- Granular control over each remediation phase
- Ability to invoke specific steps independently
- Easier customization of individual workflows
- Better for teams with specific security requirements

**Command Structure:**

| Command | Purpose | When to Use |
|---------|---------|-------------|
| `/snyk-fix` | Main orchestrator | Entry point that dispatches to specialized commands |
| `/snyk-code-fix` | SAST remediation | Fix code vulnerabilities (XSS, SQLi, Path Traversal, etc.) |
| `/snyk-sca-fix` | Dependency remediation | Upgrade vulnerable packages |
| `/create-security-pr` | PR workflow | Create branch, commit, push, and open pull request |

**Workflow:**

```
User: /snyk-fix
  ↓
/snyk-fix analyzes the issue type
  ↓
Routes to → /snyk-code-fix OR /snyk-sca-fix
  ↓
Returns control to /snyk-fix
  ↓
User confirms PR creation
  ↓
/create-security-pr executes
```

**Generic Command Definitions:**

[Include the generic markdown for each command - snyk-fix.md, snyk-code-fix.md, snyk-sca-fix.md, create-security-pr.md]

---

## Single All-in-One Command README (`/command_directives/remediation/single_all_in_one_command/README.md`)

### Content:

**Title:** Single All-in-One Remediation Command

**Overview:**

This approach combines all remediation phases into a single, self-contained command. This provides:

- Simpler setup (one file to install)
- No dependencies between multiple commands
- Complete workflow in one place
- Easier to understand the full process
- Better for straightforward use cases

**Command:**

`/snyk-fix` - Complete security remediation from scan to PR

**Workflow:**

All phases execute within the same command:
1. Input parsing
2. Security scanning
3. Vulnerability analysis
4. Fix application
5. Validation
6. Summary and PR prompt
7. PR creation (if confirmed)

**Generic Command Definition:**

[Include the complete all-in-one snyk-fix.md content]

---

## Guardrail Directives README (`/guardrail_directives/README.md`)

### Content:

**Title:** Guardrail Directives

**Definition:**

Guardrail directives are automatically injected into agent interactions. They govern agent behavior by providing persistent context, setting security policies, and enforcing compliance rules.

[Learn more in Snyk's documentation](https://docs.snyk.io/integrations/snyk-studio-agentic-integrations/directives#guardrail-directives)

**Implementation Approaches:**

Guardrail directives generally follow two implementation patterns:

1. **Hooks** - Scripts that run at lifecycle events (deterministic) 
2. **Rules** - Instructions embedded in the AI's context (non-deterministic)

**Choosing an Approach:**

| Consideration | Hooks | Rules |
|---------------|-------|-------|
| **Enforcement** | Always executes | AI follows as guidance |
| **Timing** | With specific events | Inline during generation |
| **Setup** | Multiple files + configuration | Single file |
| **Best for** | Guaranteed compliance | Real-time feedback |

**Recommendation:** Use hooks when available for determinism.

**Available Guardrail Directives:**

- [Secure at Inception](./secure_at_inception/) - Automatically scan AI-generated code for vulnerabilities
- [Package Health Check](./package_health_check/) - Enforce security scanning before package installation

---

## Secure at Inception README (`/guardrail_directives/secure_at_inception/README.md`)

### Content:

**Title:** Secure at Inception

**Definition:**

Secure at inception directives are guardrails that ensure AI-generated code is tested for security issues at the time of code generation. This implements the "shift-left" security principle—catching vulnerabilities as code is written.

Secure at inception directives can be configured for one or more Snyk products.

**Coding Assistant Implementations:**

Specific implementations for particular coding assistants can be found within each implementation approach directory.

---

## Secure at Inception - Rules README (`/guardrail_directives/secure_at_inception/rules/README.md`)
TODO: should we replace all rules with skills?

### Content:

**Title:** Secure at Inception - Rules Implementation

**Overview:**

The rules implementation embeds security scanning instructions directly into the AI agent's context. When the AI generates or modifies code, it sees these rules and follows them as guidance—scanning code and fixing vulnerabilities in real-time.

**Generic Rule Content:**

TODO: Code only
TODO: All products

**Coding Assistant Documentation:**

Consult your coding assistant's official documentation for how to implement rules:

- [Cursor](https://cursor.com/docs/context/rules)
- [GitHub Copilot](https://docs.github.com/en/copilot/how-tos/configure-custom-instructions/add-repository-instructions?tool=vscode)
- [Windsurf](https://docs.windsurf.com/windsurf/cascade/memories)
- [Claude Code](https://code.claude.com/docs/en/memory#modular-rules-with-claude%2Frules%2F)
- [Gemini CLI](https://geminicli.com/docs/cli/gemini-md/)

**Coding Assistant Implementations:**

- [Cursor](./cursor/) - `.cursor/rules/*.mdc` format
- ...

---

## Secure at Inception - Hooks README (`/guardrail_directives/secure_at_inception/hooks/README.md`)

### Content:

**Title:** Secure at Inception - Hooks Implementation

**Overview:**

The hooks implementation uses lifecycle event scripts to prompt the AI agent to run security scans at session end. This provides deterministic enforcement—the hook always fires regardless of what the AI decided to do during the session.

**How It Works:**

1. AI generates/modifies code during session
2. Session completes
3. Hook script runs at a particular event (e.g., `stop`)
4. Script sends follow-up message to AI
5. AI runs security scans in response
6. AI fixes any issues found

**Implementation Requirements:**

Hook implementations typically require two files:

1. **Hook configuration file** - Registers the hook with the coding assistant
2. **Hook script** - Contains the logic that runs at the event

**Generic Hook Logic:**

The hook should:
- Trigger on session completion event (e.g., `stop`, `afterTask`)
- Check if code was modified during the session
- Send a follow-up message prompting security scans
- Prevent infinite loops (check if already prompted)

**Example Follow-up Message:**
```
If you changed any code, run snyk_code_scan on current directory. 
If you added any new packages, run snyk_sca_scan.
```

**Coding Assistant Documentation:**

Consult your coding assistant's official documentation for how to implement hooks:

- [Cursor](https://cursor.com/docs/agent/hooks)
- [GitHub Copilot](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/use-hooks)
- [Windsurf](https://docs.windsurf.com/windsurf/cascade/hooks)
- [Claude Code](https://code.claude.com/docs/en/hooks)
- [Gemini CLI](https://geminicli.com/docs/hooks/)

**Coding Assistant Implementations:**

- [Cursor](./cursor/) - `hooks.json` + shell script
- ...

---

## Package Health Check README (`/guardrail_directives/package_health_check/README.md`)

### Content:

**Title:** Package Health Check

**Definition:**

Package health check directives enforce security scanning before package installation. They implement a "scan-before-install" security gate that prevents vulnerable dependencies from being added without review.

**How It Works:**

1. AI adds dependencies to package manifest
2. Guardrail detects the change
3. AI attempts to run install command
4. Guardrail blocks the install
5. AI runs security scan
6. If scan passes, install is allowed

**Generic Implementation Concept:**

The guardrail should:
- Detect when package manifest files are modified (package.json, requirements.txt, etc.)
- Block package manager install commands until a scan runs
- Clear the block when `snyk_package_health` is executed
- Support common package managers (npm, yarn, pnpm, pip, maven, etc.)

**Implementation Approaches:**

This directory contains two implementation patterns:

1. **[Rules](./rules/)** - Instructions for AI to scan before installing (non-deterministic)
2. **[Hooks](./hooks/)** - Scripts that block install commands until scanned (deterministic)

**Choosing an Approach:**

| Consideration | Hooks | Rules |
|---------------|-------|-------|
| **Enforcement** | Always executes | AI follows as guidance |
| **Timing** | With specific events | Inline during generation |
| **Setup** | Multiple files + configuration | Single file |
| **Best for** | Guaranteed compliance | Real-time feedback |

**Recommendation:** Use hooks when available for determinism.

**Coding Assistant Implementations:**

Specific implementations for particular coding assistants can be found within each implementation approach directory.

---

## Package Health Check - Rules README (`/guardrail_directives/package_health_check/rules/README.md`)

### Content:

**Title:** Package Health Check - Rules Implementation

**Overview:**

The rules implementation embeds package scanning instructions into the AI agent's context. The AI follows these instructions when adding dependencies—running security scans before installation.

**Generic Rule Content:**

```
Before introducing a new open source dependency or updating an existing one, run the package_health_check tool:
- If the package is Healthy, proceed with adding the dependency.
- If Review recommended, pause execution, explain the concerns, require explicit user approval, and suggest alternatives when possible.
- If Not recommended, do not proceed automatically. Clearly explain why the package is not recommended and require explicit user approval to continue.
- If Unknown, do not assume the package is safe or unsafe. Clearly explain why the package health could not be determined.
```

**Coding Assistant Implementations:**

- [Cursor](./cursor/) - `.cursor/rules/*.mdc` format
- ...

---

## Package Health Check - Hooks README (`/guardrail_directives/package_health_check/hooks/README.md`)

### Content:

**Title:** Package Health Check - Hooks Implementation

**Overview:**

The hooks implementation uses lifecycle event scripts to enforce security scanning before package installation. This provides deterministic, hard enforcement—install commands are blocked until a scan runs.

**How It Works:**
TODO: Revisit this section
1. AI modifies package manifest → `afterFileEdit` hook records pending scan
2. AI attempts install command → `beforeShellExecution` hook blocks it
3. AI runs `snyk_package_health` → `beforeMCPExecution` hook clears the block
4. AI retries install command → now allowed

**Implementation Requirements:**

Hook implementations typically require two files:

1. **Hook configuration file** - Registers multiple hook events
2. **Hook script** - Manages state and blocks/allows commands

**Required Hook Events:**

- `afterFileEdit` - Detect manifest changes
- `beforeShellExecution` - Block install commands
- `beforeMCPExecution` - Clear block when scan runs
- `stop` (optional) - Remind if scan never ran

**Generic Hook Logic:**

The hook should:
- Monitor manifest files (package.json, requirements.txt, etc.)
- Maintain state (pending scan flag) across events
- Block install command patterns (npm install, pip install, etc.)
- Clear state when security scan tool is called

**Coding Assistant Implementations:**

- [Cursor](./cursor/) - `hooks.json` + Python script
- ...

---

## Summary of Structure Benefits:

1. **Drastically reduced duplication**
   - No repeated explanations at multiple levels
   - Generic implementations serve all coding assistants
   - Mock examples removed

2. **Clear information hierarchy**
   - Each level has distinct purpose
   - Easy to navigate parent → child
   - Consistent structure across branches

3. **Maintainable**
   - Single source of truth for each concept
   - Adding coding assistant = one directory
   - Updating directive = one location

4. **Scalable**
   - Easy to add new directive types
   - Easy to add new implementation approaches
   - Easy to add new coding assistants

5. **User-friendly**
   - Links to official documentation
   - Clear recommendations
   - Generic examples adaptable to any tool
