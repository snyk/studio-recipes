# Guardrail Directives

This directory contains proactive security enforcement mechanisms for AI coding assistants. Unlike command directives (which are invoked on-demand), guardrails run automatically to prevent security issues from being introduced.

## Overview

Guardrail directives implement the "shift-left" security principle—catching vulnerabilities as code is written, not after. They work by:

1. **Monitoring** AI agent actions (file edits, shell commands, tool calls)
2. **Enforcing** security policies before or after specific actions
3. **Guiding** the AI to scan and fix issues automatically

## Guardrail Types

### 1. Secure At Inception (SAI)
Automatically scans new or modified code for vulnerabilities.

| Implementation | Mechanism | When It Runs |
|----------------|-----------|--------------|
| **Rule Version** | Cursor Rules | Inline with AI responses |
| **Hooks Version** | Cursor Hooks | After agent task completes |

**Use Case:** Ensures every piece of generated code is scanned before the session ends.

### 2. Package Enforcement
Blocks dependency installation until security scans pass.

| Implementation | Mechanism | When It Runs |
|----------------|-----------|--------------|
| **Hooks** | Cursor Hooks | Before `npm install`, `yarn add`, etc. |

**Use Case:** Prevents installing vulnerable packages without review.

## How Guardrails Work

### Rule-Based (Non-Deterministic)
Rules are instructions embedded in the AI's context. The AI "sees" the rule and follows it as guidance.

```
┌─────────────────────────────────────────┐
│          AI Agent Context               │
│                                         │
│  System: You are a helpful assistant... │
│  Rules:                                 │
│  - Always run snyk_code_scan for new    │
│    code in supported languages          │
│  - Fix any issues found                 │
│                                         │
│  User: Create a login function          │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│          AI Response                    │
│                                         │
│  1. Creates login function              │
│  2. (Sees rule) Runs snyk_code_scan     │
│  3. Finds SQL injection                 │
│  4. Fixes the vulnerability             │
│  5. Re-scans to confirm                 │
└─────────────────────────────────────────┘
```

### Hook-Based (Deterministic)
Hooks are scripts that run at specific lifecycle events, independent of AI decision-making.

```
┌─────────────────────┐
│  AI edits file      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  afterFileEdit hook │──▶ Records that package.json changed
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  AI runs npm install│
└──────────┬──────────┘
           │
           ▼
┌──────────────────────────┐
│  beforeShellExecution    │──▶ BLOCKS! "Run snyk_sca_scan first"
│  hook                    │
└──────────────────────────┘
```

## Use Cases

### Secure At Inception: Auto-Scan New Code
```
User: "Create a file upload handler"

AI: Creates handler with potential path traversal
    ↓
    [SAI Rule triggers]
    ↓
    Runs snyk_code_scan
    ↓
    Finds Path Traversal vulnerability
    ↓
    Fixes by adding path validation
    ↓
    Re-scans to confirm fix
    ↓
    Returns secure code to user
```

### Package Enforcement: Gate Dependencies
```
User: "Add lodash to the project"

AI: Edits package.json to add lodash
    ↓
    [afterFileEdit hook records change]
    ↓
AI: Runs npm install
    ↓
    [beforeShellExecution hook BLOCKS]
    ↓
    "Must run snyk_sca_scan first"
    ↓
AI: Runs snyk_sca_scan
    ↓
    [beforeMCPExecution hook clears block]
    ↓
AI: Runs npm install (now allowed)
```

## Mock Example: Hook Script Flow

```python
# Conceptual hook script logic

def handle_hook(event, data):
    if event == "afterFileEdit":
        if is_package_manifest(data.file_path):
            record_pending_scan(data.workspace)
            log("Package manifest changed - scan required")
    
    elif event == "beforeShellExecution":
        if is_install_command(data.command):
            if has_pending_scan(data.workspace):
                return {
                    "permission": "deny",
                    "message": "Run snyk_sca_scan before installing"
                }
    
    elif event == "beforeMCPExecution":
        if is_security_scan(data.tool_name):
            clear_pending_scan(data.workspace)
            log("Scan initiated - installs now allowed")
    
    return {"permission": "allow"}
```

## Choosing an Approach

| Consideration | Rules | Hooks |
|---------------|-------|-------|
| **Enforcement** | Non-deterministic (AI may skip) | Deterministic (always runs) |
| **Complexity** | Simple (one file) | More complex (scripts) |
| **Flexibility** | AI can adapt to context | Fixed behavior |
| **Setup** | Copy to rules directory | Configure hooks.json + scripts |
| **Visibility** | Inline in conversation | Separate output panel |

## Getting Started

1. **Choose your approach** (rules vs hooks, or both)
2. **Navigate to the appropriate subdirectory**
3. **Follow installation instructions** in that README
4. **Configure your IDE** (Cursor rules or hooks.json)
5. **Test with a sample project**

## See Also

- [Command Directives](../command_directives/) - On-demand security fixing
- [Secure At Inception](secure_at_inception/) - Auto-scan implementations
- [Package Enforcement](package_enforcement/) - Dependency gate implementations

