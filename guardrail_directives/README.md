# Guardrail Directives

Guardrail directives are automatically injected into agent interactions. They govern agent behavior by providing persistent context, setting security policies, and enforcing compliance rules. Unlike [command directives](../command_directives/) (which are invoked on-demand), guardrails run automatically to prevent security issues from being introduced.

[Learn more in Snyk's documentation](https://docs.snyk.io/integrations/snyk-studio-agentic-integrations/directives#guardrail-directives)

## Implementation Approaches

Guardrail directives generally follow two implementation patterns:

1. **Hooks** - Scripts that run at lifecycle events (deterministic)
2. **Rules** - Instructions embedded in the AI's context (non-deterministic)

### Choosing an Approach

| Consideration | Rules | Hooks |
|---------------|-------|-------|
| **Enforcement** | Non-deterministic (AI may skip) | Deterministic (always runs) |
| **Complexity** | Simple (one file) | More complex (scripts) |
| **Flexibility** | AI can adapt to context | Fixed behavior |
| **Setup** | Copy to rules directory | Configure hooks + scripts |
| **Visibility** | Inline in conversation | Separate output panel |

**Recommendation:** Use hooks when available for determinism. Combine with rules for real-time inline feedback.

## Available Guardrail Directives

### 1. Secure At Inception (SAI)
Automatically scans new or modified code for vulnerabilities.

| Implementation | Mechanism | Coding Assistant | Enforcement |
|----------------|-----------|-----------------|-------------|
| **[Rule Version](./secure_at_inception/rule_version/)** | Cursor Rules (`.mdc`) | Cursor | Non-deterministic |
| **[Hooks - Cursor](./secure_at_inception/hooks_version/cursor/)** | Cursor Hooks (`stop` event) | Cursor | Deterministic |
| **[Hooks - Claude Code](./secure_at_inception/hooks_version/claude/)** | Claude Code Hooks (`PostToolUse`) | Claude Code | Deterministic |
| **[Kiro/Git Hooks](./secure_at_inception/kiro_hooks/)** | Git pre-commit + Kiro background scanning | Kiro / any Git client | Deterministic |

### 2. Package Enforcement
Blocks dependency installation until security scans pass.

| Implementation | Mechanism | Coding Assistant | Enforcement |
|----------------|-----------|-----------------|-------------|
| **[Hooks](./package_enforcement/cursor/hooks/)** | Cursor Hooks (multi-event) | Cursor | Deterministic |

## How Guardrails Work

### Rule-Based (Non-Deterministic)
Rules are instructions embedded in the AI's context. The AI "sees" the rule and follows it as guidance.

```
┌─────────────────────────────────────────┐
│          AI Agent Context               │
│                                         │
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
│  AI generates code  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Hook fires at      │
│  lifecycle event    │──▶ Prompts AI to run scans
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  AI runs scans and  │
│  fixes any issues   │
└─────────────────────┘
```

## Getting Started

1. **Choose your approach** (rules vs hooks, or both)
2. **Navigate to the appropriate subdirectory**
3. **Follow installation instructions** in that README
4. **Configure your IDE**
5. **Test with a sample project**

## See Also

- [Command Directives](../command_directives/) - On-demand security fixing
- [Secure At Inception](secure_at_inception/) - Auto-scan implementations
- [Package Enforcement](package_enforcement/) - Dependency gate implementations
