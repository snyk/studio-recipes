# Secure At Inception (SAI)

Automatically scan new or modified code for security vulnerabilities as the AI generates it. This implements the "shift-left" security principle—catching issues at the moment of creation.

## Overview

Secure At Inception ensures that every piece of AI-generated code is security-scanned before the session ends. Choose between two implementation approaches based on your needs.

## Implementation Options

| Approach | Mechanism | Timing | Enforcement |
|----------|-----------|--------|-------------|
| **Rule Version** | Cursor Rules | Inline with AI responses | Non-deterministic (AI follows guidance) |
| **Hooks Version** | Cursor Hooks | After agent task completes | Deterministic (always runs) |

## Comparison

### Rule Version (Non-Deterministic)

**How it works:**
- Rule is embedded in AI's context/instructions
- AI "sees" the rule and follows it as guidance
- Scanning happens inline during the conversation

**Pros:**
- Immediate feedback during code generation
- AI can fix issues before presenting code to user
- Iterative refinement in real-time

**Cons:**
- AI may occasionally skip the scan (non-deterministic)
- Relies on AI's interpretation of the rule

```
User: "Create a login function"
          │
          ▼
    ┌───────────────────────────────────┐
    │  AI sees SAI rule in context      │
    │  "Always run snyk_code_scan..."   │
    └───────────────────────────────────┘
          │
          ▼
    AI generates code
          │
          ▼
    AI runs snyk_code_scan (following rule)
          │
          ▼
    AI fixes any issues found
          │
          ▼
    AI presents secure code to user
```

### Hooks Version (Deterministic)

**How it works:**
- Hook script runs at the `stop` event (task completion)
- Script prompts AI to run scans if code was changed
- Always executes regardless of AI's decisions

**Pros:**
- Guaranteed execution at session end
- Independent of AI decision-making
- Catch-all for anything missed inline

**Cons:**
- Feedback comes at end of session, not inline
- May require additional turn to apply fixes

```
    AI generates code
          │
          ▼
    AI completes task
          │
          ▼
    ┌───────────────────────────────────┐
    │  stop hook fires                  │
    │  "If you changed code, run       │
    │   snyk_code_scan..."             │
    └───────────────────────────────────┘
          │
          ▼
    AI runs security scans
          │
          ▼
    AI fixes any issues
```

## Use Cases

### Real-Time Security Feedback (Rule Version)
```
User: "Create a file upload handler"

AI (with SAI rule active):
  1. Creates upload handler code
  2. [Sees rule] Runs snyk_code_scan
  3. Finds path traversal vulnerability
  4. Fixes the vulnerability
  5. Returns secure code to user
```

### End-of-Session Safety Net (Hooks Version)
```
User: "Build a REST API for user management"

AI: Creates multiple files over several turns
    - controllers/users.ts
    - routes/users.ts
    - models/user.ts

Session completes
  → stop hook fires
  → "Run snyk_code_scan if you changed code"

AI: Runs comprehensive scan
    - Finds SQL injection in users.ts
    - Fixes the vulnerability
```

## Mock Example: Rule Content

```markdown
---
alwaysApply: true
description: Snyk Security At Inception
---

# Project security best practices

- Always run snyk_code_scan tool for new first party code
- Always run snyk_sca_scan when a new package is introduced
- If any security issues are found, attempt to fix them
- Rescan after fixing to ensure no new issues
- Repeat until no issues remain
```

## Mock Example: Hook Flow

```bash
#!/bin/bash
# Simplified hook logic

# Read hook event data
json_input=$(cat)
status=$(echo "$json_input" | jq -r '.status')

# Only trigger on task completion
if [[ "$status" == "completed" ]]; then
  # Send follow-up message to AI
  cat << EOF
{
  "followup_message": "If you changed any code, run snyk_code_scan. If you added packages, run snyk_sca_scan."
}
EOF
fi
```

## Choosing an Approach

| Consideration | Rule Version | Hooks Version |
|---------------|--------------|---------------|
| **Best for** | Real-time feedback | Guaranteed compliance |
| **Timing** | Inline | End of session |
| **Setup** | Copy rule file | Configure hook script |
| **AI control** | AI decides when to scan | Hook prompts scan |

**Recommendation:** Use both for maximum coverage:
- Rules provide inline feedback during development
- Hooks act as a safety net to catch anything missed

## Getting Started

1. **Choose your approach** (or use both)
2. **Navigate to the subdirectory:**
   - [rule_version/](rule_version/) for rules
   - [hooks_version/](hooks_version/) for hooks
3. **Follow installation instructions** in that README

## See Also

- [Rule Version](rule_version/) - Inline scanning rules
- [Hooks Version](hooks_version/) - Session-end scanning hooks
- [Package Enforcement](../package_enforcement/) - Dependency scanning gates
- [Guardrail Directives](../) - Overview of all guardrails