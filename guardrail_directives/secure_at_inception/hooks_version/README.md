# Hooks Version - Secure At Inception

This directory contains a hook-based implementation of Secure At Inception for Cursor IDE. The hook runs at session end to ensure all generated code has been scanned.

## Overview

The hooks version uses Cursor's `stop` hook event to prompt the AI agent to run security scans before completing a task. This provides a deterministic safety net—the hook always fires regardless of what the AI decided to do during the session.

## How It Works

```
┌────────────────────────────────────────────────────────────┐
│  AI Agent Session                                          │
│                                                            │
│  Turn 1: Creates new files                                 │
│  Turn 2: Modifies existing code                           │
│  Turn 3: Adds dependencies                                │
│  Turn 4: Completes task                                   │
└────────────────────────────┬───────────────────────────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────────────┐
│  stop Hook Fires                                           │
│                                                            │
│  Script checks:                                            │
│  - Is this the first completion? (not a retry loop)       │
│  - Status is "completed"?                                  │
│                                                            │
│  Returns followup_message:                                │
│  "If you changed code, run snyk_code_scan.               │
│   If you added packages, run snyk_sca_scan."             │
└────────────────────────────┬───────────────────────────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────────────┐
│  AI Receives Follow-up                                     │
│                                                            │
│  AI reads the message and:                                │
│  1. Recalls what files were changed                       │
│  2. Runs snyk_code_scan on modified code                  │
│  3. Runs snyk_sca_scan if packages added                  │
│  4. Fixes any issues found                                │
│  5. Re-scans to verify                                    │
└────────────────────────────────────────────────────────────┘
```

## Use Cases

### Code Generation Session
```
User: "Create a REST API for managing users"

AI Session:
  - Creates src/controllers/users.ts
  - Creates src/routes/users.ts
  - Creates src/models/user.ts
  - Task marked complete

[stop hook fires]
→ "If you changed code, run snyk_code_scan..."

AI Follow-up:
  - Runs snyk_code_scan on src/
  - Finds SQL injection in users.ts:45
  - Fixes the vulnerability
  - Re-scans to confirm fix
```

### Mixed Code and Dependencies
```
User: "Add authentication to the project"

AI Session:
  - Adds bcrypt, jsonwebtoken to package.json
  - Creates src/auth/middleware.ts
  - Creates src/auth/jwt.ts
  - Runs npm install
  - Task complete

[stop hook fires]
→ "If you changed code, run snyk_code_scan.
   If you added packages, run snyk_sca_scan."

AI Follow-up:
  - Runs snyk_code_scan → Finds hardcoded secret
  - Fixes by using environment variable
  - Runs snyk_sca_scan → All packages clean
```

### No Changes Made
```
User: "Explain how the auth middleware works"

AI Session:
  - Reads files
  - Explains code
  - No modifications made
  - Task complete

[stop hook fires]
→ "If you changed code, run snyk_code_scan..."

AI Follow-up:
  - Notes: "No code was changed in this session"
  - No scans needed
```

## Mock Example: Hook Script Logic

```bash
#!/bin/bash
# snyk_sai_sast_sca_script.sh

# Read JSON input from stdin
json_input=$(cat)

# Extract status and loop count
status=$(echo "$json_input" | jq -r '.status // empty')
loop_count=$(echo "$json_input" | jq -r '.loop_count // empty')

# Log for debugging
echo "[$timestamp] $json_input" >> /tmp/agent-audit.log
echo "Status: $status, Loop: $loop_count" >> /tmp/agent-audit.log

# Only trigger on first completion (avoid infinite loops)
if [[ "$status" == "completed" && "$loop_count" -ne 0 ]]; then
  # This is a retry after our follow-up, don't prompt again
  exit 0
fi

# Send follow-up message to prompt scanning
cat << EOF
{
  "followup_message": "If you changed any code, run snyk_code_scan on current directory. If you added any new packages, run snyk_sca_scan."
}
EOF

exit 0
```

## Installation

See [cursor/README.md](cursor/README.md) for detailed installation instructions.

## Configuration

The hook uses the `stop` event which fires when:
- AI agent marks task as complete
- User accepts/confirms the result
- Session timeout occurs

### Loop Prevention

The script checks `loop_count` to prevent infinite loops:
- `loop_count == 0`: First completion, send follow-up
- `loop_count > 0`: AI already responded to follow-up, exit

## Advantages

1. **Deterministic** - Always fires at session end
2. **Comprehensive** - Catches anything missed during session
3. **Safety Net** - Works regardless of inline rule compliance
4. **Auditable** - Can log all sessions for compliance

## Limitations

1. **Timing** - Feedback comes at end, not inline
2. **Extra Turn** - May require additional AI turn for fixes
3. **User Experience** - Session "extends" beyond initial completion

## Combining with Rules

For maximum coverage, use both hooks and rules:

```
┌─────────────────────────────────────────────┐
│  SAI Rule (inline)                          │
│  - Real-time scanning during generation     │
│  - Immediate fix before presenting code     │
└─────────────────────────────────────────────┘
                    +
┌─────────────────────────────────────────────┐
│  SAI Hook (session end)                     │
│  - Catch anything missed by rule            │
│  - Guaranteed final check                   │
└─────────────────────────────────────────────┘
```

## See Also

- [Cursor Implementation](cursor/) - Installation guide
- [Rule Version](../rule_version/) - Inline scanning alternative
- [Secure At Inception Overview](../) - Comparison of approaches

