# Cursor Hooks - Secure At Inception

This directory contains the Cursor IDE hook implementation for Secure At Inception. Install these files to enable automatic security scan prompts at the end of each AI agent session.

## Files

| File | Purpose |
|------|---------|
| `hooks.json` | Hook configuration for Cursor |
| `snyk_sai_sast_sca_script.sh` | Shell script that sends follow-up message |

## Installation

### Step 1: Create Hooks Directory

```bash
mkdir -p /path/to/project/.cursor/hooks
```

### Step 2: Copy Configuration

```bash
cp hooks.json /path/to/project/.cursor/

cp snyk_sai_sast_sca_script.sh /path/to/project/.cursor/hooks/

chmod +x /path/to/project/.cursor/hooks/snyk_sai_sast_sca_script.sh
```

### Step 3: Verify Structure

Your project should have:
```
your-project/
├── .cursor/
│   ├── hooks.json
│   └── hooks/
│       └── snyk_sai_sast_sca_script.sh
└── ... (your project files)
```

## Configuration

### hooks.json

```json
{
  "version": 1,
  "hooks": {
    "stop": [
      {
        "command": "./hooks/snyk_sai_sast_sca_script.sh"
      }
    ]
  }
}
```

The `stop` hook fires when:
- AI agent marks task as complete
- Session ends (timeout or user action)

### Script Behavior

The script:
1. Reads JSON input from stdin (hook event data)
2. Checks if this is the first completion (`loop_count`)
3. Returns a `followup_message` prompting security scans

### Loop Prevention

The script checks `loop_count` to prevent infinite loops:
- `loop_count == 0`: First completion, send follow-up
- `loop_count > 0`: AI already responded to follow-up, exit

## How It Works

```
┌─────────────────────────────────────────┐
│  AI completes task                      │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  Cursor fires "stop" hook               │
│                                         │
│  Passes JSON to script:                 │
│  {                                      │
│    "hook_event_name": "stop",          │
│    "status": "completed",              │
│    "loop_count": 0                     │
│  }                                      │
└─────────────────┬───────────────────────┘
                  │ (first completion)
                  ▼
┌─────────────────────────────────────────┐
│  Script outputs:                        │
│  {                                      │
│    "followup_message": "If you changed │
│     any code, run snyk_code_scan..."   │
│  }                                      │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  AI receives follow-up                  │
│  AI runs appropriate scans              │
│  AI fixes any issues found              │
│  Session truly completes                │
└─────────────────────────────────────────┘
```


## See Also

- [Hooks Version Overview](../) - How the hook approach works
- [Claude Code Implementation](../claude/sync_mcp_version/) - Alternative for Claude Code users
- [Rule Version](../../rule_version/) - Alternative inline approach
- [Cursor Hooks Documentation](https://docs.cursor.com/hooks)
