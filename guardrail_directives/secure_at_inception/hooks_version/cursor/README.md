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
# Copy hooks.json to .cursor directory
cp hooks.json /path/to/project/.cursor/

# Copy script to hooks directory
cp snyk_sai_sast_sca_script.sh /path/to/project/.cursor/hooks/

# Make script executable
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
                  │
                  ▼
┌─────────────────────────────────────────┐
│  Script checks loop_count               │
│                                         │
│  loop_count == 0 → First completion     │
│  loop_count > 0  → Already prompted     │
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
│                                         │
│  AI runs appropriate scans              │
│  AI fixes any issues found              │
│  Session truly completes                │
└─────────────────────────────────────────┘
```

## Use Cases

### New Code Generated
```
Session: Create a file upload handler

AI creates: src/upload/handler.ts
AI completes task
  → stop hook fires
  → "If you changed code, run snyk_code_scan"

AI runs snyk_code_scan
  → Finds path traversal
  → Fixes vulnerability
  → Session complete
```

### New Packages Added
```
Session: Add logging to the project

AI adds winston to package.json
AI creates src/logger.ts
AI completes task
  → stop hook fires
  → "If you added packages, run snyk_sca_scan"

AI runs snyk_sca_scan
  → Winston is safe
AI runs snyk_code_scan
  → Logger code is clean
  → Session complete
```

### Informational Session
```
Session: Explain how the auth works

AI reads files, explains code
No modifications made
AI completes task
  → stop hook fires
  → "If you changed code..."

AI notes: "No code was changed"
  → No scans needed
  → Session complete
```

## Debugging

### Check Hook Is Firing

Look for log entries:
```bash
tail -f /tmp/agent-audit.log
```

### Common Issues

**Hook not firing:**
- Verify `hooks.json` is valid JSON
- Check file is in `.cursor/` (not `.cursor/hooks/`)
- Restart Cursor IDE

**Script not executing:**
- Verify script has execute permissions
- Check script path in hooks.json matches actual location

**Infinite loop:**
- Ensure `loop_count` check is working
- Script should exit without output when `loop_count > 0`

## Mock Example: Script Output

When the script runs on first completion:

**Input (from Cursor):**
```json
{
  "hook_event_name": "stop",
  "status": "completed",
  "loop_count": 0,
  "workspace_roots": ["/path/to/project"]
}
```

**Output (to Cursor):**
```json
{
  "followup_message": "If you changed any code, Run a snyk code scan on current directory. If you added any new packages run a snyk SCA scan."
}
```

## Customization

### Modify the Prompt

Edit `snyk_sai_sast_sca_script.sh` to customize the follow-up message:

```bash
cat << EOF
{
  "followup_message": "Your custom message here. Include specific scan instructions."
}
EOF
```

### Add Conditional Logic

Enhance the script to check what was changed:

```bash
# Example: Check if package.json was modified
if git diff --name-only | grep -q "package.json"; then
  # Include SCA scan in message
fi
```

## See Also

- [Hooks Version Overview](../) - How the hook approach works
- [Rule Version](../../rule_version/) - Alternative inline approach
- [Cursor Hooks Documentation](https://docs.cursor.com/hooks)

