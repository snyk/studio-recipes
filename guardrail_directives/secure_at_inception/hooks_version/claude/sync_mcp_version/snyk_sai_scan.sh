#!/bin/bash
#
# Snyk Secure at Inception - Claude Code PostToolUse Hook (Sync MCP Version)
#
# Fires after every Edit/Write tool call. If the modified file is a
# Snyk-supported language, injects additionalContext prompting Claude
# to run snyk_code_scan and fix only newly introduced vulnerabilities.
#
# Fail-closed on auth: the snyk_code_scan MCP tool needs an authenticated
# Snyk CLI. If we cannot confirm authentication, the hook BLOCKS and asks the
# user to run `snyk auth` rather than emitting a scan prompt that would
# silently fail — consistent with the CLI hooks (secure_at_commit, Kiro).
#
# CAVEAT: authentication is probed via the Snyk CLI configstore
# (SNYK_TOKEN env, then ~/.config/configstore/snyk.json). The Snyk MCP server
# may authenticate independently of the CLI configstore, so this probe can be
# a false negative; the block message tells Claude it may proceed if it has
# already confirmed auth by other means.

# Returns 0 when Snyk appears authenticated, 1 otherwise. Reads no stdin.
snyk_authenticated() {
  if [ -n "${SNYK_TOKEN:-}" ]; then
    return 0
  fi
  # Hardcode ~/.config (the configstore default) rather than trusting
  # $XDG_CONFIG_HOME from the environment.
  cfg="$HOME/.config/configstore/snyk.json"
  if command -v jq >/dev/null 2>&1 && [ -f "$cfg" ]; then
    tok=$(jq -r '.api // .INTERNAL_OAUTH_TOKEN_STORAGE // empty' "$cfg" 2>/dev/null)
    if [ -n "$tok" ]; then
      return 0
    fi
  fi
  return 1
}

FILE_PATH=$(jq -r '.tool_input.file_path // .tool_input.filePath // empty')

if [ -z "$FILE_PATH" ]; then
  exit 0
fi

EXT="${FILE_PATH##*.}"
EXT=$(echo "$EXT" | tr '[:upper:]' '[:lower:]')

case "$EXT" in
  js|jsx|mjs|cjs|ts|tsx|\
  py|\
  java|kt|kts|\
  go|\
  rb|\
  php|\
  cs|vb|\
  swift|m|mm|\
  scala|\
  rs|\
  c|cpp|cc|h|hpp|\
  cls|trigger|\
  ex|exs|\
  groovy|\
  dart)
    ;;
  *)
    exit 0
    ;;
esac

if ! snyk_authenticated; then
  cat << 'EOF'
{
  "decision": "block",
  "reason": "Snyk is not authenticated, so the required snyk_code_scan security scan cannot run on the code you just modified. Ask the user to run `snyk auth` in a terminal to authenticate, then continue. If you have already confirmed Snyk is authenticated (for example via the MCP server), you may proceed."
}
EOF
  exit 0
fi

cat << 'EOF'
{
  "hookSpecificOutput": {
    "hookEventName": "PostToolUse",
    "additionalContext": "SECURITY SCAN REQUIRED: You have just modified a source code file. After completing your current set of edits, run the snyk_code_scan MCP tool on the current directory to check for security vulnerabilities. If the scan finds issues in code you just wrote or modified (newly introduced issues), fix them. Do NOT fix pre-existing issues that were present before your changes. After fixing, re-scan to verify your fixes resolved the issues without introducing new ones. Repeat until no newly introduced issues remain."
  }
}
EOF

exit 0
