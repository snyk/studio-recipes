#!/bin/bash
#
# Snyk Secure at Inception - Claude Code PostToolUse Hook (Sync MCP Version)
#
# Fires after every Edit/Write tool call. If the modified file is a
# Snyk-supported language, injects additionalContext prompting Claude
# to run snyk_code_scan and fix only newly introduced vulnerabilities.

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

cat << 'EOF'
{
  "hookSpecificOutput": {
    "hookEventName": "PostToolUse",
    "additionalContext": "SECURITY SCAN REQUIRED: You have just modified a source code file. After completing your current set of edits, run the snyk_code_scan MCP tool on the current directory to check for security vulnerabilities. If the scan finds issues in code you just wrote or modified (newly introduced issues), fix them. Do NOT fix pre-existing issues that were present before your changes. After fixing, re-scan to verify your fixes resolved the issues without introducing new ones. Repeat until no newly introduced issues remain."
  }
}
EOF

exit 0
