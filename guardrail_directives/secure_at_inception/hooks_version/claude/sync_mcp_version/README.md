# Snyk Secure at Inception -- Claude Code Hook (Synchronous MCP Version)

A minimal Claude Code hook that prompts the agent to run `snyk_code_scan` after every code file edit or write, and fix only newly introduced vulnerabilities.


## How It Works

1. Claude edits or writes a source code file
2. The `PostToolUse` hook fires and checks the file extension
3. If the file is a Snyk-supported language, the hook injects `additionalContext` into Claude's conversation telling it to run `snyk_code_scan`
4. Claude calls the `snyk_code_scan` MCP tool on the current directory
5. If new issues are found in code Claude just wrote, it fixes them
6. The hook fires again on the fix edits, prompting a re-scan
7. The cycle repeats until no newly introduced issues remain
