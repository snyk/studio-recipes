# Secrets At Commit

A Git pre-commit check that scans the changes you're about to commit for hardcoded secrets and blocks when a finding is classified as part of this commit.

Secrets At Commit is secrets-only. It can be installed alongside Secure At Inception or Secure At Commit because it does not run SAST or SCA scans. It is opt-in and installs into a target Git repository.

## Install

Run the Snyk Studio installer from the repository you want to protect, or pass `--workspace`:

```bash
bash ./snyk-studio-install.sh --workspace /path/to/repo --secrets-precommit-hook
```

Authenticate the Snyk CLI before using the hook:

```bash
snyk auth
```

## What you get

- A commit-time gate scoped to secret findings in staged changes.
- Visible output warns when findings are classified as pre-existing, without printing file-level detail for those non-blocking findings.
- By default, scans run against a temporary snapshot of the staged index, so unstaged working-tree edits are not scanned by accident.

## How it works

1. Reads the staged file list.
2. Builds a temporary snapshot of the staged content and scans it with Snyk Secrets.
3. Classifies findings as either part of this commit or pre-existing.
4. Warns about pre-existing findings and blocks the commit when an in-scope finding is at or above the configured severity.

Use `git commit --no-verify` to bypass the hook.

## Configuration

| Variable | Default | Description |
|---|---:|---|
| `SECRETS_MIN_BLOCK_SEVERITY` | `medium` | Lowest severity that blocks a commit: `low`, `medium`, `high`, or `critical`. |
| `SECRETS_SCAN_TIMEOUT` | `90` | Seconds to wait for the Snyk CLI scan before treating it as a scan failure. |
| `SECRETS_BLOCK_ON_SCAN_FAILURE` | `0` | By default, scan failures warn and allow the commit. Set to `1` to block on scan failures. |
| `SECRETS_FALLBACK_TO_WORKING_DIR` | `0` | By default, failure to snapshot staged content blocks the commit because the hook cannot confirm it scanned the index. Set to `1` to scan the working tree instead, with a warning. |
| `SECRETS_IGNORE_PATHS` | unset | Comma-separated glob patterns for staged relative paths to skip. |
| `SECRETS_HOOK_DEBUG` | `0` | Set to `1` for verbose stderr logging. |
| `SECRETS_DIFF_STRATEGY` | `line` | `line` classifies findings by overlap with added/changed lines. `content` also scans baseline content and compares matched secret text, which can reduce false positives when an existing secret's line is edited for unrelated reasons. |

`SECRETS_SCAN_TIMEOUT` only applies to the Snyk CLI scan. Git operations used to inspect and snapshot the staged index have fixed internal timeouts; a timeout or Git error is treated as a prerequisite failure.

## Logging

For runs inside a Git repository, the hook appends the same decision-level lines shown on stderr to a per-repository log:

```text
~/.snyk-studio/git-hooks/secrets-hooks/ws/<repo-folder-name>/log.txt
```

The log includes scan start, failures, summary counts, and debug lines when enabled. It does not include secret values or file-level finding details. The log rotates to `log.txt.1` after it exceeds 1 MiB.

## Windows notes

- Git and Snyk subprocess output is decoded as UTF-8.
- On Windows, Snyk is invoked through `cmd.exe` so npm-installed `snyk.cmd` launchers can run.

## Uninstall

```bash
bash ./snyk-studio-install.sh --workspace /path/to/repo --uninstall
```

This removes the installed script and the pre-commit integration from the target repository.
