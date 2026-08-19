# Secrets At Commit

A Git pre-commit check that scans the changes you're about to commit for hardcoded secrets and blocks when a finding is classified as part of this commit.

Secrets At Commit is secrets-only. It can be installed alongside Secure At Commit because it does not run SAST or SCA scans. It is opt-in and installs into a target Git repository.

## Install

It belongs to no profile, so name it with `--recipes` under the **experimental** profile. Run the Snyk Studio installer from the repository you want to protect, or pass `--workspace`:

```bash
bash ./snyk-studio-install.sh --profile experimental --recipes secrets-precommit-hook --workspace /path/to/repo
```

To install it alongside Secure At Commit, name both:

```bash
bash ./snyk-studio-install.sh --profile experimental --recipes secure-at-commit,secrets-precommit-hook --workspace /path/to/repo
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
| `SECRETS_SCAN_TIMEOUT` | `90` | Seconds to wait for the scan before treating it as a scan failure. Set to `-1` for no timeout at all. |
| `SECRETS_BLOCK_ON_SCAN_FAILURE` | `1` | By default, a scan failure (after retries) blocks the commit. Set to `0` to warn and allow instead. |
| `SECRETS_HOOK_DEBUG` | `0` | Set to `1` for verbose stderr logging. |

`SECRETS_SCAN_TIMEOUT` bounds the whole hook, not just the Snyk CLI scan: the git operations used to inspect and snapshot the staged index share the same wall-clock budget, so the total run time is `SECRETS_SCAN_TIMEOUT` plus a small, fixed amount of non-subprocess overhead. Running out of budget (or a Git error) while determining what to scan is a prerequisite failure; running out of budget while preparing a snapshot of that content to scan respects `SECRETS_BLOCK_ON_SCAN_FAILURE` like any other scan failure.

Findings are classified as added-by-this-commit or pre-existing by comparing
matched secret text against a `HEAD` baseline scan, run concurrently with the
staged-content scan. A finding falls back to line-range overlap when there's
no baseline content to compare against (a new file, an unresolved rename, or
text that can't be re-extracted).

To suppress a specific secret finding (a known placeholder, a revoked key, a
won't-fix case), use Snyk's own per-finding ignore instead of excluding a
whole path: a blocked commit prints the ignore request command for findings
that can be ignored (requires Code Consistent Ignores enabled for your org).

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
