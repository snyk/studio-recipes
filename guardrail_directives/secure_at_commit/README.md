# Secure At Commit (SAC) — Experimental

> **Experimental.** Secure At Commit is early access. Behavior, flags, and configuration may change.

Stop vulnerable code and dependencies from ever reaching a commit. Secure At Commit (SAC) adds a Git pre-commit check that scans the changes you're about to commit and blocks the commit if it finds new vulnerabilities.

SAC is the commit-time complement to [Secure at Inception (SAI)](../). Where SAI scans code as your AI assistant writes it, SAC enforces a single deterministic gate at `git commit` — so it catches risky code no matter how it got there: AI agent, manual edit, or copy-paste.

## What you get

- **A hard gate at commit time.** New vulnerabilities in your staged changes block the commit. It always runs — regardless of which assistant or workflow produced the code.
- **Code *and* dependency coverage.** Runs Snyk Code (SAST) on staged source files and Snyk Open Source (SCA) on changed dependency manifests.
- **Shared with your team.** The hook lives in the repository, so teammates get the same protection automatically on `git pull`.

## Get it

Follow the [Quick start](../../README.md#quick-start) to download the installer and authenticate the Snyk CLI — then install SAC by selecting the **experimental** profile. Run the installer from inside the Git repository you want to protect:

```bash
bash ./snyk-studio-install.sh --profile experimental
```

To target a repository other than your current directory, pass `--workspace`:

```bash
bash ./snyk-studio-install.sh --profile experimental --workspace /path/to/repo
```

> SAC and SAI are mutually exclusive. The `experimental` profile installs SAC in place of the default Secure at Inception guardrails, and the installer warns you if leftover SAI hooks are still present.

## How it works

When you run `git commit`, the hook:

1. Looks at the files you've staged.
2. Scans staged source with Snyk Code and any changed dependency manifests with Snyk Open Source.
3. If it finds new vulnerabilities at or above the block threshold, it prints a report and stops the commit. Otherwise the commit proceeds.

Commits with no code or dependency changes (for example, docs only) pass straight through. Need to commit anyway? `git commit --no-verify` bypasses the check.

## Tune it

- `SAC_MIN_BLOCK_SEVERITY` — lowest dependency severity that blocks a commit: `low`, `medium`, `high`, or `critical` (default `medium`).

## Uninstall

```bash
bash ./snyk-studio-install.sh --uninstall
```

Removes the pre-commit hook and the installed script from the repository.
