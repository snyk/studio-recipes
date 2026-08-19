"""Warns if a removed env var flag is still set, without changing behavior.
New removal: add one entry to `_DEPRECATED_FLAGS`."""

import os
from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class DeprecatedFlag:
    name: str
    message: str


_DEPRECATED_FLAGS: Dict[str, DeprecatedFlag] = {
    "SECRETS_FALLBACK_TO_WORKING_DIR": DeprecatedFlag(
        name="SECRETS_FALLBACK_TO_WORKING_DIR",
        message=(
            "a snapshot failure no longer falls back to anything else -- we only "
            "ever scan the exact content being committed, not whatever else is on disk"
        ),
    ),
    "SECRETS_IGNORE_PATHS": DeprecatedFlag(
        name="SECRETS_IGNORE_PATHS",
        message=(
            "blocked commits print the ignore request command for findings "
            "that can be ignored (requires Code Consistent Ignores enabled "
            "for your org)"
        ),
    ),
    "SECRETS_DIFF_STRATEGY": DeprecatedFlag(
        name="SECRETS_DIFF_STRATEGY",
        message="the hook always compares against HEAD content now; there is no line-only mode",
    ),
    "SECRETS_MIN_BLOCK_SEVERITY": DeprecatedFlag(
        name="SECRETS_MIN_BLOCK_SEVERITY",
        message=(
            "severity filtering is no longer done on this machine; every finding "
            "blocks. Snyk's org-level Security Policies (see "
            "https://docs.snyk.io/scan-fix-and-prevent/prevent/policies/security-policies) "
            "cover Open Source and Container today, not Secrets yet"
        ),
    ),
}


def get_deprecated_flag_warnings() -> List[str]:
    """One warning line per registered flag still set in the environment
    (any value), in registration order."""
    warnings = []
    for name, flag in _DEPRECATED_FLAGS.items():
        if name in os.environ:
            warnings.append(f"{name} is no longer supported and has no effect -- {flag.message}")
    return warnings
