"""Secrets-finding type and SARIF parsing."""

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Mirrors SARIF's `suppression.status` enum, plus "none" for no suppression.
SuppressionStatus = Literal["none", "accepted", "underReview", "rejected"]


@dataclass(frozen=True)
class Finding:
    id: str = ""
    title: str = ""
    severity: str = ""
    cwe: Optional[str] = None
    file_path: str = ""
    start_line: int = 0
    start_column: int = 0
    end_line: int = 0
    end_column: int = 0
    # `snyk ignore create --finding-id=` -- absent on older CLI versions.
    finding_id: Optional[str] = None
    suppression: SuppressionStatus = "none"

    @property
    def is_ignored(self) -> bool:
        return self.suppression == "accepted"

    @property
    def is_under_review(self) -> bool:
        return self.suppression == "underReview"

    @property
    def is_rejected(self) -> bool:
        return self.suppression == "rejected"

    def __post_init__(self) -> None:
        # 0 is never a real line/column (both are 1-indexed), so it's safe
        # to treat as "not given" and default to the start -- keeps end >=
        # start a real invariant for every Finding, including ones built
        # directly (e.g. in tests) rather than via parse_secrets_results.
        if self.end_line == 0:
            object.__setattr__(self, "end_line", self.start_line)
        if self.end_column == 0:
            object.__setattr__(self, "end_column", self.start_column)


def _severity_from_priority_score(score: int) -> str:
    if score >= 700:
        return "critical"
    if score >= 500:
        return "high"
    if score >= 300:
        return "medium"
    return "low"


def _as_dict(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("expected object")
    return value


def _as_list(value: Any) -> List[Any]:
    if not isinstance(value, list):
        raise ValueError("expected list")
    return value


def _optional_object(parent: Dict[str, Any], key: str) -> Dict[str, Any]:
    return _as_dict(parent.get(key, {}))


def _optional_list(parent: Dict[str, Any], key: str) -> List[Any]:
    return _as_list(parent.get(key, []))


def _optional_string(parent: Dict[str, Any], key: str, default: str) -> str:
    value = parent.get(key, default)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    return value


def _optional_int(parent: Dict[str, Any], key: str, default: int = 0) -> int:
    value = parent.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    return value


def _severity_from_result(result: Dict[str, Any]) -> str:
    level = _optional_string(result, "level", "warning")
    severity = {"error": "high", "warning": "medium", "note": "low"}.get(level, "medium")

    properties = _optional_object(result, "properties")
    score = properties.get("priorityScore")
    if score is not None:
        if isinstance(score, bool) or not isinstance(score, int):
            raise ValueError("priorityScore must be an integer")
        severity = _severity_from_priority_score(score)
    return severity


def _cwe_from_result(result: Dict[str, Any]) -> Optional[str]:
    cwe_list = _optional_list(_optional_object(result, "properties"), "cwe")
    if not cwe_list:
        return None
    cwe = cwe_list[0]
    if not isinstance(cwe, str):
        raise ValueError("cwe entries must be strings")
    return cwe


def _title_from_rule_id(rule_id: str) -> str:
    return rule_id.replace("/", " - ").replace("_", " ").title()


def _finding_id_from_result(result: Dict[str, Any]) -> Optional[str]:
    """Reads the finding ID for `snyk ignore create --finding-id=` from
    `fingerprints["snyk/asset/finding/v1"]` (singular "asset" -- Snyk
    Code's own docs use the plural "assets" at the same key name for that
    product, so don't assume they match). An unexpected shape here
    degrades to "no ignore hint available" rather than aborting the whole
    scan over a hint-only field."""
    fingerprints = result.get("fingerprints")
    if not isinstance(fingerprints, dict):
        return None
    finding_id = fingerprints.get("snyk/asset/finding/v1")
    if not isinstance(finding_id, str):
        return None
    return finding_id


def _finding_from_location(
    location: Any,
    *,
    rule_id: str,
    severity: str,
    cwe: Optional[str],
    finding_id: Optional[str],
    suppression: SuppressionStatus,
) -> Finding:
    physical_location = _optional_object(_as_dict(location), "physicalLocation")
    artifact = _optional_object(physical_location, "artifactLocation")
    region = _optional_object(physical_location, "region")
    return Finding(
        id=rule_id,
        title=_title_from_rule_id(rule_id),
        severity=severity,
        cwe=cwe,
        file_path=_optional_string(artifact, "uri", "unknown"),
        start_line=_optional_int(region, "startLine"),
        start_column=_optional_int(region, "startColumn"),
        end_line=_optional_int(region, "endLine"),
        end_column=_optional_int(region, "endColumn"),
        finding_id=finding_id,
        suppression=suppression,
    )


# Highest-priority status wins if a result somehow carries more than one --
# matches Snyk's own GetHighestSuppression (go-application-framework).
_SUPPRESSION_PRIORITY: Dict[str, int] = {"accepted": 3, "underReview": 2, "rejected": 1}


def _suppression_status(result: Dict[str, Any]) -> SuppressionStatus:
    best: SuppressionStatus = "none"
    best_rank = 0
    for suppression in _optional_list(result, "suppressions"):
        if not isinstance(suppression, dict):
            continue
        status = suppression.get("status")
        if not isinstance(status, str):
            # SARIF 2.1's suppression.status defaults to "accepted" when absent.
            status = "accepted"
        rank = _SUPPRESSION_PRIORITY.get(status, 0)
        if rank > best_rank:
            best_rank = rank
            best = status  # type: ignore[assignment]
    return best


def _findings_from_result(result_value: Any) -> List[Finding]:
    result = _as_dict(result_value)
    rule_id = _optional_string(result, "ruleId", "unknown")
    severity = _severity_from_result(result)
    cwe = _cwe_from_result(result)
    finding_id = _finding_id_from_result(result)
    suppression = _suppression_status(result)
    return [
        _finding_from_location(
            location,
            rule_id=rule_id,
            severity=severity,
            cwe=cwe,
            finding_id=finding_id,
            suppression=suppression,
        )
        for location in _optional_list(result, "locations")
    ]


def _findings_from_run(run_value: Any) -> List[Finding]:
    findings: List[Finding] = []
    for result in _optional_list(_as_dict(run_value), "results"):
        findings.extend(_findings_from_result(result))
    return findings


def parse_secrets_results(json_output: str) -> Optional[List[Finding]]:
    """Parse `snyk secrets test --json` (SARIF) output into findings.
    Returns None if the output isn't valid, dict-shaped SARIF -- callers
    must treat that as a scan failure, not "zero findings", since either
    would otherwise look identical and the latter silently lets a commit
    through unscanned."""
    try:
        data = json.loads(json_output)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None

    findings: List[Finding] = []
    try:
        for run in _optional_list(data, "runs"):
            findings.extend(_findings_from_run(run))
    except (TypeError, ValueError):
        # Valid JSON, dict at the top level, but some nested shape wasn't
        # what SARIF promises (e.g. "runs" isn't a list of objects).
        return None
    return findings
