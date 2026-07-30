#!/usr/bin/env python3
"""Git hook integration dispatcher for Snyk Studio Recipes installer."""

import logging
import subprocess
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from git_hooks_impl.git_native import ConfigBasedHookStrategy, FileShimStrategy
from git_hooks_impl.husky import HuskyStrategy
from git_hooks_impl.pre_commit import PreCommitFrameworkStrategy
from git_hooks_impl.types import (
    HookIntegrationKind,
    HookIntegrationSkipped,  # noqa: F401
    HookSpec,
    HookStrategy,
    normalize_path,
)

logger = logging.getLogger(__name__)

_PRE_COMMIT_STRATEGY = PreCommitFrameworkStrategy()
_HUSKY_STRATEGY = HuskyStrategy()
_CONFIG_BASED_STRATEGY = ConfigBasedHookStrategy()
_FILE_SHIM_STRATEGY = FileShimStrategy()

HOOK_STRATEGIES: List[HookStrategy] = [
    _PRE_COMMIT_STRATEGY,
    _HUSKY_STRATEGY,
    _CONFIG_BASED_STRATEGY,
    _FILE_SHIM_STRATEGY,
]


def _select_strategy(workspace: Path, strategies: Sequence[HookStrategy]) -> HookStrategy:
    for strategy in strategies:
        if strategy.check_prerequisite(workspace):
            return strategy
    return _FILE_SHIM_STRATEGY


def _install_candidates(
    selected: HookStrategy, workspace: Path, strategies: Sequence[HookStrategy]
) -> List[HookStrategy]:
    if not selected.fallback_eligible:
        return [selected]

    candidates: List[HookStrategy] = []
    selected_seen = False
    for strategy in strategies:
        if not strategy.fallback_eligible:
            continue
        if strategy is selected:
            selected_seen = True
        if selected_seen and strategy.check_prerequisite(workspace):
            candidates.append(strategy)
    return candidates


def _exc_detail(exc: BaseException) -> str:
    stderr = getattr(exc, "stderr", None)
    if stderr:
        return f"{exc} - stderr: {stderr.strip()}"
    return str(exc)


def _same_path(left: Optional[Path], right: Optional[Path]) -> bool:
    if left is None or right is None:
        return False
    return bool(normalize_path(left) == normalize_path(right))


def _cleanup_stale_strategies(
    workspace: Path,
    spec: HookSpec,
    active: HookStrategy,
    strategies: Sequence[HookStrategy],
) -> Tuple[bool, str]:
    active_path = active.file_hook_path(workspace)
    removed_any = False
    last_path = ""
    for strategy in strategies:
        if strategy is active:
            continue
        if _same_path(strategy.file_hook_path(workspace), active_path):
            continue
        removed, path = strategy.safe_uninstall(workspace, spec)
        if removed:
            removed_any = True
        if path:
            last_path = path
    return removed_any, last_path


def _install_selected_strategy(
    workspace: Path,
    spec: HookSpec,
    selected: HookStrategy,
    strategies: Sequence[HookStrategy],
) -> Tuple[HookStrategy, bool, str]:
    last_error: Optional[Exception] = None
    for strategy in _install_candidates(selected, workspace, strategies):
        try:
            installed, path = strategy.install(workspace, spec)
        except (OSError, subprocess.SubprocessError) as exc:
            if not strategy.fallback_eligible:
                raise
            logger.warning(
                "%s install failed (%s); trying next strategy", strategy.name, _exc_detail(exc)
            )
            last_error = exc
            continue
        cleaned_stale, _ = _cleanup_stale_strategies(workspace, spec, strategy, strategies)
        return strategy, installed or cleaned_stale, path

    if last_error is not None:
        raise last_error
    raise RuntimeError("no hook strategy could be attempted")


def install_hook(workspace: Path, spec: HookSpec) -> Tuple[HookIntegrationKind, bool, str]:
    selected = _select_strategy(workspace, HOOK_STRATEGIES)
    strategy, installed, path = _install_selected_strategy(
        workspace, spec, selected, HOOK_STRATEGIES
    )
    return strategy.integration_kind, installed, path


def uninstall_hook(workspace: Path, spec: HookSpec) -> Tuple[HookIntegrationKind, bool, str]:
    primary = _select_strategy(workspace, HOOK_STRATEGIES).integration_kind
    removed_any = False
    primary_path = ""
    for strategy in HOOK_STRATEGIES:
        ok, path = strategy.safe_uninstall(workspace, spec)
        if ok:
            removed_any = True
            if strategy.integration_kind == primary:
                primary_path = path
    return primary, removed_any, primary_path


def verify_hook(workspace: Path, spec: HookSpec) -> Tuple[HookIntegrationKind, bool, str]:
    selected = _select_strategy(workspace, HOOK_STRATEGIES)
    ok, path = selected.is_installed(workspace, spec)
    if ok:
        return selected.integration_kind, True, path
    for strategy in HOOK_STRATEGIES:
        if strategy is selected or not strategy.fallback_eligible:
            continue
        ok, path = strategy.is_installed(workspace, spec)
        if ok:
            return strategy.integration_kind, True, path
    return selected.integration_kind, False, path
