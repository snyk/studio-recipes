#!/usr/bin/env python3
"""Git hook integration dispatcher for Snyk Studio Recipes installer."""

import logging
import subprocess
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from git_hooks_impl.git_native import (
    ConfigBasedHookStrategy,
    FileShimStrategy,
    GlobalConfigBasedHookStrategy,
    _hook_config_section,
)
from git_hooks_impl.husky import HuskyStrategy
from git_hooks_impl.pre_commit import PreCommitFrameworkStrategy
from git_hooks_impl.types import (
    HookIntegrationKind,
    HookIntegrationSkipped,
    HookSpec,
    HookStrategy,
    HookVerification,
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

# No fallback below git 2.54 yet - see GlobalConfigBasedHookStrategy.
_GLOBAL_STRATEGY = GlobalConfigBasedHookStrategy()


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
    """Install *spec*, but only report success once ``is_installed``
    confirms git will actually execute it. Raises ``HookIntegrationSkipped``
    instead of returning success on a mismatch; the write itself is not
    rolled back.
    """
    selected = _select_strategy(workspace, HOOK_STRATEGIES)
    strategy, installed, path = _install_selected_strategy(
        workspace, spec, selected, HOOK_STRATEGIES
    )
    check = strategy.is_installed(workspace, spec)
    if not check.installed:
        detail = f": {check.reason}" if check.reason else ""
        action = (
            f"wrote {strategy.integration_kind} hook to {path}"
            if installed
            else f"found an existing {strategy.integration_kind} hook at {path}"
        )
        raise HookIntegrationSkipped(
            f"{action}, but cannot confirm git will actually execute it{detail}"
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


def verify_hook(workspace: Path, spec: HookSpec) -> HookVerification:
    selected = _select_strategy(workspace, HOOK_STRATEGIES)
    check = selected.is_installed(workspace, spec)
    if check.installed:
        return HookVerification(selected.integration_kind, True, check.path)
    # Check fallback-eligible siblings too; prefer one with a specific
    # reason over the selected strategy's bare "not installed".
    best_kind, best_check = selected.integration_kind, check
    for strategy in HOOK_STRATEGIES:
        if strategy is selected or not strategy.fallback_eligible:
            continue
        candidate = strategy.is_installed(workspace, spec)
        if candidate.installed:
            return HookVerification(strategy.integration_kind, True, candidate.path)
        if candidate.reason and not best_check.reason:
            best_kind, best_check = strategy.integration_kind, candidate
    return HookVerification(best_kind, False, best_check.path, best_check.reason)


def install_global_hook(spec: HookSpec) -> Tuple[HookIntegrationKind, bool, str]:
    """Install *spec* machine-wide; same contract as ``install_hook``."""
    if not _GLOBAL_STRATEGY.check_prerequisite():
        raise HookIntegrationSkipped(_GLOBAL_STRATEGY.unavailable_reason())
    installed, path = _GLOBAL_STRATEGY.install(spec)
    check = _GLOBAL_STRATEGY.is_installed(spec)
    if not check.installed:
        detail = f": {check.reason}" if check.reason else ""
        action = (
            f"wrote {_GLOBAL_STRATEGY.integration_kind} hook to {path}"
            if installed
            else f"found an existing {_GLOBAL_STRATEGY.integration_kind} hook at {path}"
        )
        raise HookIntegrationSkipped(
            f"{action}, but cannot confirm git will actually execute it{detail}"
        )
    return _GLOBAL_STRATEGY.integration_kind, installed, path


def uninstall_global_hook(spec: HookSpec) -> Tuple[HookIntegrationKind, bool, str]:
    removed, path = _GLOBAL_STRATEGY.safe_uninstall(spec)
    return _GLOBAL_STRATEGY.integration_kind, removed, path


def verify_global_hook(spec: HookSpec) -> HookVerification:
    if not _GLOBAL_STRATEGY.check_prerequisite():
        return HookVerification(
            _GLOBAL_STRATEGY.integration_kind, False, "", _GLOBAL_STRATEGY.unavailable_reason()
        )
    check = _GLOBAL_STRATEGY.is_installed(spec)
    return HookVerification(
        _GLOBAL_STRATEGY.integration_kind, check.installed, check.path, check.reason
    )


def global_hook_config_section(spec: HookSpec) -> str:
    """Git config section the global hook for *spec* would use (or does) -
    known ahead of install, unlike a local hook's strategy/path."""
    return str(_hook_config_section(spec))


def _active_local_strategy(workspace: Path, spec: HookSpec) -> Optional[HookStrategy]:
    """The strategy ``verify_hook`` would report as actually installed for
    *spec* right now, or ``None`` if nothing is. A stale fallback shim can be
    the real active strategy even when git >= 2.54 would prefer config-based
    for a fresh install - mirrors ``verify_hook``'s own selected-then-
    fallback-siblings order so both agree on what's really active."""
    selected = _select_strategy(workspace, HOOK_STRATEGIES)
    if selected.is_installed(workspace, spec).installed:
        return selected
    for strategy in HOOK_STRATEGIES:
        if strategy is selected or not strategy.fallback_eligible:
            continue
        if strategy.is_installed(workspace, spec).installed:
            return strategy
    return None


def local_install_shadows_global_for_free(workspace: Path, spec: HookSpec) -> bool:
    """Whether *spec*'s actually-active local install (if any) uses the same
    git-config-local strategy the global hook uses, so normal git config
    precedence (local wins) shadows it for free. Falls back to what a fresh
    install would pick when nothing is active yet."""
    active = _active_local_strategy(workspace, spec)
    if active is None:
        active = _select_strategy(workspace, HOOK_STRATEGIES)
    return active is _CONFIG_BASED_STRATEGY


def is_global_hook_active_for_tag(tag: str) -> bool:
    """Whether the global hook is active for *tag*, ignoring command -
    a local and global command are never byte-identical, so
    ``verify_global_hook``'s exact match can't answer this."""
    return bool(_GLOBAL_STRATEGY.check_prerequisite() and _GLOBAL_STRATEGY.is_tag_active(tag))


def local_install_double_fires_with_global(workspace: Path, spec: HookSpec) -> bool:
    """Whether *spec* installed locally would coexist with an active global
    hook of the same tag, rather than shadowing it."""
    if local_install_shadows_global_for_free(workspace, spec):
        return False
    return is_global_hook_active_for_tag(spec.tag)
