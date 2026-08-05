import io
from pathlib import Path
from typing import Any, ClassVar, List, Optional, Tuple, cast

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.error import CommentMark
from ruamel.yaml.tokens import CommentToken
from ruamel.yaml.util import load_yaml_guess_indent

from .marked_files import (
    _normalize_existing,
    _read_hook_text_for_query,
    _read_hook_text_for_update,
    _write_hook_text_for_update,
)
from .types import (
    HookCheckResult,
    HookIntegrationKind,
    HookIntegrationSkipped,
    HookSpec,
    HookStrategy,
)

PRE_COMMIT_YAML_NAMES = (".pre-commit-config.yaml", ".pre-commit-config.yml")


def _precommit_yaml_path(workspace: Path) -> Optional[Path]:
    for name in PRE_COMMIT_YAML_NAMES:
        candidate = workspace / name
        if candidate.is_file():
            return candidate
    return None


def _new_yaml() -> YAML:
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.width = 4096
    return yaml


def _apply_guessed_indent(yaml: YAML, indent: Any, block_seq_indent: Any) -> None:
    if isinstance(indent, int) and isinstance(block_seq_indent, int):
        yaml.indent(mapping=indent, sequence=indent, offset=block_seq_indent)
    else:
        yaml.indent(mapping=2, sequence=2, offset=0)


def _dump_yaml_text(yaml: YAML, data: CommentedMap) -> str:
    stream = io.StringIO()
    yaml.dump(data, stream)
    text = stream.getvalue()
    return text if text.endswith("\n") else text + "\n"


def _ensure_repos_seq(data: CommentedMap) -> CommentedSeq:
    repos = data.get("repos")
    if repos is None:
        repos = CommentedSeq()
        data["repos"] = repos
    if not isinstance(repos, list):
        raise HookIntegrationSkipped(".pre-commit-config.yaml must contain a 'repos' sequence")
    if not isinstance(repos, CommentedSeq):
        repos = CommentedSeq(repos)
        data["repos"] = repos
    repos.fa.set_block_style()
    return repos


def _load_precommit_yaml_ruamel(yaml_path: Path) -> Tuple[str, YAML, CommentedMap]:
    raw_text = _normalize_existing(_read_hook_text_for_update(yaml_path, ".pre-commit-config.yaml"))
    yaml = _new_yaml()
    try:
        loaded, indent, block_seq_indent = load_yaml_guess_indent(raw_text, yaml=yaml)
    except Exception as exc:
        raise HookIntegrationSkipped(f"cannot safely parse .pre-commit-config.yaml: {exc}") from exc
    _apply_guessed_indent(yaml, indent, block_seq_indent)

    data = loaded
    if data is None:
        data = CommentedMap()
    if not isinstance(data, dict):
        raise HookIntegrationSkipped(".pre-commit-config.yaml must be a YAML mapping")
    if not isinstance(data, CommentedMap):
        data = CommentedMap(data)
    return raw_text, yaml, cast(CommentedMap, data)


def _new_precommit_repo_entry(spec: HookSpec) -> CommentedMap:
    stages = CommentedSeq(["pre-commit"])
    stages.fa.set_flow_style()

    hook = CommentedMap()
    hook["id"] = spec.tag
    hook["name"] = spec.name
    hook["entry"] = spec.command
    hook["language"] = "system"
    hook["pass_filenames"] = False
    hook["always_run"] = True
    hook["verbose"] = True
    hook["stages"] = stages

    hooks = CommentedSeq([hook])
    repo = CommentedMap()
    repo.yaml_set_start_comment(spec.begin_marker, indent=0)
    repo["repo"] = "local"
    repo["hooks"] = hooks
    repo.yaml_end_comment_extend([CommentToken(spec.end_marker + "\n", CommentMark(0))])
    return repo


def _ruamel_comment_marker_lines(value: Any, marker: str) -> List[int]:
    token_value = getattr(value, "value", None)
    if isinstance(token_value, str) and marker in token_value:
        line = getattr(getattr(value, "start_mark", None), "line", None)
        return [line] if isinstance(line, int) else []
    if isinstance(value, dict):
        return [
            line for item in value.values() for line in _ruamel_comment_marker_lines(item, marker)
        ]
    if isinstance(value, (list, tuple)):
        return [line for item in value for line in _ruamel_comment_marker_lines(item, marker)]
    return []


def _node_marker_lines(node: Any, marker: str) -> List[int]:
    comments = getattr(node, "ca", None)
    if comments is None:
        return []
    return (
        _ruamel_comment_marker_lines(comments.comment, marker)
        + _ruamel_comment_marker_lines(comments.items, marker)
        + _ruamel_comment_marker_lines(comments.end, marker)
    )


def _collect_marker_lines(node: Any, marker: str, seen: Optional[set[int]] = None) -> List[int]:
    if seen is None:
        seen = set()
    if id(node) in seen:
        return []
    seen.add(id(node))

    lines = _node_marker_lines(node, marker)
    if isinstance(node, dict):
        for value in node.values():
            lines.extend(_collect_marker_lines(value, marker, seen))
    elif isinstance(node, list):
        for value in node:
            lines.extend(_collect_marker_lines(value, marker, seen))
    return lines


def _marker_line_spans(begin_lines: List[int], end_lines: List[int]) -> List[Tuple[int, int]]:
    open_begin: Optional[int] = None
    spans: List[Tuple[int, int]] = []
    events = sorted(
        [(line, "begin") for line in set(begin_lines)] + [(line, "end") for line in set(end_lines)]
    )
    for line, kind in events:
        if kind == "begin":
            open_begin = line
        elif open_begin is not None and open_begin < line:
            spans.append((open_begin, line))
            open_begin = None
    return spans


def _comment_has_marker(value: Any, spec: HookSpec) -> bool:
    token_value = getattr(value, "value", None)
    return isinstance(token_value, str) and (
        spec.begin_marker in token_value or spec.end_marker in token_value
    )


def _empty_comment(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, (list, tuple)):
        return all(_empty_comment(item) for item in value)
    return False


def _clean_comment_tokens(value: Any, spec: HookSpec) -> Any:
    if value is None:
        return None
    if _comment_has_marker(value, spec):
        return None
    if isinstance(value, list):
        cleaned_items = [_clean_comment_tokens(item, spec) for item in value]
        return [item for item in cleaned_items if not _empty_comment(item)]
    if isinstance(value, tuple):
        cleaned_tuple = tuple(_clean_comment_tokens(item, spec) for item in value)
        return tuple(item for item in cleaned_tuple if not _empty_comment(item))
    return value


def _clean_positional_comment(value: Any, spec: HookSpec) -> Any:
    if not isinstance(value, list):
        return _clean_comment_tokens(value, spec)
    cleaned = [_clean_comment_tokens(item, spec) for item in value]
    return None if _empty_comment(cleaned) else cleaned


def _clear_managed_marker_comments(
    node: Any, spec: HookSpec, seen: Optional[set[int]] = None
) -> None:
    if seen is None:
        seen = set()
    if id(node) in seen:
        return
    seen.add(id(node))

    comments = getattr(node, "ca", None)
    if comments is not None:
        comments.comment = _clean_positional_comment(comments.comment, spec)
        comments.end = _clean_comment_tokens(comments.end, spec)
        for key, value in list(comments.items.items()):
            cleaned = _clean_positional_comment(value, spec)
            if _empty_comment(cleaned):
                del comments.items[key]
            else:
                comments.items[key] = cleaned

    if isinstance(node, dict):
        for value in node.values():
            _clear_managed_marker_comments(value, spec, seen)
    elif isinstance(node, list):
        for value in node:
            _clear_managed_marker_comments(value, spec, seen)


def _node_start_line(node: Any) -> Optional[int]:
    line = getattr(getattr(node, "lc", None), "line", None)
    return line if isinstance(line, int) else None


def _repo_in_marker_span(
    repo: Any,
    marker_spans: List[Tuple[int, int]],
) -> bool:
    repo_line = _node_start_line(repo)
    if repo_line is None:
        return False
    return any(begin_line < repo_line < end_line for begin_line, end_line in marker_spans)


def _managed_precommit_repo_indexes(repos: Any, spec: HookSpec) -> List[int]:
    if not isinstance(repos, list):
        return []
    begin_lines = _collect_marker_lines(repos, spec.begin_marker)
    end_lines = _collect_marker_lines(repos, spec.end_marker)
    marker_spans = _marker_line_spans(begin_lines, end_lines)
    return [index for index, repo in enumerate(repos) if _repo_in_marker_span(repo, marker_spans)]


def _managed_precommit_repos(repos: Any, spec: HookSpec) -> List[CommentedMap]:
    if not isinstance(repos, list):
        return []
    return [
        cast(CommentedMap, repos[index])
        for index in _managed_precommit_repo_indexes(repos, spec)
        if isinstance(repos[index], dict)
    ]


def _managed_precommit_hook(repo: Any, spec: HookSpec) -> Optional[CommentedMap]:
    if not isinstance(repo, dict):
        return None
    hooks = repo.get("hooks")
    if not isinstance(hooks, list):
        return None
    for hook in hooks:
        if isinstance(hook, dict) and hook.get("id") == spec.tag:
            return cast(CommentedMap, hook)
    return None


def _managed_precommit_hooks(repos: Any, spec: HookSpec) -> List[CommentedMap]:
    return [
        hook
        for repo in _managed_precommit_repos(repos, spec)
        for hook in [_managed_precommit_hook(repo, spec)]
        if hook is not None
    ]


def _precommit_hook_current(hook: CommentedMap, spec: HookSpec) -> bool:
    return bool(hook.get("name") == spec.name and hook.get("entry") == spec.command)


def _precommit_entry_present(data: CommentedMap, spec: HookSpec) -> bool:
    return any(
        _precommit_hook_current(hook, spec)
        for hook in _managed_precommit_hooks(data.get("repos"), spec)
    )


def _remove_managed_precommit_entries(
    data: CommentedMap,
    repos: CommentedSeq,
    spec: HookSpec,
) -> int:
    removed = 0
    for repo_index in reversed(_managed_precommit_repo_indexes(repos, spec)):
        del repos[repo_index]
        removed += 1
    if removed:
        _clear_managed_marker_comments(data, spec)
    return removed


def install_precommit_framework(workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
    yaml_path = _precommit_yaml_path(workspace)
    if yaml_path is None:
        raise FileNotFoundError(".pre-commit-config.yaml not found")

    original_text, yaml, data = _load_precommit_yaml_ruamel(yaml_path)
    repos = _ensure_repos_seq(data)
    managed_repos = _managed_precommit_repos(repos, spec)
    managed_hooks = [
        hook
        for repo in managed_repos
        for hook in [_managed_precommit_hook(repo, spec)]
        if hook is not None
    ]
    if (
        len(managed_repos) == 1
        and len(managed_hooks) == 1
        and _precommit_hook_current(managed_hooks[0], spec)
    ):
        return False, str(yaml_path)

    _remove_managed_precommit_entries(data, repos, spec)
    repos.append(_new_precommit_repo_entry(spec))
    final_text = _dump_yaml_text(yaml, data)
    _write_hook_text_for_update(yaml_path, final_text, ".pre-commit-config.yaml")
    return final_text != original_text, str(yaml_path)


def uninstall_precommit_framework(workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
    yaml_path = _precommit_yaml_path(workspace)
    if yaml_path is None or not yaml_path.is_file():
        return False, ""
    try:
        original_text, yaml, data = _load_precommit_yaml_ruamel(yaml_path)
        repos = _ensure_repos_seq(data)
        removed = _remove_managed_precommit_entries(data, repos, spec)
    except HookIntegrationSkipped:
        return False, str(yaml_path)
    if not removed:
        return False, str(yaml_path)
    final_text = _dump_yaml_text(yaml, data)
    if final_text != original_text:
        try:
            _write_hook_text_for_update(yaml_path, final_text, ".pre-commit-config.yaml")
        except HookIntegrationSkipped:
            return False, str(yaml_path)
    return True, str(yaml_path)


def verify_precommit_framework(workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
    yaml_path = _precommit_yaml_path(workspace)
    if yaml_path is None or not yaml_path.is_file():
        return False, ""
    if _read_hook_text_for_query(yaml_path) is None:
        return False, str(yaml_path)
    try:
        _original_text, _yaml, data = _load_precommit_yaml_ruamel(yaml_path)
    except HookIntegrationSkipped:
        return False, str(yaml_path)
    return _precommit_entry_present(data, spec), str(yaml_path)


class PreCommitFrameworkStrategy(HookStrategy):
    name = "pre-commit"
    integration_kind: ClassVar[HookIntegrationKind] = "pre-commit"

    def check_prerequisite(self, workspace: Path) -> bool:
        return _precommit_yaml_path(workspace) is not None

    def install(self, workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
        return install_precommit_framework(workspace, spec)

    def is_installed(self, workspace: Path, spec: HookSpec) -> HookCheckResult:
        ok, path = verify_precommit_framework(workspace, spec)
        return HookCheckResult(ok, path)

    def safe_uninstall(self, workspace: Path, spec: HookSpec) -> Tuple[bool, str]:
        return uninstall_precommit_framework(workspace, spec)

    def file_hook_path(self, workspace: Path) -> Optional[Path]:
        return _precommit_yaml_path(workspace)
