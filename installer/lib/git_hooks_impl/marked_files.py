import os
import re
import stat
from pathlib import Path
from typing import Optional, Tuple

from .types import HookIntegrationSkipped, HookSpec, MarkedFilePolicy


def _self_propagating_block(command: str) -> str:
    """Wraps `command` in a brace group so its exit status always
    propagates -- a trailing comment in `command` can't reach `|| exit
    $?` on the line after."""
    return f"{{\n{command}\n}} || exit $?"


def _wrap_block(spec: HookSpec, body: str) -> str:
    """Return *body* sandwiched between this spec's begin/end markers."""
    return f"{spec.begin_marker}\n{body.rstrip()}\n{spec.end_marker}\n"


def _strip_block(text: str, spec: HookSpec) -> str:
    """Remove well-formed marker-delimited blocks belonging to *spec* from *text*.

    The inner ``(?:(?!BEGIN).)*?`` is a "tempered" non-greedy match: it
    consumes any character that is NOT the start of another begin marker.
    The whole pattern therefore matches only a begin/end pair with NO
    intervening begin marker between them. If a file is corrupted into
    BEGIN..BEGIN..END (e.g. an orphan begin left behind by a failed manual
    edit), a plain ``.*?`` would match from the first BEGIN to the END and
    silently delete the orphan begin plus every line between it and the
    closing end - destroying user configuration. The tempered version
    refuses to match at all in that case and leaves the malformed region
    intact so the user can see and fix it.

    Tolerates trailing newlines and CRLF line endings; collapses any
    chain of three or more newlines down to two so the file stays tidy on
    repeated install/uninstall cycles.
    """
    begin = re.escape(spec.begin_marker)
    end = re.escape(spec.end_marker)
    pattern = re.compile(
        rf"(?:\r?\n)?{begin}(?:(?!{begin}).)*?{end}(?:\r?\n)?",
        re.DOTALL,
    )
    cleaned = pattern.sub("\n", text)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned


def _read_hook_text_for_update(
    path: Path, label: str, missing_default: Optional[str] = None
) -> str:
    """Read an existing file, or return ``missing_default`` when allowed."""
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        if missing_default is not None:
            return missing_default
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise HookIntegrationSkipped(f"cannot safely read {label}: {exc}") from exc


def _read_hook_text_for_query(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError, UnicodeDecodeError):
        return None


def _write_lf_text(path: Path, text: str) -> None:
    # Keep shell hook files LF-only on Windows so brace-group syntax stays valid.
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _write_hook_text_for_update(path: Path, text: str, label: str) -> None:
    try:
        _write_lf_text(path, text)
    except OSError as exc:
        raise HookIntegrationSkipped(f"cannot safely update {label}: {exc}") from exc


def _missing_marked_file_result(path: Optional[Path], policy: MarkedFilePolicy) -> Tuple[bool, str]:
    if path is not None and policy.report_path_when_missing:
        return False, str(path)
    return False, ""


def _verify_marked_file(
    path: Optional[Path],
    spec: HookSpec,
    policy: MarkedFilePolicy,
) -> Tuple[bool, str]:
    if path is None or not path.is_file():
        return _missing_marked_file_result(path, policy)
    text = _read_hook_text_for_query(path)
    if text is None:
        return False, str(path)
    return (
        spec.begin_marker in text and spec.end_marker in text and spec.command in text,
        str(path),
    )


def _install_marked_file(
    path: Optional[Path],
    spec: HookSpec,
    body: str,
    policy: MarkedFilePolicy,
) -> Tuple[bool, str]:
    if path is None or (policy.require_existing and not path.is_file()):
        raise FileNotFoundError(policy.missing_error)
    if policy.create_parent:
        try:
            _ensure_parent(path)
        except OSError as exc:
            raise HookIntegrationSkipped(f"cannot safely prepare {policy.label}: {exc}") from exc

    existing = _read_hook_text_for_update(
        path, policy.label, missing_default="" if not policy.require_existing else None
    )
    if not existing and policy.seed_when_empty:
        existing = policy.seed_when_empty
    existing = _normalize_existing(existing)
    block = _wrap_block(spec, body)
    if block.strip() in existing:
        if policy.chmod_on_noop:
            _chmod_executable(path)
        return False, str(path)

    cleaned = _strip_block(existing, spec)
    if not cleaned.endswith("\n"):
        cleaned += "\n"
    _write_hook_text_for_update(path, cleaned + block, policy.label)
    if policy.chmod_after_write:
        _chmod_executable(path)
    return True, str(path)


def _uninstall_marked_file(
    path: Optional[Path],
    spec: HookSpec,
    policy: MarkedFilePolicy,
) -> Tuple[bool, str]:
    if path is None or not path.is_file():
        return _missing_marked_file_result(path, policy)
    text = _read_hook_text_for_query(path)
    if text is None or spec.begin_marker not in text:
        return False, str(path)

    cleaned = _strip_block(text, spec)
    if cleaned.strip() in policy.delete_when_cleaned_is:
        try:
            path.unlink()
        except OSError:
            return False, str(path)
    else:
        try:
            _write_lf_text(path, cleaned)
        except OSError:
            return False, str(path)
    return True, str(path)


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _chmod_executable(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        mode = path.stat().st_mode
        path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass


def _normalize_existing(text: str) -> str:
    if not text:
        return ""
    if not text.endswith("\n"):
        text += "\n"
    return text
