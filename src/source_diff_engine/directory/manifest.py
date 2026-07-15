from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


DEFAULT_TEXT_EXTENSIONS: Set[str] = {
    ".py",
    ".php",
    ".java",
}
DEFAULT_EXCLUDE_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "vendor",
}
DEFAULT_EXCLUDE_GLOBS: Set[str] = {
    "*.class",
    "*.jar",
    "*.lock",
    "*.min.js",
    "*.min.css",
    "*.pyc",
    "*.war",
    "*generated*",
}
DEFAULT_MAX_FILE_SIZE_BYTES = 1024 * 1024


def _normalize_rel_path(path: Path) -> str:
    return str(path).replace("\\", "/")


def _is_binary_file(path: Path, sample_size: int = 4096) -> bool:
    try:
        chunk = path.read_bytes()[:sample_size]
    except OSError:
        return False
    return b"\x00" in chunk


def _skip_reason(
    file_path: Path,
    rel_path: str,
    *,
    allow_extensions: Set[str],
    exclude_dirs: Set[str],
    exclude_globs: Set[str],
    max_file_size_bytes: int,
) -> str:
    rel_parts = {part.lower() for part in Path(rel_path).parts}
    if exclude_dirs and rel_parts.intersection(exclude_dirs):
        return "excluded_dir"
    rel_norm = rel_path.replace("\\", "/")
    name = file_path.name
    if any(fnmatch(rel_norm, pattern) or fnmatch(name, pattern) for pattern in exclude_globs):
        return "excluded_glob"
    if allow_extensions and file_path.suffix.lower() not in allow_extensions:
        return "extension_not_included"
    try:
        size = file_path.stat().st_size
    except OSError:
        return "stat_error"
    if max_file_size_bytes > 0 and size > max_file_size_bytes:
        return "file_too_large"
    if _is_binary_file(file_path):
        return "binary_file"
    return ""


def _append_skip(skipped: List[Dict[str, Any]], *, rel_path: str, side: str, reason: str, path: Path) -> None:
    skipped.append(
        {
            "rel_path": str(rel_path),
            "side": str(side),
            "reason": str(reason),
            "path": str(path),
        }
    )


def build_file_manifest(
    root: str,
    include_extensions: Optional[Set[str]] = None,
    exclude_dirs: Optional[Set[str]] = None,
    exclude_globs: Optional[Set[str]] = None,
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
    side: str = "",
) -> Dict[str, str]:
    manifest, _ = build_file_manifest_with_skips(
        root,
        include_extensions=include_extensions,
        exclude_dirs=exclude_dirs,
        exclude_globs=exclude_globs,
        max_file_size_bytes=max_file_size_bytes,
        side=side,
    )
    return manifest


def build_file_manifest_with_skips(
    root: str,
    include_extensions: Optional[Set[str]] = None,
    exclude_dirs: Optional[Set[str]] = None,
    exclude_globs: Optional[Set[str]] = None,
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
    side: str = "",
) -> Tuple[Dict[str, str], List[Dict[str, Any]]]:
    base = Path(root).resolve()
    allow = {x.lower() for x in (include_extensions or DEFAULT_TEXT_EXTENSIONS)}
    excluded_dirs = {x.lower() for x in (exclude_dirs or DEFAULT_EXCLUDE_DIRS)}
    excluded_globs = set(exclude_globs or DEFAULT_EXCLUDE_GLOBS)
    manifest: Dict[str, str] = {}
    skipped: List[Dict[str, Any]] = []
    if not base.exists():
        return manifest, skipped

    for file_path in base.rglob("*"):
        if not file_path.is_file():
            continue
        rel = _normalize_rel_path(file_path.relative_to(base))
        reason = _skip_reason(
            file_path,
            rel,
            allow_extensions=allow,
            exclude_dirs=excluded_dirs,
            exclude_globs=excluded_globs,
            max_file_size_bytes=max_file_size_bytes,
        )
        if reason:
            _append_skip(skipped, rel_path=rel, side=side, reason=reason, path=file_path)
            continue
        manifest[rel] = str(file_path)
    return manifest, skipped


def pair_manifests(old_manifest: Dict[str, str], new_manifest: Dict[str, str]) -> List[Dict[str, Optional[str]]]:
    all_rel_paths = sorted(set(old_manifest.keys()) | set(new_manifest.keys()))
    pairs: List[Dict[str, Optional[str]]] = []
    for rel in all_rel_paths:
        old_path = old_manifest.get(rel)
        new_path = new_manifest.get(rel)
        if old_path and new_path:
            status = "modified"
        elif old_path:
            status = "removed"
        else:
            status = "added"
        pairs.append(
            {
                "rel_path": rel,
                "status": status,
                "old_path": old_path,
                "new_path": new_path,
            }
        )
    return pairs


def build_directory_pairs(
    old_root: str,
    new_root: str,
    include_extensions: Optional[Set[str]] = None,
    exclude_dirs: Optional[Set[str]] = None,
    exclude_globs: Optional[Set[str]] = None,
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
) -> Dict[str, object]:
    old_manifest, old_skipped = build_file_manifest_with_skips(
        old_root,
        include_extensions=include_extensions,
        exclude_dirs=exclude_dirs,
        exclude_globs=exclude_globs,
        max_file_size_bytes=max_file_size_bytes,
        side="old",
    )
    new_manifest, new_skipped = build_file_manifest_with_skips(
        new_root,
        include_extensions=include_extensions,
        exclude_dirs=exclude_dirs,
        exclude_globs=exclude_globs,
        max_file_size_bytes=max_file_size_bytes,
        side="new",
    )
    pairs = pair_manifests(old_manifest, new_manifest)
    skipped_files = old_skipped + new_skipped
    skipped_by_reason: Dict[str, int] = {}
    for item in skipped_files:
        reason = str(item.get("reason", "unknown"))
        skipped_by_reason[reason] = skipped_by_reason.get(reason, 0) + 1
    return {
        "old_root": str(Path(old_root).resolve()),
        "new_root": str(Path(new_root).resolve()),
        "old_file_count": len(old_manifest),
        "new_file_count": len(new_manifest),
        "pair_count": len(pairs),
        "skipped_file_count": len(skipped_files),
        "skipped_files": skipped_files,
        "skipped_by_reason": skipped_by_reason,
        "pairs": pairs,
    }
