from __future__ import annotations

import re
from typing import Any, Dict, List


_SUSPICIOUS_HINTS = (
    "request",
    "input",
    "cmd",
    "command",
    "query",
    "sql",
    "path",
    "file",
    "filename",
    "token",
    "auth",
    "user",
    "payload",
)

_STRING_LITERAL_RE = re.compile(r"'([^'\\]{1,80})'|\"([^\"\\]{1,80})\"")


def _unique_limited(items: List[str], limit: int) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in items:
        text = str(item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= limit:
            break
    return out


def extract_called_symbols(code: str) -> List[str]:
    if not code:
        return []
    hits = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", code)
    return _unique_limited(sorted(hits), 30)


def extract_imports(code: str, language: str = "python") -> List[str]:
    if not code:
        return []
    lang = (language or "python").lower()
    if lang == "python":
        hits = re.findall(r"^\s*(?:from\s+([A-Za-z0-9_\.]+)\s+import|import\s+([A-Za-z0-9_\.]+))", code, re.MULTILINE)
        return _unique_limited([a or b for a, b in hits], 20)
    if lang == "java":
        hits = re.findall(r"^\s*import\s+([A-Za-z0-9_\.]+)", code, re.MULTILINE)
        return _unique_limited(hits, 20)
    hits = re.findall(r"^\s*(?:require|include|include_once|require_once)\s*\(?\s*[\"']([^\"']+)[\"']", code, re.MULTILINE)
    return _unique_limited(hits, 20)


def extract_declared_symbols(code: str, language: str = "python") -> List[str]:
    if not code:
        return []
    lang = (language or "python").lower()
    patterns = {
        "python": [
            r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
            r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(|:)",
        ],
        "java": [
            r"^\s*(?:public|private|protected)?\s*(?:static\s+)?(?:class|interface|enum)\s+([A-Za-z_][A-Za-z0-9_]*)",
            r"^\s*(?:public|private|protected)?\s*(?:static\s+)?[\w<>\[\],\s]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        ],
        "php": [
            r"^\s*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
            r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\b",
        ],
    }
    hits: List[str] = []
    for pattern in patterns.get(lang, patterns["python"]):
        hits.extend(re.findall(pattern, code, re.MULTILINE))
    return _unique_limited(hits, 20)


def extract_suspicious_identifiers(code: str) -> List[str]:
    if not code:
        return []
    identifiers = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", code)
    hits = [name for name in identifiers if any(hint in name.lower() for hint in _SUSPICIOUS_HINTS)]
    return _unique_limited(hits, 20)


def extract_string_literals(code: str) -> List[str]:
    if not code:
        return []
    values: List[str] = []
    for left, right in _STRING_LITERAL_RE.findall(code):
        text = left or right
        if text:
            values.append(text)
    return _unique_limited(values, 12)


def _normalize_symbol_context(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {"language": "", "line_range": [0, 0], "display": "", "symbols": [], "innermost_symbol": {}}
    line_range = value.get("line_range", [0, 0])
    if not isinstance(line_range, list) or len(line_range) != 2:
        line_range = [0, 0]
    symbols = value.get("symbols", [])
    if not isinstance(symbols, list):
        symbols = []
    innermost = value.get("innermost_symbol", {})
    if not isinstance(innermost, dict):
        innermost = {}
    return {
        "language": str(value.get("language", "") or ""),
        "line_range": [int(line_range[0] or 0), int(line_range[1] or 0)],
        "display": str(value.get("display", "") or ""),
        "symbols": symbols[:6],
        "innermost_symbol": innermost,
    }


def build_local_context(
    old_code: str,
    new_code: str,
    language: str = "python",
    artifact: str = "",
    old_symbol_context: Dict[str, Any] | None = None,
    new_symbol_context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    old_calls = extract_called_symbols(old_code)
    new_calls = extract_called_symbols(new_code)
    old_ctx = _normalize_symbol_context(old_symbol_context)
    new_ctx = _normalize_symbol_context(new_symbol_context)
    return {
        "language": (language or "python").lower(),
        "artifact": str(artifact or ""),
        "old_line_count": len((old_code or "").splitlines()),
        "new_line_count": len((new_code or "").splitlines()),
        "old_symbol_context": old_ctx,
        "new_symbol_context": new_ctx,
        "old_enclosing_symbol": str(old_ctx.get("display", "") or ""),
        "new_enclosing_symbol": str(new_ctx.get("display", "") or ""),
        "old_called_symbols": old_calls,
        "new_called_symbols": new_calls,
        "added_called_symbols": [x for x in new_calls if x not in old_calls][:12],
        "removed_called_symbols": [x for x in old_calls if x not in new_calls][:12],
        "old_imports": extract_imports(old_code, language=language),
        "new_imports": extract_imports(new_code, language=language),
        "declared_symbols": extract_declared_symbols(new_code or old_code, language=language),
        "suspicious_identifiers": extract_suspicious_identifiers(f"{old_code or ''}\n{new_code or ''}"),
        "string_literals": extract_string_literals(new_code or old_code),
    }
