from __future__ import annotations

import difflib
from pathlib import Path
import re
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from source_diff_engine.logger_config import get_logger

logger = get_logger(__name__)


class SourcePreprocessor:
    SUPPORTED_LANGUAGES = {"python", "java", "php"}
    _FALLBACK_TEXT_ENCODINGS = ("gb18030", "latin-1")

    def __init__(self, language: str = "python"):
        self.language = self.normalize_language(language)

    @classmethod
    def normalize_language(cls, language: str) -> str:
        raw = (language or "").strip().lower()
        aliases = {
            "py": "python",
            "python3": "python",
            "java": "java",
            "php": "php",
            "auto": "python",
        }
        normalized = aliases.get(raw, raw)
        if normalized not in cls.SUPPORTED_LANGUAGES:
            supported = ", ".join(sorted(cls.SUPPORTED_LANGUAGES))
            raise ValueError(f"unsupported language '{language}', expected one of: {supported}")
        return normalized

    @staticmethod
    def infer_language_from_path(path: str) -> str:
        lowered = (path or "").lower()
        if lowered.endswith(".java"):
            return "java"
        if lowered.endswith(".php"):
            return "php"
        if lowered.endswith(".py"):
            return "python"
        raise ValueError(f"unsupported file extension for '{path}'; only .py, .java, and .php are supported")

    @classmethod
    def infer_language_from_paths(cls, old_path: str = "", new_path: str = "") -> str:
        candidates = [path for path in (old_path, new_path) if str(path or "").strip()]
        if not candidates:
            raise ValueError("cannot infer language without a source path")
        inferred = [cls.infer_language_from_path(path) for path in candidates]
        unique = sorted(set(inferred))
        if len(unique) > 1:
            raise ValueError(
                f"mismatched source languages inferred from paths: {old_path!r}, {new_path!r}; expected one of: .py, .java, .php"
            )
        return unique[0]

    def process_source_diff(self, old_source: str, new_source: str) -> Dict[str, Any]:
        diff_text, return_code, stderr_text, diff_read = self._run_git_diff(old_source, new_source)
        diff_units, old_units, new_units = self._parse_unified_diff(diff_text)
        source_read = self._attach_symbol_context(
            diff_units=diff_units,
            old_units=old_units,
            new_units=new_units,
            old_source=old_source,
            new_source=new_source,
        )
        diff_summary = self._summarize_diff_text(diff_text)
        zero_unit_reason = self._classify_zero_unit_reason(
            diff_text=diff_text,
            return_code=return_code,
            stderr_text=stderr_text,
            unit_count=len(diff_units),
        )
        return {
            "diff_units": diff_units,
            "old_units": old_units,
            "new_units": new_units,
            "diff_text": diff_text,
            "init_report": {
                "diff_engine": "git_diff_no_index",
                "old_source": old_source,
                "new_source": new_source,
                "diff_return_code": return_code,
                "stderr": (stderr_text or "").strip()[:500],
                "unit_count": len(diff_units),
                "hunk_count": diff_summary["hunk_count"],
                "added_line_count": diff_summary["added_line_count"],
                "deleted_line_count": diff_summary["deleted_line_count"],
                "file_kind": "binary" if diff_summary["is_binary"] else "text",
                "is_identical": zero_unit_reason == "identical",
                "zero_unit_reason": zero_unit_reason,
                "read_summary": self._build_read_summary(
                    old_source=source_read["old_source"],
                    new_source=source_read["new_source"],
                    diff_stdout=diff_read["stdout"],
                    diff_stderr=diff_read["stderr"],
                ),
            },
        }

    def _run_git_diff(self, old_source: str, new_source: str) -> Tuple[str, int, str, Dict[str, Dict[str, Any]]]:
        cmd = ["git", "diff", "--no-index", "--unified=3", "--", old_source, new_source]
        logger.debug("running diff command: %s", " ".join(cmd))
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=False,
            check=False,
        )
        stdout_decoded = self._decode_bytes(proc.stdout or b"", label="diff_stdout")
        stderr_decoded = self._decode_bytes(proc.stderr or b"", label="diff_stderr")
        if proc.returncode not in (0, 1):
            logger.error(
                "git diff failed returncode=%s old=%s new=%s stderr=%s",
                proc.returncode,
                old_source,
                new_source,
                stderr_decoded["text"].strip(),
            )
            raise RuntimeError(f"git diff failed: {stderr_decoded['text'].strip()}")
        return (
            stdout_decoded["text"],
            int(proc.returncode),
            stderr_decoded["text"],
            {
                "stdout": stdout_decoded["metadata"],
                "stderr": stderr_decoded["metadata"],
            },
        )

    @staticmethod
    def _summarize_diff_text(diff_text: str) -> Dict[str, Any]:
        hunk_count = 0
        added_line_count = 0
        deleted_line_count = 0
        is_binary = False
        for line in (diff_text or "").splitlines():
            if line.startswith("@@ "):
                hunk_count += 1
                continue
            if line.startswith("Binary files ") or line.startswith("GIT binary patch"):
                is_binary = True
                continue
            if line.startswith("+") and not line.startswith("+++"):
                added_line_count += 1
                continue
            if line.startswith("-") and not line.startswith("---"):
                deleted_line_count += 1
        return {
            "hunk_count": hunk_count,
            "added_line_count": added_line_count,
            "deleted_line_count": deleted_line_count,
            "is_binary": is_binary,
        }

    @staticmethod
    def _classify_zero_unit_reason(
        diff_text: str,
        return_code: int,
        stderr_text: str,
        unit_count: int,
    ) -> str:
        if int(unit_count) > 0:
            return ""
        lowered = (diff_text or "").lower()
        if "binary files " in lowered or "git binary patch" in lowered:
            return "binary"
        if int(return_code) == 0:
            return "identical"
        if (stderr_text or "").strip():
            return "error"
        if (diff_text or "").strip():
            return "parse_empty"
        return "empty"

    def _parse_unified_diff(
        self, diff_text: str
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
        lines = diff_text.splitlines()
        pairs: List[Dict[str, Any]] = []
        old_units: Dict[str, Dict[str, Any]] = {}
        new_units: Dict[str, Dict[str, Any]] = {}

        old_path = ""
        new_path = ""
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith("--- "):
                old_path = self._normalize_diff_path(line[4:])
                i += 1
                continue
            if line.startswith("+++ "):
                new_path = self._normalize_diff_path(line[4:])
                i += 1
                continue
            if not line.startswith("@@ "):
                i += 1
                continue

            header = line
            old_start, new_start = self._parse_hunk_header(header)
            i += 1
            old_chunk: List[str] = []
            new_chunk: List[str] = []
            old_focus_lines: List[int] = []
            new_focus_lines: List[int] = []
            old_line_no = old_start
            new_line_no = new_start
            while i < len(lines) and not lines[i].startswith("@@ ") and not lines[i].startswith("--- "):
                hline = lines[i]
                if hline.startswith("\\ No newline at end of file"):
                    i += 1
                    continue
                if hline.startswith(" "):
                    text = hline[1:]
                    old_chunk.append(text)
                    new_chunk.append(text)
                    old_line_no += 1
                    new_line_no += 1
                elif hline.startswith("-") and not hline.startswith("---"):
                    old_chunk.append(hline[1:])
                    old_focus_lines.append(old_line_no)
                    new_focus_lines.append(max(new_start, new_line_no - 1))
                    old_line_no += 1
                elif hline.startswith("+") and not hline.startswith("+++"):
                    new_chunk.append(hline[1:])
                    new_focus_lines.append(new_line_no)
                    old_focus_lines.append(max(old_start, old_line_no - 1))
                    new_line_no += 1
                i += 1

            if not old_chunk and not new_chunk:
                continue
            old_code = self._join_code_lines(old_chunk)
            new_code = self._join_code_lines(new_chunk)
            file_label = new_path or old_path or "unknown"
            similarity = difflib.SequenceMatcher(None, old_code, new_code).ratio() if (old_code or new_code) else 0.0
            old_end = old_line_no - 1 if old_chunk else old_start
            new_end = new_line_no - 1 if new_chunk else new_start
            old_focus_range = self._focus_range(old_focus_lines, old_start, old_end)
            new_focus_range = self._focus_range(new_focus_lines, new_start, new_end)

            if old_code and new_code:
                old_id = f"{old_path or file_label}:{old_start}"
                new_id = f"{new_path or file_label}:{new_start}"
                old_units[old_id] = {
                    "name": old_id,
                    "code": old_code,
                    "file_path": old_path,
                    "line_range": [old_start, old_end],
                    "focus_line_range": old_focus_range,
                }
                new_units[new_id] = {
                    "name": new_id,
                    "code": new_code,
                    "file_path": new_path,
                    "line_range": [new_start, new_end],
                    "focus_line_range": new_focus_range,
                }
                pairs.append(
                    {
                        "old_unit": old_id,
                        "new_unit": new_id,
                        "similarity": similarity,
                        "change_type": "modification",
                        "old_code": old_code,
                        "new_code": new_code,
                        "file_path": file_label,
                        "old_start": old_start,
                        "new_start": new_start,
                        "old_focus_line_range": old_focus_range,
                        "new_focus_line_range": new_focus_range,
                        "hunk_header": header,
                    }
                )
            elif old_code:
                old_id = f"{file_label}:{old_start}->removed"
                old_units[old_id] = {
                    "name": old_id,
                    "code": old_code,
                    "file_path": old_path,
                    "line_range": [old_start, old_end],
                    "focus_line_range": old_focus_range,
                }
                pairs.append(
                    {
                        "old_unit": old_id,
                        "new_unit": None,
                        "similarity": 0.0,
                        "change_type": "removed",
                        "old_code": old_code,
                        "new_code": "",
                        "file_path": file_label,
                        "old_start": old_start,
                        "new_start": 0,
                        "old_focus_line_range": old_focus_range,
                        "new_focus_line_range": [0, 0],
                        "hunk_header": header,
                    }
                )
            else:
                new_id = f"{file_label}:added->{new_start}"
                new_units[new_id] = {
                    "name": new_id,
                    "code": new_code,
                    "file_path": new_path,
                    "line_range": [new_start, new_end],
                    "focus_line_range": new_focus_range,
                }
                pairs.append(
                    {
                        "old_unit": None,
                        "new_unit": new_id,
                        "similarity": 0.0,
                        "change_type": "added",
                        "old_code": "",
                        "new_code": new_code,
                        "file_path": file_label,
                        "old_start": 0,
                        "new_start": new_start,
                        "old_focus_line_range": [0, 0],
                        "new_focus_line_range": new_focus_range,
                        "hunk_header": header,
                    }
                )
        logger.info("parsed %d diff units", len(pairs))
        return pairs, old_units, new_units

    def _attach_symbol_context(
        self,
        diff_units: List[Dict[str, Any]],
        old_units: Dict[str, Dict[str, Any]],
        new_units: Dict[str, Dict[str, Any]],
        old_source: str,
        new_source: str,
    ) -> Dict[str, Dict[str, Any]]:
        old_read = self.read_text_with_metadata(old_source)
        new_read = self.read_text_with_metadata(new_source)
        old_text = old_read["text"]
        new_text = new_read["text"]
        old_symbols = self._extract_symbols_from_source(old_text, self.language)
        new_symbols = self._extract_symbols_from_source(new_text, self.language)

        for unit in old_units.values():
            unit["symbol_context"] = self._build_symbol_context(old_symbols, unit.get("focus_line_range") or unit.get("line_range", [0, 0]))
            unit["symbol_context"]["language"] = self.language
        for unit in new_units.values():
            unit["symbol_context"] = self._build_symbol_context(new_symbols, unit.get("focus_line_range") or unit.get("line_range", [0, 0]))
            unit["symbol_context"]["language"] = self.language

        for unit in diff_units:
            old_ctx = {}
            new_ctx = {}
            if unit.get("old_unit") and unit["old_unit"] in old_units:
                old_ctx = dict(old_units[unit["old_unit"]].get("symbol_context", {}))
            if unit.get("new_unit") and unit["new_unit"] in new_units:
                new_ctx = dict(new_units[unit["new_unit"]].get("symbol_context", {}))
            unit["old_symbol_context"] = old_ctx
            unit["new_symbol_context"] = new_ctx
            unit["source_read_summary"] = self._build_read_summary(
                old_source=dict(old_read["metadata"]),
                new_source=dict(new_read["metadata"]),
                diff_stdout=self._empty_read_metadata(label="diff_stdout"),
                diff_stderr=self._empty_read_metadata(label="diff_stderr"),
            )
        return {
            "old_source": dict(old_read["metadata"]),
            "new_source": dict(new_read["metadata"]),
        }

    @staticmethod
    def _read_source_text(path: str) -> str:
        return SourcePreprocessor.read_text_with_metadata(path)["text"]

    @classmethod
    def read_text_with_metadata(cls, path: str) -> Dict[str, Any]:
        empty = cls._empty_read_metadata(label="source", path=path)
        if not path:
            empty["quality"] = "missing_path"
            empty["read_error"] = "missing_path"
            return {"text": "", "metadata": empty}
        try:
            payload = Path(path).read_bytes()
        except Exception as exc:
            meta = cls._empty_read_metadata(label="source", path=path)
            meta["quality"] = "read_error"
            meta["read_error"] = str(exc)
            return {"text": "", "metadata": meta}

        decoded = cls._decode_bytes(payload, label="source", path=path)
        return decoded

    @classmethod
    def strip_leading_bom(cls, text: str) -> str:
        if not text:
            return ""
        return str(text).lstrip("\ufeff")

    @classmethod
    def _decode_bytes(cls, payload: bytes, *, label: str, path: str = "") -> Dict[str, Any]:
        raw = bytes(payload or b"")
        meta = cls._empty_read_metadata(label=label, path=path)
        if not raw:
            meta["quality"] = "empty"
            return {"text": "", "metadata": meta}

        has_utf8_bom = raw.startswith(b"\xef\xbb\xbf")
        has_utf16_bom = raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff")
        candidates: List[Tuple[str, bool]] = []
        if has_utf8_bom:
            candidates.append(("utf-8-sig", False))
        elif has_utf16_bom:
            candidates.append(("utf-16", False))
        else:
            candidates.append(("utf-8", False))
        candidates.extend((encoding, True) for encoding in cls._FALLBACK_TEXT_ENCODINGS)

        last_error = ""
        for encoding, used_fallback in candidates:
            try:
                text = raw.decode(encoding)
            except UnicodeDecodeError as exc:
                last_error = f"{encoding}:{exc.reason}@{exc.start}"
                continue
            text = cls.strip_leading_bom(text)
            meta["encoding"] = "utf-8-sig" if encoding == "utf-8-sig" else encoding
            meta["used_fallback"] = bool(used_fallback)
            meta["bom_detected"] = bool(has_utf8_bom or has_utf16_bom)
            meta["quality"] = "fallback_decode" if used_fallback else "exact"
            return {"text": text, "metadata": meta}

        meta["quality"] = "read_error"
        meta["read_error"] = last_error or "decode_failed"
        return {"text": "", "metadata": meta}

    @staticmethod
    def _empty_read_metadata(*, label: str, path: str = "") -> Dict[str, Any]:
        return {
            "label": label,
            "path": path,
            "encoding": "",
            "used_fallback": False,
            "bom_detected": False,
            "quality": "unknown",
            "read_error": "",
        }

    @staticmethod
    def _build_read_summary(
        *,
        old_source: Dict[str, Any],
        new_source: Dict[str, Any],
        diff_stdout: Dict[str, Any],
        diff_stderr: Dict[str, Any],
    ) -> Dict[str, Any]:
        channels = {
            "old_source": dict(old_source),
            "new_source": dict(new_source),
            "diff_stdout": dict(diff_stdout),
            "diff_stderr": dict(diff_stderr),
        }
        decode_fallback_count = sum(1 for item in channels.values() if bool(item.get("used_fallback", False)))
        read_error_count = sum(1 for item in channels.values() if str(item.get("quality", "")) == "read_error")
        return {
            "channels": channels,
            "any_decode_fallback": decode_fallback_count > 0,
            "decode_fallback_count": decode_fallback_count,
            "read_error_count": read_error_count,
            "bom_detected": any(bool(item.get("bom_detected", False)) for item in channels.values()),
        }

    def _extract_symbols_from_source(self, source_text: str, language: str) -> List[Dict[str, Any]]:
        if not source_text:
            return []
        lang = (language or self.language or "python").lower()
        if lang == "python":
            return self._extract_python_symbols(source_text)
        return self._extract_brace_language_symbols(source_text, lang)

    @classmethod
    def _extract_python_symbols(cls, source_text: str) -> List[Dict[str, Any]]:
        lines = source_text.splitlines()
        stack: List[Dict[str, Any]] = []
        symbols: List[Dict[str, Any]] = []
        pattern = re.compile(r"^\s*(class|def|async\s+def)\s+([A-Za-z_][A-Za-z0-9_]*)\b")

        for lineno, raw_line in enumerate(lines, start=1):
            expanded = raw_line.expandtabs(4)
            stripped = expanded.strip()
            if not stripped or stripped.startswith("#"):
                continue

            indent = len(expanded) - len(expanded.lstrip(" "))
            while stack and indent <= int(stack[-1]["indent"]):
                closed = stack.pop()
                closed["end_line"] = max(int(closed["start_line"]), lineno - 1)

            match = pattern.match(expanded)
            if not match:
                continue

            token = match.group(1).replace(" ", "")
            kind = "class" if token == "class" else "function"
            signature = stripped.rstrip(":")
            stack.append(
                {
                    "kind": kind,
                    "name": match.group(2),
                    "signature": signature[:220],
                    "start_line": lineno,
                    "end_line": len(lines),
                    "indent": indent,
                }
            )
            symbols.append(stack[-1])

        for symbol in stack:
            symbol["end_line"] = max(int(symbol["start_line"]), len(lines))
        return [cls._finalize_symbol(symbol) for symbol in symbols]

    def _extract_brace_language_symbols(self, source_text: str, language: str) -> List[Dict[str, Any]]:
        lines = source_text.splitlines()
        brace_depth = 0
        pending: Optional[Dict[str, Any]] = None
        stack: List[Dict[str, Any]] = []
        symbols: List[Dict[str, Any]] = []

        for lineno, raw_line in enumerate(lines, start=1):
            stripped = raw_line.strip()

            if pending:
                pending["signature"] = self._merge_signature(str(pending.get("signature", "")), stripped)
                if "{" in raw_line:
                    stack.append(self._open_brace_symbol(pending, lineno, brace_depth + 1))
                    symbols.append(stack[-1])
                    pending = None
                elif ";" in raw_line:
                    pending = None

            matches = self._find_brace_language_symbols(raw_line, language)
            depth_cursor = brace_depth + sum(1 for item in stack if int(item["start_line"]) == lineno and int(item["body_depth"]) > brace_depth)
            for match in matches:
                if match["has_body"]:
                    depth_cursor += 1
                    stack.append(self._open_brace_symbol(match, lineno, depth_cursor))
                    symbols.append(stack[-1])
                else:
                    pending = match

            brace_depth += raw_line.count("{") - raw_line.count("}")
            while stack and brace_depth < int(stack[-1]["body_depth"]):
                closed = stack.pop()
                closed["end_line"] = max(int(closed["start_line"]), lineno)

        for symbol in stack:
            symbol["end_line"] = max(int(symbol["start_line"]), len(lines))
        return [self._finalize_symbol(symbol) for symbol in symbols]

    @staticmethod
    def _find_brace_language_symbols(raw_line: str, language: str) -> List[Dict[str, Any]]:
        line = raw_line.strip()
        if not line:
            return []

        patterns: List[Tuple[str, re.Pattern[str]]] = []
        if language == "java":
            patterns = [
                (
                    "class",
                    re.compile(
                        r"(?:^|[;{}])\s*(?:(?:public|private|protected|abstract|final|static)\s+)*(?:class|interface|enum)\s+([A-Za-z_][A-Za-z0-9_]*)\b"
                    ),
                ),
                (
                    "function",
                    re.compile(
                        r"(?:^|[;{}])\s*(?:(?:public|private|protected|static|final|synchronized|abstract|native|default|strictfp)\s+)*"
                        r"(?:<[^>]+>\s+)?(?:[\w\[\]<>?,]+\s+)+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*(?:throws\s+[\w\.,\s]+)?"
                    ),
                ),
                (
                    "function",
                    re.compile(
                        r"(?:^|[;{}])\s*(?:(?:public|private|protected)\s+)+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*(?:throws\s+[\w\.,\s]+)?"
                    ),
                ),
            ]
        elif language == "php":
            patterns = [
                ("class", re.compile(r"\b(?:class|interface|trait)\s+([A-Za-z_][A-Za-z0-9_]*)\b")),
                ("function", re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)")),
            ]
        else:
            return []

        matches: List[Dict[str, Any]] = []
        for kind, pattern in patterns:
            for hit in pattern.finditer(line):
                matched = hit.group(0).strip()
                has_body = "{" in line[hit.end() :]
                matches.append(
                    {
                        "kind": kind,
                        "name": hit.group(1),
                        "signature": re.sub(r"\s+", " ", matched)[:220],
                        "has_body": has_body,
                        "start_pos": hit.start(),
                    }
                )
        matches.sort(key=lambda item: int(item.get("start_pos", 0)))
        deduped: List[Dict[str, Any]] = []
        seen = set()
        for item in matches:
            key = (item["kind"], item["name"], item["start_pos"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped

    @staticmethod
    def _open_brace_symbol(symbol: Dict[str, Any], lineno: int, body_depth: int) -> Dict[str, Any]:
        return {
            "kind": str(symbol.get("kind", "function")),
            "name": str(symbol.get("name", "")),
            "signature": str(symbol.get("signature", ""))[:220],
            "start_line": lineno,
            "end_line": lineno,
            "body_depth": body_depth,
        }

    @staticmethod
    def _merge_signature(existing: str, fragment: str) -> str:
        parts = [str(existing or "").strip(), str(fragment or "").strip()]
        merged = " ".join([part for part in parts if part])
        return re.sub(r"\s+", " ", merged)[:220]

    @staticmethod
    def _finalize_symbol(symbol: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "kind": str(symbol.get("kind", "function")),
            "name": str(symbol.get("name", "")),
            "signature": str(symbol.get("signature", ""))[:220],
            "start_line": max(1, int(symbol.get("start_line", 1))),
            "end_line": max(int(symbol.get("start_line", 1)), int(symbol.get("end_line", symbol.get("start_line", 1)))),
        }

    @classmethod
    def _build_symbol_context(cls, symbols: List[Dict[str, Any]], line_range: Any) -> Dict[str, Any]:
        start_line, end_line = cls._normalize_line_range(line_range)
        if start_line <= 0 or end_line <= 0:
            return {"line_range": [start_line, end_line], "display": "", "symbols": [], "innermost_symbol": {}}

        containing = [
            symbol
            for symbol in symbols
            if int(symbol.get("start_line", 0)) <= start_line and int(symbol.get("end_line", 0)) >= end_line
        ]
        containing.sort(
            key=lambda symbol: (
                int(symbol.get("start_line", 0)),
                -int(symbol.get("end_line", 0)),
            )
        )
        formatted = [cls._symbol_view(symbol) for symbol in containing]
        display = ".".join(symbol["name"] for symbol in formatted if symbol.get("name"))
        innermost = dict(formatted[-1]) if formatted else {}
        return {
            "line_range": [start_line, end_line],
            "display": display,
            "symbols": formatted,
            "innermost_symbol": innermost,
        }

    @staticmethod
    def _normalize_line_range(line_range: Any) -> Tuple[int, int]:
        if not isinstance(line_range, list) or len(line_range) != 2:
            return 0, 0
        try:
            start_line = int(line_range[0])
            end_line = int(line_range[1])
        except Exception:
            return 0, 0
        if end_line < start_line:
            end_line = start_line
        return start_line, end_line

    @staticmethod
    def _symbol_view(symbol: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "kind": str(symbol.get("kind", "function")),
            "name": str(symbol.get("name", "")),
            "signature": str(symbol.get("signature", ""))[:220],
            "line_range": [
                max(1, int(symbol.get("start_line", 1))),
                max(int(symbol.get("start_line", 1)), int(symbol.get("end_line", symbol.get("start_line", 1)))),
            ],
        }

    @staticmethod
    def _normalize_diff_path(path_token: str) -> str:
        token = path_token.strip().strip('"')
        if token.startswith(("a/", "b/")):
            return token[2:]
        return token

    @staticmethod
    def _join_code_lines(lines: List[str]) -> str:
        if not lines:
            return ""
        joined = "\n".join(lines)
        return SourcePreprocessor.strip_leading_bom(joined)

    @staticmethod
    def _focus_range(focus_lines: List[int], default_start: int, default_end: int) -> List[int]:
        resolved = [int(line) for line in focus_lines if int(line) > 0]
        if resolved:
            return [min(resolved), max(resolved)]
        if default_start <= 0:
            return [0, 0]
        if default_end < default_start:
            default_end = default_start
        return [default_start, default_end]

    @staticmethod
    def _parse_hunk_header(header: str) -> Tuple[int, int]:
        m = re.match(r"@@\s+-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@", header)
        if not m:
            return 1, 1
        return int(m.group(1)), int(m.group(2))
