from __future__ import annotations

import difflib
import re
from typing import Any, Dict, List, Optional, Tuple


def diff_added_removed_lines(old_code: str, new_code: str) -> Tuple[List[str], List[str]]:
    added: List[str] = []
    removed: List[str] = []
    for line in difflib.ndiff((old_code or "").splitlines(), (new_code or "").splitlines()):
        if not line or len(line) < 2:
            continue
        tag = line[:2]
        text = line[2:].strip()
        if not text:
            continue
        if tag == "+ ":
            added.append(text)
        elif tag == "- ":
            removed.append(text)
    return added, removed


def added_lines(old_code: str, new_code: str) -> List[str]:
    added, _ = diff_added_removed_lines(old_code, new_code)
    return added


def removed_lines(old_code: str, new_code: str) -> List[str]:
    _, removed = diff_added_removed_lines(old_code, new_code)
    return removed


def extract_symbol_context_signals(
    symbol_context: Optional[Dict[str, Any]],
    language: Optional[str] = None,
) -> Dict[str, Any]:
    context = symbol_context if isinstance(symbol_context, dict) else {}
    innermost = context.get("innermost_symbol", {}) if isinstance(context.get("innermost_symbol"), dict) else {}
    symbols_raw = context.get("symbols", []) if isinstance(context.get("symbols"), list) else []
    symbols = [item for item in symbols_raw if isinstance(item, dict)]

    lang = str(language or context.get("language", "python")).lower()
    display = str(context.get("display", "")).strip()
    display_lower = display.lower()
    name = str(innermost.get("name", "")).strip()
    name_lower = name.lower()
    signature = str(innermost.get("signature", "")).strip()
    signature_lower = signature.lower()
    kind = str(innermost.get("kind", "")).strip()
    kind_lower = kind.lower()

    symbol_names = [str(item.get("name", "")).strip() for item in symbols if str(item.get("name", "")).strip()]
    symbol_names_lower = [item.lower() for item in symbol_names]
    parent_name_lower = symbol_names_lower[-2] if len(symbol_names_lower) >= 2 else ""

    entrypoint_names = {
        "python": {"__call__", "get", "post", "put", "delete", "dispatch", "handle", "run"},
        "java": {"doget", "dopost", "doput", "dodelete", "service", "handle", "run"},
        "php": {"__invoke", "get", "post", "put", "delete", "handle", "run"},
    }
    generic_entrypoint_names = {"execute", "process"}
    role_keywords = ("controller", "handler", "route", "router", "endpoint", "servlet", "action", "resource")

    context_hits: List[str] = []
    entrypoint_hits: List[str] = []
    attack_surface_flags: List[str] = []
    priority_boost = 0.0

    if name_lower in entrypoint_names.get(lang, set()) or name_lower in generic_entrypoint_names:
        entrypoint_hits.append(f"symbol_name:{name}")
        attack_surface_flags.append("entrypoint_like_symbol_context")
        priority_boost += 0.35

    role_hit = next(
        (
            keyword
            for keyword in role_keywords
            if keyword in display_lower or keyword in signature_lower or any(keyword in item for item in symbol_names_lower)
        ),
        "",
    )
    if role_hit:
        context_hits.append(f"symbol_role:{role_hit}")
        attack_surface_flags.append("handler_or_controller_context")
        priority_boost += 0.25

    is_constructor = bool(kind_lower == "constructor")
    if not is_constructor and lang == "java" and name_lower and parent_name_lower and name_lower == parent_name_lower:
        is_constructor = True
    is_magic_method = name_lower in {"__init__", "__call__", "__construct", "__invoke"}
    if is_constructor or is_magic_method:
        magic_label = name if is_magic_method and name else "constructor"
        context_hits.append(f"symbol_lifecycle:{magic_label}")
        attack_surface_flags.append("constructor_or_magic_method_context")
        priority_boost += 0.2

    if name_lower in {"__call__", "__invoke"}:
        entrypoint_hits.append(f"symbol_name:{name}")
        if "entrypoint_like_symbol_context" not in attack_surface_flags:
            attack_surface_flags.append("entrypoint_like_symbol_context")
            priority_boost += 0.15

    context_hits = list(dict.fromkeys([hit for hit in context_hits if hit]))
    entrypoint_hits = list(dict.fromkeys([hit for hit in entrypoint_hits if hit]))
    attack_surface_flags = list(dict.fromkeys([flag for flag in attack_surface_flags if flag]))
    if attack_surface_flags and not any(hit.startswith("symbol_display:") for hit in context_hits) and display:
        context_hits.insert(0, f"symbol_display:{display}")

    return {
        "display": display,
        "context_hits": context_hits[:5],
        "entrypoint_hits": entrypoint_hits[:5],
        "attack_surface_flags": attack_surface_flags[:5],
        "priority_boost": round(min(priority_boost, 0.8), 2),
    }


def decapitalize_identifier(name: str) -> str:
    text = str(name or "").strip()
    if not text:
        return ""
    if len(text) >= 2 and text[:2].isupper():
        return text
    return text[:1].lower() + text[1:]


def canonical_callable_stem(name: str) -> str:
    raw = str(name or "").strip()
    if not raw:
        return ""
    for prefix in ("get", "set", "is", "has"):
        if raw.startswith(prefix) and len(raw) > len(prefix) and raw[len(prefix)].isupper():
            return decapitalize_identifier(raw[len(prefix) :])
    return raw


def filter_attack_surface_entries(names: List[str], language: str = "python") -> List[str]:
    lang = str(language or "python").lower()
    raw_names = [str(name).strip() for name in names if str(name).strip()]
    if not raw_names:
        return []

    if lang != "java":
        return sorted(dict.fromkeys(raw_names))

    explicit_noise = {
        "builder",
        "build",
        "equals",
        "hashcode",
        "tostring",
        "canequal",
        "copy",
        "component1",
        "component2",
        "component3",
        "component4",
        "component5",
    }
    stem_counts: Dict[str, int] = {}
    lowered_to_stem: Dict[str, str] = {}
    for name in raw_names:
        stem = canonical_callable_stem(name)
        lowered_to_stem[name.lower()] = stem.lower()
        if stem:
            stem_counts[stem.lower()] = stem_counts.get(stem.lower(), 0) + 1

    filtered: List[str] = []
    seen = set()
    for name in raw_names:
        lowered = name.lower()
        if lowered in explicit_noise:
            continue
        stem_lower = lowered_to_stem.get(lowered, lowered)
        is_prefixed_accessor = bool(re.match(r"^(get|set|is|has)[A-Z]", name))
        is_fluent_accessor = lowered == stem_lower and stem_counts.get(stem_lower, 0) >= 2
        if is_prefixed_accessor or is_fluent_accessor:
            continue
        if lowered in seen:
            continue
        seen.add(lowered)
        filtered.append(name)
    return sorted(filtered)


def detect_added_scope(
    old_code: str,
    new_code: str,
    artifact: str,
    new_symbol_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    added = added_lines(old_code, new_code)
    added_text = "\n".join(added)
    symbol_language = ""
    if isinstance(new_symbol_context, dict):
        symbol_language = str(new_symbol_context.get("language", "")).strip().lower()
    inferred_language = symbol_language
    if not inferred_language:
        lowered_artifact = str(artifact or "").lower()
        if lowered_artifact.endswith(".java"):
            inferred_language = "java"
        elif lowered_artifact.endswith(".php"):
            inferred_language = "php"
        else:
            inferred_language = "python"

    symbol_signals = extract_symbol_context_signals(new_symbol_context, language=inferred_language)

    has_func = any(re.search(r"^\s*(def|function|public|private|protected)\s+", line) for line in added)
    has_type = any(re.search(r"^\s*(class|interface)\s+", line) for line in added)
    if has_func:
        scope_type = "函数逻辑变更"
    elif has_type:
        scope_type = "类型/类变更"
    elif added:
        scope_type = "代码片段变更"
    else:
        scope_type = "无新增"

    flags: List[str] = []
    endpoint_patterns = [
        r"@\s*(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\b",
        r"\bapp\.(get|post|put|delete|patch|route)\s*\(",
        r"\brouter\.(get|post|put|delete|patch)\s*\(",
        r"@app\.route\s*\(",
    ]
    if any(re.search(p, added_text, re.IGNORECASE) for p in endpoint_patterns):
        flags.append("new_http_endpoint")

    entry_patterns = [
        r"^\s*[\ufeff]*def\s+([A-Za-z_]\w*)\s*\(",
        r"^\s*[\ufeff]*function\s+([A-Za-z_]\w*)\s*\(",
        r"^\s*[\ufeff]*public\s+[\w<>\[\],\s]+\s+([A-Za-z_]\w*)\s*\(",
        r"^\s*[\ufeff]*private\s+[\w<>\[\],\s]+\s+([A-Za-z_]\w*)\s*\(",
        r"^\s*[\ufeff]*protected\s+[\w<>\[\],\s]+\s+([A-Za-z_]\w*)\s*\(",
    ]

    def _collect_entry_names(code: str) -> set[str]:
        names: set[str] = set()
        for line in (code or "").splitlines():
            for pattern in entry_patterns:
                match = re.search(pattern, line)
                if match:
                    names.add(match.group(1))
                    break
        return names

    old_entries = _collect_entry_names(old_code)
    new_entries = _collect_entry_names(new_code)
    truly_new_entries = filter_attack_surface_entries(sorted(new_entries - old_entries), language=inferred_language)
    if truly_new_entries:
        flags.append("new_callable_entry")

    dangerous_patterns = [
        r"\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder|exec\(|system\(|shell_exec\(|passthru\(|eval\()",
        r"\bSocket\s*\(|ServerSocket\s*\(|DatagramSocket\s*\(",
        r"\bDriverManager\.getConnection\s*\(",
    ]
    if any(re.search(p, added_text, re.IGNORECASE) for p in dangerous_patterns):
        flags.append("new_dangerous_capability")
    flags.extend(symbol_signals["attack_surface_flags"])
    flags = list(dict.fromkeys(flags))

    attack_surface_weights = {
        "new_dangerous_capability": 3,
        "new_http_endpoint": 2,
        "new_callable_entry": 1,
        "entrypoint_like_symbol_context": 1,
        "constructor_or_magic_method_context": 1,
        "handler_or_controller_context": 1,
    }
    score = sum(attack_surface_weights.get(flag, 0) for flag in flags)
    if score >= 3:
        attack_surface_level = "high"
    elif score >= 2:
        attack_surface_level = "medium"
    elif score >= 1:
        attack_surface_level = "low"
    else:
        attack_surface_level = "none"

    feature_signals: List[str] = []
    if has_type:
        feature_signals.append("new_type_or_class_declaration")
    if truly_new_entries:
        feature_signals.append("new_callable_entry")
    if "new_http_endpoint" in flags:
        feature_signals.append("new_http_entrypoint")
    if "entrypoint_like_symbol_context" in flags:
        feature_signals.append("entrypoint_like_symbol_context")
    if "constructor_or_magic_method_context" in flags:
        feature_signals.append("constructor_or_magic_method_context")
    if "handler_or_controller_context" in flags:
        feature_signals.append("handler_or_controller_context")
    if added:
        feature_signals.append("new_code_lines_added")
    feature_signals = list(dict.fromkeys(feature_signals))

    return {
        "scope_type": scope_type,
        "artifact": artifact,
        "added_line_count": len(added),
        "has_new_feature": bool(feature_signals),
        "feature_signals": feature_signals,
        "has_new_attack_surface": bool(flags),
        "attack_surface_flags": flags,
        "attack_surface_level": attack_surface_level,
        "new_callable_entries": truly_new_entries,
        "symbol_context_display": str(symbol_signals.get("display", "")),
        "symbol_context_hits": list(symbol_signals.get("context_hits", [])),
    }
