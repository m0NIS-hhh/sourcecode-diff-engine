from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from source_diff_engine.analysis.pipeline import analyze_diff_units_in_memory
from source_diff_engine.analysis.profiles import DEFAULT_ANALYSIS_PROFILE, get_analysis_profile, normalize_analysis_profile, profile_llm_mode
from source_diff_engine.config_loader import DEFAULT_CONFIG_PATH, load_config
from source_diff_engine.directory.runner import run_directory_analysis as _run_directory_analysis_engine
from source_diff_engine.llm.client import LLMErrorInfo
from source_diff_engine.logger_config import get_logger
from source_diff_engine.output.schema import (
    SCHEMA_VERSION,
    build_run_meta,
    build_single_file_detailed,
    build_single_file_init_overview,
    build_single_file_overview,
    build_top_risky_file_entry,
)
from source_diff_engine.output.writer import (
    build_file_result_explanation,
    build_high_risk_index_entries,
    build_run_summary,
    build_run_summary_markdown,
    normalize_run_id,
    sanitize_rel_path,
    write_json_atomic,
    write_text_atomic,
)
from source_diff_engine.pipeline.results import normalize_evidence
from source_diff_engine.preprocess.source_preprocessor import SourcePreprocessor
from source_diff_engine.output.consistency import verify_run as _verify_run
from source_diff_engine.source_analyzer import SourceAnalyzer

logger = get_logger(__name__)
PROMPTS_FILE = Path(__file__).resolve().parent / "llm" / "prompts.yaml"


def _sanitize_llm_error_detail(detail: str, *, limit: int = 300) -> str:
    """Keep service-level fallback errors bounded and free of common credentials."""
    text = str(detail or "").strip()
    text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text)
    text = re.sub(r"(?i)(api[-_ ]?key|authorization|token)(\s*[:=]\s*)\S+", r"\1\2[REDACTED]", text)
    text = re.sub(r"sk-[A-Za-z0-9_-]{12,}", "sk-[REDACTED]", text)
    return text[:limit]


def resolve_path(base_dir: str, raw_path: str) -> str:
    return raw_path if os.path.isabs(raw_path) else os.path.join(base_dir, raw_path)


def resolve_output_root(raw_path: str) -> str:
    raw = str(raw_path or "").strip() or str(Path("artifacts") / "outputs")
    return str(Path(raw).resolve()) if os.path.isabs(raw) else str((Path.cwd() / raw).resolve())


def make_run_id(raw: str) -> str:
    normalized = normalize_run_id(raw)
    if normalized:
        return normalized
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def create_analyzer(llm_cfg: Dict[str, Any]) -> SourceAnalyzer:
    return SourceAnalyzer(
        model=str(llm_cfg.get("model", "")),
        base_url=str(llm_cfg.get("base_url", "")),
        api_key=str(llm_cfg.get("api_key", "")),
        prompts_file=str(PROMPTS_FILE),
        temperature=float(llm_cfg.get("temperature", 0.1)),
        timeout=int(llm_cfg.get("timeout", 60)),
        max_retries=int(llm_cfg.get("max_retries", 2)),
        max_tokens=int(llm_cfg.get("max_tokens", 4000)),
        api_style=str(llm_cfg.get("api_style", "auto")),
    )


def resolve_effective_llm_mode(
    *,
    llm_mode_override: str = "",
    configured_llm_mode: str = "",
    analysis_profile: str = DEFAULT_ANALYSIS_PROFILE,
) -> str:
    explicit = str(llm_mode_override or "").strip().lower()
    if explicit in {"off", "try", "required"}:
        return explicit

    configured = str(configured_llm_mode or "").strip().lower()
    if configured in {"off", "try", "required"}:
        return configured

    profile = get_analysis_profile(analysis_profile)
    mode = profile_llm_mode(profile)
    return mode if mode in {"off", "try", "required"} else "try"


def _check_writable_path(path: Path) -> Dict[str, Any]:
    target = Path(path)
    try:
        target.mkdir(parents=True, exist_ok=True)
        probe = target / f".doctor_write_probe_{os.getpid()}_{datetime.now().strftime('%H%M%S%f')}"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return {"ok": True, "path": str(target.resolve())}
    except Exception as exc:
        return {"ok": False, "path": str(target), "error": str(exc)}


def _check_git_available() -> Dict[str, Any]:
    git_path = shutil.which("git") or ""
    if not git_path:
        return {"ok": False, "path": "", "version": "", "error": "git not found on PATH"}
    try:
        completed = subprocess.run(
            ["git", "--version"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        version = (completed.stdout or completed.stderr or "").strip()
        return {"ok": True, "path": git_path, "version": version, "error": ""}
    except Exception as exc:
        return {"ok": False, "path": git_path, "version": "", "error": str(exc)}


def _build_smoke_fixture(input_root: Path) -> Dict[str, str]:
    old_path = input_root / "old.py"
    new_path = input_root / "new.py"
    old_path.write_text(
        "def format_name(name):\n"
        "    return name.strip()\n",
        encoding="utf-8",
    )
    new_path.write_text(
        "def format_name(name):\n"
        "    cleaned = name.strip()\n"
        "    return cleaned.lower()\n",
        encoding="utf-8",
    )
    return {"old_file": old_path.name, "new_file": new_path.name, "old_path": str(old_path), "new_path": str(new_path)}


def ensure_llm_ready(
    analyzer: SourceAnalyzer,
    *,
    llm_mode: str,
    skip_preflight: bool,
) -> Dict[str, Any]:
    mode = str(llm_mode or "try").strip().lower()
    if mode == "off":
        analyzer.llm.disable(reason="llm_mode_off")
        logger.info("llm disabled explicitly via llm_mode=off")
        return {
            "llm_mode": "off",
            "llm_enabled": False,
            "llm_preflight": "disabled_by_mode",
            "llm_fallback_reason": "llm_mode_off",
            "llm_error_category": "",
            "llm_skip_preflight": bool(skip_preflight),
        }

    if not bool(getattr(analyzer.llm, "enabled", False)):
        reason = "missing_api_key"
        logger.warning("llm disabled: missing API key; running in static-analysis mode")
        if mode == "required":
            raise RuntimeError("LLM required but no API key is configured")
        return {
            "llm_mode": mode,
            "llm_enabled": False,
            "llm_preflight": "skipped_no_api_key",
            "llm_fallback_reason": reason,
            "llm_error_category": reason,
            "llm_skip_preflight": bool(skip_preflight),
        }

    if bool(skip_preflight):
        return {
            "llm_mode": mode,
            "llm_enabled": True,
            "llm_preflight": "skipped_by_flag",
            "llm_fallback_reason": "",
            "llm_error_category": "",
            "llm_skip_preflight": True,
        }

    try:
        analyzer.llm.preflight()
        return {
            "llm_mode": mode,
            "llm_enabled": True,
            "llm_preflight": "ok",
            "llm_fallback_reason": "",
            "llm_error_category": "",
            "llm_skip_preflight": False,
        }
    except Exception as exc:
        err = getattr(analyzer.llm, "last_error_info", None)
        category = str(getattr(err, "category", "") or "unknown")
        if not isinstance(err, LLMErrorInfo):
            category = str(category or "unknown")
        sanitizer = getattr(analyzer.llm, "_sanitize_error_detail", None)
        if callable(sanitizer):
            safe_detail = str(sanitizer(str(exc)))
        else:
            safe_detail = _sanitize_llm_error_detail(str(exc))
        logger.error("llm preflight failed: category=%s detail=%s", category, safe_detail)
        if mode == "required":
            raise
        analyzer.llm.disable(reason=f"preflight_failed:{category}")
        return {
            "llm_mode": mode,
            "llm_enabled": False,
            "llm_preflight": "failed_fallback_static",
            "llm_fallback_reason": safe_detail,
            "llm_error_category": category,
            "llm_skip_preflight": False,
        }


def write_single_file_outputs(
    *,
    run_root: Path,
    rel_path: str,
    status: str,
    language: str,
    mem: Dict[str, Any],
    diff_text: str,
    llm_runtime: Dict[str, Any],
    analysis_profile: str = DEFAULT_ANALYSIS_PROFILE,
) -> Dict[str, Any]:
    pair_dir = run_root / "pairs" / sanitize_rel_path(rel_path)
    concise_rows = list(mem.get("concise_rows", []))
    detailed_doc = dict(mem.get("detailed_doc", {}))
    overview = dict(mem.get("overview", {}))
    units = list(detailed_doc.get("units", [])) if isinstance(detailed_doc.get("units", []), list) else []
    file_summary = dict(detailed_doc.get("file_summary", {})) if isinstance(detailed_doc.get("file_summary", {}), dict) else {}
    high_risk_index = build_high_risk_index_entries(
        rel_path=rel_path,
        status=status,
        language=language,
        concise_rows=concise_rows,
        units=units,
    )
    analysis_quality = "valid" if concise_rows else "no_changes"
    quality_issues = [] if concise_rows else ["no_diff_units_detected"]

    write_json_atomic(
        pair_dir / "summary.json",
        {
            "schema_version": SCHEMA_VERSION,
            "rel_path": rel_path,
            "status": status,
            "language": language,
            "unit_count": len(concise_rows),
            "overview": overview,
            "file_summary": file_summary,
            "analysis_profile": overview.get("analysis_profile", "generic"),
        },
    )
    write_json_atomic(pair_dir / "results.json", concise_rows)
    write_json_atomic(pair_dir / "units.json", units)
    if (diff_text or "").strip():
        write_text_atomic(pair_dir / "diff.patch", diff_text)

    primary_conclusion = file_summary.get("primary_conclusion", {}) if isinstance(file_summary.get("primary_conclusion"), dict) else {}
    primary_evidence = normalize_evidence(primary_conclusion.get("evidence", {}))
    top_risky_files = [
        build_top_risky_file_entry(
            rel_path=rel_path,
            language=language,
            status=status,
            risk_score=float(
                primary_conclusion.get(
                    "primary_score",
                    primary_conclusion.get("analysis_score", primary_conclusion.get("vulnerability_score", 0.0)),
                )
                or 0.0
            ),
            unit_count=len(concise_rows),
            vulnerability_type=str(primary_conclusion.get("vulnerability_type", "")),
            change_intent=str(primary_conclusion.get("change_intent", "")),
            security_impact=str(primary_conclusion.get("security_impact", "")),
            attack_surface_impact=str(primary_conclusion.get("attack_surface_impact", "")),
            review_required=bool(primary_conclusion.get("review_required", False)),
            evidence_status=str(primary_evidence.get("convenience_summary", {}).get("evidence_status", "")),
        )
    ]
    run_overview = build_single_file_overview(
        file_summary=file_summary,
        overview=overview,
        top_risky_files=top_risky_files,
        analysis_quality=analysis_quality,
        quality_issues=quality_issues,
        total_units=len(concise_rows),
        analysis_profile=normalize_analysis_profile(analysis_profile),
    )
    run_detailed = build_single_file_detailed(
        rel_path=rel_path,
        status=status,
        language=language,
        detail=detailed_doc,
        overview=overview,
    )
    init_overview = build_single_file_init_overview(
        rel_path=rel_path,
        status=status,
        unit_count=len(concise_rows),
        analysis_quality=analysis_quality,
        quality_issues=quality_issues,
        no_changes_only=not bool(concise_rows),
    )

    write_json_atomic(run_root / "results.json", concise_rows)
    write_json_atomic(run_root / "detailed.json", run_detailed)
    write_json_atomic(run_root / "overview.json", run_overview)
    write_json_atomic(run_root / "init_overview.json", init_overview)
    write_json_atomic(run_root / "failed_pairs.json", [])
    write_json_atomic(run_root / "high_risk_index.json", high_risk_index)
    summary = build_run_summary(
        mode="single_file",
        run_root=str(run_root.resolve()),
        llm_runtime=llm_runtime,
        overview=run_overview,
        top_risky_files=top_risky_files,
    )
    summary["file_result"] = build_file_result_explanation(file_summary)
    write_json_atomic(run_root / "summary.json", summary)
    write_text_atomic(run_root / "summary.md", build_run_summary_markdown(summary))
    return run_overview


def build_run_context(
    *,
    output_root: str,
    run_id: str,
    mode: str,
    llm_cfg: Dict[str, Any],
    llm_runtime: Dict[str, Any],
    extra_meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    run_root = Path(output_root) / run_id
    run_root.mkdir(parents=True, exist_ok=True)
    meta = build_run_meta(
        run_id=run_id,
        output_root=output_root,
        run_root=str(run_root.resolve()),
        mode=mode,
        llm_model=str(llm_cfg.get("model", "")),
        llm_api_style=str(llm_cfg.get("api_style", "")),
        llm_api_key_env=str(llm_cfg.get("api_key_env", "")),
        llm_runtime=llm_runtime,
        extra_fields=extra_meta,
    )
    write_json_atomic(run_root / "meta.json", meta)
    return {"run_root": run_root, "meta": meta}


def review_single_pair(
    *,
    analyzer: SourceAnalyzer,
    data_folder: str,
    old_file: str,
    new_file: str,
    language: str,
    run_root: Path,
    llm_runtime: Dict[str, Any],
    run_cfg: Dict[str, Any],
    analysis_profile: str = DEFAULT_ANALYSIS_PROFILE,
) -> Dict[str, Any]:
    old_source = resolve_path(data_folder, old_file)
    new_source = resolve_path(data_folder, new_file)
    if not os.path.isfile(old_source):
        raise FileNotFoundError(f"old file not found: {old_source}")
    if not os.path.isfile(new_source):
        raise FileNotFoundError(f"new file not found: {new_source}")

    resolved_language = (
        SourcePreprocessor.infer_language_from_paths(old_path=old_source, new_path=new_source)
        if str(language or "").strip().lower() == "auto"
        else SourcePreprocessor.normalize_language(language)
    )
    logger.info("resolved language=%s", resolved_language)

    preprocessor = SourcePreprocessor(language=resolved_language)
    pre_data = preprocessor.process_source_diff(old_source, new_source)
    min_similarity = float(run_cfg.get("min_similarity", 0.0))
    max_similarity = float(run_cfg.get("max_similarity", 1.0))
    filtered_units = [
        item
        for item in pre_data["diff_units"]
        if min_similarity <= float(item.get("similarity", 0.0)) <= max_similarity
        or item.get("change_type") in {"added", "removed"}
    ]
    logger.info("preprocessing done: %d units", len(filtered_units))

    mem = analyze_diff_units_in_memory(
        analyzer=analyzer,
        diff_units=filtered_units[: int(run_cfg.get("max_diff_units", 100))],
        language=resolved_language,
        git_diff_text=str(pre_data.get("diff_text", "")),
        analysis_profile=normalize_analysis_profile(analysis_profile),
    )
    llm_runtime["llm_request_count"] = int(getattr(getattr(analyzer, "llm", None), "request_count", 0) or 0)
    metrics = getattr(getattr(analyzer, "llm", None), "metrics", None)
    if callable(metrics):
        llm_runtime.update(
            {
                f"llm_{key}": value
                for key, value in metrics().items()
                if key != "request_count"
            }
        )
    llm_runtime["static_fallback_count"] = sum(
        1
        for row in mem.get("concise_rows", [])
        if str(row.get("analysis_backend", "static")).strip().lower() != "llm"
    )
    rel_path = Path(new_source).name
    overview = write_single_file_outputs(
        run_root=run_root,
        rel_path=rel_path,
        status="modified",
        language=resolved_language,
        mem=mem,
        diff_text=str(pre_data.get("diff_text", "")),
        llm_runtime=llm_runtime,
        analysis_profile=analysis_profile,
    )
    return {
        "concise_rows": list(mem.get("concise_rows", [])),
        "overview": overview,
        "run_root": str(run_root.resolve()),
        "language": resolved_language,
    }


def review_directory_diff(
    *,
    analyzer: SourceAnalyzer,
    data_folder: str,
    old_root: str,
    new_root: str,
    output_root: str,
    run_id: str,
    language: str,
    run_root: Path,
    llm_cfg: Dict[str, Any],
    llm_runtime: Dict[str, Any],
    max_units_per_file: int,
    max_files: int,
    workers: int,
    fail_fast: bool,
    retry_failed_files: int,
    checkpoint_file: str,
    resume: bool,
    min_total_units: int,
    max_zero_unit_ratio: float,
    fail_on_invalid_quality: bool,
    review_score_threshold: float,
    review_top_n: int,
    enable_llm_review_pass: bool,
    analysis_profile: str = DEFAULT_ANALYSIS_PROFILE,
    include_extensions: list[str] | None = None,
    exclude_dirs: list[str] | None = None,
    exclude_globs: list[str] | None = None,
    max_file_size_bytes: int = 1024 * 1024,
) -> Dict[str, Any]:
    old_root_path = resolve_path(data_folder, old_root)
    new_root_path = resolve_path(data_folder, new_root)
    if not os.path.isdir(old_root_path):
        raise FileNotFoundError(f"old root not found: {old_root_path}")
    if not os.path.isdir(new_root_path):
        raise FileNotFoundError(f"new root not found: {new_root_path}")

    return _run_directory_analysis_engine(
        analyzer=analyzer,
        old_root=old_root_path,
        new_root=new_root_path,
        output_root=output_root,
        run_id=run_id,
        language=language,
        max_units_per_file=max_units_per_file,
        max_files=max_files,
        workers=workers,
        fail_fast=fail_fast,
        retry_failed_files=retry_failed_files,
        checkpoint_file=checkpoint_file or str(run_root / "directory_checkpoint.json"),
        resume=resume,
        min_total_units=min_total_units,
        max_zero_unit_ratio=max_zero_unit_ratio,
        fail_on_invalid_quality=fail_on_invalid_quality,
        review_score_threshold=review_score_threshold,
        review_top_n=review_top_n,
        enable_llm_review_pass=enable_llm_review_pass,
        analysis_profile=normalize_analysis_profile(analysis_profile),
        include_extensions=include_extensions,
        exclude_dirs=exclude_dirs,
        exclude_globs=exclude_globs,
        max_file_size_bytes=max_file_size_bytes,
        meta_overrides={
            "llm_model": str(llm_cfg.get("model", "")),
            "llm_api_style": str(llm_cfg.get("api_style", "")),
            "llm_api_key_env": str(llm_cfg.get("api_key_env", "")),
            **llm_runtime,
        },
    )


def smoke(
    *,
    config_path: str = DEFAULT_CONFIG_PATH,
    output_root: str = str(Path("artifacts") / "outputs"),
    run_id: str = "",
    language: str = "auto",
    llm_mode: str = "",
    skip_llm_preflight: bool = False,
    analysis_profile: str = DEFAULT_ANALYSIS_PROFILE,
) -> Dict[str, Any]:
    try:
        cfg = load_config(config_path)
        llm_cfg = cfg["llm"]
        profile_name = normalize_analysis_profile(analysis_profile or cfg.get("analysis", {}).get("profile", DEFAULT_ANALYSIS_PROFILE))
        analyzer = create_analyzer(llm_cfg)
        llm_runtime = ensure_llm_ready(
            analyzer,
            llm_mode=resolve_effective_llm_mode(
                llm_mode_override=str(llm_mode or ""),
                configured_llm_mode=str(llm_cfg.get("mode", "")),
                analysis_profile=profile_name,
            ),
            skip_preflight=bool(skip_llm_preflight or llm_cfg.get("skip_preflight", False)),
        )
        llm_runtime["analysis_profile"] = profile_name
        resolved_output_root = resolve_output_root(output_root)
        resolved_run_id = make_run_id(run_id or "smoke")
        run_context = build_run_context(
            output_root=resolved_output_root,
            run_id=resolved_run_id,
            mode="single_file",
            llm_cfg=llm_cfg,
            llm_runtime=llm_runtime,
            extra_meta={"smoke": True, "analysis_profile": profile_name},
        )
        run_root = Path(run_context["run_root"])

        with tempfile.TemporaryDirectory(prefix="source_diff_engine_smoke_inputs_") as input_dir:
            input_root = Path(input_dir)
            sample = _build_smoke_fixture(input_root)
            result = review_single_pair(
                analyzer=analyzer,
                data_folder=str(input_root),
                old_file=sample["old_file"],
                new_file=sample["new_file"],
                language=language,
                run_root=run_root,
                llm_runtime=llm_runtime,
                run_cfg=cfg["run"],
                analysis_profile=profile_name,
            )

        summary = summarize_run(run_root)
        verification = verify_run(run_root)
        ok = bool(verification.get("ok", False)) and summary.get("analysis_quality") != "invalid"
        return {
            "ok": ok,
            "run_root": str(run_root.resolve()),
            "summary": summary,
            "verification": verification,
            "overview": result["overview"],
            "language": result["language"],
            "sample": sample,
            "llm_runtime": llm_runtime,
            "config_path": str(Path(config_path)),
        }
    except Exception as exc:
        logger.exception("smoke run failed")
        return {
            "ok": False,
            "error": str(exc),
            "run_root": "",
            "summary": {},
            "verification": {"ok": False, "issues": [str(exc)], "details": {}},
            "overview": {},
            "language": str(language or "auto"),
            "sample": {},
            "llm_runtime": {},
            "config_path": str(Path(config_path)),
        }


def doctor(
    *,
    config_path: str = DEFAULT_CONFIG_PATH,
    output_root: str = str(Path("artifacts") / "outputs"),
    smoke_output_root: str = "",
    llm_mode: str = "",
    skip_llm_preflight: bool = False,
    analysis_profile: str = DEFAULT_ANALYSIS_PROFILE,
) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "ok": True,
        "issues": [],
        "checks": {
            "python": {
                "version": platform.python_version(),
                "executable": sys.executable,
            },
            "git": _check_git_available(),
            "config_path": str(config_path),
            "output_root": str(resolve_output_root(output_root)),
            "analysis_profile": normalize_analysis_profile(analysis_profile),
        },
    }

    issues = report["issues"]
    if not report["checks"]["git"].get("ok", False):
        issues.append("git_unavailable")

    config: Dict[str, Any] | None = None
    try:
        config = load_config(config_path)
        report["checks"]["config"] = {
            "ok": True,
            "path": str(config_path),
            "llm_api_key_env": str(config["llm"].get("api_key_env", "")),
            "run": dict(config.get("run", {})),
        }
    except Exception as exc:
        report["checks"]["config"] = {"ok": False, "path": str(config_path), "error": str(exc)}
        issues.append(f"config_load_failed:{exc}")

    writable = _check_writable_path(Path(resolve_output_root(output_root)))
    report["checks"]["output_root_writable"] = writable
    if not writable.get("ok", False):
        issues.append(f"output_root_not_writable:{writable.get('error', 'unknown')}")

    llm_runtime: Dict[str, Any] = {}
    if config is not None:
        profile_name = normalize_analysis_profile(analysis_profile or config.get("analysis", {}).get("profile", DEFAULT_ANALYSIS_PROFILE))
        analyzer = create_analyzer(config["llm"])
        try:
            llm_runtime = ensure_llm_ready(
                analyzer,
                llm_mode=resolve_effective_llm_mode(
                    llm_mode_override=str(llm_mode or ""),
                    configured_llm_mode=str(config["llm"].get("mode", "")),
                    analysis_profile=profile_name,
                ),
                skip_preflight=bool(skip_llm_preflight or config["llm"].get("skip_preflight", False)),
            )
        except Exception as exc:
            llm_runtime = {
                "llm_mode": resolve_effective_llm_mode(
                    llm_mode_override=str(llm_mode or ""),
                    configured_llm_mode=str(config["llm"].get("mode", "")),
                    analysis_profile=profile_name,
                ),
                "llm_enabled": False,
                "llm_preflight": "required_failed",
                "llm_fallback_reason": str(exc),
                "llm_error_category": "required_failed",
                "llm_skip_preflight": bool(skip_llm_preflight or config["llm"].get("skip_preflight", False)),
            }
            issues.append(f"llm_preflight_failed:{exc}")
        llm_runtime["analysis_profile"] = profile_name
        report["checks"]["llm"] = llm_runtime

    smoke_output_root_resolved = smoke_output_root or tempfile.mkdtemp(prefix="source_diff_engine_doctor_smoke_")
    smoke_report = smoke(
        config_path=config_path,
        output_root=smoke_output_root_resolved,
        run_id="doctor_smoke",
        language="auto",
        llm_mode="off",
        skip_llm_preflight=True,
        analysis_profile=normalize_analysis_profile(analysis_profile),
    )
    report["checks"]["smoke"] = smoke_report
    if not smoke_report.get("ok", False):
        issues.append(f"smoke_failed:{smoke_report.get('error', 'unknown')}")

    report["ok"] = len(issues) == 0
    return report


def summarize_run(run_root: str | Path) -> Dict[str, Any]:
    root = Path(run_root)
    summary_path = root / "summary.json"
    if summary_path.exists():
        return json.loads(summary_path.read_text(encoding="utf-8"))

    overview_path = root / "overview.json"
    meta_path = root / "meta.json"
    if not overview_path.exists() or not meta_path.exists():
        raise FileNotFoundError(f"summary inputs missing under {root}")
    overview = json.loads(overview_path.read_text(encoding="utf-8"))
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    summary = build_run_summary(
        mode=str(meta.get("mode", "")),
        run_root=str(root.resolve()),
        llm_runtime=meta,
        overview=overview,
        top_risky_files=list(overview.get("top_risky_files", [])) if isinstance(overview.get("top_risky_files"), list) else [],
    )
    if str(meta.get("mode", "")) == "single_file":
        file_summary = overview.get("file_summary", {}) if isinstance(overview.get("file_summary"), dict) else {}
        summary["file_result"] = build_file_result_explanation(file_summary)
    return summary


def verify_run(run_root: str | Path) -> Dict[str, Any]:
    return _verify_run(Path(run_root))
