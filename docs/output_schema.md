# Output Schema

`summary.json` is the stable, lightweight machine-readable entrypoint for LLM and automation consumers.

Stable top-level fields:

- `ok`: wrapper-level success when present
- `schema_version`: currently `3.0`
- `mode`: `single_file` or `directory`
- `analysis_profile`: selected profile
- `analysis_quality`: `valid`, `invalid`, `no_changes`, or `unknown`
- `llm_enabled`: whether LLM review was active
- `total_files_analyzed`
- `total_units`
- `failed_file_count`
- `skipped_file_count`
- `high_risk_unit_count`
- `quality_issues`
- `top_findings`
- `artifact_paths`

`risk_score` is an audit ordering score. It is not CVSS and is not a vulnerability confirmation score.

Evidence status values:

- `observed`
- `inferred`
- `partial`
- `not_applicable`
- `missing`

Artifact roles:

- `summary.json`: stable automation summary
- `summary.md`: human-readable review summary
- `detailed.json`: unit-level evidence and trace data
- `high_risk_index.json`: review queue ordered by risk
- `failed_pairs.json`: failed file-pair processing records

