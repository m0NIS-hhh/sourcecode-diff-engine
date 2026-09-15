# Scripts

These scripts are thin operational helpers around the project runtime. The primary interface is
`python main.py doctor|smoke|run ...`; `python -m source_diff_engine.main ...` is reserved for
internal and automation scenarios.

- `run_diff.py`: convenience wrapper for single-file or directory runs.
- `verify_run_consistency.py`: validates run-level and pair-level output counters.
- `run_high_risk_review_pass.py`: explicitly runs the optional high-risk review pass.
- `check_llm_connectivity.py`: checks configured LLM connectivity without changing analysis output.
- `test_llm_direct.py`: exercises a configured LLM endpoint for diagnostics.

All scripts default to `configs/config.example.json`, accept explicit configuration paths, and write UTF-8 JSON output. They must not be used to store credentials or local run artifacts in the repository.
