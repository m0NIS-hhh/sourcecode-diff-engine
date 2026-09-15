# Architecture

Source Diff Engine is a checkout-runnable Python project. Runtime code lives under `src/source_diff_engine`; the repository root contains configuration, documentation, scripts, tests, and the primary `main.py` launcher. Installation remains optional.

The main package boundaries are:

- `analysis/`: analysis profiles, domain scoring, and the top-level static pipeline.
- `pipeline/`: fix assessment, new-vulnerability checks, attack-surface checks, and result normalization.
- `preprocess/`: source reading, encoding metadata, git-style diff generation, diff units, and symbol context.
- `directory/`: manifests, filtering, concurrent execution, retries, checkpoints, resume, quality gates, and review queues.
- `llm/`: optional client and prompt construction. Static fallback remains authoritative.
- `output/`: schema 3.0, JSON/Markdown writers, and consistency validation.
- `app_service.py`: service orchestration for single-file, directory, doctor, smoke, and existing-run review.
- `main.py`: the standard CLI entry point.

The runtime flow is:

1. Resolve configuration, profile, language, and LLM mode.
2. Read old/new sources with UTF-8-first decoding and explicit fallback metadata.
3. Generate a unified diff and split it into hunk or file units.
4. Evaluate change intent, source/guard/sink evidence, attack-surface impact, and behavioral effects.
5. Optionally request LLM review without discarding static evidence.
6. Normalize unit, file, and run summaries into stable schema 3.0 artifacts.
7. For directory runs, persist checkpoints and quality information atomically.

The supported entrypoints have an explicit priority:

1. Daily project use: `python main.py doctor|smoke|run ...`.
2. Internal and automation use: `python -m source_diff_engine.main ...`.
3. Optional convenience command: `source-diff-engine ...`.

`scripts/` contains thin operational helpers; it does not define a second runtime package.
