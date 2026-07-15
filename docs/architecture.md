# Architecture

Source Diff Engine is organized into three layers:

- `src/source_diff_engine`: analysis engine, CLI, output schema, preprocessing, directory runner, and LLM integration
- `sourcecode-diff-skill`: skill operating manual and wrapper entrypoint
- `tests`, `docs`, and `tests/fixtures`: regression coverage, documentation, and sample inputs

Core flow:

1. Build a git-style diff from old/new inputs.
2. Split changes into file or hunk units.
3. Classify change intent: security fix, non-security change, new code, removed code.
4. Evaluate new vulnerability candidates with source, sink, guard, and condition-chain evidence.
5. Evaluate attack-surface expansion from new files, routes, handlers, configuration, and exposed functions.
6. Normalize results into stable run-level and pair-level artifacts.

Static analysis is preferred. LLM review is optional and governed by `llm_mode`.

