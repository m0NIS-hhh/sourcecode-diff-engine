# Source Code Diff Skill

This directory contains the Codex-facing skill wrapper and operating manual for Source Diff Engine.

## Run

```bash
python scripts/run_skill_diff.py --data-folder tests/fixtures/basic --old-file old.py --new-file new.py --language auto --profile security --llm-mode off
python scripts/run_skill_diff.py --data-folder . --old-root OLD_ROOT --new-root NEW_ROOT --language auto --profile security --llm-mode off
```

After installation:

```bash
source-diff-skill-run --data-folder tests/fixtures/basic --old-file old.py --new-file new.py --language auto --profile security --llm-mode off
```

Read `codex_summary.json` first. Use `summary.md` and `detailed.json` only when user-facing evidence detail is needed.
