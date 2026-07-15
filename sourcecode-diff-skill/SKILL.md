# Source Code Diff Skill

Use this skill to review source-code changes between old/new files or old/new directories. The skill produces structured audit evidence for security fixes, newly introduced vulnerability risk, and expanded attack surface.

This is an audit assistant. It does not prove exploitability. Treat high-risk results as review leads.

## Inputs

Provide exactly one input mode:

- Single file: `old_file` and `new_file`
- Directory: `old_root` and `new_root`

Also set:

- `language`: `auto`, `python`, `java`, or `php`
- `profile`: `generic`, `security`, `security-strict`, `api-surface`, or `behavior-review`
- `llm_mode`: `off`, `try`, or `required`

Defaults:

- `config`: `config.json.example`
- `output_root`: `artifacts/skill_runs`
- `profile`: `security`
- `language`: `auto`

## Standard Workflow

1. Run `doctor` if the environment is unknown:

   ```bash
   python main.py doctor --config config.json.example --llm-mode off
   ```

2. Prefer the wrapper for analysis because it writes `codex_summary.json` and verifies run consistency.

   Single file:

   ```bash
   python scripts/run_skill_diff.py --data-folder . --old-file OLD --new-file NEW --language auto --profile security --llm-mode off
   ```

   Directory:

   ```bash
   python scripts/run_skill_diff.py --data-folder . --old-root OLD_ROOT --new-root NEW_ROOT --language auto --profile security --llm-mode off --exclude-dir vendor --max-file-size-bytes 1048576
   ```

3. Read artifacts in this order:

   - `codex_summary.json` when the wrapper was used
   - `summary.json`
   - `summary.md`
   - `high_risk_index.json`
   - `failed_pairs.json`
   - `detailed.json` only when deeper evidence is needed

4. Report skipped and failed coverage:

   - Always mention `skipped_file_count`
   - Always mention `failed_file_count` or failed pairs
   - For directory runs, inspect `init_overview.json` or `overview.json` for skip reasons

## Reporting Rules

- Do not report `evidence_status=inferred` as confirmed.
- Do not treat a sink alone as a confirmed vulnerability.
- A high-risk item must include source, sink, and guard/guard absence evidence, or a clear manual-review reason.
- If `review_required=true`, say that manual review is required.
- `risk_score` is an audit ordering score, not CVSS and not proof of a vulnerability.
- Separate confirmed observations from inferred or partial chains.

## LLM Mode

- `off`: static analysis only
- `try`: use LLM review when configured and available, otherwise continue statically
- `required`: fail when LLM is unavailable

LLM results may add candidates or review notes. They must not erase static evidence.

