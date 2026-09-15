# Roadmap

This roadmap describes improvements to the standalone Source Diff Engine. It intentionally focuses on analysis quality, runtime reliability, and stable output contracts.

## Current foundation

- Python, Java, and PHP single-file and directory diff analysis.
- Generic, security, security-strict, API-surface, and behavior-review profiles.
- Static fix assessment, new-vulnerability checks, attack-surface analysis, and evidence normalization.
- Optional LLM modes: `off`, `try`, and `required`, with static fallback.
- Directory manifests, filters, concurrency, retries, checkpoints, resume, quality gates, and high-risk review queues.
- JSON and Markdown output with schema version 3.0.
- Regression fixtures and consistency validation.

## Near-term priorities

1. Improve source/guard/sink evidence chains and make `observed`, `inferred`, `partial`, and `missing` states explicit.
2. Keep `summary.json`, `overview.json`, `detailed.json`, and high-risk artifacts backward compatible while centralizing field defaults and status values.
3. Expand regression fixtures for false positives, false negatives, multi-language parsing, and encoding edge cases.
4. Verify checkpoint atomicity, retry/resume determinism, concurrent output ordering, and failure categorization.
5. Record LLM request counts, failure classes, fallback reasons, and review-pass cost signals without exposing credentials.

## Longer-term work

- Add AST-backed symbol and call-flow extraction.
- Add carefully scoped cross-function and cross-file data-flow analysis.
- Improve framework-specific entry-point recognition for common Python, Java, and PHP stacks.
- Add incremental directory analysis and content-addressed caching.
- Extend CI with deterministic CLI, install, consistency, and regression-fixture jobs.

## Scope constraints

The system is an audit assistant. A sink match alone is not a confirmed vulnerability, risk scores are not CVSS, and LLM output cannot replace static evidence or human review.
