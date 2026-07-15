# Known Limitations

Source Diff Engine is not an automatic vulnerability proof system.

Limitations:

- Static rules can miss framework-specific dataflow.
- A sink match without source and guard context is not enough to confirm a vulnerability.
- `evidence_status=inferred` means the finding needs manual validation.
- LLM review can improve triage notes but may still be incomplete or wrong.
- Directory runs can skip files by extension, path filter, size, binary detection, or read errors.
- `risk_score` is for audit prioritization, not CVSS.

Use high-risk output as a review queue. Confirm exploitability with code-level evidence, reachable entrypoints, guard analysis, and runtime context.

