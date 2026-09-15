from __future__ import annotations

from source_diff_engine.analysis.tools import build_local_context


def test_build_local_context_exposes_richer_python_signals() -> None:
    old_code = "import os\n\ndef run(cmd):\n    return cmd\n"
    new_code = (
        "import os\nimport subprocess\n\n"
        "class Runner:\n"
        "    def run(self, cmd, user_input):\n"
        "        sql = user_input\n"
        "        return subprocess.run(sql)\n"
    )

    context = build_local_context(old_code, new_code, language="python", artifact="runner.py")
    assert context["language"] == "python"
    assert context["artifact"] == "runner.py"
    assert "subprocess" in context["new_imports"]
    assert "Runner" in context["declared_symbols"]
    assert "run" in context["added_called_symbols"] or "run" in context["new_called_symbols"]
    assert any(name in context["suspicious_identifiers"] for name in ("cmd", "user_input", "sql"))


def test_build_local_context_keeps_enclosing_symbol_hints() -> None:
    context = build_local_context(
        old_code="def run(cmd):\n    return cmd\n",
        new_code="def run(cmd):\n    os.system(cmd)\n",
        language="python",
        artifact="runner.py",
        old_symbol_context={
            "language": "python",
            "line_range": [1, 2],
            "display": "run",
            "symbols": [{"kind": "function", "name": "run", "signature": "def run(cmd)", "line_range": [1, 2]}],
            "innermost_symbol": {"kind": "function", "name": "run", "signature": "def run(cmd)", "line_range": [1, 2]},
        },
        new_symbol_context={
            "language": "python",
            "line_range": [1, 2],
            "display": "Runner.run",
            "symbols": [
                {"kind": "class", "name": "Runner", "signature": "class Runner", "line_range": [1, 3]},
                {"kind": "function", "name": "run", "signature": "def run(cmd)", "line_range": [2, 3]},
            ],
            "innermost_symbol": {"kind": "function", "name": "run", "signature": "def run(cmd)", "line_range": [2, 3]},
        },
    )

    assert context["old_enclosing_symbol"] == "run"
    assert context["new_enclosing_symbol"] == "Runner.run"
    assert context["new_symbol_context"]["innermost_symbol"]["name"] == "run"
