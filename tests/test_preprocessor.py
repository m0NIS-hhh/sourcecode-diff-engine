from __future__ import annotations

from pathlib import Path

import pytest

from preprocessor import SourcePreprocessor


def test_preprocessor_extracts_diff_units(tmp_path: Path) -> None:
    root = tmp_path / "extract"
    root.mkdir(parents=True, exist_ok=True)
    old_file = root / "old.py"
    new_file = root / "new.py"
    old_file.write_text("def f(x):\n    return x\n", encoding="utf-8")
    new_file.write_text("def f(x):\n    if x > 100:\n        return 100\n    return x\n", encoding="utf-8")

    pre = SourcePreprocessor(language="python")
    data = pre.process_source_diff(str(old_file), str(new_file))
    assert len(data["diff_units"]) >= 1
    assert data["diff_units"][0]["change_type"] in {"modification", "added", "removed"}


def test_preprocessor_supports_java_and_php_language(tmp_path: Path) -> None:
    root = tmp_path / "multi_lang"
    root.mkdir(parents=True, exist_ok=True)

    java_old = root / "Old.java"
    java_new = root / "New.java"
    java_old.write_text("class A { String run(String x){ return x; } }", encoding="utf-8")
    java_new.write_text("class A { String run(String x){ if(x.length()>8){ return \"\"; } return x; } }", encoding="utf-8")
    java_data = SourcePreprocessor(language="java").process_source_diff(str(java_old), str(java_new))
    assert len(java_data["diff_units"]) >= 1

    php_old = root / "old.php"
    php_new = root / "new.php"
    php_old.write_text("<?php function run($x){ return $x; }", encoding="utf-8")
    php_new.write_text("<?php function run($x){ if(strlen($x)>8){ return ''; } return $x; }", encoding="utf-8")
    php_data = SourcePreprocessor(language="php").process_source_diff(str(php_old), str(php_new))
    assert len(php_data["diff_units"]) >= 1

    assert SourcePreprocessor.infer_language_from_path(str(java_new)) == "java"
    assert SourcePreprocessor.infer_language_from_path(str(php_new)) == "php"


def test_preprocessor_init_report_marks_identical_diff(tmp_path: Path) -> None:
    root = tmp_path / "identical"
    root.mkdir(parents=True, exist_ok=True)
    old_file = root / "old.py"
    new_file = root / "new.py"
    content = "def f(x):\n    return x\n"
    old_file.write_text(content, encoding="utf-8")
    new_file.write_text(content, encoding="utf-8")

    data = SourcePreprocessor(language="python").process_source_diff(str(old_file), str(new_file))
    report = data.get("init_report", {})
    assert isinstance(report, dict)
    assert report.get("unit_count") == 0
    assert report.get("is_identical") is True
    assert report.get("zero_unit_reason") == "identical"
    assert report.get("file_kind") in {"text", "binary"}
    assert report.get("read_summary", {}).get("decode_fallback_count") == 0
    assert report.get("read_summary", {}).get("read_error_count") == 0


def test_preprocessor_tracks_bom_and_decode_fallback(tmp_path: Path) -> None:
    root = tmp_path / "encoding"
    root.mkdir(parents=True, exist_ok=True)
    old_file = root / "old.py"
    new_file = root / "new.py"
    old_file.write_text("def run(value):\n    return value\n", encoding="utf-8")
    new_file.write_bytes("def run(value):\n    return '你好'\n".encode("gb18030"))

    data = SourcePreprocessor(language="python").process_source_diff(str(old_file), str(new_file))
    report = data["init_report"]["read_summary"]
    assert report["decode_fallback_count"] >= 1
    assert report["channels"]["new_source"]["used_fallback"] is True


def test_preprocessor_strips_bom_from_source_text_and_hunk_code(tmp_path: Path) -> None:
    root = tmp_path / "bom"
    root.mkdir(parents=True, exist_ok=True)
    old_file = root / "old.py"
    new_file = root / "new.py"
    old_file.write_text("def run(cmd):\n    return cmd\n", encoding="utf-8")
    new_file.write_bytes(b"\xef\xbb\xbfdef run(cmd):\n    if not cmd:\n        raise ValueError('bad')\n    return cmd\n")

    read_result = SourcePreprocessor.read_text_with_metadata(str(new_file))
    assert not read_result["text"].startswith("\ufeff")
    assert read_result["metadata"]["bom_detected"] is True

    data = SourcePreprocessor(language="python").process_source_diff(str(old_file), str(new_file))
    unit = data["diff_units"][0]
    assert not unit["new_code"].startswith("\ufeff")
    assert "\ufeff" not in unit["new_code"]


def test_preprocessor_keeps_hunk_context_in_old_and_new_code(tmp_path: Path) -> None:
    root = tmp_path / "hunk_context"
    root.mkdir(parents=True, exist_ok=True)
    old_file = root / "old.py"
    new_file = root / "new.py"
    old_file.write_text(
        "def run(cmd):\n"
        "    prefix = 'safe'\n"
        "    os.system(cmd)\n"
        "    return prefix\n",
        encoding="utf-8",
    )
    new_file.write_text(
        "def run(cmd):\n"
        "    prefix = 'safe'\n"
        "    if not cmd.startswith(prefix):\n"
        "        raise ValueError('bad')\n"
        "    os.system(cmd)\n"
        "    return prefix\n",
        encoding="utf-8",
    )

    data = SourcePreprocessor(language="python").process_source_diff(str(old_file), str(new_file))
    unit = data["diff_units"][0]
    assert "def run(cmd):" in unit["old_code"]
    assert "def run(cmd):" in unit["new_code"]
    assert "os.system(cmd)" in unit["old_code"]
    assert "os.system(cmd)" in unit["new_code"]
    assert "return prefix" in unit["old_code"]
    assert "return prefix" in unit["new_code"]


def test_preprocessor_attaches_python_symbol_context_to_hunk(tmp_path: Path) -> None:
    root = tmp_path / "python_symbols"
    root.mkdir(parents=True, exist_ok=True)
    old_file = root / "old.py"
    new_file = root / "new.py"
    old_file.write_text(
        "class Handler:\n"
        "    def run(self, cmd):\n"
        "        return cmd\n",
        encoding="utf-8",
    )
    new_file.write_text(
        "class Handler:\n"
        "    def run(self, cmd):\n"
        "        if not cmd.startswith('safe_'):\n"
        "            raise ValueError('bad')\n"
        "        return cmd\n",
        encoding="utf-8",
    )

    data = SourcePreprocessor(language="python").process_source_diff(str(old_file), str(new_file))
    unit = data["diff_units"][0]
    assert unit["old_unit"] is not None
    assert unit["new_unit"] is not None
    assert unit["new_symbol_context"]["display"] == "Handler.run"
    assert unit["new_symbol_context"]["innermost_symbol"]["name"] == "run"
    assert unit["new_symbol_context"]["symbols"][0]["name"] == "Handler"


def test_preprocessor_attaches_java_symbol_context_to_hunk(tmp_path: Path) -> None:
    root = tmp_path / "java_symbols"
    root.mkdir(parents=True, exist_ok=True)
    old_file = root / "Old.java"
    new_file = root / "New.java"
    old_file.write_text(
        "class Runner {\n"
        "    String run(String cmd) {\n"
        "        return cmd;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    new_file.write_text(
        "class Runner {\n"
        "    String run(String cmd) {\n"
        "        if (!cmd.startsWith(\"safe_\")) {\n"
        "            throw new IllegalArgumentException();\n"
        "        }\n"
        "        return cmd;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    data = SourcePreprocessor(language="java").process_source_diff(str(old_file), str(new_file))
    unit = data["diff_units"][0]
    assert unit["new_symbol_context"]["display"] == "Runner.run"
    assert unit["new_symbol_context"]["innermost_symbol"]["kind"] == "function"


def test_preprocessor_attaches_php_symbol_context_to_hunk(tmp_path: Path) -> None:
    root = tmp_path / "php_symbols"
    root.mkdir(parents=True, exist_ok=True)
    old_file = root / "old.php"
    new_file = root / "new.php"
    old_file.write_text(
        "<?php\n"
        "class Runner {\n"
        "    function run($cmd) {\n"
        "        return $cmd;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    new_file.write_text(
        "<?php\n"
        "class Runner {\n"
        "    function run($cmd) {\n"
        "        if (!preg_match('/^safe_/', $cmd)) {\n"
        "            throw new Exception('bad');\n"
        "        }\n"
        "        return $cmd;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    data = SourcePreprocessor(language="php").process_source_diff(str(old_file), str(new_file))
    unit = data["diff_units"][0]
    assert unit["new_symbol_context"]["display"] == "Runner.run"
    assert unit["new_symbol_context"]["innermost_symbol"]["name"] == "run"


def test_preprocessor_rejects_unsupported_file_extension() -> None:
    with pytest.raises(ValueError, match=r"only \.py, \.java, and \.php are supported"):
        SourcePreprocessor.infer_language_from_path("sample.txt")


def test_preprocessor_rejects_mismatched_file_languages() -> None:
    with pytest.raises(ValueError, match="mismatched source languages"):
        SourcePreprocessor.infer_language_from_paths(old_path="old.py", new_path="new.java")
