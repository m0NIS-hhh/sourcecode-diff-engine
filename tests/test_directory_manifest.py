from __future__ import annotations

from pathlib import Path

from source_diff_engine.directory.manifest import build_directory_pairs, build_file_manifest_with_skips


def test_manifest_records_skip_reasons(tmp_path: Path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    (root / "ok.py").write_text("x\n", encoding="utf-8")
    (root / "notes.txt").write_text("ignore\n", encoding="utf-8")
    (root / "big.py").write_text("x" * 20, encoding="utf-8")
    (root / "bin.py").write_bytes(b"abc\x00def")
    vendor = root / "vendor"
    vendor.mkdir()
    (vendor / "lib.py").write_text("print('vendor')\n", encoding="utf-8")

    manifest, skipped = build_file_manifest_with_skips(
        str(root),
        include_extensions={".py"},
        exclude_dirs={"vendor"},
        exclude_globs=set(),
        max_file_size_bytes=10,
        side="new",
    )

    assert sorted(manifest) == ["ok.py"]
    reasons = {item["rel_path"]: item["reason"] for item in skipped}
    assert reasons["notes.txt"] == "extension_not_included"
    assert reasons["big.py"] == "file_too_large"
    assert reasons["bin.py"] == "binary_file"
    assert reasons["vendor/lib.py"] == "excluded_dir"


def test_directory_pairs_exports_skipped_summary(tmp_path: Path) -> None:
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    (old / "a.py").write_text("old\n", encoding="utf-8")
    (new / "a.py").write_text("new\n", encoding="utf-8")
    (new / "package-lock.json").write_text("{}\n", encoding="utf-8")

    pairs = build_directory_pairs(
        str(old),
        str(new),
        include_extensions={".py", ".json"},
        exclude_globs={"*-lock.json"},
    )

    assert pairs["pair_count"] == 1
    assert pairs["skipped_file_count"] == 1
    assert pairs["skipped_by_reason"] == {"excluded_glob": 1}
