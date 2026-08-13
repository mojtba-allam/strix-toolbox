"""Filesystem tool tests."""

from __future__ import annotations

from pathlib import Path

from strix.toolbox.filesystem import list_files, project_info, read_file, search_code


def test_list_and_read(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("print(1)\n", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("secret\n", encoding="utf-8")
    info = project_info(tmp_path)
    assert info.success
    listed = list_files(root=tmp_path)
    assert listed.success
    paths = {item["path"] for item in listed.data["entries"]}
    assert "a.py" in paths
    read = read_file(root=tmp_path, path="a.py")
    assert read.success
    assert "print(1)" in read.data["content"]


def test_search_code(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("password = 'hunter2'\n", encoding="utf-8")
    result = search_code(root=tmp_path, pattern="password")
    assert result.success
    assert result.data["hits"]
    assert result.data["hits"][0]["line"] == 1


def test_path_escape_rejected(tmp_path: Path) -> None:
    result = read_file(root=tmp_path, path="../etc/passwd")
    assert result.success is False
    assert "escapes" in (result.error or "")
