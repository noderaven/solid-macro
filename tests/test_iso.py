"""Tests for delivery/iso/build_iso.py."""

import io
import sys
from pathlib import Path

import pytest

pycdlib = pytest.importorskip("pycdlib")

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "delivery" / "iso"))

import build_iso  # noqa: E402


def test_to_iso_name_basic():
    assert build_iso._to_iso_name("report.docm") == "REPORT.DOC;1"


def test_to_iso_name_no_extension():
    assert build_iso._to_iso_name("README") == "README;1"


def test_to_iso_name_truncates_to_8_3():
    assert build_iso._to_iso_name("verylongfilename.extension") == "VERYLONG.EXT;1"


def test_build_creates_file(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hello")
    out = tmp_path / "out.iso"
    rc = build_iso.main([str(f), "--out", str(out), "--label", "TEST"])
    assert rc == 0
    assert out.exists()
    assert out.stat().st_size > 0


def test_build_root_level_file_roundtrips(tmp_path):
    f = tmp_path / "report.txt"
    f.write_text("hello world")
    out = tmp_path / "out.iso"
    build_iso.main([str(f), "--out", str(out)])

    iso = pycdlib.PyCdlib()
    iso.open(str(out))
    buf = io.BytesIO()
    iso.get_file_from_iso_fp(buf, joliet_path="/report.txt")
    iso.close()
    assert buf.getvalue().decode("utf-8") == "hello world"


def test_build_preserves_subdirectory(tmp_path, monkeypatch):
    sub = tmp_path / "data"
    sub.mkdir()
    f = sub / "doc.txt"
    f.write_text("subdir content")
    out = tmp_path / "out.iso"
    monkeypatch.chdir(tmp_path)
    rc = build_iso.main(["data/doc.txt", "--out", str(out)])
    assert rc == 0
    iso = pycdlib.PyCdlib()
    iso.open(str(out))
    buf = io.BytesIO()
    iso.get_file_from_iso_fp(buf, joliet_path="/data/doc.txt")
    iso.close()
    assert buf.getvalue().decode("utf-8") == "subdir content"


def test_build_missing_file_fails(tmp_path, capsys):
    rc = build_iso.main([str(tmp_path / "nope.bin"), "--out", str(tmp_path / "o.iso")])
    assert rc == 1
    assert "not found" in capsys.readouterr().err
