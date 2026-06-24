"""Tests for macro/build/assemble.py."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "macro" / "build"))

import assemble  # noqa: E402


def write_module(macro_dir: Path, name: str, body: str) -> None:
    (macro_dir / f"{name}.bas").write_text(body, encoding="utf-8")


def minimal(name: str) -> str:
    return f"Option Explicit\n\nPublic Sub {name}Stub()\nEnd Sub\n"


def setup_fixture(macro_dir: Path) -> None:
    for m in assemble.MODULE_ORDER:
        write_module(macro_dir, m, minimal(m))


def test_check_clean_fixture_passes(tmp_path, capsys):
    setup_fixture(tmp_path)
    rc = assemble.run_check(tmp_path, assemble.MODULE_ORDER, debug=False)
    assert rc == 0
    assert "OK" in capsys.readouterr().out


def test_check_missing_module_fails(tmp_path, capsys):
    setup_fixture(tmp_path)
    (tmp_path / "Strings.bas").unlink()
    rc = assemble.run_check(tmp_path, assemble.MODULE_ORDER, debug=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "Strings.bas" in err and "not found" in err


def test_check_sub_end_mismatch_fails(tmp_path, capsys):
    setup_fixture(tmp_path)
    write_module(tmp_path, "Strings",
                 "Public Sub A()\nEnd Sub\nPublic Sub B()\n")
    rc = assemble.run_check(tmp_path, assemble.MODULE_ORDER, debug=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert "Strings" in err and "open count" in err


def test_check_flat_sensitive_literal_fails(tmp_path, capsys):
    setup_fixture(tmp_path)
    write_module(tmp_path, "Strings",
                 'Public Sub Bad()\n    Dim s As String\n    s = "VirtualAllocEx"\nEnd Sub\n')
    rc = assemble.run_check(tmp_path, assemble.MODULE_ORDER, debug=False)
    assert rc == 1
    assert "VirtualAllocEx" in capsys.readouterr().err


def test_check_ignores_sensitive_in_comments(tmp_path):
    setup_fixture(tmp_path)
    write_module(tmp_path, "Strings",
                 "' Note: replaces VirtualAllocEx with syscall\nPublic Sub A()\nEnd Sub\n")
    rc = assemble.run_check(tmp_path, assemble.MODULE_ORDER, debug=False)
    assert rc == 0


def test_check_orphan_continuation_at_eof_fails(tmp_path, capsys):
    setup_fixture(tmp_path)
    write_module(tmp_path, "Strings",
                 'Public Sub A()\n    Dim s As String\n    s = "abc" & _\n')
    rc = assemble.run_check(tmp_path, assemble.MODULE_ORDER, debug=False)
    assert rc == 1
    assert "continuation" in capsys.readouterr().err.lower()


def test_build_emits_per_module_files(tmp_path):
    macro_dir = tmp_path / "macro"
    out_dir = tmp_path / "out"
    macro_dir.mkdir()
    for m in assemble.MODULE_ORDER:
        write_module(macro_dir, m, minimal(m))
    rc = assemble.run_build(macro_dir, out_dir, assemble.MODULE_ORDER, debug=False, flatten=False)
    assert rc == 0
    for m in assemble.MODULE_ORDER:
        out_file = out_dir / f"{m}.bas"
        assert out_file.exists()
        assert f'Attribute VB_Name = "{m}"' in out_file.read_text(encoding="utf-8")


def test_build_flatten_emits_single_module(tmp_path):
    macro_dir = tmp_path / "macro"
    out_dir = tmp_path / "out"
    macro_dir.mkdir()
    for m in assemble.MODULE_ORDER:
        write_module(macro_dir, m, minimal(m))
    rc = assemble.run_build(macro_dir, out_dir, assemble.MODULE_ORDER, debug=False, flatten=True)
    assert rc == 0
    flat = out_dir / "Module1.bas"
    assert flat.exists()
    content = flat.read_text(encoding="utf-8")
    assert 'Attribute VB_Name = "Module1"' in content
    for m in assemble.MODULE_ORDER:
        assert f"==== module: {m} ====" in content


def test_build_with_debug_includes_debug_module(tmp_path):
    macro_dir = tmp_path / "macro"
    out_dir = tmp_path / "out"
    macro_dir.mkdir()
    for m in assemble.MODULE_ORDER + [assemble.DEBUG_MODULE]:
        write_module(macro_dir, m, minimal(m))
    rc = assemble.run_build(macro_dir, out_dir, assemble.MODULE_ORDER, debug=True, flatten=False)
    assert rc == 0
    assert (out_dir / "Debug.bas").exists()


def test_main_invokes_check(tmp_path, capsys):
    setup_fixture(tmp_path)
    rc = assemble.main(["--check", "--macro-dir", str(tmp_path)])
    assert rc == 0
    assert "OK" in capsys.readouterr().out
