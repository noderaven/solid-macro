"""Tests for delivery/lnk/build_lnk.py."""

import struct
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "delivery" / "lnk"))

import build_lnk  # noqa: E402


HEADER_CLSID_HEX = "0114020000000000c000000000000046"


def parse_lnk(blob: bytes):
    """Return a dict with HeaderSize, ClsidHex, flags, and the string blocks."""
    assert len(blob) >= 76
    (header_size,) = struct.unpack_from("<I", blob, 0)
    clsid = blob[4:20]
    (flags,) = struct.unpack_from("<I", blob, 20)
    offset = 76
    strings = []
    for _ in range(4):
        (count,) = struct.unpack_from("<H", blob, offset)
        offset += 2
        s = blob[offset: offset + count * 2].decode("utf-16-le")
        offset += count * 2
        strings.append(s)
    (terminator,) = struct.unpack_from("<I", blob, offset)
    return {
        "header_size": header_size,
        "clsid_hex": clsid.hex(),
        "flags": flags,
        "relative_path": strings[0],
        "working_dir": strings[1],
        "arguments": strings[2],
        "icon_location": strings[3],
        "terminator": terminator,
    }


def test_header_size_and_clsid(tmp_path):
    out = tmp_path / "t.lnk"
    build_lnk.main(["--target", "x.docm", "--out", str(out)])
    blob = out.read_bytes()
    parsed = parse_lnk(blob)
    assert parsed["header_size"] == 0x4C
    assert parsed["clsid_hex"] == HEADER_CLSID_HEX


def test_flags_include_relative_path_and_unicode(tmp_path):
    out = tmp_path / "t.lnk"
    build_lnk.main(["--target", "x.docm", "--out", str(out)])
    p = parse_lnk(out.read_bytes())
    assert p["flags"] & build_lnk.FLAG_HAS_RELATIVE_PATH
    assert p["flags"] & build_lnk.FLAG_IS_UNICODE


def test_strings_match_inputs(tmp_path):
    out = tmp_path / "t.lnk"
    build_lnk.main([
        "--target", "data\\report.docm",
        "--args=--my-flag",
        "--working-dir", "data",
        "--icon-from", "shell32.dll,3",
        "--out", str(out),
    ])
    p = parse_lnk(out.read_bytes())
    assert p["relative_path"] == "data\\report.docm"
    assert p["working_dir"] == "data"
    assert p["arguments"] == "--my-flag"
    assert p["icon_location"] == "shell32.dll"


def test_extra_terminator_is_zero(tmp_path):
    out = tmp_path / "t.lnk"
    build_lnk.main(["--target", "x.docm", "--out", str(out)])
    p = parse_lnk(out.read_bytes())
    assert p["terminator"] == 0


def test_filetime_in_reasonable_range():
    ft = build_lnk.windows_filetime(1782129600)
    assert ft == (11644473600 + 1782129600) * 10_000_000


def test_utf16_le_count_prefixed_encoding():
    enc = build_lnk.utf16_le_count_prefixed("ABC")
    assert enc == b"\x03\x00A\x00B\x00C\x00"


def test_parse_icon_with_index():
    assert build_lnk.parse_icon("shell32.dll,5") == ("shell32.dll", 5)


def test_parse_icon_without_index():
    assert build_lnk.parse_icon("ico.dll") == ("ico.dll", 0)
