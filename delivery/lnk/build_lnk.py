"""Build a minimal MS-SHLLINK .lnk file.

Spec: [MS-SHLLINK] Shell Link (.LNK) Binary File Format, Microsoft Open Specifications.

Produces an LNK with:
  - ShellLinkHeader (76 bytes, LinkFlags set for RELATIVE_PATH / WORKING_DIR /
    ARGUMENTS / ICON_LOCATION / IS_UNICODE)
  - StringData: relative target path, working dir, args, icon location
  - Empty ExtraData terminator block
"""

from __future__ import annotations

import argparse
import struct
import time
from pathlib import Path


HEADER_CLSID = bytes.fromhex("0114020000000000c000000000000046")

FLAG_HAS_RELATIVE_PATH = 0x00000008
FLAG_HAS_WORKING_DIR = 0x00000010
FLAG_HAS_ARGUMENTS = 0x00000020
FLAG_HAS_ICON_LOCATION = 0x00000040
FLAG_IS_UNICODE = 0x00000080

FILE_ATTRIBUTE_ARCHIVE = 0x20
SW_SHOWNORMAL = 1


def windows_filetime(ts: float) -> int:
    return int((ts + 11644473600) * 10_000_000)


def utf16_le_count_prefixed(s: str) -> bytes:
    return struct.pack("<H", len(s)) + s.encode("utf-16-le")


def build_lnk(relative_path: str, args: str, working_dir: str,
              icon_location: str, icon_index: int, now_ts: float | None = None) -> bytes:
    flags = (FLAG_HAS_RELATIVE_PATH | FLAG_HAS_WORKING_DIR
             | FLAG_HAS_ARGUMENTS | FLAG_HAS_ICON_LOCATION
             | FLAG_IS_UNICODE)
    ft = windows_filetime(now_ts if now_ts is not None else time.time())
    header = (
        struct.pack("<I", 0x4C)
        + HEADER_CLSID
        + struct.pack("<I", flags)
        + struct.pack("<I", FILE_ATTRIBUTE_ARCHIVE)
        + struct.pack("<Q", ft) + struct.pack("<Q", ft) + struct.pack("<Q", ft)
        + struct.pack("<I", 0)
        + struct.pack("<i", icon_index)
        + struct.pack("<I", SW_SHOWNORMAL)
        + struct.pack("<H", 0)
        + b"\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
    )
    assert len(header) == 76, f"header is {len(header)} bytes, expected 76"

    string_data = (
        utf16_le_count_prefixed(relative_path)
        + utf16_le_count_prefixed(working_dir)
        + utf16_le_count_prefixed(args)
        + utf16_le_count_prefixed(icon_location)
    )
    extra_terminator = struct.pack("<I", 0)

    return header + string_data + extra_terminator


def parse_icon(spec: str) -> tuple[str, int]:
    if "," in spec:
        path, idx = spec.rsplit(",", 1)
        return path, int(idx)
    return spec, 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build a minimal MS-SHLLINK .lnk file")
    ap.add_argument("--target", required=True, help="Relative path of target (e.g. data\\\\report.docm)")
    ap.add_argument("--args", default="", help="Command-line arguments")
    ap.add_argument("--working-dir", default="", help="Working directory (relative)")
    ap.add_argument("--icon-from", default="shell32.dll,1", help="Icon source: path,index")
    ap.add_argument("--out", type=Path, required=True, help="Output .lnk path")
    args = ap.parse_args(argv)
    icon_path, icon_idx = parse_icon(args.icon_from)
    blob = build_lnk(args.target, args.args, args.working_dir, icon_path, icon_idx)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(blob)
    print(f"Wrote {args.out} ({len(blob)} bytes)")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
