"""Bundle files into an ISO 9660 + Joliet image (delivery wrapper)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _to_iso_name(name: str) -> str:
    """Convert a filename to ISO 9660 8.3 uppercase + version suffix."""
    if "." in name:
        stem, _, ext = name.rpartition(".")
    else:
        stem, ext = name, ""
    stem = stem.upper().replace(".", "_")[:8]
    ext = ext.upper()[:3]
    return (stem + "." + ext if ext else stem) + ";1"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Bundle files into ISO 9660 + Joliet")
    ap.add_argument("files", nargs="+", type=Path,
                    help="Files to include. One level of subdirectory is preserved.")
    ap.add_argument("--label", default="DATA", help="Volume label (<= 32 chars)")
    ap.add_argument("--out", type=Path, required=True, help="Output .iso path")
    args = ap.parse_args(argv)

    try:
        import pycdlib
    except ImportError:
        print("FAIL: pycdlib not installed. Run: pip install -r delivery/iso/requirements.txt",
              file=sys.stderr)
        return 1

    for f in args.files:
        if not f.exists():
            print(f"FAIL: {f} not found", file=sys.stderr)
            return 1

    iso = pycdlib.PyCdlib()
    iso.new(joliet=3, vol_ident=args.label[:32])

    dirs_created: set[str] = set()

    for local in args.files:
        parts = list(local.parts)
        # Preserve a single-level subdirectory only if the input path is relative
        # and has exactly one parent. Absolute paths drop subdirectory structure
        # so they always land at the ISO root.
        if local.is_absolute() or len(parts) <= 1:
            iso_dir = ""
            joliet_dir = ""
        else:
            iso_dir = "/" + parts[0].upper()[:8]
            joliet_dir = "/" + parts[0]
            if iso_dir not in dirs_created:
                iso.add_directory(iso_dir, joliet_path=joliet_dir)
                dirs_created.add(iso_dir)

        iso_filename = _to_iso_name(local.name)
        iso_path = (iso_dir or "") + "/" + iso_filename
        joliet_path = (joliet_dir or "") + "/" + local.name

        iso.add_file(str(local), iso_path=iso_path, joliet_path=joliet_path)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    iso.write(str(args.out))
    iso.close()
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
