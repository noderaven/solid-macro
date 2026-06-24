# Delivery

How to get the assembled `.docm` past Mark-of-the-Web and modern Office
macro-lockdown defaults onto a target endpoint.

## The Mark-of-the-Web problem

Since Office build 16.0.14931 (Feb 2022), macros from MotW-tagged files are
blocked outright. The user sees a red banner; there is no "Enable Content"
affordance. A naked `.docm` delivered via web / email is effectively dead.

Delivery research focuses on stripping MotW from the `.docm` before the
user opens it. The two living vectors as of 2026 are:

1. ISO/IMG container wrappers (this repo: `delivery/iso/`)
2. LNK-driven indirection (this repo: `delivery/lnk/`)

## ISO container

Windows' built-in ISO driver mounts the image, presents its contents as a
drive letter. When the user copies or opens a file from inside the mount,
MotW is *not* transferred to the extracted file. Effective on default Win11
configs in 2026.

**Build:**

```
python delivery/iso/build_iso.py \
    report.lnk \
    data/report.docm \
    --label "Q4_DATA" \
    --out report.iso
```

The ISO will contain:

```
report.iso
+- report.lnk         <- at root, friendly icon
+- data/
   +- report.docm     <- the assembled macro
```

User experience: download `report.iso`, double-click to mount, see `report.lnk`,
double-click, Word opens `data\report.docm`, macros prompt fires (because the
.docm now has no MotW).

## LNK indirection

A `.lnk` co-located with the target preserves the MotW status of the LNK
itself, but the file it launches inherits no MotW. Useful inside an ISO to
disguise the `.docm` behind a friendlier icon and filename.

**Build:**

```
python delivery/lnk/build_lnk.py \
    --target "data\\report.docm" \
    --working-dir "data" \
    --icon-from "shell32.dll,1" \
    --out report.lnk
```

## Hardening that breaks this delivery chain

- **`BlockDownloadsOfAllSamples` GPO**: blocks downloads from internet zone
  outright. Hardened orgs deploy this; the ISO never reaches the user.
- **`OOXMLFileSandboxAttachments` Office policy (2024 templates)**: sandboxes
  Office files regardless of MotW. The `.docm` opens in Protected View;
  macros don't run.
- **Smart App Control (Win11 22H2+)**: blocks unsigned LNKs on consumer SKUs.
- **AppLocker / WDAC** publisher-restricted policies: blocks `winword.exe`
  launching unsigned macros.

This delivery chain works against a Win11 default-config endpoint in 2026.
It does not work against a fully hardened Office + SAC + AppLocker target.

## Vectors not implemented in v2

Documented for reference; could be added in future work:

- **IMG / VHD** containers: same MotW behavior as ISO; format varies.
- **HTA**: `mshta.exe`-driven HTML+VBScript; killed by recent Defender
  default rules.
- **OneNote** with embedded objects: killed in mid-2023 by Microsoft.
- **Search-ms protocol**: `search-ms://...` URI scheme triggering a
  remote query; works on some Win10 configs, hardened on Win11.
- **MSIX** with abused-certificate signing: enterprise-grade delivery
  vector; out of scope for a public study artifact.
