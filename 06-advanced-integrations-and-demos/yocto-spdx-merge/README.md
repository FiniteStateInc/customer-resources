# yocto-spdx-merge

Merge a Yocto `.spdx.tar` archive into a single, flat, validated SPDX 2.3 JSON document.

Yocto emits SPDX as a tar of many per-package/per-recipe/per-runtime JSON files tied
together by `externalDocumentRefs`. Most downstream SBOM tooling expects a single
self-contained document. This tool flattens the archive, keeps only real package
documents, resolves cross-document license references, enriches packages with `purl`
and (where mapped) CPE 2.3 `externalRefs`, and validates the result against SPDX 2.3.

## Installation

```bash
uv sync          # or: pip install -e .
```

To accept zstd-compressed archives (`.spdx.tar.zst`, the default in many
modern Yocto configurations), install the optional `zstd` extra:

```bash
pip install -e '.[zstd]'   # or: uv sync --extra zstd
```

Requires Python 3.9+.

## Usage

```bash
yocto-spdx-merge <image>.spdx.tar[.zst] [-o <output>.spdx.json]
```

If `-o` is omitted, the output path is derived from the input:
`core-image-minimal.spdx.tar` → `core-image-minimal.spdx.json`.

Example:

```
$ yocto-spdx-merge core-image-minimal.spdx.tar
Reading core-image-minimal.spdx.tar...
  Found 842 SPDX documents in archive
  Top-level image: core-image-minimal
  Package refs: 312 (skipped 530 runtime/recipe)
  CPE mapped: 187/312 (59%), all 312 have purl
  Assembled 312 packages
  Validating SPDX 2.3 compliance...
  Validation passed
  Output: core-image-minimal.spdx.json (1284.3 KB, 312 packages)
```

On validation failure the output file is deleted and the tool exits non-zero with
the first 20 error messages.

## What it does

1. **Extract** — read every `*.spdx.json` from the tar into memory (`extract.py`).
2. **Locate top-level doc** — the image document is the one with `externalDocumentRefs`
   (or the one with the most, if multiple candidates exist).
3. **Filter refs** — drop `DocumentRef-runtime-*` and `DocumentRef-recipe-*`; keep
   only real package documents (`merge.filter_package_refs`).
4. **Extract packages** — pull each referenced package, sanitize/deduplicate its
   `SPDXID`, and resolve cross-document license references
   (`DocumentRef-xxx:LicenseRef-yyy` → bare `LicenseRef-yyy` when the target
   document is present; otherwise the whole expression collapses to `NOASSERTION`).
   Deprecated SPDX IDs like `GPL-3.0-with-GCC-exception` are normalized to SPDX 2.3
   `WITH`-form equivalents (`licenses.py`).
5. **Enrich** — every package gets a `pkg:yocto/<name>@<version>` purl. Packages
   whose name (or a dash-stripped base) matches `data/cpe_map.yaml` also get a
   CPE 2.3 `externalRef`. Yocto `+git` version suffixes are stripped from CPE
   versions; existing `externalRefs` are preserved and deduplicated by locator
   (`enrich.py`).
6. **Assemble** — emit a single SPDX 2.3 document: the image package plus all
   component packages, with a `DESCRIBES` relationship from the document to the
   image and `DEPENDS_ON` relationships from the image to each component
   (`merge.assemble_document`).
7. **Validate** — parse and validate the output with `spdx-tools`. On failure,
   delete the output and exit 1.

## Project layout

```
src/yocto_spdx_merge/
  cli.py             # argparse entry point, orchestration, progress output
  extract.py         # tar reading, top-level doc detection, namespace index
  merge.py           # ref filtering, package extraction, document assembly
  licenses.py        # cross-doc LicenseRef resolution, deprecated ID mapping
  enrich.py          # purl + CPE externalRef generation
  validate.py        # spdx-tools wrapper
  data/cpe_map.yaml  # Yocto recipe name → {vendor, product} for CPE lookup
```

## CPE mapping

`data/cpe_map.yaml` maps Yocto package names to CPE `vendor`/`product` pairs:

```yaml
openssl:
  vendor: openssl
  product: openssl
busybox:
  vendor: busybox
  product: busybox
```

Lookup order for a package `foo-bar-baz`:

1. Exact match on the full name.
2. Known Yocto suffix stripped (`-dev`, `-dbg`, `-doc`, `-staticdev`, `-src`, `-ptest`).
3. Iterative right-dash stripping (`foo-bar-baz` → `foo-bar` → `foo`).

First hit wins. Add new entries to `cpe_map.yaml` to expand CPE coverage.

The shipped map covers the common `core-image-*` recipes and roughly 150 of
the most CVE-relevant Yocto packages. Coverage on a stock `core-image-minimal`
or `core-image-full-cmdline` is typically 55-70%; broader BSPs (Qt, vendor
SoC layers, Mender) will start lower and benefit most from local additions.
