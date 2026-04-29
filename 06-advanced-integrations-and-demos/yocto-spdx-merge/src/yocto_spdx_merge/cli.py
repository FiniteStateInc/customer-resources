"""CLI entry point for yocto-spdx-merge."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from yocto_spdx_merge import __version__
from yocto_spdx_merge.extract import open_tar, find_top_level_doc, build_namespace_index
from yocto_spdx_merge.merge import filter_package_refs, extract_packages, assemble_document
from yocto_spdx_merge.validate import validate_spdx_file


def _derive_output_name(tar_path: str) -> str:
    """Derive output filename from tar path: foo.spdx.tar -> foo.spdx.json"""
    base = os.path.basename(tar_path)
    if base.endswith(".spdx.tar"):
        return base.replace(".spdx.tar", ".spdx.json")
    if base.endswith(".tar"):
        return base.replace(".tar", ".spdx.json")
    return base + ".spdx.json"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="yocto-spdx-merge",
        description="Merge Yocto SPDX tar archives into a single SPDX 2.3 JSON document.",
    )
    parser.add_argument("input", help="Path to Yocto .spdx.tar file")
    parser.add_argument("-o", "--output", help="Output SPDX JSON path (default: derived from input)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    tar_path = args.input
    if not os.path.exists(tar_path):
        print(f"Error: file not found: {tar_path}", file=sys.stderr)
        sys.exit(1)

    output_path = args.output or _derive_output_name(tar_path)

    # Step 1: Read tar
    print(f"Reading {tar_path}...", file=sys.stderr)
    docs = open_tar(tar_path)
    print(f"  Found {len(docs)} SPDX documents in archive", file=sys.stderr)

    # Step 2: Find top-level doc
    top = find_top_level_doc(docs)
    image_name = top["name"]
    image_package = top["packages"][0]
    print(f"  Top-level image: {image_name}", file=sys.stderr)

    # Step 3: Index all docs by namespace
    index = build_namespace_index(docs)

    # Step 4: Filter to package refs only
    all_refs = top["externalDocumentRefs"]
    package_refs = filter_package_refs(all_refs)
    skipped = len(all_refs) - len(package_refs)
    print(f"  Package refs: {len(package_refs)} (skipped {skipped} runtime/recipe)", file=sys.stderr)

    # Step 5: Extract packages
    packages, warnings = extract_packages(package_refs, index, all_refs)
    for w in warnings:
        print(f"  WARNING: {w}", file=sys.stderr)

    # Enrichment summary
    cpe_count = sum(
        1 for p in packages
        if any(r.get("referenceType") == "cpe23Type" for r in p.get("externalRefs", []))
    )
    purl_count = sum(
        1 for p in packages
        if any(r.get("referenceType") == "purl" for r in p.get("externalRefs", []))
    )
    if packages:
        pct = 100 * cpe_count // len(packages)
        print(f"  CPE mapped: {cpe_count}/{len(packages)} ({pct}%), all {purl_count} have purl", file=sys.stderr)
    else:
        print("  No component packages extracted (all refs were runtime/recipe or unresolved)", file=sys.stderr)

    # Step 6: Assemble output document
    image_version = image_package.get("versionInfo", "")
    merged = assemble_document(image_name, image_version, image_package, packages)

    # Step 7: Write to temp file for validation
    print(f"  Assembled {len(packages)} packages", file=sys.stderr)
    output = Path(output_path)
    output.write_text(json.dumps(merged, indent=2))

    # Step 8: Validate
    print("  Validating SPDX 2.3 compliance...", file=sys.stderr)
    errors = validate_spdx_file(str(output))
    if errors:
        print(f"  VALIDATION FAILED ({len(errors)} errors):", file=sys.stderr)
        for err in errors[:20]:
            print(f"    {err}", file=sys.stderr)
        if len(errors) > 20:
            print(f"    ... and {len(errors) - 20} more", file=sys.stderr)
        output.unlink()
        sys.exit(1)

    # Step 9: Summary
    size_kb = output.stat().st_size / 1024
    print(f"  Validation passed", file=sys.stderr)
    print(f"  Output: {output_path} ({size_kb:.1f} KB, {len(packages)} packages)", file=sys.stderr)


if __name__ == "__main__":
    main()
