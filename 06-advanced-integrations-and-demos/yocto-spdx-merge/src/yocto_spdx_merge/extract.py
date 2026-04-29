"""Read a Yocto .spdx.tar and locate the top-level image document."""

from __future__ import annotations

import io
import json
import sys
import tarfile
from pathlib import Path


def _open_tarfile(tar_path: str | Path) -> tarfile.TarFile:
    """Open a tar archive, transparently handling .zst compression.

    Python's tarfile autodetects gzip/bzip2/xz but not zstd. Modern Yocto
    builds frequently emit .spdx.tar.zst, so we sniff the path and
    decompress via the optional ``zstandard`` package when needed.
    """
    path_str = str(tar_path)
    if path_str.endswith(".zst") or path_str.endswith(".zstd"):
        try:
            import zstandard
        except ImportError:
            print(
                "Error: input is zstd-compressed but the 'zstandard' package is not installed.\n"
                "Install with: pip install 'yocto-spdx-merge[zstd]'  (or: pip install zstandard)",
                file=sys.stderr,
            )
            sys.exit(1)
        with open(path_str, "rb") as raw:
            decompressed = zstandard.ZstdDecompressor().stream_reader(raw).read()
        return tarfile.open(fileobj=io.BytesIO(decompressed), mode="r")
    return tarfile.open(path_str, "r")


def open_tar(tar_path: str | Path) -> list[dict]:
    """Read all SPDX JSON documents from a tar archive into memory."""
    docs = []
    with _open_tarfile(tar_path) as tf:
        for member in tf.getmembers():
            if not member.name.endswith(".spdx.json"):
                continue
            f = tf.extractfile(member)
            if f is None:
                continue
            docs.append(json.load(f))
    return docs


def find_top_level_doc(docs: list[dict]) -> dict:
    """Find the top-level image SPDX document (the one with externalDocumentRefs).

    The top-level doc is the one that references other documents. If multiple
    documents have externalDocumentRefs (e.g. multi-image builds), the one with
    the most refs is chosen and the others are reported on stderr.
    """
    candidates = [d for d in docs if d.get("externalDocumentRefs")]
    if len(candidates) == 0:
        print("Error: no top-level SPDX document found (none have externalDocumentRefs)", file=sys.stderr)
        sys.exit(1)
    if len(candidates) > 1:
        candidates.sort(key=lambda d: len(d["externalDocumentRefs"]), reverse=True)
        chosen = candidates[0]
        dropped = [f"{d.get('name', '<unnamed>')} ({len(d['externalDocumentRefs'])} refs)" for d in candidates[1:]]
        print(
            f"  WARNING: {len(candidates)} documents have externalDocumentRefs; "
            f"using '{chosen.get('name', '<unnamed>')}' ({len(chosen['externalDocumentRefs'])} refs). "
            f"Ignored: {', '.join(dropped)}",
            file=sys.stderr,
        )
        return chosen
    return candidates[0]


def build_namespace_index(docs: list[dict]) -> dict[str, dict]:
    """Build a map from documentNamespace URI to parsed SPDX document."""
    index = {}
    for doc in docs:
        ns = doc.get("documentNamespace")
        if ns:
            index[ns] = doc
    return index
