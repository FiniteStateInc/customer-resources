"""End-to-end CLI test on a synthetic Yocto-shaped .spdx.tar archive."""

from __future__ import annotations

import io
import json
import tarfile

from yocto_spdx_merge.cli import main

from test_download_location import make_package_doc, make_recipe_doc

IMAGE_NS = "http://spdx.org/spdxdocs/core-image-minimal-9999"


def make_image_doc(package_doc: dict) -> dict:
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "core-image-minimal",
        "documentNamespace": IMAGE_NS,
        "externalDocumentRefs": [
            {
                "externalDocumentId": f"DocumentRef-{package_doc['name']}",
                "spdxDocument": package_doc["documentNamespace"],
                "checksum": {"algorithm": "SHA1", "checksumValue": "0" * 40},
            },
            {
                "externalDocumentId": "DocumentRef-runtime-busybox",
                "spdxDocument": "http://spdx.org/spdxdocs/runtime-busybox-3333",
                "checksum": {"algorithm": "SHA1", "checksumValue": "0" * 40},
            },
        ],
        "packages": [
            {
                "SPDXID": "SPDXRef-Image-core-image-minimal",
                "name": "core-image-minimal",
                "versionInfo": "1.0",
                "downloadLocation": "NOASSERTION",
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Image-core-image-minimal",
            }
        ],
    }


def write_archive(tar_path, docs: dict[str, dict]) -> None:
    with tarfile.open(tar_path, "w") as tf:
        for name, doc in docs.items():
            data = json.dumps(doc).encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def test_merge_backfills_download_location_end_to_end(tmp_path, capsys):
    recipe_doc = make_recipe_doc(["git://git.busybox.net/busybox@abc123"])
    package_doc = make_package_doc()
    image_doc = make_image_doc(package_doc)

    tar_path = tmp_path / "core-image-minimal.spdx.tar"
    write_archive(
        tar_path,
        {
            "core-image-minimal.spdx.json": image_doc,
            "packages/busybox.spdx.json": package_doc,
            "recipes/recipe-busybox.spdx.json": recipe_doc,
        },
    )
    out_path = tmp_path / "out.spdx.json"

    main([str(tar_path), "-o", str(out_path)])

    merged = json.loads(out_path.read_text())
    by_name = {p["name"]: p for p in merged["packages"]}
    assert by_name["busybox"]["downloadLocation"] == "git://git.busybox.net/busybox@abc123"

    stderr = capsys.readouterr().err
    assert "downloadLocation populated: 1/1" in stderr
