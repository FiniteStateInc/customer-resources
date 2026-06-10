"""Tests for downloadLocation backfill from Yocto recipe documents."""

from __future__ import annotations

from yocto_spdx_merge.downloads import resolve_download_location
from yocto_spdx_merge.merge import extract_packages


RECIPE_NS = "http://spdx.org/spdxdocs/recipe-busybox-1111"
PACKAGE_NS = "http://spdx.org/spdxdocs/busybox-2222"


def make_recipe_doc(downloads: list[str], pn: str = "busybox", ns: str = RECIPE_NS) -> dict:
    """Build a recipe doc shaped like create-spdx-2.2.bbclass output."""
    recipe_id = f"SPDXRef-Recipe-{pn}"
    packages = [
        {
            "SPDXID": recipe_id,
            "name": pn,
            "versionInfo": "1.36.1",
            "downloadLocation": "NOASSERTION",
        }
    ]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": recipe_id,
        }
    ]
    for idx, uri in enumerate(downloads, start=1):
        download_id = f"SPDXRef-Download-{pn}-{idx}"
        packages.append(
            {
                "SPDXID": download_id,
                "name": f"{pn}-source-{idx}",
                "downloadLocation": uri,
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": download_id,
            }
        )
        relationships.append(
            {
                "spdxElementId": download_id,
                "relationshipType": "BUILD_DEPENDENCY_OF",
                "relatedSpdxElement": recipe_id,
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"recipe-{pn}",
        "documentNamespace": ns,
        "packages": packages,
        "relationships": relationships,
    }


def make_package_doc(
    pkg: str = "busybox",
    pn: str = "busybox",
    recipe_ns: str = RECIPE_NS,
    download_location: str = "NOASSERTION",
    with_generated_from: bool = True,
) -> dict:
    """Build a package doc shaped like create-spdx-2.2.bbclass output."""
    pkg_id = f"SPDXRef-Package-{pkg}"
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": pkg_id,
        }
    ]
    if with_generated_from:
        relationships.insert(
            0,
            {
                "spdxElementId": pkg_id,
                "relationshipType": "GENERATED_FROM",
                "relatedSpdxElement": f"DocumentRef-recipe-{pn}:SPDXRef-Recipe-{pn}",
            },
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": pkg,
        "documentNamespace": f"http://spdx.org/spdxdocs/{pkg}-2222",
        "externalDocumentRefs": [
            {
                "externalDocumentId": f"DocumentRef-recipe-{pn}",
                "spdxDocument": recipe_ns,
                "checksum": {"algorithm": "SHA1", "checksumValue": "0" * 40},
            }
        ],
        "packages": [
            {
                "SPDXID": pkg_id,
                "name": pkg,
                "versionInfo": "1.36.1",
                "downloadLocation": download_location,
                "licenseDeclared": "GPL-2.0-only",
            }
        ],
        "relationships": relationships,
    }


class TestResolveDownloadLocation:
    def test_resolves_uri_from_recipe_doc(self):
        recipe = make_recipe_doc(["git://git.busybox.net/busybox@abc123"])
        pkg_doc = make_package_doc()
        index = {RECIPE_NS: recipe, pkg_doc["documentNamespace"]: pkg_doc}

        uri = resolve_download_location("SPDXRef-Package-busybox", pkg_doc, index)

        assert uri == "git://git.busybox.net/busybox@abc123"

    def test_picks_first_download_when_multiple(self):
        recipe = make_recipe_doc(
            [
                "https://downloads.example.com/busybox-1.36.1.tar.bz2",
                "https://downloads.example.com/extras.tar.gz",
            ]
        )
        pkg_doc = make_package_doc()
        index = {RECIPE_NS: recipe}

        uri = resolve_download_location("SPDXRef-Package-busybox", pkg_doc, index)

        assert uri == "https://downloads.example.com/busybox-1.36.1.tar.bz2"

    def test_returns_none_when_recipe_doc_missing(self):
        pkg_doc = make_package_doc()
        uri = resolve_download_location("SPDXRef-Package-busybox", pkg_doc, {})
        assert uri is None

    def test_returns_none_without_generated_from(self):
        recipe = make_recipe_doc(["git://git.busybox.net/busybox"])
        pkg_doc = make_package_doc(with_generated_from=False)
        index = {RECIPE_NS: recipe}

        uri = resolve_download_location("SPDXRef-Package-busybox", pkg_doc, index)

        assert uri is None

    def test_returns_none_when_recipe_has_no_downloads(self):
        # file:// only recipes produce no download packages
        recipe = make_recipe_doc([])
        pkg_doc = make_package_doc()
        index = {RECIPE_NS: recipe}

        uri = resolve_download_location("SPDXRef-Package-busybox", pkg_doc, index)

        assert uri is None

    def test_ignores_noassertion_download_packages(self):
        recipe = make_recipe_doc(["NOASSERTION", "https://example.com/src.tar.gz"])
        pkg_doc = make_package_doc()
        index = {RECIPE_NS: recipe}

        uri = resolve_download_location("SPDXRef-Package-busybox", pkg_doc, index)

        assert uri == "https://example.com/src.tar.gz"

    def test_falls_back_to_download_prefix_without_relationships(self):
        recipe = make_recipe_doc(["git://git.busybox.net/busybox"])
        recipe["relationships"] = []  # no BUILD_DEPENDENCY_OF edges
        pkg_doc = make_package_doc()
        index = {RECIPE_NS: recipe}

        uri = resolve_download_location("SPDXRef-Package-busybox", pkg_doc, index)

        assert uri == "git://git.busybox.net/busybox"


class TestExtractPackagesBackfill:
    def _refs_for(self, pkg_doc: dict) -> list[dict]:
        return [
            {
                "externalDocumentId": f"DocumentRef-{pkg_doc['name']}",
                "spdxDocument": pkg_doc["documentNamespace"],
            }
        ]

    def test_backfills_noassertion_download_location(self):
        recipe = make_recipe_doc(["git://git.busybox.net/busybox@abc123"])
        pkg_doc = make_package_doc()
        index = {RECIPE_NS: recipe, pkg_doc["documentNamespace"]: pkg_doc}

        packages, warnings = extract_packages(self._refs_for(pkg_doc), index)

        assert warnings == []
        assert packages[0]["downloadLocation"] == "git://git.busybox.net/busybox@abc123"

    def test_preserves_existing_download_location(self):
        recipe = make_recipe_doc(["git://git.busybox.net/busybox@abc123"])
        pkg_doc = make_package_doc(download_location="https://already.example.com/src.tar.gz")
        index = {RECIPE_NS: recipe, pkg_doc["documentNamespace"]: pkg_doc}

        packages, _ = extract_packages(self._refs_for(pkg_doc), index)

        assert packages[0]["downloadLocation"] == "https://already.example.com/src.tar.gz"

    def test_leaves_noassertion_when_unresolvable(self):
        pkg_doc = make_package_doc()  # recipe doc absent from index
        index = {pkg_doc["documentNamespace"]: pkg_doc}

        packages, _ = extract_packages(self._refs_for(pkg_doc), index)

        assert packages[0]["downloadLocation"] == "NOASSERTION"
