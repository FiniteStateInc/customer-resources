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

    def test_tolerates_relationship_without_spdx_element_id(self):
        # A malformed BUILD_DEPENDENCY_OF edge must not crash resolution
        recipe = make_recipe_doc(["git://git.busybox.net/busybox"])
        recipe["relationships"].append(
            {
                "relationshipType": "BUILD_DEPENDENCY_OF",
                "relatedSpdxElement": "SPDXRef-Recipe-busybox",
            }
        )
        pkg_doc = make_package_doc()
        index = {RECIPE_NS: recipe}

        uri = resolve_download_location("SPDXRef-Package-busybox", pkg_doc, index)

        assert uri == "git://git.busybox.net/busybox"

    def test_prefix_fallback_is_scoped_to_the_recipe(self):
        # A download package belonging to a different recipe in the same doc
        # must not be picked up by the prefix fallback
        recipe = make_recipe_doc([])
        recipe["relationships"] = []
        recipe["packages"].append(
            {
                "SPDXID": "SPDXRef-Download-otherpkg-1",
                "name": "otherpkg-source-1",
                "downloadLocation": "https://example.com/otherpkg.tar.gz",
            }
        )
        pkg_doc = make_package_doc()
        index = {RECIPE_NS: recipe}

        uri = resolve_download_location("SPDXRef-Package-busybox", pkg_doc, index)

        assert uri is None

    def test_unions_relationship_and_prefix_candidates(self):
        # Relationship edges only cover Download-2; Download-1 (lower SRC_URI
        # index) is discoverable by ID convention and must win
        recipe = make_recipe_doc(
            ["https://example.com/first.tar.gz", "https://example.com/second.tar.gz"]
        )
        recipe["relationships"] = [
            rel
            for rel in recipe["relationships"]
            if rel.get("spdxElementId") != "SPDXRef-Download-busybox-1"
        ]
        pkg_doc = make_package_doc()
        index = {RECIPE_NS: recipe}

        uri = resolve_download_location("SPDXRef-Package-busybox", pkg_doc, index)

        assert uri == "https://example.com/first.tar.gz"

    def test_handles_src_uri_index_gap(self):
        # Yocto enumerates all SRC_URI entries but skips file:// ones, so the
        # first emitted download package may be Download-<pn>-2
        recipe = make_recipe_doc([])
        for idx, uri in ((2, "https://example.com/remote.tar.gz"), (3, "https://example.com/extra.tar.gz")):
            download_id = f"SPDXRef-Download-busybox-{idx}"
            recipe["packages"].append(
                {
                    "SPDXID": download_id,
                    "name": f"busybox-source-{idx}",
                    "downloadLocation": uri,
                }
            )
            recipe["relationships"].append(
                {
                    "spdxElementId": download_id,
                    "relationshipType": "BUILD_DEPENDENCY_OF",
                    "relatedSpdxElement": "SPDXRef-Recipe-busybox",
                }
            )
        pkg_doc = make_package_doc()
        index = {RECIPE_NS: recipe}

        uri = resolve_download_location("SPDXRef-Package-busybox", pkg_doc, index)

        assert uri == "https://example.com/remote.tar.gz"

    def test_falls_back_to_recipe_package_download_location(self):
        # Defensive: if a create-spdx variant puts the location on the recipe
        # package itself, use it when no download packages exist
        recipe = make_recipe_doc([])
        recipe["packages"][0]["downloadLocation"] = "https://example.com/recipe-src.tar.gz"
        pkg_doc = make_package_doc()
        index = {RECIPE_NS: recipe}

        uri = resolve_download_location("SPDXRef-Package-busybox", pkg_doc, index)

        assert uri == "https://example.com/recipe-src.tar.gz"

    def test_rejects_whitespace_only_locations(self):
        recipe = make_recipe_doc(["   "])
        pkg_doc = make_package_doc()
        index = {RECIPE_NS: recipe}

        uri = resolve_download_location("SPDXRef-Package-busybox", pkg_doc, index)

        assert uri is None

    def test_rejects_file_uri_locations(self):
        # A file:// path is useless as an SBOM downloadLocation
        recipe = make_recipe_doc([])
        recipe["packages"][0]["downloadLocation"] = "file:///build/downloads/src.tar.gz"
        pkg_doc = make_package_doc()
        index = {RECIPE_NS: recipe}

        uri = resolve_download_location("SPDXRef-Package-busybox", pkg_doc, index)

        assert uri is None

    def test_ignores_non_download_relationship_candidates(self):
        # A BUILD_DEPENDENCY_OF edge from a non-download package must not win
        # over the real download package (it would sort first with key 0)
        recipe = make_recipe_doc(["https://example.com/right.tar.gz"])
        recipe["packages"].append(
            {
                "SPDXID": "SPDXRef-Helper-busybox",
                "name": "helper",
                "downloadLocation": "https://example.com/wrong.tar.gz",
            }
        )
        recipe["relationships"].append(
            {
                "spdxElementId": "SPDXRef-Helper-busybox",
                "relationshipType": "BUILD_DEPENDENCY_OF",
                "relatedSpdxElement": "SPDXRef-Recipe-busybox",
            }
        )
        pkg_doc = make_package_doc()
        index = {RECIPE_NS: recipe}

        uri = resolve_download_location("SPDXRef-Package-busybox", pkg_doc, index)

        assert uri == "https://example.com/right.tar.gz"

    def test_tries_all_generated_from_edges(self):
        # First GENERATED_FROM edge points at an unresolvable target; the
        # second one (the real recipe) must still be followed
        recipe = make_recipe_doc(["git://git.busybox.net/busybox"])
        pkg_doc = make_package_doc()
        pkg_doc["relationships"].insert(
            0,
            {
                "spdxElementId": "SPDXRef-Package-busybox",
                "relationshipType": "GENERATED_FROM",
                "relatedSpdxElement": "DocumentRef-dependency-other:SPDXRef-Recipe-other",
            },
        )
        index = {RECIPE_NS: recipe}

        uri = resolve_download_location("SPDXRef-Package-busybox", pkg_doc, index)

        assert uri == "git://git.busybox.net/busybox"

    def test_resolves_recipe_ref_via_extra_doc_refs(self):
        # If the package doc lacks its own externalDocumentRefs, top-level
        # refs (e.g. from the image doc) are consulted as a fallback
        recipe = make_recipe_doc(["git://git.busybox.net/busybox"])
        pkg_doc = make_package_doc()
        extra_refs = pkg_doc.pop("externalDocumentRefs")
        index = {RECIPE_NS: recipe}

        uri = resolve_download_location(
            "SPDXRef-Package-busybox", pkg_doc, index, extra_doc_refs=extra_refs
        )

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

    def test_normalizes_empty_download_location_to_noassertion(self):
        pkg_doc = make_package_doc(download_location="")  # recipe doc absent
        index = {pkg_doc["documentNamespace"]: pkg_doc}

        packages, _ = extract_packages(self._refs_for(pkg_doc), index)

        assert packages[0]["downloadLocation"] == "NOASSERTION"

    def test_replaces_file_uri_when_recipe_resolvable(self):
        # A pre-existing local build path is upgraded to the real upstream URI
        recipe = make_recipe_doc(["git://git.busybox.net/busybox@abc123"])
        pkg_doc = make_package_doc(download_location="file:///build/tmp/work/src.tar.gz")
        index = {RECIPE_NS: recipe, pkg_doc["documentNamespace"]: pkg_doc}

        packages, _ = extract_packages(self._refs_for(pkg_doc), index)

        assert packages[0]["downloadLocation"] == "git://git.busybox.net/busybox@abc123"

    def test_normalizes_file_uri_to_noassertion_when_unresolvable(self):
        # spdx-tools rejects file:// downloadLocation values, so an
        # unresolvable local path must become NOASSERTION or the merged
        # document fails validation
        pkg_doc = make_package_doc(download_location="file:///build/tmp/work/src.tar.gz")
        index = {pkg_doc["documentNamespace"]: pkg_doc}

        packages, _ = extract_packages(self._refs_for(pkg_doc), index)

        assert packages[0]["downloadLocation"] == "NOASSERTION"

    def test_backfills_null_download_location(self):
        # JSON null is not a valid SPDX value — backfill or normalize it
        recipe = make_recipe_doc(["git://git.busybox.net/busybox@abc123"])
        pkg_doc = make_package_doc()
        pkg_doc["packages"][0]["downloadLocation"] = None
        index = {RECIPE_NS: recipe, pkg_doc["documentNamespace"]: pkg_doc}

        packages, _ = extract_packages(self._refs_for(pkg_doc), index)

        assert packages[0]["downloadLocation"] == "git://git.busybox.net/busybox@abc123"

    def test_normalizes_null_to_noassertion_when_unresolvable(self):
        pkg_doc = make_package_doc()
        pkg_doc["packages"][0]["downloadLocation"] = None
        index = {pkg_doc["documentNamespace"]: pkg_doc}

        packages, _ = extract_packages(self._refs_for(pkg_doc), index)

        assert packages[0]["downloadLocation"] == "NOASSERTION"

    def test_preserves_explicit_none(self):
        # NONE is a valid SPDX assertion ("intentionally no download location")
        recipe = make_recipe_doc(["git://git.busybox.net/busybox"])
        pkg_doc = make_package_doc(download_location="NONE")
        index = {RECIPE_NS: recipe, pkg_doc["documentNamespace"]: pkg_doc}

        packages, _ = extract_packages(self._refs_for(pkg_doc), index)

        assert packages[0]["downloadLocation"] == "NONE"

    def test_backfills_via_top_level_doc_refs(self):
        # Package doc without its own externalDocumentRefs resolves through
        # the top-level refs passed as all_external_doc_refs
        recipe = make_recipe_doc(["git://git.busybox.net/busybox@abc123"])
        pkg_doc = make_package_doc()
        top_refs = pkg_doc.pop("externalDocumentRefs") + self._refs_for(pkg_doc)
        index = {RECIPE_NS: recipe, pkg_doc["documentNamespace"]: pkg_doc}

        packages, _ = extract_packages(self._refs_for(pkg_doc), index, top_refs)

        assert packages[0]["downloadLocation"] == "git://git.busybox.net/busybox@abc123"
