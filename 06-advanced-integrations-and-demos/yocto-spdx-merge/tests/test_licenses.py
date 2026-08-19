"""Tests for SPDX license expression normalization."""

from __future__ import annotations

import io
import json
import tarfile

import pytest

from yocto_spdx_merge.cli import main
from yocto_spdx_merge.licenses import resolve_license_expression
from yocto_spdx_merge.validate import validate_spdx_file

from test_cli import make_image_doc
from test_download_location import make_package_doc, make_recipe_doc


class TestResolveLicenseExpression:
    def test_passes_through_noassertion(self):
        assert resolve_license_expression("NOASSERTION", {}) == "NOASSERTION"

    def test_passes_through_plain_license_id(self):
        assert resolve_license_expression("MIT", {}) == "MIT"

    @pytest.mark.parametrize(
        "deprecated,expected",
        [
            ("GPL-3.0-with-GCC-exception", "GPL-3.0-only WITH GCC-exception-3.1"),
            ("GPL-2.0-with-classpath-exception", "GPL-2.0-only WITH Classpath-exception-2.0"),
            ("GPL-2.0-with-font-exception", "GPL-2.0-only WITH Font-exception-2.0"),
            ("GPL-2.0-with-bison-exception", "GPL-2.0-only WITH Bison-exception-2.2"),
            ("GPL-2.0-with-autoconf-exception", "GPL-2.0-only WITH Autoconf-exception-2.0"),
            # Regression: create-spdx.bbclass emits this for the gnu-config
            # recipe; it was missing from the deprecated-license map, so it
            # passed through unnormalized and failed spdx-tools SPDX 2.3
            # validation with a bare, unmerged output.
            ("GPL-3.0-with-autoconf-exception", "GPL-3.0-only WITH Autoconf-exception-2.0"),
            # The official SPDX License List has 7 deprecated compound
            # GPL-*-with-*-exception ids; this was the one other one missing
            # from the map alongside the autoconf-2.0 gap above.
            ("GPL-2.0-with-GCC-exception", "GPL-2.0-only WITH GCC-exception-2.0"),
        ],
    )
    def test_normalizes_deprecated_license_ids(self, deprecated, expected):
        assert resolve_license_expression(deprecated, {}) == expected

    def test_normalizes_deprecated_id_inside_compound_expression(self):
        expr = "GPL-3.0-with-autoconf-exception AND MIT"
        assert (
            resolve_license_expression(expr, {})
            == "GPL-3.0-only WITH Autoconf-exception-2.0 AND MIT"
        )


class TestGnuConfigRegression:
    """End-to-end regression for the gnu-config licenseDeclared/licenseConcluded bug.

    Reproduces the customer-reported failure exactly: create-spdx.bbclass
    emits "GPL-3.0-with-autoconf-exception" for gnu-config, which previously
    passed straight through to the merged document and failed spdx-tools'
    SPDX 2.3 validator with:

        [SpdxElementType.LICENSE_EXPRESSION] A license exception symbol can
        only be used as an exception in a "WITH exception" statement.

    On failure the CLI deletes the partially-written output file (cli.py's
    `output.unlink()`), which is why the customer saw no flat file at all.
    """

    def _write_archive(self, tar_path, docs: dict[str, dict]) -> None:
        with tarfile.open(tar_path, "w") as tf:
            for name, doc in docs.items():
                data = json.dumps(doc).encode()
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))

    def test_gnu_config_license_declared_merges_and_validates(self, tmp_path):
        recipe_doc = make_recipe_doc([], pn="gnu-config", ns="http://spdx.org/spdxdocs/recipe-gnu-config-1111")
        package_doc = make_package_doc(
            pkg="gnu-config", pn="gnu-config", recipe_ns="http://spdx.org/spdxdocs/recipe-gnu-config-1111"
        )
        package_doc["packages"][0]["licenseDeclared"] = "GPL-3.0-with-autoconf-exception"
        image_doc = make_image_doc(package_doc)

        tar_path = tmp_path / "core-image-minimal.spdx.tar"
        self._write_archive(
            tar_path,
            {
                "core-image-minimal.spdx.json": image_doc,
                "packages/gnu-config.spdx.json": package_doc,
                "recipes/recipe-gnu-config.spdx.json": recipe_doc,
            },
        )
        out_path = tmp_path / "out.spdx.json"

        main([str(tar_path), "-o", str(out_path)])

        assert out_path.exists(), "merge must not delete output on a false validation failure"
        merged = json.loads(out_path.read_text())
        by_name = {p["name"]: p for p in merged["packages"]}
        assert by_name["gnu-config"]["licenseDeclared"] == "GPL-3.0-only WITH Autoconf-exception-2.0"

        errors = validate_spdx_file(str(out_path))
        assert errors == []

    def test_license_concluded_is_also_normalized(self, tmp_path):
        # licenseConcluded went straight through unnormalized (merge.py only
        # resolved licenseDeclared), so a deprecated ID there would trip the
        # same validation failure the licenseDeclared fix didn't cover.
        recipe_doc = make_recipe_doc([], pn="gnu-config", ns="http://spdx.org/spdxdocs/recipe-gnu-config-2222")
        package_doc = make_package_doc(
            pkg="gnu-config", pn="gnu-config", recipe_ns="http://spdx.org/spdxdocs/recipe-gnu-config-2222"
        )
        package_doc["packages"][0]["licenseConcluded"] = "GPL-3.0-with-autoconf-exception"
        image_doc = make_image_doc(package_doc)

        tar_path = tmp_path / "core-image-minimal.spdx.tar"
        self._write_archive(
            tar_path,
            {
                "core-image-minimal.spdx.json": image_doc,
                "packages/gnu-config.spdx.json": package_doc,
                "recipes/recipe-gnu-config.spdx.json": recipe_doc,
            },
        )
        out_path = tmp_path / "out.spdx.json"

        main([str(tar_path), "-o", str(out_path)])

        assert out_path.exists()
        merged = json.loads(out_path.read_text())
        by_name = {p["name"]: p for p in merged["packages"]}
        assert by_name["gnu-config"]["licenseConcluded"] == "GPL-3.0-only WITH Autoconf-exception-2.0"

        errors = validate_spdx_file(str(out_path))
        assert errors == []
