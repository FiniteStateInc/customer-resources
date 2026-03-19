# Copyright (c) 2024 Finite State, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""PDF renderer using weasyprint HTML→PDF conversion."""

import logging
import tempfile
from pathlib import Path

from fs_report.models import Recipe, ReportData
from fs_report.renderers.html_renderer import HTMLRenderer


class PDFRenderer:
    """Renderer for PDF output format using weasyprint."""

    def __init__(self) -> None:
        """Initialize the PDF renderer."""
        self.logger = logging.getLogger(__name__)
        self._html_renderer = HTMLRenderer()

    def render(
        self, recipe: Recipe, report_data: ReportData, output_path: Path
    ) -> Path:
        """Render the report to PDF via HTML intermediate."""
        import weasyprint  # type: ignore[import-untyped]

        # Render HTML to a temp file first
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            self._html_renderer.render(recipe, report_data, tmp_path)
            weasyprint.HTML(filename=str(tmp_path)).write_pdf(str(output_path))
        finally:
            tmp_path.unlink(missing_ok=True)

        return output_path
