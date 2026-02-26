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

"""CSV renderer for exporting data as CSV files."""

import logging
from pathlib import Path
from typing import Any

import pandas as pd


class CSVRenderer:
    """Renderer for CSV output format."""

    def __init__(self) -> None:
        """Initialize the CSV renderer."""
        self.logger = logging.getLogger(__name__)

    def render(self, data: Any, output_path: Path) -> None:
        """Render data as CSV file."""
        try:
            # Convert data to DataFrame if it's not already
            if isinstance(data, pd.DataFrame):
                df = data
            else:
                df = pd.DataFrame(data)

            # Sanitize cells that could be interpreted as formulas by spreadsheet apps
            _FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

            def _sanitize_cell(val: object) -> object:
                if isinstance(val, str) and val and val[0] in _FORMULA_PREFIXES:
                    return "'" + val
                return val

            df = df.map(_sanitize_cell)

            # Export to CSV
            df.to_csv(output_path, index=False, encoding="utf-8")
            self.logger.debug(f"CSV exported to: {output_path}")

        except Exception as e:
            self.logger.error(f"Error generating CSV: {e}")
            raise
