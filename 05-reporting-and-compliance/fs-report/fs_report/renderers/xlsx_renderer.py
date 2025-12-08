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

"""XLSX renderer for exporting data as Excel files."""

import logging
from pathlib import Path
from typing import Any

import pandas as pd


class XLSXRenderer:
    """Renderer for XLSX output format."""

    def __init__(self) -> None:
        """Initialize the XLSX renderer."""
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def safe_sheet_name(name: str) -> str:
        """Ensure Excel worksheet name is <= 31 chars."""
        return name[:28] + "..." if len(name) > 31 else name

    def render(self, data: Any, output_path: Path, sheet_name: str = "Data") -> None:
        """Render data as XLSX file."""
        try:
            # Convert data to DataFrame if it's not already
            if isinstance(data, pd.DataFrame):
                df = data
            else:
                df = pd.DataFrame(data)

            # Truncate sheet name if necessary
            safe_name = self.safe_sheet_name(sheet_name)

            # Export to XLSX
            with pd.ExcelWriter(output_path, engine="xlsxwriter") as writer:
                df.to_excel(writer, sheet_name=safe_name, index=False)

                # Get the workbook and worksheet objects
                workbook = writer.book
                worksheet = writer.sheets[safe_name]

                # Add some formatting
                header_format = workbook.add_format(
                    {
                        "bold": True,
                        "text_wrap": True,
                        "valign": "top",
                        "fg_color": "#D7E4BC",
                        "border": 1,
                    }
                )

                # Write the column headers with the defined format
                for col_num, value in enumerate(df.columns.values):
                    worksheet.write(0, col_num, value, header_format)

                # Set column widths
                for col_num, column in enumerate(df.columns):
                    max_length = max(
                        df[column].astype(str).map(len).max(), len(str(column))
                    )
                    worksheet.set_column(col_num, col_num, min(max_length + 2, 50))

            self.logger.debug(f"XLSX exported to: {output_path}")

        except Exception as e:
            self.logger.error(f"Error generating XLSX: {e}")
            raise
