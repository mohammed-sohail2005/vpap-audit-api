"""
Generic Excel reader for VPAP ingestion.

This module is responsible only for reading Excel rows.

It does NOT:
- validate vulnerability data,
- normalize source fields,
- determine the source system,
- enrich CVEs,
- calculate risk,
- modify the source data.
"""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import openpyxl


# This function is designed to read data from an Excel (.xlsx) file.
# It processes the file row by row, treating the first row as column headers and yielding each subsequent data row as a dictionary where keys are column names.
# It focuses solely on reading and structuring the data, without performing any validation or transformation.
def read_excel_file(file_path: str | Path) -> Iterator[dict[str, Any]]:
    """
    Read an .xlsx file and yield each data row as a dictionary.

    The first row is treated as the column header.

    Each subsequent row is returned as:

        {
            "column_name": value,
            ...
        }

    The raw values are read as supplied by openpyxl.
    No field-name normalization or value transformation is performed here.

    Raises:
        FileNotFoundError: If the Excel file does not exist.
        ValueError: If the file is not an .xlsx file.
    """

    # Converts the input file_path to a Path object for consistent file system operations.
    path = Path(file_path)

    # Checks if the specified file actually exists on the file system.
    # If not, it raises a FileNotFoundError to indicate the problem.
    if not path.exists():
        raise FileNotFoundError(f"Excel file not found: {path}")

    # Verifies that the file has an .xlsx extension (case-insensitive).
    # If the extension is not .xlsx, it raises a ValueError, as this reader is specifically designed for this format.
    if path.suffix.lower() != ".xlsx":
        raise ValueError(
            f"Expected an .xlsx file, received: {path.name}"
        )

    # Loads the Excel workbook using openpyxl.
    # `read_only=True` optimizes memory usage for reading large files.
    # `data_only=True` ensures that cell values are read as their calculated results, rather than formulas.
    workbook = openpyxl.load_workbook(
        filename=path,
        read_only=True,
        data_only=True,
    )

    # Uses a try-finally block to ensure the workbook is always closed, releasing file handles and resources.
    try:
        # Gets the active worksheet from the workbook.
        worksheet = workbook.active

        # Creates an iterator over the rows of the worksheet, returning only cell values.
        rows = worksheet.iter_rows(values_only=True)

        # Attempts to read the first row, which is expected to contain the column headers.
        # If the worksheet is empty (StopIteration), it means there are no headers or data.
        try:
            headers = next(rows)
        except StopIteration:
            return

        # If the headers row is empty (e.g., a row exists but all cells are blank), there's no meaningful data to process, so the function returns.
        if not headers:
            return

        # Converts the headers tuple into a list to preserve the column names exactly.
        # Preserve the column names exactly as they appear in the source.
        header_names = list(headers)

        # Iterates through the remaining rows (data rows) of the worksheet.
        for row in rows:
            # For each row, it creates a dictionary by zipping the header names with the row's values.
            # `strict=False` is used to handle cases where the number of headers and values might not match, preventing a ValueError if a row has fewer values than headers.
            # Preserve source values exactly as returned by openpyxl.
            yield dict(zip(header_names, row, strict=False))

    finally:
        workbook.close()