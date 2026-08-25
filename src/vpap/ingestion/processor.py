"""
VPAP ingestion processor.

The processor coordinates:

    source file
        ↓
    Excel reader
        ↓
    raw source record
        ↓
    explicitly supplied source system
        ↓
    source registry
        ↓
    source-specific mapper
        ↓
    canonical Finding
        OR
    rejected record

The processor does not guess the source system and does not modify
the original raw source records.
"""

from pathlib import Path
from typing import Any

from vpap.connectors.registry import get_source_config, load_mapper
from vpap.domain.finding import Finding
from vpap.domain.ingestion_result import IngestionResult
from vpap.domain.rejected_record import RejectedRecord
from vpap.ingestion.excel_reader import read_excel_file


def process_source_data(
    file_path: str | Path,
    source_system: str,
) -> IngestionResult:
    """
    Process source data into canonical VPAP Findings.

    Each source record produces one of two outcomes:

    - an accepted canonical Finding together with its original
      raw source record, or
    - a RejectedRecord containing the original source record
      and the reason it could not be mapped.

    Args:
        file_path:
            Path to the source Excel file.

        source_system:
            Explicit source identifier, e.g. "WIZ".

    Returns:
        IngestionResult containing accepted and rejected records.

    Raises:
        ValueError:
            If the source system is not registered or its mapper
            configuration is invalid.
    """

    source_key = source_system.upper()

    source_config = get_source_config(source_key)

    mapper = load_mapper(source_config["mapper"])

    accepted_records: list[
        tuple[Finding, dict[str, Any]]
    ] = []

    rejected_records: list[RejectedRecord] = []

    for raw_record in read_excel_file(file_path):
        try:
            finding = mapper(raw_record)

            accepted_records.append(
                (finding, raw_record)
            )

        except (TypeError, ValueError) as exc:
            rejected_records.append(
                RejectedRecord(
                    source_system=source_key,
                    raw_record=raw_record,
                    reason=str(exc),
                )
            )

    return IngestionResult(
        accepted_records=accepted_records,
        rejected_records=rejected_records,
    )