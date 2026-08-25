"""
Result returned by the VPAP ingestion processor.
"""
from typing import Any
from pydantic import BaseModel

from vpap.domain.finding import Finding
from vpap.domain.rejected_record import RejectedRecord


class IngestionResult(BaseModel):
    """
    Separates successfully mapped findings from records that
    could not be mapped.
    """
    accepted_records: list[tuple[Finding, dict[str, Any]]]
    rejected_records: list[RejectedRecord]