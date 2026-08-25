"""
Canonical representation of a source record that could not be
converted into a VPAP Finding.
"""

from typing import Any

from pydantic import BaseModel


class RejectedRecord(BaseModel):
    """
    Preserves the original source record and records why ingestion
    could not produce a canonical Finding.
    """

    source_system: str
    raw_record: dict[str, Any]
    reason: str