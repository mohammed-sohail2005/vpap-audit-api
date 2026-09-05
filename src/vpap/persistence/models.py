"""
Persistence models for the VPAP backend API.

These models represent data owned by the ingestion/validation
pipeline that needs to be persisted by the backend.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class IngestionBatchCreate(BaseModel):
    """
    Data required to create an ingestion_batch.
    """

    tenant_id: str
    source_system: str
    source_type: str
    source_reference: str | None = None
    source_file_name: str | None = None

    total_records: int = 0
    accepted_records: int = 0
    rejected_records: int = 0
    validation_failed_records: int = 0

    status: str = "RECEIVED"
    error_message: str | None = None


class FindingInstanceCreate(BaseModel):
    """
    Data required to persist one finding_instance.
    """

    tenant_id: str
    idempotency_key: str

    source_system: str
    source_finding_id: str

    cve_id: str
    asset_id: str
    package_id: str | None = None

    cvss_base: float | None = None
    cvss_vector: str | None = None

    description: str | None = None

    business_service_id: str | None = None
    internet_exposed: bool | None = None

    first_detected_at: datetime | None = None

    status: str = "VALID"


class DeadLetterCreate(BaseModel):
    """
    Data required to create a dead_letter record.
    """

    tenant_id: str
    source_system: str

    batch_id: str | None = None
    source_finding_id: str | None = None

    stage: str

    error_code: str
    error_message: str

    raw_record: dict[str, Any] | None = None

    status: str = "OPEN"
    retry_count: int = 0

from vpap.domain.finding import Finding


def finding_to_persistence_model(
    finding: Finding,
    tenant_id: str,
) -> FindingInstanceCreate:
    """
    Convert a canonical Finding into the payload required
    to persist a finding_instance.
    """

    return FindingInstanceCreate(
        tenant_id=tenant_id,
        idempotency_key=finding.idempotency_key(),
        source_system=finding.source_system,
        source_finding_id=finding.source_finding_id,
        cve_id=finding.cve_id,
        asset_id=finding.asset_id,
        package_id=finding.package_id,
        cvss_base=finding.cvss_base,
        cvss_vector=finding.cvss_vector,
        description=finding.description,
        business_service_id=finding.business_service_id,
        internet_exposed=finding.internet_exposed,
        first_detected_at=finding.first_detected_at,
    )