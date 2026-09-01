from datetime import datetime
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel


T = TypeVar("T")


class EvidenceValue(BaseModel, Generic[T]):
    """
    Represents one piece of evidence and its provenance.

    UNKNOWN does not mean False or 0.
    It means we do not have trustworthy evidence to determine
    the value.
    """

    value: T | None = None

    # Original value received from the source.
    # Useful when VPAP normalizes the source value.
    raw_value: Any | None = None

    # Version of the mapping/configuration used to normalize
    # the source value.
    mapping_version: str | None = None

    status: Literal["KNOWN", "UNKNOWN", "STALE", "ERROR"]

    # Explains why evidence is unavailable when status is
    # UNKNOWN, STALE, or ERROR.
    reason_code: str | None = None

    source: str

    # Exact source field/query that produced the evidence,
    # when applicable.
    source_field: str | None = None

    source_timestamp: datetime | None = None

    retrieved_at: datetime

    confidence: Literal["HIGH", "MEDIUM", "LOW"]


class CompensatingControl(BaseModel):
    """
    Represents one verified compensating control.
    """

    type: str
    status: str
    scope: str | None = None
    source: str
    verified_at: datetime | None = None
    relationship: str | None = None


class FindingEvidence(BaseModel):
    """
    Complete evidence record for one vulnerability finding.
    """

    # Schema/provenance information
    schema_version: str
    tenant_id: str
    source_system: str
    source_instance_id: str
    source_finding_id: str

    adapter_name: str
    adapter_version: str

    enrichment_run_id: str
    evidence_snapshot_id: str
    evidence_snapshot_sha256: str

    # Core finding information
    finding_instance_id: str
    cve_id: str
    asset_id: str
    cvss_base: float | None

    # Evidence
    epss_probability: EvidenceValue[float]
    epss_percentile: EvidenceValue[float]
    kev_status: EvidenceValue[bool]

    internet_exposure: EvidenceValue[bool]
    runtime_applicability: EvidenceValue[bool]
    attack_path_reachable: EvidenceValue[bool]

    business_criticality: EvidenceValue[str]

    compensating_controls: EvidenceValue[
        list[CompensatingControl]
    ]