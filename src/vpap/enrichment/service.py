import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any
from vpap.domain.finding import Finding
from vpap.enrichment.epss import EPSSResult, get_epss
from vpap.enrichment.kev import KEVCatalogue, is_in_kev
from vpap.enrichment.models import (
    CompensatingControl,
    EvidenceValue,
    FindingEvidence,
)


# ---------------------------------------------------------
# Contract / adapter metadata
# ---------------------------------------------------------

SCHEMA_VERSION = "1.0"

ADAPTER_NAME = "wiz_enrichment_adapter"
ADAPTER_VERSION = "1.0.0"

SOURCE_SYSTEM = "WIZ"

# Synthetic POC values for now.
# These will eventually come from the real tenant/configuration.
DEFAULT_POC_SOURCE_INSTANCE_ID = "synthetic-wiz-instance"

BUSINESS_CRITICALITY_MAPPING_VERSION = "business-tier-map-1.0"


# ---------------------------------------------------------
# Helper: create a unique ID
# ---------------------------------------------------------

def generate_id(prefix: str) -> str:
    """
    Generate a unique identifier for an enrichment object.

    Example:
        snapshot-abc123...
        run-abc123...
    """
    return f"{prefix}-{uuid.uuid4().hex}"


# ---------------------------------------------------------
# Helper: create UNKNOWN evidence
# ---------------------------------------------------------

def build_unknown_evidence(
    source: str,
    reason_code: str,
    confidence: str = "LOW",
    now: datetime | None = None,
) -> EvidenceValue:
    """
    Create an evidence value when we do not have enough
    trustworthy information to determine the actual value.

    UNKNOWN is different from False or 0.

    reason_code explains WHY the value is unavailable.
    """

    if now is None:
        now = datetime.now(timezone.utc)

    return EvidenceValue(
        value=None,
        status="UNKNOWN",
        reason_code=reason_code,
        source=source,
        retrieved_at=now,
        confidence=confidence,
    )


# ---------------------------------------------------------
# Helper: calculate evidence snapshot hash
# ---------------------------------------------------------

def calculate_snapshot_sha256(
    evidence_data: dict[str, Any],
) -> str:
    """
    Calculate a deterministic SHA-256 hash for the evidence
    snapshot.

    The data is serialized in a canonical form so that the same
    evidence produces the same hash.
    """

    canonical_json = json.dumps(
        evidence_data,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )

    return hashlib.sha256(
        canonical_json.encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------
# Main enrichment function
# ---------------------------------------------------------

def enrich_finding(
    finding: Finding,
    tenant_id: str,
    enrichment_run_id: str | None = None,
    source_instance_id: str = DEFAULT_POC_SOURCE_INSTANCE_ID,
    finding_instance_id: str | None = None,
    epss_result: EPSSResult | None = None,
) ->  tuple[FindingEvidence, KEVCatalogue | None]:
    """
    Enrich one canonical Finding with the evidence currently
    available to us.

    enrichment_run_id:
        Identifies the enrichment batch/job.

        If this function is called directly without one, a new
        run ID is generated. When processing a batch, the caller
        should generate ONE run ID and pass it to every finding.
    """

    # ---------------------------------------------------------
    # 0. Enrichment run
    # ---------------------------------------------------------

    if enrichment_run_id is None:
        enrichment_run_id = generate_id("run")

    # One retrieval timestamp for this finding's enrichment.
    now = datetime.now(timezone.utc)

    # Every finding receives its own evidence snapshot.
    evidence_snapshot_id = generate_id("snapshot")

    # ---------------------------------------------------------
    # 1. Basic finding information
    # ---------------------------------------------------------

    finding_instance_id = (
        finding_instance_id or finding.source_finding_id
    )
    cve_id = finding.cve_id
    asset_id = finding.asset_id
    cvss_base = finding.cvss_base

    # ---------------------------------------------------------
    # 2. EPSS enrichment
    # ---------------------------------------------------------

    if epss_result is None:
        epss_result = get_epss(cve_id)

    if epss_result.status == "FOUND":

        epss_probability = EvidenceValue[float](
            value=epss_result.epss,
            status="KNOWN",
            source="FIRST_EPSS",
            source_timestamp=epss_result.source_timestamp,
            retrieved_at=now,
            confidence="HIGH",
        )

        epss_percentile = EvidenceValue[float](
            value=epss_result.percentile,
            status="KNOWN",
            source="FIRST_EPSS",
            source_timestamp=epss_result.source_timestamp,
            retrieved_at=now,
            confidence="HIGH",
        )

    elif epss_result.status == "NOT_FOUND":

        epss_probability = build_unknown_evidence(
            source="FIRST_EPSS",
            reason_code="CVE_NOT_SCORED",
            now=now,
        )

        epss_percentile = build_unknown_evidence(
            source="FIRST_EPSS",
            reason_code="CVE_NOT_SCORED",
            now=now,
        )

    else:
        # API/request/response failure.
        # Do NOT convert a connector failure into UNKNOWN.
        epss_probability = EvidenceValue[float](
            value=None,
            status="ERROR",
            reason_code=epss_result.reason_code or "CONNECTOR_ERROR",
            source="FIRST_EPSS",
            source_timestamp=None,
            retrieved_at=now,
            confidence="LOW",
        )

        epss_percentile = EvidenceValue[float](
            value=None,
            status="ERROR",
            reason_code=epss_result.reason_code or "CONNECTOR_ERROR",
            source="FIRST_EPSS",
            source_timestamp=None,
            retrieved_at=now,
            confidence="LOW",
        )
   # ---------------------------------------------------------
    # 3. CISA KEV enrichment
    # ---------------------------------------------------------

    kev_result, refreshed_catalogue = is_in_kev(cve_id)

    if kev_result.status == "FOUND":

        kev_status = EvidenceValue[bool](
            value=True,
            status="KNOWN",
            source="CISA_KEV",
            source_timestamp=kev_result.source_timestamp,
            retrieved_at=now,
            confidence="HIGH",
        )

    elif kev_result.status == "NOT_FOUND":

        kev_status = EvidenceValue[bool](
            value=False,
            status="KNOWN",
            source="CISA_KEV",
            source_timestamp=kev_result.source_timestamp,
            retrieved_at=now,
            confidence="HIGH",
        )

    elif kev_result.status == "STALE":

        kev_status = EvidenceValue[bool](
            value=None,
            status="STALE",
            reason_code=kev_result.reason_code or "SOURCE_STALE",
            source="CISA_KEV",
            source_timestamp=kev_result.source_timestamp,
            retrieved_at=now,
            confidence="LOW",
        )

    else:

        kev_status = EvidenceValue[bool](
            value=None,
            status="ERROR",
            reason_code=kev_result.reason_code or "CONNECTOR_ERROR",
            source="CISA_KEV",
            source_timestamp=kev_result.source_timestamp,
            retrieved_at=now,
            confidence="LOW",
        )
        # ---------------------------------------------------------
    # 4. Business Criticality
    # ---------------------------------------------------------

    # Business criticality is not part of the validated canonical
    # Finding contract yet. Do not inspect scanner-specific fields.
    business_criticality = build_unknown_evidence(
        source="NOT_QUERIED",
        reason_code="FIELD_NOT_AVAILABLE",
        now=now,
    )
    # ---------------------------------------------------------
    # 5. Internet exposure
    # ---------------------------------------------------------
    #
    # We have NOT implemented the required Wiz Security Graph
    # query yet.
    #
    # Therefore we must NOT claim the source is WIZ.
    #

    internet_exposure = build_unknown_evidence(
        source="NOT_QUERIED",
        reason_code="FIELD_NOT_REQUESTED",
        now=now,
    )

    # ---------------------------------------------------------
    # 6. Runtime applicability
    # ---------------------------------------------------------
    #
    # Runtime evidence has not been queried yet.
    #

    runtime_applicability = build_unknown_evidence(
        source="NOT_QUERIED",
        reason_code="FIELD_NOT_REQUESTED",
        now=now,
    )

    # ---------------------------------------------------------
    # 7. Attack path reachability
    # ---------------------------------------------------------
    #
    # Wiz Security Graph attack-path query has not been
    # implemented yet.
    #

    attack_path_reachable = build_unknown_evidence(
        source="NOT_QUERIED",
        reason_code="FIELD_NOT_REQUESTED",
        now=now,
    )

    # ---------------------------------------------------------
    # 8. Compensating controls
    # ---------------------------------------------------------
    #
    # We have not connected any control sources yet.
    #
    # IMPORTANT:
    # value=None means "we did not determine this".
    #
    # Later:
    #
    # value=[] + status="KNOWN"
    #
    # will mean "we checked and found no controls".
    #

    compensating_controls = EvidenceValue[
        list[CompensatingControl]
    ](
        value=None,
        status="UNKNOWN",
        reason_code="CONTROL_SOURCES_NOT_CONNECTED",
        source="NOT_QUERIED",
        source_timestamp=None,
        retrieved_at=now,
        confidence="LOW",
    )

    # ---------------------------------------------------------
    # 9. Create the evidence data used for hashing
    # ---------------------------------------------------------
    #
    # We intentionally exclude the SHA itself because the hash
    # must be calculated FROM the evidence, not from itself.
    #

    snapshot_data = {
        "schema_version": SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "source_system": finding.source_system,
        "source_instance_id": source_instance_id,
        "source_finding_id": finding_instance_id,
        "adapter_name": ADAPTER_NAME,
        "adapter_version": ADAPTER_VERSION,
        "enrichment_run_id": enrichment_run_id,
        "evidence_snapshot_id": evidence_snapshot_id,
        "finding_instance_id": finding_instance_id,
        "cve_id": cve_id,
        "asset_id": asset_id,
        "cvss_base": cvss_base,
        "epss_probability": epss_probability.model_dump(
            mode="json"
        ),
        "epss_percentile": epss_percentile.model_dump(
            mode="json"
        ),
        "kev_status": kev_status.model_dump(
            mode="json"
        ),
        "internet_exposure": internet_exposure.model_dump(
            mode="json"
        ),
        "runtime_applicability": (
            runtime_applicability.model_dump(mode="json")
        ),
        "attack_path_reachable": (
            attack_path_reachable.model_dump(mode="json")
        ),
        "business_criticality": (
            business_criticality.model_dump(mode="json")
        ),
        "compensating_controls": (
            compensating_controls.model_dump(mode="json")
        ),
    }

    evidence_snapshot_sha256 = calculate_snapshot_sha256(
        snapshot_data
    )

    # ---------------------------------------------------------
    # 10. Build final evidence object
    # ---------------------------------------------------------

    return (
        FindingEvidence(
            # Provenance
            schema_version=SCHEMA_VERSION,
            tenant_id=tenant_id,
            source_system=finding.source_system,
            source_instance_id=source_instance_id,
            source_finding_id=finding_instance_id,
            adapter_name=ADAPTER_NAME,
            adapter_version=ADAPTER_VERSION,
            enrichment_run_id=enrichment_run_id,
            evidence_snapshot_id=evidence_snapshot_id,
            evidence_snapshot_sha256=evidence_snapshot_sha256,

            # Finding
            finding_instance_id=finding_instance_id,
            cve_id=cve_id,
            asset_id=asset_id,
            cvss_base=cvss_base,

            # Evidence
            epss_probability=epss_probability,
            epss_percentile=epss_percentile,
            kev_status=kev_status,
            internet_exposure=internet_exposure,
            runtime_applicability=runtime_applicability,
            attack_path_reachable=attack_path_reachable,
            business_criticality=business_criticality,
            compensating_controls=compensating_controls,
        ), refreshed_catalogue,
    )
