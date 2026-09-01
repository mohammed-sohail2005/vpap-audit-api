from datetime import datetime, timezone

from vpap.enrichment.models import (
    CompensatingControl,
    EvidenceValue,
    FindingEvidence,
)


def test_finding_evidence() -> None:
    now = datetime.now(timezone.utc)

    evidence = FindingEvidence(
        # ---------------------------------------------------------
        # Provenance
        # ---------------------------------------------------------
        schema_version="1.0",
        tenant_id="synthetic-tenant",
        source_system="WIZ",
        source_instance_id="synthetic-wiz-instance",
        source_finding_id="wiz-vf-000001",

        adapter_name="wiz_enrichment_adapter",
        adapter_version="1.0.0",

        enrichment_run_id="run-test-001",
        evidence_snapshot_id="snapshot-test-001",
        evidence_snapshot_sha256="abc123",

        # ---------------------------------------------------------
        # Finding
        # ---------------------------------------------------------
        finding_instance_id="wiz-vf-000001",
        cve_id="CVE-2099-20001",
        asset_id="wiz-asset-000001",
        cvss_base=8.8,

        # ---------------------------------------------------------
        # EPSS
        # ---------------------------------------------------------
        epss_probability=EvidenceValue[float](
            value=0.72,
            status="KNOWN",
            source="FIRST_EPSS",
            source_timestamp=now,
            retrieved_at=now,
            confidence="HIGH",
        ),

        epss_percentile=EvidenceValue[float](
            value=94.3,
            status="KNOWN",
            source="FIRST_EPSS",
            source_timestamp=now,
            retrieved_at=now,
            confidence="HIGH",
        ),

        # ---------------------------------------------------------
        # KEV
        # ---------------------------------------------------------
        kev_status=EvidenceValue[bool](
            value=False,
            status="KNOWN",
            source="CISA_KEV",
            source_timestamp=now,
            retrieved_at=now,
            confidence="HIGH",
        ),

        # ---------------------------------------------------------
        # Wiz evidence not queried yet
        # ---------------------------------------------------------
        internet_exposure=EvidenceValue[bool](
            value=None,
            status="UNKNOWN",
            reason_code="FIELD_NOT_REQUESTED",
            source="NOT_QUERIED",
            retrieved_at=now,
            confidence="LOW",
        ),

        runtime_applicability=EvidenceValue[bool](
            value=None,
            status="UNKNOWN",
            reason_code="FIELD_NOT_REQUESTED",
            source="NOT_QUERIED",
            retrieved_at=now,
            confidence="LOW",
        ),

        attack_path_reachable=EvidenceValue[bool](
            value=None,
            status="UNKNOWN",
            reason_code="FIELD_NOT_REQUESTED",
            source="NOT_QUERIED",
            retrieved_at=now,
            confidence="LOW",
        ),

        # ---------------------------------------------------------
        # Business Criticality
        # ---------------------------------------------------------
        business_criticality=EvidenceValue[str](
            value="HIGH",
            raw_value="Tier-2",
            mapping_version="business-tier-map-1.0",
            status="KNOWN",
            source="WIZ_TAG",
            source_field="BusinessCriticality",
            retrieved_at=now,
            confidence="MEDIUM",
        ),

        # ---------------------------------------------------------
        # Compensating controls not queried
        # ---------------------------------------------------------
        compensating_controls=EvidenceValue[
            list[CompensatingControl]
        ](
            value=None,
            status="UNKNOWN",
            reason_code="CONTROL_SOURCES_NOT_CONNECTED",
            source="NOT_QUERIED",
            retrieved_at=now,
            confidence="LOW",
        ),
    )

    assert evidence.finding_instance_id == "wiz-vf-000001"
    assert evidence.cve_id == "CVE-2099-20001"

    assert evidence.epss_probability.value == 0.72
    assert evidence.epss_probability.status == "KNOWN"

    assert evidence.kev_status.value is False
    assert evidence.kev_status.status == "KNOWN"

    assert evidence.internet_exposure.value is None
    assert evidence.internet_exposure.status == "UNKNOWN"
    assert evidence.internet_exposure.reason_code == "FIELD_NOT_REQUESTED"
    assert evidence.internet_exposure.source == "NOT_QUERIED"

    assert evidence.business_criticality.value == "HIGH"
    assert evidence.business_criticality.raw_value == "Tier-2"
    assert (
        evidence.business_criticality.mapping_version
        == "business-tier-map-1.0"
    )

    assert evidence.compensating_controls.value is None
    assert evidence.compensating_controls.status == "UNKNOWN"
    assert (
        evidence.compensating_controls.reason_code
        == "CONTROL_SOURCES_NOT_CONNECTED"
    )