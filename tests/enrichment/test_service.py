from unittest.mock import Mock, patch

from vpap.domain.finding import Finding
from vpap.enrichment.service import enrich_finding
def test_enrich_finding() -> None:
    # This represents the normalized Finding that will eventually
    # come from the ingestion stage.
    finding = Finding(
        source_system="WIZ",
        source_finding_id="wiz-vf-000001",
        cve_id="CVE-2099-20001",
        asset_id="wiz-asset-000001",
        cvss_base=8.8,
    )
    # Use a fixed run ID for the test so we can verify that it is
    # preserved in the resulting evidence.
    run_id = "test-enrichment-run-001"

    fake_epss_result = Mock()

    fake_epss_result.status = "FOUND"
    fake_epss_result.epss = 0.72
    fake_epss_result.percentile = 0.943
    fake_epss_result.source_timestamp = None
    fake_epss_result.reason_code = None
    fake_kev_result = Mock()

    fake_kev_result.status = "FOUND"
    fake_kev_result.source_timestamp = None
    fake_kev_result.reason_code = None
    with patch(
    "vpap.enrichment.service.get_epss",
        return_value=fake_epss_result,
    ), patch(
        "vpap.enrichment.service.is_in_kev",
        return_value=fake_kev_result,
    ):
        evidence = enrich_finding(
            finding,
            enrichment_run_id=run_id,
        )

    # ---------------------------------------------------------
    # Core finding information
    # ---------------------------------------------------------

    assert evidence.finding_instance_id == "wiz-vf-000001"
    assert evidence.cve_id == "CVE-2099-20001"
    assert evidence.asset_id == "wiz-asset-000001"
    assert evidence.cvss_base == 8.8

    # ---------------------------------------------------------
    # Provenance
    # ---------------------------------------------------------

    assert evidence.schema_version == "1.0"
    assert evidence.tenant_id
    assert evidence.source_system == "WIZ"
    assert evidence.source_instance_id
    assert evidence.source_finding_id == "wiz-vf-000001"

    assert evidence.adapter_name
    assert evidence.adapter_version

    assert evidence.enrichment_run_id == run_id

    # Each finding must have its own snapshot.
    assert evidence.evidence_snapshot_id
    assert evidence.evidence_snapshot_id != "synthetic-test-snapshot"

    # A SHA-256 hash must be present.
    assert evidence.evidence_snapshot_sha256
    assert len(evidence.evidence_snapshot_sha256) == 64

    # ---------------------------------------------------------
    # EPSS
    # ---------------------------------------------------------

    assert evidence.epss_probability.value == 0.72
    assert evidence.epss_probability.status == "KNOWN"
    assert evidence.epss_probability.source == "FIRST_EPSS"

    assert evidence.epss_percentile.value == 0.943
    assert evidence.epss_percentile.status == "KNOWN"

    # ---------------------------------------------------------
    # KEV
    # ---------------------------------------------------------

    assert evidence.kev_status.value is True
    assert evidence.kev_status.status == "KNOWN"
    assert evidence.kev_status.source == "CISA_KEV"

    # ---------------------------------------------------------
    # Wiz evidence that has NOT been queried
    # ---------------------------------------------------------

    assert evidence.internet_exposure.value is None
    assert evidence.internet_exposure.status == "UNKNOWN"
    assert evidence.internet_exposure.reason_code == "FIELD_NOT_REQUESTED"
    assert evidence.internet_exposure.source == "NOT_QUERIED"

    assert evidence.runtime_applicability.value is None
    assert evidence.runtime_applicability.status == "UNKNOWN"
    assert evidence.runtime_applicability.reason_code == "FIELD_NOT_REQUESTED"
    assert evidence.runtime_applicability.source == "NOT_QUERIED"

    assert evidence.attack_path_reachable.value is None
    assert evidence.attack_path_reachable.status == "UNKNOWN"
    assert evidence.attack_path_reachable.reason_code == "FIELD_NOT_REQUESTED"
    assert evidence.attack_path_reachable.source == "NOT_QUERIED"

    # ---------------------------------------------------------
    # Business Criticality
    # ---------------------------------------------------------

    # This finding has no BusinessCriticality tag, so it should
    # remain UNKNOWN rather than being inferred.
    assert evidence.business_criticality.value is None
    assert evidence.business_criticality.status == "UNKNOWN"
    assert evidence.business_criticality.reason_code == "FIELD_NOT_AVAILABLE"
    assert evidence.business_criticality.source == "NOT_QUERIED"
    # ---------------------------------------------------------
    # Compensating controls
    # ---------------------------------------------------------

    assert evidence.compensating_controls.value is None
    assert evidence.compensating_controls.status == "UNKNOWN"
    assert (
        evidence.compensating_controls.reason_code
        == "CONTROL_SOURCES_NOT_CONNECTED"
    )
    assert evidence.compensating_controls.source == "NOT_QUERIED"
def make_test_finding() -> Finding:
    return Finding(
        source_system="WIZ",
        source_finding_id="wiz-vf-000001",
        cve_id="CVE-2099-20001",
        asset_id="wiz-asset-000001",
        cvss_base=8.8,
    )
def make_fake_epss_result() -> Mock:
    result = Mock()

    result.status = "FOUND"
    result.epss = 0.72
    result.percentile = 0.943
    result.source_timestamp = None
    result.reason_code = None

    return result
def test_service_maps_kev_not_found() -> None:
    finding = make_test_finding()

    fake_epss_result = make_fake_epss_result()

    fake_kev_result = Mock()
    fake_kev_result.status = "NOT_FOUND"
    fake_kev_result.source_timestamp = None
    fake_kev_result.reason_code = None

    with patch(
        "vpap.enrichment.service.get_epss",
        return_value=fake_epss_result,
    ), patch(
        "vpap.enrichment.service.is_in_kev",
        return_value=fake_kev_result,
    ):
        evidence = enrich_finding(
            finding,
            enrichment_run_id="test-run-not-found",
        )

    assert evidence.kev_status.value is False
    assert evidence.kev_status.status == "KNOWN"
    assert evidence.kev_status.source == "CISA_KEV"
def test_service_maps_kev_stale() -> None:
    finding = make_test_finding()

    fake_epss_result = make_fake_epss_result()

    fake_kev_result = Mock()
    fake_kev_result.status = "STALE"
    fake_kev_result.source_timestamp = None
    fake_kev_result.reason_code = "SOURCE_STALE"

    with patch(
        "vpap.enrichment.service.get_epss",
        return_value=fake_epss_result,
    ), patch(
        "vpap.enrichment.service.is_in_kev",
        return_value=fake_kev_result,
    ):
        evidence = enrich_finding(
            finding,
            enrichment_run_id="test-run-stale",
        )

    assert evidence.kev_status.value is None
    assert evidence.kev_status.status == "STALE"
    assert evidence.kev_status.reason_code == "SOURCE_STALE"
    assert evidence.kev_status.source == "CISA_KEV"
def test_service_maps_kev_error() -> None:
    finding = make_test_finding()

    fake_epss_result = make_fake_epss_result()

    fake_kev_result = Mock()
    fake_kev_result.status = "ERROR"
    fake_kev_result.source_timestamp = None
    fake_kev_result.reason_code = "CONNECTOR_ERROR"

    with patch(
        "vpap.enrichment.service.get_epss",
        return_value=fake_epss_result,
    ), patch(
        "vpap.enrichment.service.is_in_kev",
        return_value=fake_kev_result,
    ):
        evidence = enrich_finding(
            finding,
            enrichment_run_id="test-run-error",
        )

    assert evidence.kev_status.value is None
    assert evidence.kev_status.status == "ERROR"
    assert evidence.kev_status.reason_code == "CONNECTOR_ERROR"
    assert evidence.kev_status.source == "CISA_KEV"

def test_service_accepts_custom_tenant_and_source_instance() -> None:
    finding = make_test_finding()

    fake_epss_result = make_fake_epss_result()

    fake_kev_result = Mock()
    fake_kev_result.status = "FOUND"
    fake_kev_result.source_timestamp = None
    fake_kev_result.reason_code = None

    with patch(
        "vpap.enrichment.service.get_epss",
        return_value=fake_epss_result,
    ), patch(
        "vpap.enrichment.service.is_in_kev",
        return_value=fake_kev_result,
    ):
        evidence = enrich_finding(
            finding,
            enrichment_run_id="test-custom-context",
            tenant_id="real-tenant-123",
            source_instance_id="wiz-prod-instance",
        )

    assert evidence.tenant_id == "real-tenant-123"
    assert evidence.source_instance_id == "wiz-prod-instance"
