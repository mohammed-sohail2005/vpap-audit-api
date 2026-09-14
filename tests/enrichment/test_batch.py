from unittest.mock import Mock, patch
from vpap.domain.finding import Finding
from vpap.enrichment.service import enrich_finding
def test_enriches_100_synthetic_findings() -> None:
    """
    Verify that the enrichment service can process 100 findings
    and produce one valid FindingEvidence object for each one.

    All findings belong to the same enrichment run, but every
    finding receives its own evidence snapshot.
    """

    findings = []

    for i in range(1, 101):
        findings.append(
            Finding(
                source_system="WIZ",
                source_finding_id=f"wiz-vf-{i:06d}",
                cve_id=f"CVE-2099-{20000 + i:05d}",
                asset_id=f"wiz-asset-{i:06d}",
                cvss_base=8.8,
            )
        )

    enriched = []

    # One enrichment run ID for the entire batch.
    enrichment_run_id = "test-batch-run-001"

    fake_epss_result = Mock()

    fake_epss_result.status = "FOUND"
    fake_epss_result.epss = 0.72
    fake_epss_result.percentile = 0.943
    fake_epss_result.source_timestamp = None
    fake_epss_result.reason_code = None

    with patch(
        "vpap.enrichment.service.get_epss",
        return_value=fake_epss_result,
    ):
        for finding in findings:
            evidence,_ = enrich_finding(
                finding,
                tenant_id="test-tenant",
                enrichment_run_id=enrichment_run_id,
            )

            enriched.append(evidence)

    # ---------------------------------------------------------
    # Batch size
    # ---------------------------------------------------------

    assert len(enriched) == 100

    # ---------------------------------------------------------
    # Finding IDs must be unique
    # ---------------------------------------------------------

    finding_ids = {
        evidence.finding_instance_id
        for evidence in enriched
    }

    assert len(finding_ids) == 100

    # ---------------------------------------------------------
    # All findings must belong to the same enrichment run
    # ---------------------------------------------------------

    run_ids = {
        evidence.enrichment_run_id
        for evidence in enriched
    }

    assert run_ids == {enrichment_run_id}

    # ---------------------------------------------------------
    # Every finding must have a UNIQUE evidence snapshot
    # ---------------------------------------------------------

    snapshot_ids = {
        evidence.evidence_snapshot_id
        for evidence in enriched
    }

    assert len(snapshot_ids) == 100

    # ---------------------------------------------------------
    # Every snapshot must have a SHA-256 hash
    # ---------------------------------------------------------

    for evidence in enriched:
        assert evidence.evidence_snapshot_sha256
        assert len(evidence.evidence_snapshot_sha256) == 64

    # ---------------------------------------------------------
    # Core identity fields
    # ---------------------------------------------------------

    for evidence in enriched:
        assert evidence.finding_instance_id
        assert evidence.cve_id
        assert evidence.asset_id

    # ---------------------------------------------------------
    # Evidence not available from the canonical input
    # ---------------------------------------------------------

    for evidence in enriched:
        assert evidence.internet_exposure.status == "UNKNOWN"
        assert (
            evidence.internet_exposure.reason_code
            == "FIELD_NOT_REQUESTED"
        )
        assert evidence.internet_exposure.source == "NOT_QUERIED"

        assert evidence.runtime_applicability.status == "UNKNOWN"
        assert (
            evidence.runtime_applicability.reason_code
            == "FIELD_NOT_REQUESTED"
        )
        assert evidence.runtime_applicability.source == "NOT_QUERIED"

        assert evidence.attack_path_reachable.status == "UNKNOWN"
        assert (
            evidence.attack_path_reachable.reason_code
            == "FIELD_NOT_REQUESTED"
        )
        assert evidence.attack_path_reachable.source == "NOT_QUERIED"

    # ---------------------------------------------------------
    # Compensating controls
    # ---------------------------------------------------------

    for evidence in enriched:
        assert evidence.compensating_controls.value is None
        assert evidence.compensating_controls.status == "UNKNOWN"
        assert (
            evidence.compensating_controls.reason_code
            == "CONTROL_SOURCES_NOT_CONNECTED"
        )