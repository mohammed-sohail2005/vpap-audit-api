from pathlib import Path
from unittest.mock import Mock, patch

from vpap.enrichment.service import enrich_finding
from vpap.ingestion.processor import process_source_data
from vpap.validation.validator import validate_findings


SAMPLE_FILE = Path(
    "docs/Wiz_VulnerabilityFinding_Exact_Field_Sample_100_Rows (2).csv.xlsx"
)


def test_ingestion_validation_enrichment_pipeline() -> None:
    """
    Verify that the enrichment stage consumes the canonical Findings
    produced by validation.
    """

    # 1. Run the existing ingestion stage.
    ingestion_result = process_source_data(
        SAMPLE_FILE,
        "WIZ",
    )

    assert len(ingestion_result.accepted_records) == 100
    assert len(ingestion_result.rejected_records) == 0

    # 2. Run the existing validation stage.
    validation_result = validate_findings(
        ingestion_result.accepted_records
    )

    assert len(validation_result.valid_findings) == 100
    assert len(validation_result.validation_failures) == 0

    # 3. Control external enrichment dependencies.
    fake_epss_result = Mock(
        status="FOUND",
        epss=0.72,
        percentile=0.943,
        source_timestamp=None,
        reason_code=None,
    )

    fake_kev_result = Mock(
        status="FOUND",
        source_timestamp=None,
        reason_code=None,
    )

    with patch(
        "vpap.enrichment.service.get_epss",
        return_value=fake_epss_result,
    ), patch(
        "vpap.enrichment.service.is_in_kev",
        return_value=fake_kev_result,
    ):
        # 4. Pass the ACTUAL validation output into enrichment.
        enriched = [
            enrich_finding(
                finding,
                enrichment_run_id="integration-test-run",
            )
            for finding in validation_result.valid_findings
        ]

    # 5. Verify enrichment produced one evidence record per
    # validated canonical Finding.
    assert len(enriched) == 100

    # 6. Verify the enrichment output preserves canonical identity.
    for finding, evidence in zip(
        validation_result.valid_findings,
        enriched,
        strict=True,
    ):
        assert evidence.source_finding_id == finding.source_finding_id
        assert evidence.cve_id == finding.cve_id
        assert evidence.asset_id == finding.asset_id
        assert evidence.cvss_base == finding.cvss_base
        assert evidence.source_system == finding.source_system
    # 7. Verify the enrichment run is shared across the batch.
    assert {
        evidence.enrichment_run_id
        for evidence in enriched
    } == {"integration-test-run"}

    # 8. Each finding gets its own evidence snapshot.
    snapshot_ids = {
        evidence.evidence_snapshot_id
        for evidence in enriched
    }

    assert len(snapshot_ids) == 100
    # 9. Verify the evidence can be serialized into the
    # JSON-compatible contract consumed by the next stage.
    for evidence in enriched:
        payload = evidence.model_dump(mode="json")

        assert payload["schema_version"]
        assert payload["tenant_id"]
        assert payload["source_system"]
        assert payload["source_instance_id"]
        assert payload["source_finding_id"]
        assert payload["adapter_name"]
        assert payload["adapter_version"]
        assert payload["enrichment_run_id"]
        assert payload["evidence_snapshot_id"]
        assert len(payload["evidence_snapshot_sha256"]) == 64

        assert "epss_probability" in payload
        assert "epss_percentile" in payload
        assert "kev_status" in payload
        assert "internet_exposure" in payload
        assert "runtime_applicability" in payload
        assert "attack_path_reachable" in payload
        assert "business_criticality" in payload
        assert "compensating_controls" in payload
