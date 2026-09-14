from unittest.mock import Mock, patch
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor
import pytest

from vpap.domain.finding import Finding
from vpap.enrichment.epss import EPSSResult
from vpap.enrichment.models import FindingEvidence
from vpap.enrichment.pipeline import EnrichmentPipeline


def make_finding(source_finding_id: str = "wiz-001") -> Finding:
    return Finding(
        source_system="WIZ",
        source_finding_id=source_finding_id,
        cve_id="CVE-2024-12345",
        asset_id="asset-001",
        package_id="package-001",
        cvss_base=8.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        description="Test vulnerability",
        business_service_id="service-001",
        internet_exposed=True,
    )


def make_epss_repository() -> Mock:
    repository = Mock()
    repository.get_latest.return_value = {
        "requested": [],
        "found": 0,
        "values": [],
    }
    return repository


def make_epss_result() -> EPSSResult:
    return EPSSResult(
        status="FOUND",
        epss=0.5,
        percentile=0.9,
    )


def test_process_creates_one_run_and_persists_evidence():
    run_repository = Mock()
    evidence_repository = Mock()
    kev_catalogue_repository = Mock()
    epss_snapshot_repository = make_epss_repository()

    run_repository.create.return_value = {
        "enrichment_run_id": "run-001",
    }

    evidence_repository.create.return_value = {
        "evidence_id": "evidence-001",
    }

    pipeline = EnrichmentPipeline(
        enrichment_run_repository=run_repository,
        finding_evidence_repository=evidence_repository,
        kev_catalogue_repository=kev_catalogue_repository,
        epss_snapshot_repository=epss_snapshot_repository,
    )

    finding = make_finding()
    epss_result = make_epss_result()

    fake_evidence = Mock(spec=FindingEvidence)
    fake_evidence.enrichment_run_id = "run-001"

    with patch(
        "vpap.enrichment.pipeline.get_epss_batch",
        return_value={"CVE-2024-12345": epss_result},
    ) as get_epss_batch, patch(
        "vpap.enrichment.pipeline.enrich_finding",
        return_value=(fake_evidence, None),
    ) as enrich:
        result = pipeline.process(
            findings=[finding],
            tenant_id="tenant-001",
            source_instance_id="wiz-instance-001",
        )

    assert result == [{"evidence_id": "evidence-001"}]

    run_repository.create.assert_called_once()

    get_epss_batch.assert_called_once_with({"CVE-2024-12345"})

    enrich.assert_called_once_with(
        finding,
        enrichment_run_id="run-001",
        tenant_id="tenant-001",
        source_instance_id="wiz-instance-001",
        finding_instance_id=None,
        epss_result=epss_result,
    )

    evidence_repository.create.assert_called_once_with(fake_evidence)


def test_process_reuses_same_run_for_every_finding():
    run_repository = Mock()
    evidence_repository = Mock()
    kev_catalogue_repository = Mock()
    epss_snapshot_repository = make_epss_repository()

    run_repository.create.return_value = {
        "enrichment_run_id": "run-001",
    }

    evidence_repository.create.side_effect = [
        {"evidence_id": "evidence-001"},
        {"evidence_id": "evidence-002"},
    ]

    pipeline = EnrichmentPipeline(
        enrichment_run_repository=run_repository,
        finding_evidence_repository=evidence_repository,
        kev_catalogue_repository=kev_catalogue_repository,
        epss_snapshot_repository=epss_snapshot_repository,
    )

    findings = [
        make_finding("wiz-001"),
        make_finding("wiz-002"),
    ]

    epss_result = make_epss_result()

    with patch(
        "vpap.enrichment.pipeline.get_epss_batch",
        return_value={"CVE-2024-12345": epss_result},
    ) as get_epss_batch, patch(
        "vpap.enrichment.pipeline.enrich_finding",
        side_effect=[
            (Mock(spec=FindingEvidence), None),
            (Mock(spec=FindingEvidence), None),
        ],
    ) as enrich:
        result = pipeline.process(
            findings=findings,
            tenant_id="tenant-001",
            source_instance_id="wiz-instance-001",
        )

    assert result == [
        {"evidence_id": "evidence-001"},
        {"evidence_id": "evidence-002"},
    ]

    run_repository.create.assert_called_once()

    # Both findings have the same CVE, so FIRST should only be called once.
    get_epss_batch.assert_called_once_with({"CVE-2024-12345"})

    assert enrich.call_count == 2

    assert enrich.call_args_list[0].kwargs["enrichment_run_id"] == "run-001"
    assert enrich.call_args_list[1].kwargs["enrichment_run_id"] == "run-001"

    assert (
        enrich.call_args_list[0].kwargs["epss_result"]
        is epss_result
    )
    assert (
        enrich.call_args_list[1].kwargs["epss_result"]
        is epss_result
    )

    assert evidence_repository.create.call_count == 2


def test_process_requires_enrichment_run_id():
    run_repository = Mock()
    evidence_repository = Mock()
    kev_catalogue_repository = Mock()
    epss_snapshot_repository = make_epss_repository()

    run_repository.create.return_value = {
        "id": "run-001",
    }

    pipeline = EnrichmentPipeline(
        enrichment_run_repository=run_repository,
        finding_evidence_repository=evidence_repository,
        kev_catalogue_repository=kev_catalogue_repository,
        epss_snapshot_repository=epss_snapshot_repository,
    )

    with pytest.raises(
        ValueError,
        match="did not contain enrichment_run_id",
    ):
        pipeline.process(
            findings=[make_finding()],
            tenant_id="tenant-001",
            source_instance_id="wiz-instance-001",
        )

    evidence_repository.create.assert_not_called()


def test_process_persists_refreshed_kev_catalogue():
    run_repository = Mock()
    evidence_repository = Mock()
    kev_catalogue_repository = Mock()
    epss_snapshot_repository = make_epss_repository()

    run_repository.create.return_value = {
        "enrichment_run_id": "run-001",
    }

    evidence_repository.create.return_value = {
        "evidence_id": "evidence-001",
    }

    pipeline = EnrichmentPipeline(
        enrichment_run_repository=run_repository,
        finding_evidence_repository=evidence_repository,
        kev_catalogue_repository=kev_catalogue_repository,
        epss_snapshot_repository=epss_snapshot_repository,
    )

    refreshed_catalogue = Mock()
    refreshed_catalogue.source_timestamp = datetime(
        2026,
        8,
        28,
        tzinfo=timezone.utc,
    )
    refreshed_catalogue.catalogue_sha256 = "abc123"
    refreshed_catalogue.record_count = 2
    refreshed_catalogue.cve_ids = {
        "CVE-2024-00001",
        "CVE-2024-00002",
    }

    with patch(
        "vpap.enrichment.pipeline.enrich_finding",
        return_value=(Mock(spec=FindingEvidence), refreshed_catalogue),
    ):
        pipeline.process(
            findings=[make_finding()],
            tenant_id="tenant-001",
            source_instance_id="wiz-instance-001",
        )

    kev_catalogue_repository.create.assert_called_once_with(
        refreshed_catalogue
    )
def test_process_reuses_fresh_cached_epss_without_calling_first():
    run_repository = Mock()
    evidence_repository = Mock()
    kev_catalogue_repository = Mock()
    epss_snapshot_repository = make_epss_repository()

    run_repository.create.return_value = {
        "enrichment_run_id": "run-001",
    }

    evidence_repository.create.return_value = {
        "evidence_id": "evidence-001",
    }

    epss_snapshot_repository.get_latest.return_value = {
        "requested": ["CVE-2024-12345"],
        "found": 1,
        "values": [
            {
                "snapshot_id": "snapshot-001",
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
                "cve_id": "CVE-2024-12345",
                "epss_probability": 0.75,
                "epss_percentile": 0.95,
            }
        ],
    }

    pipeline = EnrichmentPipeline(
        enrichment_run_repository=run_repository,
        finding_evidence_repository=evidence_repository,
        kev_catalogue_repository=kev_catalogue_repository,
        epss_snapshot_repository=epss_snapshot_repository,
    )

    finding = make_finding()

    with patch(
        "vpap.enrichment.pipeline.get_epss_batch",
    ) as get_epss_batch, patch(
        "vpap.enrichment.pipeline.enrich_finding",
        return_value=(Mock(spec=FindingEvidence), None),
    ):
        pipeline.process(
            findings=[finding],
            tenant_id="tenant-001",
            source_instance_id="wiz-instance-001",
        )

    get_epss_batch.assert_not_called()
    epss_snapshot_repository.create.assert_not_called()


def test_process_fetches_missing_epss_in_batch_and_persists_snapshot():
    run_repository = Mock()
    evidence_repository = Mock()
    kev_catalogue_repository = Mock()
    epss_snapshot_repository = make_epss_repository()

    run_repository.create.return_value = {
        "enrichment_run_id": "run-001",
    }

    evidence_repository.create.return_value = {
        "evidence_id": "evidence-001",
    }

    epss_result = EPSSResult(
        status="FOUND",
        epss=0.75,
        percentile=0.95,
        source_timestamp=datetime.now(timezone.utc),
    )

    epss_snapshot_repository.create.return_value = {
        "status": "ok",
        "snapshot_id": "snapshot-001",
    }

    pipeline = EnrichmentPipeline(
        enrichment_run_repository=run_repository,
        finding_evidence_repository=evidence_repository,
        kev_catalogue_repository=kev_catalogue_repository,
        epss_snapshot_repository=epss_snapshot_repository,
    )

    findings = [
        make_finding("wiz-001"),
        make_finding("wiz-002"),
    ]

    with patch(
        "vpap.enrichment.pipeline.get_epss_batch",
        return_value={
            "CVE-2024-12345": epss_result,
        },
    ) as get_epss_batch, patch(
        "vpap.enrichment.pipeline.enrich_finding",
        return_value=(Mock(spec=FindingEvidence), None),
    ):
        pipeline.process(
            findings=findings,
            tenant_id="tenant-001",
            source_instance_id="wiz-instance-001",
        )

    # Same CVE appears in two findings, so FIRST is called once
    # with one unique CVE.
        get_epss_batch.assert_called_once_with(
        {"CVE-2024-12345"}
    )

    epss_snapshot_repository.create.assert_called_once()

    snapshot_call = epss_snapshot_repository.create.call_args.kwargs

    assert snapshot_call["source_timestamp"] == epss_result.source_timestamp
    assert isinstance(snapshot_call["retrieved_at"], datetime)
    assert snapshot_call["entries"] == {
        "CVE-2024-12345": (0.75, 0.95),
    }
def test_process_uses_last_known_good_epss_when_refresh_fails():
    run_repository = Mock()
    evidence_repository = Mock()
    kev_catalogue_repository = Mock()
    epss_snapshot_repository = make_epss_repository()

    run_repository.create.return_value = {
        "enrichment_run_id": "run-001",
    }

    evidence_repository.create.return_value = {
        "evidence_id": "evidence-001",
    }

    stale_retrieved_at = (
        datetime.now(timezone.utc)
        - timedelta(days=10)
    )

    epss_snapshot_repository.get_latest.return_value = {
        "requested": ["CVE-2024-12345"],
        "found": 1,
        "values": [
            {
                "snapshot_id": "snapshot-old",
                "retrieved_at": stale_retrieved_at.isoformat(),
                "cve_id": "CVE-2024-12345",
                "epss_probability": 0.75,
                "epss_percentile": 0.95,
            }
        ],
    }

    epss_snapshot_repository.create.return_value = {
        "status": "ok",
        "snapshot_id": "snapshot-new",
    }

    pipeline = EnrichmentPipeline(
        enrichment_run_repository=run_repository,
        finding_evidence_repository=evidence_repository,
        kev_catalogue_repository=kev_catalogue_repository,
        epss_snapshot_repository=epss_snapshot_repository,
        epss_max_age=timedelta(days=7),
    )

    finding = make_finding()

    failed_result = EPSSResult(
        status="ERROR",
        reason_code="CONNECTOR_ERROR",
    )

    with patch(
        "vpap.enrichment.pipeline.get_epss_batch",
        return_value={
            "CVE-2024-12345": failed_result,
        },
    ) as get_epss_batch, patch(
        "vpap.enrichment.pipeline.enrich_finding",
        return_value=(Mock(spec=FindingEvidence), None),
    ) as enrich:
        pipeline.process(
            findings=[finding],
            tenant_id="tenant-001",
            source_instance_id="wiz-instance-001",
        )

    get_epss_batch.assert_called_once_with(
        {"CVE-2024-12345"}
    )

    epss_snapshot_repository.create.assert_not_called()

    passed_result = enrich.call_args.kwargs["epss_result"]

    assert passed_result.status == "FOUND"
    assert passed_result.epss == 0.75
    assert passed_result.percentile == 0.95
def test_process_returns_error_for_missing_epss_when_first_fails():
    run_repository = Mock()
    evidence_repository = Mock()
    kev_catalogue_repository = Mock()
    epss_snapshot_repository = make_epss_repository()

    run_repository.create.return_value = {
        "enrichment_run_id": "run-001",
    }

    evidence_repository.create.return_value = {
        "evidence_id": "evidence-001",
    }

    pipeline = EnrichmentPipeline(
        enrichment_run_repository=run_repository,
        finding_evidence_repository=evidence_repository,
        kev_catalogue_repository=kev_catalogue_repository,
        epss_snapshot_repository=epss_snapshot_repository,
    )

    finding = make_finding()

    failed_result = EPSSResult(
        status="ERROR",
        reason_code="CONNECTOR_ERROR",
    )

    with patch(
        "vpap.enrichment.pipeline.get_epss_batch",
        return_value={
            "CVE-2024-12345": failed_result,
        },
    ), patch(
        "vpap.enrichment.pipeline.enrich_finding",
        return_value=(Mock(spec=FindingEvidence), None),
    ) as enrich:
        pipeline.process(
            findings=[finding],
            tenant_id="tenant-001",
            source_instance_id="wiz-instance-001",
        )

    passed_result = enrich.call_args.kwargs["epss_result"]

    assert passed_result.status == "ERROR"
    assert passed_result.reason_code == "CONNECTOR_ERROR"

    epss_snapshot_repository.create.assert_not_called()
def test_process_rejects_mismatched_finding_instance_ids():
    run_repository = Mock()
    evidence_repository = Mock()
    kev_catalogue_repository = Mock()
    epss_snapshot_repository = make_epss_repository()

    run_repository.create.return_value = {
        "enrichment_run_id": "run-001",
    }

    pipeline = EnrichmentPipeline(
        enrichment_run_repository=run_repository,
        finding_evidence_repository=evidence_repository,
        kev_catalogue_repository=kev_catalogue_repository,
        epss_snapshot_repository=epss_snapshot_repository,
    )

    with pytest.raises(
        ValueError,
        match="Number of findings must match number of finding instance IDs",
    ):
        pipeline.process(
            findings=[make_finding("wiz-001"), make_finding("wiz-002")],
            tenant_id="tenant-001",
            source_instance_id="wiz-instance-001",
            finding_instance_ids=["finding-001"],
        )
    run_repository.create.assert_not_called()
    evidence_repository.create.assert_not_called()
def test_process_includes_tenant_id_in_enrichment_run():
    run_repository = Mock()
    evidence_repository = Mock()
    kev_catalogue_repository = Mock()
    epss_snapshot_repository = make_epss_repository()

    run_repository.create.return_value = {
        "enrichment_run_id": "run-001",
    }

    pipeline = EnrichmentPipeline(
        enrichment_run_repository=run_repository,
        finding_evidence_repository=evidence_repository,
        kev_catalogue_repository=kev_catalogue_repository,
        epss_snapshot_repository=epss_snapshot_repository,
    )

    with patch(
        "vpap.enrichment.pipeline.get_epss_batch",
        return_value={"CVE-2024-12345": make_epss_result()},
    ), patch(
        "vpap.enrichment.pipeline.enrich_finding",
        return_value=(Mock(spec=FindingEvidence), None),
    ):
        pipeline.process(
            findings=[make_finding()],
            tenant_id="tenant-001",
            source_instance_id="wiz-instance-001",
        )

    run_payload = run_repository.create.call_args.args[0]

    assert run_payload["tenant_id"] == "tenant-001"
def test_process_marks_run_failed_when_enrichment_fails():
    run_repository = Mock()
    evidence_repository = Mock()
    kev_catalogue_repository = Mock()
    epss_snapshot_repository = make_epss_repository()

    run_repository.create.return_value = {
        "enrichment_run_id": "run-001",
    }

    pipeline = EnrichmentPipeline(
        enrichment_run_repository=run_repository,
        finding_evidence_repository=evidence_repository,
        kev_catalogue_repository=kev_catalogue_repository,
        epss_snapshot_repository=epss_snapshot_repository,
    )

    findings = [
        make_finding("wiz-001"),
        make_finding("wiz-002"),
    ]

    with patch(
        "vpap.enrichment.pipeline.get_epss_batch",
        return_value={"CVE-2024-12345": make_epss_result()},
    ), patch(
        "vpap.enrichment.pipeline.enrich_finding",
        side_effect=[
            (Mock(spec=FindingEvidence), None),
            RuntimeError("enrichment failed"),
        ],
    ):
        with pytest.raises(RuntimeError, match="enrichment failed"):
            pipeline.process(
                findings=findings,
                tenant_id="tenant-001",
                source_instance_id="wiz-instance-001",
            )

    run_repository.update.assert_called_once()
    update_kwargs = run_repository.update.call_args.kwargs

    assert update_kwargs["enrichment_run_id"] == "run-001"
    assert update_kwargs["status"] == "FAILED"
    assert isinstance(update_kwargs["completed_at"], datetime)
def test_concurrent_enrichment_jobs_keep_refreshed_catalogues_isolated():
    run_repository_a = Mock()
    evidence_repository_a = Mock()
    kev_catalogue_repository_a = Mock()

    run_repository_b = Mock()
    evidence_repository_b = Mock()
    kev_catalogue_repository_b = Mock()

    epss_snapshot_repository_a = make_epss_repository()
    epss_snapshot_repository_b = make_epss_repository()

    run_repository_a.create.return_value = {
        "enrichment_run_id": "run-a",
    }
    run_repository_b.create.return_value = {
        "enrichment_run_id": "run-b",
    }

    pipeline_a = EnrichmentPipeline(
        enrichment_run_repository=run_repository_a,
        finding_evidence_repository=evidence_repository_a,
        kev_catalogue_repository=kev_catalogue_repository_a,
        epss_snapshot_repository=epss_snapshot_repository_a,
    )

    pipeline_b = EnrichmentPipeline(
        enrichment_run_repository=run_repository_b,
        finding_evidence_repository=evidence_repository_b,
        kev_catalogue_repository=kev_catalogue_repository_b,
        epss_snapshot_repository=epss_snapshot_repository_b,
    )

    evidence_a = Mock(spec=FindingEvidence)
    evidence_b = Mock(spec=FindingEvidence)
    evidence_repository_a.create.side_effect = lambda evidence: evidence
    evidence_repository_b.create.side_effect = lambda evidence: evidence
    catalogue_a = Mock()
    catalogue_b = Mock()

    def enrich_side_effect(finding, **kwargs):
        if kwargs["tenant_id"] == "tenant-a":
            return evidence_a, catalogue_a
        return evidence_b, catalogue_b

    findings_a = [make_finding("wiz-a")]
    findings_b = [make_finding("wiz-b")]

    with patch(
        "vpap.enrichment.pipeline.get_epss_batch",
        return_value={
            "CVE-2024-12345": make_epss_result(),
        },
    ), patch(
        "vpap.enrichment.pipeline.enrich_finding",
        side_effect=enrich_side_effect,
    ):
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_a = executor.submit(
                pipeline_a.process,
                findings=findings_a,
                tenant_id="tenant-a",
                source_instance_id="wiz-instance-a",
            )
            future_b = executor.submit(
                pipeline_b.process,
                findings=findings_b,
                tenant_id="tenant-b",
                source_instance_id="wiz-instance-b",
            )

            result_a = future_a.result()
            result_b = future_b.result()

    assert result_a == [evidence_a]
    assert result_b == [evidence_b]

    kev_catalogue_repository_a.create.assert_called_once_with(catalogue_a)
    kev_catalogue_repository_b.create.assert_called_once_with(catalogue_b)

    assert (
        kev_catalogue_repository_a.create.call_args.args[0]
        is not kev_catalogue_repository_b.create.call_args.args[0]
    )
def test_pipeline_rejects_empty_finding_instance_id() -> None:
    run_repository = Mock()
    evidence_repository = Mock()
    kev_catalogue_repository = Mock()
    epss_snapshot_repository = make_epss_repository()

    run_repository.create.return_value = {
        "enrichment_run_id": "run-001",
    }

    pipeline = EnrichmentPipeline(
        enrichment_run_repository=run_repository,
        finding_evidence_repository=evidence_repository,
        kev_catalogue_repository=kev_catalogue_repository,
        epss_snapshot_repository=epss_snapshot_repository,
    )

    with pytest.raises(
        ValueError,
        match="Finding instance IDs must not be empty",
    ):
        pipeline.process(
            findings=[make_finding()],
            tenant_id="tenant-001",
            source_instance_id="wiz-instance-001",
            finding_instance_ids=[""],
        )
    run_repository.create.assert_not_called()
    evidence_repository.create.assert_not_called()

def test_process_emits_audit_events_for_each_finding():
    run_repository = Mock()
    evidence_repository = Mock()
    kev_catalogue_repository = Mock()
    epss_snapshot_repository = make_epss_repository()
    audit_event_repository = Mock()

    run_repository.create.return_value = {
        "enrichment_run_id": "run-001",
    }

    evidence = Mock(spec=FindingEvidence)
    evidence.evidence_snapshot_id = "snapshot-001"

    evidence_repository.create.return_value = {
        "evidence_id": "evidence-001",
    }

    pipeline = EnrichmentPipeline(
        enrichment_run_repository=run_repository,
        finding_evidence_repository=evidence_repository,
        kev_catalogue_repository=kev_catalogue_repository,
        epss_snapshot_repository=epss_snapshot_repository,
        audit_event_repository=audit_event_repository,
    )

    finding = make_finding()

    with patch(
        "vpap.enrichment.pipeline.get_epss_batch",
        return_value={"CVE-2024-12345": make_epss_result()},
    ), patch(
        "vpap.enrichment.pipeline.enrich_finding",
        return_value=(evidence, None),
    ):
        result = pipeline.process(
            findings=[finding],
            tenant_id="tenant-001",
            source_instance_id="wiz-instance-001",
            finding_instance_ids=["finding-001"],
        )

    assert result == [{"evidence_id": "evidence-001"}]

    assert audit_event_repository.create.call_count == 3

    events = [
        call.args[0]
        for call in audit_event_repository.create.call_args_list
    ]

    assert events[0] == {
        "actor_type": "system",
        "actor_id": "enrichment-service",
        "action": "enrichment_run.started",
        "entity_type": "enrichment_run",
        "entity_id": "run-001",
        "correlation_id": "finding-001",
        "tenant_id": "tenant-001",
    }

    assert events[1] == {
        "actor_type": "system",
        "actor_id": "enrichment-service",
        "action": "finding_evidence.recorded",
        "entity_type": "finding_evidence",
        "entity_id": "snapshot-001",
        "correlation_id": "finding-001",
        "tenant_id": "tenant-001",
        "evidence_ref": "snapshot-001",
    }

    assert events[2] == {
        "actor_type": "system",
        "actor_id": "enrichment-service",
        "action": "enrichment_run.completed",
        "entity_type": "enrichment_run",
        "entity_id": "run-001",
        "correlation_id": "finding-001",
        "tenant_id": "tenant-001",
    }


def test_process_emits_failed_audit_event_when_enrichment_fails():
    run_repository = Mock()
    evidence_repository = Mock()
    kev_catalogue_repository = Mock()
    epss_snapshot_repository = make_epss_repository()
    audit_event_repository = Mock()

    run_repository.create.return_value = {
        "enrichment_run_id": "run-001",
    }

    pipeline = EnrichmentPipeline(
        enrichment_run_repository=run_repository,
        finding_evidence_repository=evidence_repository,
        kev_catalogue_repository=kev_catalogue_repository,
        epss_snapshot_repository=epss_snapshot_repository,
        audit_event_repository=audit_event_repository,
    )

    with patch(
        "vpap.enrichment.pipeline.get_epss_batch",
        side_effect=RuntimeError("EPSS unavailable"),
    ):
        with pytest.raises(RuntimeError, match="EPSS unavailable"):
            pipeline.process(
                findings=[make_finding()],
                tenant_id="tenant-001",
                source_instance_id="wiz-instance-001",
                finding_instance_ids=["finding-001"],
            )

    events = [
        call.args[0]
        for call in audit_event_repository.create.call_args_list
    ]

    assert events[0]["action"] == "enrichment_run.started"
    assert events[1] == {
        "actor_type": "system",
        "actor_id": "enrichment-service",
        "action": "enrichment_run.failed",
        "entity_type": "enrichment_run",
        "entity_id": "run-001",
        "correlation_id": "finding-001",
        "tenant_id": "tenant-001",
    }

    run_repository.update.assert_called_once()
    update_kwargs = run_repository.update.call_args.kwargs
    assert update_kwargs["enrichment_run_id"] == "run-001"
    assert update_kwargs["status"] == "FAILED"
    assert isinstance(update_kwargs["completed_at"], datetime)
    assert update_kwargs["completed_at"].tzinfo == timezone.utc
