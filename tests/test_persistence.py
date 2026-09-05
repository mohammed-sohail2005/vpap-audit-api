from datetime import datetime, timezone
from unittest.mock import Mock, patch

import pytest

from vpap.domain.finding import Finding
from vpap.domain.ingestion_result import IngestionResult
from vpap.domain.rejected_record import RejectedRecord
from vpap.domain.validation_failure import ValidationFailure
from vpap.domain.validation_result import ValidationResult
from vpap.persistence.client import PersistenceClient
from vpap.persistence.models import (
    DeadLetterCreate,
    FindingInstanceCreate,
    IngestionBatchCreate,
    finding_to_persistence_model,
)
from vpap.persistence.pipeline import PersistencePipeline
from vpap.persistence.repositories import (
    DeadLetterRepository,
    FindingInstanceRepository,
    IngestionBatchRepository,
)


# ============================================================================
# Persistence Client Tests
# ============================================================================


def test_post_sends_json_payload_and_returns_response():
    client = PersistenceClient(
        base_url="https://example.com/",
        timeout=15.0,
    )

    payload = {
        "tenant_id": "tenant-001",
        "source_system": "WIZ",
    }

    response = Mock()
    response.json.return_value = {
        "id": "record-001",
    }

    with patch(
        "vpap.persistence.client.requests.post",
        return_value=response,
    ) as post:
        result = client._post("/test-endpoint", payload)

    post.assert_called_once_with(
        "https://example.com/test-endpoint",
        json=payload,
        timeout=15.0,
    )

    response.raise_for_status.assert_called_once_with()
    assert result == {"id": "record-001"}


def test_post_rejects_non_object_json_response():
    client = PersistenceClient("https://example.com")

    response = Mock()
    response.json.return_value = ["unexpected", "list"]

    with patch(
        "vpap.persistence.client.requests.post",
        return_value=response,
    ):
        with pytest.raises(
            ValueError,
            match="non-object JSON response",
        ):
            client._post(
                "/test-endpoint",
                {"key": "value"},
            )


def test_post_propagates_http_error():
    client = PersistenceClient("https://example.com")

    response = Mock()
    response.raise_for_status.side_effect = RuntimeError("HTTP failure")

    with patch(
        "vpap.persistence.client.requests.post",
        return_value=response,
    ):
        with pytest.raises(RuntimeError, match="HTTP failure"):
            client._post(
                "/test-endpoint",
                {"key": "value"},
            )


def test_create_ingestion_batch_uses_correct_endpoint():
    client = PersistenceClient("https://example.com")

    payload = {"tenant_id": "tenant-001"}

    with patch.object(
        client,
        "_post",
        return_value={"id": "batch-001"},
    ) as post:
        result = client.create_ingestion_batch(payload)

    post.assert_called_once_with(
        "/ingestion-batches",
        payload,
    )
    assert result == {"id": "batch-001"}


def test_create_finding_instance_uses_correct_endpoint():
    client = PersistenceClient("https://example.com")

    payload = {"tenant_id": "tenant-001"}

    with patch.object(
        client,
        "_post",
        return_value={"id": "finding-001"},
    ) as post:
        result = client.create_finding_instance(payload)

    post.assert_called_once_with(
        "/findings",
        payload,
    )
    assert result == {"id": "finding-001"}


def test_create_dead_letter_uses_correct_endpoint():
    client = PersistenceClient("https://example.com")

    payload = {"tenant_id": "tenant-001"}

    with patch.object(
        client,
        "_post",
        return_value={"id": "dead-letter-001"},
    ) as post:
        result = client.create_dead_letter(payload)

    post.assert_called_once_with(
        "/dead-letters",
        payload,
    )
    assert result == {"id": "dead-letter-001"}


# ============================================================================
# Persistence Model Tests
# ============================================================================


def test_ingestion_batch_create():
    batch = IngestionBatchCreate(
        tenant_id="tenant-001",
        source_system="WIZ",
        source_type="FILE",
        source_reference="batch-001",
        source_file_name="findings.xlsx",
        total_records=100,
        accepted_records=95,
        rejected_records=5,
        validation_failed_records=2,
        status="COMPLETED",
    )

    assert batch.tenant_id == "tenant-001"
    assert batch.source_system == "WIZ"
    assert batch.source_type == "FILE"
    assert batch.source_reference == "batch-001"
    assert batch.source_file_name == "findings.xlsx"
    assert batch.total_records == 100
    assert batch.accepted_records == 95
    assert batch.rejected_records == 5
    assert batch.validation_failed_records == 2
    assert batch.status == "COMPLETED"


def test_finding_instance_create():
    detected_at = datetime(
        2026,
        9,
        3,
        12,
        30,
        tzinfo=timezone.utc,
    )

    finding = FindingInstanceCreate(
        tenant_id="tenant-001",
        idempotency_key="abc123",
        source_system="WIZ",
        source_finding_id="wiz-001",
        cve_id="CVE-2024-12345",
        asset_id="asset-001",
        package_id="package-001",
        cvss_base=8.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        description="Test vulnerability",
        business_service_id="service-001",
        internet_exposed=True,
        first_detected_at=detected_at,
    )

    assert finding.tenant_id == "tenant-001"
    assert finding.idempotency_key == "abc123"
    assert finding.source_system == "WIZ"
    assert finding.source_finding_id == "wiz-001"
    assert finding.cve_id == "CVE-2024-12345"
    assert finding.asset_id == "asset-001"
    assert finding.package_id == "package-001"
    assert finding.cvss_base == 8.5
    assert finding.cvss_vector.startswith("CVSS:3.1")
    assert finding.description == "Test vulnerability"
    assert finding.business_service_id == "service-001"
    assert finding.internet_exposed is True
    assert finding.first_detected_at == detected_at
    assert finding.status == "VALID"


def test_finding_instance_allows_optional_fields_to_be_none():
    finding = FindingInstanceCreate(
        tenant_id="tenant-001",
        idempotency_key="abc123",
        source_system="WIZ",
        source_finding_id="wiz-001",
        cve_id="CVE-2024-12345",
        asset_id="asset-001",
    )

    assert finding.package_id is None
    assert finding.cvss_base is None
    assert finding.cvss_vector is None
    assert finding.description is None
    assert finding.business_service_id is None
    assert finding.internet_exposed is None
    assert finding.first_detected_at is None
    assert finding.status == "VALID"


def test_dead_letter_create():
    dead_letter = DeadLetterCreate(
        tenant_id="tenant-001",
        source_system="WIZ",
        batch_id="batch-001",
        source_finding_id="wiz-001",
        stage="VALIDATION",
        error_code="VALIDATION_ERROR",
        error_message="Source finding ID is missing",
        raw_record={
            "id": "",
            "vulnerabilityExternalId": "CVE-2024-12345",
        },
    )

    assert dead_letter.tenant_id == "tenant-001"
    assert dead_letter.source_system == "WIZ"
    assert dead_letter.batch_id == "batch-001"
    assert dead_letter.source_finding_id == "wiz-001"
    assert dead_letter.stage == "VALIDATION"
    assert dead_letter.error_code == "VALIDATION_ERROR"
    assert dead_letter.error_message == "Source finding ID is missing"
    assert dead_letter.raw_record["id"] == ""
    assert dead_letter.status == "OPEN"
    assert dead_letter.retry_count == 0


def test_finding_to_persistence_model_maps_all_finding_fields():
    detected_at = datetime(
        2026,
        9,
        3,
        12,
        30,
        tzinfo=timezone.utc,
    )

    finding = Finding(
        source_system="WIZ",
        source_finding_id="wiz-001",
        cve_id="CVE-2024-12345",
        asset_id="asset-001",
        package_id="package-001",
        cvss_base=8.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        description="Test vulnerability",
        business_service_id="service-001",
        internet_exposed=True,
        first_detected_at=detected_at,
    )

    result = finding_to_persistence_model(
        finding,
        tenant_id="tenant-001",
    )

    assert result.tenant_id == "tenant-001"

    assert result.source_system == finding.source_system
    assert result.source_finding_id == finding.source_finding_id
    assert result.cve_id == finding.cve_id
    assert result.asset_id == finding.asset_id
    assert result.package_id == finding.package_id
    assert result.cvss_base == finding.cvss_base
    assert result.cvss_vector == finding.cvss_vector
    assert result.description == finding.description
    assert result.business_service_id == finding.business_service_id
    assert result.internet_exposed == finding.internet_exposed
    assert result.first_detected_at == finding.first_detected_at

    assert result.idempotency_key == finding.idempotency_key()
    assert result.status == "VALID"


# ============================================================================
# Persistence Pipeline Tests
# ============================================================================


def make_finding(source_finding_id: str = "F-001") -> Finding:
    return Finding(
        source_system="WIZ",
        source_finding_id=source_finding_id,
        cve_id="CVE-2024-1234",
        asset_id="asset-001",
        package_id="pkg-001",
        cvss_base=7.5,
        cvss_vector=None,
        description="Test finding",
        business_service_id=None,
        internet_exposed=None,
        first_detected_at=None,
    )


def make_pipeline():
    ingestion_batches = Mock(spec=IngestionBatchRepository)
    findings = Mock(spec=FindingInstanceRepository)
    dead_letters = Mock(spec=DeadLetterRepository)

    ingestion_batches.create.return_value = {
        "status": "ok",
        "batch_id": "batch-001",
    }

    findings.create.return_value = {
        "status": "ok",
        "finding_id": "finding-001",
    }

    dead_letters.create.side_effect = [
        {
            "status": "ok",
            "dead_letter_id": "dl-001",
        },
        {
            "status": "ok",
            "dead_letter_id": "dl-002",
        },
    ]

    pipeline = PersistencePipeline(
        ingestion_batches=ingestion_batches,
        findings=findings,
        dead_letters=dead_letters,
    )

    return pipeline, ingestion_batches, findings, dead_letters


def test_persists_batch_and_valid_findings():
    pipeline, batches, findings, dead_letters = make_pipeline()

    finding = make_finding()

    ingestion = IngestionResult(
        accepted_records=[
            (
                finding,
                {"id": "F-001"},
            )
        ],
        rejected_records=[],
    )

    validation = ValidationResult(
        valid_findings=[finding],
        validation_failures=[],
    )

    result = pipeline.persist(
        ingestion=ingestion,
        validation=validation,
        tenant_id="tenant-001",
        source_system="WIZ",
        source_type="API",
    )

    batches.create.assert_called_once()
    findings.create.assert_called_once()
    dead_letters.create.assert_not_called()

    assert result["batch"]["batch_id"] == "batch-001"
    assert len(result["findings"]) == 1
    assert result["dead_letters"] == []


def test_persists_ingestion_rejection_as_dead_letter():
    pipeline, batches, findings, dead_letters = make_pipeline()

    rejected = RejectedRecord(
        source_system="WIZ",
        raw_record={
            "id": "F-002",
            "vulnerabilityExternalId": "INVALID",
        },
        reason="Invalid CVE format",
    )

    ingestion = IngestionResult(
        accepted_records=[],
        rejected_records=[rejected],
    )

    validation = ValidationResult(
        valid_findings=[],
        validation_failures=[],
    )

    result = pipeline.persist(
        ingestion=ingestion,
        validation=validation,
        tenant_id="tenant-001",
        source_system="WIZ",
        source_type="API",
    )

    findings.create.assert_not_called()
    dead_letters.create.assert_called_once()

    dead_letter = dead_letters.create.call_args.args[0]

    assert dead_letter.tenant_id == "tenant-001"
    assert dead_letter.source_system == "WIZ"
    assert dead_letter.batch_id == "batch-001"
    assert dead_letter.source_finding_id == "F-002"
    assert dead_letter.stage == "INGESTION"
    assert dead_letter.error_message == "Invalid CVE format"
    assert dead_letter.raw_record == rejected.raw_record

    assert len(result["dead_letters"]) == 1


def test_persists_validation_failure_as_dead_letter_with_raw_record():
    pipeline, batches, findings, dead_letters = make_pipeline()

    finding = make_finding()

    raw_record = {
        "id": "F-001",
        "vulnerabilityExternalId": "CVE-2024-1234",
        "vulnerableAsset": {
            "id": "asset-001",
        },
    }

    failure = ValidationFailure(
        finding=finding,
        rule="cvss_base_required",
        reason="CVSS base score is required",
    )

    ingestion = IngestionResult(
        accepted_records=[
            (
                finding,
                raw_record,
            )
        ],
        rejected_records=[],
    )

    validation = ValidationResult(
        valid_findings=[],
        validation_failures=[failure],
    )

    result = pipeline.persist(
        ingestion=ingestion,
        validation=validation,
        tenant_id="tenant-001",
        source_system="WIZ",
        source_type="API",
    )

    findings.create.assert_not_called()
    dead_letters.create.assert_called_once()

    dead_letter = dead_letters.create.call_args.args[0]

    assert dead_letter.tenant_id == "tenant-001"
    assert dead_letter.source_system == "WIZ"
    assert dead_letter.batch_id == "batch-001"
    assert dead_letter.source_finding_id == "F-001"
    assert dead_letter.stage == "VALIDATION"
    assert dead_letter.error_message == "CVSS base score is required"
    assert dead_letter.raw_record == raw_record

    assert len(result["dead_letters"]) == 1
    assert result["validation_failures"] == 1


def test_does_not_persist_validation_failed_finding():
    pipeline, batches, findings, dead_letters = make_pipeline()

    finding = make_finding()

    ingestion = IngestionResult(
        accepted_records=[
            (
                finding,
                {"id": "F-001"},
            )
        ],
        rejected_records=[],
    )

    validation = ValidationResult(
        valid_findings=[],
        validation_failures=[
            ValidationFailure(
                finding=finding,
                rule="test_rule",
                reason="Test validation failure",
            )
        ],
    )

    pipeline.persist(
        ingestion=ingestion,
        validation=validation,
        tenant_id="tenant-001",
        source_system="WIZ",
        source_type="API",
    )

    findings.create.assert_not_called()
    dead_letters.create.assert_called_once()


def test_persists_both_ingestion_and_validation_dead_letters():
    pipeline, batches, findings, dead_letters = make_pipeline()

    valid_finding = make_finding("F-001")
    invalid_finding = make_finding("F-002")

    rejected = RejectedRecord(
        source_system="WIZ",
        raw_record={"id": "F-003"},
        reason="Ingestion failed",
    )

    validation_failure = ValidationFailure(
        finding=invalid_finding,
        rule="test_rule",
        reason="Validation failed",
    )

    ingestion = IngestionResult(
        accepted_records=[
            (
                valid_finding,
                {"id": "F-001"},
            ),
            (
                invalid_finding,
                {"id": "F-002"},
            ),
        ],
        rejected_records=[rejected],
    )

    validation = ValidationResult(
        valid_findings=[valid_finding],
        validation_failures=[validation_failure],
    )

    result = pipeline.persist(
        ingestion=ingestion,
        validation=validation,
        tenant_id="tenant-001",
        source_system="WIZ",
        source_type="API",
    )

    findings.create.assert_called_once()
    assert dead_letters.create.call_count == 2

    calls = dead_letters.create.call_args_list

    assert calls[0].args[0].stage == "INGESTION"
    assert calls[1].args[0].stage == "VALIDATION"

    assert len(result["findings"]) == 1
    assert len(result["dead_letters"]) == 2


# ============================================================================
# Persistence Repository Tests
# ============================================================================


def test_ingestion_batch_repository_create():
    client = Mock()
    client.create_ingestion_batch.return_value = {
        "id": "batch-001",
    }

    repository = IngestionBatchRepository(client)

    batch = IngestionBatchCreate(
        tenant_id="tenant-001",
        source_system="WIZ",
        source_type="FILE",
        source_reference="ref-001",
        source_file_name="findings.xlsx",
        total_records=10,
        accepted_records=8,
        rejected_records=2,
        validation_failed_records=1,
    )

    result = repository.create(batch)

    assert result == {"id": "batch-001"}

    client.create_ingestion_batch.assert_called_once_with(
        batch.model_dump(mode="json")
    )


def test_finding_instance_repository_create():
    client = Mock()
    client.create_finding_instance.return_value = {
        "id": "finding-001",
    }

    repository = FindingInstanceRepository(client)

    finding = FindingInstanceCreate(
        tenant_id="tenant-001",
        idempotency_key="key-001",
        source_system="WIZ",
        source_finding_id="wiz-001",
        cve_id="CVE-2024-12345",
        asset_id="asset-001",
        package_id="package-001",
        cvss_base=8.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        description="Test vulnerability",
        business_service_id="service-001",
        internet_exposed=True,
    )

    result = repository.create(finding)

    assert result == {"id": "finding-001"}

    client.create_finding_instance.assert_called_once_with(
        finding.model_dump(mode="json")
    )


def test_dead_letter_repository_create():
    client = Mock()
    client.create_dead_letter.return_value = {
        "id": "dead-letter-001",
    }

    repository = DeadLetterRepository(client)

    dead_letter = DeadLetterCreate(
        tenant_id="tenant-001",
        source_system="WIZ",
        batch_id="batch-001",
        source_finding_id="wiz-001",
        stage="VALIDATION",
        error_code="VALIDATION_ERROR",
        error_message="Invalid finding",
        raw_record={
            "id": "wiz-001",
            "vulnerabilityExternalId": "CVE-2024-12345",
        },
    )

    result = repository.create(dead_letter)

    assert result == {"id": "dead-letter-001"}

    client.create_dead_letter.assert_called_once_with(
        dead_letter.model_dump(mode="json")
    )