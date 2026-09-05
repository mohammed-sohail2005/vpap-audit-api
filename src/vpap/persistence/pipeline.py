from typing import Any

from vpap.domain.ingestion_result import IngestionResult
from vpap.domain.validation_result import ValidationResult
from vpap.persistence.models import (
    DeadLetterCreate,
    IngestionBatchCreate,
    finding_to_persistence_model,
)
from vpap.persistence.repositories import (
    DeadLetterRepository,
    FindingInstanceRepository,
    IngestionBatchRepository,
)


class PersistencePipeline:
    def __init__(
        self,
        ingestion_batches: IngestionBatchRepository,
        findings: FindingInstanceRepository,
        dead_letters: DeadLetterRepository,
    ) -> None:
        self.ingestion_batches = ingestion_batches
        self.findings = findings
        self.dead_letters = dead_letters

    def persist(
        self,
        ingestion: IngestionResult,
        validation: ValidationResult,
        tenant_id: str,
        source_system: str,
        source_type: str,
        source_file_name: str | None = None,
        source_reference: str | None = None,
    ) -> dict[str, Any]:
        batch = IngestionBatchCreate(
            tenant_id=tenant_id,
            source_system=source_system,
            source_type=source_type,
            source_reference=source_reference,
            source_file_name=source_file_name,
            total_records=(
                len(ingestion.accepted_records)
                + len(ingestion.rejected_records)
            ),
            accepted_records=len(ingestion.accepted_records),
            rejected_records=len(ingestion.rejected_records),
            validation_failed_records=len(
                validation.validation_failures
            ),
            status="COMPLETED",
        )

        batch_response = self.ingestion_batches.create(batch)

        batch_id = batch_response.get("batch_id")

        # Build a lookup so validation failures can be associated
        # with their original raw records.
        raw_records_by_key = {
            finding.idempotency_key(): raw_record
            for finding, raw_record in ingestion.accepted_records
        }

        persisted_findings: list[dict[str, Any]] = []
        persisted_dead_letters: list[dict[str, Any]] = []

        # --------------------------------------------------------
        # Valid findings -> finding_instance
        # --------------------------------------------------------

        for finding in validation.valid_findings:
            payload = finding_to_persistence_model(
                finding,
                tenant_id=tenant_id,
            )

            response = self.findings.create(payload)
            persisted_findings.append(response)

        # --------------------------------------------------------
        # Ingestion failures -> dead_letter
        # --------------------------------------------------------

        for rejected in ingestion.rejected_records:
            dead_letter = DeadLetterCreate(
                tenant_id=tenant_id,
                source_system=rejected.source_system,
                batch_id=batch_id,
                source_finding_id=rejected.raw_record.get("id"),
                stage="INGESTION",
                error_code="INGESTION_ERROR",
                error_message=rejected.reason,
                raw_record=rejected.raw_record,
            )

            response = self.dead_letters.create(dead_letter)
            persisted_dead_letters.append(response)

        # --------------------------------------------------------
        # Validation failures -> dead_letter
        # --------------------------------------------------------

        for failure in validation.validation_failures:
            raw_record = raw_records_by_key.get(
                failure.finding.idempotency_key()
            )

            dead_letter = DeadLetterCreate(
                tenant_id=tenant_id,
                source_system=failure.finding.source_system,
                batch_id=batch_id,
                source_finding_id=failure.finding.source_finding_id,
                stage="VALIDATION",
                error_code="VALIDATION_ERROR",
                error_message=failure.reason,
                raw_record=raw_record,
            )

            response = self.dead_letters.create(dead_letter)
            persisted_dead_letters.append(response)

        return {
            "batch": batch_response,
            "findings": persisted_findings,
            "dead_letters": persisted_dead_letters,
            "validation_failures": len(
                validation.validation_failures
            ),
        }