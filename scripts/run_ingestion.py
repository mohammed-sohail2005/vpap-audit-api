import os
from pathlib import Path
from vpap.ingestion.processor import process_source_data
from vpap.persistence.client import PersistenceClient
from vpap.persistence.pipeline import PersistencePipeline
from vpap.persistence.repositories import (
    AuditEventRepository,
    DeadLetterRepository,
    EnrichmentRunRepository,
    FindingEvidenceRepository,
    FindingInstanceRepository,
    IngestionBatchRepository,
    KEVCatalogueRepository,
    EPSSSnapshotRepository,
)
from vpap.enrichment.pipeline import EnrichmentPipeline
from vpap.validation.validator import validate_findings

def main() -> None:
    api_url = os.environ["VPAP_AUDIT_API_URL"]

    input_file_value = os.environ.get("VPAP_INPUT_FILE")

    if not input_file_value:
        raise RuntimeError("VPAP_INPUT_FILE must be configured")

    input_file = Path(input_file_value).resolve()

    if not input_file.is_file():
        raise FileNotFoundError(
            f"Input file does not exist: {input_file}"
        )

    if input_file.suffix.lower() != ".xlsx":
        raise ValueError("Only .xlsx input files are supported")
    tenant_id = os.environ.get("VPAP_TENANT_ID")
    if not tenant_id:
        raise RuntimeError("VPAP_TENANT_ID must be configured")
    source_instance_id = os.environ.get("VPAP_SOURCE_INSTANCE_ID")
    if not source_instance_id:
        raise RuntimeError("VPAP_SOURCE_INSTANCE_ID must be configured")
    access_token = os.environ.get("VPAP_PERSISTENCE_ACCESS_TOKEN")
    if not access_token:
        raise RuntimeError(
            "VPAP_PERSISTENCE_ACCESS_TOKEN must be configured"
        )
    # ---------------------------------------------------------
    # 1. Ingestion
    # ---------------------------------------------------------
    ingestion_result = process_source_data(
        input_file,
        "WIZ",
    )

    # ---------------------------------------------------------
    # 2. Validation
    # ---------------------------------------------------------
    validation_result = validate_findings(
        ingestion_result.accepted_records
    )

    # ---------------------------------------------------------
    # 3. Persistence
    # ---------------------------------------------------------
    client = PersistenceClient(
        api_url,
        access_token=access_token,
    )

    pipeline = PersistencePipeline(
        ingestion_batches=IngestionBatchRepository(client),
        findings=FindingInstanceRepository(client),
        dead_letters=DeadLetterRepository(client),
    )

    result = pipeline.persist(
        ingestion=ingestion_result,
        validation=validation_result,
        tenant_id=tenant_id,
        source_system="WIZ",
        source_type="FILE",
        source_file_name=input_file.name,
    )
    # ---------------------------------------------------------
    # 4. Enrichment
    # ---------------------------------------------------------
    enrichment_pipeline = EnrichmentPipeline(
        enrichment_run_repository=EnrichmentRunRepository(client),
        finding_evidence_repository=FindingEvidenceRepository(client),
        kev_catalogue_repository=KEVCatalogueRepository(client),
        epss_snapshot_repository=EPSSSnapshotRepository(client),
        audit_event_repository=AuditEventRepository(client),
    )


    enrichment_results = enrichment_pipeline.process(
        findings=validation_result.valid_findings,
        tenant_id=tenant_id,
        source_instance_id=source_instance_id,
        finding_instance_ids=[
            finding_response["finding_id"]
            for finding_response in result["findings"]
        ],
    )
    # ---------------------------------------------------------
    # 5. Summary
    # ---------------------------------------------------------
    print(
        f"Ingestion accepted: "
        f"{len(ingestion_result.accepted_records)}"
    )
    print(
        f"Ingestion rejected: "
        f"{len(ingestion_result.rejected_records)}"
    )
    print(
        f"Validation passed: "
        f"{len(validation_result.valid_findings)}"
    )
    print(
        f"Validation failed: "
        f"{len(validation_result.validation_failures)}"
    )
    print(
        f"Persisted findings: "
        f"{len(result['findings'])}"
    )
    print(
        f"Persisted dead letters: "
        f"{len(result['dead_letters'])}"
    )
    print(
        f"Enriched findings: "
        f"{len(enrichment_results)}"
    )
    print(
        f"Enrichment run ID: "
        f"{enrichment_pipeline.enrichment_run_id}"
    )
    print(
        f"Batch ID: "
        f"{result['batch']['batch_id']}"
    )


if __name__ == "__main__":
    main()