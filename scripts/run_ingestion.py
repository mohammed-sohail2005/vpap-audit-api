import os
from pathlib import Path

from vpap.ingestion.processor import process_source_data
from vpap.persistence.client import PersistenceClient
from vpap.persistence.pipeline import PersistencePipeline
from vpap.persistence.repositories import (
    DeadLetterRepository,
    FindingInstanceRepository,
    IngestionBatchRepository,
)
from vpap.validation.validator import validate_findings


# INPUT_FILE = Path(
#     "docs/Wiz_VulnerabilityFinding_Exact_Field_Sample_100_Rows (2).csv.xlsx"
# )

INPUT_FILE = Path("docs/Wiz_VulnerabilityFinding_DeadLetter_Test.xlsx")

def main() -> None:
    api_url = os.environ["VPAP_AUDIT_API_URL"]
    tenant_id = os.environ.get("VPAP_TENANT_ID", "default")

    # ---------------------------------------------------------
    # 1. Ingestion
    # ---------------------------------------------------------
    ingestion_result = process_source_data(
        INPUT_FILE,
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
    client = PersistenceClient(api_url)

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
        source_file_name=INPUT_FILE.name,
    )

    # ---------------------------------------------------------
    # 4. Summary
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
        f"Batch ID: "
        f"{result['batch']['batch_id']}"
    )


if __name__ == "__main__":
    main()