import json
from pathlib import Path
from uuid import uuid4

from vpap.enrichment.service import enrich_finding
from vpap.ingestion.processor import process_source_data
from vpap.validation.validator import validate_findings


INPUT_FILE = Path(
    "docs/Wiz_VulnerabilityFinding_Exact_Field_Sample_100_Rows (2).csv.xlsx"
)

OUTPUT_FILE = Path("synthetic_enriched_findings.json")


def main() -> None:
    # ONE run ID for the entire enrichment batch.
    enrichment_run_id = str(uuid4())

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
    # 3. Enrichment
    # ---------------------------------------------------------
    enriched_findings = []

    for finding in validation_result.valid_findings:
        evidence = enrich_finding(
            finding,
            enrichment_run_id=enrichment_run_id,
        )

        enriched_findings.append(
            evidence.model_dump(mode="json")
        )

    # ---------------------------------------------------------
    # 4. Write output
    # ---------------------------------------------------------
    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            enriched_findings,
            file,
            indent=2,
        )

    print(
        f"Ingestion accepted: "
        f"{len(ingestion_result.accepted_records)}"
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
        f"Processed: {len(enriched_findings)} findings"
    )
    print(f"Enrichment run: {enrichment_run_id}")
    print(f"Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()