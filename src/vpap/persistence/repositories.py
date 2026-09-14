"""
Persistence repositories.

Repositories provide domain-oriented persistence operations
without exposing HTTP implementation details to the pipeline.
"""

from typing import Any
from datetime import datetime
from vpap.persistence.client import PersistenceClient
from vpap.persistence.models import (
    DeadLetterCreate,
    FindingInstanceCreate,
    IngestionBatchCreate,
)
from vpap.enrichment.models import FindingEvidence
from vpap.enrichment.kev import KEVCatalogue
class IngestionBatchRepository:
    """
    Repository for ingestion_batch records.
    """

    def __init__(self, client: PersistenceClient) -> None:
        self.client = client

    def create(
        self,
        batch: IngestionBatchCreate,
    ) -> dict[str, Any]:
        return self.client.create_ingestion_batch(
            batch.model_dump(mode="json")
        )

class FindingInstanceRepository:
    """
    Repository for finding_instance records.
    """

    def __init__(self, client: PersistenceClient) -> None:
        self.client = client

    def create(
        self,
        finding: FindingInstanceCreate,
    ) -> dict[str, Any]:
        return self.client.create_finding_instance(
            finding.model_dump(mode="json")
        )

class DeadLetterRepository:
    """
    Repository for dead_letter records.
    """

    def __init__(self, client: PersistenceClient) -> None:
        self.client = client

    def create(
        self,
        dead_letter: DeadLetterCreate,
    ) -> dict[str, Any]:
        return self.client.create_dead_letter(
            dead_letter.model_dump(mode="json")
        )

class EnrichmentRunRepository:
    """
    Repository for enrichment_run records.
    """

    def __init__(self, client: PersistenceClient) -> None:
        self.client = client

    def create(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self.client.create_enrichment_run(payload)

    def update(
        self,
        enrichment_run_id: str,
        tenant_id: str,
        status: str,
        completed_at: datetime,
    ) -> dict[str, Any]:
        return self.client.update_enrichment_run(
            enrichment_run_id,
            {
                "tenant_id": tenant_id,
                "status": status,
                "completed_at": completed_at.isoformat(),
            },
        )

class FindingEvidenceRepository:
    """
    Repository for finding_evidence records.
    """

    def __init__(self, client: PersistenceClient) -> None:
        self.client = client

    def create(
        self,
        evidence: FindingEvidence,
    ) -> dict[str, Any]:
        return self.client.create_evidence(
            evidence.model_dump(mode="json")
        )

class AuditEventRepository:
    """
    Repository for audit event records.
    """

    def __init__(self, client: PersistenceClient) -> None:
        self.client = client

    def create(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self.client.create_audit_event(payload)


class KEVCatalogueRepository:
    def __init__(self, client: PersistenceClient) -> None:
        self.client = client

    def create(
        self,
        catalogue: KEVCatalogue,
    ) -> dict[str, Any]:
        catalogue_response = self.client.create_kev_catalogue(
            {
                "source_timestamp": catalogue.source_timestamp.isoformat(),
                "catalogue_sha256": catalogue.catalogue_sha256,
                "record_count": catalogue.record_count,
                "status": "OK",
            }
        )

        catalogue_id = catalogue_response.get("catalogue_id")

        if not catalogue_id:
            raise ValueError(
                "KEV catalogue response did not contain catalogue_id"
            )

        self.client.create_kev_catalogue_entries(
            {
                "entries": [
                    {
                        "catalogue_id": catalogue_id,
                        "cve_id": cve_id,
                    }
                    for cve_id in sorted(catalogue.cve_ids)
                ]
            }
        )

        return catalogue_response

class EPSSSnapshotRepository:
    def __init__(self, client):
        self.client = client

    def create(
        self,
        source_timestamp: datetime,
        retrieved_at: datetime,
        entries: dict[str, tuple[float, float]],
    ) -> dict[str, Any]:
        snapshot_response = self.client.create_epss_snapshot(
            {
                "source_timestamp": source_timestamp.isoformat(),
                "retrieved_at": retrieved_at.isoformat(),
                "record_count": len(entries),
            }
        )

        snapshot_id = snapshot_response.get("snapshot_id")

        if not snapshot_id:
            raise ValueError(
                "EPSS snapshot response did not contain snapshot_id"
            )

        self.client.create_epss_snapshot_entries(
            {
                "entries": [
                    {
                        "snapshot_id": snapshot_id,
                        "cve_id": cve_id,
                        "epss_probability": epss,
                        "epss_percentile": percentile,
                    }
                    for cve_id, (epss, percentile) in sorted(entries.items())
                ]
            }
        )

        return snapshot_response

    def get_latest(
        self,
        cve_ids: set[str],
    ) -> dict[str, Any]:
        if not cve_ids:
            return {
                "requested": [],
                "found": 0,
                "values": [],
            }

        return self.client.get_latest_epss_values(cve_ids)