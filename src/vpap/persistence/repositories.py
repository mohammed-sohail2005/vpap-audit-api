"""
Persistence repositories.

Repositories provide domain-oriented persistence operations
without exposing HTTP implementation details to the pipeline.
"""

from typing import Any

from vpap.persistence.client import PersistenceClient
from vpap.persistence.models import (
    DeadLetterCreate,
    FindingInstanceCreate,
    IngestionBatchCreate,
)


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