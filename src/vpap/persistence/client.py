"""
HTTP client for the VPAP persistence backend.
"""

from typing import Any

import requests


class PersistenceClient:
    """
    REST client used to communicate with the VPAP backend.
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _post(
        self,
        endpoint: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """
        POST a JSON payload to the backend and return the
        decoded JSON response.
        """

        response = requests.post(
            f"{self.base_url}/{endpoint.lstrip('/')}",
            json=payload,
            timeout=self.timeout,
        )

        response.raise_for_status()

        data = response.json()

        if not isinstance(data, dict):
            raise ValueError(
                "Persistence API returned a non-object JSON response"
            )

        return data

    def create_ingestion_batch(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self._post("/ingestion-batches", payload)

    def create_finding_instance(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self._post("/findings", payload)

    def create_dead_letter(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self._post("/dead-letters", payload)