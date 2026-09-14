"""
HTTP client for the VPAP persistence backend.
"""
import logging
import requests

from typing import Any
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class PersistenceClient:
    """
    REST client used to communicate with the VPAP backend.
    """

    def __init__(
        self,
        base_url: str,
        access_token: str,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        if not self.base_url.startswith("https://"):
            raise ValueError("Persistence API must use HTTPS")

        if not access_token:
            raise ValueError("Persistence API access token must be configured")

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            }
        )

        retry_policy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "PATCH"}),
        )

        self.session.mount(
            "https://",
            HTTPAdapter(max_retries=retry_policy),
        )
    def _post(
        self,
        endpoint: str,
        payload: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """
        POST a JSON payload to the backend and return the
        decoded JSON response.
        """
        headers = {}

        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        request_kwargs = {
            "json": payload,
            "timeout": self.timeout,
        }

        if headers:
            request_kwargs["headers"] = headers

        response = self.session.post(
            f"{self.base_url}/{endpoint.lstrip('/')}",
            **request_kwargs,
        )

        try:
            response.raise_for_status()
        except requests.HTTPError:
            logger.error(
                "Persistence API request failed",
                extra={
                    "status_code": response.status_code,
                    "endpoint": endpoint,
                    "request_id": response.headers.get("X-Request-ID"),
                },
            )
            raise

        data = response.json()

        if not isinstance(data, dict):
            raise ValueError(
                "Persistence API returned a non-object JSON response"
            )

        return data
    def _patch(
        self,
        endpoint: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        response = self.session.patch(
            f"{self.base_url}/{endpoint.lstrip('/')}",
            json=payload,
            timeout=self.timeout,
        )

        try:
            response.raise_for_status()
        except requests.HTTPError:
            logger.error(
                "Persistence API request failed",
                extra={
                    "status_code": response.status_code,
                    "endpoint": endpoint,
                    "request_id": response.headers.get("X-Request-ID"),
                },
            )
            raise

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

    def create_enrichment_run(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/enrichment-runs", payload)

    def update_enrichment_run(
        self,
        enrichment_run_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self._patch(
            f"/enrichment-runs/{enrichment_run_id}",
            payload,
        )

    def create_audit_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/audit-events", payload)

    def create_evidence(self, payload: dict[str, Any]) -> dict[str, Any]:
        idempotency_key = payload.get("evidence_snapshot_sha256")

        if idempotency_key:
            return self._post(
                "/evidence",
                payload,
                idempotency_key=idempotency_key,
            )

        return self._post("/evidence", payload)
    def create_kev_catalogue(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/kev-catalogue", payload)

    def create_kev_catalogue_entries(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self._post("/kev-catalogue-entries", payload)

    def create_epss_snapshot(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self._post("/epss-snapshots", payload)

    def create_epss_snapshot_entries(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self._post("/epss-snapshot-entries", payload)

    def get_latest_epss_values(
        self,
        cve_ids: set[str],
    ) -> dict[str, Any]:
        response = self.session.get(
            f"{self.base_url}/epss-snapshot-entries/latest",
            params={"cve_ids": ",".join(sorted(cve_ids))},
            timeout=self.timeout,
        )
        try:
            response.raise_for_status()
        except requests.HTTPError:
            logger.error(
                "Persistence API request failed",
                extra={
                    "status_code": response.status_code,
                    "endpoint": "/epss-snapshot-entries/latest",
                    "request_id": response.headers.get("X-Request-ID"),
                },
            )
            raise

        data = response.json()

        if not isinstance(data, dict):
            raise ValueError(
                "Persistence API returned a non-object JSON response"
            )

        return data
