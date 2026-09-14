"""
VPAP token vending client.

Obtains short-lived JWTs from the VPAP Audit API using a per-service
vending credential. The vending credential is never sent as a tenant,
subject, or scope claim; the server decides the identity associated with it.

Environment variables:
    VPAP_AUDIT_API_URL       e.g. https://vpap-audit-api.onrender.com
    VPAP_VENDING_CREDENTIAL  private service credential
    VPAP_TOKEN_REFRESH_SKEW  optional seconds before expiry to refresh (default 60)

Usage:
    from token_client import VpapTokenClient

    client = VpapTokenClient()
    headers = client.auth_headers()

    # Reuse headers for API calls. The client refreshes the JWT automatically.
    response = requests.post(
        f"{client.base_url}/findings",
        headers=headers,
        json=payload,
        timeout=30,
    )
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any

import requests


class VpapTokenError(RuntimeError):
    """Raised when a VPAP vending token cannot be obtained."""


class VpapTokenClient:
    """Thread-safe in-memory cache for a short-lived VPAP JWT."""

    def __init__(
        self,
        base_url: str | None = None,
        vending_credential: str | None = None,
        refresh_skew: int | None = None,
        timeout: float = 15.0,
    ) -> None:
        self.base_url = (
            base_url or os.environ.get("VPAP_AUDIT_API_URL")
        )
        if not self.base_url:
            raise RuntimeError("VPAP_AUDIT_API_URL must be configured")

        self.base_url = self.base_url.rstrip("/")

        if not self.base_url.startswith("https://"):
            raise RuntimeError("VPAP_AUDIT_API_URL must use HTTPS")

        self.vending_credential = (
            vending_credential
            or os.environ.get("VPAP_VENDING_CREDENTIAL")
        )
        if not self.vending_credential:
            raise RuntimeError("VPAP_VENDING_CREDENTIAL must be configured")

        self.refresh_skew = int(
            refresh_skew
            if refresh_skew is not None
            else os.environ.get("VPAP_TOKEN_REFRESH_SKEW", "60")
        )
        if self.refresh_skew < 0:
            raise ValueError("VPAP_TOKEN_REFRESH_SKEW must be >= 0")

        self.timeout = timeout
        self._token: str | None = None
        self._expires_at: float = 0.0
        self._lock = threading.Lock()

    def _request_token(self) -> tuple[str, int]:
        """Request a fresh JWT from the server."""
        try:
            response = requests.post(
                f"{self.base_url}/auth/vend-token",
                json={"vending_credential": self.vending_credential},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise VpapTokenError(
                f"Unable to reach VPAP token vending endpoint: {exc}"
            ) from exc

        if response.status_code != 200:
            # Never include the vending credential in an error message.
            detail: Any
            try:
                body = response.json()
                detail = body.get("detail", body)
            except ValueError:
                detail = response.text[:500]

            raise VpapTokenError(
                f"VPAP token vending failed (HTTP {response.status_code}): "
                f"{detail}"
            )

        try:
            data = response.json()
            token = data["access_token"]
            expires_in = int(data["expires_in"])
        except (ValueError, KeyError, TypeError) as exc:
            raise VpapTokenError(
                "VPAP token vending returned an invalid response"
            ) from exc

        if not token or expires_in <= 0:
            raise VpapTokenError(
                "VPAP token vending returned an unusable token"
            )

        return token, expires_in

    def get_token(self) -> str:
        """Return a valid cached JWT, refreshing it when necessary."""
        now = time.time()

        if self._token and now < self._expires_at - self.refresh_skew:
            return self._token

        with self._lock:
            now = time.time()
            if self._token and now < self._expires_at - self.refresh_skew:
                return self._token

            token, expires_in = self._request_token()

            # Keep the JWT only in memory. Never write it to a file.
            self._token = token
            self._expires_at = time.time() + expires_in

            return token

    def auth_headers(self) -> dict[str, str]:
        """Return Authorization headers for a protected VPAP API call."""
        return {
            "Authorization": f"Bearer {self.get_token()}",
            "Content-Type": "application/json",
        }

    def clear(self) -> None:
        """Discard the cached JWT so the next call obtains a fresh one."""
        with self._lock:
            self._token = None
            self._expires_at = 0.0
