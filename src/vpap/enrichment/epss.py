from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
import math

import requests


EPSS_API_URL = "https://api.first.org/data/v1/epss"


@dataclass
class EPSSResult:
    """
    Result returned by the EPSS connector.

    status:
        FOUND   -> EPSS score was returned
        NOT_FOUND -> API succeeded but CVE has no score
        ERROR   -> API request or response failed
    """

    status: str

    epss: float | None = None
    percentile: float | None = None
    source_timestamp: datetime | None = None
    reason_code: str | None = None


def get_epss(cve_id: str) -> EPSSResult:
    """
    Query the FIRST EPSS API for one CVE.

    The connector returns a structured result instead of using
    None for every failure case.
    """

    try:
        response = requests.get(
            EPSS_API_URL,
            params={"cve": cve_id},
            timeout=10,
        )

    except requests.RequestException:
        return EPSSResult(
            status="ERROR",
            reason_code="CONNECTOR_ERROR",
        )

    # HTTP-level failure
    if response.status_code != 200:
        return EPSSResult(
            status="ERROR",
            reason_code="CONNECTOR_ERROR",
        )

    try:
        payload: dict[str, Any] = response.json()

    except ValueError:
        return EPSSResult(
            status="ERROR",
            reason_code="CONNECTOR_ERROR",
        )

    # FIRST returns the scores inside the "data" list.
    data = payload.get("data")

    if not isinstance(data, list):
        return EPSSResult(
            status="ERROR",
            reason_code="CONNECTOR_ERROR",
        )

    # Successful response, but CVE isn't scored.
    if len(data) == 0:
        return EPSSResult(
            status="NOT_FOUND",
            reason_code="CVE_NOT_SCORED",
        )

    record = data[0]

    try:
        epss = float(record["epss"])
        percentile = float(record["percentile"])

    except (KeyError, TypeError, ValueError):
        return EPSSResult(
            status="ERROR",
            reason_code="INVALID_CONNECTOR_DATA",
        )

    if not (
        math.isfinite(epss)
        and math.isfinite(percentile)
        and 0 <= epss <= 1
        and 0 <= percentile <= 1
    ):
        return EPSSResult(
            status="ERROR",
            reason_code="INVALID_CONNECTOR_DATA",
        )

    return EPSSResult(
        status="FOUND",
        epss=epss,
        percentile=percentile,
        source_timestamp=datetime.now(timezone.utc),
    )