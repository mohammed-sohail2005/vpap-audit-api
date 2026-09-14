from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
import math
from urllib.parse import urlencode

import requests


EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_QUERY_MAX_LENGTH = 2000


@dataclass
class EPSSResult:
    """
    Result returned by the EPSS connector.

    status:
        FOUND      -> EPSS score was returned
        NOT_FOUND  -> API succeeded but CVE has no score
        ERROR      -> API request or response failed
    """

    status: str
    epss: float | None = None
    percentile: float | None = None
    source_timestamp: datetime | None = None
    reason_code: str | None = None


def _parse_record(
    record: Any,
    source_timestamp: datetime,
) -> EPSSResult:
    if not isinstance(record, dict):
        return EPSSResult(
            status="ERROR",
            reason_code="INVALID_CONNECTOR_DATA",
        )

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
        source_timestamp=source_timestamp,
    )


def _build_cve_batches(cve_ids: set[str]) -> list[list[str]]:
    """
    Split CVEs into batches whose encoded query string stays
    within FIRST's 2000-character cve query limit.
    """

    batches: list[list[str]] = []
    current: list[str] = []

    for cve_id in sorted(cve_ids):
        candidate = current + [cve_id]

        query_length = len(
            urlencode({"cve": ",".join(candidate)})
        )

        if current and query_length > EPSS_QUERY_MAX_LENGTH:
            batches.append(current)
            current = [cve_id]
        else:
            current = candidate

    if current:
        batches.append(current)

    return batches


def get_epss_batch(
    cve_ids: set[str],
) -> dict[str, EPSSResult]:
    """
    Query FIRST EPSS for multiple CVEs.

    CVEs are automatically split according to FIRST's
    encoded query-length limit.
    """

    if not cve_ids:
        return {}

    results: dict[str, EPSSResult] = {}

    for batch in _build_cve_batches(cve_ids):
        try:
            response = requests.get(
                EPSS_API_URL,
                params={"cve": ",".join(batch)},
                timeout=10,
            )

        except requests.RequestException:
            for cve_id in batch:
                results[cve_id] = EPSSResult(
                    status="ERROR",
                    reason_code="CONNECTOR_ERROR",
                )
            continue

        if response.status_code != 200:
            for cve_id in batch:
                results[cve_id] = EPSSResult(
                    status="ERROR",
                    reason_code="CONNECTOR_ERROR",
                )
            continue

        try:
            payload: dict[str, Any] = response.json()
        except ValueError:
            for cve_id in batch:
                results[cve_id] = EPSSResult(
                    status="ERROR",
                    reason_code="CONNECTOR_ERROR",
                )
            continue

        data = payload.get("data")

        if not isinstance(data, list):
            for cve_id in batch:
                results[cve_id] = EPSSResult(
                    status="ERROR",
                    reason_code="CONNECTOR_ERROR",
                )
            continue

        source_timestamp = datetime.now(timezone.utc)

        returned_cves: set[str] = set()

        for record in data:
            if not isinstance(record, dict):
                continue

            cve_id = record.get("cve")

            if not isinstance(cve_id, str):
                continue

            returned_cves.add(cve_id)

            results[cve_id] = _parse_record(
                record,
                source_timestamp,
            )

        # FIRST can successfully return no record for an unscored CVE.
        for cve_id in batch:
            if cve_id not in returned_cves:
                results[cve_id] = EPSSResult(
                    status="NOT_FOUND",
                    reason_code="CVE_NOT_SCORED",
                    source_timestamp=source_timestamp,
                )

    return results


def get_epss(cve_id: str) -> EPSSResult:
    """
    Backward-compatible single-CVE wrapper.
    """

    return get_epss_batch({cve_id}).get(
        cve_id,
        EPSSResult(
            status="ERROR",
            reason_code="CONNECTOR_ERROR",
        ),
    )