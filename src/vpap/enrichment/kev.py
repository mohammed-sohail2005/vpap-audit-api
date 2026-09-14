from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from threading import Lock
import hashlib
import requests


KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
from datetime import timedelta


KEV_MAX_AGE = timedelta(days=7)

@dataclass
class KEVResult:
    """
    Result returned by the CISA KEV connector.

    status:
        FOUND    -> catalogue loaded and CVE is present
        NOT_FOUND -> catalogue loaded and CVE is absent
        ERROR    -> catalogue could not be downloaded or validated
        STALE    -> catalogue is older than the approved limit
    """

    status: str

    value: bool | None = None
    reason_code: str | None = None

    source_timestamp: datetime | None = None
    retrieved_at: datetime | None = None

    catalogue_sha256: str | None = None
    catalogue_record_count: int | None = None
    cve_ids: set[str] | None = None
@dataclass
class KEVCatalogue:
    """
    Last successfully validated CISA KEV catalogue.
    """

    cve_ids: set[str]

    source_timestamp: datetime
    retrieved_at: datetime

    catalogue_sha256: str
    record_count: int
_cached_catalogue: KEVCatalogue | None = None
_kev_cache_lock = Lock()
def clear_kev_cache() -> None:
    """
    Clear the in-memory KEV catalogue cache.

    This is primarily used by tests so each test starts
    with a clean catalogue state.
    """
    global _cached_catalogue

    _cached_catalogue = None
def is_catalogue_stale(
    catalogue: KEVCatalogue,
    now: datetime,
) -> bool:
    """
    Return True when the catalogue is older than the
    configured maximum age.
    """

    age = now - catalogue.source_timestamp

    return age > KEV_MAX_AGE
def load_kev_catalogue() -> KEVResult:
    """
    Download, validate and prepare the CISA KEV catalogue.

    A successful result contains enough information to create
    the last-known-good cache.
    """

    retrieved_at = datetime.now(timezone.utc)

    try:
        response = requests.get(
            KEV_CATALOG_URL,
            timeout=20,
        )

    except requests.RequestException:
        return KEVResult(
            status="ERROR",
            reason_code="CONNECTOR_ERROR",
            retrieved_at=retrieved_at,
        )

    if response.status_code != 200:
        return KEVResult(
            status="ERROR",
            reason_code="CONNECTOR_ERROR",
            retrieved_at=retrieved_at,
        )

    payload_bytes = response.content

    try:
        payload = response.json()

    except ValueError:
        return KEVResult(
            status="ERROR",
            reason_code="INVALID_JSON",
            retrieved_at=retrieved_at,
        )

    valid, reason_code, record_count = validate_catalogue(
        payload
    )

    if not valid:
        return KEVResult(
            status="ERROR",
            reason_code=reason_code,
            retrieved_at=retrieved_at,
        )

    try:
        source_timestamp = datetime.fromisoformat(
            payload["dateReleased"]
        ).replace(tzinfo=timezone.utc)

    except (KeyError, TypeError, ValueError):
        return KEVResult(
            status="ERROR",
            reason_code="CATALOGUE_DATE_INVALID",
            retrieved_at=retrieved_at,
        )

    cve_ids = {
        record["cveID"]
        for record in payload["vulnerabilities"]
    }

    return KEVResult(
        status="FOUND",
        value=True,
        source_timestamp=source_timestamp,
        retrieved_at=retrieved_at,
        catalogue_sha256=calculate_sha256(payload_bytes),
        catalogue_record_count=record_count,
        cve_ids=cve_ids,
    )
def calculate_sha256(payload: bytes) -> str:
    """
    Calculate SHA-256 hash of the downloaded catalogue.
    """

    return hashlib.sha256(payload).hexdigest()


def validate_catalogue(
    payload: dict[str, Any],
) -> tuple[bool, str | None, int | None]:
    """
    Validate the basic structure of the CISA KEV catalogue.

    Returns:

        (True, None, record_count)

    or:

        (False, reason_code, None)
    """

    # ---------------------------------------------------------
    # 1. Top-level structure
    # ---------------------------------------------------------

    if not isinstance(payload, dict):
        return False, "INVALID_SCHEMA", None

    # CISA KEV uses a vulnerabilities array.
    vulnerabilities = payload.get("vulnerabilities")

    if not isinstance(vulnerabilities, list):
        return False, "INVALID_SCHEMA", None

    # ---------------------------------------------------------
    # 2. Catalogue date
    # ---------------------------------------------------------

    date_released = payload.get("dateReleased")

    if not date_released:
        return False, "CATALOGUE_DATE_MISSING", None
    # ---------------------------------------------------------
    # 3. Catalogue record count
    # ---------------------------------------------------------

    declared_count = payload.get("count")

    if not isinstance(declared_count, int):
        return False, "CATALOGUE_COUNT_MISSING", None
    # ---------------------------------------------------------
    # 4. Validate each record
    # ---------------------------------------------------------

    cves: set[str] = set()

    for record in vulnerabilities:

        if not isinstance(record, dict):
            return False, "INVALID_SCHEMA", None

        cve_id = record.get("cveID")

        if not isinstance(cve_id, str) or not cve_id:
            return False, "INVALID_SCHEMA", None

        # Duplicate CVEs indicate a malformed catalogue.
        if cve_id in cves:
            return False, "DUPLICATE_CVE", None

        cves.add(cve_id)
    # The catalogue's declared count must match the actual
    # number of vulnerability records.
    if declared_count != len(vulnerabilities):
        return False, "RECORD_COUNT_MISMATCH", None

    return True, None, len(vulnerabilities)


def download_kev_catalogue() -> KEVResult:
    """
    Download and validate the current CISA KEV catalogue.

    This function does not yet implement caching or stale handling.
    """

    retrieved_at = datetime.now(timezone.utc)

    try:

        response = requests.get(
            KEV_CATALOG_URL,
            timeout=20,
        )

    except requests.RequestException:

        return KEVResult(
            status="ERROR",
            reason_code="CONNECTOR_ERROR",
            retrieved_at=retrieved_at,
        )

    if response.status_code != 200:

        return KEVResult(
            status="ERROR",
            reason_code="CONNECTOR_ERROR",
            retrieved_at=retrieved_at,
        )

    payload_bytes = response.content

    try:

        payload = response.json()

    except ValueError:

        return KEVResult(
            status="ERROR",
            reason_code="INVALID_JSON",
            retrieved_at=retrieved_at,
        )

    valid, reason_code, record_count = validate_catalogue(
        payload
    )

    if not valid:

        return KEVResult(
            status="ERROR",
            reason_code=reason_code,
            retrieved_at=retrieved_at,
        )

    source_timestamp = None

    try:

        source_timestamp = datetime.fromisoformat(
            payload["dateReleased"]
        ).replace(tzinfo=timezone.utc)

    except (KeyError, TypeError, ValueError):

        return KEVResult(
            status="ERROR",
            reason_code="CATALOGUE_DATE_INVALID",
            retrieved_at=retrieved_at,
        )

    return KEVResult(
        status="FOUND",
        value=True,
        source_timestamp=source_timestamp,
        retrieved_at=retrieved_at,
        catalogue_sha256=calculate_sha256(payload_bytes),
        catalogue_record_count=record_count,
    )


def is_in_kev(
    cve_id: str,
) -> tuple[KEVResult, KEVCatalogue | None]:
    """
    Check whether a CVE exists in the current CISA KEV catalogue.

    A successfully downloaded and validated catalogue is cached
    and reused for subsequent CVE lookups.

    The cache represents the last known good catalogue.
    """

    global _cached_catalogue

    now = datetime.now(timezone.utc)

    with _kev_cache_lock:
        # ---------------------------------------------------------
        # 1. Load catalogue if we don't have one yet
        # ---------------------------------------------------------

        if _cached_catalogue is None:
            result = load_kev_catalogue()

            if result.status == "ERROR":
                return result, None

            _cached_catalogue = KEVCatalogue(
                cve_ids=result.cve_ids or set(),
                source_timestamp=result.source_timestamp,
                retrieved_at=result.retrieved_at,
                catalogue_sha256=result.catalogue_sha256,
                record_count=result.catalogue_record_count,
            )
            refreshed_catalogue = _cached_catalogue
        else:
            refreshed_catalogue = None

        # ---------------------------------------------------------
        # 2. Refresh catalogue if it is stale
        # ---------------------------------------------------------

        if is_catalogue_stale(
            _cached_catalogue,
            now,
        ):
            refreshed = load_kev_catalogue()

            if refreshed.status == "FOUND":
                _cached_catalogue = KEVCatalogue(
                    cve_ids=refreshed.cve_ids or set(),
                    source_timestamp=refreshed.source_timestamp,
                    retrieved_at=refreshed.retrieved_at,
                    catalogue_sha256=refreshed.catalogue_sha256,
                    record_count=refreshed.catalogue_record_count,
                )

                refreshed_catalogue = _cached_catalogue

            else:
                return (
                    KEVResult(
                        status="STALE",
                        value=None,
                        reason_code="SOURCE_STALE",
                        source_timestamp=_cached_catalogue.source_timestamp,
                        retrieved_at=now,
                        catalogue_sha256=_cached_catalogue.catalogue_sha256,
                        catalogue_record_count=_cached_catalogue.record_count,
                    ),
                    None,
                )

        # ---------------------------------------------------------
        # 3. Look up CVE in the cached catalogue
        # ---------------------------------------------------------

        if cve_id in _cached_catalogue.cve_ids:
            return (
                KEVResult(
                    status="FOUND",
                    value=True,
                    source_timestamp=_cached_catalogue.source_timestamp,
                    retrieved_at=now,
                    catalogue_sha256=_cached_catalogue.catalogue_sha256,
                    catalogue_record_count=_cached_catalogue.record_count,
                ),
                refreshed_catalogue,
            )

        return (
            KEVResult(
                status="NOT_FOUND",
                value=False,
                source_timestamp=_cached_catalogue.source_timestamp,
                retrieved_at=now,
                catalogue_sha256=_cached_catalogue.catalogue_sha256,
                catalogue_record_count=_cached_catalogue.record_count,
            ),
            refreshed_catalogue,
        )