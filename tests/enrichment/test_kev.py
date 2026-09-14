from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import vpap.enrichment.kev as kev
from vpap.enrichment.kev import (
    clear_kev_cache,
    is_in_kev,
)
def setup_function() -> None:
    clear_kev_cache()

def make_fake_catalogue_response() -> Mock:
    """
    Create a fake successful CISA KEV response.
    """

    response = Mock()

    response.status_code = 200

    response.content = b'{"fake": "catalogue"}'

    response.json.return_value = {
        "dateReleased": datetime.now(timezone.utc).date().isoformat(),
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-00001",
                "vendorProject": "Example",
                "product": "Example Product",
            },
            {
                "cveID": "CVE-2024-00002",
                "vendorProject": "Example",
                "product": "Example Product",
            },
        ],
    }

    return response


def test_cve_in_kev() -> None:

    fake_response = make_fake_catalogue_response()

    with patch(
        "vpap.enrichment.kev.requests.get",
        return_value=fake_response,
    ):
        result,_ = is_in_kev("CVE-2024-00001")

    assert result.status == "FOUND"
    assert result.value is True
    assert result.reason_code is None
    assert result.catalogue_record_count == 2
    assert result.catalogue_sha256 is not None


def test_cve_not_in_kev() -> None:

    fake_response = make_fake_catalogue_response()

    with patch(
        "vpap.enrichment.kev.requests.get",
        return_value=fake_response,
    ):
        result,_ = is_in_kev("CVE-2024-99999")

    assert result.status == "NOT_FOUND"
    assert result.value is False
    assert result.reason_code is None


def test_kev_download_failure() -> None:

    from requests import RequestException

    with patch(
        "vpap.enrichment.kev.requests.get",
        side_effect=RequestException("network failure"),
    ):
        result,_ = is_in_kev("CVE-2024-00001")

    assert result.status == "ERROR"
    assert result.value is None
    assert result.reason_code == "CONNECTOR_ERROR"


def test_kev_malformed_json() -> None:

    fake_response = Mock()

    fake_response.status_code = 200
    fake_response.content = b"not-json"

    fake_response.json.side_effect = ValueError(
        "invalid json"
    )

    with patch(
        "vpap.enrichment.kev.requests.get",
        return_value=fake_response,
    ):
        result ,_= is_in_kev("CVE-2024-00001")

    assert result.status == "ERROR"
    assert result.reason_code == "INVALID_JSON"


def test_kev_duplicate_cves_are_rejected() -> None:

    fake_response = Mock()

    fake_response.status_code = 200
    fake_response.content = b'{"fake": "catalogue"}'

    fake_response.json.return_value = {
        "dateReleased": datetime.now(timezone.utc).date().isoformat(),
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-00001",
            },
            {
                "cveID": "CVE-2024-00001",
            },
        ],
    }

    with patch(
        "vpap.enrichment.kev.requests.get",
        return_value=fake_response,
    ):
        result,_ = is_in_kev("CVE-2024-00001")

    assert result.status == "ERROR"
    assert result.reason_code == "DUPLICATE_CVE"
def test_kev_record_count_mismatch_is_rejected() -> None:

    fake_response = Mock()

    fake_response.status_code = 200
    fake_response.content = b'{"fake": "catalogue"}'

    fake_response.json.return_value = {
        "dateReleased": datetime.now(timezone.utc).date().isoformat(),
        "count": 3,
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-00001",
            },
            {
                "cveID": "CVE-2024-00002",
            },
        ],
    }

    with patch(
        "vpap.enrichment.kev.requests.get",
        return_value=fake_response,
    ):
        result ,_= is_in_kev("CVE-2024-00001")

    assert result.status == "ERROR"
    assert result.reason_code == "RECORD_COUNT_MISMATCH"
def test_stale_kev_catalogue_is_refreshed() -> None:
    """
    A stale catalogue must be refreshed before it is used.
    """

    fake_response = make_fake_catalogue_response()

    with patch(
        "vpap.enrichment.kev.requests.get",
        return_value=fake_response,
    ) as mock_get:
        result,_ = is_in_kev("CVE-2024-00001")

        assert result.status == "FOUND"
        assert mock_get.call_count == 1

        # Make the cached catalogue artificially old.
        kev._cached_catalogue.source_timestamp = (
            datetime.now(timezone.utc)
            - kev.KEV_MAX_AGE
            - timedelta(seconds=1)
        )

        result,_ = is_in_kev("CVE-2024-00001")

    assert result.status == "FOUND"
    assert mock_get.call_count == 2
def test_last_known_good_catalogue_is_preserved_on_refresh_failure() -> None:
    """
    A valid catalogue must remain available when a later
    catalogue refresh fails.
    """

    # First request succeeds.
    good_response = make_fake_catalogue_response()

    with patch(
        "vpap.enrichment.kev.requests.get",
        return_value=good_response,
    ):
        first_result,_ = is_in_kev("CVE-2024-00001")

    assert first_result.status == "FOUND"
    assert first_result.value is True

    # Now simulate a failed refresh.
    from requests import RequestException

    with patch(
        "vpap.enrichment.kev.requests.get",
        side_effect=RequestException("network failure"),
    ):
        refresh_result = kev.load_kev_catalogue()

    assert refresh_result.status == "ERROR"
    assert refresh_result.reason_code == "CONNECTOR_ERROR"

    # The previously cached catalogue must still exist.
    assert kev._cached_catalogue is not None

    assert "CVE-2024-00001" in kev._cached_catalogue.cve_ids