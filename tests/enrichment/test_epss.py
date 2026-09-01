from unittest.mock import Mock, patch

from requests import RequestException

from vpap.enrichment.epss import EPSS_API_URL, get_epss

def test_get_epss_for_known_cve() -> None:
    """
    Successful FIRST response containing an EPSS score.
    """

    fake_response = Mock()

    fake_response.status_code = 200

    fake_response.json.return_value = {
        "status": "OK",
        "data": [
            {
                "cve": "CVE-2099-20001",
                "epss": "0.72",
                "percentile": "0.943",
            }
        ],
    }

    with patch(
        "vpap.enrichment.epss.requests.get",
        return_value=fake_response,
    ):
        result = get_epss("CVE-2099-20001")

    assert result.status == "FOUND"
    assert result.epss == 0.72
    assert result.percentile == 0.943
    assert result.reason_code is None


def test_get_epss_for_unknown_cve() -> None:
    """
    FIRST responds successfully but does not return a score
    for the requested CVE.
    """

    fake_response = Mock()

    fake_response.status_code = 200

    fake_response.json.return_value = {
        "status": "OK",
        "data": [],
    }

    with patch(
        "vpap.enrichment.epss.requests.get",
        return_value=fake_response,
    ):
        result = get_epss("CVE-2099-99999")

    assert result.status == "NOT_FOUND"
    assert result.epss is None
    assert result.percentile is None
    assert result.reason_code == "CVE_NOT_SCORED"


def test_get_epss_when_api_fails() -> None:
    """
    Network/request failure should become ERROR.
    """

    with patch(
        "vpap.enrichment.epss.requests.get",
        side_effect=RequestException("network failure"),
    ):
        result = get_epss("CVE-2099-20001")

    assert result.status == "ERROR"
    assert result.reason_code == "CONNECTOR_ERROR"
def test_get_epss_uses_first_epss_api_endpoint() -> None:
    """
    EPSS requests must use the FIRST EPSS data API endpoint.
    """

    fake_response = Mock()
    fake_response.status_code = 200
    fake_response.json.return_value = {
        "status": "OK",
        "data": [
            {
                "cve": "CVE-2021-44228",
                "epss": "0.99999",
                "percentile": "1.0",
            }
        ],
    }

    with patch(
        "vpap.enrichment.epss.requests.get",
        return_value=fake_response,
    ) as mock_get:
        result = get_epss("CVE-2021-44228")

    assert result.status == "FOUND"

    mock_get.assert_called_once_with(
        EPSS_API_URL,
        params={"cve": "CVE-2021-44228"},
        timeout=10,
    )

    assert EPSS_API_URL == "https://api.first.org/data/v1/epss"

def test_get_epss_rejects_negative_values() -> None:
    fake_response = Mock(status_code=200)
    fake_response.json.return_value = {
        "status": "OK",
        "data": [
            {
                "cve": "CVE-2021-44228",
                "epss": "-0.1",
                "percentile": "0.5",
            }
        ],
    }

    with patch(
        "vpap.enrichment.epss.requests.get",
        return_value=fake_response,
    ):
        result = get_epss("CVE-2021-44228")

    assert result.status == "ERROR"
    assert result.reason_code == "INVALID_CONNECTOR_DATA"


def test_get_epss_rejects_values_above_one() -> None:
    fake_response = Mock(status_code=200)
    fake_response.json.return_value = {
        "status": "OK",
        "data": [
            {
                "cve": "CVE-2021-44228",
                "epss": "1.1",
                "percentile": "0.5",
            }
        ],
    }

    with patch(
        "vpap.enrichment.epss.requests.get",
        return_value=fake_response,
    ):
        result = get_epss("CVE-2021-44228")

    assert result.status == "ERROR"
    assert result.reason_code == "INVALID_CONNECTOR_DATA"


def test_get_epss_rejects_nan() -> None:
    fake_response = Mock(status_code=200)
    fake_response.json.return_value = {
        "status": "OK",
        "data": [
            {
                "cve": "CVE-2021-44228",
                "epss": "nan",
                "percentile": "0.5",
            }
        ],
    }

    with patch(
        "vpap.enrichment.epss.requests.get",
        return_value=fake_response,
    ):
        result = get_epss("CVE-2021-44228")

    assert result.status == "ERROR"
    assert result.reason_code == "INVALID_CONNECTOR_DATA"


def test_get_epss_rejects_infinity() -> None:
    fake_response = Mock(status_code=200)
    fake_response.json.return_value = {
        "status": "OK",
        "data": [
            {
                "cve": "CVE-2021-44228",
                "epss": "inf",
                "percentile": "0.5",
            }
        ],
    }

    with patch(
        "vpap.enrichment.epss.requests.get",
        return_value=fake_response,
    ):
        result = get_epss("CVE-2021-44228")

    assert result.status == "ERROR"
    assert result.reason_code == "INVALID_CONNECTOR_DATA"


def test_get_epss_rejects_non_numeric_values() -> None:
    fake_response = Mock(status_code=200)
    fake_response.json.return_value = {
        "status": "OK",
        "data": [
            {
                "cve": "CVE-2021-44228",
                "epss": "not-a-number",
                "percentile": "0.5",
            }
        ],
    }

    with patch(
        "vpap.enrichment.epss.requests.get",
        return_value=fake_response,
    ):
        result = get_epss("CVE-2021-44228")

    assert result.status == "ERROR"
    assert result.reason_code == "INVALID_CONNECTOR_DATA"

def test_get_epss_rejects_invalid_percentile() -> None:
    invalid_values = ["-0.1", "1.1", "nan", "inf", "not-a-number"]

    for value in invalid_values:
        fake_response = Mock(status_code=200)
        fake_response.json.return_value = {
            "status": "OK",
            "data": [
                {
                    "cve": "CVE-2021-44228",
                    "epss": "0.5",
                    "percentile": value,
                }
            ],
        }

        with patch(
            "vpap.enrichment.epss.requests.get",
            return_value=fake_response,
        ):
            result = get_epss("CVE-2021-44228")

        assert result.status == "ERROR"
        assert result.reason_code == "INVALID_CONNECTOR_DATA"