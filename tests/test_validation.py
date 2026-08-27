import pytest

from vpap.domain.finding import Finding
from vpap.validation.validator import (
    validate_finding_record,
    validate_findings,
)


def make_valid_finding(**overrides) -> Finding:
    data = {
        "source_system": "WIZ",
        "source_finding_id": "wiz-vf-000001",
        "cve_id": "CVE-2099-20001",
        "asset_id": "wiz-asset-000001",
        "package_id": None,
        "cvss_base": 8.8,
        "cvss_vector": None,
        "description": "Synthetic vulnerability finding.",
        "business_service_id": None,
        "internet_exposed": None,
        "first_detected_at": None,
    }

    data.update(overrides)

    return Finding(**data)


def test_valid_finding_passes_validation():
    finding = make_valid_finding()

    failures = validate_finding_record(finding)

    assert failures == []


def test_missing_source_finding_id_is_rejected():
    finding = make_valid_finding(
        source_finding_id=" ",
    )

    failures = validate_finding_record(finding)

    assert len(failures) == 1
    assert failures[0].rule == "source_finding_id_required"


def test_missing_asset_id_is_rejected():
    finding = make_valid_finding(
        asset_id=" ",
    )

    failures = validate_finding_record(finding)

    assert len(failures) == 1
    assert failures[0].rule == "asset_id_required"


def test_missing_source_system_is_rejected():
    finding = make_valid_finding(
        source_system=" ",
    )

    failures = validate_finding_record(finding)

    assert len(failures) == 1
    assert failures[0].rule == "source_system_required"


def test_lowercase_source_system_is_rejected():
    finding = make_valid_finding(
        source_system="wiz",
    )

    failures = validate_finding_record(finding)

    assert len(failures) == 1
    assert failures[0].rule == "source_system_normalized"


def test_whitespace_in_source_system_is_rejected():
    finding = make_valid_finding(
        source_system=" WIZ ",
    )

    failures = validate_finding_record(finding)

    assert len(failures) == 1
    assert failures[0].rule == "source_system_normalized"


def test_idempotency_key_is_generated():
    finding = make_valid_finding()

    failures = validate_finding_record(finding)

    assert failures == []
    assert finding.idempotency_key()


def test_one_invalid_finding_does_not_stop_validation():
    valid_finding = make_valid_finding(
        source_finding_id="valid-001",
    )

    invalid_finding = make_valid_finding(
        source_finding_id=" ",
    )

    another_valid_finding = make_valid_finding(
        source_finding_id="valid-002",
    )

    result = validate_findings(
        [
            (valid_finding, {}),
            (invalid_finding, {}),
            (another_valid_finding, {}),
        ]
    )

    assert len(result.valid_findings) == 2
    assert len(result.validation_failures) == 1

    assert result.valid_findings[0].source_finding_id == "valid-001"
    assert result.valid_findings[1].source_finding_id == "valid-002"

    assert (
        result.validation_failures[0].finding.source_finding_id
        == " "
    )


def test_multiple_validation_failures_are_retained():
    finding = make_valid_finding(
        source_system=" ",
        source_finding_id=" ",
        asset_id=" ",
    )

    failures = validate_finding_record(finding)

    assert len(failures) == 3

    rules = {failure.rule for failure in failures}

    assert rules == {
        "source_system_required",
        "source_finding_id_required",
        "asset_id_required",
    }


def test_validation_does_not_modify_finding():
    finding = make_valid_finding()

    original = finding.model_dump()

    validate_finding_record(finding)

    assert finding.model_dump() == original