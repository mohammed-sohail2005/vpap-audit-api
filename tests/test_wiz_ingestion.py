"""
Tests for the Wiz ingestion pipeline.
"""

import pytest
from datetime import datetime
from pathlib import Path

from vpap.domain.finding import Finding
from vpap.ingestion.processor import process_source_data
from vpap.ingestion.excel_reader import read_excel_file


SAMPLE_FILE = Path(
    "docs/Wiz_VulnerabilityFinding_Exact_Field_Sample_100_Rows (2).csv.xlsx"
)


def test_unsupported_source_system_is_rejected() -> None:
    """
    The ingestion layer must not guess or silently accept
    an unsupported source system.
    """

    with pytest.raises(ValueError, match="Unsupported source system"):
        process_source_data(SAMPLE_FILE, "UNKNOWN")


def test_wiz_sample_contains_100_findings() -> None:
    """
    The supplied Wiz sample contains 100 rows.
    """

    result = process_source_data(SAMPLE_FILE, "WIZ")

    assert len(result.accepted_records) == 100
    assert len(result.rejected_records) == 0


def test_first_wiz_record_maps_to_canonical_fields() -> None:
    """
    Verify the confirmed Wiz -> VPAP mappings.
    """

    result = process_source_data(SAMPLE_FILE, "WIZ")

    finding, raw_record = result.accepted_records[0]

    assert finding.source_system == "WIZ"
    assert finding.source_finding_id == str(raw_record["id"])
    assert finding.cve_id == str(raw_record["vulnerabilityExternalId"])
    assert finding.asset_id == str(raw_record["vulnerableAsset.id"])
    assert finding.cvss_base == float(raw_record["score"])
    assert finding.description == raw_record["description"]

    assert isinstance(finding.first_detected_at, datetime)

    # These fields have no confirmed Wiz mapping.
    assert finding.package_id is None
    assert finding.cvss_vector is None
    assert finding.business_service_id is None
    assert finding.internet_exposed is None


def test_raw_record_is_preserved() -> None:
    """
    Verify that the original source record is retained separately.
    """

    result = process_source_data(SAMPLE_FILE, "WIZ")

    finding, raw_record = result.accepted_records[0]

    # The raw record must still contain the original source field names.
    assert "id" in raw_record
    assert "vulnerabilityExternalId" in raw_record
    assert "vulnerableAsset.id" in raw_record
    assert "score" in raw_record
    assert "firstDetectedAt" in raw_record

    # The canonical Finding should use canonical names independently.
    assert finding.source_finding_id == str(raw_record["id"])


def test_idempotency_key_is_deterministic_for_equivalent_findings() -> None:
    """
    Equivalent canonical findings must produce the same idempotency key.
    """

    result = process_source_data(SAMPLE_FILE, "WIZ")

    finding, _ = result.accepted_records[0]

    equivalent_finding = finding.model_copy(deep=True)

    assert finding is not equivalent_finding
    assert finding == equivalent_finding
    assert finding.idempotency_key() == equivalent_finding.idempotency_key()


def test_missing_required_wiz_field_is_rejected() -> None:
    """
    Required Wiz fields must not be silently converted into
    placeholder strings such as "None".
    """

    result = process_source_data(SAMPLE_FILE, "WIZ")
    _, raw_record = result.accepted_records[0]

    invalid_record = raw_record.copy()
    invalid_record["id"] = None

    from vpap.connectors.wiz_mapper import map_wiz_record_to_finding

    with pytest.raises((TypeError, ValueError)):
        map_wiz_record_to_finding(invalid_record)


def test_missing_wiz_cve_field_is_rejected() -> None:
    """
    A missing vulnerabilityExternalId must be rejected rather than
    converted into the string "None".
    """

    result = process_source_data(SAMPLE_FILE, "WIZ")
    _, raw_record = result.accepted_records[0]

    invalid_record = raw_record.copy()
    invalid_record["vulnerabilityExternalId"] = None

    from vpap.connectors.wiz_mapper import map_wiz_record_to_finding

    with pytest.raises(ValueError, match="vulnerabilityExternalId"):
        map_wiz_record_to_finding(invalid_record)


def test_missing_wiz_asset_field_is_rejected() -> None:
    """
    A missing vulnerableAsset.id must be rejected rather than
    converted into the string "None".
    """

    result = process_source_data(SAMPLE_FILE, "WIZ")
    _, raw_record = result.accepted_records[0]

    invalid_record = raw_record.copy()
    invalid_record["vulnerableAsset.id"] = None

    from vpap.connectors.wiz_mapper import map_wiz_record_to_finding

    with pytest.raises(ValueError, match="vulnerableAsset.id"):
        map_wiz_record_to_finding(invalid_record)


def test_invalid_wiz_score_is_rejected() -> None:
    """
    A non-numeric Wiz score must be rejected rather than
    silently converted into an invalid canonical value.
    """

    result = process_source_data(SAMPLE_FILE, "WIZ")
    _, raw_record = result.accepted_records[0]

    invalid_record = raw_record.copy()
    invalid_record["score"] = "not-a-score"

    from vpap.connectors.wiz_mapper import map_wiz_record_to_finding

    with pytest.raises((TypeError, ValueError)):
        map_wiz_record_to_finding(invalid_record)


def test_wiz_score_above_cvss_range_is_rejected() -> None:
    """
    A Wiz score above the canonical CVSS range must be rejected.
    """

    result = process_source_data(SAMPLE_FILE, "WIZ")
    _, raw_record = result.accepted_records[0]

    invalid_record = raw_record.copy()
    invalid_record["score"] = 10.1

    from vpap.connectors.wiz_mapper import map_wiz_record_to_finding

    with pytest.raises(ValueError):
        map_wiz_record_to_finding(invalid_record)


def test_wiz_score_below_cvss_range_is_rejected() -> None:
    """
    A Wiz score below the canonical CVSS range must be rejected.
    """

    result = process_source_data(SAMPLE_FILE, "WIZ")
    _, raw_record = result.accepted_records[0]

    invalid_record = raw_record.copy()
    invalid_record["score"] = -0.1

    from vpap.connectors.wiz_mapper import map_wiz_record_to_finding

    with pytest.raises(ValueError):
        map_wiz_record_to_finding(invalid_record)


def test_malformed_wiz_timestamp_is_rejected() -> None:
    """
    A malformed firstDetectedAt value must be rejected.
    """

    result = process_source_data(SAMPLE_FILE, "WIZ")
    _, raw_record = result.accepted_records[0]

    invalid_record = raw_record.copy()
    invalid_record["firstDetectedAt"] = "not-a-timestamp"

    from vpap.connectors.wiz_mapper import map_wiz_record_to_finding

    with pytest.raises(ValueError):
        map_wiz_record_to_finding(invalid_record)


def test_wiz_timestamp_preserves_timezone() -> None:
    """
    A UTC timestamp from Wiz must remain timezone-aware.
    """

    result = process_source_data(SAMPLE_FILE, "WIZ")
    finding, _ = result.accepted_records[0]

    assert finding.first_detected_at is not None
    assert finding.first_detected_at.tzinfo is not None
    assert finding.first_detected_at.utcoffset() is not None


def test_wiz_mapper_does_not_mutate_raw_record() -> None:
    """
    Mapping a Wiz record must not modify the original raw record.
    """

    result = process_source_data(SAMPLE_FILE, "WIZ")
    _, raw_record = result.accepted_records[0]

    original_record = raw_record.copy()

    from vpap.connectors.wiz_mapper import map_wiz_record_to_finding

    map_wiz_record_to_finding(raw_record)

    assert raw_record == original_record


def test_excel_reader_preserves_wiz_headers_and_raw_values() -> None:
    """
    The Excel reader must preserve the source column names and values
    exactly as supplied by the workbook.
    """

    from vpap.ingestion.excel_reader import read_excel_file

    rows = list(read_excel_file(SAMPLE_FILE))

    assert len(rows) == 100

    first_row = rows[0]

    assert first_row["id"] == "wiz-vf-000001"
    assert first_row["vulnerabilityExternalId"] == "CVE-2099-20001"
    assert first_row["vulnerableAsset.id"] == "wiz-asset-000001"
    assert first_row["score"] == 8.8
    assert first_row["firstDetectedAt"] is not None

    # The original Wiz field names must remain unchanged.
    assert "id" in first_row
    assert "vulnerabilityExternalId" in first_row
    assert "vulnerableAsset.id" in first_row

    # The reader must not replace source names with canonical VPAP names.
    assert "source_finding_id" not in first_row
    assert "asset_id" not in first_row
    assert "cve_id" not in first_row


def test_missing_excel_file_is_rejected() -> None:
    """
    A nonexistent Excel file must raise FileNotFoundError.
    """

    from vpap.ingestion.excel_reader import read_excel_file

    with pytest.raises(FileNotFoundError):
        list(read_excel_file("docs/does-not-exist.xlsx"))


def test_non_excel_file_is_rejected() -> None:
    """
    The Excel reader must reject files that are not .xlsx files.
    """

    from vpap.ingestion.excel_reader import read_excel_file

    with pytest.raises(ValueError, match="Expected an .xlsx file"):
        list(read_excel_file("README.md"))


def test_processor_uses_registered_wiz_mapper() -> None:
    """
    The processor must resolve the mapper through SOURCE_REGISTRY
    rather than maintaining its own source-to-mapper mapping.
    """

    from vpap.connectors.registry import SOURCE_REGISTRY

    config = SOURCE_REGISTRY["WIZ"]

    assert config["mapper"] == (
        "vpap.connectors.wiz_mapper.map_wiz_record_to_finding"
    )
    assert config["schema_version"] == "v1"
    assert config["type"] == "file"


def test_load_mapper_resolves_registered_wiz_mapper() -> None:
    """
    The mapper path stored in the registry must resolve to a callable.
    """

    from vpap.connectors.registry import SOURCE_REGISTRY, load_mapper

    mapper = load_mapper(SOURCE_REGISTRY["WIZ"]["mapper"])

    assert callable(mapper)
    assert mapper.__name__ == "map_wiz_record_to_finding"


def test_wiz_ingestion_contract_preserves_all_source_records() -> None:
    """
    The ingestion contract is:

        source Excel rows
            -> canonical Finding
            -> original raw record

    Every source row must produce exactly one Finding/raw-record pair,
    and the raw record must remain unchanged.
    """

    source_rows = list(read_excel_file(SAMPLE_FILE))
    result = process_source_data(SAMPLE_FILE, "WIZ")

    # Every source row must produce exactly one accepted ingestion result
    # for the clean supplied sample.
    assert len(source_rows) == 100
    assert len(result.accepted_records) == len(source_rows)
    assert len(result.rejected_records) == 0

    for source_row, (finding, raw_record) in zip(
        source_rows,
        result.accepted_records,
        strict=True,
    ):
        # The raw record must be preserved exactly.
        assert raw_record == source_row

        # The canonical output must be a Finding.
        assert isinstance(finding, Finding)

        # Required canonical fields must be populated.
        assert finding.source_system == "WIZ"
        assert finding.source_finding_id
        assert finding.cve_id
        assert finding.asset_id

        # The raw source identity must correspond to the canonical identity.
        assert finding.source_finding_id == str(source_row["id"])
        assert finding.cve_id == str(
            source_row["vulnerabilityExternalId"]
        )
        assert finding.asset_id == str(
            source_row["vulnerableAsset.id"]
        )


def test_invalid_record_is_retained_with_rejection_reason(
    tmp_path: Path,
) -> None:
    """
    An invalid Wiz record must be retained as a rejected record
    with its original source data and the reason for rejection.
    """

    import openpyxl

    file_path = tmp_path / "invalid_wiz.xlsx"

    workbook = openpyxl.Workbook()
    worksheet = workbook.active

    headers = [
        "id",
        "vulnerabilityExternalId",
        "vulnerableAsset.id",
        "score",
        "description",
        "firstDetectedAt",
    ]

    worksheet.append(headers)

    invalid_row = [
        None,
        "CVE-2099-20001",
        "wiz-asset-000001",
        8.8,
        "Synthetic test finding",
        "2026-08-02T16:00:00Z",
    ]

    worksheet.append(invalid_row)
    workbook.save(file_path)
    workbook.close()

    result = process_source_data(file_path, "WIZ")

    assert len(result.accepted_records) == 0
    assert len(result.rejected_records) == 1

    rejected = result.rejected_records[0]

    assert rejected.source_system == "WIZ"
    assert rejected.raw_record["id"] is None
    assert "id" in rejected.reason


def test_invalid_record_does_not_stop_subsequent_records(
    tmp_path: Path,
) -> None:
    """
    An invalid record must not terminate processing of subsequent
    valid records.
    """

    import openpyxl

    file_path = tmp_path / "mixed_wiz.xlsx"

    workbook = openpyxl.Workbook()
    worksheet = workbook.active

    headers = [
        "id",
        "vulnerabilityExternalId",
        "vulnerableAsset.id",
        "score",
        "description",
        "firstDetectedAt",
    ]

    worksheet.append(headers)

    worksheet.append([
        "wiz-vf-invalid",
        None,
        "wiz-asset-000001",
        8.8,
        "Invalid synthetic finding",
        "2026-08-02T16:00:00Z",
    ])

    worksheet.append([
        "wiz-vf-valid",
        "CVE-2099-20002",
        "wiz-asset-000002",
        7.5,
        "Valid synthetic finding",
        "2026-08-02T17:00:00Z",
    ])

    workbook.save(file_path)
    workbook.close()

    result = process_source_data(file_path, "WIZ")

    assert len(result.accepted_records) == 1
    assert len(result.rejected_records) == 1

    finding, raw_record = result.accepted_records[0]

    assert finding.source_finding_id == "wiz-vf-valid"
    assert raw_record["id"] == "wiz-vf-valid"

    rejected = result.rejected_records[0]

    assert rejected.raw_record["id"] == "wiz-vf-invalid"
    assert "vulnerabilityExternalId" in rejected.reason


def test_rejected_record_preserves_original_raw_data(
    tmp_path: Path,
) -> None:
    """
    The rejected record must contain the original source values
    without modification.
    """

    import openpyxl

    file_path = tmp_path / "rejected_wiz.xlsx"

    workbook = openpyxl.Workbook()
    worksheet = workbook.active

    headers = [
        "id",
        "vulnerabilityExternalId",
        "vulnerableAsset.id",
        "score",
    ]

    worksheet.append(headers)

    worksheet.append([
        "wiz-vf-000001",
        None,
        "wiz-asset-000001",
        8.8,
    ])

    workbook.save(file_path)
    workbook.close()

    source_rows = list(read_excel_file(file_path))

    result = process_source_data(file_path, "WIZ")

    assert len(result.rejected_records) == 1

    rejected = result.rejected_records[0]

    assert rejected.raw_record == source_rows[0]