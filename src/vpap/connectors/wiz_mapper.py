"""
Wiz-specific mapper.

This module converts one raw Wiz record into the canonical VPAP Finding.

IMPORTANT:
The raw record is never modified by this mapper.
Only the values required to construct the canonical Finding are read.
"""

from datetime import datetime
from typing import Any

from vpap.domain.finding import Finding


# This private helper function is responsible for parsing and converting the 'firstDetectedAt' field from a raw Wiz record into a Python datetime object.
# It handles various input types (None, empty string, existing datetime, ISO-8601 string) and raises a TypeError for unsupported formats, ensuring data quality.
def _parse_first_detected_at(value: Any) -> datetime | None:
    """
    Convert Wiz's firstDetectedAt value into a datetime.

    The canonical Finding expects a datetime object.

    No transformation is performed on the raw record itself.
    """

    # If the value is None or an empty string, it means the field is not present or not provided, so we return None as per the canonical Finding model.
    if value is None or value == "":
        return None

    # If the value is already a datetime object, no conversion is needed; it's returned directly.
    if isinstance(value, datetime):
        return value

    # If the value is a string, it attempts to parse it as an ISO-8601 formatted datetime.
    # Specifically, it replaces 'Z' (Zulu time, indicating UTC) with '+00:00' to ensure Python's fromisoformat can correctly interpret it as a timezone-aware UTC datetime.
    if isinstance(value, str):
        # Handle the ISO-8601 UTC representation used by the sample.
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    # If the value is neither None, an empty string, a datetime object, nor a string, it indicates an unexpected data type, and a TypeError is raised.
    raise TypeError(
        "Wiz firstDetectedAt must be a datetime, ISO-8601 string, "
        f"or None; received {type(value).__name__}"
    )

# This private helper function enforces the presence of critical fields from the raw Wiz record.
# It retrieves a specified field's value and raises a ValueError if the field is missing or contains an empty string, preventing the creation of incomplete canonical Findings.
def _require_wiz_field(
    raw_record: dict[str, Any],
    field_name: str,
) -> Any:
    """Return a required Wiz field or raise an error if it is missing."""

    # Retrieves the value associated with the given field_name from the raw_record.
    value = raw_record.get(field_name)

    # Checks if the retrieved value is None or an empty string.
    # If so, it raises a ValueError, indicating that a mandatory field is absent.
    if value is None or value == "":
        raise ValueError(
            f"Required Wiz field {field_name!r} is missing or empty"
        )

    # If the field is present and not empty, its value is returned.
    return value

# This is the main mapper function for Wiz records.
# It takes a single raw dictionary representing a Wiz vulnerability finding and transforms it into a canonical VPAP `Finding` object.
# It applies specific mapping rules and data transformations as defined in the VPAP specification for Wiz data.
def map_wiz_record_to_finding(raw_record: dict[str, Any]) -> Finding:
    """
    Map one raw Wiz record to the canonical VPAP Finding.

    Confirmed mappings:

        Wiz id
            -> source_finding_id

        Wiz vulnerabilityExternalId
            -> cve_id

        Wiz vulnerableAsset.id
            -> asset_id

        Wiz score
            -> cvss_base

        Wiz description
            -> description

        Wiz firstDetectedAt
            -> first_detected_at

    Fields with no confirmed source mapping remain None.

    The raw_record itself is never modified.
    """
    score = raw_record.get("score")

    # Constructs a new Finding object by extracting and transforming data from the raw_record according to the defined mappings.
    return Finding(
        # Source identity is explicitly supplied by the connector.
        source_system="WIZ",

        # Confirmed Wiz -> VPAP mappings.
        # These fields are considered mandatory and use _require_wiz_field to ensure their presence, converting them to string type.
        source_finding_id=str(
            _require_wiz_field(raw_record, "id")
        ),  
        cve_id=str(
            _require_wiz_field(raw_record, "vulnerabilityExternalId")
        ),
        asset_id=str(
            _require_wiz_field(raw_record, "vulnerableAsset.id")
        ),      

        # The 'score' field from Wiz is mapped to 'cvss_base'.
        # It handles cases where 'score' might be None, otherwise converts it to a float. score is confirmed as the CVSS base score in the supplied sample.
        cvss_base=(
            None
            if score is None
            else float(score)
        ),
        
        # The 'description' field is directly retrieved using .get() which gracefully handles its absence by returning None.
        description=raw_record.get("description"),

        # The 'firstDetectedAt' field is processed by the _parse_first_detected_at helper to ensure it's converted into a proper datetime object or None.
        first_detected_at=_parse_first_detected_at(
            raw_record.get("firstDetectedAt")
        ),

        # No confirmed Wiz source fields exist for these canonical fields.
        package_id=None,
        cvss_vector=None,
        business_service_id=None,
        internet_exposed=None,
    )