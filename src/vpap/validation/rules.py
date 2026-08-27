"""
Validation rules for canonical VPAP Findings.

These rules operate only on canonical Finding objects.
They do not modify the Finding.
"""

# Import the canonical Finding domain model.
# All validation rules in this module operate on Finding objects.
from vpap.domain.finding import Finding


def validate_required_identifiers(
    finding: Finding,
) -> list[tuple[str, str]]:
    """
    Validate required canonical identifiers.

    Returns:
        A list of (rule_name, reason) pairs.
    """

    # Stores all validation failures found for the current Finding.
    failures: list[tuple[str, str]] = []

    # Check whether the canonical source-system identifier is present and contains a non-empty value.
    if not finding.source_system.strip():
        failures.append(
            (
                "source_system_required",
                "Source system is missing or empty",
            )
        )

    # Check whether the source-specific finding identifier is present and contains a non-empty value.
    if not finding.source_finding_id.strip():
        failures.append(
            (
                "source_finding_id_required",
                "Source finding ID is missing or empty",
            )
        )

    # Check whether the CVE identifier is present and contains a non-empty value.
    if not finding.cve_id.strip():
        failures.append(
            (
                "cve_id_required",
                "CVE ID is missing or empty",
            )
        )

    # Check whether the canonical asset identifier is present and contains a non-empty value.
    if not finding.asset_id.strip():
        failures.append(
            (
                "asset_id_required",
                "Asset ID is missing or empty",
            )
        )

    # Return every required-identifier failure found for this Finding.
    return failures


def validate_source_system(
    finding: Finding,
) -> list[tuple[str, str]]:
    """
    Validate the canonical source-system identifier.
    """

    # Remove leading and trailing whitespace temporarily so that the normalized value can be compared with the original value.
    source_system = finding.source_system.strip()

    # Empty values are handled by validate_required_identifiers().
    # Therefore, this rule does not report the same missing-value failure again.
    if not source_system:
        return []

    # Check whether the original source-system value contains leading or trailing whitespace.
    if source_system != finding.source_system:
        return [
            (
                "source_system_normalized",
                "Source system contains leading or trailing whitespace",
            )
        ]

    # Check whether the source-system identifier uses the required uppercase canonical representation.
    if source_system != source_system.upper():
        return [
            (
                "source_system_normalized",
                "Source system must use uppercase canonical form",
            )
        ]

    # No source-system validation failures were found.
    return []


def validate_idempotency_key(
    finding: Finding,
) -> list[tuple[str, str]]:
    """
    Validate that the Finding produces a deterministic idempotency key.
    """

    # Generate the idempotency key using the deterministic logic defined by the canonical Finding model.
    key = finding.idempotency_key()

    # Verify that an idempotency key was successfully produced.
    if not key:
        return [
            (
                "idempotency_key_required",
                "Finding produced an empty idempotency key",
            )
        ]

    # The Finding produced a non-empty idempotency key.
    return []


def validate_finding(
    finding: Finding,
) -> list[tuple[str, str]]:
    """
    Run all validation rules against one canonical Finding.
    """

    # Stores failures returned by all validation rules executed against the current Finding.
    failures: list[tuple[str, str]] = []

    # Validate that all required canonical identifiers are present.
    failures.extend(validate_required_identifiers(finding))

    # Validate that the source-system identifier is in canonical form.
    failures.extend(validate_source_system(finding))

    # Validate that the Finding can produce an idempotency key.
    failures.extend(validate_idempotency_key(finding))

    # Return all validation failures found across all rules.
    return failures