"""
VPAP validation processor.

Consumes canonical Findings produced by ingestion and separates
them into valid findings and validation failures.
"""

# Import Iterable so the validation processor can accept any iterable of ingestion records rather than requiring a specific collection type.
from typing import Iterable

# Import the canonical Finding model produced by the ingestion layer.
from vpap.domain.finding import Finding

# Import the domain model used to represent a failed validation rule.
from vpap.domain.validation_failure import ValidationFailure

# Import the domain model containing both successful findings and validation failures.
from vpap.domain.validation_result import ValidationResult

# Import the function that executes all validation rules against a single canonical Finding.
from vpap.validation.rules import validate_finding


def validate_finding_record(
    finding: Finding,
) -> list[ValidationFailure]:
    """
    Validate a single canonical Finding.

    Returns:
        A list of validation failures.

    An empty list means the Finding passed all validation rules.
    """

    # Run all validation rules against the supplied canonical Finding.
    # The function returns (rule_name, reason) pairs for every failure.
    failures = validate_finding(finding)

    # Convert each rule failure into a structured ValidationFailure domain object containing the original Finding, failed rule, and explanation for the failure.
    return [
        ValidationFailure(
            finding=finding,
            rule=rule,
            reason=reason,
        )
        for rule, reason in failures
    ]


def validate_findings(
    records: Iterable[tuple[Finding, dict]],
) -> ValidationResult:
    """
    Validate canonical Findings produced by the ingestion layer.

    Each ingestion record contains:

        (Finding, original_raw_record)

    The original raw record is ignored by validation because validation
    operates on the canonical Finding.

    Each Finding is evaluated independently. One invalid Finding
    does not terminate validation of the remaining Findings.
    """

    # Stores canonical Findings that successfully pass all validation rules.
    valid_findings: list[Finding] = []

    # Stores structured validation failures for Findings that fail one or more validation rules.
    validation_failures: list[ValidationFailure] = []

    # Process each record produced by the ingestion layer.
    # Each record contains the canonical Finding and its original raw source record.
    for finding, _raw_record in records:
        # Validate only the canonical Finding.
        # The original raw record is intentionally not modified or used by the validation rules.
        failures = validate_finding_record(finding)

        # If one or more validation rules failed, retain all failures and do not add the Finding to valid_findings.
        if failures:
            validation_failures.extend(failures)

        # If no validation rules failed, retain the Finding as a valid record for the next pipeline stage.
        else:
            valid_findings.append(finding)

    # Return both successful Findings and validation failures in a single structured validation result.
    return ValidationResult(
        valid_findings=valid_findings,
        validation_failures=validation_failures,
    )