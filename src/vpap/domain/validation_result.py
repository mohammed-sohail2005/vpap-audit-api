"""
Validation result domain model.
"""

# Import Pydantic's BaseModel to define the validation result as a structured and validated domain model.
from pydantic import BaseModel

# Import the canonical Finding model representing records that successfully passed validation.
from vpap.domain.finding import Finding

# Import the ValidationFailure model representing records that failed one or more validation rules.
from vpap.domain.validation_failure import ValidationFailure


class ValidationResult(BaseModel):
    """
    Result of validating a collection of canonical Findings.
    """

    # Stores all canonical Findings that successfully passed the validation rules.
    valid_findings: list[Finding]

    # Stores all validation failures, including the Finding, the failed rule, and the reason for the failure.
    validation_failures: list[ValidationFailure]