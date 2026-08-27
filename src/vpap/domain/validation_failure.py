"""
Validation failure domain model.

Represents a canonical Finding that failed one or more
validation rules.
"""

# Import Pydantic's BaseModel to define the validation failure as a structured and validated domain model.
from pydantic import BaseModel

# Import the canonical Finding model because every validation failure must be associated with the Finding that failed validation.
from vpap.domain.finding import Finding


class ValidationFailure(BaseModel):
    """
    Describes a validation failure for a canonical Finding.
    """

    # Stores the canonical Finding that failed validation.
    finding: Finding

    # Stores the name or identifier of the validation rule that the Finding failed.
    rule: str

    # Stores the human-readable explanation of why the validation rule failed.
    reason: str