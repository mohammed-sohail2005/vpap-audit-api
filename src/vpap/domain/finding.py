"""
Canonical VPAP Finding domain model.

This model represents the normalized finding structure expected by VPAP.
It must remain independent of any specific source system such as Wiz.
"""

from datetime import datetime
from hashlib import sha256

from pydantic import BaseModel, Field


# This class defines the canonical data model for a vulnerability finding within VPAP.
# It inherits from Pydantic's BaseModel, which provides data validation, serialization, and deserialization capabilities out of the box.
# This model is designed to be independent of any specific source system, acting as a standardized representation for all incoming vulnerability data.
class Finding(BaseModel):
    """
    Canonical VPAP vulnerability finding.

    Source-specific data must be mapped into this model by the appropriate
    source connector/mapper.
    """

    # Identifies the original system from which the finding originated (e.g., "WIZ").
    # This is a mandatory string field.
    source_system: str
    # A unique identifier for the finding within its original source system.
    # This is a mandatory string field.
    source_finding_id: str
    # The Common Vulnerabilities and Exposures (CVE) ID associated with the finding.
    # It's a mandatory string field and is validated against a regex pattern to ensure it conforms to the standard CVE format (e.g., "CVE-YYYY-NNNN").
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    # The identifier of the asset on which the finding was discovered.
    # This is a mandatory string field.
    asset_id: str
    # An optional identifier for the software package related to the finding.
    # It can be a string or None.
    package_id: str | None = None
    # The CVSS Base Score, representing the fundamental severity of the vulnerability.
    # It's an optional float field, constrained to be between 0 and 10 (inclusive).
    cvss_base: float | None = Field(default=None, ge=0, le=10)
    # The CVSS Vector string, providing a detailed breakdown of the CVSS score.
    # It's an optional string field.
    cvss_vector: str | None = None
    # A textual description of the vulnerability.
    # It's an optional string field with a maximum length of 4000 characters.
    description: str | None = Field(default=None, max_length=4000)
    # An optional identifier for the business service affected by the finding.
    # It can be a string or None.
    business_service_id: str | None = None
    # A boolean flag indicating whether the affected asset is exposed to the internet.
    # It's an optional boolean field.
    internet_exposed: bool | None = None
    # The timestamp indicating when the vulnerability was first detected.
    # It's an optional datetime object.
    first_detected_at: datetime | None = None

    # This method generates a deterministic idempotency key for the finding.
    # The key is a SHA256 hash derived from a combination of core finding attributes.
    # This ensures that identical findings from different ingestion runs or sources can be uniquely identified and deduplicated within the VPAP system.
    def idempotency_key(self) -> str:
        """
        Generate the deterministic VPAP idempotency key.

        The calculation follows the canonical model specified by VPAP.
        """

        # Constructs a string by concatenating key attributes, separated by "|".
        # The 'package_id' uses a placeholder "-" if it's None to maintain consistency in the material string for hashing.
        material = "|".join(
            [
                self.source_system,
                self.source_finding_id,
                self.asset_id,
                self.package_id or "-",
            ]
        )

        # Encodes the material string to bytes and computes its SHA256 hash.
        # The hexadecimal representation of the hash is returned as the idempotency key.
        return sha256(material.encode()).hexdigest()