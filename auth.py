"""
vpap_audit.auth
-----------------

Authentication and secure token vending for the VPAP Persistence API.

Every protected API call must carry:

    Authorization: Bearer <token>

The JWT contains:
- tenant_id
- scope
- subject
- issuer
- audience
- issued-at time
- expiry time

AUTHENTICATION MODEL
--------------------

The VPAP API uses two different kinds of credentials:

1. VPAP_AUTH_SECRET
   - Server-side only.
   - Used to sign and verify JWTs.
   - NEVER distributed to teammates.

2. Vending credentials
   - One separate credential per service.
   - Used only to request a short-lived JWT.
   - Do NOT contain signing authority.
   - The server determines tenant, subject and scope.

Example:

    Muizz credential
        ->
    ingestion-service
        ->
    vpap-pilot
        ->
    persistence:*

The client cannot choose a different tenant or subject.

In a real production deployment:
- VPAP_AUTH_SECRET would be replaced by a real IdP public key.
- Tokens would come from a real identity provider.
- Token validation would use the IdP's public key/JWKS.

For the current POC, this module provides secure mock token
issuance through the vending endpoint.
"""

import hashlib
import hmac
import json
import os
import time
from typing import Optional

import jwt
from fastapi import Header, HTTPException


# ============================================================
# Configuration
# ============================================================

# Shared secret used to sign and verify JWTs in this MOCK setup.
#
# IMPORTANT:
# There is intentionally NO fallback/default secret.
#
# This value must exist in the server environment.
#
# NEVER distribute this value to teammates.
AUTH_SECRET = os.environ["VPAP_AUTH_SECRET"]

AUTH_ALGORITHM = "HS256"


# ------------------------------------------------------------
# Secret fingerprint
# ------------------------------------------------------------
#
# This is only a short diagnostic fingerprint.
# The actual secret is never printed.
#
# You may remove this in production if desired.
_secret_fingerprint = hashlib.sha256(
    AUTH_SECRET.encode()
).hexdigest()[:8]

print(
    f"[auth] VPAP_AUTH_SECRET fingerprint at startup: "
    f"{_secret_fingerprint}"
)


# ------------------------------------------------------------
# JWT issuer and audience
# ------------------------------------------------------------

TOKEN_ISSUER = os.environ.get(
    "VPAP_TOKEN_ISSUER",
    "vpap-audit-api-poc",
)

TOKEN_AUDIENCE = os.environ.get(
    "VPAP_TOKEN_AUDIENCE",
    "vpap-persistence-api",
)


# ------------------------------------------------------------
# JWT lifetime
# ------------------------------------------------------------

TOKEN_LIFETIME_SECONDS = 8 * 60 * 60  # 8 hours


# ============================================================
# VENDING CREDENTIAL CONFIGURATION
# ============================================================

"""
Vending credentials are configured through:

    VPAP_VENDING_CREDENTIALS

The environment variable contains JSON.

Example structure:

[
    {
        "key_hash": "<sha256 hash>",
        "subject": "ingestion-service",
        "tenant_id": "vpap-pilot",
        "scope": "persistence:*"
    },
    {
        "key_hash": "<sha256 hash>",
        "subject": "enrichment-service",
        "tenant_id": "vpap-pilot",
        "scope": "persistence:*"
    },
    {
        "key_hash": "<sha256 hash>",
        "subject": "policy-engine",
        "tenant_id": "vpap-pilot",
        "scope": "persistence:*"
    }
]

IMPORTANT:

Only SHA-256 hashes of vending credentials are stored on
the server.

The actual vending credentials are given to teammates once
through a secure out-of-band channel.

The server never needs to store the plaintext credential.
"""


class VendingIdentity:
    """
    Server-side identity associated with a vending credential.

    The client does NOT provide these values.

    They are determined entirely by the server.
    """

    def __init__(
        self,
        subject: str,
        tenant_id: str,
        scope: str,
    ):
        self.subject = subject
        self.tenant_id = tenant_id
        self.scope = scope


def _load_vending_credentials() -> dict[str, VendingIdentity]:
    """
    Load vending credentials from the environment.

    Returns:

        {
            sha256_hash: VendingIdentity(...)
        }

    If VPAP_VENDING_CREDENTIALS is not configured, vending is
    unavailable.

    This does NOT affect normal JWT validation.
    """

    raw = os.environ.get(
        "VPAP_VENDING_CREDENTIALS"
    )

    if not raw:
        return {}

    try:
        entries = json.loads(raw)

    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "VPAP_VENDING_CREDENTIALS contains invalid JSON."
        ) from exc

    if not isinstance(entries, list):
        raise RuntimeError(
            "VPAP_VENDING_CREDENTIALS must contain a JSON list."
        )

    credentials: dict[str, VendingIdentity] = {}

    for entry in entries:

        if not isinstance(entry, dict):
            raise RuntimeError(
                "Each vending credential must be a JSON object."
            )

        key_hash = entry.get("key_hash")
        subject = entry.get("subject")
        tenant_id = entry.get("tenant_id")
        scope = entry.get("scope")

        if not all(
            isinstance(value, str) and value.strip()
            for value in (
                key_hash,
                subject,
                tenant_id,
                scope,
            )
        ):
            raise RuntimeError(
                "Each vending credential must contain "
                "key_hash, subject, tenant_id and scope."
            )

        if len(key_hash) != 64:
            raise RuntimeError(
                "Vending credential key_hash must be "
                "a SHA-256 hexadecimal hash."
            )

        key_hash = key_hash.lower()

        if key_hash in credentials:
            raise RuntimeError(
                "Duplicate vending credential hash configured."
            )

        credentials[key_hash] = VendingIdentity(
            subject=subject,
            tenant_id=tenant_id,
            scope=scope,
        )

    return credentials


def _hash_vending_credential(
    credential: str,
) -> str:
    """
    Hash a plaintext vending credential.

    The plaintext credential is never stored by this module.
    """

    return hashlib.sha256(
        credential.encode("utf-8")
    ).hexdigest()


def authenticate_vending_credential(
    credential: str,
) -> VendingIdentity:
    """
    Validate a vending credential.

    IMPORTANT:

    The caller supplies only the credential.

    The caller cannot supply:
        tenant_id
        subject
        scope

    Those values come from the server-side mapping.

    Raises:
        HTTP 503 if vending is not configured.
        HTTP 401 if the credential is invalid.
    """

    if not credential:
        raise HTTPException(
            status_code=401,
            detail="Missing vending credential.",
        )

    credentials = _load_vending_credentials()

    if not credentials:
        raise HTTPException(
            status_code=503,
            detail="Token vending is not configured.",
        )

    presented_hash = _hash_vending_credential(
        credential
    )

    identity = None

    for stored_hash, configured_identity in credentials.items():

        if hmac.compare_digest(
            presented_hash,
            stored_hash,
        ):
            identity = configured_identity
            break

    if identity is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid vending credential.",
        )

    return identity


# ============================================================
# TOKEN ISSUANCE
# ============================================================

def issue_token(
    tenant_id: str,
    scope: str,
    subject: str,
) -> dict:
    """
    Issue a signed JWT carrying:

    - tenant_id
    - scope
    - issuer
    - audience
    - subject
    - issued-at time
    - expiry

    This function should only be called by trusted server-side
    code after identity has been established.

    The vending endpoint calls this function only after looking
    up the server-side vending credential.
    """

    now = int(time.time())

    payload = {
        "sub": subject,
        "tenant_id": tenant_id,
        "scope": scope,
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "iat": now,
        "exp": now + TOKEN_LIFETIME_SECONDS,
    }

    token = jwt.encode(
        payload,
        AUTH_SECRET,
        algorithm=AUTH_ALGORITHM,
    )

    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": TOKEN_LIFETIME_SECONDS,
        "tenant_id": tenant_id,
        "scope": scope,
        "subject": subject,
    }


# ============================================================
# AUTHENTICATION CONTEXT
# ============================================================

class AuthContext:
    """
    Verified identity and claims extracted from a valid JWT.

    Endpoint functions can use this object to determine:

    - which tenant the caller belongs to
    - what scope the caller has
    - which service/identity made the request
    """

    def __init__(
        self,
        tenant_id: str,
        scope: str,
        subject: str,
    ):
        self.tenant_id = tenant_id
        self.scope = scope
        self.subject = subject


# ============================================================
# BEARER TOKEN EXTRACTION
# ============================================================

def _extract_bearer_token(
    authorization: Optional[str],
) -> str:
    """
    Extract the JWT from:

        Authorization: Bearer <token>
    """

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header.",
        )

    parts = authorization.split()

    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail=(
                "Authorization header must be "
                "'Bearer <token>'."
            ),
        )

    return parts[1]


# ============================================================
# JWT VALIDATION
# ============================================================

def require_auth(
    authorization: Optional[str] = Header(None),
) -> AuthContext:
    """
    FastAPI authentication dependency.

    Protected endpoints should use:

        auth: AuthContext = Depends(require_auth)

    Checks:

    1. Authorization header exists.
    2. Header uses Bearer authentication.
    3. JWT signature is valid.
    4. JWT has not expired.
    5. JWT issuer matches TOKEN_ISSUER.
    6. JWT audience matches TOKEN_AUDIENCE.
    7. JWT contains tenant_id.
    8. JWT contains scope.
    """

    token = _extract_bearer_token(
        authorization
    )

    try:

        payload = jwt.decode(
            token,
            AUTH_SECRET,
            algorithms=[AUTH_ALGORITHM],
            issuer=TOKEN_ISSUER,
            audience=TOKEN_AUDIENCE,
        )

    except jwt.ExpiredSignatureError:

        raise HTTPException(
            status_code=401,
            detail=(
                "Token has expired. "
                "Please obtain a new token."
            ),
        )

    except jwt.InvalidIssuerError:

        raise HTTPException(
            status_code=401,
            detail="Token issuer is not recognized.",
        )

    except jwt.InvalidAudienceError:

        raise HTTPException(
            status_code=401,
            detail="Token audience does not match this API.",
        )

    except jwt.InvalidTokenError:

        raise HTTPException(
            status_code=401,
            detail="Invalid or tampered token.",
        )

    tenant_id = payload.get(
        "tenant_id"
    )

    scope = payload.get(
        "scope"
    )

    subject = payload.get(
        "sub"
    )

    if not tenant_id or not scope or not subject:

        raise HTTPException(
            status_code=401,
            detail=(
                "Token is missing required claims "
                "(tenant_id, scope, subject)."
            ),
        )

    return AuthContext(
        tenant_id=tenant_id,
        scope=scope,
        subject=subject,
    )


# ============================================================
# TENANT VALIDATION
# ============================================================

def require_tenant_match(
    auth: AuthContext,
    request_tenant_id: str,
) -> None:
    """
    Ensure the tenant inside the signed token matches
    the tenant requested by the API operation.
    """

    if auth.tenant_id != request_tenant_id:

        raise HTTPException(
            status_code=403,
            detail=(
                f"Token is authorized for tenant "
                f"'{auth.tenant_id}', "
                f"but request is for tenant "
                f"'{request_tenant_id}'."
            ),
        )


# ============================================================
# SCOPE VALIDATION
# ============================================================

def require_scope(
    auth: AuthContext,
    required_scope: str,
) -> None:
    """
    Verify that the token has permission for the requested action.

    Exact:

        persistence:write

    Wildcard:

        persistence:*

    allows all persistence actions.
    """

    if (
        auth.scope != required_scope
        and auth.scope != "persistence:*"
    ):

        raise HTTPException(
            status_code=403,
            detail=(
                f"Token scope '{auth.scope}' does not permit "
                f"'{required_scope}'."
            ),
        )