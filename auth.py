"""
vpap_audit.auth
-----------------
Mock IdP / OAuth2-style authentication for the VPAP Persistence API.

WHY THIS EXISTS:
Every call into the Persistence API must carry a Bearer token
(Authorization: Bearer <token>), separate from the request body.

The token is a JWT (JSON Web Token) carrying:
- tenant_id
- scope
- subject
- issuer
- audience
- issued-at time
- expiry time

The API validates the token before allowing protected operations.

This is a MOCK identity provider for the POC phase.

In a real production deployment:
- VPAP_AUTH_SECRET would be replaced by a real IdP public key.
- Tokens would come from a real identity provider.
- Token validation would use the IdP's public key/JWKS.

Token issuance is NOT exposed through a public HTTP endpoint.
Tokens are generated out-of-band by a trusted operator using
generate_token.py.
"""

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
# There is intentionally NO fallback/default secret here.
# VPAP_AUTH_SECRET must be explicitly configured in the environment.
#
# This prevents the API from silently using a known development
# secret when the real deployment secret is missing.
AUTH_SECRET = os.environ["VPAP_AUTH_SECRET"]

AUTH_ALGORITHM = "HS256"


# Issuer and audience identify where the token came from
# and which API it is intended for.
TOKEN_ISSUER = os.environ.get(
    "VPAP_TOKEN_ISSUER",
    "vpap-audit-api-poc",
)

TOKEN_AUDIENCE = os.environ.get(
    "VPAP_TOKEN_AUDIENCE",
    "vpap-persistence-api",
)


# Token lifetime.
# One token can be reused throughout a pipeline run instead
# of authenticating again for every API call.
TOKEN_LIFETIME_SECONDS = 8 * 60 * 60  # 8 hours


# ============================================================
# Token issuance
# ============================================================

def issue_token(
    tenant_id: str,
    scope: str,
    subject: str,
) -> dict:
    """
    Issue a signed JWT carrying tenant_id, scope, issuer,
    audience, subject, issued-at time and expiry.

    This function is NOT exposed through a public HTTP endpoint.

    It is intended to be called by generate_token.py,
    which is run by a trusted operator.

    Parameters
    ----------
    tenant_id:
        Tenant the token is authorized to operate against.

    scope:
        Permissions granted to the token, for example:
        "persistence:read"
        "persistence:write"
        "persistence:*"

    subject:
        Service or identity receiving the token.
        Example:
        "enrichment-service"
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
    }


# ============================================================
# Authentication context
# ============================================================

class AuthContext:
    """
    Verified identity and claims extracted from a valid JWT.

    Endpoint functions can use this object to determine:
    - which tenant the caller belongs to
    - what scope the caller has
    - which service/identity issued the request
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
# Bearer token extraction
# ============================================================

def _extract_bearer_token(
    authorization: Optional[str],
) -> str:
    """
    Extract the JWT from:

        Authorization: Bearer <token>

    Authentication material stays in the HTTP header,
    separate from the request body.
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
            detail="Authorization header must be 'Bearer <token>'.",
        )

    return parts[1]


# ============================================================
# JWT validation
# ============================================================

def require_auth(
    authorization: Optional[str] = Header(None),
) -> AuthContext:
    """
    FastAPI authentication dependency.

    Protected endpoints should use:

        auth: AuthContext = Depends(require_auth)

    The following checks are performed:

    1. Authorization header exists.
    2. Header uses Bearer authentication.
    3. JWT signature is valid.
    4. JWT has not expired.
    5. JWT issuer matches TOKEN_ISSUER.
    6. JWT audience matches TOKEN_AUDIENCE.
    7. JWT contains tenant_id.
    8. JWT contains scope.

    Tenant matching against the request body is performed
    separately by require_tenant_match().
    """

    token = _extract_bearer_token(authorization)

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
            detail="Token has expired. Please re-authenticate.",
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

    tenant_id = payload.get("tenant_id")
    scope = payload.get("scope")
    subject = payload.get("sub")

    if not tenant_id or not scope:
        raise HTTPException(
            status_code=401,
            detail=(
                "Token is missing required claims "
                "(tenant_id, scope)."
            ),
        )

    return AuthContext(
        tenant_id=tenant_id,
        scope=scope,
        subject=subject,
    )


# ============================================================
# Tenant validation
# ============================================================

def require_tenant_match(
    auth: AuthContext,
    request_tenant_id: str,
) -> None:
    """
    Ensure the tenant inside the signed token matches
    the tenant requested by the API operation.

    Example:

        Token tenant_id = vpap-pilot
        Request tenant_id = vpap-pilot

        -> allowed

    But:

        Token tenant_id = vpap-pilot
        Request tenant_id = another-tenant

        -> rejected with HTTP 403
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
# Scope validation
# ============================================================

def require_scope(
    auth: AuthContext,
    required_scope: str,
) -> None:
    """
    Verify that the token has permission for the requested action.

    Exact scope example:

        persistence:write

    Wildcard scope:

        persistence:*

    allows all persistence actions.

    NOTE:
    This function only performs the check.
    Protected endpoints must explicitly call it if scope
    enforcement is required.
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