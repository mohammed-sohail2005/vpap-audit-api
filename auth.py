"""
vpap_audit.auth
-----------------

Authentication for the VPAP Persistence API.

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

VPAP_AUTH_SECRET:
   - Server-side only.
   - Used to sign and verify JWTs.
   - NEVER distributed to teammates.

Tokens are issued out-of-band by a trusted operator running
generate_token.py locally. There is no public token-issuance
endpoint.

In a real production deployment:
- VPAP_AUTH_SECRET would be replaced by a real IdP public key.
- Tokens would come from a real identity provider (e.g. Entra ID,
  Okta) via OIDC/OAuth2 client credentials or workload identity.
- Token validation would use the IdP's public key/JWKS.

For the current POC, this module validates JWTs issued
out-of-band by generate_token.py.
"""

import hashlib
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

    This function is called by generate_token.py, run locally
    by a trusted operator.
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