"""
vpap_audit.auth
-----------------
Mock IdP / OAuth2-style authentication for the VPAP Persistence API.

WHY THIS EXISTS (context for reviewers):
The team decided every call into the Persistence API must carry a Bearer
token (Authorization: Bearer <token>), separate from the request body.
The token is a JWT (JSON Web Token - a signed, tamper-evident piece of
text) carrying claims: which tenant it belongs to, what it's allowed to
do (scope), and when it expires. The API checks all three before doing
any work.

This is a MOCK identity provider, not a real one - appropriate for this
POC phase. In a real production deployment, VPAP_AUTH_SECRET would be
replaced by a real IdP's public key (e.g. Auth0/Okta/Azure AD), and
/auth/token below would not exist at all - tokens would come from that
real IdP instead. Swapping to a real IdP later only requires changing
how tokens are ISSUED; the VALIDATION logic here (checking signature,
expiry, tenant, scope) stays the same either way.

WHY A TOKEN, NOT JUST A TENANT_ID IN THE BODY:
A JWT is cryptographically signed - the server can prove nobody tampered
with it after it was issued. If we just trusted a plain "tenant_id" field
in the request body, anyone could type in any tenant_id they wanted with
zero verification. The signature is what makes the tenant claim trustworthy
(defense in depth - even if a token is intercepted, it can't be altered to
claim a different tenant, and it can't be reused after it expires).
"""

import os
import time
from typing import Optional
import jwt  # PyJWT
from fastapi import Header, HTTPException

# ============================================================
# Configuration
# ============================================================

# Shared secret used to sign/verify tokens. In this MOCK setup, the same
# secret both issues and validates tokens (symmetric signing, HS256).
# A real IdP would instead publish a public key (JWKS) and use asymmetric
# signing (RS256), so only the IdP itself can issue valid tokens - the
# API would only ever hold the public key, never a signing secret.
AUTH_SECRET = os.environ.get("VPAP_AUTH_SECRET", "dev-only-mock-secret-change-me")
AUTH_ALGORITHM = "HS256"

# How long an issued token stays valid before it must be refreshed.
# Per the team's requirement ("no repeated authentication at every step"),
# this is set generously so one token can be reused across a whole
# pipeline run (ingestion -> enrichment -> policy engine) without needing
# to re-authenticate for every single API call.
TOKEN_LIFETIME_SECONDS = 8 * 60 * 60  # 8 hours


# ============================================================
# Token issuance (the MOCK "IdP" side)
# ============================================================

def issue_token(tenant_id: str, scope: str, subject: str) -> dict:
    """
    Issue a signed JWT carrying tenant_id and scope claims.

    tenant_id: which tenant this token is authorized to act as - every
               API request made with this token must match this tenant,
               enforced in require_auth() below.
    scope:     what the caller is allowed to do, e.g. "persistence:write"
               or "persistence:read". Kept simple for the POC - a real
               system might have finer-grained scopes per table/action.
    subject:   who/what this token was issued to (e.g. "enrichment-service"),
               for traceability - shows up in logs and audit_event's actor_id.
    """
    now = int(time.time())
    payload = {
        "sub": subject,
        "tenant_id": tenant_id,
        "scope": scope,
        "iat": now,                              # issued-at
        "exp": now + TOKEN_LIFETIME_SECONDS,      # expiry - checked automatically by jwt.decode()
    }
    token = jwt.encode(payload, AUTH_SECRET, algorithm=AUTH_ALGORITHM)
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": TOKEN_LIFETIME_SECONDS,
        "tenant_id": tenant_id,
        "scope": scope,
    }


# ============================================================
# Token validation (what every protected endpoint runs first)
# ============================================================

class AuthContext:
    """The verified identity/claims extracted from a valid token.
    Passed into endpoint functions that need to know who's calling
    and enforce tenant-matching against the request body."""
    def __init__(self, tenant_id: str, scope: str, subject: str):
        self.tenant_id = tenant_id
        self.scope = scope
        self.subject = subject


def _extract_bearer_token(authorization: Optional[str]) -> str:
    """
    Pulls the raw token out of the Authorization header.
    Expected format: "Authorization: Bearer <token>" - the auth
    material is deliberately kept OUT of the request body, per the
    team's requirement, so persistence payloads stay pure data.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header.")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authorization header must be 'Bearer <token>'.")
    return parts[1]


def require_auth(authorization: Optional[str] = Header(None)) -> AuthContext:
    """
    FastAPI dependency - add `auth: AuthContext = Depends(require_auth)`
    to any endpoint that needs authentication. FastAPI automatically
    runs this BEFORE the endpoint's own code, and rejects the request
    with a 401 if anything below fails.

    Checks, in order:
      1. Header is present and well-formed
      2. Token signature is valid (proves it was issued by us, unaltered)
      3. Token is not expired (checked automatically by jwt.decode via 'exp')
      4. Token has the required claims (tenant_id, scope)
    Tenant-matching against the actual request body happens separately,
    in require_tenant_match() below, since that needs to see the request
    body which isn't available at this stage.
    """
    token = _extract_bearer_token(authorization)

    try:
        payload = jwt.decode(token, AUTH_SECRET, algorithms=[AUTH_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired. Please re-authenticate.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid or tampered token.")

    tenant_id = payload.get("tenant_id")
    scope = payload.get("scope")
    subject = payload.get("sub")

    if not tenant_id or not scope:
        raise HTTPException(status_code=401, detail="Token is missing required claims (tenant_id, scope).")

    return AuthContext(tenant_id=tenant_id, scope=scope, subject=subject)


def require_tenant_match(auth: AuthContext, request_tenant_id: str) -> None:
    """
    Defense-in-depth check per Hidayat's instruction: even with a valid,
    signed token, the tenant_id INSIDE the token must match the tenant_id
    the request is actually trying to act on. This stops a token that
    leaked/was intercepted (MITM) from being reused to write into a
    DIFFERENT tenant's data - the token is cryptographically locked to
    one tenant only.
    """
    if auth.tenant_id != request_tenant_id:
        raise HTTPException(
            status_code=403,
            detail=f"Token is authorized for tenant '{auth.tenant_id}', "
                   f"but request is for tenant '{request_tenant_id}'.",
        )


def require_scope(auth: AuthContext, required_scope: str) -> None:
    """Checks the token's scope permits the requested action."""
    if auth.scope != required_scope and auth.scope != "persistence:*":
        raise HTTPException(
            status_code=403,
            detail=f"Token scope '{auth.scope}' does not permit '{required_scope}'.",
        )