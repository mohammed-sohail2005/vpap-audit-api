"""
Test: PATCH /enrichment-runs/{id} auth + tenant enforcement
------------------------------------------------------------

This test uses manually issued JWTs.

Required environment variables:

    VPAP_TEST_TOKEN
        Valid token for tenant "vpap-pilot"

    VPAP_WRONG_TENANT_TOKEN
        Valid token for a different tenant

Set them in PowerShell before running:

    $env:VPAP_TEST_TOKEN="..."
    $env:VPAP_WRONG_TENANT_TOKEN="..."

Do NOT put tokens in this file or commit them to Git.

Tests:

  1. Create a real enrichment run
  2. No token -> 401
  3. Valid token + wrong tenant in body -> 403
  4. Valid token + matching tenant -> 200
  5. Tampered token -> 401
"""

import os
import requests
from datetime import datetime, timezone


BASE = "https://vpap-audit-api.onrender.com"

TENANT_ID = "vpap-pilot"
WRONG_TENANT = "some-other-tenant"


# ============================================================
# HELPERS
# ============================================================

def get_required_env(name):
    value = os.environ.get(name)

    if not value:
        raise RuntimeError(
            f"{name} is not set.\n"
            f"Set it in PowerShell before running this test."
        )

    return value


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def check(label, response, expected_status):
    ok = response.status_code == expected_status

    print(
        f"{'PASS' if ok else 'FAIL'} - {label}: "
        f"got {response.status_code}, expected {expected_status}"
    )

    if not ok:
        print(
            f"       response body: "
            f"{response.text[:500]}"
        )

    return ok


# ============================================================
# LOAD MANUALLY ISSUED TOKENS
# ============================================================

print("=" * 60)
print("PATCH ENRICHMENT RUN AUTH + TENANT TEST")
print("=" * 60)

token = get_required_env("VPAP_TEST_TOKEN")
wrong_tenant_token = get_required_env("VPAP_WRONG_TENANT_TOKEN")

HEADERS = {
    "Authorization": f"Bearer {token}"
}

WRONG_TENANT_HEADERS = {
    "Authorization": f"Bearer {wrong_tenant_token}"
}

print("Valid token loaded successfully")
print("Wrong-tenant token loaded successfully")
print()


# ============================================================
# SETUP - CREATE ENRICHMENT RUN
# ============================================================

print("=" * 60)
print("SETUP - create enrichment run")
print("=" * 60)

run_resp = requests.post(
    f"{BASE}/enrichment-runs",
    headers=HEADERS,
    json={
        "tenant_id": TENANT_ID,
        "source_system": "WIZ",
        "adapter_name": "auth-test-adapter",
        "adapter_version": "1.0.0",
        "schema_version": "1.0",
        "started_at": now_iso(),
        "status": "RUNNING",
    },
    timeout=30,
)

if run_resp.status_code != 200:
    raise RuntimeError(
        "Failed to create enrichment run.\n"
        f"Status: {run_resp.status_code}\n"
        f"Response: {run_resp.text[:500]}"
    )

enrichment_run_id = run_resp.json()["enrichment_run_id"]

print(
    f"PASS - enrichment run created: "
    f"{enrichment_run_id}"
)
print()


# ============================================================
# TEST 1 - NO TOKEN
# ============================================================

print("=" * 60)
print("1) No token at all")
print("=" * 60)

response = requests.patch(
    f"{BASE}/enrichment-runs/{enrichment_run_id}",
    json={
        "tenant_id": TENANT_ID,
        "status": "COMPLETED",
        "completed_at": now_iso(),
    },
    timeout=30,
)

check(
    "No token -> 401",
    response,
    401,
)

print()


# ============================================================
# TEST 2 - WRONG TENANT
# ============================================================

print("=" * 60)
print("2) Valid token, WRONG tenant")
print("=" * 60)

response = requests.patch(
    f"{BASE}/enrichment-runs/{enrichment_run_id}",
    headers=WRONG_TENANT_HEADERS,
    json={
        "tenant_id": TENANT_ID,
        "status": "COMPLETED",
        "completed_at": now_iso(),
    },
    timeout=30,
)

check(
    "Wrong tenant -> 403",
    response,
    403,
)

print()


# ============================================================
# TEST 3 - MATCHING TENANT
# ============================================================

print("=" * 60)
print("3) Valid token, matching tenant")
print("=" * 60)

response = requests.patch(
    f"{BASE}/enrichment-runs/{enrichment_run_id}",
    headers=HEADERS,
    json={
        "tenant_id": TENANT_ID,
        "status": "COMPLETED",
        "completed_at": now_iso(),
    },
    timeout=30,
)

ok = check(
    "Matching tenant -> 200",
    response,
    200,
)

if ok:
    print(
        f"       response: "
        f"{response.text[:500]}"
    )

print()


# ============================================================
# TEST 4 - TAMPERED / GARBAGE TOKEN
# ============================================================

print("=" * 60)
print("4) Tampered/garbage token")
print("=" * 60)

response = requests.patch(
    f"{BASE}/enrichment-runs/{enrichment_run_id}",
    headers={
        "Authorization": "Bearer this.is.not.a.real.jwt"
    },
    json={
        "tenant_id": TENANT_ID,
        "status": "COMPLETED",
        "completed_at": now_iso(),
    },
    timeout=30,
)

check(
    "Garbage token -> 401",
    response,
    401,
)

print()


# ============================================================
# SUMMARY
# ============================================================

print("=" * 60)
print("AUTH + TENANT ENFORCEMENT TEST COMPLETE")
print("=" * 60)