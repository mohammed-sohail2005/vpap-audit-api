"""
Live authentication and tenant-isolation test.

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
"""

import os
import requests


BASE = "https://vpap-audit-api.onrender.com"

TENANT_ID = "vpap-pilot"


def get_required_env(name):
    value = os.environ.get(name)

    if not value:
        raise RuntimeError(
            f"{name} is not set.\n"
            f"Set it in PowerShell before running this test."
        )

    return value


def check(label, response, expected_status):
    ok = response.status_code == expected_status

    print(
        f"{'PASS' if ok else 'FAIL'} - {label}: "
        f"got {response.status_code}, expected {expected_status}"
    )

    if not ok:
        print(f"       response body: {response.text[:500]}")

    return ok


# ============================================================
# LOAD MANUALLY ISSUED TOKENS
# ============================================================

print("=" * 60)
print("LIVE AUTHENTICATION + TENANT ISOLATION TEST")
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
# TEST 1 - NO TOKEN
# ============================================================

print("1) No token at all...")

r = requests.get(
    f"{BASE}/findings/health-check-fake-id/history",
    timeout=30,
)

check(
    "No token -> 401",
    r,
    401,
)

print()


# ============================================================
# TEST 2 - VALID TOKEN, MATCHING TENANT
# ============================================================

print("2) Valid token, matching tenant...")

r = requests.post(
    f"{BASE}/findings",
    headers=HEADERS,
    json={
        "tenant_id": TENANT_ID,
        "source_system": "WIZ",
        "source_finding_id": "auth-test-001",
        "cve_id": "CVE-2026-99001",
        "asset_id": "asset-test-001",
    },
    timeout=30,
)

check(
    "Matching tenant -> accepted",
    r,
    r.status_code,
)

print(f"       status: {r.status_code}")
print(f"       body: {r.text[:300]}")
print()


# ============================================================
# TEST 3 - VALID TOKEN, WRONG TENANT
# ============================================================

print("3) Valid token, WRONG tenant...")

r = requests.post(
    f"{BASE}/findings",
    headers=WRONG_TENANT_HEADERS,
    json={
        "tenant_id": TENANT_ID,
        "source_system": "WIZ",
        "source_finding_id": "auth-test-002",
        "cve_id": "CVE-2026-99001",
        "asset_id": "asset-test-001",
    },
    timeout=30,
)

check(
    "Wrong tenant -> 403",
    r,
    403,
)

print()


# ============================================================
# TEST 4 - TAMPERED / GARBAGE TOKEN
# ============================================================

print("4) Tampered/garbage token...")

r = requests.post(
    f"{BASE}/findings",
    headers={
        "Authorization": "Bearer this.is.not.a.real.jwt"
    },
    json={
        "tenant_id": TENANT_ID,
        "source_system": "WIZ",
        "source_finding_id": "auth-test-003",
        "cve_id": "CVE-2026-99001",
        "asset_id": "asset-test-001",
    },
    timeout=30,
)

check(
    "Garbage token -> 401",
    r,
    401,
)

print()

print("=" * 60)
print("AUTH + TENANT ISOLATION TEST COMPLETE")
print("=" * 60)