
"""
Test: finding_evidence idempotency
----------------------------------

Calls POST /evidence TWICE with the exact same:

    finding_instance_id
    enrichment_run_id

Confirms:

  1. Both calls succeed
  2. Both calls return the SAME evidence_snapshot_id
  3. The database upsert does not create a second evidence snapshot

Authentication uses a manually issued JWT supplied through:

    VPAP_TEST_TOKEN

Run with:

    py test_idempotency.py
"""

import os
import requests
import time
from datetime import datetime, timezone


BASE = "https://vpap-audit-api.onrender.com"

TENANT_ID = "vpap-pilot"

TEST_TOKEN = os.environ.get("VPAP_TEST_TOKEN")

if not TEST_TOKEN:
    raise RuntimeError(
        "VPAP_TEST_TOKEN environment variable is not set.\n"
        "Set it in PowerShell before running this test."
    )


# ============================================================
# HELPERS
# ============================================================

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def get_token():
    """
    Use a manually issued JWT supplied through VPAP_TEST_TOKEN.
    """

    if not TEST_TOKEN:
        raise RuntimeError(
            "VPAP_TEST_TOKEN environment variable is not set."
        )

    return TEST_TOKEN


def ok(resp, label):
    """
    Require HTTP 200 and return JSON response.
    """

    print(f"  -> {resp.status_code}", end=" ")

    if resp.status_code == 200:
        print("OK")
        return resp.json()

    print(f"FAILED: {resp.text[:500]}")

    raise SystemExit(
        f"{label} failed - stopping test"
    )


def ev(
    value,
    status="KNOWN",
    source="TEST_ADAPTER",
    confidence="HIGH",
):
    """
    Build an evidence value object.
    """

    return {
        "value": value,
        "status": status,
        "source": source,
        "retrieved_at": now_iso(),
        "confidence": confidence,
    }


# ============================================================
# SETUP
# ============================================================

print("=" * 60)
print("SETUP - authentication")
print("=" * 60)

token = get_token()

HEADERS = {
    "Authorization": f"Bearer {token}"
}

print("  auth token loaded successfully")


# ============================================================
# CREATE FINDING
# ============================================================

print("\n" + "=" * 60)
print("SETUP - create a finding")
print("=" * 60)

source_finding_id = (
    f"idempotency-test-{int(time.time())}"
)

finding_resp = ok(
    requests.post(
        f"{BASE}/findings",
        headers=HEADERS,
        json={
            "tenant_id": TENANT_ID,
            "source_system": "WIZ",
            "source_finding_id": source_finding_id,
            "cve_id": "CVE-2026-99002",
            "asset_id": "asset-idempotency-test",
            "cvss_base": 7.5,
            "status": "VALID",
        },
        timeout=30,
    ),
    "create finding",
)

finding_id = finding_resp["finding_id"]

print(f"  finding_id = {finding_id}")


# ============================================================
# CREATE ENRICHMENT RUN
# ============================================================

print("\n" + "=" * 60)
print("SETUP - create enrichment run")
print("=" * 60)

run_resp = ok(
    requests.post(
        f"{BASE}/enrichment-runs",
        headers=HEADERS,
        json={
            "tenant_id": TENANT_ID,
            "source_system": "WIZ",
            "adapter_name": "idempotency-test-adapter",
            "adapter_version": "1.0.0",
            "schema_version": "1.0",
            "started_at": now_iso(),
            "status": "RUNNING",
        },
        timeout=30,
    ),
    "create enrichment run",
)

enrichment_run_id = run_resp["enrichment_run_id"]

print(f"  enrichment_run_id = {enrichment_run_id}")


# ============================================================
# BUILD EVIDENCE PAYLOAD
# ============================================================

evidence_payload = {
    "finding_instance_id": finding_id,

    "source_finding_id": source_finding_id,

    "tenant_id": TENANT_ID,

    "source_system": "WIZ",

    "enrichment_run_id": enrichment_run_id,

    "schema_version": "1.0",

    "adapter_name": "idempotency-test-adapter",

    "adapter_version": "1.0.0",

    "cve_id": "CVE-2026-99002",

    "asset_id": "asset-idempotency-test",

    "cvss_base": 7.5,

    "epss_probability": ev(0.5),

    "epss_percentile": ev(0.5),

    "kev_status": ev(False),

    "internet_exposure": ev(True),

    "runtime_applicability": ev(True),

    "attack_path_reachable": ev(False),

    "business_criticality": ev("MEDIUM"),

    "compensating_controls": ev(
        [],
        status="KNOWN",
    ),
}


# ============================================================
# CALL 1
# ============================================================

print("\n" + "=" * 60)
print("CALL 1 - first evidence recording")
print("=" * 60)

resp1 = ok(
    requests.post(
        f"{BASE}/evidence",
        headers=HEADERS,
        json=evidence_payload,
        timeout=30,
    ),
    "evidence call 1",
)

snapshot_id_1 = resp1["evidence_snapshot_id"]

print(
    f"  evidence_snapshot_id = {snapshot_id_1}"
)


# ============================================================
# CALL 2
# ============================================================

print("\n" + "=" * 60)
print(
    "CALL 2 - EXACT SAME finding + enrichment run"
)
print("=" * 60)

resp2 = ok(
    requests.post(
        f"{BASE}/evidence",
        headers=HEADERS,
        json=evidence_payload,
        timeout=30,
    ),
    "evidence call 2",
)

snapshot_id_2 = resp2["evidence_snapshot_id"]

print(
    f"  evidence_snapshot_id = {snapshot_id_2}"
)


# ============================================================
# RESULT
# ============================================================

print("\n" + "=" * 60)
print("RESULT")
print("=" * 60)

if snapshot_id_1 == snapshot_id_2:

    print(
        "PASS - both calls returned the SAME "
        "evidence_snapshot_id"
    )

    print(
        "       idempotency is working."
    )

    print(
        "       Retry reused/updated the existing "
        "evidence record."
    )

else:

    print(
        "FAIL - two DIFFERENT evidence IDs were returned:"
    )

    print(
        f"       First : {snapshot_id_1}"
    )

    print(
        f"       Second: {snapshot_id_2}"
    )

    print(
        "       This indicates that the evidence "
        "idempotency behavior is not working."
    )

    raise SystemExit(
        "FAIL - evidence idempotency check failed."
    )

print("=" * 60)
