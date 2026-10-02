"""
VPAP 4.1 - End-to-end pipeline + audit trail test
--------------------------------------------------

Simulates ONE finding moving through the full VPAP pipeline:

    Ingestion
        |
        v
    finding_instance
        |
        +--> audit event
        |
        v
    Enrichment
        |
        +--> enrichment_run
        |
        +--> finding_evidence
        |
        +--> audit event
        |
        v
    Policy Engine
        |
        +--> policy_version
        |
        +--> priority_decision
        |
        +--> audit event
        |
        v
    Finding History / Audit Trail

Authentication:

    Authentication uses a manually issued JWT supplied through:

    VPAP_TEST_TOKEN

Run with:

    py test_pipeline_e2e.py
"""

import os
import requests
import time
from datetime import datetime, timezone


# ============================================================
# CONFIGURATION
# ============================================================

BASE = "https://vpap-audit-api.onrender.com"

TENANT_ID = "vpap-pilot"

TEST_TOKEN = os.environ.get("VPAP_TEST_TOKEN")


# ============================================================
# CONFIGURATION CHECK
# ============================================================

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

    print(
        f"  -> {resp.status_code}",
        end=" "
    )

    if resp.status_code == 200:
        print("OK")
        return resp.json()

    print(
        f"FAILED: {resp.text[:500]}"
    )

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
# STEP 0 - WAKE UP API
# ============================================================

print("=" * 60)
print(
    "STEP 0 - Wake up the API "
    "(free tier may be idle)"
)
print("=" * 60)

health_response = requests.get(
    f"{BASE}/",
    timeout=30,
)

print(
    f"  health check -> "
    f"{health_response.status_code} "
    f"{health_response.json()}"
)


if health_response.status_code != 200:
    raise SystemExit(
        "API health check failed."
    )


# ============================================================
# AUTH
# ============================================================

print("\n" + "=" * 60)
print(
    "AUTH - using manually issued JWT "
    "from VPAP_TEST_TOKEN"
)
print("=" * 60)

TOKEN = get_token()

HEADERS = {
    "Authorization": f"Bearer {TOKEN}"
}

print("  token loaded successfully")


# ============================================================
# STAGE 1 - INGESTION
# ============================================================

print("\n" + "=" * 60)
print("STAGE 1: INGESTION")
print("=" * 60)


source_finding_id = (
    f"wiz-e2e-test-{int(time.time())}"
)


# ------------------------------------------------------------
# 1a. Create finding
# ------------------------------------------------------------

print(
    "1a. Create finding via POST /findings"
)

finding_resp = ok(
    requests.post(
        f"{BASE}/findings",
        headers=HEADERS,
        json={
            "tenant_id": TENANT_ID,
            "source_system": "WIZ",
            "source_finding_id": source_finding_id,
            "cve_id": "CVE-2026-99001",
            "asset_id": "asset-payments-api-prod-01",
            "cvss_base": 9.8,
            "status": "VALID",
        },
        timeout=30,
    ),
    "create finding",
)

finding_id = finding_resp["finding_id"]

print(
    f"  finding_id = {finding_id}"
)


# ------------------------------------------------------------
# 1b. Log finding audit event
# ------------------------------------------------------------

print(
    "1b. Log audit event: "
    "finding_instance.created"
)

ok(
    requests.post(
        f"{BASE}/audit-events",
        headers=HEADERS,
        json={
            "actor_type": "system",
            "tenant_id": TENANT_ID,
            "actor_id": "ingest-service",
            "action": "finding_instance.created",
            "entity_type": "finding_instance",
            "entity_id": finding_id,
            "correlation_id": finding_id,
            "after_state": {
                "cve_id": "CVE-2026-99001",
                "asset_id": "asset-payments-api-prod-01",
            },
        },
        timeout=30,
    ),
    "audit: finding_instance.created",
)


# ============================================================
# STAGE 2 - ENRICHMENT
# ============================================================

print("\n" + "=" * 60)
print("STAGE 2: ENRICHMENT")
print("=" * 60)


# ------------------------------------------------------------
# 2a. Create enrichment run
# ------------------------------------------------------------

print(
    "2a. Start enrichment run via "
    "POST /enrichment-runs"
)

run_resp = ok(
    requests.post(
        f"{BASE}/enrichment-runs",
        headers=HEADERS,
        json={
            "tenant_id": TENANT_ID,
            "source_system": "WIZ",
            "adapter_name": "epss-kev-adapter",
            "adapter_version": "1.0.0",
            "schema_version": "1.0",
            "started_at": now_iso(),
            "status": "RUNNING",
        },
        timeout=30,
    ),
    "create enrichment run",
)

enrichment_run_id = run_resp[
    "enrichment_run_id"
]

print(
    f"  enrichment_run_id = "
    f"{enrichment_run_id}"
)


# ------------------------------------------------------------
# 2b. Log enrichment audit event
# ------------------------------------------------------------

print(
    "2b. Log audit event: "
    "enrichment_run.started"
)

ok(
    requests.post(
        f"{BASE}/audit-events",
        headers=HEADERS,
        json={
            "actor_type": "system",
            "tenant_id": TENANT_ID,
            "actor_id": "enrichment-service",
            "action": "enrichment_run.started",
            "entity_type": "enrichment_run",
            "entity_id": enrichment_run_id,
            "correlation_id": finding_id,
        },
        timeout=30,
    ),
    "audit: enrichment_run.started",
)


# ------------------------------------------------------------
# 2c. Record evidence
# ------------------------------------------------------------

print(
    "2c. Record evidence via POST /evidence"
)

evidence_resp = ok(
    requests.post(
        f"{BASE}/evidence",
        headers=HEADERS,
        json={
            "finding_instance_id": finding_id,

            "source_finding_id": source_finding_id,

            "tenant_id": TENANT_ID,

            "source_system": "WIZ",

            "enrichment_run_id": enrichment_run_id,

            "schema_version": "1.0",

            "adapter_name": "epss-kev-adapter",

            "adapter_version": "1.0.0",

            "cve_id": "CVE-2026-99001",

            "asset_id": "asset-payments-api-prod-01",

            "cvss_base": 9.8,

            "epss_probability": ev(0.91),

            "epss_percentile": ev(0.98),

            "kev_status": ev(True),

            "internet_exposure": ev(True),

            "runtime_applicability": ev(True),

            "attack_path_reachable": ev(True),

            "business_criticality": ev(
                "CRITICAL"
            ),

            "compensating_controls": ev(
                [],
                status="KNOWN"
            ),
        },
        timeout=30,
    ),
    "create finding evidence",
)

evidence_snapshot_id = (
    evidence_resp["evidence_snapshot_id"]
)

print(
    f"  evidence_snapshot_id = "
    f"{evidence_snapshot_id}"
)


# ------------------------------------------------------------
# 2d. Log evidence audit event
# ------------------------------------------------------------

print(
    "2d. Log audit event: "
    "finding_evidence.recorded"
)

ok(
    requests.post(
        f"{BASE}/audit-events",
        headers=HEADERS,
        json={
            "actor_type": "system",
            "tenant_id": TENANT_ID,
            "actor_id": "enrichment-service",
            "action": "finding_evidence.recorded",
            "entity_type": "finding_evidence",
            "entity_id": evidence_snapshot_id,
            "correlation_id": finding_id,
            "evidence_ref": evidence_snapshot_id,
            "after_state": {
                "epss_probability": 0.91,
                "kev_status": True,
            },
        },
        timeout=30,
    ),
    "audit: finding_evidence.recorded",
)


# ============================================================
# STAGE 3 - POLICY ENGINE
# ============================================================

print("\n" + "=" * 60)
print("STAGE 3: POLICY ENGINE")
print("=" * 60)


policy_version_id = (
    f"e2e-test-{int(time.time())}"
)


# ------------------------------------------------------------
# 3a. Register policy version
# ------------------------------------------------------------

print(
    "3a. Register policy version via "
    "POST /policy-versions"
)

ok(
    requests.post(
        f"{BASE}/policy-versions",
        headers=HEADERS,
        json={
            "version_id": policy_version_id,

            "name": "E2E Test Policy",

            "author": "e2e-test-script",

            "thresholds_json": {
                "P0": 80,
                "P1": 60,
                "P2": 35,
            },

            "weights_json": {
                "exploitation": 0.4,
                "exposure": 0.3,
            },

            "sla_json": {
                "P0": 24,
                "P1": 72,
            },

            # Database requires exactly 64 characters.
            "artifact_digest": "a" * 64,
        },
        timeout=30,
    ),
    "create policy version",
)

print(
    f"  policy_version_id = "
    f"{policy_version_id}"
)


# ------------------------------------------------------------
# 3b. Log policy audit event
# ------------------------------------------------------------

print(
    "3b. Log audit event: "
    "policy_version.published"
)

ok(
    requests.post(
        f"{BASE}/audit-events",
        headers=HEADERS,
        json={
            "actor_type": "system",
            "tenant_id": TENANT_ID,
            "actor_id": "policy-engine",
            "action": "policy_version.published",
            "entity_type": "policy_version",
            "entity_id": policy_version_id,
            "correlation_id": finding_id,
            "policy_version": policy_version_id,
        },
        timeout=30,
    ),
    "audit: policy_version.published",
)


# ------------------------------------------------------------
# 3c. Create priority decision
# ------------------------------------------------------------

print(
    "3c. Record priority decision via "
    "POST /decisions"
)

decision_resp = ok(
    requests.post(
        f"{BASE}/decisions",
        headers=HEADERS,
        json={
            "tenant_id": TENANT_ID,

            "finding_id": finding_id,

            "evidence_snapshot_id":
                evidence_snapshot_id,

            "policy_version":
                policy_version_id,

            "mandatory_remediation": True,

            "vps": 85.0,

            "operational_priority": "P0",

            "ssvc_outcome": "ACT",

            "confidence": "HIGH",

            "decision_status": "FINAL",

            "rules_applied": [
                "SSVC.EXPLOITATION.ACTIVE",
                "VPS.THRESHOLD.P0",
            ],

            "evidence_refs": [
                evidence_snapshot_id
            ],
        },
        timeout=30,
    ),
    "create priority decision",
)

decision_id = (
    decision_resp["priority_decision_id"]
)

print(
    f"  priority_decision_id = "
    f"{decision_id}"
)


# ============================================================
# IMPORTANT:
# The current /decisions endpoint already creates the
# priority_decision.completed audit event.
#
# Therefore we DO NOT manually POST another
# priority_decision.completed event here.
# ============================================================

print(
    "3d. priority_decision.completed audit "
    "event is created by POST /decisions"
)


# ============================================================
# VERIFICATION
# ============================================================

print("\n" + "=" * 60)
print("VERIFICATION - pulling everything back out")
print("=" * 60)


# ------------------------------------------------------------
# A. Finding history
# ------------------------------------------------------------

print(
    f"\nA) GET /findings/"
    f"{finding_id}/history"
)

history = ok(
    requests.get(
        f"{BASE}/findings/"
        f"{finding_id}/history",
        headers=HEADERS,
        timeout=30,
    ),
    "get finding history",
)


print(
    f"   finding present:     "
    f"{history['finding'] is not None}"
)

print(
    f"   evidence rows:       "
    f"{len(history['evidence'])}"
)

print(
    f"   decisions:           "
    f"{len(history['decisions'])}"
)

print(
    f"   human_decisions:     "
    f"{len(history['human_decisions'])}"
)

print(
    f"   exceptions:          "
    f"{len(history['exceptions'])}"
)

print(
    f"   tickets:             "
    f"{len(history['tickets'])}"
)

print(
    f"   audit_trail entries: "
    f"{len(history['audit_trail'])}"
)


# ------------------------------------------------------------
# B. Raw audit trail
# ------------------------------------------------------------

print(
    f"\nB) GET /audit-events/"
    f"{finding_id}"
)

trail = ok(
    requests.get(
        f"{BASE}/audit-events/"
        f"{finding_id}",
        headers=HEADERS,
        timeout=30,
    ),
    "get audit trail",
)


print(
    f"   event_count = "
    f"{trail['event_count']}"
)


for event in trail["events"]:

    print(
        f"   {event['occurred_at']}  "
        f"{event['action']:35s} "
        f"entity={event['entity_type']}"
    )


# ============================================================
# VERIFY EXPECTED EVENTS
# ============================================================

print("\n" + "=" * 60)
print("FINAL VERIFICATION")
print("=" * 60)


expected_actions = {
    "finding_instance.created",
    "enrichment_run.started",
    "finding_evidence.recorded",
    "policy_version.published",
    "priority_decision.completed",
}


actual_actions = {
    event["action"]
    for event in trail["events"]
}


missing_actions = (
    expected_actions - actual_actions
)


unexpected_actions = (
    actual_actions - expected_actions
)


print(
    f"   expected events: "
    f"{len(expected_actions)}"
)

print(
    f"   actual events:   "
    f"{trail['event_count']}"
)


if not missing_actions and not unexpected_actions:

    print()
    print(
        "PASS - complete VPAP pipeline "
        "and audit trail verified."
    )

    print()
    print(
        "All expected audit events are present:"
    )

    for action in sorted(expected_actions):
        print(
            f"   PASS - {action}"
        )

else:

    print()

    if missing_actions:

        print(
            "MISSING audit events:"
        )

        for action in sorted(missing_actions):
            print(
                f"   - {action}"
            )

    if unexpected_actions:

        print(
            "UNEXPECTED audit events:"
        )

        for action in sorted(unexpected_actions):
            print(
                f"   - {action}"
            )

    raise SystemExit(
        "FAIL - audit trail does not match "
        "the expected VPAP pipeline."
    )


print("=" * 60)
