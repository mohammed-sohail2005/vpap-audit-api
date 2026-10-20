"""
tests/test_asset_context.py
----------------------------
Comprehensive tests for Asset Context Source (ACS) backend persistence and API endpoints:
  - asset_context.create (POST /asset-contexts)
  - asset_context.get (GET /asset-contexts/{asset_id})
  - ingestion_batch.create with ACS + FILE
  - dead_letter.create with ACS + INGESTION + asset_context

Run with:
    py -m pytest tests/test_asset_context.py -v
"""

import os
import hashlib
import uuid
import pytest
from fastapi.testclient import TestClient

from audit_api import app
from auth import issue_token

client = TestClient(app)

TENANT_A = "vpap-tenant-alpha"
TENANT_B = "vpap-tenant-beta"

TOKEN_A = issue_token(tenant_id=TENANT_A, scope="persistence:*", subject="acs-adapter")["access_token"]
TOKEN_B = issue_token(tenant_id=TENANT_B, scope="persistence:*", subject="acs-adapter")["access_token"]

HEADERS_A = {"Authorization": f"Bearer {TOKEN_A}"}
HEADERS_B = {"Authorization": f"Bearer {TOKEN_B}"}


def calc_idempotency_key(source_system: str, asset_id: str) -> str:
    material = f"{source_system}|{asset_id}"
    return hashlib.sha256(material.encode()).hexdigest()


# ============================================================
# 1. ASSET_CONTEXT.CREATE TESTS (POST /asset-contexts)
# ============================================================

def test_asset_context_create_success():
    asset_id = f"asset-srv-prod-{uuid.uuid4().hex[:8]}"
    idempotency_key = calc_idempotency_key("ACS", asset_id)

    payload = {
        "tenant_id": TENANT_A,
        "idempotency_key": idempotency_key,
        "source_system": "ACS",
        "asset_id": asset_id,
        "hostname": "srv-prod-01.internal",
        "ip_address": "10.0.4.15",
        "asset_type": "VIRTUAL_MACHINE",
        "platform_os": "Ubuntu 22.04 LTS",
        "environment": "PRODUCTION",
        "business_unit": "Payment Engineering",
        "business_criticality": "HIGH",
        "owner_team": "SecOps Core",
        "internet_exposed": True,
        "location_zone": "aws-us-east-1a",
        "software_inventory": [
            {"name": "openssl", "version": "3.0.2", "type": "library"},
            {"name": "nginx", "version": "1.24.0", "type": "application"}
        ],
        "lifecycle_state": "ACTIVE",
        "data_classification": "PCI-DSS",
        "status": "HEALTHY",
    }

    # 1a. First Creation -> returns CREATED
    resp = client.post("/asset-contexts", json=payload, headers=HEADERS_A)
    assert resp.status_code == 200, f"Failed: {resp.text}"
    data = resp.json()

    assert data["status"] == "CREATED"
    assert data["asset_id"] == asset_id
    assert "id" in data and len(data["id"]) > 0

    asset_uuid = data["id"]

    # 1b. Repeated Upsert with SAME (tenant_id, idempotency_key) -> returns UPDATED
    payload["hostname"] = "srv-prod-01-updated.internal"
    payload["software_inventory"].append({"name": "docker", "version": "24.0.5", "type": "runtime"})

    resp_update = client.post("/asset-contexts", json=payload, headers=HEADERS_A)
    assert resp_update.status_code == 200, f"Failed: {resp_update.text}"
    data_update = resp_update.json()

    assert data_update["status"] == "UPDATED"
    assert data_update["id"] == asset_uuid
    assert data_update["asset_id"] == asset_id


def test_asset_context_create_auth_and_tenant_validation():
    asset_id = f"asset-srv-{uuid.uuid4().hex[:6]}"
    idempotency_key = calc_idempotency_key("ACS", asset_id)

    payload = {
        "tenant_id": TENANT_A,
        "idempotency_key": idempotency_key,
        "source_system": "ACS",
        "asset_id": asset_id,
        "business_criticality": "MEDIUM",
    }

    # Missing Authorization Token -> 401
    resp_unauth = client.post("/asset-contexts", json=payload)
    assert resp_unauth.status_code == 401

    # Tenant mismatch (Token A attempting to post for Tenant B) -> 403
    payload_mismatch = dict(payload)
    payload_mismatch["tenant_id"] = TENANT_B

    resp_mismatch = client.post("/asset-contexts", json=payload_mismatch, headers=HEADERS_A)
    assert resp_mismatch.status_code == 403


# ============================================================
# 2. ASSET_CONTEXT.GET TESTS (GET /asset-contexts/{asset_id})
# ============================================================

def test_asset_context_get_success_and_tenant_isolation():
    asset_id = f"asset-db-{uuid.uuid4().hex[:8]}"
    idempotency_key = calc_idempotency_key("ACS", asset_id)

    payload = {
        "tenant_id": TENANT_A,
        "idempotency_key": idempotency_key,
        "source_system": "ACS",
        "asset_id": asset_id,
        "hostname": "db-primary.internal",
        "environment": "PRODUCTION",
        "business_criticality": "CRITICAL",
        "owner_team": "Database Operations",
        "software_inventory": [{"name": "postgresql", "version": "15.3"}],
    }

    create_resp = client.post("/asset-contexts", json=payload, headers=HEADERS_A)
    assert create_resp.status_code == 200

    # 2a. GET by Tenant A -> returns AssetContext
    get_resp = client.get(f"/asset-contexts/{asset_id}", headers=HEADERS_A)
    assert get_resp.status_code == 200
    asset_data = get_resp.json()

    assert asset_data["asset_id"] == asset_id
    assert asset_data["tenant_id"] == TENANT_A
    assert asset_data["hostname"] == "db-primary.internal"
    assert asset_data["business_criticality"] == "CRITICAL"
    assert len(asset_data["software_inventory"]) == 1
    assert asset_data["software_inventory"][0]["name"] == "postgresql"

    # 2b. GET by Tenant B for Tenant A's asset -> returns 404 (Prevent cross-tenant access)
    get_resp_b = client.get(f"/asset-contexts/{asset_id}", headers=HEADERS_B)
    assert get_resp_b.status_code == 404, "Tenant B must NOT access Tenant A's asset context"

    # 2c. GET for non-existent asset -> 404
    get_resp_missing = client.get("/asset-contexts/non-existent-asset-9999", headers=HEADERS_A)
    assert get_resp_missing.status_code == 404


# ============================================================
# 3. EXISTING ACTIONS VERIFICATION (INGESTION_BATCH & DEAD_LETTER)
# ============================================================

def test_ingestion_batch_create_acs_file():
    payload = {
        "tenant_id": TENANT_A,
        "source_system": "ACS",
        "source_type": "FILE",
        "source_reference": "acs-export-20261007.xlsx",
        "total_records": 100,
        "accepted_records": 98,
        "rejected_records": 2,
        "status": "COMPLETED",
    }

    resp = client.post("/ingestion-batches", json=payload, headers=HEADERS_A)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "batch_id" in data


def test_dead_letter_create_acs_record():
    payload = {
        "tenant_id": TENANT_A,
        "source_system": "ACS",
        "stage": "INGESTION",
        "record_type": "asset_context",
        "error_code": "INVALID_ASSET_ID",
        "error_message": "Missing mandatory asset_id field in ACS record",
        "raw_record": {"hostname": "unknown-host.local", "ip": "192.168.1.50"},
    }

    resp = client.post("/dead-letters", json=payload, headers=HEADERS_A)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "dead_letter_id" in data
