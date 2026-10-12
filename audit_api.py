"""
VPAP 4.1 - Full Data & Audit API, with Authentication
------------------------------------------------------

Centralized REST service for vulnerability prioritization, enrichment,
policy evaluation, and immutable audit logging.

AUTHENTICATION
--------------

Every protected endpoint requires:

    Authorization: Bearer <token>

Each token contains:

    tenant_id
    scope
    subject
    issuer
    audience
    expiry

The API verifies the token before allowing access.

Tenant isolation is enforced for tenant-owned data.

ENDPOINTS
---------

Health:
    GET  /

Ingestion Pipeline:
    POST /ingestion-batches
    POST /findings
    POST /dead-letters
    GET  /findings/{finding_id}/history
    POST /asset-contexts
    GET  /asset-contexts/{asset_id}

Enrichment Service:
    POST  /enrichment-runs
    PATCH /enrichment-runs/{enrichment_run_id}
    POST  /evidence
    POST  /kev-catalogue
    POST  /kev-catalogue-entries
    POST  /epss-snapshots
    POST  /epss-snapshot-entries
    GET   /epss-snapshot-entries/latest

Policy Engine:
    POST  /policy-versions
    POST  /decisions
    POST  /human-decisions
    GET   /human-decisions
    POST  /exceptions
    GET   /exceptions
    PATCH /exceptions/{exception_id}
    POST  /outbox-events
    GET   /outbox-events
    PATCH /outbox-events/{outbox_event_id}
    POST  /ticket-links

Audit Service:
    POST /audit-events
    GET  /audit-events
    GET  /audit-events/{correlation_id}
    GET  /live-audit-feed

Run locally:

    py -m uvicorn audit_api:app --host 0.0.0.0 --port 8000
"""

from datetime import datetime, timezone
from typing import Optional, Literal, Any

import logging

from fastapi import FastAPI, HTTPException, Depends, Query
from pydantic import BaseModel, Field, model_validator
from psycopg.errors import UniqueViolation

from auth import (
    issue_token,
    require_auth,
    require_tenant_match,
    AuthContext,
)

from audit_client import (
    AuditClient,

    # Ingestion
    IngestionBatch,
    FindingInstance,
    DeadLetter,
    AssetContext,

    # Enrichment
    EvidenceValue,
    EnrichmentRun,
    FindingEvidence as DBFindingEvidence,
    KevCatalogue,
    KevCatalogueEntry,
    EpssSnapshot,
    EpssSnapshotEntry,

    # Policy
    PolicyVersion,
    PriorityDecision,
    HumanDecision,
    ExceptionRecord,
    OutboxEvent,
    TicketLink,

    # Audit
    AuditEvent as DBAuditEvent,

    # Action validation
    ACTIONS_BY_ENTITY,
)


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO
)

logger = logging.getLogger(
    "vpap-audit-api"
)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os

app = FastAPI(
    title="VPAP Audit & Data API",
    description=(
        "Shared, authenticated endpoints for "
        "ingestion, enrichment, policy engine, "
        "and audit data."
    ),
    version="4.1.0",
)

# CORS middleware for frontend UI integration
# CORS middleware for frontend UI integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

frontend_dist = os.path.join(os.path.dirname(__file__), "frontend", "dist")
if os.path.exists(frontend_dist):
    app.mount("/ui", StaticFiles(directory=frontend_dist, html=True), name="ui")



audit_client = AuditClient()


# ============================================================
# COMMON TYPES
# ============================================================

ActorType = Literal[
    "system",
    "human",
    "llm",
]

Priority = Literal[
    "P0",
    "P1",
    "P2",
    "P3",
    "REVIEW",
]


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/")
def health_check():
    """
    Public health endpoint.

    No authentication required.
    """

    return {
        "status": "ok",
        "service": "vpap-audit-api",
        "version": "4.1.0",
    }


# ============================================================
# INGESTION & VALIDATION
# ============================================================

class IngestionBatchRequest(BaseModel):
    tenant_id: str
    source_system: str

    source_type: Literal[
        "FILE",
        "API",
        "STREAM",
    ]

    source_reference: Optional[str] = None
    source_file_name: Optional[str] = None
    processing_started_at: Optional[str] = None
    processing_completed_at: Optional[str] = None

    total_records: int = 0
    accepted_records: int = 0
    rejected_records: int = 0
    validation_failed_records: int = 0

    status: str = "RECEIVED"
    error_message: Optional[str] = None


@app.post("/ingestion-batches")
def create_ingestion_batch(
    batch: IngestionBatchRequest,
    auth: AuthContext = Depends(require_auth),
):
    """
    Create an ingestion batch.

    The tenant in the request must match the authenticated tenant.
    """

    require_tenant_match(
        auth,
        batch.tenant_id,
    )

    try:

        batch_id = audit_client.log_ingestion_batch(
            IngestionBatch(
                **batch.model_dump()
            )
        )

        logger.info(
            f"Logged ingestion batch: "
            f"id={batch_id} "
            f"tenant={auth.tenant_id} "
            f"by={auth.subject}"
        )

        return {
            "status": "ok",
            "batch_id": batch_id,
        }

    except Exception as e:

        logger.error(
            f"Failed to log ingestion batch: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to record ingestion batch.",
        )


# ============================================================
# FINDINGS
# ============================================================

class FindingRequest(BaseModel):
    tenant_id: str
    source_system: str
    source_finding_id: str
    cve_id: str
    asset_id: str

    package_id: Optional[str] = None
    cvss_base: Optional[float] = None
    cvss_vector: Optional[str] = None
    description: Optional[str] = None
    business_service_id: Optional[str] = None
    internet_exposed: Optional[bool] = None
    first_detected_at: Optional[str] = None

    status: str = "VALID"


@app.post("/findings")
def create_finding(
    finding: FindingRequest,
    auth: AuthContext = Depends(require_auth),
):
    """
    Idempotent finding upsert.
    """

    require_tenant_match(
        auth,
        finding.tenant_id,
    )

    try:

        finding_id = audit_client.upsert_finding(
            FindingInstance(
                **finding.model_dump()
            )
        )

        logger.info(
            f"Upserted finding: "
            f"id={finding_id} "
            f"cve={finding.cve_id} "
            f"tenant={auth.tenant_id} "
            f"by={auth.subject}"
        )

        return {
            "status": "ok",
            "finding_id": finding_id,
        }

    except Exception:

        logger.exception(
            f"Failed to upsert finding: "
            f"cve={finding.cve_id} "
            f"tenant={auth.tenant_id} "
            f"source_finding_id={finding.source_finding_id}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to record finding.",
        )


# ============================================================
# DEAD LETTER
# ============================================================

class DeadLetterRequest(BaseModel):
    tenant_id: str
    source_system: str

    batch_id: Optional[str] = None
    source_finding_id: Optional[str] = None
    record_type: Optional[str] = None

    stage: Literal[
        "INGESTION",
        "VALIDATION",
    ]

    error_code: str
    error_message: str

    raw_record: Optional[dict] = None

    status: str = "OPEN"
    retry_count: int = 0


@app.post("/dead-letters")
def create_dead_letter(
    entry: DeadLetterRequest,
    auth: AuthContext = Depends(require_auth),
):
    require_tenant_match(
        auth,
        entry.tenant_id,
    )

    try:

        dl_id = audit_client.log_dead_letter(
            DeadLetter(
                **entry.model_dump()
            )
        )

        logger.info(
            f"Logged dead letter: "
            f"id={dl_id} "
            f"stage={entry.stage} "
            f"tenant={auth.tenant_id} "
            f"by={auth.subject}"
        )

        return {
            "status": "ok",
            "dead_letter_id": dl_id,
        }

    except Exception as e:

        logger.error(
            f"Failed to log dead letter: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to record dead letter.",
        )


# ============================================================
# ACS - ASSET CONTEXT SOURCE ENDPOINTS
# ============================================================

class AssetContextRequest(BaseModel):
    tenant_id: str
    idempotency_key: str
    source_system: str = "ACS"
    asset_id: str

    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    asset_type: Optional[str] = None
    platform_os: Optional[str] = None
    environment: Optional[str] = None
    business_unit: Optional[str] = None
    business_criticality: Optional[str] = None
    owner_team: Optional[str] = None
    internet_exposed: Optional[bool] = None
    location_zone: Optional[str] = None

    software_inventory: list = Field(default_factory=list)

    lifecycle_state: Optional[str] = None
    data_classification: Optional[str] = None
    status: Optional[str] = None


@app.post("/asset-contexts")
def create_asset_context(
    body: AssetContextRequest,
    auth: AuthContext = Depends(require_auth),
):
    """
    Action: asset_context.create
    Idempotent creation or update of an AssetContext record based on (tenant_id, idempotency_key).
    Returns {"id": "<asset_uuid>", "status": "CREATED" | "UPDATED", "asset_id": "<asset_id>"}.
    """
    require_tenant_match(
        auth,
        body.tenant_id,
    )

    try:
        result = audit_client.upsert_asset_context(
            AssetContext(
                **body.model_dump()
            )
        )

        logger.info(
            f"Upserted asset context: "
            f"id={result['id']} "
            f"status={result['status']} "
            f"asset_id={body.asset_id} "
            f"tenant={auth.tenant_id} "
            f"by={auth.subject}"
        )

        return result

    except Exception as e:
        logger.error(f"Failed to upsert asset context: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to record asset context.",
        )


@app.get("/asset-contexts/{asset_id}")
def get_asset_context(
    asset_id: str,
    auth: AuthContext = Depends(require_auth),
):
    """
    Action: asset_context.get
    Retrieve the AssetContext associated with the given asset_id.
    Strictly scoped to the authenticated tenant.
    """
    try:
        res = audit_client.get_asset_context(
            tenant_id=auth.tenant_id,
            asset_id=asset_id,
        )

        if not res:
            raise HTTPException(
                status_code=404,
                detail="AssetContext not found.",
            )

        return res

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch asset context: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to fetch asset context.",
        )



# ============================================================
# FINDING HISTORY
# ============================================================

@app.get("/findings/{finding_id}/history")
def get_finding_history(
    finding_id: str,
    auth: AuthContext = Depends(require_auth),
):
    """
    Read-only finding history.

    Tenant isolation is enforced by audit_client.
    """

    try:

        history = audit_client.get_finding_history(
            finding_id=finding_id,
            tenant_id=auth.tenant_id,
        )

        if history.get("finding") is None:

            raise HTTPException(
                status_code=404,
                detail="Finding not found.",
            )

        return history

    except HTTPException:
        raise

    except Exception as e:

        logger.error(
            f"Failed to fetch finding history: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to fetch finding history.",
        )


# ============================================================
# ENRICHMENT PIPELINE
# ============================================================

class EvidenceValueRequest(BaseModel):
    value: Optional[Any] = None
    raw_value: Optional[Any] = None
    mapping_version: Optional[str] = None

    status: Literal[
        "KNOWN",
        "UNKNOWN",
        "STALE",
        "ERROR",
    ]

    reason_code: Optional[str] = None
    source: str
    source_field: Optional[str] = None
    source_timestamp: Optional[str] = None
    retrieved_at: str

    confidence: Literal[
        "HIGH",
        "MEDIUM",
        "LOW",
    ]


# ============================================================
# ENRICHMENT RUN
# ============================================================

class EnrichmentRunRequest(BaseModel):
    tenant_id: str
    source_system: str

    source_instance_id: Optional[str] = None

    adapter_name: str
    adapter_version: str
    schema_version: str

    started_at: Optional[str] = None
    completed_at: Optional[str] = None

    status: str


@app.post("/enrichment-runs")
def create_enrichment_run(
    run: EnrichmentRunRequest,
    auth: AuthContext = Depends(require_auth),
):
    require_tenant_match(
        auth,
        run.tenant_id,
    )

    try:

        run_id = audit_client.log_enrichment_run(
            EnrichmentRun(
                **run.model_dump()
            )
        )

        logger.info(
            f"Logged enrichment run: "
            f"id={run_id} "
            f"tenant={auth.tenant_id} "
            f"by={auth.subject}"
        )

        return {
            "status": "ok",
            "enrichment_run_id": run_id,
        }

    except Exception as e:

        logger.error(
            f"Failed to log enrichment run: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to record enrichment run.",
        )


# ============================================================
# PATCH ENRICHMENT RUN
# ============================================================

class EnrichmentRunUpdateRequest(BaseModel):
    tenant_id: str
    status: str
    completed_at: Optional[str] = None


@app.patch("/enrichment-runs/{enrichment_run_id}")
def update_enrichment_run(
    enrichment_run_id: str,
    update: EnrichmentRunUpdateRequest,
    auth: AuthContext = Depends(require_auth),
):
    """
    Update an existing enrichment run.

    Tenant isolation is enforced using the authenticated
    tenant ID.
    """

    require_tenant_match(
        auth,
        update.tenant_id,
    )

    try:

        updated_id = audit_client.update_enrichment_run(
            enrichment_run_id=enrichment_run_id,
            tenant_id=auth.tenant_id,
            status=update.status,
            completed_at=update.completed_at,
        )

        if updated_id is None:

            raise HTTPException(
                status_code=404,
                detail="Enrichment run not found.",
            )

        logger.info(
            f"Updated enrichment run: "
            f"id={updated_id} "
            f"status={update.status} "
            f"tenant={auth.tenant_id} "
            f"by={auth.subject}"
        )

        return {
            "status": "ok",
            "enrichment_run_id": updated_id,
            "run_status": update.status,
        }

    except HTTPException:
        raise

    except Exception as e:

        logger.error(
            f"Failed to update enrichment run "
            f"{enrichment_run_id}: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to update enrichment run.",
        )


# ============================================================
# FINDING EVIDENCE
# ============================================================

class FindingEvidenceRequest(BaseModel):
    finding_instance_id: str
    source_finding_id: str

    tenant_id: str
    source_system: str

    source_instance_id: Optional[str] = None

    enrichment_run_id: str
    schema_version: str
    adapter_name: str
    adapter_version: str

    cve_id: str
    asset_id: str

    cvss_base: Optional[float] = None

    epss_probability: EvidenceValueRequest
    epss_percentile: EvidenceValueRequest
    kev_status: EvidenceValueRequest
    internet_exposure: EvidenceValueRequest
    runtime_applicability: EvidenceValueRequest
    attack_path_reachable: EvidenceValueRequest
    business_criticality: EvidenceValueRequest
    compensating_controls: EvidenceValueRequest


@app.post("/evidence")
def create_finding_evidence(
    evidence: FindingEvidenceRequest,
    auth: AuthContext = Depends(require_auth),
):
    require_tenant_match(
        auth,
        evidence.tenant_id,
    )

    try:

        db_evidence = DBFindingEvidence(
            **evidence.model_dump(
                exclude={
                    "epss_probability",
                    "epss_percentile",
                    "kev_status",
                    "internet_exposure",
                    "runtime_applicability",
                    "attack_path_reachable",
                    "business_criticality",
                    "compensating_controls",
                }
            ),

            epss_probability=EvidenceValue(
                **evidence.epss_probability.model_dump()
            ),

            epss_percentile=EvidenceValue(
                **evidence.epss_percentile.model_dump()
            ),

            kev_status=EvidenceValue(
                **evidence.kev_status.model_dump()
            ),

            internet_exposure=EvidenceValue(
                **evidence.internet_exposure.model_dump()
            ),

            runtime_applicability=EvidenceValue(
                **evidence.runtime_applicability.model_dump()
            ),

            attack_path_reachable=EvidenceValue(
                **evidence.attack_path_reachable.model_dump()
            ),

            business_criticality=EvidenceValue(
                **evidence.business_criticality.model_dump()
            ),

            compensating_controls=EvidenceValue(
                **evidence.compensating_controls.model_dump()
            ),
        )

        evidence_id = audit_client.log_finding_evidence(
            db_evidence
        )

        logger.info(
            f"Logged finding evidence: "
            f"id={evidence_id} "
            f"tenant={auth.tenant_id} "
            f"by={auth.subject}"
        )

        return {
            "status": "ok",
            "evidence_snapshot_id": evidence_id,
        }

    except Exception as e:

        logger.error(
            f"Failed to log finding evidence: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to record finding evidence.",
        )


# ============================================================
# KEV CATALOGUE
# ============================================================

class KevCatalogueRequest(BaseModel):
    source_timestamp: Optional[str] = None
    catalogue_sha256: str
    record_count: int
    status: str


@app.post("/kev-catalogue")
def create_kev_catalogue(
    catalogue: KevCatalogueRequest,
    auth: AuthContext = Depends(require_auth),
):
    """
    KEV catalogue is a shared global feed.
    """

    try:

        catalogue_id = audit_client.log_kev_catalogue(
            KevCatalogue(
                **catalogue.model_dump()
            )
        )

        logger.info(
            f"Logged KEV catalogue: "
            f"id={catalogue_id} "
            f"by={auth.subject}"
        )

        return {
            "status": "ok",
            "catalogue_id": catalogue_id,
        }

    except Exception as e:

        logger.error(
            f"Failed to log KEV catalogue: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to record KEV catalogue.",
        )


# ============================================================
# KEV CATALOGUE ENTRIES
# ============================================================

class KevCatalogueEntryRequest(BaseModel):
    catalogue_id: str
    cve_id: str


class KevCatalogueEntriesRequest(BaseModel):
    entries: list[KevCatalogueEntryRequest]


@app.post("/kev-catalogue-entries")
def create_kev_catalogue_entries(
    request: KevCatalogueEntriesRequest,
    auth: AuthContext = Depends(require_auth),
):
    try:

        db_entries = [
            KevCatalogueEntry(
                **entry.model_dump()
            )
            for entry in request.entries
        ]

        count = audit_client.log_kev_catalogue_entries(
            db_entries
        )

        logger.info(
            f"Logged {count} KEV catalogue entries "
            f"by={auth.subject}"
        )

        return {
            "status": "ok",
            "entries_inserted": count,
        }

    except Exception as e:

        logger.error(
            f"Failed to log KEV catalogue entries: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to record KEV catalogue entries.",
        )


# ============================================================
# EPSS SNAPSHOT
# ============================================================

class EpssSnapshotRequest(BaseModel):
    source_timestamp: Optional[str] = None
    record_count: int


@app.post("/epss-snapshots")
def create_epss_snapshot(
    snapshot: EpssSnapshotRequest,
    auth: AuthContext = Depends(require_auth),
):
    """
    EPSS is a shared global feed.
    """

    try:

        snapshot_id = audit_client.log_epss_snapshot(
            EpssSnapshot(
                **snapshot.model_dump()
            )
        )

        logger.info(
            f"Logged EPSS snapshot: "
            f"id={snapshot_id} "
            f"by={auth.subject}"
        )

        return {
            "status": "ok",
            "snapshot_id": snapshot_id,
        }

    except Exception as e:

        logger.error(
            f"Failed to log EPSS snapshot: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to record EPSS snapshot.",
        )


# ============================================================
# EPSS SNAPSHOT ENTRIES
# ============================================================

class EpssSnapshotEntryRequest(BaseModel):
    snapshot_id: str
    cve_id: str
    epss_probability: float
    epss_percentile: float


class EpssSnapshotEntriesRequest(BaseModel):
    entries: list[EpssSnapshotEntryRequest]


@app.post("/epss-snapshot-entries")
def create_epss_snapshot_entries(
    request: EpssSnapshotEntriesRequest,
    auth: AuthContext = Depends(require_auth),
):
    try:

        entries = [
            EpssSnapshotEntry(
                **entry.model_dump()
            )
            for entry in request.entries
        ]

        count = audit_client.log_epss_snapshot_entries(
            entries
        )

        logger.info(
            f"Logged {count} EPSS snapshot entries "
            f"by={auth.subject}"
        )

        return {
            "status": "ok",
            "entries_inserted": count,
        }

    except Exception as e:

        logger.error(
            f"Failed to log EPSS snapshot entries: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to record EPSS snapshot entries.",
        )


# ============================================================
# LATEST EPSS VALUES
# ============================================================

@app.get("/epss-snapshot-entries/latest")
def get_latest_epss_values(
    cve_ids: str,
    auth: AuthContext = Depends(require_auth),
):
    """
    Example:

        ?cve_ids=CVE-2026-1,CVE-2026-2
    """

    try:

        cve_list = [
            c.strip()
            for c in cve_ids.split(",")
            if c.strip()
        ]

        rows = audit_client.get_latest_epss_values(
            cve_list
        )

        return {
            "requested": cve_list,
            "found": len(rows),
            "values": rows,
        }

    except Exception as e:

        logger.error(
            f"Failed to fetch latest EPSS values: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to fetch latest EPSS values.",
        )


# ============================================================
# POLICY ENGINE
# ============================================================

# ============================================================
# POLICY VERSION
# ============================================================

class PolicyVersionRequest(BaseModel):
    version_id: str

    name: str

    description: Optional[str] = None

    author: str

    thresholds_json: dict
    weights_json: dict
    sla_json: dict

    conservative_floor_default: Priority = "P0"

    artifact_digest: str

    is_active: bool = True


@app.post("/policy-versions")
def create_policy_version(
    policy: PolicyVersionRequest,
    auth: AuthContext = Depends(require_auth),
):
    """
    Create a policy version.

    Duplicate version_id returns HTTP 409.
    """

    try:

        version_id = audit_client.log_policy_version(
            PolicyVersion(
                **policy.model_dump()
            )
        )

        logger.info(
            f"Logged policy version: "
            f"id={version_id} "
            f"by={auth.subject}"
        )

        return {
            "status": "ok",
            "version_id": version_id,
        }

    except UniqueViolation:

        logger.warning(
            f"Duplicate policy version: "
            f"{policy.version_id}"
        )

        raise HTTPException(
            status_code=409,
            detail="Policy version already exists.",
        )

    except Exception as e:

        logger.error(
            f"Failed to log policy version: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to record policy version.",
        )


# ============================================================
# PRIORITY DECISIONS
# ============================================================

class DecisionRequest(BaseModel):
    tenant_id: str

    finding_id: str

    evidence_snapshot_id: str

    policy_version: str

    mandatory_remediation: bool

    vps: Optional[float] = None

    operational_priority: Priority

    ssvc_outcome: Optional[
        Literal[
            "TRACK",
            "TRACK*",
            "ATTEND",
            "ACT",
        ]
    ] = None

    confidence: Literal[
        "HIGH",
        "MEDIUM",
        "LOW",
    ]

    decision_status: Literal[
        "FINAL",
        "PROVISIONAL",
        "NEEDS_REVIEW",
        "QUARANTINED",
    ]

    conservative_floor: Optional[
        Priority
    ] = None

    sla_hours: Optional[float] = None

    sla_due_at: Optional[str] = None

    rules_applied: list = Field(
        default_factory=list
    )

    evidence_refs: list = Field(
        default_factory=list
    )


@app.post("/decisions")
def create_decision(
    decision: DecisionRequest,
    auth: AuthContext = Depends(require_auth),
):
    """
    Create a priority decision and its audit event.

    Flow:

        Policy Engine
              |
              v
        priority_decision
              |
              v
        priority_decision.completed
              |
              v
        finding audit history

    The audit event is linked to the finding using
    correlation_id=decision.finding_id.
    """

    require_tenant_match(
        auth,
        decision.tenant_id,
    )

    try:

        # --------------------------------------------------------
        # 1. Create the priority decision
        # --------------------------------------------------------

        decision_id = audit_client.log_decision(
            PriorityDecision(
                **decision.model_dump()
            )
        )

        # --------------------------------------------------------
        # 2. Create audit event for the decision
        # --------------------------------------------------------

        audit_event = DBAuditEvent(
            actor_type="system",
            actor_id=auth.subject,

            action="priority_decision.completed",

            entity_type="priority_decision",
            entity_id=decision_id,

            # The finding ID is used as the correlation ID so
            # this event can appear in finding history.
            correlation_id=decision.finding_id,

            tenant_id=auth.tenant_id,

            policy_version=decision.policy_version,

            evidence_ref=decision.evidence_snapshot_id,

            before_state=None,

            after_state={
                "priority_decision_id": decision_id,
                "finding_id": decision.finding_id,
                "evidence_snapshot_id": (
                    decision.evidence_snapshot_id
                ),
                "policy_version": (
                    decision.policy_version
                ),
                "mandatory_remediation": (
                    decision.mandatory_remediation
                ),
                "vps": decision.vps,
                "operational_priority": (
                    decision.operational_priority
                ),
                "ssvc_outcome": decision.ssvc_outcome,
                "confidence": decision.confidence,
                "decision_status": decision.decision_status,
                "conservative_floor": (
                    decision.conservative_floor
                ),
                "sla_hours": decision.sla_hours,
                "sla_due_at": decision.sla_due_at,
                "rules_applied": decision.rules_applied,
                "evidence_refs": decision.evidence_refs,
            },
        )

        audit_client.log(
            audit_event
        )

        # --------------------------------------------------------
        # 3. Log successful operation
        # --------------------------------------------------------

        logger.info(
            f"Logged decision and audit event: "
            f"id={decision_id} "
            f"priority={decision.operational_priority} "
            f"finding={decision.finding_id} "
            f"tenant={auth.tenant_id} "
            f"by={auth.subject}"
        )

        return {
            "status": "ok",
            "priority_decision_id": decision_id,
        }

    except Exception as e:

        logger.error(
            f"Failed to log decision: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to record decision.",
        )


# ============================================================
# HUMAN DECISIONS
# ============================================================

class HumanDecisionRequest(BaseModel):
    tenant_id: str

    finding_instance_id: str

    request_id: str

    decision_type: str

    original_priority: Priority

    proposed_priority: Priority

    actor_id: str

    actor_username: str

    actor_role: Literal[
        "ANALYST",
        "VULN_LEAD",
        "RISK_OWNER",
        "CISO_DELEGATE",
        "AUDITOR",
    ]

    rationale: str

    signatures_json: list


@app.post("/human-decisions")
def create_human_decision(
    decision: HumanDecisionRequest,
    auth: AuthContext = Depends(require_auth),
):
    require_tenant_match(
        auth,
        decision.tenant_id,
    )

    try:

        decision_id = audit_client.log_human_decision(
            HumanDecision(
                **decision.model_dump()
            )
        )

        logger.info(
            f"Logged human decision: "
            f"id={decision_id} "
            f"tenant={auth.tenant_id} "
            f"by={auth.subject}"
        )

        return {
            "status": "ok",
            "human_decision_id": decision_id,
        }

    except Exception as e:

        logger.error(
            f"Failed to log human decision: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to record human decision.",
        )


# ============================================================
# GET HUMAN DECISIONS
# ============================================================

@app.get("/human-decisions")
def get_human_decisions(
    finding_id: str,
    auth: AuthContext = Depends(require_auth),
):
    """
    Retrieve human review decisions for a finding.
    """

    try:

        rows = audit_client.get_human_decisions(
            finding_id=finding_id,
            tenant_id=auth.tenant_id,
        )

        return {
            "finding_id": finding_id,
            "count": len(rows),
            "human_decisions": rows,
        }

    except Exception as e:

        logger.error(
            f"Failed to fetch human decisions: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to fetch human decisions.",
        )


# ============================================================
# EXCEPTIONS
# ============================================================

class ExceptionRequest(BaseModel):
    tenant_id: str

    finding_id: str

    requester: str

    approver: Optional[str] = None

    status: Literal[
        "PENDING",
        "APPROVED",
        "REJECTED",
        "EXPIRED",
    ] = "PENDING"

    justification: str

    risk_level: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ]

    valid_until: str


@app.post("/exceptions")
def create_exception(
    exception: ExceptionRequest,
    auth: AuthContext = Depends(require_auth),
):
    require_tenant_match(
        auth,
        exception.tenant_id,
    )

    try:

        exception_id = audit_client.log_exception(
            ExceptionRecord(
                **exception.model_dump()
            )
        )

        logger.info(
            f"Logged exception: "
            f"id={exception_id} "
            f"tenant={auth.tenant_id} "
            f"by={auth.subject}"
        )

        return {
            "status": "ok",
            "exception_id": exception_id,
        }

    except Exception as e:

        logger.error(
            f"Failed to log exception: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to record exception.",
        )


# ============================================================
# EXCEPTION UPDATE
# ============================================================

class ExceptionUpdateRequest(BaseModel):
    status: Literal[
        "PENDING",
        "APPROVED",
        "REJECTED",
        "EXPIRED",
    ]

    approver: Optional[str] = None

    approved_at: Optional[str] = None


# ============================================================
# GET EXCEPTIONS
# ============================================================

@app.get("/exceptions")
def get_exceptions(
    status: Optional[str] = None,
    auth: AuthContext = Depends(require_auth),
):
    """
    Get exceptions belonging only to the authenticated tenant.
    """

    try:

        rows = audit_client.get_exceptions(
            tenant_id=auth.tenant_id,
            status=status,
        )

        return {
            "tenant_id": auth.tenant_id,
            "count": len(rows),
            "exceptions": rows,
        }

    except Exception as e:

        logger.error(
            f"Failed to fetch exceptions: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to fetch exceptions.",
        )


# ============================================================
# PATCH EXCEPTION
# ============================================================

@app.patch("/exceptions/{exception_id}")
def update_exception(
    exception_id: str,
    update: ExceptionUpdateRequest,
    auth: AuthContext = Depends(require_auth),
):
    """
    Approve/reject/expire an exception.
    """

    try:

        updated = audit_client.update_exception(
            exception_id=exception_id,
            tenant_id=auth.tenant_id,
            status=update.status,
            approver=update.approver,
            approved_at=update.approved_at,
        )

        if updated is None:

            raise HTTPException(
                status_code=404,
                detail="Exception not found.",
            )

        logger.info(
            f"Updated exception: "
            f"id={exception_id} "
            f"status={update.status} "
            f"tenant={auth.tenant_id} "
            f"by={auth.subject}"
        )

        return {
            "status": "ok",
            "exception": updated,
        }

    except HTTPException:
        raise

    except Exception as e:

        logger.error(
            f"Failed to update exception: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to update exception.",
        )


# ============================================================
# OUTBOX EVENTS
# ============================================================

class OutboxEventRequest(BaseModel):
    tenant_id: str

    event_type: str

    aggregate_id: str

    idempotency_key: str

    payload: dict

    status: str = "PENDING"

    retry_count: int = 0

    external_id: Optional[str] = None

    error_message: Optional[str] = None


@app.post("/outbox-events")
def create_outbox_event(
    event: OutboxEventRequest,
    auth: AuthContext = Depends(require_auth),
):
    """
    Create an outbox event.

    Duplicate idempotency_key returns HTTP 409.
    """

    require_tenant_match(
        auth,
        event.tenant_id,
    )

    try:

        event_id = audit_client.log_outbox_event(
            OutboxEvent(
                **event.model_dump()
            )
        )

        logger.info(
            f"Logged outbox event: "
            f"id={event_id} "
            f"tenant={auth.tenant_id} "
            f"by={auth.subject}"
        )

        return {
            "status": "ok",
            "outbox_event_id": event_id,
        }

    except UniqueViolation:

        logger.warning(
            "Duplicate outbox idempotency key: "
            f"{event.idempotency_key}"
        )

        raise HTTPException(
            status_code=409,
            detail=(
                "Outbox event with this "
                "idempotency_key already exists."
            ),
        )

    except Exception as e:

        logger.error(
            f"Failed to log outbox event: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to record outbox event.",
        )


# ============================================================
# GET OUTBOX EVENTS
# ============================================================

@app.get("/outbox-events")
def get_outbox_events(
    status: Optional[str] = None,
    auth: AuthContext = Depends(require_auth),
):
    """
    Get outbox events belonging only to the authenticated tenant.
    """

    try:

        rows = audit_client.get_outbox_events(
            tenant_id=auth.tenant_id,
            status=status,
        )

        return {
            "tenant_id": auth.tenant_id,
            "count": len(rows),
            "outbox_events": rows,
        }

    except Exception as e:

        logger.error(
            f"Failed to fetch outbox events: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to fetch outbox events.",
        )


# ============================================================
# OUTBOX UPDATE
# ============================================================

class OutboxEventUpdateRequest(BaseModel):
    status: Literal[
        "PENDING",
        "DELIVERED",
        "FAILED",
        "DEAD_LETTER",
    ]

    external_id: Optional[str] = None

    retry_count: Optional[int] = None

    error_message: Optional[str] = None


@app.patch("/outbox-events/{outbox_event_id}")
def update_outbox_event(
    outbox_event_id: str,
    update: OutboxEventUpdateRequest,
    auth: AuthContext = Depends(require_auth),
):
    try:

        updated = audit_client.update_outbox_event(
            outbox_event_id=outbox_event_id,
            tenant_id=auth.tenant_id,
            status=update.status,
            external_id=update.external_id,
            retry_count=update.retry_count,
            error_message=update.error_message,
        )

        if updated is None:

            raise HTTPException(
                status_code=404,
                detail="Outbox event not found.",
            )

        logger.info(
            f"Updated outbox event: "
            f"id={outbox_event_id} "
            f"status={update.status} "
            f"tenant={auth.tenant_id} "
            f"by={auth.subject}"
        )

        return {
            "status": "ok",
            "outbox_event": updated,
        }

    except HTTPException:
        raise

    except Exception as e:

        logger.error(
            f"Failed to update outbox event: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to update outbox event.",
        )


# ============================================================
# TICKET LINKS
# ============================================================

class TicketLinkRequest(BaseModel):
    tenant_id: str

    finding_instance_id: str

    system: Literal[
        "JIRA",
        "SERVICENOW",
        "HYBRID",
    ]

    ticket_key: str

    ticket_url: Optional[str] = None

    status: str = "OPEN"

    priority: Optional[str] = None

    sla_due_at: Optional[str] = None

    last_synced_at: Optional[str] = None


@app.post("/ticket-links")
def create_ticket_link(
    ticket: TicketLinkRequest,
    auth: AuthContext = Depends(require_auth),
):
    require_tenant_match(
        auth,
        ticket.tenant_id,
    )

    try:

        ticket_id = audit_client.log_ticket_link(
            TicketLink(
                **ticket.model_dump()
            )
        )

        logger.info(
            f"Logged ticket link: "
            f"id={ticket_id} "
            f"tenant={auth.tenant_id} "
            f"by={auth.subject}"
        )

        return {
            "status": "ok",
            "ticket_link_id": ticket_id,
        }

    except Exception as e:

        logger.error(
            f"Failed to log ticket link: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to record ticket link.",
        )


# ============================================================
# AUDIT TRAIL SERVICE
# ============================================================

class AuditEventRequest(BaseModel):
    actor_type: ActorType

    actor_id: str

    action: str

    entity_type: str

    entity_id: str

    correlation_id: str

    tenant_id: str

    policy_version: Optional[str] = None

    evidence_ref: Optional[str] = None

    before_state: Optional[dict] = None

    after_state: Optional[dict] = None

    @model_validator(mode="after")
    def validate_action_for_entity_type(
        self,
    ) -> "AuditEventRequest":
        """
        Validate action/entity_type combinations before
        the database operation.

        ACTIONS_BY_ENTITY is the single source of truth.
        """

        allowed_actions = ACTIONS_BY_ENTITY.get(
            self.entity_type
        )

        if (
            allowed_actions is not None
            and self.action not in allowed_actions
        ):

            raise ValueError(
                f"Invalid action "
                f"'{self.action}' "
                f"for entity_type "
                f"'{self.entity_type}'. "
                f"Allowed actions: "
                f"{sorted(allowed_actions)}"
            )

        return self


# ============================================================
# CREATE AUDIT EVENT
# ============================================================

@app.post("/audit-events")
def create_audit_event(
    event: AuditEventRequest,
    auth: AuthContext = Depends(require_auth),
):
    """
    Create an immutable audit event.

    Tenant from JWT must match tenant in request.
    """

    require_tenant_match(
        auth,
        event.tenant_id,
    )

    try:

        db_event = DBAuditEvent(
            **event.model_dump()
        )

        audit_client.log(
            db_event
        )

        logger.info(
            f"Logged audit event: "
            f"actor={event.actor_id} "
            f"action={event.action} "
            f"entity={event.entity_type} "
            f"tenant={auth.tenant_id} "
            f"by={auth.subject}"
        )

        return {
            "status": "ok",
            "message": "Audit event recorded",
        }

    except Exception as e:

        logger.error(
            f"Failed to write audit event: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to record audit event.",
        )


# ============================================================
# GET AUDIT TRAIL
# ============================================================

@app.get("/audit-events/{correlation_id}")
def get_audit_trail(
    correlation_id: str,
    auth: AuthContext = Depends(require_auth),
):
    """
    Read-only audit trail.

    Tenant isolation is enforced by audit_client.
    """

    try:

        rows = audit_client.get_trail(
            correlation_id=correlation_id,
            tenant_id=auth.tenant_id,
        )

        return {
            "correlation_id": correlation_id,
            "event_count": len(rows),
            "events": rows,
        }

    except Exception as e:

        logger.error(
            f"Failed to fetch audit trail: {e}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to fetch audit trail.",
        )


@app.get("/audit-events")
def list_audit_events(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    entity_type: Optional[str] = None,
    action: Optional[str] = None,
    tenant_id: Optional[str] = None,
    since: Optional[str] = None,
    auth: AuthContext = Depends(require_auth),
):
    """
    Paginated, filterable audit event list across system or tenant.
    """
    target_tenant = auth.tenant_id

    if tenant_id is not None and tenant_id != auth.tenant_id:
        raise HTTPException(
            status_code=403,
            detail="Access denied: cannot access another tenant's audit events.",
        )

    try:
        rows = audit_client.get_all_events(
            tenant_id=target_tenant,
            limit=limit,
            offset=offset,
            entity_type=entity_type,
            action=action,
            since=since,
        )
        return {
            "total_returned": len(rows),
            "limit": limit,
            "offset": offset,
            "events": rows,
        }
    except Exception as e:
        logger.error(f"Failed to fetch audit events: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to fetch audit events.",
        )


@app.get("/live-audit-feed")
def get_live_audit_feed(
    limit: int = 50,
    offset: int = 0,
    entity_type: Optional[str] = None,
    action: Optional[str] = None,
    tenant_id: Optional[str] = None,
    since: Optional[str] = None,
):
    """
    Server-side proxy feed endpoint for the secondary Live Monitor UI.
    Requires no browser token input (server authentication proxy).
    """
    try:
        rows = audit_client.get_all_events(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
            entity_type=entity_type,
            action=action,
            since=since,
        )
        return {
            "status": "live",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_returned": len(rows),
            "events": rows,
        }
    except Exception as e:
        logger.error(f"Failed to fetch live audit feed: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to fetch live audit feed.",
        )