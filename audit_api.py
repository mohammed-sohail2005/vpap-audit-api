"""
VPAP 4.1 - Full data & audit API
------------------------------------
One REST endpoint per table, so Muizz, Anafa, Vignesh, and I never need
direct database credentials. Everyone calls this API; this service is
the only thing holding the real Supabase connection string.

    Muizz (ingestion):   POST /ingestion-batches, POST /findings, POST /dead-letters
    Anafa (enrichment):  POST /enrichment-runs, POST /evidence,
                         POST /kev-catalogue, POST /kev-catalogue-entries
    Vignesh (policy):    POST /policy-versions, POST /decisions,
                         POST /human-decisions, POST /exceptions,
                         POST /outbox-events, POST /ticket-links
    Sohail (audit):      POST /audit-events, GET /audit-events/{correlation_id}
    Everyone:            GET /findings/{finding_id}/history

Run locally with:
    py -m uvicorn audit_api:app --host 0.0.0.0 --port 8000
"""

from typing import Optional, Literal, Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import logging

from audit_client import (
    AuditClient,
    IngestionBatch, FindingInstance, DeadLetter,
    EvidenceValue, EnrichmentRun, FindingEvidence as DBFindingEvidence,
    KevCatalogue, KevCatalogueEntry,
    EpssSnapshot, EpssSnapshotEntry,
    PolicyVersion, PriorityDecision, HumanDecision, ExceptionRecord,
    OutboxEvent, TicketLink,
    AuditEvent as DBAuditEvent,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vpap-audit-api")

app = FastAPI(
    title="VPAP Audit & Data API",
    description="Shared endpoints for ingestion, enrichment, policy engine, and audit data.",
    version="3.0.0",
)

audit_client = AuditClient()

ActorType = Literal["system", "human", "llm"]
Priority = Literal["P0", "P1", "P2", "P3", "REVIEW"]


@app.get("/")
def health_check():
    return {"status": "ok", "service": "vpap-audit-api"}


# ============================================================
# MUIZZ - Ingestion & Validation
# ============================================================

class IngestionBatchRequest(BaseModel):
    tenant_id: str
    source_system: str
    source_type: Literal["FILE", "API", "STREAM"]
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
def create_ingestion_batch(batch: IngestionBatchRequest):
    try:
        batch_id = audit_client.log_ingestion_batch(IngestionBatch(**batch.model_dump()))
        logger.info(f"Logged ingestion batch: id={batch_id}")
        return {"status": "ok", "batch_id": batch_id}
    except Exception as e:
        logger.error(f"Failed to log ingestion batch: {e}")
        raise HTTPException(status_code=500, detail="Failed to record ingestion batch.")


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
def create_finding(finding: FindingRequest):
    """Idempotent - same source_system+source_finding_id+asset_id+package_id returns the same finding_id."""
    try:
        finding_id = audit_client.upsert_finding(FindingInstance(**finding.model_dump()))
        logger.info(f"Upserted finding: id={finding_id} cve={finding.cve_id}")
        return {"status": "ok", "finding_id": finding_id}
    except Exception as e:
        logger.error(f"Failed to upsert finding: {e}")
        raise HTTPException(status_code=500, detail="Failed to record finding.")


class DeadLetterRequest(BaseModel):
    tenant_id: str
    source_system: str
    batch_id: Optional[str] = None
    source_finding_id: Optional[str] = None
    stage: Literal["INGESTION", "VALIDATION"]
    error_code: str
    error_message: str
    raw_record: Optional[dict] = None
    status: str = "OPEN"
    retry_count: int = 0


@app.post("/dead-letters")
def create_dead_letter(entry: DeadLetterRequest):
    try:
        dl_id = audit_client.log_dead_letter(DeadLetter(**entry.model_dump()))
        logger.info(f"Logged dead letter: id={dl_id} stage={entry.stage}")
        return {"status": "ok", "dead_letter_id": dl_id}
    except Exception as e:
        logger.error(f"Failed to log dead letter: {e}")
        raise HTTPException(status_code=500, detail="Failed to record dead letter.")


@app.get("/findings/{finding_id}/history")
def get_finding_history(finding_id: str):
    try:
        return audit_client.get_finding_history(finding_id)
    except Exception as e:
        logger.error(f"Failed to fetch finding history: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch finding history.")


# ============================================================
# ANAFA - Enrichment
# ============================================================

class EvidenceValueRequest(BaseModel):
    value: Optional[Any] = None
    raw_value: Optional[Any] = None
    mapping_version: Optional[str] = None
    status: Literal["KNOWN", "UNKNOWN", "STALE", "ERROR"]
    reason_code: Optional[str] = None
    source: str
    source_field: Optional[str] = None
    source_timestamp: Optional[str] = None
    retrieved_at: str
    confidence: Literal["HIGH", "MEDIUM", "LOW"]


class EnrichmentRunRequest(BaseModel):
    tenant_id: str = "default"
    source_system: str
    source_instance_id: Optional[str] = None
    adapter_name: str
    adapter_version: str
    schema_version: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    status: str


@app.post("/enrichment-runs")
def create_enrichment_run(run: EnrichmentRunRequest):
    try:
        run_id = audit_client.log_enrichment_run(EnrichmentRun(**run.model_dump()))
        logger.info(f"Logged enrichment run: id={run_id}")
        return {"status": "ok", "enrichment_run_id": run_id}
    except Exception as e:
        logger.error(f"Failed to log enrichment run: {e}")
        raise HTTPException(status_code=500, detail="Failed to record enrichment run.")


class FindingEvidenceRequest(BaseModel):
    finding_instance_id: str
    source_finding_id: str
    tenant_id: str = "default"
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
def create_finding_evidence(evidence: FindingEvidenceRequest):
    try:
        db_evidence = DBFindingEvidence(
            **evidence.model_dump(exclude={
                "epss_probability", "epss_percentile", "kev_status", "internet_exposure",
                "runtime_applicability", "attack_path_reachable", "business_criticality",
                "compensating_controls",
            }),
            epss_probability=EvidenceValue(**evidence.epss_probability.model_dump()),
            epss_percentile=EvidenceValue(**evidence.epss_percentile.model_dump()),
            kev_status=EvidenceValue(**evidence.kev_status.model_dump()),
            internet_exposure=EvidenceValue(**evidence.internet_exposure.model_dump()),
            runtime_applicability=EvidenceValue(**evidence.runtime_applicability.model_dump()),
            attack_path_reachable=EvidenceValue(**evidence.attack_path_reachable.model_dump()),
            business_criticality=EvidenceValue(**evidence.business_criticality.model_dump()),
            compensating_controls=EvidenceValue(**evidence.compensating_controls.model_dump()),
        )
        evidence_id = audit_client.log_finding_evidence(db_evidence)
        logger.info(f"Logged finding evidence: id={evidence_id}")
        return {"status": "ok", "evidence_snapshot_id": evidence_id}
    except Exception as e:
        logger.error(f"Failed to log finding evidence: {e}")
        raise HTTPException(status_code=500, detail="Failed to record finding evidence.")


class KevCatalogueRequest(BaseModel):
    source_timestamp: Optional[str] = None
    catalogue_sha256: str
    record_count: int
    status: str


@app.post("/kev-catalogue")
def create_kev_catalogue(catalogue: KevCatalogueRequest):
    try:
        catalogue_id = audit_client.log_kev_catalogue(KevCatalogue(**catalogue.model_dump()))
        logger.info(f"Logged KEV catalogue: id={catalogue_id}")
        return {"status": "ok", "catalogue_id": catalogue_id}
    except Exception as e:
        logger.error(f"Failed to log KEV catalogue: {e}")
        raise HTTPException(status_code=500, detail="Failed to record KEV catalogue.")


class KevCatalogueEntryRequest(BaseModel):
    catalogue_id: str
    cve_id: str


class KevCatalogueEntriesRequest(BaseModel):
    entries: list[KevCatalogueEntryRequest]


@app.post("/kev-catalogue-entries")
def create_kev_catalogue_entries(request: KevCatalogueEntriesRequest):
    try:
        entries = [KevCatalogueEntry(**e.model_dump()) for e in request.entries]
        count = audit_client.log_kev_catalogue_entries(entries)
        logger.info(f"Logged {count} KEV catalogue entries")
        return {"status": "ok", "entries_inserted": count}
    except Exception as e:
        logger.error(f"Failed to log KEV catalogue entries: {e}")
        raise HTTPException(status_code=500, detail="Failed to record KEV catalogue entries.")


class EpssSnapshotRequest(BaseModel):
    source_timestamp: Optional[str] = None
    record_count: int


@app.post("/epss-snapshots")
def create_epss_snapshot(snapshot: EpssSnapshotRequest):
    """Record one EPSS bulk download/snapshot. Returns snapshot_id to attach entries to."""
    try:
        snapshot_id = audit_client.log_epss_snapshot(EpssSnapshot(**snapshot.model_dump()))
        logger.info(f"Logged EPSS snapshot: id={snapshot_id} record_count={snapshot.record_count}")
        return {"status": "ok", "snapshot_id": snapshot_id}
    except Exception as e:
        logger.error(f"Failed to log EPSS snapshot: {e}")
        raise HTTPException(status_code=500, detail="Failed to record EPSS snapshot.")


class EpssSnapshotEntryRequest(BaseModel):
    snapshot_id: str
    cve_id: str
    epss_probability: float
    epss_percentile: float


class EpssSnapshotEntriesRequest(BaseModel):
    entries: list[EpssSnapshotEntryRequest]


@app.post("/epss-snapshot-entries")
def create_epss_snapshot_entries(request: EpssSnapshotEntriesRequest):
    """Bulk-insert EPSS scores for a snapshot. Duplicates (same snapshot+CVE) are silently skipped."""
    try:
        entries = [EpssSnapshotEntry(**e.model_dump()) for e in request.entries]
        count = audit_client.log_epss_snapshot_entries(entries)
        logger.info(f"Logged {count} EPSS snapshot entries")
        return {"status": "ok", "entries_inserted": count}
    except Exception as e:
        logger.error(f"Failed to log EPSS snapshot entries: {e}")
        raise HTTPException(status_code=500, detail="Failed to record EPSS snapshot entries.")


@app.get("/epss-snapshot-entries/latest")
def get_latest_epss_values(cve_ids: str):
    """
    Look up the latest EPSS values for a batch of CVEs, so enrichment
    can reuse cached values instead of querying EPSS per finding.
    cve_ids: comma-separated list, e.g. ?cve_ids=CVE-2026-1,CVE-2026-2
    Returns each CVE found in the single most recent snapshot, along
    with that snapshot's retrieved_at so the caller can judge freshness.
    """
    try:
        cve_list = [c.strip() for c in cve_ids.split(",") if c.strip()]
        rows = audit_client.get_latest_epss_values(cve_list)
        return {"requested": cve_list, "found": len(rows), "values": rows}
    except Exception as e:
        logger.error(f"Failed to fetch latest EPSS values: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch latest EPSS values.")


# ============================================================
# VIGNESH - Policy Engine
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
def create_policy_version(policy: PolicyVersionRequest):
    try:
        version_id = audit_client.log_policy_version(PolicyVersion(**policy.model_dump()))
        logger.info(f"Logged policy version: id={version_id}")
        return {"status": "ok", "version_id": version_id}
    except Exception as e:
        logger.error(f"Failed to log policy version: {e}")
        raise HTTPException(status_code=500, detail="Failed to record policy version.")


class DecisionRequest(BaseModel):
    tenant_id: str
    finding_id: str
    evidence_snapshot_id: str
    policy_version: str
    mandatory_remediation: bool
    vps: Optional[float] = None
    operational_priority: Priority
    ssvc_outcome: Optional[Literal["TRACK", "TRACK*", "ATTEND", "ACT"]] = None
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
    decision_status: Literal["FINAL", "PROVISIONAL", "NEEDS_REVIEW", "QUARANTINED"]
    conservative_floor: Optional[Priority] = None
    sla_hours: Optional[float] = None
    sla_due_at: Optional[str] = None
    rules_applied: list = []
    evidence_refs: list = []


@app.post("/decisions")
def create_decision(decision: DecisionRequest):
    """Versioned - never mutated. An override creates a NEW row."""
    try:
        decision_id = audit_client.log_decision(PriorityDecision(**decision.model_dump()))
        logger.info(f"Logged decision: id={decision_id} priority={decision.operational_priority}")
        return {"status": "ok", "priority_decision_id": decision_id}
    except Exception as e:
        logger.error(f"Failed to log decision: {e}")
        raise HTTPException(status_code=500, detail="Failed to record decision.")


class HumanDecisionRequest(BaseModel):
    tenant_id: str
    finding_instance_id: str
    request_id: str
    decision_type: str
    original_priority: Priority
    proposed_priority: Priority
    actor_id: str
    actor_username: str
    actor_role: Literal["ANALYST", "VULN_LEAD", "RISK_OWNER", "CISO_DELEGATE", "AUDITOR"]
    rationale: str
    signatures_json: list


@app.post("/human-decisions")
def create_human_decision(decision: HumanDecisionRequest):
    try:
        decision_id = audit_client.log_human_decision(HumanDecision(**decision.model_dump()))
        logger.info(f"Logged human decision: id={decision_id}")
        return {"status": "ok", "human_decision_id": decision_id}
    except Exception as e:
        logger.error(f"Failed to log human decision: {e}")
        raise HTTPException(status_code=500, detail="Failed to record human decision.")


class ExceptionRequest(BaseModel):
    tenant_id: str
    finding_id: str
    requester: str
    approver: Optional[str] = None
    status: str = "PENDING"
    justification: str
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    valid_until: str


@app.post("/exceptions")
def create_exception(exception: ExceptionRequest):
    try:
        exception_id = audit_client.log_exception(ExceptionRecord(**exception.model_dump()))
        logger.info(f"Logged exception: id={exception_id}")
        return {"status": "ok", "exception_id": exception_id}
    except Exception as e:
        logger.error(f"Failed to log exception: {e}")
        raise HTTPException(status_code=500, detail="Failed to record exception.")


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
def create_outbox_event(event: OutboxEventRequest):
    try:
        event_id = audit_client.log_outbox_event(OutboxEvent(**event.model_dump()))
        logger.info(f"Logged outbox event: id={event_id}")
        return {"status": "ok", "outbox_event_id": event_id}
    except Exception as e:
        logger.error(f"Failed to log outbox event: {e}")
        raise HTTPException(status_code=500, detail="Failed to record outbox event.")


class TicketLinkRequest(BaseModel):
    tenant_id: str
    finding_instance_id: str
    system: Literal["JIRA", "SERVICENOW", "HYBRID"]
    ticket_key: str
    ticket_url: Optional[str] = None
    status: str = "OPEN"
    priority: Optional[str] = None
    sla_due_at: Optional[str] = None
    last_synced_at: Optional[str] = None


@app.post("/ticket-links")
def create_ticket_link(ticket: TicketLinkRequest):
    try:
        ticket_id = audit_client.log_ticket_link(TicketLink(**ticket.model_dump()))
        logger.info(f"Logged ticket link: id={ticket_id}")
        return {"status": "ok", "ticket_link_id": ticket_id}
    except Exception as e:
        logger.error(f"Failed to log ticket link: {e}")
        raise HTTPException(status_code=500, detail="Failed to record ticket link.")


# ============================================================
# SOHAIL - Audit
# ============================================================

class AuditEventRequest(BaseModel):
    actor_type: ActorType
    actor_id: str
    action: str
    entity_type: str
    entity_id: str
    correlation_id: str
    tenant_id: str = "default"
    policy_version: Optional[str] = None
    evidence_ref: Optional[str] = None
    before_state: Optional[dict] = None
    after_state: Optional[dict] = None


@app.post("/audit-events")
def create_audit_event(event: AuditEventRequest):
    try:
        db_event = DBAuditEvent(**event.model_dump())
        audit_client.log(db_event)
        logger.info(f"Logged audit event: actor={event.actor_id} action={event.action}")
        return {"status": "ok", "message": "Audit event recorded"}
    except Exception as e:
        logger.error(f"Failed to write audit event: {e}")
        raise HTTPException(status_code=500, detail="Failed to record audit event.")


@app.get("/audit-events/{correlation_id}")
def get_audit_trail(correlation_id: str):
    try:
        rows = audit_client.get_trail(correlation_id)
        return {"correlation_id": correlation_id, "event_count": len(rows), "events": rows}
    except Exception as e:
        logger.error(f"Failed to fetch audit trail: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch audit trail.")