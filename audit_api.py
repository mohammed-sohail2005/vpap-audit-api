"""
VPAP 4.1 - Audit/data API service
------------------------------------
Exposes the proper VPAP data model as HTTP endpoints, so Muizz
(ingestion/validation), Anafa (enrichment), and Vignesh (policy engine)
can write into the shared Supabase database without ever holding
database credentials themselves.

Endpoints map 1:1 to the design doc's tables:

    POST /findings              -> finding_instance   (Muizz - ingestion)
    POST /evidence               -> evidence_snapshot   (Anafa - enrichment)
    POST /decisions               -> priority_decision   (Vignesh - policy engine)
    POST /human-decisions         -> human_decision       (HITL review)
    POST /exceptions              -> exception_record     (HITL review)
    POST /audit-events            -> audit_event          (everyone - the "what happened" trail)

    GET  /findings/{finding_id}/history  -> full reconstructed story of one finding
    GET  /audit-events/{correlation_id}  -> raw audit trail for one finding

Run locally with:
    py -m uvicorn audit_api:app --host 0.0.0.0 --port 8000
"""

from typing import Optional, Literal, Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import logging

from audit_client import (
    AuditClient,
    FindingInstance,
    PriorityDecision,
    HumanDecision,
    ExceptionRecord,
    AuditEvent as DBAuditEvent,
    EvidenceValue,
    CompensatingControl,
    EnrichmentRun,
    FindingEvidence as DBFindingEvidence,
    KevCatalogue,
    KevCatalogueEntry,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vpap-audit-api")

app = FastAPI(
    title="VPAP Audit & Data API",
    description="Internal endpoints for writing to the shared VPAP database (finding_instance, evidence_snapshot, priority_decision, human_decision, exception_record, audit_event).",
    version="2.0.0",
)

audit_client = AuditClient()

ActorType = Literal["system", "human", "llm"]
Priority = Literal["P0", "P1", "P2", "P3", "REVIEW"]
EvidenceStatus = Literal["KNOWN", "UNKNOWN", "STALE", "ERROR"]


# ============================================================
# Request models (mirror audit_client models 1:1)
# ============================================================

class FindingRequest(BaseModel):
    tenant_id: str = "default"
    source_system: str
    source_finding_id: str
    cve_id: str
    asset_id: str
    package_id: Optional[str] = None
    status: str = "NEW"


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


class KevCatalogueRequest(BaseModel):
    source_timestamp: Optional[str] = None
    catalogue_sha256: str
    record_count: int
    status: str


class KevCatalogueEntryRequest(BaseModel):
    catalogue_id: str
    cve_id: str


class KevCatalogueEntriesRequest(BaseModel):
    entries: list[KevCatalogueEntryRequest]


class DecisionRequest(BaseModel):
    finding_id: str
    evidence_snapshot_id: Optional[str] = None
    policy_version: str
    mandatory_remediation: bool = False
    vps: Optional[float] = None
    operational_priority: Priority
    confidence: str
    decision_status: str
    rules_applied: list[str]
    evidence_refs: list[str]


class HumanDecisionRequest(BaseModel):
    priority_decision_id: str
    actor_id: str
    decision: str
    reason: Optional[str] = None


class ExceptionRequest(BaseModel):
    finding_id: str
    actor_id: str
    reason: str
    exception_type: str
    revalidate_at: Optional[str] = None


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


# ============================================================
# Health check
# ============================================================

@app.get("/")
def health_check():
    return {"status": "ok", "service": "vpap-audit-api"}


# ============================================================
# finding_instance - Muizz (ingestion/validation)
# ============================================================

@app.post("/findings")
def create_finding(finding: FindingRequest):
    """
    Ingest/validate a finding. Idempotent - calling this again with the
    same source_system + source_finding_id + asset_id + package_id
    returns the SAME finding_instance.id instead of creating a duplicate.
    """
    try:
        db_finding = FindingInstance(**finding.model_dump())
        finding_id = audit_client.upsert_finding(db_finding)
        logger.info(f"Upserted finding: id={finding_id} cve={finding.cve_id}")
        return {"status": "ok", "finding_id": finding_id}
    except Exception as e:
        logger.error(f"Failed to upsert finding: {e}")
        raise HTTPException(status_code=500, detail="Failed to record finding.")


@app.get("/findings/{finding_id}/history")
def get_finding_history(finding_id: str):
    """Full reconstructed story of one finding: itself, evidence, decisions, human decisions, exceptions."""
    try:
        return audit_client.get_finding_history(finding_id)
    except Exception as e:
        logger.error(f"Failed to fetch finding history: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch finding history.")


# ============================================================
# Enrichment tables - Anafa
# ============================================================

@app.post("/enrichment-runs")
def create_enrichment_run(run: EnrichmentRunRequest):
    """Start/record one enrichment batch run. Returns enrichment_run_id to reuse across the batch."""
    try:
        db_run = EnrichmentRun(**run.model_dump())
        run_id = audit_client.log_enrichment_run(db_run)
        logger.info(f"Logged enrichment run: id={run_id} adapter={run.adapter_name}")
        return {"status": "ok", "enrichment_run_id": run_id}
    except Exception as e:
        logger.error(f"Failed to log enrichment run: {e}")
        raise HTTPException(status_code=500, detail="Failed to record enrichment run.")


@app.post("/evidence")
def create_finding_evidence(evidence: FindingEvidenceRequest):
    """
    Record the complete evidence for one finding (EPSS, KEV, exposure,
    runtime applicability, attack path, business criticality,
    compensating controls) - each as a full EvidenceValue with
    value/status/reason_code/provenance, never a bare value.
    """
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
        logger.info(f"Logged finding evidence: id={evidence_id} finding_instance_id={evidence.finding_instance_id}")
        return {"status": "ok", "evidence_snapshot_id": evidence_id}
    except Exception as e:
        logger.error(f"Failed to log finding evidence: {e}")
        raise HTTPException(status_code=500, detail="Failed to record finding evidence.")


@app.post("/kev-catalogue")
def create_kev_catalogue(catalogue: KevCatalogueRequest):
    """Record one downloaded KEV catalogue snapshot. Returns catalogue_id to attach entries to."""
    try:
        db_catalogue = KevCatalogue(**catalogue.model_dump())
        catalogue_id = audit_client.log_kev_catalogue(db_catalogue)
        logger.info(f"Logged KEV catalogue: id={catalogue_id} record_count={catalogue.record_count}")
        return {"status": "ok", "catalogue_id": catalogue_id}
    except Exception as e:
        logger.error(f"Failed to log KEV catalogue: {e}")
        raise HTTPException(status_code=500, detail="Failed to record KEV catalogue.")


@app.post("/kev-catalogue-entries")
def create_kev_catalogue_entries(request: KevCatalogueEntriesRequest):
    """Bulk-insert the CVEs listed in a KEV catalogue snapshot. Duplicates are silently skipped."""
    try:
        db_entries = [KevCatalogueEntry(**e.model_dump()) for e in request.entries]
        count = audit_client.log_kev_catalogue_entries(db_entries)
        logger.info(f"Logged {count} KEV catalogue entries")
        return {"status": "ok", "entries_inserted": count}
    except Exception as e:
        logger.error(f"Failed to log KEV catalogue entries: {e}")
        raise HTTPException(status_code=500, detail="Failed to record KEV catalogue entries.")


# ============================================================
# priority_decision - Vignesh (policy engine)
# ============================================================

@app.post("/decisions")
def create_decision(decision: DecisionRequest):
    """Record the policy engine's scoring output for a finding. Versioned - never mutated."""
    try:
        db_decision = PriorityDecision(**decision.model_dump())
        decision_id = audit_client.log_decision(db_decision)
        logger.info(f"Logged decision: id={decision_id} finding_id={decision.finding_id} priority={decision.operational_priority}")
        return {"status": "ok", "priority_decision_id": decision_id}
    except Exception as e:
        logger.error(f"Failed to log decision: {e}")
        raise HTTPException(status_code=500, detail="Failed to record decision.")


# ============================================================
# human_decision - HITL review
# ============================================================

@app.post("/human-decisions")
def create_human_decision(decision: HumanDecisionRequest):
    """Record a human reviewer's approval/override/rejection of a priority_decision."""
    try:
        db_decision = HumanDecision(**decision.model_dump())
        decision_id = audit_client.log_human_decision(db_decision)
        logger.info(f"Logged human decision: id={decision_id} priority_decision_id={decision.priority_decision_id}")
        return {"status": "ok", "human_decision_id": decision_id}
    except Exception as e:
        logger.error(f"Failed to log human decision: {e}")
        raise HTTPException(status_code=500, detail="Failed to record human decision.")


# ============================================================
# exception_record - HITL review
# ============================================================

@app.post("/exceptions")
def create_exception(exception: ExceptionRequest):
    """Record a risk acceptance, false-positive, or deferment for a finding."""
    try:
        db_exception = ExceptionRecord(**exception.model_dump())
        exception_id = audit_client.log_exception(db_exception)
        logger.info(f"Logged exception: id={exception_id} finding_id={exception.finding_id}")
        return {"status": "ok", "exception_id": exception_id}
    except Exception as e:
        logger.error(f"Failed to log exception: {e}")
        raise HTTPException(status_code=500, detail="Failed to record exception.")


# ============================================================
# audit_event - everyone, the "what happened" trail
# ============================================================

@app.post("/audit-events")
def create_audit_event(event: AuditEventRequest):
    """Append one audit event. This is the immutable 'who did what when' record."""
    try:
        db_event = DBAuditEvent(**event.model_dump())
        audit_client.log(db_event)
        logger.info(f"Logged audit event: actor={event.actor_id} action={event.action} correlation_id={event.correlation_id}")
        return {"status": "ok", "message": "Audit event recorded"}
    except Exception as e:
        logger.error(f"Failed to write audit event: {e}")
        raise HTTPException(status_code=500, detail="Failed to record audit event.")


@app.get("/audit-events/{correlation_id}")
def get_audit_trail(correlation_id: str):
    """Fetch the raw audit_event rows for one finding, in chronological order."""
    try:
        rows = audit_client.get_trail(correlation_id)
        return {"correlation_id": correlation_id, "event_count": len(rows), "events": rows}
    except Exception as e:
        logger.error(f"Failed to fetch audit trail: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch audit trail.")