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

from typing import Optional, Literal
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import logging

from audit_client import (
    AuditClient,
    FindingInstance,
    EvidenceSnapshot,
    PriorityDecision,
    HumanDecision,
    ExceptionRecord,
    AuditEvent as DBAuditEvent,
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


class EvidenceRequest(BaseModel):
    finding_id: str
    source_name: str
    status: EvidenceStatus
    payload: dict
    source_snapshot_at: Optional[str] = None


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
# evidence_snapshot - Anafa (enrichment)
# ============================================================

@app.post("/evidence")
def create_evidence(evidence: EvidenceRequest):
    """Record one enrichment source's result (EPSS, KEV, CMDB, etc.) for a finding."""
    try:
        db_evidence = EvidenceSnapshot(**evidence.model_dump())
        evidence_id = audit_client.log_evidence(db_evidence)
        logger.info(f"Logged evidence: id={evidence_id} finding_id={evidence.finding_id} source={evidence.source_name}")
        return {"status": "ok", "evidence_snapshot_id": evidence_id}
    except Exception as e:
        logger.error(f"Failed to log evidence: {e}")
        raise HTTPException(status_code=500, detail="Failed to record evidence.")


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