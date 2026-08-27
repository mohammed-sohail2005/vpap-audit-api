"""
VPAP 4.1 - Audit API service
------------------------------
A small FastAPI service that exposes ONE endpoint: POST /audit-events

Muizz (ingestion/validation), Anafa (enrichment), and Vignesh (policy engine)
call this endpoint from their own code whenever something happens in their
part of the pipeline. They never see the database password or touch
Supabase directly - this service is the only thing that holds real DB
credentials (via audit_client.py + .env).

Run locally with:
    py -m uvicorn audit_api:app --host 0.0.0.0 --port 8000

--host 0.0.0.0 means "listen on all network interfaces", not just
localhost - this is what lets teammates on the same network reach it
using your PC's IP address, e.g. http://192.168.1.42:8000/audit-events

Teammates then call it like this from their own Python code:

    import requests

    requests.post(
        "http://192.168.1.42:8000/audit-events",
        json={
            "actor_type": "system",
            "actor_id": "ingest-service",
            "action": "finding.ingested",
            "entity_type": "finding_instance",
            "entity_id": "finding-8f31a2",
            "correlation_id": "finding-8f31a2",
            "after_state": {"cve_id": "CVE-2026-99001"},
        },
    )
"""

from typing import Optional, Literal
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import logging

from audit_client import AuditClient, AuditEvent as DBAuditEvent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vpap-audit-api")

app = FastAPI(
    title="VPAP Audit API",
    description="Internal endpoint for logging audit events into the shared VPAP audit database.",
    version="1.0.0",
)

# One shared AuditClient instance, reused across every request - it reads
# VPAP_AUDIT_DSN from .env once at startup.
audit_client = AuditClient()


ActorType = Literal["system", "human", "llm"]


class AuditEventRequest(BaseModel):
    """
    The shape teammates send in their POST request body.
    Matches audit_client.AuditEvent, but defined separately here so the
    API's public contract doesn't silently change if audit_client.py's
    internals change later.
    """
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


@app.get("/")
def health_check():
    """Simple endpoint to confirm the service is running and reachable."""
    return {"status": "ok", "service": "vpap-audit-api"}


@app.post("/audit-events")
def create_audit_event(event: AuditEventRequest):
    """
    Receives one audit event from any pipeline stage (ingestion,
    enrichment, policy engine, etc.) and writes it into the shared
    Supabase audit_event table.
    """
    try:
        db_event = DBAuditEvent(
            actor_type=event.actor_type,
            actor_id=event.actor_id,
            action=event.action,
            entity_type=event.entity_type,
            entity_id=event.entity_id,
            correlation_id=event.correlation_id,
            tenant_id=event.tenant_id,
            policy_version=event.policy_version,
            evidence_ref=event.evidence_ref,
            before_state=event.before_state,
            after_state=event.after_state,
        )
        audit_client.log(db_event)
        logger.info(f"Logged audit event: actor={event.actor_id} action={event.action} correlation_id={event.correlation_id}")
        return {"status": "ok", "message": "Audit event recorded"}

    except Exception as e:
        logger.error(f"Failed to write audit event: {e}")
        # 500 because this is a server-side (our DB/logic) failure, not
        # the caller's fault - but we don't leak internal error details
        # like DB credentials in the response.
        raise HTTPException(status_code=500, detail="Failed to record audit event. Please retry or contact the audit team.")


@app.get("/audit-events/{correlation_id}")
def get_audit_trail(correlation_id: str):
    """
    Fetch the full audit trail for one finding, in chronological order.
    Useful for debugging and for anyone (including teammates) to check
    "what happened to this finding so far".
    """
    try:
        rows = audit_client.get_trail(correlation_id)
        return {"correlation_id": correlation_id, "event_count": len(rows), "events": rows}
    except Exception as e:
        logger.error(f"Failed to fetch audit trail: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch audit trail.")