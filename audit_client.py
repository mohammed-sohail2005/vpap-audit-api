"""
vpap_audit.audit_client
------------------------
Shared audit-logging client for VPAP 4.1.

Every stage of the pipeline (ingestion, enrichment, policy engine, ITSM
connector, HITL API) imports this ONE module and calls write_audit_event()
instead of writing its own SQL. This guarantees:

  - every team writes to the audit_event table in the exact same shape
  - the append-only DB permissions are respected (nobody accidentally
    opens a connection with write/update access)
  - a single place to change the schema/behavior later

Usage from any teammate's service:

    from vpap_audit.audit_client import AuditClient, AuditEvent

    audit = AuditClient(dsn="postgresql://vpap_app:...@host:5432/vpap")

    audit.log(AuditEvent(
        actor_type="system",
        actor_id="enrichment-service",
        action="finding.enriched",
        entity_type="finding_instance",
        entity_id=finding_id,
        correlation_id=finding_id,
        evidence_ref=snapshot_id,
        after_state={"epss_probability": 0.9, "kev_value": True},
    ))
"""

from __future__ import annotations

import os
from typing import Optional, Literal
from pydantic import BaseModel
import psycopg
from psycopg.types.json import Json
from dotenv import load_dotenv

load_dotenv()  # reads .env in the current folder and loads it into os.environ


ActorType = Literal["system", "human", "llm"]


class AuditEvent(BaseModel):
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
    source_ip: Optional[str] = None


class AuditClient:
    """
    Thin wrapper around a Postgres connection pool, scoped to writing
    audit_event rows. Each teammate's service creates ONE AuditClient
    at startup and reuses it for every event it logs.
    """

    def __init__(self, dsn: Optional[str] = None):
        # dsn example: "postgresql://vpap_app:password@localhost:5432/vpap"
        # Recommended: read from an environment variable, never hardcode
        # credentials in code that gets committed.
        self.dsn = dsn or os.environ["VPAP_AUDIT_DSN"]

    def log(self, event: AuditEvent) -> None:
        """Write one audit event. Raises if the insert fails - callers
        should decide whether a failed audit write should block the
        pipeline (recommended: yes, for decision-critical events)."""
        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO audit_event
                        (tenant_id, actor_type, actor_id, action, entity_type,
                         entity_id, correlation_id, policy_version, evidence_ref,
                         before_state, after_state, source_ip)
                    VALUES
                        (%(tenant_id)s, %(actor_type)s, %(actor_id)s, %(action)s,
                         %(entity_type)s, %(entity_id)s, %(correlation_id)s,
                         %(policy_version)s, %(evidence_ref)s,
                         %(before_state)s, %(after_state)s, %(source_ip)s)
                    """,
                    {
                        "tenant_id": event.tenant_id,
                        "actor_type": event.actor_type,
                        "actor_id": event.actor_id,
                        "action": event.action,
                        "entity_type": event.entity_type,
                        "entity_id": event.entity_id,
                        "correlation_id": event.correlation_id,
                        "policy_version": event.policy_version,
                        "evidence_ref": event.evidence_ref,
                        "before_state": Json(event.before_state) if event.before_state else None,
                        "after_state": Json(event.after_state) if event.after_state else None,
                        "source_ip": event.source_ip,
                    },
                )
            conn.commit()

    def get_trail(self, correlation_id: str) -> list[dict]:
        """Fetch the full ordered audit trail for one finding - useful for
        debugging, demos, and answering 'what happened to this finding'."""
        with psycopg.connect(self.dsn) as conn:
            with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                cur.execute(
                    """
                    SELECT * FROM audit_event
                    WHERE correlation_id = %(cid)s
                    ORDER BY occurred_at ASC
                    """,
                    {"cid": correlation_id},
                )
                return cur.fetchall()