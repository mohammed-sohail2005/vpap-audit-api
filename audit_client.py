"""
vpap_audit.audit_client
------------------------
Shared database client for VPAP 4.1, aligned with the design doc's
actual data model:

    finding_instance    - one row per unique finding
    evidence_snapshot   - enrichment data, FK to finding_instance
    priority_decision   - scoring output, FK to finding_instance + evidence_snapshot
    human_decision       - review/override actions, FK to priority_decision
    exception_record     - risk acceptance/false-positive/deferment, FK to finding_instance
    audit_event          - append-only "who did what when" trail, references any of the above

Every pipeline stage (ingestion, enrichment, policy engine, HITL review)
imports this ONE module. Import it directly if you're calling it from
within the same Python process; otherwise call the equivalent endpoint
on audit_api.py, which wraps every method here behind HTTP so nobody
needs direct database credentials.
"""

from __future__ import annotations

import os
import hashlib
import json
from typing import Optional, Literal
from pydantic import BaseModel
import psycopg
from psycopg.types.json import Json
from dotenv import load_dotenv

load_dotenv()  # reads .env in the current folder and loads it into os.environ


ActorType = Literal["system", "human", "llm"]
Priority = Literal["P0", "P1", "P2", "P3", "REVIEW"]
EvidenceStatus = Literal["KNOWN", "UNKNOWN", "STALE", "ERROR"]


# ============================================================
# Models - one per table
# ============================================================

class FindingInstance(BaseModel):
    tenant_id: str = "default"
    source_system: str
    source_finding_id: str
    cve_id: str
    asset_id: str
    package_id: Optional[str] = None
    status: str = "NEW"

    def idempotency_key(self) -> str:
        """Matches Finding.idempotency_key() from the Build Guide's domain model."""
        material = "|".join([self.source_system, self.source_finding_id, self.asset_id, self.package_id or "-"])
        return hashlib.sha256(material.encode()).hexdigest()


# ============================================================
# Enrichment models (Anafa) - mirror her Pydantic contract exactly
# ============================================================

from typing import Generic, TypeVar, Any
from datetime import datetime

T = TypeVar("T")


class EvidenceValue(BaseModel, Generic[T]):
    """One piece of evidence and its provenance. UNKNOWN != False/0."""
    value: Optional[T] = None
    raw_value: Optional[Any] = None
    mapping_version: Optional[str] = None
    status: Literal["KNOWN", "UNKNOWN", "STALE", "ERROR"]
    reason_code: Optional[str] = None
    source: str
    source_field: Optional[str] = None
    source_timestamp: Optional[datetime] = None
    retrieved_at: datetime
    confidence: Literal["HIGH", "MEDIUM", "LOW"]


class CompensatingControl(BaseModel):
    type: str
    status: str
    scope: Optional[str] = None
    source: str
    verified_at: Optional[datetime] = None
    relationship: Optional[str] = None


class EnrichmentRun(BaseModel):
    tenant_id: str = "default"
    source_system: str
    source_instance_id: Optional[str] = None
    adapter_name: str
    adapter_version: str
    schema_version: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    status: str


class FindingEvidence(BaseModel):
    """Complete evidence record for one vulnerability finding."""
    finding_instance_id: str
    source_finding_id: str
    tenant_id: str = "default"
    source_system: str
    source_instance_id: Optional[str] = None
    enrichment_run_id: str
    schema_version: str
    adapter_name: str
    adapter_version: str
    evidence_snapshot_sha256: str

    cve_id: str
    asset_id: str
    cvss_base: Optional[float] = None

    epss_probability: EvidenceValue
    epss_percentile: EvidenceValue
    kev_status: EvidenceValue
    internet_exposure: EvidenceValue
    runtime_applicability: EvidenceValue
    attack_path_reachable: EvidenceValue
    business_criticality: EvidenceValue
    compensating_controls: EvidenceValue


class KevCatalogue(BaseModel):
    source_timestamp: Optional[str] = None
    catalogue_sha256: str
    record_count: int
    status: str


class KevCatalogueEntry(BaseModel):
    catalogue_id: str
    cve_id: str


class PriorityDecision(BaseModel):
    finding_id: str
    evidence_snapshot_id: Optional[str] = None
    policy_version: str
    mandatory_remediation: bool = False
    vps: Optional[float] = None
    operational_priority: Priority
    confidence: str
    decision_status: str  # 'FINAL' | 'NEEDS_REVIEW'
    rules_applied: list[str]
    evidence_refs: list[str]


class HumanDecision(BaseModel):
    priority_decision_id: str
    actor_id: str
    decision: str  # 'APPROVED' | 'OVERRIDDEN' | 'REJECTED'
    reason: Optional[str] = None


class ExceptionRecord(BaseModel):
    finding_id: str
    actor_id: str
    reason: str
    exception_type: str  # 'RISK_ACCEPTED' | 'FALSE_POSITIVE' | 'DEFERRED'
    revalidate_at: Optional[str] = None


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


# ============================================================
# Client
# ============================================================

class AuditClient:
    """
    Thin wrapper around a Postgres connection, scoped to the VPAP schema.
    Each service creates ONE AuditClient at startup and reuses it.
    """

    def __init__(self, dsn: Optional[str] = None):
        self.dsn = dsn or os.environ["VPAP_AUDIT_DSN"]

    def _connect(self):
        return psycopg.connect(self.dsn)

    # -------------------- finding_instance --------------------

    def upsert_finding(self, finding: FindingInstance) -> str:
        """
        Insert a finding, or return the existing row's id if this exact
        (tenant, idempotency_key) already exists - matches the domain
        model's idempotency contract so re-ingesting the same finding
        never creates a duplicate.
        Returns the finding_instance.id (uuid as text).
        """
        key = finding.idempotency_key()
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO finding_instance
                        (tenant_id, idempotency_key, source_system, source_finding_id,
                         cve_id, asset_id, package_id, status, first_seen_at, last_seen_at)
                    VALUES
                        (%(tenant_id)s, %(idempotency_key)s, %(source_system)s, %(source_finding_id)s,
                         %(cve_id)s, %(asset_id)s, %(package_id)s, %(status)s, now(), now())
                    ON CONFLICT (tenant_id, idempotency_key)
                    DO UPDATE SET last_seen_at = now(), status = EXCLUDED.status
                    RETURNING id
                    """,
                    {**finding.model_dump(), "idempotency_key": key},
                )
                row = cur.fetchone()
            conn.commit()
        return str(row[0])

    # -------------------- enrichment_run --------------------

    def log_enrichment_run(self, run: EnrichmentRun) -> str:
        """Insert one enrichment_run row. Returns its enrichment_run_id."""
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO enrichment_run
                        (tenant_id, source_system, source_instance_id, adapter_name,
                         adapter_version, schema_version, started_at, completed_at, status)
                    VALUES
                        (%(tenant_id)s, %(source_system)s, %(source_instance_id)s, %(adapter_name)s,
                         %(adapter_version)s, %(schema_version)s, %(started_at)s, %(completed_at)s, %(status)s)
                    RETURNING enrichment_run_id
                    """,
                    run.model_dump(),
                )
                row = cur.fetchone()
            conn.commit()
        return str(row[0])

    # -------------------- finding_evidence --------------------

    def log_finding_evidence(self, evidence: FindingEvidence) -> str:
        """Insert one finding_evidence row. Returns its evidence_snapshot_id."""
        evidence_fields = [
            "epss_probability", "epss_percentile", "kev_status", "internet_exposure",
            "runtime_applicability", "attack_path_reachable", "business_criticality",
            "compensating_controls",
        ]
        payload = evidence.model_dump(mode="json", exclude=set(evidence_fields))
        for f in evidence_fields:
            payload[f] = Json(getattr(evidence, f).model_dump(mode="json"))

        # evidence_snapshot_sha256 is computed from the full evidence payload,
        # so it's tamper-evident - recompute here rather than trusting a
        # caller-supplied hash.
        hashable = evidence.model_dump(mode="json")
        computed_sha256 = hashlib.sha256(json.dumps(hashable, sort_keys=True).encode()).hexdigest()
        payload["evidence_snapshot_sha256"] = computed_sha256

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO finding_evidence
                        (finding_instance_id, source_finding_id, tenant_id, source_system,
                         source_instance_id, enrichment_run_id, schema_version, adapter_name,
                         adapter_version, evidence_snapshot_sha256, cve_id, asset_id, cvss_base,
                         epss_probability, epss_percentile, kev_status, internet_exposure,
                         runtime_applicability, attack_path_reachable, business_criticality,
                         compensating_controls)
                    VALUES
                        (%(finding_instance_id)s, %(source_finding_id)s, %(tenant_id)s, %(source_system)s,
                         %(source_instance_id)s, %(enrichment_run_id)s, %(schema_version)s, %(adapter_name)s,
                         %(adapter_version)s, %(evidence_snapshot_sha256)s, %(cve_id)s, %(asset_id)s, %(cvss_base)s,
                         %(epss_probability)s, %(epss_percentile)s, %(kev_status)s, %(internet_exposure)s,
                         %(runtime_applicability)s, %(attack_path_reachable)s, %(business_criticality)s,
                         %(compensating_controls)s)
                    RETURNING evidence_snapshot_id
                    """,
                    payload,
                )
                row = cur.fetchone()
            conn.commit()
        return str(row[0])

    # -------------------- kev_catalogue --------------------

    def log_kev_catalogue(self, catalogue: KevCatalogue) -> str:
        """Insert one kev_catalogue snapshot row. Returns its catalogue_id."""
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO kev_catalogue
                        (source_timestamp, catalogue_sha256, record_count, status)
                    VALUES
                        (%(source_timestamp)s, %(catalogue_sha256)s, %(record_count)s, %(status)s)
                    RETURNING catalogue_id
                    """,
                    catalogue.model_dump(),
                )
                row = cur.fetchone()
            conn.commit()
        return str(row[0])

    def log_kev_catalogue_entries(self, entries: list[KevCatalogueEntry]) -> int:
        """Bulk-insert kev_catalogue_entry rows. Returns count inserted (duplicates skipped)."""
        if not entries:
            return 0
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.executemany(
                    """
                    INSERT INTO kev_catalogue_entry (catalogue_id, cve_id)
                    VALUES (%(catalogue_id)s, %(cve_id)s)
                    ON CONFLICT (catalogue_id, cve_id) DO NOTHING
                    """,
                    [e.model_dump() for e in entries],
                )
                count = cur.rowcount
            conn.commit()
        return count

    # -------------------- priority_decision --------------------

    def log_decision(self, decision: PriorityDecision) -> str:
        """Insert one priority_decision row (versioned - never mutated). Returns its id."""
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO priority_decision
                        (finding_id, evidence_snapshot_id, policy_version, mandatory_remediation,
                         vps, operational_priority, confidence, decision_status,
                         rules_applied, evidence_refs)
                    VALUES
                        (%(finding_id)s, %(evidence_snapshot_id)s, %(policy_version)s, %(mandatory_remediation)s,
                         %(vps)s, %(operational_priority)s, %(confidence)s, %(decision_status)s,
                         %(rules_applied)s, %(evidence_refs)s)
                    RETURNING id
                    """,
                    {
                        **decision.model_dump(exclude={"rules_applied", "evidence_refs"}),
                        "rules_applied": Json(decision.rules_applied),
                        "evidence_refs": Json(decision.evidence_refs),
                    },
                )
                row = cur.fetchone()
            conn.commit()
        return str(row[0])

    # -------------------- human_decision --------------------

    def log_human_decision(self, decision: HumanDecision) -> str:
        """Insert one human_decision row, linked to a priority_decision. Returns its id."""
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO human_decision (priority_decision_id, actor_id, decision, reason)
                    VALUES (%(priority_decision_id)s, %(actor_id)s, %(decision)s, %(reason)s)
                    RETURNING id
                    """,
                    decision.model_dump(),
                )
                row = cur.fetchone()
            conn.commit()
        return str(row[0])

    # -------------------- exception_record --------------------

    def log_exception(self, exception: ExceptionRecord) -> str:
        """Insert one exception_record row. Returns its id."""
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO exception_record
                        (finding_id, actor_id, reason, exception_type, revalidate_at)
                    VALUES
                        (%(finding_id)s, %(actor_id)s, %(reason)s, %(exception_type)s, %(revalidate_at)s)
                    RETURNING id
                    """,
                    exception.model_dump(),
                )
                row = cur.fetchone()
            conn.commit()
        return str(row[0])

    # -------------------- audit_event --------------------

    def log(self, event: AuditEvent) -> None:
        """Write one audit event. This table is append-only - INSERT only."""
        with self._connect() as conn:
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
                        **event.model_dump(exclude={"before_state", "after_state"}),
                        "before_state": Json(event.before_state) if event.before_state else None,
                        "after_state": Json(event.after_state) if event.after_state else None,
                    },
                )
            conn.commit()

    def get_trail(self, correlation_id: str) -> list[dict]:
        """Fetch the full ordered audit trail for one finding."""
        with self._connect() as conn:
            with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                cur.execute(
                    "SELECT * FROM audit_event WHERE correlation_id = %(cid)s ORDER BY occurred_at ASC",
                    {"cid": correlation_id},
                )
                return cur.fetchall()

    def get_finding_history(self, finding_id: str) -> dict:
        """
        Fetch everything known about one finding: the finding itself,
        all evidence snapshots, all priority decisions (with any human
        decisions on each), and any exceptions - for reconstructing a
        finding's complete story across the proper relational schema.
        """
        with self._connect() as conn:
            with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                cur.execute("SELECT * FROM finding_instance WHERE id = %(id)s", {"id": finding_id})
                finding = cur.fetchone()

                cur.execute(
                    "SELECT * FROM evidence_snapshot WHERE finding_id = %(id)s ORDER BY retrieved_at ASC",
                    {"id": finding_id},
                )
                evidence = cur.fetchall()

                cur.execute(
                    "SELECT * FROM priority_decision WHERE finding_id = %(id)s ORDER BY created_at ASC",
                    {"id": finding_id},
                )
                decisions = cur.fetchall()

                decision_ids = [d["id"] for d in decisions]
                human_decisions = []
                if decision_ids:
                    cur.execute(
                        "SELECT * FROM human_decision WHERE priority_decision_id = ANY(%(ids)s) ORDER BY created_at ASC",
                        {"ids": decision_ids},
                    )
                    human_decisions = cur.fetchall()

                cur.execute(
                    "SELECT * FROM exception_record WHERE finding_id = %(id)s ORDER BY created_at ASC",
                    {"id": finding_id},
                )
                exceptions = cur.fetchall()

        return {
            "finding": finding,
            "evidence": evidence,
            "decisions": decisions,
            "human_decisions": human_decisions,
            "exceptions": exceptions,
        }