"""
vpap_audit.audit_client
------------------------

Shared database client for VPAP 4.1, covering all confirmed tables:

    Muizz (ingestion):
        ingestion_batch
        finding_instance
        dead_letter

    Anafa (enrichment):
        enrichment_run
        finding_evidence
        kev_catalogue
        kev_catalogue_entry
        epss_snapshot
        epss_snapshot_entry

    Vignesh (policy):
        policy_version
        priority_decision
        human_decision
        exception_record
        outbox_event
        ticket_link

    Sohail (audit):
        audit_event

Every pipeline stage imports this ONE module, or calls the equivalent
endpoint on audit_api.py.

The API layer wraps these methods behind HTTP so teammates do not need
direct database credentials.
"""

from __future__ import annotations

import os
import hashlib
import json

from datetime import datetime
from typing import Optional, Literal, Generic, TypeVar, Any

import psycopg
from psycopg.types.json import Json
from dotenv import load_dotenv

from pydantic import BaseModel, Field, model_validator


load_dotenv()


# ============================================================
# COMMON TYPES
# ============================================================

ActorType = Literal["system", "human", "llm"]

Priority = Literal[
    "P0",
    "P1",
    "P2",
    "P3",
    "REVIEW",
]

EvidenceStatus = Literal[
    "KNOWN",
    "UNKNOWN",
    "STALE",
    "ERROR",
]

T = TypeVar("T")


# ============================================================
# MUIZZ - INGESTION & VALIDATION
# ============================================================

class IngestionBatch(BaseModel):
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


class FindingInstance(BaseModel):
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

    def idempotency_key(self) -> str:
        material = "|".join(
            [
                self.source_system,
                self.source_finding_id,
                self.asset_id,
                self.package_id or "-",
            ]
        )

        return hashlib.sha256(
            material.encode()
        ).hexdigest()


class DeadLetter(BaseModel):
    tenant_id: str
    source_system: str

    batch_id: Optional[str] = None
    source_finding_id: Optional[str] = None

    stage: Literal[
        "INGESTION",
        "VALIDATION",
    ]

    error_code: str
    error_message: str

    raw_record: Optional[dict] = None

    status: str = "OPEN"
    retry_count: int = 0


# ============================================================
# ANAFA - ENRICHMENT
# ============================================================

class EvidenceValue(BaseModel, Generic[T]):
    value: Optional[T] = None
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

    source_timestamp: Optional[datetime] = None
    retrieved_at: datetime

    confidence: Literal[
        "HIGH",
        "MEDIUM",
        "LOW",
    ]


class CompensatingControl(BaseModel):
    type: str
    status: str

    scope: Optional[str] = None

    source: str

    verified_at: Optional[datetime] = None
    relationship: Optional[str] = None


class EnrichmentRun(BaseModel):
    """
    Represents one enrichment pipeline execution.

    tenant_id is REQUIRED.
    There is intentionally no 'default' tenant fallback.
    """

    tenant_id: str

    source_system: str
    source_instance_id: Optional[str] = None

    adapter_name: str
    adapter_version: str
    schema_version: str

    started_at: Optional[str] = None
    completed_at: Optional[str] = None

    status: str


class FindingEvidence(BaseModel):
    """
    Evidence produced for a finding during an enrichment run.
    """

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


class EpssSnapshot(BaseModel):
    source_timestamp: Optional[str] = None
    record_count: int


class EpssSnapshotEntry(BaseModel):
    snapshot_id: str
    cve_id: str

    epss_probability: float
    epss_percentile: float


# ============================================================
# VIGNESH - POLICY ENGINE
# ============================================================

class PolicyVersion(BaseModel):
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


class PriorityDecision(BaseModel):
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

    conservative_floor: Optional[Priority] = None

    sla_hours: Optional[float] = None
    sla_due_at: Optional[str] = None

    rules_applied: list = Field(
        default_factory=list
    )

    evidence_refs: list = Field(
        default_factory=list
    )


class HumanDecision(BaseModel):
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


class ExceptionRecord(BaseModel):
    tenant_id: str

    finding_id: str

    requester: str
    approver: Optional[str] = None

    status: str = "PENDING"

    justification: str

    risk_level: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ]

    valid_until: str


class OutboxEvent(BaseModel):
    tenant_id: str

    event_type: str
    aggregate_id: str

    idempotency_key: str

    payload: dict

    status: str = "PENDING"

    retry_count: int = 0

    external_id: Optional[str] = None
    error_message: Optional[str] = None


class TicketLink(BaseModel):
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


# ============================================================
# SOHAIL - AUDIT ACTION VOCABULARY
# ============================================================

"""
Exact action values used by the audit trail.

These values are validated by AuditEvent and audit_api.py.

------------------------------------------------------------
MUIZZ - INGESTION
------------------------------------------------------------

finding_instance.created
dead_letter.created

------------------------------------------------------------
ANAFA - ENRICHMENT
------------------------------------------------------------

enrichment_run.started
enrichment_run.completed
enrichment_run.failed

finding_evidence.recorded

------------------------------------------------------------
VIGNESH - POLICY ENGINE
------------------------------------------------------------

priority_decision.completed

human_decision.recorded

policy_version.published

exception_record.created
exception_record.approved
exception_record.rejected
exception_record.expired

outbox_event.created
outbox_event.delivered
outbox_event.failed

ticket_link.created
"""


ACTIONS_BY_ENTITY: dict[str, set[str]] = {

    # --------------------------------------------------------
    # MUIZZ - INGESTION
    # --------------------------------------------------------

    "finding_instance": {
        "finding_instance.created",
    },

    "dead_letter": {
        "dead_letter.created",
    },

    # --------------------------------------------------------
    # ANAFA - ENRICHMENT
    # --------------------------------------------------------

    "enrichment_run": {
        "enrichment_run.started",
        "enrichment_run.completed",
        "enrichment_run.failed",
    },

    "finding_evidence": {
        "finding_evidence.recorded",
    },

    # --------------------------------------------------------
    # EXISTING ENRICHMENT CATALOGUE EVENTS
    # --------------------------------------------------------

    "kev_catalogue": {
        "kev_catalogue.created",
    },

    "kev_catalogue_entry": {
        "kev_catalogue_entry.created",
    },

    "epss_snapshot": {
        "epss_snapshot.created",
    },

    "epss_snapshot_entry": {
        "epss_snapshot_entry.created",
    },

    # --------------------------------------------------------
    # VIGNESH - POLICY ENGINE
    # --------------------------------------------------------

    "priority_decision": {
        "priority_decision.completed",
    },

    "human_decision": {
        "human_decision.recorded",
    },

    "policy_version": {
        "policy_version.published",
    },

    "exception_record": {
        "exception_record.created",
        "exception_record.approved",
        "exception_record.rejected",
        "exception_record.expired",
    },

    "outbox_event": {
        "outbox_event.created",
        "outbox_event.delivered",
        "outbox_event.failed",
    },

    "ticket_link": {
        "ticket_link.created",
    },
}


class AuditEvent(BaseModel):
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

    source_ip: Optional[str] = None

    @model_validator(mode="after")
    def validate_action_for_entity_type(
        self,
    ) -> "AuditEvent":

        allowed_actions = ACTIONS_BY_ENTITY.get(
            self.entity_type
        )

        if (
            allowed_actions is not None
            and self.action not in allowed_actions
        ):
            raise ValueError(
                f"Invalid action '{self.action}' "
                f"for entity_type '{self.entity_type}'. "
                f"Allowed actions: "
                f"{sorted(allowed_actions)}"
            )

        return self


# ============================================================
# CLIENT
# ============================================================

class AuditClient:

    def __init__(
        self,
        dsn: Optional[str] = None,
    ):
        self.dsn = (
            dsn
            or os.environ["VPAP_AUDIT_DSN"]
        )

    # ========================================================
    # DATABASE CONNECTION
    # ========================================================

    def _connect(self):
        """
        Connect to PostgreSQL/Supabase.

        prepare_threshold=None disables psycopg3 server-side
        prepared statements.

        This is required for Supabase transaction-mode poolers
        where connections can be reused between sessions.
        """

        return psycopg.connect(
            self.dsn,
            prepare_threshold=None,
        )

    # ========================================================
    # GENERIC INSERT
    # ========================================================

    def _insert_returning(
        self,
        table: str,
        columns: list[str],
        values: dict,
        returning: str,
    ) -> str:

        placeholders = ", ".join(
            f"%({column})s"
            for column in columns
        )

        column_list = ", ".join(
            columns
        )

        with self._connect() as conn:

            with conn.cursor() as cur:

                cur.execute(
                    f"""
                    INSERT INTO {table}
                        ({column_list})
                    VALUES
                        ({placeholders})
                    RETURNING {returning}
                    """,
                    values,
                )

                row = cur.fetchone()

            conn.commit()

        return str(row[0])

    # ========================================================
    # MUIZZ - INGESTION BATCH
    # ========================================================

    def log_ingestion_batch(
        self,
        batch: IngestionBatch,
    ) -> str:

        cols = list(
            IngestionBatch.model_fields.keys()
        )

        return self._insert_returning(
            "public.ingestion_batch",
            cols,
            batch.model_dump(),
            "id",
        )

    # ========================================================
    # MUIZZ - FINDING INSTANCE
    # ========================================================

    def upsert_finding(
        self,
        finding: FindingInstance,
    ) -> str:

        key = finding.idempotency_key()

        with self._connect() as conn:

            with conn.cursor() as cur:

                cur.execute(
                    """
                    INSERT INTO public.finding_instance
                        (
                            tenant_id,
                            idempotency_key,
                            source_system,
                            source_finding_id,
                            cve_id,
                            asset_id,
                            package_id,
                            cvss_base,
                            cvss_vector,
                            description,
                            business_service_id,
                            internet_exposed,
                            first_detected_at,
                            status,
                            first_seen_at,
                            last_seen_at
                        )
                    VALUES
                        (
                            %(tenant_id)s,
                            %(idempotency_key)s,
                            %(source_system)s,
                            %(source_finding_id)s,
                            %(cve_id)s,
                            %(asset_id)s,
                            %(package_id)s,
                            %(cvss_base)s,
                            %(cvss_vector)s,
                            %(description)s,
                            %(business_service_id)s,
                            %(internet_exposed)s,
                            %(first_detected_at)s,
                            %(status)s,
                            now(),
                            now()
                        )

                    ON CONFLICT (
                        tenant_id,
                        idempotency_key
                    )

                    DO UPDATE SET
                        last_seen_at = now(),
                        status = EXCLUDED.status,
                        updated_at = now()

                    RETURNING id
                    """,
                    {
                        **finding.model_dump(),
                        "idempotency_key": key,
                    },
                )

                row = cur.fetchone()

            conn.commit()

        return str(row[0])

    # ========================================================
    # MUIZZ - DEAD LETTER
    # ========================================================

    def log_dead_letter(
        self,
        entry: DeadLetter,
    ) -> str:

        payload = entry.model_dump(
            exclude={"raw_record"}
        )

        payload["raw_record"] = (
            Json(entry.raw_record)
            if entry.raw_record
            else None
        )

        cols = list(
            DeadLetter.model_fields.keys()
        )

        return self._insert_returning(
            "public.dead_letter",
            cols,
            payload,
            "id",
        )

    # ========================================================
    # ANAFA - ENRICHMENT RUN
    # ========================================================

    def log_enrichment_run(
        self,
        run: EnrichmentRun,
    ) -> str:

        cols = list(
            EnrichmentRun.model_fields.keys()
        )

        return self._insert_returning(
            "public.enrichment_run",
            cols,
            run.model_dump(),
            "enrichment_run_id",
        )

    # --------------------------------------------------------
    # PATCH ENRICHMENT RUN
    # --------------------------------------------------------

    def update_enrichment_run(
        self,
        enrichment_run_id: str,
        tenant_id: str,
        status: str,
        completed_at: Optional[str] = None,
    ) -> str:
        """
        Update the lifecycle status of an existing enrichment run.

        Tenant isolation is enforced using both:

            enrichment_run_id
            tenant_id

        Typical transitions:

            RUNNING -> COMPLETED
            RUNNING -> FAILED

        Exposed by audit_api.py through:

            PATCH /enrichment-runs/{enrichment_run_id}
        """

        with self._connect() as conn:

            with conn.cursor() as cur:

                cur.execute(
                    """
                    UPDATE public.enrichment_run

                    SET
                        status = %(status)s,
                        completed_at = %(completed_at)s

                    WHERE enrichment_run_id =
                        %(enrichment_run_id)s

                    AND tenant_id =
                        %(tenant_id)s

                    RETURNING enrichment_run_id
                    """,
                    {
                        "enrichment_run_id":
                            enrichment_run_id,

                        "tenant_id":
                            tenant_id,

                        "status":
                            status,

                        "completed_at":
                            completed_at,
                    },
                )

                row = cur.fetchone()

            conn.commit()

        if not row:

            raise ValueError(
                f"Enrichment run not found for "
                f"tenant '{tenant_id}': "
                f"{enrichment_run_id}"
            )

        return str(row[0])

    # ========================================================
    # ANAFA - FINDING EVIDENCE
    # ========================================================

    def log_finding_evidence(
        self,
        evidence: FindingEvidence,
    ) -> str:

        evidence_fields = [
            "epss_probability",
            "epss_percentile",
            "kev_status",
            "internet_exposure",
            "runtime_applicability",
            "attack_path_reachable",
            "business_criticality",
            "compensating_controls",
        ]

        payload = evidence.model_dump(
            mode="json",
            exclude=set(evidence_fields),
        )

        for field in evidence_fields:

            payload[field] = Json(
                getattr(
                    evidence,
                    field,
                ).model_dump(
                    mode="json"
                )
            )

        hashable = evidence.model_dump(
            mode="json"
        )

        payload[
            "evidence_snapshot_sha256"
        ] = hashlib.sha256(
            json.dumps(
                hashable,
                sort_keys=True,
            ).encode()
        ).hexdigest()

        with self._connect() as conn:

            with conn.cursor() as cur:

                cur.execute(
                    """
                    INSERT INTO public.finding_evidence
                        (
                            finding_instance_id,
                            source_finding_id,
                            tenant_id,
                            source_system,
                            source_instance_id,
                            enrichment_run_id,
                            schema_version,
                            adapter_name,
                            adapter_version,
                            evidence_snapshot_sha256,
                            cve_id,
                            asset_id,
                            cvss_base,
                            epss_probability,
                            epss_percentile,
                            kev_status,
                            internet_exposure,
                            runtime_applicability,
                            attack_path_reachable,
                            business_criticality,
                            compensating_controls
                        )

                    VALUES
                        (
                            %(finding_instance_id)s,
                            %(source_finding_id)s,
                            %(tenant_id)s,
                            %(source_system)s,
                            %(source_instance_id)s,
                            %(enrichment_run_id)s,
                            %(schema_version)s,
                            %(adapter_name)s,
                            %(adapter_version)s,
                            %(evidence_snapshot_sha256)s,
                            %(cve_id)s,
                            %(asset_id)s,
                            %(cvss_base)s,
                            %(epss_probability)s,
                            %(epss_percentile)s,
                            %(kev_status)s,
                            %(internet_exposure)s,
                            %(runtime_applicability)s,
                            %(attack_path_reachable)s,
                            %(business_criticality)s,
                            %(compensating_controls)s
                        )

                    ON CONFLICT (
                        finding_instance_id,
                        enrichment_run_id
                    )

                    DO UPDATE SET
                        evidence_snapshot_sha256 =
                            EXCLUDED.evidence_snapshot_sha256,

                        cvss_base =
                            EXCLUDED.cvss_base,

                        epss_probability =
                            EXCLUDED.epss_probability,

                        epss_percentile =
                            EXCLUDED.epss_percentile,

                        kev_status =
                            EXCLUDED.kev_status,

                        internet_exposure =
                            EXCLUDED.internet_exposure,

                        runtime_applicability =
                            EXCLUDED.runtime_applicability,

                        attack_path_reachable =
                            EXCLUDED.attack_path_reachable,

                        business_criticality =
                            EXCLUDED.business_criticality,

                        compensating_controls =
                            EXCLUDED.compensating_controls

                    RETURNING evidence_snapshot_id
                    """,
                    payload,
                )

                row = cur.fetchone()

            conn.commit()

        return str(row[0])

    # ========================================================
    # ANAFA - KEV CATALOGUE
    # ========================================================

    def log_kev_catalogue(
        self,
        catalogue: KevCatalogue,
    ) -> str:

        cols = list(
            KevCatalogue.model_fields.keys()
        )

        return self._insert_returning(
            "public.kev_catalogue",
            cols,
            catalogue.model_dump(),
            "catalogue_id",
        )

    # ========================================================
    # ANAFA - KEV CATALOGUE ENTRIES
    # ========================================================

    def log_kev_catalogue_entries(
        self,
        entries: list[KevCatalogueEntry],
    ) -> int:

        if not entries:
            return 0

        with self._connect() as conn:

            with conn.cursor() as cur:

                cur.executemany(
                    """
                    INSERT INTO public.kev_catalogue_entry
                        (
                            catalogue_id,
                            cve_id
                        )

                    VALUES
                        (
                            %(catalogue_id)s,
                            %(cve_id)s
                        )

                    ON CONFLICT (
                        catalogue_id,
                        cve_id
                    )
                    DO NOTHING
                    """,
                    [
                        entry.model_dump()
                        for entry in entries
                    ],
                )

                count = cur.rowcount

            conn.commit()

        return count

    # ========================================================
    # ANAFA - EPSS SNAPSHOT
    # ========================================================

    def log_epss_snapshot(
        self,
        snapshot: EpssSnapshot,
    ) -> str:

        cols = list(
            EpssSnapshot.model_fields.keys()
        )

        return self._insert_returning(
            "public.epss_snapshot",
            cols,
            snapshot.model_dump(),
            "snapshot_id",
        )

    # ========================================================
    # ANAFA - EPSS SNAPSHOT ENTRIES
    # ========================================================

    def log_epss_snapshot_entries(
        self,
        entries: list[EpssSnapshotEntry],
    ) -> int:

        if not entries:
            return 0

        with self._connect() as conn:

            with conn.cursor() as cur:

                cur.executemany(
                    """
                    INSERT INTO public.epss_snapshot_entry
                        (
                            snapshot_id,
                            cve_id,
                            epss_probability,
                            epss_percentile
                        )

                    VALUES
                        (
                            %(snapshot_id)s,
                            %(cve_id)s,
                            %(epss_probability)s,
                            %(epss_percentile)s
                        )

                    ON CONFLICT (
                        snapshot_id,
                        cve_id
                    )
                    DO NOTHING
                    """,
                    [
                        entry.model_dump()
                        for entry in entries
                    ],
                )

                count = cur.rowcount

            conn.commit()

        return count

    # ========================================================
    # ANAFA - LATEST EPSS VALUES
    # ========================================================

    def get_latest_epss_values(
        self,
        cve_ids: list[str],
    ) -> list[dict]:

        if not cve_ids:
            return []

        with self._connect() as conn:

            with conn.cursor(
                row_factory=psycopg.rows.dict_row
            ) as cur:

                cur.execute(
                    """
                    SELECT
                        s.snapshot_id,
                        s.retrieved_at,
                        e.cve_id,
                        e.epss_probability,
                        e.epss_percentile

                    FROM public.epss_snapshot s

                    JOIN public.epss_snapshot_entry e
                        ON e.snapshot_id =
                           s.snapshot_id

                    WHERE s.snapshot_id = (
                        SELECT snapshot_id
                        FROM public.epss_snapshot
                        ORDER BY retrieved_at DESC
                        LIMIT 1
                    )

                    AND e.cve_id =
                        ANY(%(cve_ids)s)
                    """,
                    {
                        "cve_ids": cve_ids
                    },
                )

                return cur.fetchall()

    # ========================================================
    # VIGNESH - POLICY VERSION
    # ========================================================

    def log_policy_version(
        self,
        policy: PolicyVersion,
    ) -> str:

        payload = policy.model_dump(
            exclude={
                "thresholds_json",
                "weights_json",
                "sla_json",
            }
        )

        payload[
            "thresholds_json"
        ] = Json(
            policy.thresholds_json
        )

        payload[
            "weights_json"
        ] = Json(
            policy.weights_json
        )

        payload[
            "sla_json"
        ] = Json(
            policy.sla_json
        )

        cols = list(
            PolicyVersion.model_fields.keys()
        )

        return self._insert_returning(
            "public.policy_version",
            cols,
            payload,
            "version_id",
        )

    # ========================================================
    # VIGNESH - PRIORITY DECISION
    # ========================================================

    def log_decision(
        self,
        decision: PriorityDecision,
    ) -> str:

        payload = decision.model_dump(
            exclude={
                "rules_applied",
                "evidence_refs",
            }
        )

        payload[
            "rules_applied"
        ] = Json(
            decision.rules_applied
        )

        payload[
            "evidence_refs"
        ] = Json(
            decision.evidence_refs
        )

        cols = list(
            PriorityDecision.model_fields.keys()
        )

        return self._insert_returning(
            "public.priority_decision",
            cols,
            payload,
            "id",
        )

    # ========================================================
    # VIGNESH - HUMAN DECISION
    # ========================================================

    def log_human_decision(
        self,
        decision: HumanDecision,
    ) -> str:

        payload = decision.model_dump(
            exclude={
                "signatures_json"
            }
        )

        payload[
            "signatures_json"
        ] = Json(
            decision.signatures_json
        )

        cols = list(
            HumanDecision.model_fields.keys()
        )

        return self._insert_returning(
            "public.human_decision",
            cols,
            payload,
            "id",
        )

    # --------------------------------------------------------
    # GET HUMAN DECISIONS
    # --------------------------------------------------------

    def get_human_decisions(
        self,
        finding_id: str,
        tenant_id: str,
    ) -> list[dict]:

        with self._connect() as conn:

            with conn.cursor(
                row_factory=psycopg.rows.dict_row
            ) as cur:

                cur.execute(
                    """
                    SELECT *
                    FROM public.human_decision

                    WHERE finding_instance_id =
                        %(finding_id)s

                    AND tenant_id =
                        %(tenant_id)s

                    ORDER BY created_at ASC
                    """,
                    {
                        "finding_id":
                            finding_id,

                        "tenant_id":
                            tenant_id,
                    },
                )

                return cur.fetchall()

    # ========================================================
    # VIGNESH - EXCEPTION RECORD
    # ========================================================

    def log_exception(
        self,
        exception: ExceptionRecord,
    ) -> str:

        cols = list(
            ExceptionRecord.model_fields.keys()
        )

        return self._insert_returning(
            "public.exception_record",
            cols,
            exception.model_dump(),
            "id",
        )

    # --------------------------------------------------------
    # GET EXCEPTIONS
    # --------------------------------------------------------

    def get_exceptions(
        self,
        tenant_id: str,
        status: Optional[str] = None,
    ) -> list[dict]:

        with self._connect() as conn:

            with conn.cursor(
                row_factory=psycopg.rows.dict_row
            ) as cur:

                if status:

                    cur.execute(
                        """
                        SELECT *
                        FROM public.exception_record

                        WHERE tenant_id =
                            %(tenant_id)s

                        AND status =
                            %(status)s

                        ORDER BY created_at DESC
                        """,
                        {
                            "tenant_id":
                                tenant_id,

                            "status":
                                status,
                        },
                    )

                else:

                    cur.execute(
                        """
                        SELECT *
                        FROM public.exception_record

                        WHERE tenant_id =
                            %(tenant_id)s

                        ORDER BY created_at DESC
                        """,
                        {
                            "tenant_id":
                                tenant_id,
                        },
                    )

                return cur.fetchall()

    # --------------------------------------------------------
    # UPDATE EXCEPTION
    # --------------------------------------------------------

    def update_exception(
        self,
        exception_id: str,
        tenant_id: str,
        status: str,
        approver: Optional[str] = None,
        approved_at: Optional[str] = None,
    ) -> Optional[dict]:
        """
        Update an exception status while enforcing tenant isolation.

        This assumes exception_record contains an approved_at column.

        If the database schema does not contain approved_at,
        remove approved_at from this method and the SQL UPDATE.
        """

        with self._connect() as conn:

            with conn.cursor(
                row_factory=psycopg.rows.dict_row
            ) as cur:

                cur.execute(
                    """
                    UPDATE public.exception_record

                    SET
                        status = %(status)s,

                        approver = COALESCE(
                            %(approver)s,
                            approver
                        ),

                        approved_at = CASE

                            WHEN %(approved_at)s
                                IS NOT NULL

                            THEN %(approved_at)s

                            ELSE approved_at

                        END

                    WHERE id =
                        %(exception_id)s

                    AND tenant_id =
                        %(tenant_id)s

                    RETURNING *
                    """,
                    {
                        "exception_id":
                            exception_id,

                        "tenant_id":
                            tenant_id,

                        "status":
                            status,

                        "approver":
                            approver,

                        "approved_at":
                            approved_at,
                    },
                )

                row = cur.fetchone()

            conn.commit()

        return row

    # ========================================================
    # VIGNESH - OUTBOX EVENT
    # ========================================================

    def log_outbox_event(
        self,
        event: OutboxEvent,
    ) -> str:

        payload = event.model_dump(
            exclude={
                "payload"
            }
        )

        payload[
            "payload"
        ] = Json(
            event.payload
        )

        cols = list(
            OutboxEvent.model_fields.keys()
        )

        return self._insert_returning(
            "public.outbox_event",
            cols,
            payload,
            "id",
        )

    # --------------------------------------------------------
    # GET OUTBOX EVENTS
    # --------------------------------------------------------

    def get_outbox_events(
        self,
        tenant_id: str,
        status: Optional[str] = None,
    ) -> list[dict]:

        with self._connect() as conn:

            with conn.cursor(
                row_factory=psycopg.rows.dict_row
            ) as cur:

                if status:

                    cur.execute(
                        """
                        SELECT *
                        FROM public.outbox_event

                        WHERE tenant_id =
                            %(tenant_id)s

                        AND status =
                            %(status)s

                        ORDER BY created_at ASC
                        """,
                        {
                            "tenant_id":
                                tenant_id,

                            "status":
                                status,
                        },
                    )

                else:

                    cur.execute(
                        """
                        SELECT *
                        FROM public.outbox_event

                        WHERE tenant_id =
                            %(tenant_id)s

                        ORDER BY created_at ASC
                        """,
                        {
                            "tenant_id":
                                tenant_id,
                        },
                    )

                return cur.fetchall()

    # --------------------------------------------------------
    # UPDATE OUTBOX EVENT
    # --------------------------------------------------------

    def update_outbox_event(
        self,
        outbox_event_id: str,
        tenant_id: str,
        status: str,
        external_id: Optional[str] = None,
        retry_count: Optional[int] = None,
        error_message: Optional[str] = None,
    ) -> Optional[dict]:

        with self._connect() as conn:

            with conn.cursor(
                row_factory=psycopg.rows.dict_row
            ) as cur:

                cur.execute(
                    """
                    UPDATE public.outbox_event

                    SET
                        status = %(status)s,

                        external_id = COALESCE(
                            %(external_id)s,
                            external_id
                        ),

                        retry_count = COALESCE(
                            %(retry_count)s,
                            retry_count
                        ),

                        error_message =
                            %(error_message)s

                    WHERE id =
                        %(outbox_event_id)s

                    AND tenant_id =
                        %(tenant_id)s

                    RETURNING *
                    """,
                    {
                        "outbox_event_id":
                            outbox_event_id,

                        "tenant_id":
                            tenant_id,

                        "status":
                            status,

                        "external_id":
                            external_id,

                        "retry_count":
                            retry_count,

                        "error_message":
                            error_message,
                    },
                )

                row = cur.fetchone()

            conn.commit()

        return row

    # ========================================================
    # VIGNESH - TICKET LINK
    # ========================================================

    def log_ticket_link(
        self,
        ticket: TicketLink,
    ) -> str:

        cols = list(
            TicketLink.model_fields.keys()
        )

        return self._insert_returning(
            "public.ticket_link",
            cols,
            ticket.model_dump(),
            "id",
        )

    # ========================================================
    # SOHAIL - AUDIT EVENT
    # ========================================================

    def log(
        self,
        event: AuditEvent,
    ) -> None:

        with self._connect() as conn:

            with conn.cursor() as cur:

                cur.execute(
                    """
                    INSERT INTO public.audit_event
                        (
                            tenant_id,
                            actor_type,
                            actor_id,
                            action,
                            entity_type,
                            entity_id,
                            correlation_id,
                            policy_version,
                            evidence_ref,
                            before_state,
                            after_state,
                            source_ip
                        )

                    VALUES
                        (
                            %(tenant_id)s,
                            %(actor_type)s,
                            %(actor_id)s,
                            %(action)s,
                            %(entity_type)s,
                            %(entity_id)s,
                            %(correlation_id)s,
                            %(policy_version)s,
                            %(evidence_ref)s,
                            %(before_state)s,
                            %(after_state)s,
                            %(source_ip)s
                        )
                    """,
                    {
                        **event.model_dump(
                            exclude={
                                "before_state",
                                "after_state",
                            }
                        ),

                        "before_state":
                            (
                                Json(
                                    event.before_state
                                )
                                if event.before_state
                                else None
                            ),

                        "after_state":
                            (
                                Json(
                                    event.after_state
                                )
                                if event.after_state
                                else None
                            ),
                    },
                )

            conn.commit()

    # ========================================================
    # AUDIT TRAIL
    # ========================================================

    def get_trail(
        self,
        correlation_id: str,
        tenant_id: str,
    ) -> list[dict]:
        """
        Retrieve audit events for a correlation ID.

        Tenant filtering is mandatory to prevent one tenant from
        reading another tenant's audit trail.
        """

        with self._connect() as conn:

            with conn.cursor(
                row_factory=psycopg.rows.dict_row
            ) as cur:

                cur.execute(
                    """
                    SELECT *
                    FROM public.audit_event

                    WHERE correlation_id =
                        %(cid)s

                    AND tenant_id =
                        %(tenant_id)s

                    ORDER BY occurred_at ASC
                    """,
                    {
                        "cid":
                            correlation_id,

                        "tenant_id":
                            tenant_id,
                    },
                )

                return cur.fetchall()

    # ========================================================
    # FINDING HISTORY
    # ========================================================

    def get_finding_history(
        self,
        finding_id: str,
        tenant_id: str,
    ) -> dict:
        """
        Full reconstructed story of one finding.

        finding_id is the external/source finding ID
        (for example: wiz-vf-000002).

        Tenant filtering is mandatory to prevent cross-tenant
        data exposure.
        """

        with self._connect() as conn:

            with conn.cursor(
                row_factory=psycopg.rows.dict_row
            ) as cur:

                # ------------------------------------------------
                # FINDING
                # ------------------------------------------------
                # The frontend/API sends source_finding_id,
                # not the internal UUID primary key.

                cur.execute(
                    """
                    SELECT *
                    FROM public.finding_instance

                    WHERE source_finding_id =
                        %(finding_id)s

                    AND tenant_id =
                        %(tenant_id)s

                    LIMIT 1
                    """,
                    {
                        "finding_id": finding_id,
                        "tenant_id": tenant_id,
                    },
                )

                finding = cur.fetchone()

                if finding is None:
                    return {
                        "finding": None,
                        "evidence": [],
                        "decisions": [],
                        "human_decisions": [],
                        "exceptions": [],
                        "tickets": [],
                        "audit_trail": [],
                    }

                # Internal PostgreSQL UUID.
                # This is required by tables that reference
                # finding_instance.id.
                finding_instance_id = str(finding["id"])

                # ------------------------------------------------
                # FINDING EVIDENCE
                # ------------------------------------------------

                cur.execute(
                    """
                    SELECT *
                    FROM public.finding_evidence

                    WHERE finding_instance_id =
                        %(finding_instance_id)s

                    AND tenant_id =
                        %(tenant_id)s

                    ORDER BY created_at ASC
                    """,
                    {
                        "finding_instance_id": finding_instance_id,
                        "tenant_id": tenant_id,
                    },
                )

                evidence = cur.fetchall()

                # ------------------------------------------------
                # PRIORITY DECISIONS
                # ------------------------------------------------
                # priority_decision.finding_id stores the
                # external/source finding ID.

                cur.execute(
                    """
                    SELECT *
                    FROM public.priority_decision

                    WHERE finding_id =
                        %(finding_id)s

                    AND tenant_id =
                        %(tenant_id)s

                    ORDER BY created_at ASC
                    """,
                    {
                        "finding_id": finding_id,
                        "tenant_id": tenant_id,
                    },
                )

                decisions = cur.fetchall()

                # ------------------------------------------------
                # HUMAN DECISIONS
                # ------------------------------------------------
                # human_decision.finding_instance_id stores
                # the internal UUID.

                cur.execute(
                    """
                    SELECT *
                    FROM public.human_decision

                    WHERE finding_instance_id =
                        %(finding_instance_id)s

                    AND tenant_id =
                        %(tenant_id)s

                    ORDER BY created_at ASC
                    """,
                    {
                        "finding_instance_id": finding_instance_id,
                        "tenant_id": tenant_id,
                    },
                )

                human_decisions = cur.fetchall()

                # ------------------------------------------------
                # EXCEPTIONS
                # ------------------------------------------------
                # exception_record.finding_id stores the
                # external/source finding ID.

                cur.execute(
                    """
                    SELECT *
                    FROM public.exception_record

                    WHERE finding_id =
                        %(finding_id)s

                    AND tenant_id =
                        %(tenant_id)s

                    ORDER BY created_at ASC
                    """,
                    {
                        "finding_id": finding_id,
                        "tenant_id": tenant_id,
                    },
                )

                exceptions = cur.fetchall()

                # ------------------------------------------------
                # TICKET LINKS
                # ------------------------------------------------
                # ticket_link.finding_instance_id stores
                # the internal UUID.

                cur.execute(
                    """
                    SELECT *
                    FROM public.ticket_link

                    WHERE finding_instance_id =
                        %(finding_instance_id)s

                    AND tenant_id =
                        %(tenant_id)s

                    ORDER BY created_at ASC
                    """,
                    {
                        "finding_instance_id": finding_instance_id,
                        "tenant_id": tenant_id,
                    },
                )

                tickets = cur.fetchall()

                # ------------------------------------------------
                # AUDIT TRAIL
                # ------------------------------------------------
                # audit_event.correlation_id stores the
                # external/source finding ID.

                cur.execute(
                    """
                    SELECT *
                    FROM public.audit_event

                    WHERE correlation_id =
                        %(finding_id)s

                    AND tenant_id =
                        %(tenant_id)s

                    ORDER BY occurred_at ASC
                    """,
                    {
                        "finding_id": finding_id,
                        "tenant_id": tenant_id,
                    },
                )

                audit_trail = cur.fetchall()

        return {
            "finding": finding,
            "evidence": evidence,
            "decisions": decisions,
            "human_decisions": human_decisions,
            "exceptions": exceptions,
            "tickets": tickets,
            "audit_trail": audit_trail,
        }