-- ============================================================
-- VPAP 4.1 - Migration 0001
-- Baseline schema
-- ============================================================
-- This migration creates the initial VPAP database schema.
--
-- IMPORTANT:
-- This is the BASELINE migration.
-- Do NOT put finding_instance.batch_id in this file.
--
-- Migration 0002 adds:
--   - finding_instance.batch_id
--   - FK to ingestion_batch(id)
--   - idx_finding_instance_batch
-- ============================================================


-- ============================================================
-- PostgreSQL Extensions
-- ============================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- ============================================================
-- MUIZZ - Ingestion & Validation
-- ============================================================


-- 1. INGESTION BATCH
CREATE TABLE IF NOT EXISTS public.ingestion_batch (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    source_system TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_reference TEXT,
    source_file_name TEXT,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processing_started_at TIMESTAMPTZ,
    processing_completed_at TIMESTAMPTZ,
    total_records INTEGER NOT NULL DEFAULT 0,
    accepted_records INTEGER NOT NULL DEFAULT 0,
    rejected_records INTEGER NOT NULL DEFAULT 0,
    validation_failed_records INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'RECEIVED',
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT ingestion_batch_source_type_check
        CHECK (source_type IN ('FILE', 'API', 'STREAM')),

    CONSTRAINT ingestion_batch_status_check
        CHECK (
            status IN (
                'RECEIVED',
                'PROCESSING',
                'COMPLETED',
                'PARTIAL',
                'FAILED'
            )
        ),

    CONSTRAINT ingestion_batch_counts_check
        CHECK (
            total_records >= 0
            AND accepted_records >= 0
            AND rejected_records >= 0
            AND validation_failed_records >= 0
        ),

    CONSTRAINT ingestion_batch_source_system_check
        CHECK (source_system = UPPER(source_system))
);


-- 2. FINDING INSTANCE
-- Canonical entity referenced by downstream stages.
--
-- IMPORTANT:
-- batch_id is intentionally NOT present here.
-- It is added by migration 0002.
CREATE TABLE IF NOT EXISTS public.finding_instance (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    source_system TEXT NOT NULL,
    source_finding_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    package_id TEXT,
    cvss_base NUMERIC(3,1),
    cvss_vector TEXT,
    description TEXT,
    business_service_id TEXT,
    internet_exposed BOOLEAN,
    first_detected_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'VALID',
    first_seen_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT finding_instance_tenant_idempotency_unique
        UNIQUE (tenant_id, idempotency_key),

    CONSTRAINT finding_instance_cvss_check
        CHECK (
            cvss_base IS NULL
            OR (cvss_base >= 0 AND cvss_base <= 10)
        ),

    CONSTRAINT finding_instance_source_system_check
        CHECK (source_system = UPPER(source_system))
);


-- 3. DEAD LETTER
CREATE TABLE IF NOT EXISTS public.dead_letter (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    source_system TEXT NOT NULL,
    batch_id UUID,
    source_finding_id TEXT,
    stage TEXT NOT NULL,
    error_code TEXT NOT NULL,
    error_message TEXT NOT NULL,
    raw_record JSONB,
    status TEXT NOT NULL DEFAULT 'OPEN',
    retry_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,

    CONSTRAINT dead_letter_batch_fk
        FOREIGN KEY (batch_id)
        REFERENCES public.ingestion_batch(id)
        ON DELETE SET NULL,

    CONSTRAINT dead_letter_stage_check
        CHECK (stage IN ('INGESTION', 'VALIDATION')),

    CONSTRAINT dead_letter_status_check
        CHECK (
            status IN (
                'OPEN',
                'REPROCESSED',
                'RESOLVED',
                'IGNORED'
            )
        ),

    CONSTRAINT dead_letter_retry_count_check
        CHECK (retry_count >= 0),

    CONSTRAINT dead_letter_source_system_check
        CHECK (source_system = UPPER(source_system))
);


-- ============================================================
-- Ingestion Indexes
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_ingestion_batch_tenant_created
    ON public.ingestion_batch (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ingestion_batch_tenant_status
    ON public.ingestion_batch (tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_finding_instance_tenant_cve
    ON public.finding_instance (tenant_id, cve_id);

CREATE INDEX IF NOT EXISTS idx_finding_instance_tenant_asset
    ON public.finding_instance (tenant_id, asset_id);

CREATE INDEX IF NOT EXISTS idx_finding_instance_tenant_status
    ON public.finding_instance (tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_finding_instance_tenant_last_seen
    ON public.finding_instance (tenant_id, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_dead_letter_tenant_status_created
    ON public.dead_letter (tenant_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_dead_letter_batch
    ON public.dead_letter (batch_id);

CREATE INDEX IF NOT EXISTS idx_dead_letter_tenant_source_finding
    ON public.dead_letter (tenant_id, source_finding_id);


-- ============================================================
-- ANAFA - Enrichment
-- ============================================================


CREATE TABLE IF NOT EXISTS public.enrichment_run (
    enrichment_run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL DEFAULT 'default',
    source_system TEXT NOT NULL,
    source_instance_id TEXT,
    adapter_name TEXT NOT NULL,
    adapter_version TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE TABLE IF NOT EXISTS public.finding_evidence (
    evidence_snapshot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_instance_id UUID NOT NULL
        REFERENCES public.finding_instance(id),
    source_finding_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    source_system TEXT NOT NULL,
    source_instance_id TEXT,
    enrichment_run_id UUID NOT NULL
        REFERENCES public.enrichment_run(enrichment_run_id),
    schema_version TEXT NOT NULL,
    adapter_name TEXT NOT NULL,
    adapter_version TEXT NOT NULL,
    evidence_snapshot_sha256 TEXT NOT NULL,

    cve_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    cvss_base NUMERIC(3,1),

    epss_probability JSONB NOT NULL,
    epss_percentile JSONB NOT NULL,
    kev_status JSONB NOT NULL,
    internet_exposure JSONB NOT NULL,
    runtime_applicability JSONB NOT NULL,
    attack_path_reachable JSONB NOT NULL,
    business_criticality JSONB NOT NULL,
    compensating_controls JSONB NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding
    ON public.finding_evidence (finding_instance_id);

CREATE INDEX IF NOT EXISTS idx_finding_evidence_run
    ON public.finding_evidence (enrichment_run_id);

CREATE INDEX IF NOT EXISTS idx_finding_evidence_cve
    ON public.finding_evidence (cve_id);


CREATE TABLE IF NOT EXISTS public.kev_catalogue (
    catalogue_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_timestamp TIMESTAMPTZ,
    retrieved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    catalogue_sha256 TEXT NOT NULL,
    record_count INTEGER NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE TABLE IF NOT EXISTS public.kev_catalogue_entry (
    catalogue_entry_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    catalogue_id UUID NOT NULL
        REFERENCES public.kev_catalogue(catalogue_id),
    cve_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (catalogue_id, cve_id)
);


CREATE INDEX IF NOT EXISTS idx_kev_catalogue_entry_cve
    ON public.kev_catalogue_entry (cve_id);


-- One row per EPSS bulk download/snapshot.
CREATE TABLE IF NOT EXISTS public.epss_snapshot (
    snapshot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_timestamp TIMESTAMPTZ,
    retrieved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    record_count INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- One row per CVE's EPSS score within a snapshot.
CREATE TABLE IF NOT EXISTS public.epss_snapshot_entry (
    entry_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id UUID NOT NULL
        REFERENCES public.epss_snapshot(snapshot_id),
    cve_id TEXT NOT NULL,
    epss_probability NUMERIC(7,5) NOT NULL,
    epss_percentile NUMERIC(7,5) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (snapshot_id, cve_id)
);


CREATE INDEX IF NOT EXISTS idx_epss_snapshot_entry_cve
    ON public.epss_snapshot_entry (cve_id);

CREATE INDEX IF NOT EXISTS idx_epss_snapshot_retrieved_at
    ON public.epss_snapshot (retrieved_at DESC);


-- ============================================================
-- VIGNESH - Policy Engine
-- ============================================================


-- 1. POLICY VERSION
CREATE TABLE IF NOT EXISTS public.policy_version (
    version_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    author TEXT NOT NULL,
    thresholds_json JSONB NOT NULL,
    weights_json JSONB NOT NULL,
    sla_json JSONB NOT NULL,
    conservative_floor_default TEXT NOT NULL DEFAULT 'P0',
    artifact_digest TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT policy_version_floor_check
        CHECK (
            conservative_floor_default
            IN ('P0','P1','P2','P3','REVIEW')
        ),

    CONSTRAINT policy_version_digest_check
        CHECK (char_length(artifact_digest) = 64)
);


-- 2. PRIORITY DECISION
CREATE TABLE IF NOT EXISTS public.priority_decision (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    finding_id UUID NOT NULL,
    evidence_snapshot_id UUID NOT NULL,
    policy_version TEXT NOT NULL,
    mandatory_remediation BOOLEAN NOT NULL,
    vps NUMERIC(5,2),
    operational_priority TEXT NOT NULL,
    ssvc_outcome TEXT,
    confidence TEXT NOT NULL,
    decision_status TEXT NOT NULL,
    conservative_floor TEXT,
    sla_hours NUMERIC(6,2),
    sla_due_at TIMESTAMPTZ,
    rules_applied JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT priority_decision_finding_fk
        FOREIGN KEY (finding_id)
        REFERENCES public.finding_instance(id)
        ON DELETE CASCADE,

    CONSTRAINT priority_decision_evidence_fk
        FOREIGN KEY (evidence_snapshot_id)
        REFERENCES public.finding_evidence(evidence_snapshot_id)
        ON DELETE CASCADE,

    CONSTRAINT priority_decision_policy_fk
        FOREIGN KEY (policy_version)
        REFERENCES public.policy_version(version_id),

    CONSTRAINT priority_decision_vps_check
        CHECK (vps IS NULL OR (vps >= 0 AND vps <= 100)),

    CONSTRAINT priority_decision_priority_check
        CHECK (
            operational_priority
            IN ('P0','P1','P2','P3','REVIEW')
        ),

    CONSTRAINT priority_decision_floor_check
        CHECK (
            conservative_floor IS NULL
            OR conservative_floor
            IN ('P0','P1','P2','P3','REVIEW')
        ),

    CONSTRAINT priority_decision_ssvc_outcome_check
        CHECK (
            ssvc_outcome IS NULL
            OR ssvc_outcome IN ('TRACK','TRACK*','ATTEND','ACT')
        ),

    CONSTRAINT priority_decision_confidence_check
        CHECK (confidence IN ('HIGH','MEDIUM','LOW')),

    CONSTRAINT priority_decision_status_check
        CHECK (
            decision_status
            IN ('FINAL','PROVISIONAL','NEEDS_REVIEW','QUARANTINED')
        ),

    CONSTRAINT priority_decision_sla_hours_check
        CHECK (sla_hours IS NULL OR sla_hours >= 0)
);


-- 3. HUMAN DECISION
CREATE TABLE IF NOT EXISTS public.human_decision (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    finding_instance_id UUID NOT NULL,
    request_id TEXT NOT NULL,
    decision_type TEXT NOT NULL,
    original_priority TEXT NOT NULL,
    proposed_priority TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_username TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    rationale TEXT NOT NULL,
    signatures_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT human_decision_finding_fk
        FOREIGN KEY (finding_instance_id)
        REFERENCES public.finding_instance(id)
        ON DELETE CASCADE,

    CONSTRAINT human_decision_original_priority_check
        CHECK (
            original_priority
            IN ('P0','P1','P2','P3','REVIEW')
        ),

    CONSTRAINT human_decision_proposed_priority_check
        CHECK (
            proposed_priority
            IN ('P0','P1','P2','P3','REVIEW')
        ),

    CONSTRAINT human_decision_actor_role_check
        CHECK (
            actor_role
            IN (
                'ANALYST',
                'VULN_LEAD',
                'RISK_OWNER',
                'CISO_DELEGATE',
                'AUDITOR'
            )
        )
);


-- 4. EXCEPTION RECORD
CREATE TABLE IF NOT EXISTS public.exception_record (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    finding_id UUID NOT NULL,
    requester TEXT NOT NULL,
    approver TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING',
    justification TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT exception_record_finding_fk
        FOREIGN KEY (finding_id)
        REFERENCES public.finding_instance(id)
        ON DELETE CASCADE,

    CONSTRAINT exception_record_status_check
        CHECK (
            status
            IN ('PENDING','APPROVED','REJECTED','EXPIRED','REVOKED')
        ),

    CONSTRAINT exception_record_risk_level_check
        CHECK (
            risk_level
            IN ('LOW','MEDIUM','HIGH','CRITICAL')
        )
);


-- 5. OUTBOX EVENT
CREATE TABLE IF NOT EXISTS public.outbox_event (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    retry_count INTEGER NOT NULL DEFAULT 0,
    external_id TEXT,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,

    CONSTRAINT outbox_event_status_check
        CHECK (
            status
            IN ('PENDING','DELIVERED','FAILED','DEAD_LETTER')
        ),

    CONSTRAINT outbox_event_retry_count_check
        CHECK (retry_count >= 0)
);


-- 6. TICKET LINK
CREATE TABLE IF NOT EXISTS public.ticket_link (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    finding_instance_id UUID NOT NULL,
    system TEXT NOT NULL,
    ticket_key TEXT NOT NULL,
    ticket_url TEXT,
    status TEXT NOT NULL DEFAULT 'OPEN',
    priority TEXT,
    sla_due_at TIMESTAMPTZ,
    last_synced_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT ticket_link_finding_fk
        FOREIGN KEY (finding_instance_id)
        REFERENCES public.finding_instance(id)
        ON DELETE CASCADE,

    CONSTRAINT ticket_link_system_check
        CHECK (
            system IN ('JIRA','SERVICENOW','HYBRID')
        ),

    CONSTRAINT ticket_link_finding_system_ticket_unique
        UNIQUE (finding_instance_id, system, ticket_key)
);


-- ============================================================
-- Policy Engine Indexes
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_policy_version_active
    ON public.policy_version (is_active, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_priority_decision_tenant_finding
    ON public.priority_decision
    (tenant_id, finding_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_priority_decision_tenant_priority
    ON public.priority_decision
    (tenant_id, operational_priority);

CREATE INDEX IF NOT EXISTS idx_priority_decision_tenant_status
    ON public.priority_decision
    (tenant_id, decision_status);

CREATE INDEX IF NOT EXISTS idx_priority_decision_tenant_sla_due
    ON public.priority_decision
    (tenant_id, sla_due_at);

CREATE INDEX IF NOT EXISTS idx_priority_decision_policy_version
    ON public.priority_decision (policy_version);

CREATE INDEX IF NOT EXISTS idx_human_decision_tenant_finding
    ON public.human_decision
    (tenant_id, finding_instance_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_human_decision_request
    ON public.human_decision (request_id);

CREATE INDEX IF NOT EXISTS idx_exception_record_tenant_status
    ON public.exception_record
    (tenant_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_exception_record_tenant_finding
    ON public.exception_record
    (tenant_id, finding_id);

CREATE INDEX IF NOT EXISTS idx_exception_record_valid_until
    ON public.exception_record (valid_until);

CREATE INDEX IF NOT EXISTS idx_outbox_event_tenant_status_created
    ON public.outbox_event
    (tenant_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_outbox_event_aggregate
    ON public.outbox_event
    (tenant_id, aggregate_id);

CREATE INDEX IF NOT EXISTS idx_ticket_link_tenant_finding
    ON public.ticket_link
    (tenant_id, finding_instance_id);

CREATE INDEX IF NOT EXISTS idx_ticket_link_tenant_status
    ON public.ticket_link
    (tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_ticket_link_sla_due
    ON public.ticket_link (sla_due_at);


-- ============================================================
-- SOHAIL - Audit & Observability
-- ============================================================
-- Append-only trail.
-- Every stage writes here.
-- ============================================================

CREATE TABLE IF NOT EXISTS public.audit_event (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant_id TEXT NOT NULL DEFAULT 'default',

    actor_type TEXT NOT NULL
        CHECK (actor_type IN ('system', 'human', 'llm')),

    actor_id TEXT NOT NULL,

    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,

    policy_version TEXT,
    evidence_ref TEXT,

    before_state JSONB,
    after_state JSONB,

    correlation_id TEXT NOT NULL,
    source_ip TEXT
);


-- ============================================================
-- Audit Indexes
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_audit_entity
    ON public.audit_event (entity_type, entity_id);

CREATE INDEX IF NOT EXISTS idx_audit_correlation
    ON public.audit_event (correlation_id);

CREATE INDEX IF NOT EXISTS idx_audit_occurred_at
    ON public.audit_event (occurred_at);

CREATE INDEX IF NOT EXISTS idx_audit_action
    ON public.audit_event (action);


-- ============================================================
-- Access Control
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT FROM pg_roles
        WHERE rolname = 'vpap_app'
    ) THEN
        CREATE ROLE vpap_app
            LOGIN
            PASSWORD 'change_me_in_real_deployment';
    END IF;
END
$$;


GRANT SELECT, INSERT, UPDATE ON
    public.ingestion_batch,
    public.finding_instance,
    public.dead_letter,
    public.enrichment_run,
    public.finding_evidence,
    public.kev_catalogue,
    public.kev_catalogue_entry,
    public.epss_snapshot,
    public.epss_snapshot_entry,
    public.policy_version,
    public.priority_decision,
    public.human_decision,
    public.exception_record,
    public.outbox_event,
    public.ticket_link
TO vpap_app;


GRANT INSERT, SELECT
ON public.audit_event
TO vpap_app;

REVOKE UPDATE, DELETE
ON public.audit_event
FROM vpap_app;