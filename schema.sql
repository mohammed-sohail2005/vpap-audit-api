-- ============================================================
-- VPAP 4.1 - Full schema
-- Combines: audit_event (Sohail), ingestion (Muizz),
-- enrichment (Anafa), policy engine (Vignesh)
-- Run this once against your Postgres/Supabase database.
-- ============================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- needed for gen_random_uuid()
    

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
        CHECK (status IN ('RECEIVED','PROCESSING','COMPLETED','PARTIAL','FAILED')),
    CONSTRAINT ingestion_batch_counts_check
        CHECK (total_records >= 0 AND accepted_records >= 0
               AND rejected_records >= 0 AND validation_failed_records >= 0),
    CONSTRAINT ingestion_batch_source_system_check
        CHECK (source_system = UPPER(source_system))
);

-- 2. FINDING INSTANCE (canonical entity referenced by every downstream stage)
CREATE TABLE IF NOT EXISTS public.finding_instance (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    batch_id UUID,
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
        CHECK (cvss_base IS NULL OR (cvss_base >= 0 AND cvss_base <= 10)),
    CONSTRAINT finding_instance_source_system_check
        CHECK (source_system = UPPER(source_system))
    CONSTRAINT finding_instance_batch_fk
        FOREIGN KEY (batch_id)
        REFERENCES public.ingestion_batch(id)
        ON DELETE SET NULL,
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
        FOREIGN KEY (batch_id) REFERENCES public.ingestion_batch(id) ON DELETE SET NULL,
    CONSTRAINT dead_letter_stage_check
        CHECK (stage IN ('INGESTION', 'VALIDATION')),
    CONSTRAINT dead_letter_status_check
        CHECK (status IN ('OPEN','REPROCESSED','RESOLVED','IGNORED')),
    CONSTRAINT dead_letter_retry_count_check
        CHECK (retry_count >= 0),
    CONSTRAINT dead_letter_source_system_check
        CHECK (source_system = UPPER(source_system))
);

CREATE INDEX IF NOT EXISTS idx_ingestion_batch_tenant_created ON public.ingestion_batch (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ingestion_batch_tenant_status ON public.ingestion_batch (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_finding_instance_batch ON public.finding_instance (batch_id);
CREATE INDEX IF NOT EXISTS idx_finding_instance_tenant_cve ON public.finding_instance (tenant_id, cve_id);
CREATE INDEX IF NOT EXISTS idx_finding_instance_tenant_asset ON public.finding_instance (tenant_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_finding_instance_tenant_status ON public.finding_instance (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_finding_instance_tenant_last_seen ON public.finding_instance (tenant_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_dead_letter_tenant_status_created ON public.dead_letter (tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dead_letter_batch ON public.dead_letter (batch_id);
CREATE INDEX IF NOT EXISTS idx_dead_letter_tenant_source_finding ON public.dead_letter (tenant_id, source_finding_id);


-- ============================================================
-- ANAFA - Enrichment
-- ============================================================

CREATE TABLE IF NOT EXISTS enrichment_run (
    enrichment_run_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            text NOT NULL DEFAULT 'default',
    source_system        text NOT NULL,
    source_instance_id   text,
    adapter_name         text NOT NULL,
    adapter_version      text NOT NULL,
    schema_version       text NOT NULL,
    started_at           timestamptz,
    completed_at         timestamptz,
    status                text NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS finding_evidence (
    evidence_snapshot_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_instance_id      uuid NOT NULL REFERENCES public.finding_instance(id),
    source_finding_id        text NOT NULL,
    tenant_id                 text NOT NULL DEFAULT 'default',
    source_system             text NOT NULL,
    source_instance_id        text,
    enrichment_run_id         uuid NOT NULL REFERENCES enrichment_run(enrichment_run_id),
    schema_version             text NOT NULL,
    adapter_name               text NOT NULL,
    adapter_version            text NOT NULL,
    evidence_snapshot_sha256   text NOT NULL,

    cve_id                     text NOT NULL,
    asset_id                   text NOT NULL,
    cvss_base                  numeric(3,1),

    epss_probability           jsonb NOT NULL,
    epss_percentile            jsonb NOT NULL,
    kev_status                 jsonb NOT NULL,
    internet_exposure          jsonb NOT NULL,
    runtime_applicability      jsonb NOT NULL,
    attack_path_reachable      jsonb NOT NULL,
    business_criticality       jsonb NOT NULL,
    compensating_controls      jsonb NOT NULL,

    created_at                 timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding ON finding_evidence (finding_instance_id);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_run     ON finding_evidence (enrichment_run_id);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_cve     ON finding_evidence (cve_id);

CREATE TABLE IF NOT EXISTS kev_catalogue (
    catalogue_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    source_timestamp     timestamptz,
    retrieved_at          timestamptz NOT NULL DEFAULT now(),
    catalogue_sha256      text NOT NULL,
    record_count          integer NOT NULL,
    status                 text NOT NULL,
    created_at             timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS kev_catalogue_entry (
    catalogue_entry_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    catalogue_id          uuid NOT NULL REFERENCES kev_catalogue(catalogue_id),
    cve_id                 text NOT NULL,
    created_at              timestamptz NOT NULL DEFAULT now(),
    UNIQUE (catalogue_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_kev_catalogue_entry_cve ON kev_catalogue_entry (cve_id);

-- One row per EPSS bulk download/snapshot (persistent, cached EPSS data
-- so enrichment can reuse values instead of querying EPSS per finding)
CREATE TABLE IF NOT EXISTS epss_snapshot (
    snapshot_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    source_timestamp  timestamptz,
    retrieved_at       timestamptz NOT NULL DEFAULT now(),
    record_count       integer NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now()
);

-- One row per CVE's EPSS score within a given snapshot
CREATE TABLE IF NOT EXISTS epss_snapshot_entry (
    entry_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id       uuid NOT NULL REFERENCES epss_snapshot(snapshot_id),
    cve_id             text NOT NULL,
    epss_probability   numeric(7,5) NOT NULL,
    epss_percentile    numeric(7,5) NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (snapshot_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_epss_snapshot_entry_cve ON epss_snapshot_entry (cve_id);
CREATE INDEX IF NOT EXISTS idx_epss_snapshot_retrieved_at ON epss_snapshot (retrieved_at DESC);


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
        CHECK (conservative_floor_default IN ('P0','P1','P2','P3','REVIEW')),
    CONSTRAINT policy_version_digest_check
        CHECK (char_length(artifact_digest) = 64)
);

-- 2. PRIORITY DECISION
-- NOTE: evidence_snapshot_id FK corrected to point at Anafa's real
-- finding_evidence table (not a placeholder evidence_snapshot table).
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
        FOREIGN KEY (finding_id) REFERENCES public.finding_instance(id) ON DELETE CASCADE,

    -- FIXED: was public.evidence_snapshot(id) (placeholder, never existed).
    -- Now correctly points at Anafa's confirmed finding_evidence table.
    CONSTRAINT priority_decision_evidence_fk
        FOREIGN KEY (evidence_snapshot_id) REFERENCES public.finding_evidence(evidence_snapshot_id) ON DELETE CASCADE,

    CONSTRAINT priority_decision_policy_fk
        FOREIGN KEY (policy_version) REFERENCES public.policy_version(version_id),
    CONSTRAINT priority_decision_vps_check
        CHECK (vps IS NULL OR (vps >= 0 AND vps <= 100)),
    CONSTRAINT priority_decision_priority_check
        CHECK (operational_priority IN ('P0','P1','P2','P3','REVIEW')),
    CONSTRAINT priority_decision_floor_check
        CHECK (conservative_floor IS NULL OR conservative_floor IN ('P0','P1','P2','P3','REVIEW')),
    CONSTRAINT priority_decision_ssvc_outcome_check
        CHECK (ssvc_outcome IS NULL OR ssvc_outcome IN ('TRACK','TRACK*','ATTEND','ACT')),
    CONSTRAINT priority_decision_confidence_check
        CHECK (confidence IN ('HIGH','MEDIUM','LOW')),
    CONSTRAINT priority_decision_status_check
        CHECK (decision_status IN ('FINAL','PROVISIONAL','NEEDS_REVIEW','QUARANTINED')),
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
        FOREIGN KEY (finding_instance_id) REFERENCES public.finding_instance(id) ON DELETE CASCADE,
    CONSTRAINT human_decision_original_priority_check
        CHECK (original_priority IN ('P0','P1','P2','P3','REVIEW')),
    CONSTRAINT human_decision_proposed_priority_check
        CHECK (proposed_priority IN ('P0','P1','P2','P3','REVIEW')),
    CONSTRAINT human_decision_actor_role_check
        CHECK (actor_role IN ('ANALYST','VULN_LEAD','RISK_OWNER','CISO_DELEGATE','AUDITOR'))
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
        FOREIGN KEY (finding_id) REFERENCES public.finding_instance(id) ON DELETE CASCADE,
    CONSTRAINT exception_record_status_check
        CHECK (status IN ('PENDING','APPROVED','REJECTED','EXPIRED','REVOKED')),
    CONSTRAINT exception_record_risk_level_check
        CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL'))
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
        CHECK (status IN ('PENDING','DELIVERED','FAILED','DEAD_LETTER')),
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
        FOREIGN KEY (finding_instance_id) REFERENCES public.finding_instance(id) ON DELETE CASCADE,
    CONSTRAINT ticket_link_system_check
        CHECK (system IN ('JIRA','SERVICENOW','HYBRID')),
    CONSTRAINT ticket_link_finding_system_ticket_unique
        UNIQUE (finding_instance_id, system, ticket_key)
);

CREATE INDEX IF NOT EXISTS idx_policy_version_active ON public.policy_version (is_active, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_priority_decision_tenant_finding ON public.priority_decision (tenant_id, finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_priority_decision_tenant_priority ON public.priority_decision (tenant_id, operational_priority);
CREATE INDEX IF NOT EXISTS idx_priority_decision_tenant_status ON public.priority_decision (tenant_id, decision_status);
CREATE INDEX IF NOT EXISTS idx_priority_decision_tenant_sla_due ON public.priority_decision (tenant_id, sla_due_at);
CREATE INDEX IF NOT EXISTS idx_priority_decision_policy_version ON public.priority_decision (policy_version);
CREATE INDEX IF NOT EXISTS idx_human_decision_tenant_finding ON public.human_decision (tenant_id, finding_instance_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_human_decision_request ON public.human_decision (request_id);
CREATE INDEX IF NOT EXISTS idx_exception_record_tenant_status ON public.exception_record (tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_exception_record_tenant_finding ON public.exception_record (tenant_id, finding_id);
CREATE INDEX IF NOT EXISTS idx_exception_record_valid_until ON public.exception_record (valid_until);
CREATE INDEX IF NOT EXISTS idx_outbox_event_tenant_status_created ON public.outbox_event (tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_outbox_event_aggregate ON public.outbox_event (tenant_id, aggregate_id);
CREATE INDEX IF NOT EXISTS idx_ticket_link_tenant_finding ON public.ticket_link (tenant_id, finding_instance_id);
CREATE INDEX IF NOT EXISTS idx_ticket_link_tenant_status ON public.ticket_link (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_ticket_link_sla_due ON public.ticket_link (tenant_id, sla_due_at);


-- ============================================================
-- SOHAIL - Audit & Observability
-- Append-only trail. Never updated or deleted - enforced via
-- GRANT/REVOKE below. Cross-cutting: every stage writes here.
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_event (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    tenant_id       text NOT NULL DEFAULT 'default',

    actor_type      text NOT NULL CHECK (actor_type IN ('system', 'human', 'llm')),
    actor_id        text NOT NULL,

    action          text NOT NULL,
    entity_type     text NOT NULL,
    entity_id       text NOT NULL,

    policy_version  text,
    evidence_ref    text,

    before_state    jsonb,
    after_state     jsonb,

    correlation_id  text NOT NULL,
    source_ip       text
);

CREATE INDEX IF NOT EXISTS idx_audit_entity      ON audit_event (entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_correlation ON audit_event (correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_occurred_at ON audit_event (occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_action      ON audit_event (action);


-- ============================================================
-- Access control
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vpap_app') THEN
        CREATE ROLE vpap_app LOGIN PASSWORD 'change_me_in_real_deployment';
    END IF;
END
$$;

GRANT SELECT, INSERT, UPDATE ON
    public.ingestion_batch, public.finding_instance, public.dead_letter,
    enrichment_run, finding_evidence, kev_catalogue, kev_catalogue_entry,
    epss_snapshot, epss_snapshot_entry,
    public.policy_version, public.priority_decision, public.human_decision,
    public.exception_record, public.outbox_event, public.ticket_link
    TO vpap_app;

GRANT INSERT, SELECT ON audit_event TO vpap_app;
REVOKE UPDATE, DELETE ON audit_event FROM vpap_app;
