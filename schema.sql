-- VPAP 4.1 schema - aligned with Detailed Design & Build Guide data model
-- (finding_instance, evidence_snapshot, priority_decision, audit_event)
-- Run this once against your Postgres/Supabase database.

CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- needed for gen_random_uuid()

-- ============================================================
-- finding_instance: one row per unique (source, finding, asset,
-- package) - matches Finding.idempotency_key() from the domain
-- model in the Build Guide (section 5).
-- ============================================================
CREATE TABLE IF NOT EXISTS finding_instance (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           text NOT NULL DEFAULT 'default',
    idempotency_key     text NOT NULL,
    source_system       text NOT NULL,
    source_finding_id   text NOT NULL,
    cve_id              text NOT NULL,
    asset_id            text NOT NULL,
    package_id          text,

    cvss_base           numeric(3,1),
    cvss_vector         text,
    description         text,
    business_service_id text,
    internet_exposed    boolean,
    first_detected_at   timestamptz,

    status              text NOT NULL DEFAULT 'VALID',
    first_seen_at       timestamptz,
    last_seen_at        timestamptz NOT NULL DEFAULT now(),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT finding_instance_tenant_idempotency_unique
        UNIQUE (tenant_id, idempotency_key),

    CONSTRAINT finding_instance_cvss_check
        CHECK (cvss_base IS NULL OR (cvss_base >= 0 AND cvss_base <= 10)),

    CONSTRAINT finding_instance_source_system_check
        CHECK (source_system = UPPER(source_system))
);

CREATE INDEX IF NOT EXISTS idx_finding_instance_cve   ON finding_instance (cve_id);
CREATE INDEX IF NOT EXISTS idx_finding_instance_asset ON finding_instance (asset_id);


CREATE TABLE IF NOT EXISTS ingestion_batch (
    id                         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                  text NOT NULL,
    source_system              text NOT NULL,
    source_type                text NOT NULL,
    source_reference           text,
    source_file_name           text,

    received_at                timestamptz NOT NULL DEFAULT now(),
    processing_started_at      timestamptz,
    processing_completed_at   timestamptz,

    total_records              integer NOT NULL DEFAULT 0,
    accepted_records           integer NOT NULL DEFAULT 0,
    rejected_records           integer NOT NULL DEFAULT 0,
    validation_failed_records  integer NOT NULL DEFAULT 0,

    status                     text NOT NULL DEFAULT 'RECEIVED',
    error_message              text,
    created_at                 timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT ingestion_batch_source_type_check
        CHECK (source_type IN ('FILE', 'API', 'STREAM')),

    CONSTRAINT ingestion_batch_status_check
        CHECK (status IN (
            'RECEIVED',
            'PROCESSING',
            'COMPLETED',
            'PARTIAL',
            'FAILED'
        )),

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


CREATE TABLE IF NOT EXISTS dead_letter (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           text NOT NULL,
    source_system       text NOT NULL,
    batch_id            uuid,

    source_finding_id   text,
    stage               text NOT NULL,
    error_code          text NOT NULL,
    error_message       text NOT NULL,
    raw_record          jsonb,

    status              text NOT NULL DEFAULT 'OPEN',
    retry_count         integer NOT NULL DEFAULT 0,

    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    resolved_at         timestamptz,

    CONSTRAINT dead_letter_batch_fk
        FOREIGN KEY (batch_id)
        REFERENCES ingestion_batch(id)
        ON DELETE SET NULL,

    CONSTRAINT dead_letter_stage_check
        CHECK (stage IN ('INGESTION', 'VALIDATION')),

    CONSTRAINT dead_letter_status_check
        CHECK (status IN (
            'OPEN',
            'REPROCESSED',
            'RESOLVED',
            'IGNORED'
        )),

    CONSTRAINT dead_letter_retry_count_check
        CHECK (retry_count >= 0),

    CONSTRAINT dead_letter_source_system_check
        CHECK (source_system = UPPER(source_system))
);

-- ============================================================
-- evidence_snapshot: enrichment results (EPSS, KEV, exposure,
-- attack path, business context, etc.) - one row per source per
-- finding, each with a tri-state status (never silently "safe").
-- ============================================================
CREATE TABLE IF NOT EXISTS evidence_snapshot (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id          uuid NOT NULL REFERENCES finding_instance(id),
    source_name         text NOT NULL,          -- e.g. 'FIRST_EPSS', 'CISA_KEV', 'CMDB'
    source_snapshot_at  timestamptz,
    retrieved_at        timestamptz NOT NULL DEFAULT now(),
    status              text NOT NULL CHECK (status IN ('KNOWN','UNKNOWN','STALE','ERROR')),
    payload             jsonb NOT NULL,
    payload_sha256      text NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_snapshot_finding ON evidence_snapshot (finding_id);

-- ============================================================
-- priority_decision: the deterministic scoring engine's output.
-- Versioned, never mutated - an override creates a NEW row
-- referencing the same finding_id, per the design's "human review
-- must not erase the original decision" rule.
-- ============================================================
CREATE TABLE IF NOT EXISTS priority_decision (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id             uuid NOT NULL REFERENCES finding_instance(id),
    evidence_snapshot_id   uuid REFERENCES evidence_snapshot(id),
    policy_version         text NOT NULL,
    mandatory_remediation  boolean NOT NULL DEFAULT false,
    vps                    numeric(5,2),
    operational_priority   text NOT NULL CHECK (operational_priority IN ('P0','P1','P2','P3','REVIEW')),
    confidence             text NOT NULL,
    decision_status        text NOT NULL,       -- 'FINAL' | 'NEEDS_REVIEW'
    rules_applied          jsonb NOT NULL,
    evidence_refs          jsonb NOT NULL,
    created_at             timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_priority_decision_finding ON priority_decision (finding_id);

-- ============================================================
-- human_decision: review/approval actions taken by a person on a
-- priority_decision. Never overwrites priority_decision - both
-- coexist so the full history is auditable.
-- ============================================================
CREATE TABLE IF NOT EXISTS human_decision (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    priority_decision_id  uuid NOT NULL REFERENCES priority_decision(id),
    actor_id              text NOT NULL,          -- the human reviewer
    decision              text NOT NULL,          -- e.g. 'APPROVED','OVERRIDDEN','REJECTED'
    reason                text,
    created_at            timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_human_decision_priority ON human_decision (priority_decision_id);

-- ============================================================
-- exception_record: risk acceptance / false-positive / deferment,
-- with a revalidation date so exceptions don't silently live forever.
-- ============================================================
CREATE TABLE IF NOT EXISTS exception_record (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id          uuid NOT NULL REFERENCES finding_instance(id),
    actor_id            text NOT NULL,
    reason              text NOT NULL,
    exception_type      text NOT NULL,          -- 'RISK_ACCEPTED' | 'FALSE_POSITIVE' | 'DEFERRED'
    revalidate_at       timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_exception_record_finding ON exception_record (finding_id);

-- ============================================================
-- audit_event: append-only trail of every security/operational
-- event. Never updated or deleted - enforced via GRANT/REVOKE below.
-- This is intentionally separate from finding_instance/evidence_snapshot/
-- priority_decision: audit_event answers "who did what, when, why";
-- the other tables hold the evolving vulnerability data itself.
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_event (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    tenant_id       text NOT NULL DEFAULT 'default',

    actor_type      text NOT NULL CHECK (actor_type IN ('system', 'human', 'llm')),
    actor_id        text NOT NULL,

    action          text NOT NULL,
    entity_type     text NOT NULL,      -- 'finding_instance' | 'priority_decision' | 'human_decision' | 'exception_record' | 'ticket_link'
    entity_id       text NOT NULL,

    policy_version  text,
    evidence_ref    text,

    before_state    jsonb,
    after_state     jsonb,

    correlation_id  text NOT NULL,      -- = finding_instance.id (as text), ties every event for one finding together
    source_ip       text
);

CREATE INDEX IF NOT EXISTS idx_audit_entity      ON audit_event (entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_correlation ON audit_event (correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_occurred_at ON audit_event (occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_action      ON audit_event (action);

-- ============================================================
-- ENRICHMENT TABLES (Anafa) - exact spec from her PR/design
-- ============================================================

-- One row per enrichment batch run
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
    status                text NOT NULL,      -- e.g. 'RUNNING' | 'COMPLETED' | 'FAILED'
    created_at            timestamptz NOT NULL DEFAULT now()
);

-- One row per enriched finding. Each *_JSON column stores a full
-- EvidenceValue object: {value, raw_value, mapping_version, status,
-- reason_code, source, source_field, source_timestamp, retrieved_at,
-- confidence} - never just a bare value, so UNKNOWN/STALE/ERROR and
-- provenance are never lost.
CREATE TABLE IF NOT EXISTS finding_evidence (
    evidence_snapshot_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_instance_id      text NOT NULL,   -- plain text for now, not a FK - finding_instance
                                                -- table doesn't exist yet (pending Muizz's schema).
                                                -- Change to `uuid REFERENCES finding_instance(id)`
                                                -- once his ingestion tables are confirmed and built.
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

    epss_probability           jsonb NOT NULL,   -- EvidenceValue[float]
    epss_percentile            jsonb NOT NULL,   -- EvidenceValue[float]
    kev_status                 jsonb NOT NULL,   -- EvidenceValue[bool]
    internet_exposure          jsonb NOT NULL,   -- EvidenceValue[bool]
    runtime_applicability      jsonb NOT NULL,   -- EvidenceValue[bool]
    attack_path_reachable      jsonb NOT NULL,   -- EvidenceValue[bool]
    business_criticality       jsonb NOT NULL,   -- EvidenceValue[str]
    compensating_controls      jsonb NOT NULL,   -- EvidenceValue[list[CompensatingControl]]

    created_at                 timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding ON finding_evidence (finding_instance_id);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_run     ON finding_evidence (enrichment_run_id);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_cve     ON finding_evidence (cve_id);

-- One row per downloaded KEV catalogue snapshot
CREATE TABLE IF NOT EXISTS kev_catalogue (
    catalogue_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    source_timestamp     timestamptz,
    retrieved_at          timestamptz NOT NULL DEFAULT now(),
    catalogue_sha256      text NOT NULL,
    record_count          integer NOT NULL,
    status                 text NOT NULL,     -- e.g. 'OK' | 'STALE' | 'MALFORMED' | 'DOWNLOAD_FAILED'
    created_at             timestamptz NOT NULL DEFAULT now()
);

-- One row per CVE listed in a given KEV catalogue snapshot
CREATE TABLE IF NOT EXISTS kev_catalogue_entry (
    catalogue_entry_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    catalogue_id          uuid NOT NULL REFERENCES kev_catalogue(catalogue_id),
    cve_id                 text NOT NULL,
    created_at              timestamptz NOT NULL DEFAULT now(),
    UNIQUE (catalogue_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_kev_catalogue_entry_cve ON kev_catalogue_entry (cve_id);

GRANT SELECT, INSERT, UPDATE ON enrichment_run, finding_evidence, kev_catalogue, kev_catalogue_entry TO vpap_app;
-- ============================================================
-- Access control: one restricted role for the application.
-- audit_event is INSERT/SELECT only (append-only, enforced at the
-- DB level). Other tables allow UPDATE where the design calls for
-- it (e.g. finding_instance.last_seen_at, finding_instance.status).
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vpap_app') THEN
        CREATE ROLE vpap_app LOGIN PASSWORD 'change_me_in_real_deployment';
    END IF;
END
$$;

GRANT SELECT, INSERT, UPDATE ON finding_instance, evidence_snapshot, priority_decision, human_decision, exception_record TO vpap_app;
GRANT INSERT, SELECT ON audit_event TO vpap_app;
REVOKE UPDATE, DELETE ON audit_event FROM vpap_app;
