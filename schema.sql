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
    status              text NOT NULL DEFAULT 'NEW',
    first_seen_at       timestamptz,
    last_seen_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_finding_instance_cve   ON finding_instance (cve_id);
CREATE INDEX IF NOT EXISTS idx_finding_instance_asset ON finding_instance (asset_id);

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