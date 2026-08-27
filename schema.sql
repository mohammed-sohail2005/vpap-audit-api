-- VPAP 4.1 audit_event schema
-- Run this once against your Postgres database to set up the table.

CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- needed for gen_random_uuid()

CREATE TABLE IF NOT EXISTS audit_event (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    tenant_id       text NOT NULL DEFAULT 'default',

    actor_type      text NOT NULL CHECK (actor_type IN ('system', 'human', 'llm')),
    actor_id        text NOT NULL,

    action          text NOT NULL,
    entity_type     text NOT NULL,
    entity_id       text NOT NULL,       -- text, not uuid, since finding IDs are strings like 'finding-8f31a2'

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

-- Create a restricted role for the application to use.
-- Everyone's services (ingestion, enrichment, policy engine) should connect as this role.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vpap_app') THEN
        CREATE ROLE vpap_app LOGIN PASSWORD 'change_me_in_real_deployment';
    END IF;
END
$$;

GRANT INSERT, SELECT ON audit_event TO vpap_app;
REVOKE UPDATE, DELETE ON audit_event FROM vpap_app;
-- This is the actual technical enforcement of "append-only": the app's own
-- DB credentials physically cannot modify or delete a row, no matter what
-- the application code tries to do.