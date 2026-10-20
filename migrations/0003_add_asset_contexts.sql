-- ============================================================
-- VPAP 4.1 - Migration 0003: Add asset_contexts table for ACS
-- Asset Context Source (ACS) persistence support
-- ============================================================

CREATE TABLE IF NOT EXISTS public.asset_contexts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL,
    idempotency_key VARCHAR(64) NOT NULL,
    source_system TEXT NOT NULL DEFAULT 'ACS',
    asset_id TEXT NOT NULL,
    hostname TEXT,
    ip_address TEXT,
    asset_type TEXT,
    platform_os TEXT,
    environment TEXT,
    business_unit TEXT,
    business_criticality TEXT,
    owner_team TEXT,
    internet_exposed BOOLEAN,
    location_zone TEXT,
    software_inventory JSONB NOT NULL DEFAULT '[]'::jsonb,
    lifecycle_state TEXT,
    data_classification TEXT,
    status TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT asset_contexts_tenant_idempotency_unique
        UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_asset_contexts_tenant_asset
    ON public.asset_contexts (tenant_id, asset_id);

GRANT SELECT, INSERT, UPDATE ON public.asset_contexts TO vpap_app;

-- ============================================================
-- Ensure audit_event accepts 'asset_context' as an entity_type
-- if the audit_event_entity_type_check constraint exists.
-- ============================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'audit_event_entity_type_check'
    ) THEN
        ALTER TABLE public.audit_event
        DROP CONSTRAINT audit_event_entity_type_check;

        ALTER TABLE public.audit_event
        ADD CONSTRAINT audit_event_entity_type_check CHECK (
            entity_type = ANY (ARRAY[
                'ingestion_batch'::text,
                'finding_instance'::text,
                'dead_letter'::text,
                'asset_context'::text,
                'enrichment_run'::text,
                'finding_evidence'::text,
                'kev_catalogue'::text,
                'kev_catalogue_entry'::text,
                'policy_version'::text,
                'priority_decision'::text,
                'human_decision'::text,
                'exception_record'::text,
                'outbox_event'::text,
                'ticket_link'::text
            ])
        );
    END IF;
END
$$;

