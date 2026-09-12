CREATE TABLE public.finding_instance (
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
        CHECK (cvss_base IS NULL OR (cvss_base >= 0 AND cvss_base <= 10)),

    CONSTRAINT finding_instance_source_system_check
        CHECK (source_system = UPPER(source_system))
);