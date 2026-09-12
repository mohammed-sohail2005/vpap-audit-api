-- Migration 0002: add finding_instance.batch_id
-- ============================================================
-- Links each finding back to the ingestion_batch that produced it.
-- Requested by Hidayat during PR #12 review, so a finding's batch
-- of origin is traceable via a real, enforced foreign key - not
-- just implied by timestamps.
--
-- IMPORTANT: this column/FK/index ALREADY EXIST in the live
-- production Supabase database (added manually before this
-- migration system existed). Running this file against THAT
-- database will fail with "column already exists" - that's
-- expected and safe to ignore there.
--
-- The real purpose of this file is for FRESH databases (CI test
-- runs, a new teammate's local setup, disaster recovery) to be
-- able to reach the exact same state through code, not tribal
-- knowledge of what was manually typed into Supabase once.
-- ============================================================

ALTER TABLE finding_instance
ADD COLUMN IF NOT EXISTS batch_id UUID;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_finding_instance_batch'
    ) THEN
        ALTER TABLE finding_instance
        ADD CONSTRAINT fk_finding_instance_batch
        FOREIGN KEY (batch_id) REFERENCES ingestion_batch(id);
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_finding_instance_batch
ON finding_instance(batch_id);