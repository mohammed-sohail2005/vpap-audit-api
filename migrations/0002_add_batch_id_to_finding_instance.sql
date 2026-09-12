-- Migration 0002: add finding_instance.batch_id
-- ============================================================
-- Links each finding back to the ingestion_batch that produced it.
--
-- This migration adds:
--   1. batch_id column
--   2. Foreign key from finding_instance.batch_id
--      to ingestion_batch.id
--   3. Index for efficient batch-based queries
-- ============================================================

ALTER TABLE public.finding_instance
ADD COLUMN IF NOT EXISTS batch_id UUID;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'fk_finding_instance_batch'
    ) THEN
        ALTER TABLE public.finding_instance
        ADD CONSTRAINT fk_finding_instance_batch
        FOREIGN KEY (batch_id)
        REFERENCES public.ingestion_batch(id)
        ON DELETE SET NULL;
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_finding_instance_batch
ON public.finding_instance(batch_id);