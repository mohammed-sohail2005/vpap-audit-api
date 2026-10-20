-- ============================================================
-- VPAP 4.1 - Migration 0002
-- Add finding_instance.batch_id
-- ============================================================
--
-- This migration adds:
--
--   1. finding_instance.batch_id
--   2. Foreign key:
--        finding_instance.batch_id
--        -> ingestion_batch.id
--   3. Index for batch-based finding queries
--
-- Migration 0001 intentionally does NOT contain these changes.
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