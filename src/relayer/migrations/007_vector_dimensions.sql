-- Migration 007: Resize embedding column to vector(1024) if needed.
-- For pgvector, atttypmod equals the dimension directly (no +4 offset like varchar).
-- Idempotent: only alters if current dimension != 1024.
-- DESTRUCTIVE: truncates vector_entries (dimension change is a breaking schema change).

DO $$
DECLARE
  actual_dim integer;
BEGIN
  SELECT atttypmod INTO actual_dim
  FROM pg_attribute a
  JOIN pg_class c ON a.attrelid = c.oid
  WHERE c.relname = 'vector_entries' AND a.attname = 'embedding' AND a.attnum > 0;

  IF actual_dim IS NOT NULL AND actual_dim != 1024 THEN
    DELETE FROM vector_entries;
    DROP INDEX IF EXISTS idx_vector_entries_embedding;
    ALTER TABLE vector_entries DROP COLUMN embedding;
    ALTER TABLE vector_entries ADD COLUMN embedding vector(1024) NOT NULL;
    CREATE INDEX idx_vector_entries_embedding ON vector_entries USING hnsw (embedding vector_cosine_ops);
  END IF;
END $$;
