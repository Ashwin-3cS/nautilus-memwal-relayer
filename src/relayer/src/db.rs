use pgvector::Vector;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::str::FromStr;

use crate::types::{AppError, SearchHit};

pub struct VectorDb {
    pool: PgPool,
}

impl VectorDb {
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Initialize database connection pool and run migrations
    pub async fn new(database_url: &str) -> Result<Self, AppError> {
        // Supabase pooler (PgBouncer, transaction mode) doesn't support
        // named prepared statements — disable the cache to avoid conflicts.
        let connect_opts = PgConnectOptions::from_str(database_url)
            .map_err(|e| AppError::Internal(format!("Invalid DATABASE_URL: {}", e)))?
            .statement_cache_capacity(0);

        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect_with(connect_opts)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to connect to database: {}", e)))?;

        let migration_001 = include_str!("../migrations/001_init.sql");
        sqlx::raw_sql(migration_001).execute(&pool).await
            .map_err(|e| AppError::Internal(format!("Failed to run migration 001: {}", e)))?;

        let migration_002 = include_str!("../migrations/002_add_namespace.sql");
        sqlx::raw_sql(migration_002).execute(&pool).await
            .map_err(|e| AppError::Internal(format!("Failed to run migration 002: {}", e)))?;

        let migration_003 = include_str!("../migrations/003_rate_limiter.sql");
        sqlx::raw_sql(migration_003).execute(&pool).await
            .map_err(|e| AppError::Internal(format!("Failed to run migration 003: {}", e)))?;

        let migration_004 = include_str!("../migrations/004_delegate_key_cache_expires.sql");
        sqlx::raw_sql(migration_004).execute(&pool).await
            .map_err(|e| AppError::Internal(format!("Failed to run migration 004: {}", e)))?;

        let migration_005 = include_str!("../migrations/005_remember_jobs.sql");
        sqlx::raw_sql(migration_005).execute(&pool).await
            .map_err(|e| AppError::Internal(format!("Failed to run migration 005: {}", e)))?;

        let migration_006 = include_str!("../migrations/006_bulk_remember.sql");
        sqlx::raw_sql(migration_006).execute(&pool).await
            .map_err(|e| AppError::Internal(format!("Failed to run migration 006: {}", e)))?;

        let migration_007 = include_str!("../migrations/007_vector_dimensions.sql");
        sqlx::raw_sql(migration_007).execute(&pool).await
            .map_err(|e| AppError::Internal(format!("Failed to run migration 007: {}", e)))?;

        let migration_008 = include_str!("../migrations/008_collapse_wallet_queues.sql");
        sqlx::raw_sql(migration_008).execute(&pool).await
            .map_err(|e| AppError::Internal(format!("Failed to run migration 008: {}", e)))?;

        tracing::info!("database connected and migrations applied");
        Ok(Self { pool })
    }

    // ============================================================
    // Vector Entries
    // ============================================================

    /// Insert a vector entry (idempotent — ON CONFLICT updates existing row)
    pub async fn insert_vector(
        &self,
        id: &str,
        owner: &str,
        namespace: &str,
        blob_id: &str,
        vector: &[f32],
        blob_size_bytes: i64,
    ) -> Result<(), AppError> {
        let embedding = Vector::from(vector.to_vec());

        sqlx::query(
            "INSERT INTO vector_entries (id, owner, namespace, blob_id, embedding, blob_size_bytes)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (id) DO UPDATE SET
                owner = EXCLUDED.owner,
                namespace = EXCLUDED.namespace,
                blob_id = EXCLUDED.blob_id,
                embedding = EXCLUDED.embedding,
                blob_size_bytes = EXCLUDED.blob_size_bytes",
        )
        .bind(id)
        .bind(owner)
        .bind(namespace)
        .bind(blob_id)
        .bind(embedding)
        .bind(blob_size_bytes)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to insert vector: {}", e)))?;

        tracing::debug!("inserted vector: id={}, blob_id={}, owner={}, ns={}, size={}B",
            id, blob_id, owner, namespace, blob_size_bytes);
        Ok(())
    }

    /// Search for similar vectors using pgvector cosine distance (<=>)
    pub async fn search_similar(
        &self,
        query_vector: &[f32],
        owner: &str,
        namespace: &str,
        limit: usize,
    ) -> Result<Vec<SearchHit>, AppError> {
        let embedding = Vector::from(query_vector.to_vec());

        let rows: Vec<(String, f64)> = sqlx::query_as(
            "SELECT blob_id, (embedding <=> $1)::float8 AS distance
             FROM vector_entries
             WHERE owner = $2 AND namespace = $3
             ORDER BY embedding <=> $1
             LIMIT $4",
        )
        .bind(embedding)
        .bind(owner)
        .bind(namespace)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to search vectors: {}", e)))?;

        Ok(rows.into_iter().map(|(blob_id, distance)| SearchHit { blob_id, distance }).collect())
    }

    /// Get all blob_ids for a given owner + namespace (used by restore flow)
    pub async fn get_blobs_by_namespace(
        &self,
        owner: &str,
        namespace: &str,
    ) -> Result<Vec<String>, AppError> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT DISTINCT blob_id FROM vector_entries WHERE owner = $1 AND namespace = $2",
        )
        .bind(owner)
        .bind(namespace)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get blobs by namespace: {}", e)))?;

        Ok(rows.into_iter().map(|(blob_id,)| blob_id).collect())
    }

    #[allow(dead_code)]
    pub async fn delete_by_namespace(&self, owner: &str, namespace: &str) -> Result<u64, AppError> {
        let result = sqlx::query(
            "DELETE FROM vector_entries WHERE owner = $1 AND namespace = $2",
        )
        .bind(owner)
        .bind(namespace)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to delete by namespace: {}", e)))?;

        let rows = result.rows_affected();
        tracing::info!("deleted {} entries for owner={}, ns={}", rows, owner, namespace);
        Ok(rows)
    }

    /// Delete a vector entry by blob_id + owner (LOW-10: owner prevents cross-user deletion)
    pub async fn delete_by_blob_id(&self, blob_id: &str, owner: &str) -> Result<u64, AppError> {
        let result = sqlx::query(
            "DELETE FROM vector_entries WHERE blob_id = $1 AND owner = $2",
        )
        .bind(blob_id)
        .bind(owner)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to delete vector by blob_id: {}", e)))?;

        let rows = result.rows_affected();
        if rows > 0 {
            tracing::info!("deleted expired blob from DB: blob_id={}, owner={}, rows={}", blob_id, owner, rows);
        }
        Ok(rows)
    }

    // ============================================================
    // Delegate Key Cache
    // ============================================================

    pub async fn get_cached_account(
        &self,
        public_key_hex: &str,
    ) -> Result<Option<(String, String)>, AppError> {
        let result: Option<(String, String)> = sqlx::query_as(
            "SELECT account_id, owner FROM delegate_key_cache WHERE public_key = $1 AND expires_at > NOW()",
        )
        .bind(public_key_hex)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to query cache: {}", e)))?;

        Ok(result)
    }

    pub async fn cache_delegate_key(
        &self,
        public_key_hex: &str,
        account_id: &str,
        owner: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO delegate_key_cache (public_key, account_id, owner, expires_at)
             VALUES ($1, $2, $3, NOW() + INTERVAL '24 hours')
             ON CONFLICT (public_key)
             DO UPDATE SET account_id = $2, owner = $3, cached_at = NOW(), expires_at = NOW() + INTERVAL '24 hours'",
        )
        .bind(public_key_hex)
        .bind(account_id)
        .bind(owner)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to cache delegate key: {}", e)))?;

        tracing::debug!("cached delegate key: {} -> account {}", public_key_hex, account_id);
        Ok(())
    }

    /// Immediately remove a single stale/revoked delegate key from cache (LOW-3)
    pub async fn delete_cached_key(&self, public_key_hex: &str) -> Result<u64, AppError> {
        let result = sqlx::query("DELETE FROM delegate_key_cache WHERE public_key = $1")
            .bind(public_key_hex)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to delete stale cached key: {}", e)))?;

        let rows = result.rows_affected();
        if rows > 0 {
            tracing::info!("evicted stale/revoked delegate key from cache: {}", public_key_hex);
        }
        Ok(rows)
    }

    pub async fn evict_expired_delegate_keys(&self) -> Result<u64, AppError> {
        let result = sqlx::query("DELETE FROM delegate_key_cache WHERE expires_at <= NOW()")
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to evict expired delegate keys: {}", e)))?;

        let rows = result.rows_affected();
        if rows > 0 {
            tracing::info!("evicted {} expired delegate keys from cache", rows);
        }
        Ok(rows)
    }

    // ============================================================
    // Remember Jobs
    // ============================================================

    /// Create a pending remember_job row before processing begins
    pub async fn insert_remember_job(
        &self,
        id: &str,
        owner: &str,
        namespace: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO remember_jobs (id, owner, namespace, status)
             VALUES ($1, $2, $3, 'pending')
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .bind(owner)
        .bind(namespace)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to insert remember job: {}", e)))?;

        Ok(())
    }

    /// Mark a remember_job as done with its final blob_id
    pub async fn complete_remember_job(&self, id: &str, blob_id: &str) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE remember_jobs SET status = 'done', blob_id = $2, updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .bind(blob_id)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to complete remember job: {}", e)))?;

        Ok(())
    }

    /// Mark a remember_job as failed with an error message
    pub async fn fail_remember_job(&self, id: &str, msg: &str) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE remember_jobs SET status = 'failed', error_msg = $2, updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .bind(msg)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fail remember job: {}", e)))?;

        Ok(())
    }

    /// Mark orphaned running/uploaded jobs as failed
    pub async fn fail_stale_remember_jobs(
        &self,
        stale_after: std::time::Duration,
    ) -> Result<u64, AppError> {
        let stale_after_secs = stale_after.as_secs().min(i64::MAX as u64) as i64;
        let result = sqlx::query(
            "UPDATE remember_jobs
             SET status = 'failed',
                 error_msg = COALESCE(error_msg, 'stale/orphaned remember job'),
                 updated_at = NOW()
             WHERE status IN ('running', 'uploaded')
               AND updated_at < NOW() - ($1 * INTERVAL '1 second')",
        )
        .bind(stale_after_secs)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fail stale remember jobs: {}", e)))?;

        let rows = result.rows_affected();
        if rows > 0 {
            tracing::warn!("marked {} stale remember jobs as failed", rows);
        }
        Ok(rows)
    }

    // ============================================================
    // Storage Quota
    // ============================================================

    pub async fn get_storage_used(&self, owner: &str) -> Result<i64, AppError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COALESCE(SUM(blob_size_bytes)::BIGINT, 0) FROM vector_entries WHERE owner = $1",
        )
        .bind(owner)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get storage used: {}", e)))?;

        Ok(row.0)
    }

    /// Get storage used within an advisory transaction lock (prevents concurrent quota races)
    pub async fn get_storage_used_with_lock(
        &self,
        owner: &str,
        lock_key: i64,
    ) -> Result<i64, AppError> {
        let mut tx = self.pool.begin().await
            .map_err(|e| AppError::Internal(format!("Failed to begin tx: {}", e)))?;

        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to acquire advisory lock: {}", e)))?;

        let row: (i64,) = sqlx::query_as(
            "SELECT COALESCE(SUM(blob_size_bytes)::BIGINT, 0) FROM vector_entries WHERE owner = $1",
        )
        .bind(owner)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get storage used: {}", e)))?;

        tx.commit().await
            .map_err(|e| AppError::Internal(format!("Failed to commit tx: {}", e)))?;

        Ok(row.0)
    }

    // ============================================================
    // Accounts (populated by v2-indexer)
    // ============================================================

    #[allow(dead_code)]
    pub async fn find_account_by_owner(&self, owner: &str) -> Result<Option<String>, AppError> {
        let result: Option<(String,)> = sqlx::query_as(
            "SELECT account_id FROM accounts WHERE owner = $1",
        )
        .bind(owner)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to query accounts: {}", e)))?;

        Ok(result.map(|(id,)| id))
    }
}
