mod auth;
mod db;
mod enclave;
mod jobs;
mod rate_limit;
mod routes;
mod seal;
mod sui;
mod types;
mod walrus;

use axum::{middleware, routing::{get, post}, Router};
use nautilus_enclave::EnclaveKeyPair;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use apalis::prelude::*;
use apalis_sql::postgres::PostgresStorage;

use db::VectorDb;
use enclave::{enclave_health, get_attestation, get_logs, LogBuffer};
use jobs::{
    execute_bulk_remember, execute_wallet_job, BulkRememberJob, MetaTransferJob, RememberJob,
    WalletJobStorage,
};
use types::{
    AppState, Config, KeyPool, DEFAULT_BLOB_CACHE_MAX_BYTES, DEFAULT_BLOB_CACHE_TTL_SECS,
    DEFAULT_EMBEDDING_CACHE_TTL_SECS,
};

const APALIS_MONITOR_RESTART_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

#[tokio::main]
async fn main() {
    // Load .env file (optional, won't error if missing)
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "memwal_server=info,tower_http=info".into()),
        )
        .init();

    // Load config
    let config = Config::from_env();
    tracing::info!("starting memwal server on port {}", config.port);
    tracing::info!("  Sui RPC: {}", config.sui_rpc_url);
    tracing::info!("  package id: {}", config.package_id);
    tracing::info!("  registry id: {}", config.registry_id);
    tracing::info!("  memwal account: {}", config.memwal_account_id.as_deref().unwrap_or("(from client header)"));
    tracing::info!("  rate limit: burst={}/min, sustained={}/hr, per-key={}/min, quota={}MB/user",
        config.rate_limit.max_requests_per_minute,
        config.rate_limit.max_requests_per_hour,
        config.rate_limit.max_requests_per_delegate_key,
        config.rate_limit.max_storage_bytes / 1_048_576
    );
    let emb_base = config.embedding_api_base.as_deref().unwrap_or(&config.openai_api_base);
    tracing::info!("  embedding model: {} @ {}", config.embedding_model, emb_base);
    if let Some(dim) = config.embedding_dimensions {
        tracing::info!("  embedding dimensions: {}", dim);
    }
    tracing::info!("  llm model: {}", config.llm_model);

    // Start TS sidecar HTTP server (SEAL + Walrus operations)
    let sidecar_url = config.sidecar_url.clone();
    tracing::info!("  sidecar: starting at {}", sidecar_url);
    // Use SIDECAR_SCRIPTS_DIR if set (Docker), otherwise derive from CARGO_MANIFEST_DIR (local dev)
    let scripts_dir = std::env::var("SIDECAR_SCRIPTS_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts"));
    // In enclave mode, node is at a fixed path and tsx is pre-installed in node_modules.
    // In local dev mode, use npx tsx as usual.
    let enclave_mode = std::env::var("ENCLAVE_MODE").map(|v| v == "true").unwrap_or(false);
    let mut sidecar_cmd = if enclave_mode {
        let tsx = scripts_dir.join("node_modules").join(".bin").join("tsx");
        let sidecar = scripts_dir.join("sidecar-server.ts");
        let mut cmd = tokio::process::Command::new("/usr/local/bin/node");
        cmd.args([tsx.as_os_str(), sidecar.as_os_str()]);
        cmd
    } else {
        let mut cmd = tokio::process::Command::new("npx");
        cmd.args(["tsx", "sidecar-server.ts"]);
        cmd
    };
    let mut sidecar_child = sidecar_cmd
        .current_dir(&scripts_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("Failed to start TS sidecar. Is Node.js installed?");

    // Wait for sidecar to be ready (health check with retry)
    let http_client = reqwest::Client::new();
    let health_url = format!("{}/health", sidecar_url);
    let mut ready = false;
    for attempt in 1..=30 {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        match http_client.get(&health_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!("  sidecar: ready (attempt {})", attempt);
                ready = true;
                break;
            }
            _ => {
                if attempt % 5 == 0 {
                    tracing::debug!("  sidecar: waiting... (attempt {})", attempt);
                }
            }
        }
    }
    if !ready {
        sidecar_child.kill().await.ok();
        panic!("TS sidecar failed to start after 15s. Check scripts/sidecar-server.ts");
    }

    // Initialize database (PostgreSQL + pgvector)
    let db = VectorDb::new(&config.database_url)
        .await
        .expect("Failed to connect to PostgreSQL");

    // Warn if the DB vector column dimension doesn't match EMBEDDING_DIMENSIONS
    if let Some(expected_dim) = config.embedding_dimensions {
        let dim_check: Result<Option<i32>, _> = sqlx::query_scalar(
            "SELECT atttypmod FROM pg_attribute a \
             JOIN pg_class c ON a.attrelid = c.oid \
             WHERE c.relname = 'vector_entries' AND a.attname = 'embedding' AND a.attnum > 0"
        )
        .fetch_optional(db.pool())
        .await;

        if let Ok(Some(actual_dim)) = dim_check {
            if actual_dim as u32 != expected_dim {
                tracing::warn!(
                    "⚠️  Vector dimension mismatch: DB column is {} but EMBEDDING_DIMENSIONS={}. \
                     Embeddings will fail. Fix with: \
                     TRUNCATE vector_entries; ALTER TABLE vector_entries ALTER COLUMN embedding TYPE vector({});",
                    actual_dim, expected_dim, expected_dim
                );
            }
        }
    }

    // Initialize Walrus client (SDK wraps Publisher + Aggregator HTTP APIs)
    let walrus_client = walrus_rs::WalrusClient::new(
        &config.walrus_aggregator_url,
        &config.walrus_publisher_url,
    )
    .expect("Failed to initialize Walrus client (invalid URL?)");
    tracing::info!("  Walrus publisher: {}", config.walrus_publisher_url);
    tracing::info!("  Walrus aggregator: {}", config.walrus_aggregator_url);
    // Log upload key pool status
    let pool_size = config.sui_private_keys.len();
    if pool_size > 0 {
        tracing::info!("  Walrus upload: {} key(s) in pool (parallel uploads up to {}x)", pool_size, pool_size);
    } else {
        tracing::warn!("  Walrus upload: no Sui private keys configured, uploads will fail");
    }

    // Build key pool for parallel Walrus uploads
    let key_pool = KeyPool::new(config.sui_private_keys.clone());

    // Initialize Redis for rate limiting
    let redis = rate_limit::create_redis_client(&config.rate_limit.redis_url)
        .await
        .expect("Failed to connect to Redis for rate limiting");
    tracing::info!("  Redis: connected at {}", config.rate_limit.redis_url);

    // Generate the enclave ephemeral keypair (uses NSM entropy in AWS Nitro).
    // The public key is bound to the enclave image via /get_attestation.
    let eph_kp = EnclaveKeyPair::generate();
    tracing::info!(
        "  enclave pubkey: {}",
        hex::encode(eph_kp.public_key_bytes())
    );

    let logs = Arc::new(LogBuffer::new(1000));

    // ── Apalis: Postgres-backed job queue ─────────────────────────────────
    let apalis_pool = sqlx::PgPool::connect(&config.database_url)
        .await
        .expect("Failed to connect to PostgreSQL for Apalis");
    PostgresStorage::<()>::setup(&apalis_pool)
        .await
        .expect("Apalis postgres migration failed");
    let job_storage: PostgresStorage<MetaTransferJob> = PostgresStorage::new(apalis_pool.clone());
    let remember_job_storage: PostgresStorage<RememberJob> =
        PostgresStorage::new(apalis_pool.clone());
    let bulk_job_storage: PostgresStorage<BulkRememberJob> =
        PostgresStorage::new(apalis_pool.clone());

    // Single Apalis queue for all WalletJob signing operations (MEM-35).
    const WALLET_QUEUE_NAME: &str = "wallet_jobs";
    let wallet_storage: WalletJobStorage = PostgresStorage::new_with_config(
        apalis_pool.clone(),
        apalis_sql::Config::new(WALLET_QUEUE_NAME),
    );
    tracing::info!(
        "  Apalis: job queue ready (table=apalis_jobs, queue={})",
        WALLET_QUEUE_NAME
    );

    // Cache TTL config (Redis-backed blob ciphertext + embedding caches)
    let blob_cache_ttl_secs = std::env::var("BLOB_CACHE_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_BLOB_CACHE_TTL_SECS);
    let blob_cache_max_bytes = std::env::var("BLOB_CACHE_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_BLOB_CACHE_MAX_BYTES);
    let embedding_cache_ttl_secs = std::env::var("EMBEDDING_CACHE_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_EMBEDDING_CACHE_TTL_SECS);
    let blob_cache_ttl = std::time::Duration::from_secs(blob_cache_ttl_secs);
    let embedding_cache_ttl = std::time::Duration::from_secs(embedding_cache_ttl_secs);
    tracing::info!(
        "  blob cache: ttl={}s max={}B; embedding cache: ttl={}s",
        blob_cache_ttl_secs,
        blob_cache_max_bytes,
        embedding_cache_ttl_secs
    );

    // Shared application state
    let state = Arc::new(AppState {
        db,
        config: config.clone(),
        http_client,
        walrus_client,
        key_pool,
        redis,
        eph_kp,
        logs,
        remember_job_storage: remember_job_storage.clone(),
        wallet_storage: wallet_storage.clone(),
        bulk_job_storage: bulk_job_storage.clone(),
        blob_cache_ttl,
        blob_cache_max_bytes,
        embedding_cache_ttl,
    });

    // ── Apalis workers: spawn 4 monitors (meta-transfer, remember, bulk, wallet)
    {
        let worker_state = state.clone();
        let storage = job_storage.clone();
        tokio::spawn(async move {
            loop {
                let worker = WorkerBuilder::new("meta-transfer")
                    .data(worker_state.clone())
                    .backend(storage.clone())
                    .build_fn(jobs::execute_meta_transfer);
                #[allow(deprecated)]
                if let Err(e) = Monitor::new().register_with_count(2, worker).run().await {
                    tracing::error!("Apalis meta-transfer monitor exited: {}", e);
                }
                tokio::time::sleep(APALIS_MONITOR_RESTART_DELAY).await;
            }
        });
        tracing::info!("  Apalis: worker 'meta-transfer' spawned (concurrency=2)");
    }
    {
        let worker_state = state.clone();
        let storage = remember_job_storage.clone();
        tokio::spawn(async move {
            loop {
                let worker = WorkerBuilder::new("remember")
                    .data(worker_state.clone())
                    .backend(storage.clone())
                    .build_fn(jobs::execute_remember);
                #[allow(deprecated)]
                if let Err(e) = Monitor::new().register_with_count(3, worker).run().await {
                    tracing::error!("Apalis remember monitor exited: {}", e);
                }
                tokio::time::sleep(APALIS_MONITOR_RESTART_DELAY).await;
            }
        });
        tracing::info!("  Apalis: worker 'remember' spawned (concurrency=3)");
    }
    {
        let worker_state = state.clone();
        let storage = bulk_job_storage.clone();
        tokio::spawn(async move {
            loop {
                let worker = WorkerBuilder::new("bulk-remember")
                    .data(worker_state.clone())
                    .backend(storage.clone())
                    .build_fn(execute_bulk_remember);
                #[allow(deprecated)]
                if let Err(e) = Monitor::new().register_with_count(2, worker).run().await {
                    tracing::error!("Apalis bulk-remember monitor exited: {}", e);
                }
                tokio::time::sleep(APALIS_MONITOR_RESTART_DELAY).await;
            }
        });
        tracing::info!("  Apalis: worker 'bulk-remember' spawned (concurrency=2)");
    }
    let wallet_concurrency: usize = std::env::var("WALLET_JOB_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8);
    {
        let worker_state = state.clone();
        let storage = wallet_storage.clone();
        tokio::spawn(async move {
            loop {
                let worker = WorkerBuilder::new("wallet_jobs")
                    .data(worker_state.clone())
                    .backend(storage.clone())
                    .build_fn(execute_wallet_job);
                #[allow(deprecated)]
                if let Err(e) = Monitor::new()
                    .register_with_count(wallet_concurrency, worker)
                    .run()
                    .await
                {
                    tracing::error!("Apalis wallet worker exited: {}", e);
                }
                tokio::time::sleep(APALIS_MONITOR_RESTART_DELAY).await;
            }
        });
        tracing::info!(
            "  Apalis: worker 'wallet_jobs' spawned (concurrency={})",
            wallet_concurrency
        );
    }

    // Build routes
    // Protected routes (require Ed25519 signature + onchain verification)
    let protected_routes = Router::new()
        .route("/api/remember", post(routes::remember))
        .route("/api/remember/{job_id}", get(routes::remember_status))
        .route("/api/remember/bulk", post(routes::remember_bulk))
        .route("/api/recall", post(routes::recall))
        .route("/api/remember/manual", post(routes::remember_manual))
        .route("/api/recall/manual", post(routes::recall_manual))
        .route("/api/analyze", post(routes::analyze))
        .route("/api/ask", post(routes::ask))
        .route("/api/restore", post(routes::restore))
        // Router::layer runs middleware bottom-to-top (last added runs first).
        // Keep auth outer so AuthInfo is in request extensions before rate limiting reads it.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit::rate_limit_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::verify_signature,
        ));

    // Public routes
    let public_routes = Router::new()
        .route("/health", get(routes::health))
        .route("/config", get(routes::get_config))
        .route("/sponsor", post(routes::sponsor_proxy))
        .route("/sponsor/execute", post(routes::sponsor_execute_proxy));

    // Nautilus enclave routes — attestation, enclave health, in-memory logs
    let enclave_routes = Router::new()
        .route("/get_attestation", get(get_attestation))
        .route("/enclave_health", get(enclave_health))
        .route("/logs", get(get_logs));

    let app = Router::new()
        .merge(protected_routes)
        .merge(public_routes)
        .merge(enclave_routes)
        .with_state(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    // Start server — bind loopback in enclave (socat VSOCK forwards externally), all interfaces locally
    let bind_host = if enclave_mode { "127.0.0.1" } else { "0.0.0.0" };
    let addr = format!("{}:{}", bind_host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind address");

    tracing::info!("memwal server listening on {}", addr);
    tracing::info!("  health: http://localhost:{}/health", config.port);
    tracing::info!("  api:    http://localhost:{}/api/{{remember,recall,analyze}}", config.port);

    // Graceful shutdown: kill sidecar when server stops
    let shutdown = async {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("shutting down...");
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .expect("Server failed");

    // Cleanup sidecar after shutdown
    sidecar_child.kill().await.ok();
    tracing::info!("sidecar stopped");
}
