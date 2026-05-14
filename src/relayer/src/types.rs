use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use nautilus_enclave::EnclaveKeyPair;
use serde::{Deserialize, Serialize};

use crate::db::VectorDb;
use crate::enclave::LogBuffer;
use crate::jobs::{BulkRememberJobStorage, RememberJobStorage, WalletJobStorage};
use crate::rate_limit::RateLimitConfig;

// ============================================================
// Cache constants (Redis-backed)
// ============================================================

/// Redis key prefix for Walrus ciphertext cache entries.
pub const BLOB_CACHE_KEY_PREFIX: &str = "memwal:blob:v1:";

/// Default max age for Redis-cached Walrus ciphertext before revalidating.
pub const DEFAULT_BLOB_CACHE_TTL_SECS: u64 = 14 * 24 * 60 * 60;

/// Default maximum ciphertext size stored in Redis.
pub const DEFAULT_BLOB_CACHE_MAX_BYTES: usize = 512 * 1024;

/// Default max age for Redis-cached recall query embeddings.
pub const DEFAULT_EMBEDDING_CACHE_TTL_SECS: u64 = 10 * 60;

// ============================================================
// App State (shared across routes + middleware)
// ============================================================

/// Shared application state passed to all routes and middleware
pub struct AppState {
    pub db: VectorDb,
    pub config: Config,
    pub http_client: reqwest::Client,
    pub walrus_client: walrus_rs::WalrusClient,
    /// Round-robin pool of Sui private keys for parallel Walrus uploads
    pub key_pool: KeyPool,
    /// Redis multiplexed connection for rate limiting
    pub redis: redis::aio::MultiplexedConnection,
    /// Ephemeral Ed25519 keypair generated on startup (NSM entropy in enclave).
    /// Used for signing responses and binding to NSM attestation docs.
    pub eph_kp: EnclaveKeyPair,
    /// In-memory ring buffer for the /logs endpoint.
    pub logs: Arc<LogBuffer>,
    /// Apalis storage for RememberJob — legacy full async pipeline.
    /// New requests use WalletJob::UploadAndTransfer instead.
    #[allow(dead_code)]
    pub remember_job_storage: RememberJobStorage,
    /// Single Apalis storage for WalletJob (MEM-35: single wallet + retry).
    pub wallet_storage: WalletJobStorage,
    /// ENG-1408: Apalis storage for BulkRememberJob.
    #[allow(dead_code)]
    pub bulk_job_storage: BulkRememberJobStorage,
    /// ENG-1405: Redis TTL for Walrus blob ciphertext cache entries.
    pub blob_cache_ttl: std::time::Duration,
    /// MEM-37: Maximum SEAL ciphertext bytes to cache in Redis.
    pub blob_cache_max_bytes: usize,
    /// ENG-1405: Redis TTL for recall query embedding cache entries.
    #[allow(dead_code)]
    pub embedding_cache_ttl: std::time::Duration,
}

// ============================================================
// Key Pool (round-robin selection for parallel uploads)
// ============================================================

/// A thread-safe round-robin pool of Sui private keys.
/// Each call to `next()` returns the next key in the pool,
/// allowing concurrent uploads to use different signer addresses.
pub struct KeyPool {
    keys: Vec<String>,
    counter: AtomicUsize,
}

impl KeyPool {
    pub fn new(keys: Vec<String>) -> Self {
        Self {
            keys,
            counter: AtomicUsize::new(0),
        }
    }

    /// Returns the next key in round-robin order, or `None` if the pool is empty.
    #[allow(dead_code)]
    pub fn next(&self) -> Option<&str> {
        if self.keys.is_empty() {
            return None;
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.keys.len();
        Some(&self.keys[idx])
    }

    /// Returns the next key index (round-robin), or `None` if pool is empty.
    /// Sidecar maps this back to a private key via SERVER_SUI_PRIVATE_KEYS.
    pub fn next_index(&self) -> Option<usize> {
        if self.keys.is_empty() {
            return None;
        }
        Some(self.counter.fetch_add(1, Ordering::Relaxed) % self.keys.len())
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

// ============================================================
// Config
// ============================================================

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub database_url: String,
    pub sui_rpc_url: String,
    pub memwal_account_id: Option<String>,
    pub openai_api_key: Option<String>,
    pub openai_api_base: String,
    /// Embedding provider (falls back to openai_api_* if not set)
    pub embedding_api_key: Option<String>,
    pub embedding_api_base: Option<String>,
    pub embedding_model: String,
    pub embedding_dimensions: Option<u32>,
    pub llm_model: String,
    pub walrus_publisher_url: String,
    pub walrus_aggregator_url: String,
    /// Primary key (used for SEAL decrypt / recall). Unchanged.
    pub sui_private_key: Option<String>,
    /// Pool of keys for parallel Walrus uploads (parsed from SERVER_SUI_PRIVATE_KEYS,
    /// falls back to SERVER_SUI_PRIVATE_KEY as a single-element list).
    pub sui_private_keys: Vec<String>,
    pub package_id: String,
    pub registry_id: String,
    /// URL of the SEAL/Walrus TS sidecar HTTP server
    pub sidecar_url: String,
    /// Shared secret for authenticating Rust→sidecar calls (X-Sidecar-Secret header)
    pub sidecar_secret: Option<String>,
    /// Sui network name (mainnet/testnet/devnet) — surfaced via GET /config
    pub sui_network: String,
    /// Allowed CORS origins (comma-separated)
    pub allowed_origins: String,
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
}

impl Config {
    pub fn from_env() -> Self {
        let network = std::env::var("SUI_NETWORK")
            .unwrap_or_else(|_| "mainnet".to_string());
        let default_rpc = match network.as_str() {
            "testnet" => "https://fullnode.testnet.sui.io:443",
            "devnet" => "https://fullnode.devnet.sui.io:443",
            _ => "https://fullnode.mainnet.sui.io:443",
        };

        Self {
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8000".to_string())
                .parse()
                .expect("PORT must be a number"),
            database_url: std::env::var("DATABASE_URL")
                .expect("DATABASE_URL must be set (e.g. postgresql://memwal:memwal_secret@localhost:5432/memwal)"),
            sui_rpc_url: std::env::var("SUI_RPC_URL")
                .unwrap_or_else(|_| default_rpc.to_string()),
            memwal_account_id: std::env::var("MEMWAL_ACCOUNT_ID").ok(),
            openai_api_key: std::env::var("OPENAI_API_KEY").ok(),
            openai_api_base: std::env::var("OPENAI_API_BASE")
                .unwrap_or_else(|_| "https://api.openai.com/v1".to_string()),
            embedding_api_key: std::env::var("EMBEDDING_API_KEY").ok(),
            embedding_api_base: std::env::var("EMBEDDING_API_BASE").ok(),
            embedding_model: std::env::var("EMBEDDING_MODEL")
                .unwrap_or_else(|_| "openai/text-embedding-3-small".to_string()),
            embedding_dimensions: std::env::var("EMBEDDING_DIMENSIONS")
                .ok()
                .and_then(|v| v.parse().ok()),
            llm_model: std::env::var("LLM_MODEL")
                .unwrap_or_else(|_| "openai/gpt-4o-mini".to_string()),
            walrus_publisher_url: std::env::var("WALRUS_PUBLISHER_URL")
                .unwrap_or_else(|_| "https://publisher.walrus-mainnet.walrus.space".to_string()),
            walrus_aggregator_url: std::env::var("WALRUS_AGGREGATOR_URL")
                .unwrap_or_else(|_| "https://aggregator.walrus-mainnet.walrus.space".to_string()),
            sui_private_key: std::env::var("SERVER_SUI_PRIVATE_KEY").ok(),
            sui_private_keys: {
                // SERVER_SUI_PRIVATE_KEYS takes priority (comma-separated list).
                // Falls back to SERVER_SUI_PRIVATE_KEY as a single-element list.
                let multi = std::env::var("SERVER_SUI_PRIVATE_KEYS").ok().map(|s| {
                    s.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect::<Vec<_>>()
                });
                let single = std::env::var("SERVER_SUI_PRIVATE_KEY").ok().map(|k| vec![k]);
                multi.or(single).unwrap_or_default()
            },
            package_id: std::env::var("MEMWAL_PACKAGE_ID")
                .expect("MEMWAL_PACKAGE_ID must be set"),
            registry_id: std::env::var("MEMWAL_REGISTRY_ID")
                .expect("MEMWAL_REGISTRY_ID must be set"),
            sidecar_url: std::env::var("SIDECAR_URL")
                .unwrap_or_else(|_| "http://localhost:9000".to_string()),
            sidecar_secret: std::env::var("SIDECAR_AUTH_TOKEN").ok(),
            sui_network: network.clone(),
            allowed_origins: std::env::var("ALLOWED_ORIGINS").unwrap_or_default(),
            rate_limit: RateLimitConfig::from_env(),
        }
    }
}

// ============================================================
// API Types
// ============================================================

/// POST /api/remember
/// Phase 2: Server handles everything — encrypt, upload Walrus, embed, store
/// Owner is derived from delegate key via onchain verification (auth middleware)
#[derive(Debug, Deserialize)]
pub struct RememberRequest {
    pub text: String,
    /// Namespace for memory isolation (default: "default")
    #[serde(default = "default_namespace")]
    pub namespace: String,
}

/// POST /api/remember — accepted job response (inside SignedResponse)
#[derive(Debug, Serialize)]
pub struct RememberAcceptedResponse {
    pub job_id: String,
    pub status: String,
}

/// GET /api/remember/:job_id — job status polling (plain JSON, not SignedResponse)
#[derive(Debug, Serialize)]
pub struct RememberJobStatusResponse {
    pub job_id: String,
    pub status: String,
    pub owner: String,
    pub namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// POST /api/remember/bulk — accepted bulk job response (plain JSON)
#[derive(Debug, Serialize)]
pub struct RememberBulkAcceptedResponse {
    pub job_ids: Vec<String>,
    pub total: usize,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct RememberBulkItem {
    pub text: String,
    #[serde(default = "default_namespace")]
    pub namespace: String,
}

#[derive(Debug, Deserialize)]
pub struct RememberBulkRequest {
    pub items: Vec<RememberBulkItem>,
}

/// GET /config — public network config (plain JSON)
#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub network: String,
    #[serde(rename = "suiRpcUrl")]
    pub sui_rpc_url: String,
}

/// Legacy sync remember response — kept for RememberManual return shape
#[derive(Debug, Serialize)]
pub struct RememberResponse {
    pub id: String,
    pub blob_id: String,
    pub owner: String,
    pub namespace: String,
}

/// POST /api/recall
/// Phase 2: Server does search → download → decrypt → return plaintext
/// Owner is derived from delegate key via onchain verification (auth middleware)
fn default_limit() -> usize {
    10
}

fn default_namespace() -> String {
    "default".to_string()
}

#[derive(Debug, Deserialize)]
pub struct RecallRequest {
    pub query: String,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default = "default_namespace")]
    pub namespace: String,
}

#[derive(Debug, Serialize)]
pub struct RecallResponse {
    pub results: Vec<RecallResult>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct RecallResult {
    pub blob_id: String,
    pub text: String,
    pub distance: f64,
}

#[derive(Debug, Serialize)]
pub struct SearchHit {
    pub blob_id: String,
    pub distance: f64,
}



/// POST /api/analyze
/// Extract facts from conversation text using LLM, then remember each fact
/// Owner is derived from delegate key via onchain verification (auth middleware)
#[derive(Debug, Deserialize)]
pub struct AnalyzeRequest {
    /// Conversation text to analyze for memorable facts
    pub text: String,
    #[serde(default = "default_namespace")]
    pub namespace: String,
}

#[derive(Debug, Serialize)]
pub struct AnalyzedFact {
    pub text: String,
    pub id: String,
    pub blob_id: String,
}

#[derive(Debug, Serialize)]
pub struct AnalyzeResponse {
    pub facts: Vec<AnalyzedFact>,
    pub total: usize,
    pub owner: String,
}

/// Per-fact entry in the analyze 202 response.
#[derive(Debug, Serialize)]
pub struct AnalyzeAcceptedFact {
    pub text: String,
    pub id: String,
    pub job_id: String,
}

/// 202-style response: analyze accepted facts and enqueued upload jobs.
/// Clients poll GET /api/remember/{job_id} for each id.
#[derive(Debug, Serialize)]
pub struct AnalyzeAcceptedResponse {
    pub job_ids: Vec<String>,
    pub facts: Vec<AnalyzeAcceptedFact>,
    pub fact_count: usize,
    pub status: String,
    pub owner: String,
}

/// POST /api/remember/manual
/// Client sends SEAL-encrypted data (base64) + pre-computed embedding vector.
/// Server uploads to Walrus via sidecar, then stores the vector ↔ blobId mapping.
#[derive(Debug, Deserialize)]
pub struct RememberManualRequest {
    pub encrypted_data: String,  // base64-encoded SEAL-encrypted bytes
    pub vector: Vec<f32>,
    #[serde(default = "default_namespace")]
    pub namespace: String,
}

#[derive(Debug, Serialize)]
pub struct RememberManualResponse {
    pub id: String,
    pub blob_id: String,
    pub owner: String,
    pub namespace: String,
}

/// POST /api/recall/manual
/// User provides pre-computed query vector.
/// Server returns matching blobIds + distances (no download/decrypt).
#[derive(Debug, Deserialize)]
pub struct RecallManualRequest {
    pub vector: Vec<f32>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default = "default_namespace")]
    pub namespace: String,
}

#[derive(Debug, Serialize)]
pub struct RecallManualResponse {
    pub results: Vec<SearchHit>,
    pub total: usize,
}

/// POST /api/ask
/// Recall memories + LLM chat — full AI-with-memory demo
#[derive(Debug, Deserialize)]
pub struct AskRequest {
    /// User's question
    pub question: String,
    /// Max memories to inject (default: 5)
    pub limit: Option<usize>,
    #[serde(default = "default_namespace")]
    pub namespace: String,
}

#[derive(Debug, Serialize)]
pub struct AskResponse {
    pub answer: String,
    pub memories_used: usize,
    pub memories: Vec<RecallResult>,
}

/// POST /api/restore
/// Restore a namespace: download blobs from Walrus, decrypt, re-embed, re-index
fn default_restore_limit() -> usize {
    50
}

#[derive(Debug, Deserialize)]
pub struct RestoreRequest {
    pub namespace: String,
    /// Max blobs to restore (default: 50)
    #[serde(default = "default_restore_limit")]
    pub limit: usize,
}

#[derive(Debug, Serialize)]
pub struct RestoreResponse {
    pub restored: usize,
    pub skipped: usize,
    pub total: usize,
    pub namespace: String,
    pub owner: String,
}

/// Health check
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

// ============================================================
// Signed enclave response wrapper
// ============================================================

/// Wraps every protected API response with an Ed25519 signature from the
/// enclave ephemeral key.  Clients can verify the signature against the
/// public key returned from GET /enclave_health, which is bound to the
/// enclave PCRs via GET /get_attestation.
///
/// Verification (TypeScript / @noble/ed25519):
///   const payload = new TextEncoder().encode(JSON.stringify(data));
///   ed25519.verify(fromHex(signature), payload, fromHex(enclave_public_key))
#[derive(Debug, Serialize)]
pub struct SignedResponse<T: Serialize> {
    pub data: T,
    /// Intent scope byte — distinguishes endpoints (remember=1, recall=2, …).
    /// Part of the BCS-encoded IntentMessage that the signature covers.
    pub intent_scope: u8,
    /// Unix timestamp (ms) — replay-protection field, also part of the
    /// BCS-encoded IntentMessage covered by the signature.
    pub timestamp_ms: u64,
    /// Hex-encoded Ed25519 signature over `bcs(IntentMessage { intent_scope,
    /// timestamp_ms, payload: sha256(canonical_json(data)) })`. This matches
    /// the Move `verify_signature<T, P=vector<u8>>` layout so the same
    /// signature is verifiable on-chain.
    pub signature: String,
    /// Hex-encoded enclave ephemeral Ed25519 public key.
    pub enclave_public_key: String,
}

// ============================================================
// Auth Types
// ============================================================

/// Headers required for authenticated requests
#[derive(Debug, Clone)]
pub struct AuthInfo {
    #[allow(dead_code)]
    pub public_key: String,
    /// Owner address from the onchain MemWalAccount (set after onchain verification)
    pub owner: String,
    /// MemWalAccount object ID (set after onchain verification)
    pub account_id: String,
    /// Delegate private key (hex) — used for SEAL decrypt SessionKey
    pub delegate_key: Option<String>,
    /// SEAL SessionKey (base64 JSON) — modern replacement for delegate_key on the wire.
    pub seal_session: Option<String>,
}

// ============================================================
// Error
// ============================================================

#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    #[allow(dead_code)]
    Unauthorized(String),
    Internal(String),
    /// Walrus blob not found (expired or deleted) — triggers cleanup
    BlobNotFound(String),
    /// Rate limit exceeded (HTTP 429)
    #[allow(dead_code)]
    RateLimited(String),
    /// Storage quota exceeded (HTTP 402)
    QuotaExceeded(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::BadRequest(msg) => write!(f, "Bad Request: {}", msg),
            AppError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            AppError::Internal(msg) => write!(f, "Internal Error: {}", msg),
            AppError::BlobNotFound(msg) => write!(f, "Blob Not Found: {}", msg),
            AppError::RateLimited(msg) => write!(f, "Rate Limited: {}", msg),
            AppError::QuotaExceeded(msg) => write!(f, "Quota Exceeded: {}", msg),
        }
    }
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match &self {
            AppError::BadRequest(msg) => (axum::http::StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Unauthorized(msg) => (axum::http::StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::Internal(msg) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                msg.clone(),
            ),
            AppError::BlobNotFound(msg) => (axum::http::StatusCode::NOT_FOUND, msg.clone()),
            AppError::RateLimited(msg) => (axum::http::StatusCode::TOO_MANY_REQUESTS, msg.clone()),
            AppError::QuotaExceeded(msg) => (axum::http::StatusCode::PAYMENT_REQUIRED, msg.clone()),
        };

        let body = serde_json::json!({ "error": message });
        (status, axum::Json(body)).into_response()
    }
}

// ============================================================
// Sidecar Types (shared by seal.rs + walrus.rs)
// ============================================================

/// Error response from the TS sidecar HTTP server
#[derive(Debug, Deserialize)]
pub struct SidecarError {
    pub error: String,
}
