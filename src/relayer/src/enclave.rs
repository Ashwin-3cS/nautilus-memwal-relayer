//! Nautilus TEE endpoints: attestation, enclave health, in-memory log buffer.
//!
//! These routes give clients cryptographic proof that they are talking to a
//! genuine Nitro enclave running a known image. The ephemeral `EnclaveKeyPair`
//! is generated on startup using NSM entropy and never leaves the enclave; its
//! public key is bound to the enclave image PCRs via the NSM attestation
//! document returned from `/get_attestation`.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use nautilus_enclave::EnclaveKeyPair;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::types::{AppState, SignedResponse};

// ── Intent scope constants ────────────────────────────────────────────────
//
// Each protected endpoint signs with a distinct intent byte so a signature
// minted for /api/remember can never be replayed against /api/recall etc.
// These MUST stay in sync with the client-side verifier and any on-chain
// PTBs that call `verify_signature` on the Move side.
pub const INTENT_REMEMBER:        u8 = 1;
pub const INTENT_RECALL:          u8 = 2;
pub const INTENT_REMEMBER_MANUAL: u8 = 3;
pub const INTENT_RECALL_MANUAL:   u8 = 4;
pub const INTENT_ANALYZE:         u8 = 5;
pub const INTENT_ASK:             u8 = 6;
pub const INTENT_RESTORE:         u8 = 7;

// ── IntentMessage (BCS layout matches Move `IntentMessage<vector<u8>>`) ───
//
// Move side (contracts/nautilus/sources/enclave.move):
//   public struct IntentMessage<T: drop> has copy, drop {
//       intent: u8,
//       timestamp_ms: u64,
//       payload: T,
//   }
//
// We instantiate P = vector<u8> on-chain, which BCS-encodes as
// ULEB128 length prefix + raw bytes — identical to `Vec<u8>` here.
#[derive(Serialize)]
struct IntentMessage {
    intent: u8,
    timestamp_ms: u64,
    payload: Vec<u8>,
}

// ── In-memory ring buffer for the /logs endpoint ──────────────────────────

pub struct LogBuffer {
    lines: Mutex<VecDeque<String>>,
    capacity: usize,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            lines: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    #[allow(dead_code)]
    pub fn push(&self, line: String) {
        let mut buf = self.lines.lock().unwrap();
        if buf.len() >= self.capacity {
            buf.pop_front();
        }
        buf.push_back(line);
    }

    pub fn recent(&self, n: usize) -> Vec<String> {
        let buf = self.lines.lock().unwrap();
        buf.iter().rev().take(n).rev().cloned().collect()
    }
}

// ── Signed response helper ────────────────────────────────────────────────

/// Sign `data` with the enclave ephemeral keypair and return the wrapper.
///
/// The signature covers the BCS encoding of
/// `IntentMessage { intent, timestamp_ms, payload: sha256(json(data)) }` —
/// the same byte layout the Move `verify_signature<T, vector<u8>>` function
/// reconstructs on-chain. Off-chain clients can verify by recomputing the
/// same BCS bytes from the wrapper fields.
pub fn sign_response<T: Serialize>(
    kp: &EnclaveKeyPair,
    intent: u8,
    data: T,
) -> SignedResponse<T> {
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // Hash the canonical JSON of `data` so the on-chain payload stays
    // bounded (32 bytes) regardless of response size.
    let json_bytes = serde_json::to_vec(&data).expect("serialization is infallible");
    let body_hash = Sha256::digest(&json_bytes).to_vec();

    let intent_message = IntentMessage {
        intent,
        timestamp_ms,
        payload: body_hash,
    };
    let signed_bytes = bcs::to_bytes(&intent_message).expect("bcs serialization is infallible");
    let sig = kp.sign(&signed_bytes);

    SignedResponse {
        data,
        intent_scope: intent,
        timestamp_ms,
        signature: hex::encode(sig.to_bytes()),
        enclave_public_key: hex::encode(kp.public_key_bytes()),
    }
}

// ── Error ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum EnclaveError {
    GenericError(String),
}

impl IntoResponse for EnclaveError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            EnclaveError::GenericError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

// ── GET /get_attestation ──────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct GetAttestationResponse {
    /// Hex-encoded CBOR NSM attestation document. Contains the enclave PCRs
    /// and binds `public_key` to this enclave instance.
    pub attestation: String,
}

pub async fn get_attestation(
    State(state): State<Arc<AppState>>,
) -> Result<Json<GetAttestationResponse>, EnclaveError> {
    info!("get_attestation called");
    let pk_bytes = state.eph_kp.public_key_bytes();
    let doc = nautilus_enclave::get_attestation(&pk_bytes, &[])
        .map_err(|e| EnclaveError::GenericError(format!("attestation failed: {}", e)))?;
    Ok(Json(GetAttestationResponse {
        attestation: doc.raw_cbor_hex,
    }))
}

// ── GET /enclave_health ───────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct EnclaveHealthResponse {
    /// Hex-encoded Ed25519 public key of the enclave ephemeral signing key.
    pub public_key: String,
    pub status: String,
}

pub async fn enclave_health(
    State(state): State<Arc<AppState>>,
) -> Result<Json<EnclaveHealthResponse>, EnclaveError> {
    Ok(Json(EnclaveHealthResponse {
        public_key: hex::encode(state.eph_kp.public_key_bytes()),
        status: "ok".to_string(),
    }))
}

// ── GET /logs ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LogsQueryParams {
    pub lines: Option<usize>,
}

#[derive(Serialize)]
pub struct LogsResponse {
    pub lines: Vec<String>,
    pub count: usize,
}

pub async fn get_logs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<LogsQueryParams>,
) -> Result<Json<LogsResponse>, EnclaveError> {
    let n = params.lines.unwrap_or(100).min(1000);
    let lines = state.logs.recent(n);
    Ok(Json(LogsResponse {
        count: lines.len(),
        lines,
    }))
}

