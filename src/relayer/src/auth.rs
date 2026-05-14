use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::sui::{find_account_by_delegate_key, verify_delegate_key_onchain};
use crate::types::{AppState, AuthInfo};

/// Constant-time 401 — normalizes timing across all failure paths.
async fn constant_time_reject() -> StatusCode {
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    StatusCode::UNAUTHORIZED
}

/// Ed25519 signature verification + onchain delegate key verification middleware
///
/// Expects these headers:
/// - `x-public-key`: hex-encoded Ed25519 public key (32 bytes)
/// - `x-signature`: hex-encoded Ed25519 signature (64 bytes)
/// - `x-timestamp`: Unix timestamp (seconds)
/// - `x-nonce`: UUID v4 (replay protection, SDK v0.3+)
/// - `x-account-id` (optional): account object ID hint
///
/// Signed canonical message (6-field):
///   "{timestamp}.{method}.{path_and_query}.{body_sha256}.{nonce}.{account_id}"
pub async fn verify_signature(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = request.headers();

    let public_key_hex = headers
        .get("x-public-key")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let signature_hex = headers
        .get("x-signature")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let timestamp_str = headers
        .get("x-timestamp")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let account_id_hint = headers
        .get("x-account-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let delegate_key_hex = headers
        .get("x-delegate-key")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let seal_session = headers
        .get("x-seal-session")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // MED-1: nonce required (SDK v0.3+); reject older clients
    let nonce = headers
        .get("x-nonce")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            tracing::warn!("request missing x-nonce; rejecting legacy SDK");
            StatusCode::UPGRADE_REQUIRED
        })?
        .to_string();

    if uuid::Uuid::parse_str(&nonce).is_err() {
        tracing::warn!("invalid nonce format: {}", &nonce[..nonce.len().min(36)]);
        return Err(constant_time_reject().await);
    }

    // Validate timestamp (±5 minute window) with overflow protection
    let timestamp: i64 = timestamp_str
        .parse()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let now = chrono::Utc::now().timestamp();
    let age = now.checked_sub(timestamp).unwrap_or(i64::MAX);
    if !(-300..=300).contains(&age) {
        tracing::warn!("timestamp out of window: {} (now: {})", timestamp, now);
        return Err(constant_time_reject().await);
    }

    // Decode public key
    let pk_bytes = hex::decode(&public_key_hex).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let pk_array: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let verifying_key =
        VerifyingKey::from_bytes(&pk_array).map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Decode signature
    let sig_bytes = hex::decode(&signature_hex).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let signature = Signature::from_bytes(&sig_array);

    // Build 6-field canonical signed message
    let method = request.method().as_str().to_string();
    let path = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());

    let (mut parts, body) = request.into_parts();

    let body_bytes = axum::body::to_bytes(body, 2 * 1024 * 1024)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let body_hash = hex::encode(Sha256::digest(&body_bytes));
    let account_id_for_sig = account_id_hint.clone().unwrap_or_default();
    let message = format!(
        "{}.{}.{}.{}.{}.{}",
        timestamp_str, method, path, body_hash, nonce, account_id_for_sig
    );

    if verifying_key
        .verify(message.as_bytes(), &signature)
        .is_err()
    {
        tracing::warn!("signature verification failed for key: {}", public_key_hex);
        return Err(constant_time_reject().await);
    }

    tracing::debug!("signature verified for key: {}", public_key_hex);

    // MED-1: record nonce in Redis (TTL=600s > timestamp window=300s) to block replays
    {
        let nonce_key = format!("nonce:{}", nonce);
        let mut redis = state.redis.clone();

        let set_result: Option<String> = redis
            .set_options(
                &nonce_key,
                "1",
                redis::SetOptions::default()
                    .conditional_set(redis::ExistenceCheck::NX)
                    .with_expiration(redis::SetExpiry::EX(600)),
            )
            .await
            .unwrap_or(None);

        if set_result.is_none() {
            tracing::warn!(
                "replay detected: nonce {} already seen (key={}...)",
                nonce,
                &public_key_hex[..16.min(public_key_hex.len())]
            );
            return Err(constant_time_reject().await);
        }
    }

    let (account_id, owner) =
        match resolve_account(&state, &public_key_hex, &pk_array, account_id_hint).await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!("account resolution failed: {}", e);
                return Err(constant_time_reject().await);
            }
        };

    tracing::debug!("account resolved: {} (owner: {})", account_id, owner);

    parts.extensions.insert(AuthInfo {
        public_key: public_key_hex,
        owner,
        account_id,
        delegate_key: delegate_key_hex,
        seal_session,
    });

    let request = Request::from_parts(parts, axum::body::Body::from(body_bytes));

    Ok(next.run(request).await)
}

/// Resolve delegate key → account via: cache → registry scan → header hint → config fallback.
async fn resolve_account(
    state: &AppState,
    public_key_hex: &str,
    pk_bytes: &[u8; 32],
    account_id_hint: Option<String>,
) -> Result<(String, String), String> {
    // Strategy 1: PostgreSQL cache
    if let Ok(Some((cached_account_id, _cached_owner))) =
        state.db.get_cached_account(public_key_hex).await
    {
        match verify_delegate_key_onchain(
            &state.http_client,
            &state.config.sui_rpc_url,
            &cached_account_id,
            pk_bytes,
        )
        .await
        {
            Ok(owner) => {
                tracing::debug!("account resolved from cache: {}", cached_account_id);
                return Ok((cached_account_id, owner));
            }
            Err(_) => {
                tracing::debug!("cached account {} is stale, re-resolving", cached_account_id);
            }
        }
    }

    // Strategy 2: On-chain registry scan
    match find_account_by_delegate_key(
        &state.http_client,
        &state.config.sui_rpc_url,
        &state.config.registry_id,
        pk_bytes,
    )
    .await
    {
        Ok((account_id, owner)) => {
            let _ = state.db.cache_delegate_key(public_key_hex, &account_id, &owner).await;
            return Ok((account_id, owner));
        }
        Err(e) => {
            tracing::debug!("registry scan did not find key: {}", e);
        }
    }

    // Strategy 3: Header hint or config fallback
    let fallback_account_id = account_id_hint
        .or_else(|| state.config.memwal_account_id.clone())
        .ok_or_else(|| "no account found: not in cache, registry, or header".to_string())?;

    let owner = verify_delegate_key_onchain(
        &state.http_client,
        &state.config.sui_rpc_url,
        &fallback_account_id,
        pk_bytes,
    )
    .await
    .map_err(|e| {
        format!(
            "fallback account {} verification failed: {}",
            fallback_account_id, e
        )
    })?;

    let _ = state
        .db
        .cache_delegate_key(public_key_hex, &fallback_account_id, &owner)
        .await;

    Ok((fallback_account_id, owner))
}
