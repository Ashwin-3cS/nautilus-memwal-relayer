// nautilus-enclave/src/nsm.rs
//
// Wrapper around the AWS Nitro Secure Module (NSM) API.
// When the `nsm` feature is enabled (real enclave), this calls the NSM device.
// When disabled (dev/test), it provides a mock implementation for local testing.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Attestation data returned from the NSM (or mocked for dev).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationDoc {
    /// Hex-encoded PCR0 (enclave image hash).
    pub pcr0: String,
    /// Hex-encoded PCR1 (kernel + boot ramfs hash).
    pub pcr1: String,
    /// Hex-encoded PCR2 (application hash).
    pub pcr2: String,
    /// Hex-encoded Ed25519 public key embedded as user data.
    pub public_key: String,
    /// ISO-8601 timestamp of when the attestation was generated.
    pub timestamp: String,
    /// Raw CBOR bytes of the full COSE_Sign1 attestation document (hex).
    pub raw_cbor_hex: String,
}

/// Request an attestation document from the NSM device.
///
/// - `public_key`: The enclave's Ed25519 public key (32 bytes) to embed as user data.
/// - `nonce`: A caller-provided nonce to bind this attestation to a specific request.
///
/// On a real Nitro Enclave with the `nsm` feature, this calls the NSM ioctl.
/// Without the feature, it returns a deterministic mock document for development.
pub fn get_attestation(public_key: &[u8; 32], nonce: &[u8]) -> Result<AttestationDoc> {
    let timestamp = chrono::Utc::now().to_rfc3339();

    #[cfg(feature = "nsm")]
    {
        get_attestation_real(public_key, nonce, &timestamp)
    }

    #[cfg(not(feature = "nsm"))]
    {
        get_attestation_mock(public_key, nonce, &timestamp)
    }
}

// ── Real NSM implementation (feature = "nsm") ─────────────────────────────

#[cfg(feature = "nsm")]
fn get_attestation_real(
    public_key: &[u8; 32],
    nonce: &[u8],
    timestamp: &str,
) -> Result<AttestationDoc> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver;

    let nsm_fd = driver::nsm_init();
    anyhow::ensure!(nsm_fd >= 0, "Failed to open NSM device (fd={}). Are you running inside a Nitro Enclave?", nsm_fd);

    let request = Request::Attestation {
        user_data: if nonce.is_empty() { None } else { Some(nonce.to_vec().into()) },
        nonce: None,
        public_key: Some(public_key.to_vec().into()),
    };

    let response = driver::nsm_process_request(nsm_fd, request);

    match response {
        Response::Attestation { document } => {
            let raw_cbor_hex = hex::encode(&document);

            // Extract PCRs by querying the NSM describe-pcr API
            let pcr0 = read_pcr(nsm_fd, 0)?;
            let pcr1 = read_pcr(nsm_fd, 1)?;
            let pcr2 = read_pcr(nsm_fd, 2)?;

            driver::nsm_exit(nsm_fd);

            Ok(AttestationDoc {
                pcr0,
                pcr1,
                pcr2,
                public_key: hex::encode(public_key),
                timestamp: timestamp.to_string(),
                raw_cbor_hex,
            })
        }
        Response::Error(e) => {
            driver::nsm_exit(nsm_fd);
            anyhow::bail!("NSM attestation request failed: {:?}", e);
        }
        other => {
            driver::nsm_exit(nsm_fd);
            anyhow::bail!("Unexpected NSM response: {:?}", other);
        }
    }
}

#[cfg(feature = "nsm")]
fn read_pcr(nsm_fd: i32, index: u16) -> Result<String> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver;

    let request = Request::DescribePCR { index };
    let response = driver::nsm_process_request(nsm_fd, request);

    match response {
        Response::DescribePCR { lock: _, data } => Ok(hex::encode(&data)),
        Response::Error(e) => anyhow::bail!("Failed to read PCR{}: {:?}", index, e),
        other => anyhow::bail!("Unexpected response for PCR{}: {:?}", index, other),
    }
}

// ── Mock implementation (no nsm feature) ──────────────────────────────────

#[cfg(not(feature = "nsm"))]
fn get_attestation_mock(
    public_key: &[u8; 32],
    nonce: &[u8],
    timestamp: &str,
) -> Result<AttestationDoc> {
    eprintln!("[MOCK] NSM attestation — not running inside a real Nitro Enclave");

    // Generate deterministic mock PCR values based on nonce for reproducibility
    let mock_pcr0 = hex::encode(&[0xAA; 48]);
    let mock_pcr1 = hex::encode(&[0xBB; 48]);
    let mock_pcr2 = hex::encode(&[0xCC; 48]);

    // Build a mock CBOR-like payload (not a real COSE_Sign1, just for dev)
    let mock_doc = serde_json::json!({
        "mock": true,
        "pcrs": { "0": mock_pcr0, "1": mock_pcr1, "2": mock_pcr2 },
        "public_key": hex::encode(public_key),
        "nonce": hex::encode(nonce),
    });
    let raw_cbor_hex = hex::encode(serde_json::to_vec(&mock_doc)
        .context("Failed to serialize mock attestation doc")?);

    Ok(AttestationDoc {
        pcr0: mock_pcr0,
        pcr1: mock_pcr1,
        pcr2: mock_pcr2,
        public_key: hex::encode(public_key),
        timestamp: timestamp.to_string(),
        raw_cbor_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_attestation_returns_valid_doc() {
        let pubkey = [0x42u8; 32];
        let nonce = b"test-nonce";
        let doc = get_attestation(&pubkey, nonce).unwrap();

        assert_eq!(doc.public_key, hex::encode([0x42u8; 32]));
        assert!(!doc.pcr0.is_empty());
        assert!(!doc.pcr1.is_empty());
        assert!(!doc.pcr2.is_empty());
        assert!(!doc.raw_cbor_hex.is_empty());
        assert!(!doc.timestamp.is_empty());
    }

    #[test]
    fn test_mock_attestation_pcrs_are_48_bytes_hex() {
        let pubkey = [0x01u8; 32];
        let doc = get_attestation(&pubkey, b"nonce").unwrap();

        // 48 bytes = 96 hex chars
        assert_eq!(doc.pcr0.len(), 96);
        assert_eq!(doc.pcr1.len(), 96);
        assert_eq!(doc.pcr2.len(), 96);
    }

    #[test]
    fn test_mock_attestation_empty_nonce() {
        let pubkey = [0x00u8; 32];
        let doc = get_attestation(&pubkey, b"");
        assert!(doc.is_ok());
    }
}
