// nautilus-enclave/src/crypto.rs
//
// Ed25519 keypair generation and signing helpers for Nitro Enclaves.

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

/// A freshly-generated Ed25519 keypair that lives for the lifetime of the enclave.
///
/// Inside a real Nitro Enclave, `OsRng` is backed by the NSM entropy source.
/// Outside an enclave (dev/test), it uses the OS default CSPRNG.
pub struct EnclaveKeyPair {
    signing_key: SigningKey,
}

impl EnclaveKeyPair {
    /// Generate a new random Ed25519 keypair using OS randomness.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Return the 32-byte compressed public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Return the `VerifyingKey` for external verification.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign an arbitrary byte slice with the enclave's private key.
    pub fn sign(&self, payload: &[u8]) -> Signature {
        self.signing_key.sign(payload)
    }
}

/// Verify an Ed25519 signature against a known public key and payload.
/// Returns `Ok(())` if the signature is valid, or an error if not.
pub fn verify_signature(
    public_key_bytes: &[u8; 32],
    payload: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<()> {
    use ed25519_dalek::Verifier;

    let verifying_key = VerifyingKey::from_bytes(public_key_bytes)
        .context("Invalid Ed25519 public key")?;
    let signature = Signature::from_bytes(signature_bytes);
    verifying_key
        .verify(payload, &signature)
        .context("Signature verification failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_produces_unique_keypairs() {
        let kp1 = EnclaveKeyPair::generate();
        let kp2 = EnclaveKeyPair::generate();
        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let kp = EnclaveKeyPair::generate();
        let payload = b"hello nautilus";
        let sig = kp.sign(payload);
        let sig_bytes: [u8; 64] = sig.to_bytes();
        let pub_bytes = kp.public_key_bytes();

        assert!(verify_signature(&pub_bytes, payload, &sig_bytes).is_ok());
    }

    #[test]
    fn test_verify_rejects_bad_payload() {
        let kp = EnclaveKeyPair::generate();
        let sig = kp.sign(b"correct payload");
        let sig_bytes: [u8; 64] = sig.to_bytes();
        let pub_bytes = kp.public_key_bytes();

        assert!(verify_signature(&pub_bytes, b"tampered payload", &sig_bytes).is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_key() {
        let kp1 = EnclaveKeyPair::generate();
        let kp2 = EnclaveKeyPair::generate();

        let payload = b"test message";
        let sig = kp1.sign(payload);
        let sig_bytes: [u8; 64] = sig.to_bytes();
        let wrong_pub = kp2.public_key_bytes();

        assert!(verify_signature(&wrong_pub, payload, &sig_bytes).is_err());
    }
}
