//! # nautilus-enclave
//!
//! Enclave crypto and attestation primitives for AWS Nitro Enclaves.
//!
//! This crate provides the core building blocks that any TEE application needs:
//!
//! - **Ed25519 keygen & signing** — generate a keypair on boot, sign payloads
//! - **NSM attestation** — request attestation documents from the Nitro Secure Module
//! - **Mock support** — deterministic mocks for local development without an enclave
//!
//! # Usage
//!
//! ```rust,no_run
//! use nautilus_enclave::{EnclaveKeyPair, get_attestation};
//!
//! // Generate a fresh Ed25519 keypair (uses NSM entropy inside enclave)
//! let kp = EnclaveKeyPair::generate();
//!
//! // Get an attestation document binding this public key to the enclave image
//! let doc = get_attestation(&kp.public_key_bytes(), b"optional-nonce").unwrap();
//!
//! // Sign any payload
//! let sig = kp.sign(b"hello world");
//! ```

mod crypto;
mod nsm;

pub use crypto::{EnclaveKeyPair, verify_signature};
pub use nsm::{get_attestation, AttestationDoc};
