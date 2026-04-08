// Nautilus Enclave Registration Module
// Handles permissionless registration and management of AWS Nitro enclaves on Sui

module nautilus::enclave;

use std::bcs;
use std::string::String;
use sui::ed25519;
use sui::hash;
use sui::nitro_attestation::NitroAttestationDocument;

use fun to_pcrs as NitroAttestationDocument.to_pcrs;

// Error constants
const EInvalidPCRs: u64 = 0;
const EInvalidConfigVersion: u64 = 1;
const EInvalidCap: u64 = 2;
const EInvalidOwner: u64 = 3;
const EWrongVersion: u64 = 4;
const ECannotDestroyCurrentEnclave: u64 = 5;
const EInvalidSignature: u64 = 6;

// Current contract version for migrations
const VERSION: u64 = 0;

// PCR0: Enclave image file hash
// PCR1: Enclave kernel hash
// PCR2: Enclave application hash
public struct Pcrs(vector<u8>, vector<u8>, vector<u8>) has copy, drop, store;

/// Enclave configuration containing expected PCR values and metadata
/// Generic over witness type T to allow multiple enclave types per application
public struct EnclaveConfig<phantom T> has key {
    id: UID,
    name: String,
    pcrs: Pcrs,
    capability_id: ID,
    version: u64,
    current_enclave_id: Option<ID>,
}

/// A verified enclave instance with its Ed25519 public key
/// Links to a specific EnclaveConfig version for validation
public struct Enclave<phantom T> has key {
    id: UID,
    pk: vector<u8>,
    config_version: u64,
    owner: address,
    version: u64,
}

/// Administrative capability for managing enclave configurations
/// Generic over witness type T to scope permissions per application
public struct Cap<phantom T> has key, store {
    id: UID,
}

/// Intent message wrapper for enclave-signed payloads
/// Prevents replay attacks and adds context to signatures
public struct IntentMessage<T: drop> has copy, drop {
    intent: u8,
    timestamp_ms: u64,
    payload: T,
}

/// Payload type for the sign_name endpoint — matches the tee-app's Rust SignedName struct
/// BCS field order: name (String), message (String)
public struct SignedName has copy, drop {
    name: String,
    message: String,
}

/// One-time witness for Nautilus enclave module initialization
public struct ENCLAVE has drop {}

/// Initialize the Nautilus enclave module - creates Cap and EnclaveConfig
fun init(otw: ENCLAVE, ctx: &mut TxContext) {
    let cap = new_cap(otw, ctx);

    cap.create_enclave_config(
        b"Nautilus Attestation Enclave".to_string(),
        x"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        x"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        x"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ctx,
    );

    transfer::public_transfer(cap, ctx.sender())
}

/// Migration function for contract upgrades
entry fun migrate<T>(
    config: &mut EnclaveConfig<T>,
    cap: &Cap<T>
) {
    assert!(cap.id.to_inner() == config.capability_id, EInvalidCap);
    assert!(config.version < VERSION, EInvalidConfigVersion);
    config.version = VERSION;
}

/// Create a new administrative capability using a witness type
public fun new_cap<T: drop>(_: T, ctx: &mut TxContext): Cap<T> {
    Cap {
        id: object::new(ctx),
    }
}

/// Create a new enclave configuration with expected PCR values
public fun create_enclave_config<T: drop>(
    cap: &Cap<T>,
    name: String,
    pcr0: vector<u8>,
    pcr1: vector<u8>,
    pcr2: vector<u8>,
    ctx: &mut TxContext,
) {
    let enclave_config = EnclaveConfig<T> {
        id: object::new(ctx),
        name,
        pcrs: Pcrs(pcr0, pcr1, pcr2),
        capability_id: cap.id.to_inner(),
        version: 0,
        current_enclave_id: option::none(),
    };

    transfer::share_object(enclave_config);
}

/// Register a new enclave instance using its attestation document
/// Verifies PCRs match the config and extracts the public key
public fun register_enclave<T>(
    enclave_config: &mut EnclaveConfig<T>,
    cap: &Cap<T>,
    document: NitroAttestationDocument,
    ctx: &mut TxContext,
) {
    cap.assert_is_valid_for_config(enclave_config);

    let pk = enclave_config.load_pk(&document);

    let enclave = Enclave<T> {
        id: object::new(ctx),
        pk,
        config_version: enclave_config.version,
        owner: ctx.sender(),
        version: VERSION,
    };

    let enclave_id = object::id(&enclave);
    enclave_config.current_enclave_id = option::some(enclave_id);

    transfer::share_object(enclave);
}

/// Verify a signature from an enclave using intent message format
/// Prevents replay attacks by including intent scope and timestamp
public fun verify_signature<T, P: drop>(
    enclave: &Enclave<T>,
    intent_scope: u8,
    timestamp_ms: u64,
    payload: P,
    signature: &vector<u8>,
): bool {
    let intent_message = create_intent_message(intent_scope, timestamp_ms, payload);
    let payload = bcs::to_bytes(&intent_message);
    return ed25519::ed25519_verify(signature, &enclave.pk, &payload)
}

/// Update the expected PCR values in an enclave configuration
public fun update_pcrs<T: drop>(
    config: &mut EnclaveConfig<T>,
    cap: &Cap<T>,
    pcr0: vector<u8>,
    pcr1: vector<u8>,
    pcr2: vector<u8>,
) {
    cap.assert_is_valid_for_config(config);
    config.pcrs = Pcrs(pcr0, pcr1, pcr2);
    config.current_enclave_id = option::none();
}

/// Update the display name of an enclave configuration
public fun update_name<T: drop>(config: &mut EnclaveConfig<T>, cap: &Cap<T>, name: String) {
    cap.assert_is_valid_for_config(config);
    config.name = name;
}

/// Entry function to verify a SignedName signature from a CLI or PTB call.
/// Aborts with EInvalidSignature if the signature does not match.
entry fun verify_signed_name(
    enclave: &Enclave<ENCLAVE>,
    intent_scope: u8,
    timestamp_ms: u64,
    name: String,
    message: String,
    signature: vector<u8>,
) {
    let payload = SignedName { name, message };
    let valid = verify_signature(enclave, intent_scope, timestamp_ms, payload, &signature);
    assert!(valid, EInvalidSignature);
}

/// Verify a signature over raw bytes (blake2b256 hash, no IntentMessage wrapping).
/// Used by TS template and any endpoint that signs blake2b256(data).
entry fun verify_signed_data<T>(
    enclave: &Enclave<T>,
    data: vector<u8>,
    signature: vector<u8>,
) {
    let hashed = hash::blake2b256(&data);
    let valid = ed25519::ed25519_verify(&signature, &enclave.pk, &hashed);
    assert!(valid, EInvalidSignature);
}

public fun pcr0<T>(config: &EnclaveConfig<T>): &vector<u8> { &config.pcrs.0 }
public fun pcr1<T>(config: &EnclaveConfig<T>): &vector<u8> { &config.pcrs.1 }
public fun pcr2<T>(config: &EnclaveConfig<T>): &vector<u8> { &config.pcrs.2 }
public fun pk<T>(enclave: &Enclave<T>): &vector<u8> { &enclave.pk }

/// Destroy an old enclave instance (admin function)
public fun destroy_old_enclave<T>(
    e: Enclave<T>,
    config: &EnclaveConfig<T>,
    cap: &Cap<T>
) {
    cap.assert_is_valid_for_config(config);

    let enclave_id = object::id(&e);
    if (option::is_some(&config.current_enclave_id)) {
        let current_id = *option::borrow(&config.current_enclave_id);
        assert!(enclave_id != current_id, ECannotDestroyCurrentEnclave);
    };

    assert!(e.config_version < config.version, EInvalidConfigVersion);

    let Enclave { id, .. } = e;
    id.delete();
}

/// Allow enclave owner to destroy their own enclave
public fun deploy_old_enclave_by_owner<T>(e: Enclave<T>, ctx: &mut TxContext) {
    assert!(e.owner == ctx.sender(), EInvalidOwner);
    let Enclave { id, .. } = e;
    id.delete();
}

/// Check if an enclave is the currently active one
public fun is_current_enclave<T>(config: &EnclaveConfig<T>, enclave: &Enclave<T>): bool {
    if (option::is_some(&config.current_enclave_id)) {
        let current_id = *option::borrow(&config.current_enclave_id);
        object::id(enclave) == current_id
    } else {
        false
    }
}

/// Get the current enclave ID if one exists
public fun current_enclave_id<T>(config: &EnclaveConfig<T>): Option<ID> {
    config.current_enclave_id
}

// === Private Helper Functions ===

fun assert_is_valid_for_config<T>(cap: &Cap<T>, enclave_config: &EnclaveConfig<T>) {
    assert!(cap.id.to_inner() == enclave_config.capability_id, EInvalidCap);
}

fun load_pk<T>(enclave_config: &EnclaveConfig<T>, document: &NitroAttestationDocument): vector<u8> {
    assert!(document.to_pcrs() == enclave_config.pcrs, EInvalidPCRs);
    (*document.public_key()).destroy_some()
}

fun to_pcrs(document: &NitroAttestationDocument): Pcrs {
    let pcrs = document.pcrs();
    Pcrs(*pcrs[0].value(), *pcrs[1].value(), *pcrs[2].value())
}

fun create_intent_message<P: drop>(intent: u8, timestamp_ms: u64, payload: P): IntentMessage<P> {
    IntentMessage {
        intent,
        timestamp_ms,
        payload,
    }
}
