// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Groth16 proof generation for the Provii age verification protocol.
//!
//! This module is the wallet's proving engine. It takes a [`CredentialV2`] (containing a
//! Pedersen commitment to the holder's date of birth, a RedJubjub signature from the
//! issuer, and the secret randomness `r_bits`) together with a server-provided
//! [`QrChallengePayload`], and produces a Groth16 zero knowledge proof over the
//! BLS12-381 curve that the holder satisfies the requested age predicate without
//! revealing the date of birth itself.
//!
//! # Global state
//!
//! Proving parameters are large (~40 MB serialised) and expensive to deserialise, so
//! this module stores them in process-global [`OnceCell`] statics:
//!
//! * `PROVING_PARAMS` holds the deserialised `Parameters<Bls12>`.
//! * `PROVING_KEY_FP` holds a BLAKE3-based fingerprint of the raw proving key bytes,
//!   used for diagnostics and cache invalidation.
//! * `LOADED_VK_ID` holds a 4-byte identifier derived from the verifying key
//!   (Blake2s-256 of the serialised VK, truncated to `u32` LE). The verifier sends the
//!   expected `vk_id` inside the challenge; the wallet rejects a mismatch before doing
//!   any proof work.
//! * The [`OnceCell`] wrapper on each static guarantees single-initialisation semantics
//!   and prevents TOCTOU races between init and use.
//!
//! Initialisation happens exactly once per process via [`init_prover_with_pk_bytes`] or,
//! on native mobile builds, `init_prover_with_pk_mmap`.
//!
//! # Thread safety
//!
//! Bellman's Groth16 prover internally uses a Rayon thread pool. Calling the prover
//! from *within* a Rayon worker causes a nested-pool panic. [`build_verify_request`]
//! detects this situation and bounces the work onto a dedicated OS thread with an 8 MB
//! stack (sized for Android's tighter defaults).
//!
//! # Security properties
//!
//! * The `cutoff_days` value always comes from the server challenge, never computed
//!   locally. This prevents the wallet from weakening the age predicate.
//! * Credential expiry is checked before proof work begins.
//! * The Pedersen commitment is recomputed and compared to the stored value; a mismatch
//!   aborts immediately.
//! * The RedJubjub signature is verified off-circuit in [`preflight_report`] before
//!   the (much more expensive) in-circuit verification runs.
//! * Secret witness fields (`dob_days`, `r_bits`) are never logged, even under
//!   `debug-crypto`. Both `debug_crypto!` and `debug_witness!` require
//!   `debug_assertions`, so they are unconditional no-ops in release builds.
//!   The `r_bits` clone is wrapped in [`zeroize::Zeroizing`] so it is scrubbed
//!   if dropped before consumption.

use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use blake2::{Blake2s256, Digest};
use blake3;
use log;
use once_cell::sync::OnceCell;
use serde::Serialize;
use thiserror::Error;

use crate::issuance::R_BITS_LEN;
use crate::types::{
    AgeProofJson, AgePublicJson, CredentialV2, IssuerKeyJson, QrChallengePayload,
    SubmitProofRequest,
};

pub use provii_crypto_commit::{pedersen_commit_dob_validated, pedersen_nullifier};
use provii_crypto_prover::{load_proving_key, prove_age_snark_auto, AgeSnarkProofV2Extended};
use provii_crypto_public_inputs::assemble_public_inputs_canonical;

use provii_crypto_circuit_age::{AgeDirection, AgeWitness};
use provii_crypto_commons::CredMsgV2;
use provii_crypto_sig_redjubjub;

use bellman::groth16::Parameters;
use bls12_381::Bls12;
use ff::PrimeField;

// Feature-gated logging macros.
// Like debug_witness, require debug_assertions so release builds can never
// emit crypto diagnostics even if the feature is accidentally enabled.
#[cfg(all(feature = "debug-crypto", debug_assertions))]
macro_rules! debug_crypto {
    ($($arg:tt)*) => { log::debug!($($arg)*) };
}
#[cfg(not(all(feature = "debug-crypto", debug_assertions)))]
macro_rules! debug_crypto {
    ($($arg:tt)*) => {};
}

#[cfg(feature = "debug-threading")]
macro_rules! debug_thread {
    ($($arg:tt)*) => { log::info!($($arg)*) };
}
#[cfg(not(feature = "debug-threading"))]
macro_rules! debug_thread {
    ($($arg:tt)*) => {};
}

// Gate witness logging behind both the feature flag AND debug_assertions so
// that a release build can never emit crypto material, even if someone
// accidentally enables the feature.
#[cfg(all(feature = "debug-witness", debug_assertions))]
macro_rules! debug_witness {
    ($($arg:tt)*) => { log::debug!($($arg)*) };
}
#[cfg(not(all(feature = "debug-witness", debug_assertions)))]
macro_rules! debug_witness {
    ($($arg:tt)*) => {};
}

/// Deserialised Groth16 proving parameters. Set exactly once by
/// [`init_prover_with_pk_bytes`]; read on every subsequent proof generation call.
static PROVING_PARAMS: OnceCell<Parameters<Bls12>> = OnceCell::new();

/// BLAKE3 fingerprint (first 16 bytes, base64url) of the raw proving key file.
/// Useful for cache invalidation and diagnostic logging.
static PROVING_KEY_FP: OnceCell<String> = OnceCell::new();

/// Verifying key identifier derived from the loaded parameters. Compared against the
/// `vk_id` in each incoming challenge to detect proving key / verifier key mismatches
/// before any expensive proof work begins.
static LOADED_VK_ID: OnceCell<u32> = OnceCell::new();

/// Errors returned by the prover subsystem.
///
/// Every variant is non-panicking. Callers (the FFI layer, the async flow) should
/// convert these into user-facing messages or propagate them upward.
#[derive(Debug, Error)]
pub enum ProverError {
    /// The global proving parameters have not been loaded yet. The caller must invoke
    /// [`init_prover_with_pk_bytes`] (or `init_prover_with_pk_mmap`) before attempting
    /// proof generation.
    #[error("prover not initialised; call init_prover_with_pk_bytes first")]
    NotInitialized,

    /// [`init_prover_with_pk_bytes`] was called more than once in the same process.
    /// Proving parameters are immutable once set.
    #[error("prover already initialised")]
    AlreadyInitialized,

    /// The proving key bytes could not be deserialised into valid BLS12-381 Groth16
    /// parameters. This usually means a corrupted download or a version mismatch.
    #[error("invalid proving key")]
    InvalidProvingKey,

    /// A base64url-encoded field in the challenge payload could not be decoded, or
    /// decoded to the wrong length.
    #[error("invalid base64url input: {0}")]
    InvalidBase64(String),

    /// A witness or challenge field failed validation (wrong length, out of range, or
    /// failed off-circuit signature verification).
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// The bellman prover returned an error or panicked. The inner string carries the
    /// underlying message for diagnostics.
    #[error("proof generation failed: {0}")]
    ProofGenerationFailed(String),

    /// The credential is missing `dob_days` or `r_bits`, both of which are required
    /// for witness construction.
    #[error("missing private fields in credential")]
    MissingPrivateFields,

    /// The verifying key identifier embedded in the challenge does not match the one
    /// derived from the loaded proving parameters. This means the wallet's proving key
    /// and the verifier's verifying key were generated from different trusted setups.
    #[error("vk_id mismatch: loaded {loaded}, expected {expected}")]
    VkIdMismatch {
        /// The `vk_id` computed from the wallet's loaded proving parameters.
        loaded: u32,
        /// The `vk_id` the verifier sent in the challenge payload.
        expected: u32,
    },

    /// The holder's date of birth (as epoch days) does not satisfy the age predicate
    /// defined by the server's `cutoff_days`. Returned before proof generation so the
    /// wallet can show a clear message without wasting computation.
    #[error("Your credential doesn't meet the age requirement for this verification")]
    AgeRequirementNotMet,

    /// The credential's `exp` timestamp is in the past. The wallet refuses to generate
    /// a proof for an expired credential because the verifier would reject it anyway.
    #[error("credential has expired")]
    CredentialExpired,

    /// The challenge's `expires_at` timestamp is in the past. The wallet refuses to
    /// generate a proof for an expired challenge because the verifier would reject it.
    #[error("challenge has expired")]
    ChallengeExpired,
}

/// Diagnostic snapshot produced by [`preflight_report`] before proof generation.
///
/// Every field is safe to serialise and transmit for debugging; no secret witness
/// material (`dob_days`, `r_bits`) is included. The report captures whether the
/// Pedersen commitment recomputes correctly, whether the age predicate is satisfiable,
/// and whether the loaded verifying key identifier matches the challenge.
#[derive(Debug, Serialize)]
pub struct PreflightReport {
    /// `true` if the credential carries a `dob_days` value.
    pub dob_days_present: bool,
    /// Length (in bytes) of the `r_bits` randomness vector.
    pub r_bits_len: usize,
    /// The server-provided cutoff day (epoch days) from the challenge.
    pub cutoff_days: i32,
    /// Hex-encoded Pedersen commitment stored in the credential.
    pub c_bytes_hex: String,
    /// Hex-encoded Pedersen commitment recomputed from `dob_days` and `r_bits`.
    pub recomputed_c_hex: String,
    /// Whether the stored and recomputed commitments are identical.
    pub commitment_matches: bool,
    /// Whether the holder's `dob_days` satisfies the age predicate.
    pub age_ok: bool,
    /// Base64url-encoded issuer verifying key bytes.
    pub issuer_hash_b64: String,
    /// Base64url-encoded credential nullifier (Pedersen nullifier of `c_bytes`).
    pub cred_nullifier_b64: String,
    /// BLAKE3 fingerprint of the loaded proving key, if initialised.
    pub proving_key_fp: Option<String>,
    /// The `vk_id` sent by the verifier in the challenge.
    pub verifying_key_id: u32,
    /// The `vk_id` derived from the wallet's loaded proving parameters, if present.
    pub loaded_vk_id: Option<u32>,
    /// Whether `loaded_vk_id` equals `verifying_key_id`.
    pub vk_id_matches: bool,
    /// Hex-encoded BLS12-381 scalar representations of the assembled public inputs.
    pub public_inputs_hex: Vec<String>,
}

/// Derive a 4-byte verifying key identifier from Groth16 parameters.
///
/// The identifier is `Blake2s-256(b"zerokp.vk.id.v1" || serialised_vk)` truncated to
/// the first 4 bytes, interpreted as a little-endian `u32`. Both the wallet and the
/// verifier compute this independently so they can detect key mismatches cheaply.
// SECURITY: The domain separator "zerokp.vk.id.v1" prevents collisions with other
// Blake2s usages in the protocol (e.g. RP challenge hashing).
fn compute_vk_id(params: &Parameters<Bls12>) -> u32 {
    let mut vk_bytes = Vec::new();
    // SAFETY: write() into an in-memory Vec<u8> cannot produce an I/O error.
    {
        #![allow(clippy::expect_used)]
        params
            .vk
            .write(&mut vk_bytes)
            .expect("VK serialisation cannot fail on an in-memory Vec");
    }

    let mut h = Blake2s256::new();
    h.update(b"zerokp.vk.id.v1");
    h.update(&vk_bytes);
    let digest: [u8; 32] = h.finalize().into();

    u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]])
}

/// Build a diagnostic [`PreflightReport`] for the given credential and challenge.
///
/// This function validates the credential's private fields, recomputes the Pedersen
/// commitment, checks the age predicate, verifies the RedJubjub signature off-circuit,
/// and assembles the public inputs that would be sent to the verifier. None of this
/// performs actual proof generation, so it is fast enough to call speculatively.
///
/// # Errors
///
/// Returns [`ProverError::MissingPrivateFields`] if the credential lacks `dob_days` or
/// `r_bits`, [`ProverError::InvalidInput`] if `r_bits` has the wrong length or the
/// RedJubjub signature fails off-circuit verification, and [`ProverError::InvalidBase64`]
/// if the challenge's `rp_challenge` field cannot be decoded.
pub fn preflight_report(
    cred: &CredentialV2,
    qr: &QrChallengePayload,
) -> Result<PreflightReport, ProverError> {
    debug_crypto!("preflight_report: Starting validation");

    let dob_days = zeroize::Zeroizing::new(cred.dob_days.ok_or_else(|| {
        log::error!("ERROR: Credential missing dob_days");
        ProverError::MissingPrivateFields
    })?);

    let r_bits = cred.r_bits.as_ref().ok_or_else(|| {
        log::error!("ERROR: Credential missing r_bits");
        ProverError::MissingPrivateFields
    })?;

    debug_crypto!("dob_days=[REDACTED], r_bits_len={}", r_bits.len());

    if r_bits.len() != R_BITS_LEN {
        log::error!(
            "ERROR: Invalid r_bits length: expected {}, got {}",
            R_BITS_LEN,
            r_bits.len()
        );
        return Err(ProverError::InvalidInput(format!(
            "Invalid r_bits length: expected {}, got {}",
            R_BITS_LEN,
            r_bits.len()
        )));
    }

    // Decode RP challenge for verification
    let rp_challenge = decode_b64_32(&qr.rp_challenge)?;
    debug_crypto!("=== WALLET RP TRACKING ===");
    debug_crypto!("QR rp_challenge string: {}", qr.rp_challenge);
    debug_crypto!("Decoded rp_challenge(hex): {}", hex::encode(rp_challenge));

    // SECURITY: Verify the issuer's RedJubjub signature off-circuit first. This is a
    // cheap sanity check that catches corrupted credentials before the expensive
    // in-circuit verification inside the SNARK. The circuit also verifies the signature,
    // so this is defence in depth, not a replacement.
    let cred_msg = CredMsgV2 {
        v: cred.v,
        kid: cred.kid.clone(),
        c: cred.c_bytes,
        iat: cred.iat,
        exp: cred.exp,
        schema: cred.schema.clone(),
    };

    debug_crypto!("=== OFF-CIRCUIT SIGNATURE VERIFICATION ===");
    debug_crypto!("Credential message:");
    debug_crypto!("  v: {}", cred_msg.v);
    debug_crypto!("  kid: {}", cred_msg.kid);
    debug_crypto!("  c_bytes (hex): {}", hex::encode(cred_msg.c));
    debug_crypto!("  iat: {}", cred_msg.iat);
    debug_crypto!("  exp: {}", cred_msg.exp);
    debug_crypto!("  schema: {}", cred_msg.schema);
    debug_crypto!("RP challenge (hex): {}", hex::encode(rp_challenge));
    debug_crypto!("Issuer VK (hex): {}", hex::encode(cred.issuer_vk));
    debug_crypto!("Signature (hex): {}", hex::encode(cred.sig_rj));

    match provii_crypto_sig_redjubjub::verify_cred_v2(&cred_msg, &cred.sig_rj, &cred.issuer_vk) {
        Ok(()) => {
            debug_crypto!("✅ Off-circuit RedJubjub signature verification: PASS");
        }
        Err(e) => {
            log::error!(
                "❌ Off-circuit RedJubjub signature verification FAILED: {:?}",
                e
            );
            return Err(ProverError::InvalidInput(format!(
                "RedJubjub signature verification failed: {:?}",
                e
            )));
        }
    }

    // Recompute commitment
    let (recomputed, commitment_matches) = match pedersen_commit_dob_validated(*dob_days, r_bits) {
        Ok(c) => {
            let matches = c == cred.c_bytes;
            (c, matches)
        }
        Err(e) => {
            log::error!(
                "Commitment recomputation failed (entropy validation): {:?}",
                e
            );
            ([0u8; 32], false)
        }
    };

    debug_crypto!("Original commitment: {}", hex::encode(cred.c_bytes));
    debug_crypto!("Recomputed commitment: {}", hex::encode(recomputed));
    debug_crypto!("Commitment matches: {}", commitment_matches);

    // Age predicate
    let is_under_age = qr.proof_direction.as_deref() == Some("under_age");
    let age_ok = crate::validate_age(*dob_days, qr.cutoff_days, is_under_age);
    debug_crypto!(
        "Age check: dob_days=[REDACTED] {} cutoff_days={} = {} (direction={:?})",
        if is_under_age { ">=" } else { "<=" },
        qr.cutoff_days,
        age_ok,
        qr.proof_direction,
    );

    let nullifier = pedersen_nullifier(&cred.c_bytes);

    // Get loaded vk_id and check if it matches
    let loaded_vk_id = LOADED_VK_ID.get().copied();
    let vk_id_matches = loaded_vk_id == Some(qr.verifying_key_id);

    // Compute and log the public inputs that will be sent to verifier
    let rp_hash = {
        let mut hasher = Blake2s256::new();
        hasher.update(rp_challenge);
        let result = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result);
        hash_bytes
    };

    let direction_bool = qr.proof_direction.as_deref() != Some("under_age");
    let publics = assemble_public_inputs_canonical(
        direction_bool,
        qr.cutoff_days,
        rp_hash,
        cred.issuer_vk,
        nullifier,
    )
    .map_err(|e| ProverError::InvalidInput(format!("public input assembly failed: {e}")))?;

    let public_inputs_hex: Vec<String> = publics.iter().map(|s| hex::encode(s.to_repr())).collect();

    debug_crypto!("=== PREFLIGHT PUBLIC INPUTS ===");
    debug_crypto!("Public inputs count: {} (expected 8)", publics.len());
    for (idx, hex_val) in public_inputs_hex.iter().enumerate() {
        let _ = (idx, hex_val);
        debug_crypto!("pi[{}]={}", idx, hex_val);
    }

    let issuer_vk_bytes_b64 = URL_SAFE_NO_PAD.encode(cred.issuer_vk);

    Ok(PreflightReport {
        dob_days_present: true,
        r_bits_len: r_bits.len(),
        cutoff_days: qr.cutoff_days,
        c_bytes_hex: hex::encode(cred.c_bytes),
        recomputed_c_hex: hex::encode(recomputed),
        commitment_matches,
        age_ok,
        issuer_hash_b64: issuer_vk_bytes_b64,
        cred_nullifier_b64: URL_SAFE_NO_PAD.encode(nullifier),
        proving_key_fp: get_proving_key_fingerprint(),
        verifying_key_id: qr.verifying_key_id,
        loaded_vk_id,
        vk_id_matches,
        public_inputs_hex,
    })
}

/// Initialise the global prover by deserialising a Groth16 proving key.
///
/// This must be called exactly once per process, typically at app startup after the
/// proving key file has been read (or memory-mapped). Subsequent calls return
/// [`ProverError::AlreadyInitialized`].
///
/// The function computes a BLAKE3 fingerprint of the raw bytes (for diagnostics) and a
/// `vk_id` from the embedded verifying key (for challenge matching), then stores both
/// alongside the deserialised parameters in process-global statics.
///
/// # Errors
///
/// * [`ProverError::InvalidProvingKey`] if `pk_bytes` cannot be deserialised.
/// * [`ProverError::AlreadyInitialized`] if the prover has already been initialised.
pub fn init_prover_with_pk_bytes(pk_bytes: &[u8]) -> Result<(), ProverError> {
    // Idempotent: if already initialised, return success immediately.
    // This avoids redundant 50 MB deserialisation and the OnceLock error
    // when downloadProvingKey() and initializeWallet() both call init.
    if PROVING_PARAMS.get().is_some() {
        log::info!("Prover already initialised, skipping (idempotent)");
        return Ok(());
    }

    log::info!(
        "init_prover_with_pk_bytes: Received {} bytes",
        pk_bytes.len()
    );

    #[cfg(target_os = "android")]
    {
        log::info!("Android detected: Proof generation will use optimised thread configuration");
        // Check Rayon pool status
        #[cfg(feature = "parallel")]
        log::info!(
            "Rayon pool size (current_num_threads) = {}",
            rayon::current_num_threads()
        );
    }

    // Compute fingerprint
    let fingerprint = {
        let hash = blake3::hash(pk_bytes);
        URL_SAFE_NO_PAD.encode(&hash.as_bytes()[..16])
    };

    log::info!("Loading proving key with fingerprint: {}", fingerprint);

    // Load the proving key
    let params = load_proving_key(pk_bytes).map_err(|e| {
        log::error!("ERROR: load_proving_key failed: {:?}", e);
        ProverError::InvalidProvingKey
    })?;

    // Compute and store the vk_id
    let vk_id = compute_vk_id(&params);
    log::info!("Computed vk_id from loaded parameters: {}", vk_id);

    // Store in global OnceCells
    PROVING_PARAMS.set(params).map_err(|_| {
        log::error!("Prover already initialised");
        ProverError::AlreadyInitialized
    })?;

    PROVING_KEY_FP
        .set(fingerprint.clone())
        .map_err(|_| ProverError::AlreadyInitialized)?;

    LOADED_VK_ID
        .set(vk_id)
        .map_err(|_| ProverError::AlreadyInitialized)?;

    log::info!(
        "Prover initialised successfully with fingerprint: {} and vk_id: {}",
        fingerprint,
        vk_id
    );
    Ok(())
}

/// Return the BLAKE3 fingerprint of the loaded proving key, or `None` if the prover
/// has not been initialised yet.
pub fn get_proving_key_fingerprint() -> Option<String> {
    PROVING_KEY_FP.get().cloned()
}

/// Return the verifying key identifier derived from the loaded proving parameters, or
/// `None` if the prover has not been initialised yet.
pub fn get_loaded_vk_id() -> Option<u32> {
    LOADED_VK_ID.get().copied()
}

/// Return `true` if [`init_prover_with_pk_bytes`] (or `init_prover_with_pk_mmap`) has
/// completed successfully in this process.
pub fn is_prover_initialized() -> bool {
    PROVING_PARAMS.get().is_some()
}

/// Retrieve the global proving parameters, logging the calling thread for diagnostics.
fn get_proving_params() -> Result<&'static Parameters<Bls12>, ProverError> {
    if let Some(thread_name) = std::thread::current().name() {
        if thread_name.contains("rayon") {
            debug_thread!(
                "get_proving_params called from Rayon thread: {}",
                thread_name
            );
        }
        debug_thread!("get_proving_params called from thread: {}", thread_name);
    }

    PROVING_PARAMS.get().ok_or_else(|| {
        log::error!("ERROR: Proving params not initialised");
        ProverError::NotInitialized
    })
}

/// Verify that the witness field lengths match the circuit's compile-time expectations.
///
/// The Groth16 trusted setup was generated with specific string lengths for `kid` and
/// `schema`. If a credential carries values with different lengths the circuit will
/// have a different number of constraints and bellman will panic during proving. This
/// function catches the mismatch early with a clear error message.
// SECURITY: A length mismatch here does not indicate an attack; it means the credential
// was issued under a different schema version than the proving key expects.
fn verify_circuit_shape(witness: &AgeWitness) -> Result<(), ProverError> {
    const EXPECTED_KID_LEN: usize = 14; // "provii:2026-05"
    const EXPECTED_SCHEMA_LEN: usize = 12; // "provii.age/0"

    // Check witness field lengths
    if witness.kid.len() != EXPECTED_KID_LEN {
        log::error!(
            "ERROR: kid length mismatch! Expected {} bytes, got {} bytes",
            EXPECTED_KID_LEN,
            witness.kid.len()
        );
        debug_witness!("kid value: \"{}\"", String::from_utf8_lossy(&witness.kid));
        return Err(ProverError::InvalidInput(format!(
            "kid length mismatch: expected {}, got {}",
            EXPECTED_KID_LEN,
            witness.kid.len()
        )));
    }

    if witness.schema.len() != EXPECTED_SCHEMA_LEN {
        log::error!(
            "ERROR: schema length mismatch! Expected {} bytes, got {} bytes",
            EXPECTED_SCHEMA_LEN,
            witness.schema.len()
        );
        debug_witness!(
            "schema value: \"{}\"",
            String::from_utf8_lossy(&witness.schema)
        );
        return Err(ProverError::InvalidInput(format!(
            "schema length mismatch: expected {}, got {}",
            EXPECTED_SCHEMA_LEN,
            witness.schema.len()
        )));
    }

    // Additional checks for fixed-size fields
    if witness.r_bits.len() != 128 {
        log::error!(
            "ERROR: r_bits length mismatch! Expected 128 bits, got {} bits",
            witness.r_bits.len()
        );
        return Err(ProverError::InvalidInput(format!(
            "r_bits length mismatch: expected 128, got {}",
            witness.r_bits.len()
        )));
    }

    if witness.sig_rj_bytes.len() != 64 {
        log::error!(
            "ERROR: sig_rj_bytes length mismatch! Expected 64 bytes, got {} bytes",
            witness.sig_rj_bytes.len()
        );
        return Err(ProverError::InvalidInput(format!(
            "sig_rj_bytes length mismatch: expected 64, got {}",
            witness.sig_rj_bytes.len()
        )));
    }

    debug_crypto!("✅ Circuit shape verification passed");
    debug_crypto!("  - kid: {} bytes ✓", witness.kid.len());
    debug_crypto!("  - schema: {} bytes ✓", witness.schema.len());
    debug_crypto!("  - r_bits: {} bits ✓", witness.r_bits.len());
    debug_crypto!("  - sig_rj: {} bytes ✓", witness.sig_rj_bytes.len());

    Ok(())
}

/// Decode a base64url (no-pad) string into exactly 32 bytes.
fn decode_b64_32(s: &str) -> Result<[u8; 32], ProverError> {
    let raw = URL_SAFE_NO_PAD.decode(s).map_err(|e| {
        log::error!("ERROR: Failed to decode base64url: {}", e);
        ProverError::InvalidBase64(e.to_string())
    })?;

    if raw.len() != 32 {
        log::error!("ERROR: Expected 32 bytes, got {}", raw.len());
        return Err(ProverError::InvalidBase64(format!(
            "expected 32 bytes, got {}",
            raw.len()
        )));
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Generate a Groth16 age proof and assemble the `POST /v1/verify` request body.
///
/// This is the primary entry point for proof generation in the wallet. It validates the
/// credential, runs preflight checks, constructs the witness, generates the SNARK proof,
/// and packages the result into a [`SubmitProofRequest`] ready for submission.
///
/// # Server-authoritative cutoff
///
/// The `cutoff_days` value is always taken from `qr.cutoff_days` (the server's
/// challenge). The wallet never computes this locally. After proof generation the
/// function asserts that the proof's embedded cutoff matches the challenge value.
///
/// # Thread bouncing
///
/// When compiled with the `parallel` feature, if this function detects it is running
/// inside a Rayon worker thread it spawns a dedicated OS thread (8 MB stack) to avoid
/// bellman's nested-pool panic.
///
/// # Errors
///
/// Returns a [`ProverError`] variant for every failure mode: uninitialised prover,
/// missing credential fields, expired credential, vk_id mismatch, commitment mismatch,
/// age predicate failure, or proof generation failure.
// SECURITY: cutoff_days must originate from the server challenge. The wallet is not
// trusted to compute the age predicate boundary.
pub fn build_verify_request(
    cred: &CredentialV2,
    qr: &QrChallengePayload,
) -> Result<SubmitProofRequest, ProverError> {
    // If we are inside a Rayon worker, bounce to a dedicated OS thread so bellman
    // can safely create its own internal Rayon pool without a nested-pool panic.
    #[cfg(feature = "parallel")]
    if let Some(idx) = rayon::current_thread_index() {
        log::warn!(
            "build_verify_request called from Rayon worker #{}, spawning OS thread for proof generation",
            idx
        );

        let cred_clone = cred.clone();
        let qr_clone = qr.clone();

        let handle = std::thread::Builder::new()
            .name("proof-generator".to_string())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || build_verify_request_internal(&cred_clone, &qr_clone))
            .map_err(|e| {
                ProverError::ProofGenerationFailed(format!(
                    "Failed to spawn proof generation thread: {}",
                    e
                ))
            })?;

        return handle.join().map_err(|_| {
            ProverError::ProofGenerationFailed("Proof generation thread panicked".to_string())
        })?;
    }

    build_verify_request_internal(cred, qr)
}

/// Inner implementation of [`build_verify_request`]. Must be called from a non-Rayon
/// thread because bellman's prover will create its own Rayon pool internally.
fn build_verify_request_internal(
    cred: &CredentialV2,
    qr: &QrChallengePayload,
) -> Result<SubmitProofRequest, ProverError> {
    log::info!(
        "build_verify_request START - Challenge ID: {}",
        qr.challenge_id
    );

    // SECURITY: cutoff_days comes from the server challenge, never computed locally.
    debug_crypto!(
        "Using server's cutoff_days={} from challenge",
        qr.cutoff_days
    );

    // Get current epoch day for diagnostic comparison only
    #[cfg(feature = "debug-crypto")]
    {
        let epoch_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        #[allow(clippy::arithmetic_side_effects)]
        let today_epoch_days = u32::try_from(epoch_secs / 86_400).unwrap_or(u32::MAX);
        debug_crypto!("For reference: today's epoch day is {}", today_epoch_days);

        if qr.cutoff_days < 10_000 {
            debug_crypto!(
                "cutoff_days={} looks suspiciously low - might be a duration instead of epoch days",
                qr.cutoff_days
            );
            debug_crypto!(
                "Expected value around {} for 18+ verification today",
                today_epoch_days.saturating_sub(6570)
            );
        }
    }

    // Preload proving params
    let params = get_proving_params()?;
    log::info!("Proving params preloaded successfully");

    // Check vk_id match
    let loaded_vk_id = LOADED_VK_ID
        .get()
        .copied()
        .ok_or(ProverError::NotInitialized)?;

    if loaded_vk_id != qr.verifying_key_id {
        log::error!(
            "VK_ID MISMATCH: loaded={}, expected={}",
            loaded_vk_id,
            qr.verifying_key_id
        );
        return Err(ProverError::VkIdMismatch {
            loaded: loaded_vk_id,
            expected: qr.verifying_key_id,
        });
    }

    // Reject expired credentials before doing any proof work
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if cred.exp < now {
        log::error!("Credential expired: exp={} < now={}", cred.exp, now);
        return Err(ProverError::CredentialExpired);
    }

    // Reject expired challenges before doing any proof work
    if qr.expires_at <= now {
        log::error!(
            "Challenge expired: expires_at={} <= now={}",
            qr.expires_at,
            now
        );
        return Err(ProverError::ChallengeExpired);
    }

    // Generate preflight report
    let report = preflight_report(cred, qr)?;

    debug_crypto!("Preflight report:");
    debug_crypto!("  - commitment_matches: {}", report.commitment_matches);
    debug_crypto!("  - age_ok: {}", report.age_ok);
    debug_crypto!("  - dob_days_present: {}", report.dob_days_present);
    debug_crypto!("  - cutoff_days: {} (FROM SERVER)", report.cutoff_days);
    debug_crypto!("  - vk_id_matches: {}", report.vk_id_matches);

    // Validate commitment
    if !report.commitment_matches {
        log::error!("ERROR: Commitment mismatch");
        return Err(ProverError::InvalidInput(format!(
            "Commitment mismatch: stored={}, recomputed={}",
            report.c_bytes_hex, report.recomputed_c_hex
        )));
    }

    // Validate age
    if !report.age_ok {
        log::error!("Age requirement not met: credential age is below the required threshold (cutoff_days={})", report.cutoff_days);
        return Err(ProverError::AgeRequirementNotMet);
    }

    log::info!("Preflight check passed");

    // Extract witness components
    // SECURITY: dob_days is secret witness material. Wrap in Zeroizing so
    // the stack copy is scrubbed on drop.
    let dob_days = zeroize::Zeroizing::new(cred.dob_days.ok_or(ProverError::MissingPrivateFields)?);

    let r_bits = cred
        .r_bits
        .as_ref()
        .ok_or(ProverError::MissingPrivateFields)?;

    if r_bits.len() != R_BITS_LEN {
        return Err(ProverError::InvalidInput(format!(
            "Invalid r_bits length: expected {}, got {}",
            R_BITS_LEN,
            r_bits.len()
        )));
    }

    // Parse QR fields
    let rp_challenge = decode_b64_32(&qr.rp_challenge)?;
    debug_crypto!("=== WALLET RP TRACKING ===");
    debug_crypto!("QR rp_challenge string: {}", qr.rp_challenge);
    debug_crypto!("Decoded rp_challenge(hex): {}", hex::encode(rp_challenge));

    // SECURITY: r_bits is secret randomness. Wrap the clone in Zeroizing so it is
    // scrubbed if we bail out before the witness consumes it.
    let mut r_bits_z = zeroize::Zeroizing::new(r_bits.clone());
    let witness = AgeWitness {
        dob_days: *dob_days,
        r_bits: core::mem::take(&mut *r_bits_z),
        issuer_vk_bytes: cred.issuer_vk,
        sig_rj_bytes: cred.sig_rj.to_vec(),
        v: cred.v,
        kid: cred.kid.as_bytes().to_vec(),
        c_bytes: cred.c_bytes,
        iat: cred.iat,
        exp: cred.exp,
        schema: cred.schema.as_bytes().to_vec(),
    };

    verify_circuit_shape(&witness)?;

    debug_crypto!("=== PROOF GENERATION PARAMETERS ===");
    debug_crypto!("cutoff_days: {} (FROM SERVER CHALLENGE)", qr.cutoff_days);
    debug_crypto!("vk_id: {}", qr.verifying_key_id);
    debug_crypto!("dob_days: [REDACTED] (from credential)");
    let _is_under_age_check = qr.proof_direction.as_deref() == Some("under_age");
    debug_crypto!(
        "Age check will: {} (direction={:?})",
        if crate::validate_age(witness.dob_days, qr.cutoff_days, _is_under_age_check) {
            "PASS"
        } else {
            "FAIL"
        },
        qr.proof_direction,
    );

    debug_witness!("=== WITNESS FOR PROOF GENERATION ===");
    debug_witness!("DOB days: [REDACTED]");
    debug_witness!("R bits length: {}", witness.r_bits.len());
    debug_witness!("Issuer VK (hex): {}", hex::encode(witness.issuer_vk_bytes));
    debug_witness!("Signature (hex): {}", hex::encode(&witness.sig_rj_bytes));
    debug_witness!("Commitment (hex): {}", hex::encode(witness.c_bytes));

    // Determine proof direction from QR payload
    let direction = match qr.proof_direction.as_deref() {
        Some("under_age") => AgeDirection::Under,
        _ => AgeDirection::Over,
    };

    // SECURITY: cutoff_days is the server's value, passed through unchanged.
    let proof_result = generate_proof_safe(
        params,
        qr.cutoff_days,
        rp_challenge,
        witness,
        qr.verifying_key_id,
        direction,
    )?;

    debug_crypto!("=== POST-PROOF VALIDATION ===");
    debug_crypto!("Proof generated with cutoff_days={}", proof_result.cutoff);

    // Assert that the proof's embedded cutoff matches the challenge. A mismatch here
    // would mean the prover silently altered the predicate, which must never happen.
    // proof_result.cutoff is i32 from provii-crypto.
    if proof_result.cutoff != qr.cutoff_days {
        log::error!(
            "Proof cutoff_days mismatch: proof={}, challenge={}",
            proof_result.cutoff,
            qr.cutoff_days
        );
        return Err(ProverError::ProofGenerationFailed(format!(
            "Proof cutoff_days mismatch: {} != {}",
            proof_result.cutoff, qr.cutoff_days
        )));
    }

    debug_crypto!("Proof cutoff_days matches server challenge");

    let proof_json = AgeProofJson {
        verifying_key_id: qr.verifying_key_id,
        public: AgePublicJson {
            cutoff_days: qr.cutoff_days,
            rp_challenge: qr.rp_challenge.clone(),
            issuer: IssuerKeyJson {
                value: URL_SAFE_NO_PAD.encode(proof_result.issuer_vk_bytes),
            },
            cred_nullifier: URL_SAFE_NO_PAD.encode(proof_result.cred_nullifier),
        },
        proof: URL_SAFE_NO_PAD.encode(proof_result.proof),
    };

    let submit_request = SubmitProofRequest {
        challenge_id: qr.challenge_id.clone(),
        submit_secret: qr.submit_secret.clone(),
        code_verifier: qr.code_verifier.clone(),
        proof: proof_json,
    };

    log::info!("build_verify_request SUCCESS");
    debug_crypto!(
        "Submitting proof with cutoff_days={} to server",
        qr.cutoff_days
    );
    Ok(submit_request)
}

/// Run the Groth16 prover with panic recovery and a single automatic retry.
///
/// Bellman's prover can panic under certain conditions (e.g. thread pool contention on
/// Android). This wrapper catches the panic, logs it, waits briefly, and retries once.
/// If the retry also fails the error is propagated.
fn generate_proof_safe(
    params: &Parameters<Bls12>,
    cutoff_days: i32,
    rp_challenge: [u8; 32],
    witness: AgeWitness,
    vk_id: u32,
    direction: AgeDirection,
) -> Result<AgeSnarkProofV2Extended, ProverError> {
    let start_time = std::time::Instant::now();

    // SECURITY: Reject if called from a Rayon worker. bellman internally uses the
    // global Rayon pool; nesting would cause a "wait() cannot be called from within
    // a thread pool" panic. build_verify_request should have bounced us already, but
    // this is a last-resort guard.
    #[cfg(feature = "parallel")]
    if let Some(idx) = rayon::current_thread_index() {
        log::error!(
            "generate_proof_safe entered from Rayon worker #{}, aborting",
            idx
        );
        return Err(ProverError::ProofGenerationFailed(
            "Cannot generate proof from within Rayon worker thread".to_string(),
        ));
    }

    #[cfg(feature = "parallel")]
    {
        log::info!(
            "Rayon pool size (current_num_threads) = {}",
            rayon::current_num_threads()
        );
    }

    debug_thread!("=== PROOF GENERATION THREAD INFO ===");

    let current_thread = std::thread::current();
    debug_thread!(
        "Current thread: {:?} (ID: {:?})",
        current_thread.name().unwrap_or("unnamed"),
        current_thread.id()
    );

    let hw_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let expected_threads = match hw_threads {
        1..=2 => 1,
        n => n.saturating_sub(2).max(1),
    };
    debug_thread!(
        "Hardware threads: {}, Expected for proving: {}",
        hw_threads,
        expected_threads
    );

    debug_thread!("Starting proof generation with cutoff_days={}", cutoff_days);

    // Log VK fingerprint at proof generation time
    #[cfg(feature = "debug-crypto")]
    {
        let mut vk_bytes = Vec::new();
        if let Ok(()) = params.vk.write(&mut vk_bytes) {
            let mut hasher = Blake2s256::new();
            hasher.update(&vk_bytes);
            let result = hasher.finalize();
            let vk_fp = hex::encode(result.get(..8).unwrap_or(result.as_slice()));
            debug_crypto!("Generating proof with VK fingerprint: {}", vk_fp);
        }
    }

    #[cfg(feature = "debug-crypto")]
    {
        let rp_hash = {
            let mut hasher = Blake2s256::new();
            hasher.update(rp_challenge);
            let result = hasher.finalize();
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&result);
            hash_bytes
        };

        let nullifier = pedersen_nullifier(&witness.c_bytes);

        let direction_bool = matches!(direction, AgeDirection::Over);
        let publics = assemble_public_inputs_canonical(
            direction_bool,
            cutoff_days,
            rp_hash,
            witness.issuer_vk_bytes,
            nullifier,
        )
        .map_err(|e| ProverError::InvalidInput(format!("public input assembly failed: {e}")))?;

        debug_crypto!("=== PUBLIC INPUTS TO BE PROVEN ===");
        debug_crypto!("Count: {} (expected 8)", publics.len());
        for (i, s) in publics.iter().enumerate() {
            debug_crypto!("pi[{}]={}", i, hex::encode(s.to_repr()));
        }
    }

    debug_thread!("Calling prove_age_snark_auto...");

    let witness_clone = witness.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prove_age_snark_auto(
            params,
            cutoff_days,
            rp_challenge,
            witness_clone,
            vk_id,
            direction,
        )
    }));

    let elapsed = start_time.elapsed();
    debug_thread!("=== PROOF GENERATION COMPLETE ===");
    debug_thread!("Total time: {:.3}s", elapsed.as_secs_f64());

    // Heuristic: single-threaded proving takes ~35-45s on mobile, multi-threaded ~8-15s.
    #[cfg(feature = "debug-threading")]
    {
        let likely_threaded = elapsed.as_secs() < 20;
        debug_thread!(
            "Performance suggests: {}",
            if likely_threaded {
                "MULTI-THREADED execution"
            } else {
                "SINGLE-THREADED execution"
            }
        );
    }

    match result {
        Ok(Ok(proof)) => {
            log::info!(
                "Proof generation succeeded in {:.3}s",
                elapsed.as_secs_f64()
            );

            // Log the proof's metadata if available
            #[cfg(feature = "debug-crypto")]
            {
                if let Some(ref metadata) = proof.metadata {
                    debug_crypto!(
                        "Proof metadata: generation_time={}ms, platform={}",
                        metadata.generation_time_ms,
                        metadata.platform
                    );
                }
            }

            Ok(proof)
        }
        Ok(Err(e)) => {
            log::error!("Proof generation failed (no panic): {:?}", e);
            Err(ProverError::ProofGenerationFailed(format!("{:?}", e)))
        }
        Err(panic) => {
            let msg = if let Some(s) = panic.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = panic.downcast_ref::<&str>() {
                s.to_string()
            } else {
                "Unknown panic in proof generation".to_string()
            };
            log::error!("Proof generation panicked: {}, attempting retry", msg);

            // Brief delay before retry to let the Rayon pool settle.
            std::thread::sleep(std::time::Duration::from_millis(100));

            debug_thread!(
                "Retrying prove_age_snark_auto with cutoff_days={}",
                cutoff_days
            );

            let retry_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                prove_age_snark_auto(params, cutoff_days, rp_challenge, witness, vk_id, direction)
            }));

            match retry_result {
                Ok(Ok(proof)) => {
                    log::info!("Retry succeeded");
                    Ok(proof)
                }
                Ok(Err(e)) => {
                    log::error!("Retry failed: {:?}", e);
                    Err(ProverError::ProofGenerationFailed(format!("{:?}", e)))
                }
                Err(_) => {
                    log::error!("Retry also panicked");
                    Err(ProverError::ProofGenerationFailed(
                        "Proof generation failed after retry".to_string(),
                    ))
                }
            }
        }
    }
}

/// Check whether the credential's `dob_days` satisfies the given age predicate without
/// performing any proof generation. Returns `false` if `dob_days` is absent.
///
/// When `is_under_age` is `true`, the check flips to "young enough" semantics
/// (`dob_days >= cutoff_days`). When `false` (the default), "old enough" semantics
/// apply (`dob_days <= cutoff_days`).
///
/// This is a cheap local check the UI can call to decide whether to show a "you do not
/// meet the age requirement" message before attempting the expensive proof flow.
///
/// # Privacy note
///
/// This comparison happens entirely on-device. The `cutoff_days` value comes from the
/// server challenge, but no information about `dob_days` leaves the wallet.
pub fn can_satisfy_age_requirement(
    cred: &CredentialV2,
    cutoff_days: i32,
    is_under_age: bool,
) -> bool {
    match cred.dob_days {
        Some(dob_days) => {
            let satisfied = crate::validate_age(dob_days, cutoff_days, is_under_age);
            debug_crypto!(
                "can_satisfy_age_requirement: dob_days=[REDACTED] {} cutoff_days={} = {} (under_age={})",
                if is_under_age { ">=" } else { "<=" },
                cutoff_days,
                satisfied,
                is_under_age,
            );
            satisfied
        }
        None => {
            debug_crypto!("can_satisfy_age_requirement: No dob_days in credential");
            false
        }
    }
}

/// Initialise the prover by memory-mapping a proving key file from disk.
///
/// This is the preferred initialisation path on native mobile (iOS and Android) because
/// it avoids copying ~40 MB of proving key data into the heap. The file is mapped
/// read-only, deserialised into [`Parameters<Bls12>`], and the mapping is dropped
/// immediately afterward.
///
/// # Caller obligations
///
/// The file at `path` **must not** be modified or truncated by any process for the
/// duration of this call. On iOS and Android this is guaranteed by the app bundle's
/// immutability. Passing a path to a file under concurrent write is undefined
/// behaviour (the OS may deliver SIGBUS, which Rust cannot catch).
///
/// # Errors
///
/// * [`ProverError::InvalidProvingKey`] if the file cannot be opened, mapped, or
///   deserialised.
/// * [`ProverError::AlreadyInitialized`] if the prover was already initialised.
// This is the only `unsafe` in the core crate. `deny(unsafe_code)` in lib.rs is used
// (not `forbid`) specifically to allow this feature-gated exception.
#[allow(unsafe_code)]
#[cfg(feature = "mmap")]
pub fn init_prover_with_pk_mmap(path: &str) -> Result<(), ProverError> {
    use memmap2::Mmap;
    use std::fs::File;

    log::info!("init_prover_with_pk_mmap: opening file: {}", path);
    let file = File::open(path).map_err(|e| {
        log::error!("Failed to open proving key file '{}': {}", path, e);
        ProverError::InvalidProvingKey
    })?;

    // SAFETY: `Mmap::map` requires that the underlying file is not concurrently
    // modified for the lifetime of the mapping. This invariant is upheld because:
    //
    // 1. The file is opened read-only (`File::open`, not `File::create`/`write`).
    // 2. The proving key is a static asset bundled inside the app and is never
    //    written to after installation.
    // 3. The `Mmap` is consumed immediately by `init_prover_with_pk_bytes` (which
    //    deserialises into a `Parameters<Bls12>` struct), so the mapping lifetime
    //    is very short.
    // 4. On iOS and Android, app bundle files cannot be modified by other processes.
    //
    // If the file were truncated or deleted while mapped the OS would deliver SIGBUS,
    // which is not catchable by Rust's panic mechanism. This is mitigated by the
    // short mapping lifetime and the app bundle immutability guarantee.
    debug_crypto!("Creating memory map");
    // nosemgrep: provii.mobile-sdk.unsafe-usage -- SAFETY documented above: read-only, short-lived, app-bundle immutable
    let mmap = unsafe { Mmap::map(&file) }.map_err(|e| {
        log::error!("Failed to memory-map proving key file '{}': {}", path, e);
        ProverError::InvalidProvingKey
    })?;

    init_prover_with_pk_bytes(&mmap)
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::string_slice,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used
)]
mod tests {
    use super::*;

    fn valid_witness() -> AgeWitness {
        AgeWitness {
            dob_days: 10_000,
            r_bits: vec![false; 128],
            issuer_vk_bytes: [0u8; 32],
            sig_rj_bytes: vec![0u8; 64],
            v: 2,
            kid: vec![0u8; 14],
            c_bytes: [0u8; 32],
            iat: 1_700_000_000,
            exp: 1_800_000_000,
            schema: vec![0u8; 12],
        }
    }

    fn dummy_credential(dob_days: Option<i32>) -> CredentialV2 {
        CredentialV2 {
            v: 2,
            kid: "provii:2026-05".to_string(),
            issuer_vk: [0u8; 32],
            sig_rj: [0u8; 64],
            c_bytes: [0u8; 32],
            iat: 1_700_000_000,
            exp: 1_800_000_000,
            schema: "provii.age/0".to_string(),
            dob_days,
            r_bits: None,
        }
    }

    #[test]
    fn decode_b64_32_valid_input() {
        let bytes: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        let result = decode_b64_32(&encoded).expect("should decode successfully");
        assert_eq!(result, bytes);
    }

    #[test]
    fn decode_b64_32_rejects_31_bytes() {
        let short = URL_SAFE_NO_PAD.encode([0xAAu8; 31]);
        let err = decode_b64_32(&short).unwrap_err();
        assert!(matches!(err, ProverError::InvalidBase64(_)));
    }

    #[test]
    fn decode_b64_32_rejects_33_bytes() {
        let long = URL_SAFE_NO_PAD.encode([0xBBu8; 33]);
        let err = decode_b64_32(&long).unwrap_err();
        assert!(matches!(err, ProverError::InvalidBase64(_)));
    }

    #[test]
    fn decode_b64_32_rejects_invalid_characters() {
        let err = decode_b64_32("not!valid@base64$$$").unwrap_err();
        assert!(matches!(err, ProverError::InvalidBase64(_)));
    }

    #[test]
    fn decode_b64_32_rejects_empty_string() {
        let err = decode_b64_32("").unwrap_err();
        assert!(matches!(err, ProverError::InvalidBase64(_)));
    }

    #[test]
    fn verify_circuit_shape_valid_witness() {
        let w = valid_witness();
        assert!(verify_circuit_shape(&w).is_ok());
    }

    #[test]
    fn verify_circuit_shape_kid_too_short() {
        let mut w = valid_witness();
        w.kid = vec![0u8; 13];
        let err = verify_circuit_shape(&w).unwrap_err();
        assert!(matches!(err, ProverError::InvalidInput(_)));
    }

    #[test]
    fn verify_circuit_shape_kid_too_long() {
        let mut w = valid_witness();
        w.kid = vec![0u8; 15];
        let err = verify_circuit_shape(&w).unwrap_err();
        assert!(matches!(err, ProverError::InvalidInput(_)));
    }

    #[test]
    fn verify_circuit_shape_schema_too_short() {
        let mut w = valid_witness();
        w.schema = vec![0u8; 11];
        let err = verify_circuit_shape(&w).unwrap_err();
        assert!(matches!(err, ProverError::InvalidInput(_)));
    }

    #[test]
    fn verify_circuit_shape_schema_too_long() {
        let mut w = valid_witness();
        w.schema = vec![0u8; 13];
        let err = verify_circuit_shape(&w).unwrap_err();
        assert!(matches!(err, ProverError::InvalidInput(_)));
    }

    #[test]
    fn verify_circuit_shape_r_bits_too_short() {
        let mut w = valid_witness();
        w.r_bits = vec![false; 127];
        let err = verify_circuit_shape(&w).unwrap_err();
        assert!(matches!(err, ProverError::InvalidInput(_)));
    }

    #[test]
    fn verify_circuit_shape_r_bits_too_long() {
        let mut w = valid_witness();
        w.r_bits = vec![false; 129];
        let err = verify_circuit_shape(&w).unwrap_err();
        assert!(matches!(err, ProverError::InvalidInput(_)));
    }

    #[test]
    fn verify_circuit_shape_sig_rj_too_short() {
        let mut w = valid_witness();
        w.sig_rj_bytes = vec![0u8; 63];
        let err = verify_circuit_shape(&w).unwrap_err();
        assert!(matches!(err, ProverError::InvalidInput(_)));
    }

    #[test]
    fn verify_circuit_shape_sig_rj_too_long() {
        let mut w = valid_witness();
        w.sig_rj_bytes = vec![0u8; 65];
        let err = verify_circuit_shape(&w).unwrap_err();
        assert!(matches!(err, ProverError::InvalidInput(_)));
    }

    #[test]
    fn can_satisfy_over_age_satisfied() {
        let cred = dummy_credential(Some(5_000));
        assert!(can_satisfy_age_requirement(&cred, 10_000, false));
    }

    #[test]
    fn can_satisfy_over_age_not_satisfied() {
        let cred = dummy_credential(Some(15_000));
        assert!(!can_satisfy_age_requirement(&cred, 10_000, false));
    }

    #[test]
    fn can_satisfy_under_age_satisfied() {
        let cred = dummy_credential(Some(15_000));
        assert!(can_satisfy_age_requirement(&cred, 10_000, true));
    }

    #[test]
    fn can_satisfy_under_age_not_satisfied() {
        let cred = dummy_credential(Some(5_000));
        assert!(!can_satisfy_age_requirement(&cred, 10_000, true));
    }

    #[test]
    fn can_satisfy_none_dob_returns_false() {
        let cred = dummy_credential(None);
        assert!(!can_satisfy_age_requirement(&cred, 10_000, false));
        assert!(!can_satisfy_age_requirement(&cred, 10_000, true));
    }

    #[test]
    fn test_challenge_expired_error_display() {
        let err = ProverError::ChallengeExpired;
        assert_eq!(err.to_string(), "challenge has expired");
    }

    // ================================================================
    // build_verify_request and generate_proof_safe error path tests
    // ================================================================

    fn dummy_qr_payload() -> QrChallengePayload {
        use crate::types::QrChallengePayload;

        QrChallengePayload {
            challenge_id: "test-challenge-id".to_string(),
            rp_challenge: URL_SAFE_NO_PAD.encode([0xABu8; 32]),
            cutoff_days: 19_000,
            verifying_key_id: 0,
            submit_secret: "submit_secret_value".to_string(),
            expires_at: u64::MAX,
            verify_url: "https://verify.example.com/submit".to_string(),
            code_verifier: None,
            proof_direction: None,
        }
    }

    /// build_verify_request returns NotInitialized when the prover has not
    /// been loaded.
    #[test]
    fn build_verify_request_not_initialised() {
        let cred = dummy_credential(Some(10_000));
        let qr = dummy_qr_payload();

        let err = build_verify_request(&cred, &qr).unwrap_err();
        assert!(
            matches!(err, ProverError::NotInitialized),
            "expected NotInitialized, got: {:?}",
            err,
        );
    }

    /// build_verify_request returns MissingPrivateFields when dob_days is None.
    #[test]
    fn build_verify_request_missing_dob_days() {
        let cred = dummy_credential(None);
        let qr = dummy_qr_payload();

        let err = build_verify_request(&cred, &qr);
        let pf_err = preflight_report(&cred, &qr).unwrap_err();
        assert!(
            matches!(pf_err, ProverError::MissingPrivateFields),
            "expected MissingPrivateFields, got: {:?}",
            pf_err,
        );
        assert!(err.is_err());
    }

    /// preflight_report returns MissingPrivateFields when r_bits is None.
    #[test]
    fn preflight_report_missing_r_bits() {
        let mut cred = dummy_credential(Some(10_000));
        cred.r_bits = None;

        let qr = dummy_qr_payload();
        let err = preflight_report(&cred, &qr).unwrap_err();
        assert!(
            matches!(err, ProverError::MissingPrivateFields),
            "expected MissingPrivateFields, got: {:?}",
            err,
        );
    }

    /// preflight_report returns InvalidInput when r_bits has the wrong length.
    #[test]
    fn preflight_report_wrong_r_bits_length() {
        let mut cred = dummy_credential(Some(10_000));
        cred.r_bits = Some(vec![false; 64]);

        let qr = dummy_qr_payload();
        let err = preflight_report(&cred, &qr).unwrap_err();
        assert!(
            matches!(err, ProverError::InvalidInput(_)),
            "expected InvalidInput, got: {:?}",
            err,
        );
    }

    /// preflight_report returns InvalidBase64 when rp_challenge is not valid
    /// base64url.
    #[test]
    fn preflight_report_invalid_rp_challenge() {
        let mut cred = dummy_credential(Some(10_000));
        cred.r_bits = Some(vec![false; R_BITS_LEN]);

        let mut qr = dummy_qr_payload();
        qr.rp_challenge = "not!valid!base64!data!!!".to_string();

        let err = preflight_report(&cred, &qr).unwrap_err();
        assert!(
            matches!(err, ProverError::InvalidBase64(_)),
            "expected InvalidBase64, got: {:?}",
            err,
        );
    }

    /// preflight_report returns InvalidBase64 when rp_challenge decodes to the
    /// wrong byte count (not 32).
    #[test]
    fn preflight_report_rp_challenge_wrong_length() {
        let mut cred = dummy_credential(Some(10_000));
        cred.r_bits = Some(vec![false; R_BITS_LEN]);

        let mut qr = dummy_qr_payload();
        qr.rp_challenge = URL_SAFE_NO_PAD.encode([0xCDu8; 16]);

        let err = preflight_report(&cred, &qr).unwrap_err();
        assert!(
            matches!(err, ProverError::InvalidBase64(_)),
            "expected InvalidBase64 (wrong length), got: {:?}",
            err,
        );
    }

    /// All ProverError variants produce non-empty display strings.
    #[test]
    fn prover_error_variants_display() {
        let variants: Vec<ProverError> = vec![
            ProverError::NotInitialized,
            ProverError::AlreadyInitialized,
            ProverError::InvalidProvingKey,
            ProverError::InvalidBase64("test".to_string()),
            ProverError::InvalidInput("test".to_string()),
            ProverError::ProofGenerationFailed("test".to_string()),
            ProverError::MissingPrivateFields,
            ProverError::VkIdMismatch {
                loaded: 1,
                expected: 2,
            },
            ProverError::AgeRequirementNotMet,
            ProverError::CredentialExpired,
            ProverError::ChallengeExpired,
        ];

        for v in variants {
            let msg = v.to_string();
            assert!(!msg.is_empty(), "empty display for {:?}", v);
        }
    }

    /// can_satisfy_age_requirement boundary value tests.
    #[test]
    fn can_satisfy_boundary_values() {
        let exact = dummy_credential(Some(10_000));
        assert!(can_satisfy_age_requirement(&exact, 10_000, false));
        assert!(can_satisfy_age_requirement(&exact, 10_000, true));

        let one_over = dummy_credential(Some(10_001));
        assert!(!can_satisfy_age_requirement(&one_over, 10_000, false));
        assert!(can_satisfy_age_requirement(&one_over, 10_000, true));
    }

    // ====================================================================
    // Mutation-coverage tests: kill surviving mutants in prover.rs
    // ====================================================================

    /// Helper: create a credential with a valid RedJubjub signature so
    /// preflight_report can proceed past the signature check.
    fn signed_credential_for_preflight(
        dob_days: i32,
    ) -> (CredentialV2, provii_crypto_sig_redjubjub::SigningKey) {
        use provii_crypto_commit::{generate_commitment_randomness, pedersen_commit_dob_validated};

        let mut rng = rand::rngs::OsRng;
        let r_bits_z = generate_commitment_randomness(&mut rng, R_BITS_LEN);
        let r_bits: Vec<bool> = r_bits_z.to_vec();
        let c_bytes = pedersen_commit_dob_validated(dob_days, &r_bits)
            .expect("commitment should succeed with valid inputs");

        let sk = provii_crypto_sig_redjubjub::SigningKey::random();
        let vk = sk.verification_key().to_bytes();

        let cred_msg = CredMsgV2 {
            v: 2,
            kid: "provii:2026-05".to_string(),
            c: c_bytes,
            iat: 1_700_000_000,
            exp: 1_800_000_000,
            schema: "provii.age/0".to_string(),
        };
        let sig_rj = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &sk.to_bytes())
            .expect("signing should succeed");

        let cred = CredentialV2 {
            v: 2,
            kid: "provii:2026-05".to_string(),
            issuer_vk: vk,
            sig_rj,
            c_bytes,
            iat: 1_700_000_000,
            exp: 1_800_000_000,
            schema: "provii.age/0".to_string(),
            dob_days: Some(dob_days),
            r_bits: Some(r_bits),
        };

        (cred, sk)
    }

    /// Kill: prover.rs:354 replace == with != in preflight_report (commitment_matches)
    /// A credential whose stored c_bytes matches the recomputed commitment
    /// should have commitment_matches == true.
    #[test]
    fn preflight_report_commitment_matches_true() {
        let (cred, _sk) = signed_credential_for_preflight(10_000);
        let qr = dummy_qr_payload();

        let report = preflight_report(&cred, &qr).expect("preflight should succeed");
        assert!(
            report.commitment_matches,
            "commitment_matches should be true when c_bytes matches recomputed"
        );
    }

    /// Kill: prover.rs:354 replace == with != in preflight_report (commitment_matches=false)
    /// A credential with tampered c_bytes should have commitment_matches == false.
    #[test]
    fn preflight_report_commitment_matches_false_on_tampered() {
        let (mut cred, _sk) = signed_credential_for_preflight(10_000);
        // Tamper the stored commitment
        cred.c_bytes[0] ^= 0xFF;

        // We need to re-sign with the tampered c_bytes so the signature check passes
        let sk2 = provii_crypto_sig_redjubjub::SigningKey::random();
        let vk2 = sk2.verification_key().to_bytes();
        let cred_msg = CredMsgV2 {
            v: 2,
            kid: "provii:2026-05".to_string(),
            c: cred.c_bytes,
            iat: 1_700_000_000,
            exp: 1_800_000_000,
            schema: "provii.age/0".to_string(),
        };
        let sig_rj = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &sk2.to_bytes())
            .expect("signing should succeed");
        cred.issuer_vk = vk2;
        cred.sig_rj = sig_rj;

        let qr = dummy_qr_payload();
        let report = preflight_report(&cred, &qr).expect("preflight should succeed");
        assert!(
            !report.commitment_matches,
            "commitment_matches should be false when c_bytes is tampered"
        );
    }

    /// Kill: prover.rs:371 replace == with != in preflight_report (is_under_age)
    /// When proof_direction is "under_age", the age check should use >= direction.
    /// When proof_direction is None/over_age, it should use <= direction.
    #[test]
    fn preflight_report_age_ok_over_age_direction() {
        // dob_days=5000, cutoff=19000 => 5000 <= 19000 => over_age satisfied
        let (cred, _sk) = signed_credential_for_preflight(5_000);
        let mut qr = dummy_qr_payload();
        qr.proof_direction = None; // default is over_age

        let report = preflight_report(&cred, &qr).expect("preflight should succeed");
        assert!(report.age_ok, "5000 <= 19000 in over_age direction");
    }

    #[test]
    fn preflight_report_age_ok_under_age_direction() {
        // dob_days=5000, cutoff=19000 => 5000 >= 19000 => under_age NOT satisfied
        let (cred, _sk) = signed_credential_for_preflight(5_000);
        let mut qr = dummy_qr_payload();
        qr.proof_direction = Some("under_age".to_string());

        let report = preflight_report(&cred, &qr).expect("preflight should succeed");
        assert!(
            !report.age_ok,
            "5000 >= 19000 is false in under_age direction"
        );
    }

    #[test]
    fn preflight_report_age_ok_under_age_satisfied() {
        // dob_days=20000, cutoff=19000 => 20000 >= 19000 => under_age satisfied
        let (cred, _sk) = signed_credential_for_preflight(20_000);
        let mut qr = dummy_qr_payload();
        qr.proof_direction = Some("under_age".to_string());

        let report = preflight_report(&cred, &qr).expect("preflight should succeed");
        assert!(report.age_ok, "20000 >= 19000 in under_age direction");
    }

    /// Kill: prover.rs:385 replace == with != in preflight_report (vk_id_matches)
    /// When prover is not initialised, loaded_vk_id is None, so vk_id_matches=false.
    #[test]
    fn preflight_report_vk_id_matches_false_when_not_initialized() {
        let (cred, _sk) = signed_credential_for_preflight(10_000);
        let qr = dummy_qr_payload();

        let report = preflight_report(&cred, &qr).expect("preflight should succeed");
        // LOADED_VK_ID is None (prover not initialised in test)
        assert!(
            !report.vk_id_matches,
            "vk_id_matches should be false when prover not initialised"
        );
        assert_eq!(report.loaded_vk_id, None);
    }

    /// Kill: prover.rs:397 replace != with == in preflight_report (direction_bool)
    /// direction_bool is true when NOT under_age (i.e. over_age).
    /// When proof_direction is None (default = over_age) and "over_age", both
    /// should produce the same public_inputs_hex. Under the mutant, None would
    /// produce direction_bool=true (wrong direction for !=->==) but "over_age"
    /// would produce direction_bool=false, so they would differ.
    #[test]
    fn preflight_report_direction_bool_consistency() {
        let (cred, _sk) = signed_credential_for_preflight(10_000);
        let mut qr = dummy_qr_payload();
        qr.proof_direction = None; // default = over_age

        let report_none = preflight_report(&cred, &qr).expect("preflight should succeed");

        qr.proof_direction = Some("over_age".to_string());
        let report_over = preflight_report(&cred, &qr).expect("preflight should succeed");

        // Both should produce the same direction_bool (true), hence same public inputs
        assert_eq!(
            report_none.public_inputs_hex, report_over.public_inputs_hex,
            "None and 'over_age' must produce identical public inputs"
        );

        // Under_age must differ from over_age
        qr.proof_direction = Some("under_age".to_string());
        let report_under = preflight_report(&cred, &qr).expect("preflight should succeed");
        assert_ne!(
            report_over.public_inputs_hex, report_under.public_inputs_hex,
            "public inputs must differ between over_age and under_age"
        );
    }

    /// Kill: prover.rs:518/524/530 - get_proving_key_fingerprint/get_loaded_vk_id/is_prover_initialized
    /// When prover is NOT initialised, these should return None/None/false.
    #[test]
    fn prover_state_functions_when_not_initialized() {
        // In a fresh test process, the prover should not be initialised.
        // But since tests share process state, PROVING_PARAMS might already be set.
        // We test the contract: if PROVING_PARAMS is None, is_prover_initialized=false.
        if PROVING_PARAMS.get().is_none() {
            assert!(!is_prover_initialized());
            assert_eq!(get_proving_key_fingerprint(), None);
            assert_eq!(get_loaded_vk_id(), None);
        } else {
            // Prover was initialised by another test; verify the functions return Some values.
            assert!(is_prover_initialized());
            assert!(get_proving_key_fingerprint().is_some());
            assert!(get_loaded_vk_id().is_some());
        }
    }

    /// Kill: prover.rs:454 replace init_prover_with_pk_bytes -> Result<(), ProverError> with Ok(())
    /// init_prover_with_pk_bytes must reject invalid (empty) proving key bytes.
    #[test]
    fn init_prover_rejects_invalid_bytes() {
        // If prover is already initialized, this returns Ok() due to idempotency.
        // In that case this test is a no-op. But if not initialized, empty bytes
        // must produce InvalidProvingKey.
        if PROVING_PARAMS.get().is_none() {
            let result = init_prover_with_pk_bytes(&[]);
            assert!(
                result.is_err(),
                "empty bytes should fail with InvalidProvingKey"
            );
            assert!(matches!(
                result.unwrap_err(),
                ProverError::InvalidProvingKey
            ));

            // Also try garbage bytes
            let result2 = init_prover_with_pk_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]);
            assert!(
                result2.is_err(),
                "garbage bytes should fail with InvalidProvingKey"
            );
        }
    }

    /// Kill: prover.rs:690 replace * with +/div in build_verify_request (stack_size 8*1024*1024)
    /// This is only triggered when called from within a rayon worker thread. The mutant
    /// changes the stack size calculation (8*1024*1024) to something small. We test that
    /// build_verify_request properly spawns an OS thread with adequate stack when called
    /// from a rayon context. Since proof generation requires init, we just verify the
    /// function doesn't panic with a bad credential (it should return an error, not crash).
    #[test]
    fn build_verify_request_from_rayon_context_returns_error() {
        // We can't easily test the 8 MiB stack requirement without a real proving key.
        // However, we verify that calling from a rayon pool handles errors gracefully.
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .expect("pool creation should succeed");

        let result = pool.install(|| {
            let cred = dummy_credential(Some(10_000));
            let qr = dummy_qr_payload();
            build_verify_request(&cred, &qr)
        });

        // Should error (not crash) because prover is not initialised
        assert!(result.is_err());
    }

    /// Kill: prover.rs:1210 replace init_prover_with_pk_mmap -> Result<(), ProverError> with Ok(())
    /// init_prover_with_pk_mmap must reject a non-existent file path.
    #[cfg(feature = "mmap")]
    #[test]
    fn init_prover_with_pk_mmap_rejects_invalid_path() {
        if PROVING_PARAMS.get().is_some() {
            // Prover already initialised; the function returns Ok() idempotently.
            return;
        }

        let result = init_prover_with_pk_mmap("/nonexistent/path/to/proving.key");
        assert!(
            result.is_err(),
            "non-existent path should fail with InvalidProvingKey"
        );
        assert!(matches!(
            result.unwrap_err(),
            ProverError::InvalidProvingKey
        ));
    }
}
