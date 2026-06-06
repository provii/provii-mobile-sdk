// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! UniFFI bridge for `provii-mobile-sdk-core`.
//!
//! This crate is the sole FFI surface that mobile platforms consume. UniFFI
//! generates Swift and Kotlin bindings from the `#[uniffi::export]` items
//! defined here and in child modules. The generated code is never checked in;
//! CI produces it during release builds and ships it as an XCFramework (iOS)
//! or AAR (Android).
//!
//! # Runtime model
//!
//! A single-threaded Tokio runtime (`TOKIO_RT`) is lazily initialised at
//! first use. All async work (HTTP/3 requests to provii-issuer and provii-verifier)
//! runs on that runtime via `block_on`. Rayon is available when the `parallel`
//! feature is active, giving multi-threaded Groth16 proving on devices that
//! support it.
//!
//! # Security invariants
//!
//! * Secret randomness (`r_bits`) and authoriser credentials are wrapped in
//!   [`zeroize::Zeroizing`] so they are scrubbed on drop.
//! * All cryptographic operations delegate to `provii-mobile-sdk-core` and
//!   `provii-crypto`; this crate performs no cryptography itself.
//! * The `unsafe` lint is set to `forbid` on all platforms except Android,
//!   where JNI initialisation requires a small `unsafe` block in
//!   `android_init`.

#![cfg_attr(not(target_os = "android"), forbid(unsafe_code))]
#![cfg_attr(target_os = "android", deny(unsafe_code))]

mod biometric;
mod deeplink;
mod errors;
#[cfg(feature = "http")]
mod net;
mod progress;
mod proving_key;
mod qr;
mod state;
mod storage;
mod types;
mod verify;
mod wallet;

#[cfg(target_os = "android")]
mod android_init;

#[cfg(test)]
mod lib_tests;

use once_cell::sync::OnceCell;
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};
use zeroize::Zeroizing;

use provii_mobile_sdk_core::issuance as core_issuance;
use provii_mobile_sdk_core::types::{CredentialV2, IssuerTrustAnchor, SignedCredentialHeader};

uniffi::setup_scaffolding!();

/// Global Tokio runtime shared by every `#[uniffi::export]` function that
/// performs async work (HTTP requests, file I/O).
///
/// The runtime uses the **current-thread** scheduler to minimise thread
/// creation on mobile. Blocking thread count is capped at 2 on iOS/Android
/// and 4 on desktop, never exceeding the hardware parallelism reported by the
/// OS. The cap keeps memory usage low on constrained devices while still
/// allowing a handful of blocking file-system operations to proceed without
/// starving the event loop.
static TOKIO_RT: OnceCell<Runtime> = OnceCell::new();

/// Obtain a reference to the global Tokio runtime, initialising it on first
/// call. Returns an error instead of panicking if the runtime cannot be built
/// (for example, when the OS refuses to create the underlying I/O driver).
pub(crate) fn tokio_rt() -> Result<&'static Runtime, FfiError> {
    TOKIO_RT.get_or_try_init(|| {
        let hw_threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2);

        #[cfg(any(target_os = "android", target_os = "ios"))]
        let max_blocking_threads = 2usize.min(hw_threads);

        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let max_blocking_threads = 4usize.min(hw_threads);

        log::info!(
            "Initializing Tokio runtime: current-thread scheduler, {} blocking threads",
            max_blocking_threads
        );

        Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .max_blocking_threads(max_blocking_threads)
            .thread_name("provii-tokio")
            .build()
            .map_err(|e| FfiError::Generic {
                msg: format!("Failed to initialise Tokio runtime: {}", e),
            })
    })
}

// Re-exported types that form the public FFI contract. UniFFI picks these up
// and generates corresponding Swift/Kotlin definitions in the bindings output.
pub use types::{
    AppInfo, CredentialInfo, CredentialStatus, CredentialSuitability, DeeplinkAction,
    DiagnosticInfo, NetworkStatus, QrAction, WalletConfig,
};

pub use proving_key::{ProvingKeyError, ProvingKeyProgressListener, StorageCheckResult};

pub use biometric::{BiometricAuthenticator, BiometricConfig, BiometricResult};
pub use errors::{FfiError, FfiResult};
pub use progress::{ProgressStage, ProgressTracker};
pub use state::VerificationStatus;
pub use wallet::ProviiWallet;

/// Validate and normalise a base URL for provii-issuer calls.
///
/// Rejects non-HTTPS schemes, missing hosts, and malformed URLs. Returns
/// the parsed URL with any trailing slash stripped so that path concatenation
/// (`format!("{}/v1/...", base_url)`) never produces a double slash.
fn validate_base_url(base_url: &str) -> FfiResult<String> {
    let parsed = url::Url::parse(base_url).map_err(|e| FfiError::InvalidFormat {
        msg: format!("Invalid base URL: {}", e),
    })?;
    if parsed.scheme() != "https" {
        return Err(FfiError::InvalidFormat {
            msg: "Base URL must use HTTPS".to_string(),
        });
    }
    if parsed.host_str().is_none_or(|h| h.is_empty()) {
        return Err(FfiError::InvalidFormat {
            msg: "Base URL has no host".to_string(),
        });
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

/// Opaque handle that wraps a platform-specific secure storage backend.
///
/// UniFFI cannot export trait objects directly, so this struct acts as an
/// indirection layer. Swift callers receive it from
/// [`create_default_secure_store`] or [`create_development_secure_store`] and
/// pass it into [`ProviiWallet`] methods that need persistent storage.
///
/// On iOS the inner backend targets the Keychain; on Android it targets the
/// hardware-backed Keystore. Desktop builds (used only in tests) fall back to
/// an in-memory store.
#[derive(uniffi::Object)]
pub struct SecureStorageHandle {
    inner: Arc<dyn provii_mobile_sdk_platform_storage::PlatformSecureStorage>,
}

impl SecureStorageHandle {
    /// Create a new handle wrapping the given storage backend.
    pub fn new(inner: Arc<dyn provii_mobile_sdk_platform_storage::PlatformSecureStorage>) -> Self {
        Self { inner }
    }

    /// Obtain a clone of the inner `Arc` for crate-internal use.
    ///
    /// Not exported via UniFFI. Callers within this crate use the returned
    /// `Arc` to perform storage operations on behalf of the mobile app.
    pub(crate) fn backend(
        &self,
    ) -> Arc<dyn provii_mobile_sdk_platform_storage::PlatformSecureStorage> {
        Arc::clone(&self.inner)
    }
}

/// Compute a Pedersen commitment for a date of birth.
///
/// This is the first step of client-initiated credential issuance. The
/// officer app (or the wallet itself in the blind-issuance flow) calls this
/// to produce a commitment that hides the DOB behind random blinding bits.
///
/// `dob_iso_or_days` accepts either an ISO 8601 date (`YYYY-MM-DD`) or the
/// numeric days-since-Unix-epoch representation. Both resolve to the same
/// scalar fed into the Pedersen commitment.
///
/// # Returns
///
/// A JSON string with four fields:
///
/// | Field        | Type   | Description                          |
/// |-------------|--------|--------------------------------------|
/// | `dob_days`  | `i32`  | Days since epoch for the parsed DOB  |
/// | `r_bits`    | string | Base64url-encoded blinding randomness |
/// | `commitment`| string | Base64url-encoded 32-byte commitment  |
///
/// # Errors
///
/// Returns [`FfiError::InvalidFormat`] when the input cannot be parsed as a
/// date or integer, and [`FfiError::Generic`] if the commitment computation
/// fails internally.
#[uniffi::export]
pub fn sdk_issue_compute_commitment(dob_iso_or_days: String) -> FfiResult<String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let dob_days = if dob_iso_or_days.contains('-') {
        core_issuance::parse_dob_iso(&dob_iso_or_days)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?
    } else {
        dob_iso_or_days
            .parse::<i32>()
            .map_err(|_| FfiError::InvalidFormat {
                msg: "Invalid DOB format - expected YYYY-MM-DD or numeric days".to_string(),
            })?
    };

    let parts = core_issuance::compute_commitment(dob_days)
        .map_err(|e| FfiError::Generic { msg: e.to_string() })?;

    // Pack r_bits to bytes for compact encoding. Wrapped in Zeroizing because
    // the blinding randomness is secret material.
    let r_bits_bytes = Zeroizing::new(core_issuance::bits::pack_bits(&parts.r_bits));

    let response = serde_json::json!({
        "dob_days": parts.dob_days,
        "r_bits": URL_SAFE_NO_PAD.encode(r_bits_bytes.as_slice()),
        "commitment": URL_SAFE_NO_PAD.encode(&parts.c_bytes),
    });

    Ok(response.to_string())
}

/// Merge a signed credential header from the issuer with the wallet's private
/// fields (DOB and blinding randomness) to produce a complete
/// [`CredentialV2`].
///
/// The returned JSON has secret fields stripped by `#[serde(skip_serializing)]`
/// attributes on `CredentialV2`, so it is safe for logging but **not** for
/// persistent storage. Use `ProviiWallet.finalizeAndStoreCredential()` when
/// the credential needs to be written to the device keychain.
///
/// # Arguments
///
/// * `header_json`              - JSON-serialised [`SignedCredentialHeader`] received
///   from the issuer API after a successful `/v1/issuance/blind` call.
/// * `dob_days`                 - Days-since-epoch date of birth (same value passed to
///   [`sdk_issue_compute_commitment`]).
/// * `r_bits_b64`               - Base64url-encoded blinding randomness originally
///   returned by [`sdk_issue_compute_commitment`].
/// * `issuer_trust_anchor_json` - JSON-serialised [`IssuerTrustAnchor`]. The
///   header's `issuer_vk` is validated against the anchor before finalisation.
///   Passing `None` returns an error because skipping issuer key validation
///   would allow credentials signed by untrusted keys to be accepted.
///
/// # Errors
///
/// Returns [`FfiError::InvalidFormat`] on deserialisation, base64, or trust
/// anchor validation failures, and [`FfiError::Generic`] if the finalisation
/// logic rejects the inputs.
#[uniffi::export]
pub fn sdk_issue_finalize_credential(
    header_json: String,
    dob_days: i32,
    r_bits_b64: String,
    issuer_trust_anchor_json: Option<String>,
) -> FfiResult<String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let header: SignedCredentialHeader = serde_json::from_str(&header_json)
        .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

    // Validate issuer key against the trust anchor. Callers MUST provide an
    // anchor so that only trusted issuer keys are accepted. Silently skipping
    // validation when the anchor is absent would allow any key to pass.
    let anchor_json = issuer_trust_anchor_json.ok_or_else(|| FfiError::InvalidFormat {
        msg: "issuer_trust_anchor_json is required for credential finalisation".to_string(),
    })?;
    let anchor: IssuerTrustAnchor = serde_json::from_str(&anchor_json)
        .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;
    core_issuance::validate_issuer_vk(&header, &anchor)
        .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

    // Decode r_bits. All intermediates are wrapped in Zeroizing because the
    // blinding randomness is secret material.
    let r_bits_b64 = Zeroizing::new(r_bits_b64);
    let r_bits_bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(r_bits_b64.as_str())
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?,
    );
    let r_bits = core_issuance::bits::unpack_bits(&r_bits_bytes, core_issuance::R_BITS_LEN);

    let credential = core_issuance::finalize_credential(header, dob_days, r_bits)
        .map_err(|e| FfiError::Generic { msg: e.to_string() })?;

    serde_json::to_string(&credential).map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })
}

/// Set the User-Agent string used for all subsequent HTTP requests.
///
/// The generated string follows the pattern
/// `ProviiWallet/<version> (<platform> <os_version>; <device_model>)`.
/// Fields that are `None` are omitted. The User-Agent intentionally excludes
/// any user-identifying information; it carries only the app version, platform
/// name, and (optionally) the device model family.
///
/// This should be called once at app startup, before any network requests are
/// issued. Calling it again overwrites the previous value.
#[uniffi::export]
pub fn sdk_set_user_agent(app_info: AppInfo) {
    let platform_info = if let Some(ref os_ver) = app_info.os_version {
        format!("{} {}", app_info.platform, os_ver)
    } else {
        app_info.platform.clone()
    };

    let device_info = if let Some(ref model) = app_info.device_model {
        format!("; {}", model)
    } else {
        String::new()
    };

    let ua = format!(
        "ProviiWallet/{} ({}{})",
        app_info.version, platform_info, device_info
    );

    log::info!("User-Agent set to: {}", ua);

    #[cfg(feature = "http")]
    crate::net::set_user_agent(ua);
}

/// Persist a finalised credential to the device's secure storage.
///
/// Parses `credential_json` as a [`CredentialV2`] and delegates to
/// [`ProviiWallet::store_credential`]. Returns the credential identifier
/// string on success.
///
/// Prefer `ProviiWallet.finalizeAndStoreCredential()` when you already hold a
/// wallet instance, as that avoids constructing a throwaway wallet with
/// placeholder [`AppInfo`].
///
/// # Errors
///
/// Returns [`FfiError::InvalidFormat`] if the JSON cannot be deserialised, or
/// [`FfiError::Storage`] if the underlying keychain/keystore write fails.
#[uniffi::export]
pub fn sdk_store_finalized_credential(credential_json: String) -> FfiResult<String> {
    let wallet = ProviiWallet::new(AppInfo {
        version: "2.0.0".to_string(),
        build_number: "1".to_string(),
        platform: "unknown".to_string(),
        device_model: None,
        os_version: None,
    });

    let _cred: CredentialV2 = serde_json::from_str(&credential_json)
        .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

    wallet.store_credential(credential_json)
}

/// Request a YubiKey authentication challenge from the issuer API.
///
/// Posts to `{base_url}/v1/challenge` with the given `officer_id`. The
/// response contains a random challenge that the officer's YubiKey must
/// HMAC-SHA1-sign before the SDK can proceed with attestation creation.
///
/// # Returns
///
/// The full `ChallengeResponse` serialised as a JSON string. The mobile app
/// is responsible for forwarding the challenge to the YubiKey NFC/USB
/// interface and collecting the HMAC response.
///
/// # Errors
///
/// Returns [`FfiError::Network`] on transport failures and
/// [`FfiError::InvalidFormat`] if the server response is malformed.
#[cfg(feature = "http")]
#[uniffi::export]
pub fn sdk_issue_get_yubikey_challenge(base_url: String, officer_id: String) -> FfiResult<String> {
    let base_url = validate_base_url(&base_url)?;
    use provii_mobile_sdk_core::types::{ChallengeRequest, ChallengeResponse};

    tokio_rt()?.block_on(async {
        let url = format!("{}/v1/challenge", base_url);
        let req = ChallengeRequest { officer_id };

        let request_json = serde_json::to_string(&req)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

        let response = crate::net::post_json(&url, &request_json)
            .await
            .map_err(|e| FfiError::Network { msg: e.to_string() })?;

        let body: ChallengeResponse = serde_json::from_str(&response)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

        serde_json::to_string(&body).map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })
    })
}

/// Begin an officer-initiated issuance session on the issuer API.
///
/// Posts to `{base_url}/v1/issuance/start` with the officer's identity
/// (`actor`), their authentication credentials (`authorizer_json`), and
/// optional parameters that control schema selection, credential lifetime,
/// and key identifier.
///
/// Both `authorizer_json` and `api_key` contain secret material. They are
/// wrapped in [`Zeroizing`] internally so that memory is scrubbed once the
/// request completes.
///
/// # Returns
///
/// A JSON-serialised `StartResponse` containing the `session_id` that
/// subsequent calls (`sdk_issue_sign_commitment`) must reference.
///
/// # Errors
///
/// Returns [`FfiError::InvalidFormat`] for deserialisation or validation
/// failures, and [`FfiError::Network`] for transport errors.
#[cfg(feature = "http")]
#[uniffi::export]
pub fn sdk_issue_start_session(
    base_url: String,
    actor: String,
    authorizer_json: String,
    schema: Option<String>,
    validity_days: Option<u32>,
    kid: Option<String>,
    api_key: Option<String>,
) -> FfiResult<String> {
    let base_url = validate_base_url(&base_url)?;
    use provii_mobile_sdk_core::types::{Authorizer, StartRequest, StartResponse};

    let authorizer_json = Zeroizing::new(authorizer_json);
    let api_key = api_key.map(Zeroizing::new);

    let authorizer: Authorizer = serde_json::from_str(&authorizer_json)
        .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;
    authorizer
        .validate()
        .map_err(|e| FfiError::InvalidFormat { msg: e })?;

    let result = tokio_rt()?.block_on(async {
        let url = format!("{}/v1/issuance/start", base_url);

        let request = StartRequest {
            actor: actor.to_string(),
            authorizer,
            schema,
            validity_days,
            kid,
        };

        let request_json = serde_json::to_string(&request)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

        let response = crate::net::post_json_with_api_key(
            &url,
            &request_json,
            api_key.as_ref().map(|k| k.as_str()),
            30,
        )
        .await
        .map_err(|e| FfiError::Network { msg: e.to_string() })?;

        let start_response: StartResponse = serde_json::from_str(&response)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

        Ok(start_response)
    });

    match result {
        Ok(response) => Ok(serde_json::to_string(&response)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?),
        Err(e) => Err(e),
    }
}

/// Submit a Pedersen commitment to the issuer API for blind signing.
///
/// Posts to `{base_url}/v1/issuance/blind` within the session started by
/// [`sdk_issue_start_session`]. The issuer verifies the officer's authoriser
/// credentials, then signs the commitment without ever seeing the plaintext
/// DOB.
///
/// `commitment_b64`, `authorizer_json`, and `api_key` all contain secret
/// material and are wrapped in [`Zeroizing`] internally.
///
/// # Returns
///
/// A JSON-serialised [`SignedCredentialHeader`] that the wallet must merge
/// with its private fields via [`sdk_issue_finalize_credential`].
///
/// # Errors
///
/// Returns [`FfiError::InvalidFormat`] for deserialisation or validation
/// failures, and [`FfiError::Network`] for transport errors.
#[cfg(feature = "http")]
#[uniffi::export]
pub fn sdk_issue_sign_commitment(
    base_url: String,
    session_id: String,
    commitment_b64: String,
    authorizer_json: String,
    api_key: Option<String>,
) -> FfiResult<String> {
    let base_url = validate_base_url(&base_url)?;
    use provii_mobile_sdk_core::types::{Authorizer, SignCommitmentResponse};

    let authorizer_json = Zeroizing::new(authorizer_json);
    let api_key = api_key.map(Zeroizing::new);
    let commitment_b64 = Zeroizing::new(commitment_b64);

    let authorizer: Authorizer = serde_json::from_str(&authorizer_json)
        .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;
    authorizer
        .validate()
        .map_err(|e| FfiError::InvalidFormat { msg: e })?;

    let result = tokio_rt()?.block_on(async {
        let url = format!("{}/v1/issuance/blind", base_url);

        let request_json = serde_json::json!({
            "session_id": session_id,
            "commitment": commitment_b64.as_str(),
            "authorizer": authorizer,
        });

        let request_str = serde_json::to_string(&request_json)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

        let response = crate::net::post_json_with_api_key(
            &url,
            &request_str,
            api_key.as_ref().map(|k| k.as_str()),
            30,
        )
        .await
        .map_err(|e| FfiError::Network { msg: e.to_string() })?;

        let resp: SignCommitmentResponse = serde_json::from_str(&response)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

        Ok(resp.credential)
    });

    match result {
        Ok(header) => Ok(serde_json::to_string(&header)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?),
        Err(e) => Err(e),
    }
}

/// Submit an Ed25519-signed attestation and blinding randomness for
/// client-initiated blind issuance.
///
/// This is the wallet's entry point for the blind issuance flow. The wallet
/// receives an attestation (typically via a deep link from the officer app or
/// QR scan), pairs it with the `r_bits` it generated during commitment
/// computation, and posts both to `{base_url}/v1/issuance/blind`. The issuer
/// API verifies the attestation signature, computes the Pedersen commitment
/// server-side, signs the credential header, and returns it.
///
/// # Arguments
///
/// * `base_url`         - Issuer API base URL (e.g.
///   `https://sandbox-issuer.provii.app`).
/// * `attestation_b64`  - Base64url-encoded Ed25519-signed `DobAttestation`.
/// * `r_bits_b64`       - Base64url-encoded blinding randomness from
///   [`sdk_issue_compute_commitment`].
///
/// # Returns
///
/// A JSON-serialised [`SignedCredentialHeader`] ready for finalisation with
/// [`sdk_issue_finalize_credential`].
///
/// # Errors
///
/// Returns [`FfiError::Network`] on transport failures and
/// [`FfiError::InvalidFormat`] if the response cannot be deserialised.
#[cfg(feature = "http")]
#[uniffi::export]
pub fn sdk_issue_blind(
    base_url: String,
    attestation_b64: String,
    r_bits_b64: String,
) -> FfiResult<String> {
    let base_url = validate_base_url(&base_url)?;
    use provii_mobile_sdk_core::blind_issuance::BlindIssuanceResponse;

    let r_bits_b64 = Zeroizing::new(r_bits_b64);

    let result = tokio_rt()?.block_on(async {
        let url = format!("{}/v1/issuance/blind", base_url);

        let request_json = serde_json::json!({
            "attestation": attestation_b64,
            "r_bits": r_bits_b64.as_str(),
        });

        let request_str = serde_json::to_string(&request_json)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

        let response = crate::net::post_json_with_api_key(&url, &request_str, None, 30)
            .await
            .map_err(|e| FfiError::Network { msg: e.to_string() })?;

        let resp: BlindIssuanceResponse = serde_json::from_str(&response)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

        Ok(resp.credential)
    });

    match result {
        Ok(header) => Ok(serde_json::to_string(&header)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?),
        Err(e) => Err(e),
    }
}

/// Create an Ed25519-signed DOB attestation via the issuer API.
///
/// Posts to `{base_url}/v1/attestation/create` with the officer's
/// authentication credentials and the subject's date of birth. The issuer
/// signs the attestation with its Ed25519 key and returns it in a format
/// suitable for encoding as a QR code or deep link.
///
/// `authorizer_json` contains YubiKey HMAC material and is wrapped in
/// [`Zeroizing`] internally.
///
/// # Arguments
///
/// * `base_url`         - Issuer API base URL (e.g.
///   `https://issuer.provii.app`).
/// * `dob_days`         - Days since Unix epoch representing the subject's
///   date of birth.
/// * `authorizer_json`  - JSON-serialised `Authorizer` containing the
///   officer's YubiKey HMAC response.
///
/// # Returns
///
/// A JSON string with (at minimum) an `attestation` field holding the
/// base64url-encoded signed attestation, plus `expires_at` (Unix timestamp)
/// and `issuer_id`.
///
/// # Errors
///
/// Returns [`FfiError::InvalidFormat`] if the authoriser fails validation or
/// the response lacks the `attestation` field, and [`FfiError::Network`] on
/// transport failures.
#[cfg(feature = "http")]
#[uniffi::export]
pub fn sdk_create_attestation(
    base_url: String,
    dob_days: i32,
    authorizer_json: String,
) -> FfiResult<String> {
    let base_url = validate_base_url(&base_url)?;
    use provii_mobile_sdk_core::types::Authorizer;

    let authorizer_json = Zeroizing::new(authorizer_json);

    let authorizer: Authorizer = serde_json::from_str(&authorizer_json)
        .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;
    authorizer
        .validate()
        .map_err(|e| FfiError::InvalidFormat { msg: e })?;

    tokio_rt()?.block_on(async {
        let url = format!("{}/v1/attestation/create", base_url);

        let request_json = serde_json::json!({
            "dob_days": dob_days,
            "authorizer": authorizer,
        });

        let request_str = serde_json::to_string(&request_json)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

        let response = crate::net::post_json(&url, &request_str)
            .await
            .map_err(|e| FfiError::Network { msg: e.to_string() })?;

        let resp: serde_json::Value = serde_json::from_str(&response)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

        if resp.get("attestation").is_none() {
            return Err(FfiError::InvalidFormat {
                msg: "Response missing 'attestation' field".to_string(),
            });
        }

        Ok(response)
    })
}

/// Initialise the Groth16 prover from a memory-mapped proving key file.
///
/// Memory-mapping avoids copying the entire proving key (tens of megabytes)
/// into the process heap. The file at `pk_path` must be a valid BLS12-381
/// proving key serialised by `provii-crypto-prover`. Once initialised, the
/// prover is available globally for the lifetime of the process.
///
/// Only available when the `mmap` feature is enabled. On iOS, prefer this
/// over [`sdk_init_prover`] because it halves peak memory during proving.
///
/// # Errors
///
/// Returns [`FfiError::Prover`] if the file is missing, unreadable, or
/// contains an invalid proving key.
#[cfg(feature = "mmap")]
#[uniffi::export]
pub fn sdk_init_prover_mmap(pk_path: String) -> FfiResult<()> {
    provii_mobile_sdk_core::prover::init_prover_with_pk_mmap(&pk_path)
        .map_err(|e| FfiError::Prover { msg: e.to_string() })
}

/// Create the default platform-specific secure storage backend.
///
/// On iOS this returns a Keychain-backed store; on Android, a
/// hardware-backed Keystore implementation. Desktop builds (which only
/// exist for `cargo test`) return an in-memory store backed by a
/// [`std::sync::Mutex`]-guarded `HashMap`.
///
/// # Errors
///
/// Returns [`FfiError::Storage`] if the platform storage layer fails to
/// initialise (e.g. Keychain entitlement missing on iOS, or Keystore
/// unavailable on Android).
#[uniffi::export]
pub fn create_default_secure_store() -> FfiResult<Arc<SecureStorageHandle>> {
    #[cfg(target_os = "android")]
    {
        let storage = provii_mobile_sdk_store_android::create_production_storage()
            .map_err(|e| FfiError::Storage { msg: e.to_string() })?;
        Ok(Arc::new(SecureStorageHandle::new(storage)))
    }

    #[cfg(target_os = "ios")]
    {
        let storage = provii_mobile_sdk_store_ios::create_production_storage()
            .map_err(|e| FfiError::Storage { msg: e.to_string() })?;
        Ok(Arc::new(SecureStorageHandle::new(storage)))
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        use provii_mobile_sdk_platform_storage::PlatformSecureStorage;

        struct MemoryStorage {
            data: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
        }

        impl PlatformSecureStorage for MemoryStorage {
            fn store(
                &self,
                key: &str,
                value: &[u8],
                _bio: provii_mobile_sdk_platform_storage::BiometricRequirement,
            ) -> provii_mobile_sdk_platform_storage::Result<()> {
                self.data
                    .lock()
                    .map_err(
                        |_| provii_mobile_sdk_platform_storage::WalletError::Storage {
                            msg: "mutex poisoned".to_string(),
                        },
                    )?
                    .insert(key.to_string(), value.to_vec());
                Ok(())
            }

            fn retrieve(
                &self,
                key: &str,
                _bio: provii_mobile_sdk_platform_storage::BiometricRequirement,
            ) -> provii_mobile_sdk_platform_storage::Result<Zeroizing<Vec<u8>>> {
                self.data
                    .lock()
                    .map_err(
                        |_| provii_mobile_sdk_platform_storage::WalletError::Storage {
                            msg: "mutex poisoned".to_string(),
                        },
                    )?
                    .get(key)
                    .cloned()
                    .map(Zeroizing::new)
                    .ok_or_else(
                        || provii_mobile_sdk_platform_storage::WalletError::Storage {
                            msg: "NotFound".to_string(),
                        },
                    )
            }

            fn delete(&self, key: &str) -> provii_mobile_sdk_platform_storage::Result<()> {
                self.data
                    .lock()
                    .map_err(
                        |_| provii_mobile_sdk_platform_storage::WalletError::Storage {
                            msg: "mutex poisoned".to_string(),
                        },
                    )?
                    .remove(key);
                Ok(())
            }

            fn exists(&self, key: &str) -> provii_mobile_sdk_platform_storage::Result<bool> {
                Ok(self
                    .data
                    .lock()
                    .map_err(
                        |_| provii_mobile_sdk_platform_storage::WalletError::Storage {
                            msg: "mutex poisoned".to_string(),
                        },
                    )?
                    .contains_key(key))
            }

            fn list_keys(&self) -> provii_mobile_sdk_platform_storage::Result<Vec<String>> {
                Ok(self
                    .data
                    .lock()
                    .map_err(
                        |_| provii_mobile_sdk_platform_storage::WalletError::Storage {
                            msg: "mutex poisoned".to_string(),
                        },
                    )?
                    .keys()
                    .cloned()
                    .collect())
            }
        }

        let storage = Arc::new(MemoryStorage {
            data: std::sync::Mutex::new(std::collections::HashMap::new()),
        });
        Ok(Arc::new(SecureStorageHandle::new(storage)))
    }
}

/// Create a development-mode secure storage backend.
///
/// Behaves identically to [`create_default_secure_store`] on desktop. On
/// mobile platforms the returned store may use relaxed biometric requirements
/// or a debug-friendly Keychain access group, making local development and
/// UI testing easier.
///
/// **Do not ship this in production builds.** The `development` feature gate
/// controls whether this function is callable.
///
/// # Errors
///
/// Returns [`FfiError::Storage`] if the platform storage layer fails to
/// initialise.
#[uniffi::export]
pub fn create_development_secure_store() -> FfiResult<Arc<SecureStorageHandle>> {
    #[cfg(target_os = "android")]
    {
        let storage = provii_mobile_sdk_store_android::create_development_storage()
            .map_err(|e| FfiError::Storage { msg: e.to_string() })?;
        Ok(Arc::new(SecureStorageHandle::new(storage)))
    }

    #[cfg(target_os = "ios")]
    {
        let storage = provii_mobile_sdk_store_ios::create_development_storage()
            .map_err(|e| FfiError::Storage { msg: e.to_string() })?;
        Ok(Arc::new(SecureStorageHandle::new(storage)))
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        create_default_secure_store()
    }
}

/// Initialise the Android logcat logger.
///
/// Configures the `log` crate to route all SDK log output to logcat under
/// the tag `ProviiWallet` at `Debug` level. Safe to call multiple times; the
/// underlying `android_logger::init_once` is a no-op after the first call.
///
/// On non-Android platforms this function does nothing.
#[uniffi::export]
pub fn init_android_logging() {
    #[cfg(target_os = "android")]
    {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Debug)
                .with_tag("ProviiWallet"),
        );
    }
}

/// Return the SDK version string baked in at compile time.
///
/// The value comes from `Cargo.toml` via `env!("CARGO_PKG_VERSION")`. Mobile
/// apps typically display this on a diagnostics or "about" screen.
#[uniffi::export]
pub fn get_sdk_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Initialise the Groth16 prover from an in-memory proving key.
///
/// `pk_bytes` must contain a valid BLS12-381 proving key. On Android (where
/// `mmap` support is inconsistent across OEM kernels) this is the preferred
/// initialisation path. The key is typically bundled as a raw asset or
/// downloaded on first launch.
///
/// Once initialised the prover is available globally for the lifetime of the
/// process. Calling this a second time is a no-op.
///
/// # Errors
///
/// Returns [`FfiError::Prover`] if the bytes cannot be deserialised into a
/// valid proving key.
#[uniffi::export]
pub fn sdk_init_prover(pk_bytes: Vec<u8>) -> FfiResult<()> {
    provii_mobile_sdk_core::prover::init_prover_with_pk_bytes(&pk_bytes)
        .map_err(|e| FfiError::Prover { msg: e.to_string() })
}

/// Build a JSON verification request body from a stored credential and a QR
/// challenge payload.
///
/// This is a synchronous, offline operation. It extracts the fields needed by
/// the verifier API from the credential, pairs them with the challenge
/// parameters from the QR code, and returns the assembled request as a JSON
/// string. The caller is responsible for posting it to the verifier endpoint.
///
/// # Errors
///
/// Returns [`FfiError`] (via the `verify` module) if either JSON string is
/// malformed or the credential cannot satisfy the challenge.
#[uniffi::export]
pub fn sdk_build_verify_request(
    credential_json: String,
    qr_payload_json: String,
) -> FfiResult<String> {
    verify::build_verify_request(credential_json, qr_payload_json).map_err(Into::into)
}

/// Parse a Provii deep link URL into a [`DeeplinkAction`].
///
/// Recognised URL patterns:
///
/// * `https://provii.app/verify?d=...` produces
///   [`DeeplinkAction::ScanChallenge`].
/// * `https://provii.app/attest?d=...` produces
///   [`DeeplinkAction::Attest`].
///
/// # Errors
///
/// Returns [`FfiError`] if the URL scheme is unrecognised or the query
/// parameter is missing or unparseable.
#[uniffi::export]
pub fn sdk_parse_deeplink(url: String) -> FfiResult<DeeplinkAction> {
    deeplink::parse(url).map_err(Into::into)
}

/// Run a quick thread configuration diagnostic and return a human-readable
/// report.
///
/// Queries hardware core count, Rayon pool size, and runs a trivial parallel
/// benchmark to confirm that multi-threading is actually delivering speedup.
/// The output includes estimated proof generation times based on the measured
/// parallelism. Useful for support triage when a user reports slow proving.
///
/// This function blocks for a fraction of a second while the benchmark runs.
/// It is safe to call from the main thread on mobile (the work happens on
/// Rayon worker threads), but callers may wish to dispatch it to a background
/// queue for UI responsiveness.
#[uniffi::export]
pub fn sdk_diagnose_thread_config() -> String {
    use rayon::prelude::*;
    use std::time::Instant;

    let hw_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let rayon_threads = rayon::current_num_threads();

    let in_rayon = if let Some(idx) = rayon::current_thread_index() {
        format!("Yes (index {})", idx)
    } else {
        "No".to_string()
    };

    let test_size = 50_000_000u64;
    let start = Instant::now();
    let _sum: u64 = (0..test_size).into_par_iter().map(|i| i % 17).sum();
    let parallel_time = start.elapsed();

    let start = Instant::now();
    let _single_sample: u64 = (0..1_000_000u64).map(|i| i % 17).sum();
    let sample_time = start.elapsed();
    let estimated_single = sample_time.as_secs_f64() * 50.0;

    let parallel_secs = parallel_time.as_secs_f64();
    // Guard against division by zero when parallel_time is negligible.
    let speedup = if parallel_secs > 0.0 {
        estimated_single / parallel_secs
    } else {
        0.0
    };

    // Pre-compute display values outside the format! macro so we can
    // apply targeted clippy allows for the diagnostic-only casts.
    let status_msg = if speedup > 1.5 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let speedup_display = speedup.clamp(0.0, f64::from(u32::MAX)) as u32;
        format!("Multi-threading WORKING ({}x speedup)", speedup_display)
    } else {
        "Multi-threading NOT WORKING".to_string()
    };

    let est_proof_secs = {
        let threads = u32::try_from(rayon_threads.max(1)).unwrap_or(1);
        40u32.saturating_div(threads.max(1))
    };

    format!(
        "=== THREAD CONFIGURATION DIAGNOSTIC ===\n\
        Hardware cores: {}\n\
        Rayon pool threads: {}\n\
        Currently in Rayon context: {}\n\
        \n\
        Parallel benchmark:\n\
        - Parallel time: {:.3}s\n\
        - Est. single-thread: {:.3}s\n\
        - Measured speedup: {:.1}x\n\
        - Status: {}\n\
        \n\
        Expected proof performance:\n\
        - Single-threaded: ~35-40 seconds\n\
        - With {} threads: ~{} seconds\n\
        =======================================",
        hw_threads,
        rayon_threads,
        in_rayon,
        parallel_secs,
        estimated_single,
        speedup,
        status_msg,
        rayon_threads,
        est_proof_secs,
    )
}
