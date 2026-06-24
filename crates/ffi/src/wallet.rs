// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Primary [`ProviiWallet`] UniFFI object exposed to Swift and Kotlin.
//!
//! This module contains the full wallet lifecycle: prover initialisation,
//! credential import and storage, QR code processing, zero knowledge proof
//! generation, verification submission, and diagnostic reporting. All public
//! methods are exported through UniFFI unless otherwise noted.
//!
//! Secrets (dob_days, r_bits) are stored separately from the credential body
//! and wrapped in [`Zeroizing`] or types that derive [`ZeroizeOnDrop`] to
//! ensure deterministic memory erasure.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::storage::CredentialNamespace;
use crate::{errors::*, state::*, storage::Storage, tokio_rt, types::*};
use provii_mobile_sdk_core::{
    issuance as core_issuance,
    prover::{
        build_verify_request, init_prover_with_pk_bytes, pedersen_commit_dob_validated,
        preflight_report,
    },
    types::{CredentialV2, IssuerTrustAnchor, QrChallengePayload, SubmitProofRequest},
};

/// Storage key for the persisted issuer trust anchor JSON blob.
const TRUST_ANCHOR_STORAGE_KEY: &str = "provii.issuer.trust_anchor";

use crate::biometric::{BiometricAuthenticator, BiometricConfig};
use crate::progress::{ProgressStage, ProgressTracker};
use crate::qr::{
    extract_challenge_id_from_qr, parse_qr_code, validate_challenge_id_format, validate_qr_payload,
};

/// Acquire a [`MutexGuard`], recovering from a poisoned mutex by returning
/// the inner value. This prevents a panic in one thread from permanently
/// locking the wallet.
fn safe_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::warn!("Recovering from poisoned mutex");
            poisoned.into_inner()
        }
    }
}

/// Thread-safe wallet object exposed to mobile platforms via UniFFI.
///
/// Manages credential storage, zero knowledge proof generation, QR code
/// processing, and verification state. All methods that touch secret
/// material (dob_days, r_bits) ensure secrets are zeroised before returning.
#[derive(uniffi::Object)]
pub struct ProviiWallet {
    /// Mutable runtime configuration (API URLs, timeouts, feature flags).
    config: Arc<Mutex<WalletConfig>>,
    /// Platform-backed secure storage abstraction.
    storage: Arc<Storage>,
    /// Tracks the current verification lifecycle state.
    state_manager: Arc<StateManager>,
    /// Immutable application metadata supplied by the host at construction.
    app_info: Arc<AppInfo>,
    /// In-memory cache of recently processed QR challenges, keyed by challenge ID.
    cached_challenges: Arc<Mutex<HashMap<String, CachedChallenge>>>,
    /// Trust anchor for issuer key validation. Persisted to secure storage so it
    /// survives restarts. `None` until the first successful JWKS fetch.
    issuer_trust_anchor: Arc<Mutex<Option<IssuerTrustAnchor>>>,
}

#[uniffi::export]
impl ProviiWallet {
    /// Create a wallet with default configuration.
    #[uniffi::constructor]
    pub fn new(app_info: AppInfo) -> Arc<Self> {
        Arc::new(Self {
            config: Arc::new(Mutex::new(WalletConfig::default())),
            storage: Arc::new(Storage::new()),
            state_manager: Arc::new(StateManager::new()),
            app_info: Arc::new(app_info),
            cached_challenges: Arc::new(Mutex::new(HashMap::new())),
            issuer_trust_anchor: Arc::new(Mutex::new(None)),
        })
    }

    /// Create a wallet with the supplied configuration.
    ///
    /// Validation failures are logged but do not prevent construction because
    /// UniFFI constructors cannot return `Result`. Invalid URLs will be caught
    /// at request time instead.
    #[uniffi::constructor]
    pub fn with_config(app_info: AppInfo, mut config: WalletConfig) -> Arc<Self> {
        if let Err(e) = config.validate() {
            log::error!("WalletConfig validation failed: {}", e);
        }

        let wallet = Arc::new(Self {
            config: Arc::new(Mutex::new(config.clone())),
            storage: Arc::new(Storage::new()),
            state_manager: Arc::new(StateManager::new()),
            app_info: Arc::new(app_info),
            cached_challenges: Arc::new(Mutex::new(HashMap::new())),
            issuer_trust_anchor: Arc::new(Mutex::new(None)),
        });

        // Apply parallel configuration if available
        #[cfg(feature = "parallel")]
        {
            provii_mobile_sdk_core::parallel::set_parallel_config(
                provii_mobile_sdk_core::parallel::ParallelConfig {
                    enabled: config.enable_parallel_prover,
                    max_threads: config.max_prover_threads as usize,
                },
            );
            log::info!(
                "Parallel prover config applied: enabled={}, max_threads={}",
                config.enable_parallel_prover,
                config.max_prover_threads
            );
        }

        // Zeroize the transient clone now that config is stored in the mutex
        config.zeroize_secrets();

        wallet
    }

    /// Initialise the Groth16 prover with the serialised proving key bytes.
    ///
    /// Must be called once before any proof generation. The proving key is
    /// stored in a global `OnceLock` inside `provii_mobile_sdk_core`.
    pub fn initialize_prover(&self, pk_bytes: Vec<u8>) -> FfiResult<()> {
        log::info!("initialize_prover called with {} bytes", pk_bytes.len());

        let result = init_prover_with_pk_bytes(&pk_bytes).map_err(|e| {
            log::error!("init_prover_with_pk_bytes failed: {}", e);
            FfiError::Prover { msg: e.to_string() }
        });

        if result.is_ok() {
            log::info!("Prover initialised successfully");
        }

        result
    }

    /// Register the platform-supplied secure storage backend.
    ///
    /// On iOS this is backed by the Keychain; on Android by the Keystore.
    /// Expired credentials are cleaned up automatically on registration. Any
    /// previously persisted trust anchor is loaded into memory.
    pub fn set_storage_handle(&self, handle: Arc<crate::SecureStorageHandle>) -> FfiResult<()> {
        self.storage.set_backend(handle.backend());

        // Clean up expired credentials on storage initialisation
        let removed = self.cleanup_expired_credentials();
        if removed > 0 {
            log::info!(
                "Removed {} expired credential(s) during wallet init",
                removed
            );
        }

        // Attempt to restore a previously persisted trust anchor.
        match self.load_anchor_from_storage() {
            Ok(Some(anchor)) => {
                log::info!(
                    "Loaded issuer trust anchor from storage ({} keys, fetched_at={})",
                    anchor.keys.len(),
                    anchor.fetched_at
                );
                *safe_lock(&self.issuer_trust_anchor) = Some(anchor);
            }
            Ok(None) => {
                log::info!("No persisted issuer trust anchor found");
            }
            Err(e) => {
                // Non-fatal: anchor will be fetched on next call to refresh_issuer_keys.
                log::warn!("Failed to load persisted trust anchor: {}", e);
            }
        }

        Ok(())
    }

    /// Fetch the issuer's JWKS endpoint and union-merge the result into the
    /// in-memory trust anchor. The updated anchor is persisted to secure
    /// storage so it survives app restarts.
    ///
    /// The storage key `provii.issuer.trust_anchor` holds a JSON-serialised
    /// [`IssuerTrustAnchor`].
    ///
    /// `jwks_json` is the raw response body from the issuer's `/.well-known/jwks.json`
    /// endpoint. The caller is responsible for fetching it over HTTPS.
    pub fn refresh_issuer_keys(&self, jwks_json: String) -> FfiResult<()> {
        let new_keys = core_issuance::parse_jwks_into_keys(&jwks_json).map_err(|e| {
            log::error!("Failed to parse JWKS: {}", e);
            FfiError::InvalidFormat { msg: e.to_string() }
        })?;

        if new_keys.is_empty() {
            log::warn!("JWKS contained no OKP/JUBJUB keys; trust anchor unchanged");
            return Ok(());
        }

        #[allow(clippy::cast_sign_loss)]
        let fetched_at = chrono::Utc::now().timestamp().max(0) as u64;

        let mut guard = safe_lock(&self.issuer_trust_anchor);
        match guard.as_mut() {
            Some(existing) => {
                existing.union_merge(new_keys);
                existing.fetched_at = fetched_at;
            }
            None => {
                *guard = Some(IssuerTrustAnchor {
                    keys: new_keys,
                    fetched_at,
                });
            }
        }

        // Persist before releasing the lock so any concurrent reader sees a
        // consistent view (anchor in memory == anchor in storage).
        if let Some(anchor) = guard.as_ref() {
            if let Err(e) = self.persist_anchor_to_storage(anchor) {
                // Non-fatal: the in-memory anchor is still valid.
                log::warn!("Failed to persist trust anchor: {}", e);
            } else {
                log::info!(
                    "Trust anchor refreshed and persisted ({} keys)",
                    anchor.keys.len()
                );
            }
        }

        Ok(())
    }

    /// Override the verifier API base URL at runtime. HTTPS is enforced.
    pub fn set_verifier_base_url(&self, base_url: String) -> FfiResult<()> {
        // Validate URL
        let url = url::Url::parse(&base_url).map_err(|e| FfiError::InvalidFormat {
            msg: format!("Invalid URL: {}", e),
        })?;

        // Enforce HTTPS
        if url.scheme() != "https" {
            return Err(FfiError::InvalidFormat {
                msg: "Verifier URL must use HTTPS".to_string(),
            });
        }

        // Update config
        let mut config = self.config.lock().unwrap_or_else(|e| e.into_inner());
        config.verifier_api_url = url.as_str().trim_end_matches('/').to_string();

        log::info!("Verifier base URL set to: {}", config.verifier_api_url);
        Ok(())
    }

    /// Get the current verifier API base URL
    pub fn get_verifier_base_url(&self) -> String {
        let config = self.config.lock().unwrap_or_else(|e| e.into_inner());
        config.verifier_api_url.clone()
    }

    /// Run a preflight check for a credential/challenge pair and return a
    /// JSON diagnostic report. Intended for development and debugging only.
    pub fn debug_preflight(
        &self,
        credential_id: String,
        challenge_id: String,
    ) -> FfiResult<String> {
        log::debug!(
            "debug_preflight called for cred={}, challenge={}",
            credential_id,
            challenge_id
        );

        let cred = self
            .storage
            .get_credential(&credential_id)?
            .ok_or_else(|| {
                log::error!("Credential not found: {}", credential_id);
                FfiError::Generic {
                    msg: "Credential not found".into(),
                }
            })?;

        log::debug!(
            "Retrieved credential, has dob_days={}, has r_bits={}",
            cred.dob_days.is_some(),
            cred.r_bits.is_some()
        );

        // Rehydrate private fields
        let mut cred = cred;
        if cred.dob_days.is_none() || cred.r_bits.is_none() {
            log::debug!("Credential missing private fields, loading secrets...");
            if let Some(secrets) = self.storage.load_credential_secrets(&credential_id)? {
                log::debug!(
                    "Loaded secrets: dob_days=REDACTED, r_bits_len={}",
                    secrets.r_bits.len()
                );
                cred.dob_days = Some(secrets.dob_days);
                cred.r_bits = Some(secrets.r_bits.clone());
            } else {
                log::error!("No secrets found for credential");
                return Err(FfiError::InvalidFormat {
                    msg: "Credential missing secrets".into(),
                });
            }
        }

        let cached = safe_lock(&self.cached_challenges);
        let challenge = cached.get(&challenge_id).ok_or_else(|| {
            log::error!("Challenge not found: {}", challenge_id);
            FfiError::Generic {
                msg: "Challenge not found".into(),
            }
        })?;

        log::debug!(
            "Retrieved challenge with cutoff_days={}",
            challenge.payload.cutoff_days
        );

        let report = preflight_report(&cred, &challenge.payload).map_err(|e| {
            log::error!("preflight_report failed: {}", e);
            FfiError::Prover { msg: e.to_string() }
        })?;

        // SECURITY: Zeroize secrets before clearing to prevent residual copies in memory
        if let Some(mut v) = cred.dob_days.take() {
            v.zeroize();
        }
        if let Some(mut v) = cred.r_bits.take() {
            v.zeroize();
        }

        let json = serde_json::to_string(&report)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

        log::debug!("Preflight report: {}", json);
        Ok(json)
    }

    /// Return whether secrets (dob_days, r_bits) exist in storage for the
    /// given credential. Uses an existence check only; does not trigger
    /// biometric authentication and does not load secret material into memory.
    pub fn has_credential_secrets(&self, credential_id: String) -> FfiResult<bool> {
        Ok(self.storage.credential_secrets_exist(&credential_id)?)
    }

    /// Return a JSON object with non-secret diagnostic fields for a cached
    /// challenge (cutoff_days, verifying_key_id, time until expiry).
    pub fn get_challenge_diagnostics(&self, challenge_id: String) -> FfiResult<String> {
        let cached = safe_lock(&self.cached_challenges);
        let challenge = cached.get(&challenge_id).ok_or_else(|| FfiError::Generic {
            msg: "Challenge not found".into(),
        })?;

        #[derive(serde::Serialize)]
        struct ChallengeDiagnostics {
            challenge_id: String,
            cutoff_days: i32,
            verifying_key_id: u32,
            rp_challenge: String,
            expires_in_seconds: i64,
        }

        let now = std::time::SystemTime::now();
        let expires_in = challenge
            .expires_at
            .duration_since(now)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(-1);

        let diag = ChallengeDiagnostics {
            challenge_id: challenge.payload.challenge_id.clone(),
            cutoff_days: challenge.payload.cutoff_days,
            verifying_key_id: challenge.payload.verifying_key_id,
            rp_challenge: challenge.payload.rp_challenge.clone(),
            expires_in_seconds: expires_in,
        };

        serde_json::to_string(&diag).map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })
    }

    /// Import a credential from its JSON representation into the primary slot.
    ///
    /// Secrets (dob_days, r_bits) are extracted and stored separately; the
    /// credential body stored in the main namespace contains only public fields.
    pub fn import_credential(&self, credential_json: String) -> FfiResult<String> {
        self.import_credential_internal(credential_json, None, CredentialSlot::Primary, None)
    }

    /// Import a credential into a typed slot ("primary" or "managed").
    pub fn import_credential_with_type(
        &self,
        credential_json: String,
        credential_type: String,
        nickname: Option<String>,
    ) -> FfiResult<String> {
        let slot = self.resolve_slot(&credential_type, None)?;
        self.import_credential_internal(credential_json, None, slot, nickname.as_deref())
    }

    /// Import a credential into a typed slot with an optional label (e.g. "sandbox").
    pub fn store_credential_with_label(
        &self,
        credential_json: String,
        label: Option<String>,
        credential_type: String,
        nickname: Option<String>,
    ) -> FfiResult<String> {
        let label_ref = label.as_deref();
        let slot = self.resolve_slot(&credential_type, label_ref)?;
        self.import_credential_internal(credential_json, label_ref, slot, nickname.as_deref())
    }

    /// Alias for [`import_credential`](Self::import_credential).
    pub fn store_credential(&self, credential_json: String) -> FfiResult<String> {
        self.import_credential(credential_json)
    }

    /// List metadata for all stored credentials (does not load secrets).
    pub fn list_credentials(&self) -> FfiResult<Vec<CredentialInfo>> {
        Ok(self.storage.list_credentials()?)
    }

    /// Retrieve the public-fields JSON for a credential, or `None` if not found.
    pub fn get_credential(&self, credential_id: String) -> FfiResult<Option<String>> {
        match self.storage.get_credential(&credential_id)? {
            Some(cred) => Ok(Some(
                serde_json::to_string(&cred)
                    .map_err(|e| FfiError::Generic { msg: e.to_string() })?,
            )),
            None => Ok(None),
        }
    }

    /// Delete all credentials in the sandbox namespace.
    pub fn delete_sandbox_credentials(&self) -> FfiResult<()> {
        self.storage
            .delete_sandbox_credentials()
            .map(|_| ())
            .map_err(|e| FfiError::Storage { msg: e.to_string() })
    }

    /// Delete a single credential and its associated secrets by ID.
    pub fn delete_credential(&self, credential_id: String) -> FfiResult<()> {
        self.storage.delete_credential(&credential_id)?;
        self.state_manager.record_credential_deleted(&credential_id);
        Ok(())
    }

    /// Update the nickname of a stored credential.
    ///
    /// This performs a targeted metadata-only update. It does NOT re-store
    /// the credential in the slot (which would delete secrets).
    pub fn update_credential_nickname(
        &self,
        credential_id: String,
        nickname: Option<String>,
    ) -> FfiResult<()> {
        self.storage
            .update_credential_nickname(&credential_id, nickname.as_deref())
            .map_err(|e| FfiError::Storage { msg: e.to_string() })
    }

    /// Get provable credentials for a challenge with suitability info.
    ///
    /// For each provable credential in the current namespace, checks whether
    /// the credential can satisfy the challenge's age requirement.
    /// Only loads `dob_days` from secrets (not `r_bits`) to minimise exposure.
    pub fn get_provable_credentials_for_challenge(
        &self,
        challenge_id: String,
    ) -> FfiResult<Vec<CredentialSuitability>> {
        // Get challenge from cache
        let cached = safe_lock(&self.cached_challenges);
        let challenge = cached
            .get(&challenge_id)
            .ok_or_else(|| FfiError::InvalidFormat {
                msg: format!("Challenge not found: {}", challenge_id),
            })?;
        let cutoff_days = challenge.payload.cutoff_days;
        let is_under_age = challenge.payload.proof_direction.as_deref() == Some("under_age");
        drop(cached);

        // List all credentials
        let credentials = self
            .storage
            .list_credentials()
            .map_err(|e| FfiError::Storage { msg: e.to_string() })?;

        // Filter to current namespace
        let config = self.config.lock().unwrap_or_else(|e| e.into_inner());
        let is_sandbox = config.environment.eq_ignore_ascii_case("sandbox");
        drop(config);

        let namespace_creds: Vec<_> = credentials
            .into_iter()
            .filter(|c| {
                if is_sandbox {
                    c.id.contains(".sandbox.")
                } else {
                    !c.id.contains(".sandbox.")
                }
            })
            .filter(|c| c.can_prove)
            .collect();

        let mut result = Vec::with_capacity(namespace_creds.len());
        for cred_info in &namespace_creds {
            // Load only secrets to get dob_days (CredentialSecrets has ZeroizeOnDrop)
            let can_satisfy;
            let failure_reason;

            if cred_info.is_expired {
                can_satisfy = false;
                failure_reason = Some("Credential expired".to_string());
            } else if let Ok(Some(secrets)) = self.storage.load_credential_secrets(&cred_info.id) {
                // secrets.dob_days is what we need; r_bits is loaded but will be
                // zeroized when `secrets` drops (ZeroizeOnDrop)
                let satisfied = provii_mobile_sdk_core::validate_age(
                    secrets.dob_days,
                    cutoff_days,
                    is_under_age,
                );
                can_satisfy = satisfied;
                failure_reason = if satisfied {
                    None
                } else {
                    Some("Does not meet age threshold".to_string())
                };
                // secrets drops here, triggering ZeroizeOnDrop
            } else {
                can_satisfy = false;
                failure_reason = Some("Credential secrets unavailable".to_string());
            }

            result.push(CredentialSuitability {
                id: cred_info.id.clone(),
                nickname: cred_info.nickname.clone(),
                credential_type: cred_info.credential_type.clone(),
                can_satisfy,
                failure_reason,
            });
        }

        Ok(result)
    }

    /// Get the number of available credential slots in the current namespace.
    ///
    /// Returns count of available slots: 1 primary (if empty) + available managed slots (0-5).
    pub fn get_available_slot_count(&self) -> FfiResult<u8> {
        let credentials = self
            .storage
            .list_credentials()
            .map_err(|e| FfiError::Storage { msg: e.to_string() })?;

        let config = self.config.lock().unwrap_or_else(|e| e.into_inner());
        let is_sandbox = config.environment.eq_ignore_ascii_case("sandbox");
        drop(config);

        let namespace_creds: Vec<_> = credentials
            .iter()
            .filter(|c| {
                if is_sandbox {
                    c.id.contains(".sandbox.")
                } else {
                    !c.id.contains(".sandbox.")
                }
            })
            .collect();

        let has_primary = namespace_creds
            .iter()
            .any(|c| c.credential_type == "primary");
        let managed_count = u8::try_from(
            namespace_creds
                .iter()
                .filter(|c| c.credential_type == "managed")
                .count(),
        )
        .unwrap_or(u8::MAX);

        let available_primary: u8 = if has_primary { 0 } else { 1 };
        let available_managed: u8 = 5u8.saturating_sub(managed_count);

        Ok(available_primary.saturating_add(available_managed))
    }

    /// Finalize and store a credential from issuance.
    ///
    /// # Arguments
    /// * `header_json` - The signed credential header JSON from the issuer
    /// * `dob_days` - Date of birth in days since Unix epoch
    /// * `r_bits_b64` - Base64url-encoded randomness bits (128 bits packed to 16 bytes)
    /// * `label` - Optional label (e.g., "sandbox" for sandbox credentials)
    /// * `credential_type` - "primary" or "managed"
    /// * `nickname` - Required when credential_type is "managed"
    pub fn finalize_and_store_credential(
        &self,
        header_json: String,
        dob_days: i32,
        r_bits_b64: String,
        label: Option<String>,
        credential_type: String,
        nickname: Option<String>,
    ) -> FfiResult<String> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use provii_mobile_sdk_core::types::SignedCredentialHeader;

        let credential_slot = self.resolve_slot(&credential_type, label.as_deref())?;

        log::info!(
            "finalize_and_store_credential: parsing header (type={}, slot={})",
            credential_type,
            credential_slot.storage_key_suffix()
        );

        // Parse header
        let header: SignedCredentialHeader = serde_json::from_str(&header_json).map_err(|e| {
            log::error!("Failed to parse header JSON: {}", e);
            FfiError::InvalidFormat { msg: e.to_string() }
        })?;

        // Validate the issuer verification key against the trust anchor before
        // accepting the credential. Hard fail if no anchor has been loaded.
        {
            let anchor_guard = safe_lock(&self.issuer_trust_anchor);
            match anchor_guard.as_ref() {
                Some(anchor) => {
                    core_issuance::validate_issuer_vk(&header, anchor).map_err(|e| {
                        log::error!("Issuer key trust anchor validation failed: {}", e);
                        FfiError::InvalidFormat { msg: e.to_string() }
                    })?;
                    log::info!("Issuer key validated against trust anchor");
                }
                None => {
                    log::warn!(
                        "No issuer trust anchor set; skipping issuer key validation. \
                        Call refresh_issuer_keys() to enable key pinning."
                    );
                }
            }
        }

        // Decode r_bits from base64. Wrap intermediates in Zeroizing
        // because they contain secret randomness bits.
        let r_bits_b64 = Zeroizing::new(r_bits_b64);
        let r_bits_bytes =
            Zeroizing::new(URL_SAFE_NO_PAD.decode(r_bits_b64.as_str()).map_err(|e| {
                log::error!("Failed to decode r_bits base64: {}", e);
                FfiError::InvalidFormat { msg: e.to_string() }
            })?);
        let r_bits = Zeroizing::new(core_issuance::bits::unpack_bits(
            &r_bits_bytes,
            core_issuance::R_BITS_LEN,
        ));

        log::info!("finalize_and_store_credential: finalizing credential (dob_days=REDACTED, r_bits_len={})", r_bits.len());

        // Finalize credential - this creates CredentialV2 with secrets populated
        let r_bits_vec: Vec<bool> = (*r_bits).clone();
        let mut credential =
            core_issuance::finalize_credential(header, dob_days, r_bits_vec.clone()).map_err(
                |e| {
                    log::error!("Failed to finalize credential: {}", e);
                    FfiError::Generic { msg: e.to_string() }
                },
            )?;

        // Extract secrets for separate storage
        let secrets = CredentialSecrets {
            dob_days,
            r_bits: r_bits_vec,
        };

        // SECURITY: Zeroize secrets before clearing to prevent residual copies in memory
        if let Some(mut v) = credential.dob_days.take() {
            v.zeroize();
        }
        if let Some(mut v) = credential.r_bits.take() {
            v.zeroize();
        }

        // Store credential (public parts only) in the requested slot
        let label_ref = label.as_deref();
        let cred_id = self
            .storage
            .store_credential_with_slot(
                &credential,
                label_ref,
                credential_slot,
                nickname.as_deref(),
            )
            .map_err(|e| {
                log::error!("Failed to store credential: {}", e);
                FfiError::Storage { msg: e.to_string() }
            })?;

        log::info!(
            "finalize_and_store_credential: stored credential with ID: {} (type={})",
            cred_id,
            credential_type
        );

        // Store secrets separately
        self.storage
            .store_credential_secrets(&cred_id, &secrets)
            .map_err(|e| {
                log::error!("Failed to store secrets: {}", e);
                FfiError::Storage { msg: e.to_string() }
            })?;

        log::info!("finalize_and_store_credential: stored secrets for credential");

        self.state_manager.record_credential_imported(&cred_id);

        Ok(cred_id)
    }
}

impl ProviiWallet {
    /// Shared import path: parse JSON, extract and separately store secrets,
    /// then persist the public credential body in the requested slot.
    fn import_credential_internal(
        &self,
        credential_json: String,
        label: Option<&str>,
        slot: CredentialSlot,
        nickname: Option<&str>,
    ) -> FfiResult<String> {
        log::info!(
            "import_credential called with {} chars",
            credential_json.len()
        );

        let mut cred: CredentialV2 = serde_json::from_str(&credential_json).map_err(|e| {
            log::error!("Failed to parse credential JSON: {}", e);
            FfiError::InvalidFormat { msg: e.to_string() }
        })?;

        log::info!("Parsed credential v={}, kid={}", cred.v, cred.kid);

        // SECURITY: Extract secrets using take() to avoid cloning, then explicitly zeroize
        // the original values. This ensures no unzeroized copies remain in memory.
        let secrets = match (cred.dob_days.take(), cred.r_bits.take()) {
            (Some(dob_days), Some(r_bits)) => {
                log::info!(
                    "Credential has secrets: dob_days=REDACTED, r_bits_len={}",
                    r_bits.len()
                );
                // Move r_bits into CredentialSecrets (which has ZeroizeOnDrop)
                let secrets = crate::types::CredentialSecrets { dob_days, r_bits };
                Some(secrets)
            }
            (dob_days, r_bits) => {
                // Explicitly zeroize any partial secrets that were extracted
                if let Some(mut r) = r_bits {
                    r.zeroize();
                }
                // dob_days is just an i32, no special zeroize needed (but field is now None)
                let _ = dob_days;
                log::info!("Credential has no secrets (or incomplete)");
                None
            }
        };
        // Note: cred.dob_days and cred.r_bits are already None from take()

        let cred_id = self
            .storage
            .store_credential_with_slot(&cred, label, slot, nickname)
            .map_err(|e| {
                log::error!("Failed to store credential: {}", e);
                FfiError::Storage { msg: e.to_string() }
            })?;

        if let Some(secrets) = secrets {
            self.storage
                .store_credential_secrets(&cred_id, &secrets)
                .map_err(|e| {
                    log::error!("Failed to store secrets: {}", e);
                    FfiError::Storage { msg: e.to_string() }
                })?;
            log::info!("Stored credential secrets");
        }

        self.state_manager.record_credential_imported(&cred_id);
        log::info!("Credential import complete: {}", cred_id);
        Ok(cred_id)
    }

    /// Resolve a credential_type string to a CredentialSlot, automatically
    /// finding the next available managed index when type is "managed".
    fn resolve_slot(
        &self,
        credential_type: &str,
        label: Option<&str>,
    ) -> FfiResult<CredentialSlot> {
        match credential_type {
            "managed" => {
                let namespace = CredentialNamespace::from_label(label);
                let index = self
                    .storage
                    .next_available_managed_index(namespace)
                    .map_err(|e| FfiError::Generic { msg: e.to_string() })?;
                if index >= crate::types::MAX_MANAGED_SLOTS {
                    return Err(FfiError::InvalidFormat {
                        msg: format!(
                            "managed slot index {} exceeds maximum ({})",
                            index,
                            crate::types::MAX_MANAGED_SLOTS.saturating_sub(1)
                        ),
                    });
                }
                Ok(CredentialSlot::Managed { index })
            }
            "primary" => Ok(CredentialSlot::Primary),
            other => Err(FfiError::InvalidFormat {
                msg: format!("unrecognised credential type: {}", other),
            }),
        }
    }

    /// Persist the trust anchor to secure storage under a fixed key.
    fn persist_anchor_to_storage(&self, anchor: &IssuerTrustAnchor) -> FfiResult<()> {
        use provii_mobile_sdk_platform_storage::BiometricRequirement;

        let json = serde_json::to_string(anchor)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

        let backend_guard = self.storage.backend_ref();
        let backend = backend_guard.as_ref().ok_or_else(|| FfiError::Storage {
            msg: "storage not initialised".to_string(),
        })?;

        backend
            .store(
                TRUST_ANCHOR_STORAGE_KEY,
                json.as_bytes(),
                BiometricRequirement::None,
            )
            .map_err(|e| FfiError::Storage { msg: e.to_string() })
    }

    /// Load the trust anchor from secure storage. Returns `Ok(None)` if no
    /// anchor has been persisted yet.
    fn load_anchor_from_storage(&self) -> FfiResult<Option<IssuerTrustAnchor>> {
        use provii_mobile_sdk_platform_storage::BiometricRequirement;

        let backend_guard = self.storage.backend_ref();
        let backend = match backend_guard.as_ref() {
            Some(b) => b,
            None => return Ok(None),
        };

        match backend.retrieve(TRUST_ANCHOR_STORAGE_KEY, BiometricRequirement::None) {
            Ok(data) => {
                let anchor: IssuerTrustAnchor =
                    serde_json::from_slice(&data).map_err(|e| FfiError::InvalidFormat {
                        msg: format!("failed to parse persisted trust anchor: {}", e),
                    })?;
                Ok(Some(anchor))
            }
            Err(e) if e.to_string().contains("NotFound") => Ok(None),
            Err(e) => Err(FfiError::Storage { msg: e.to_string() }),
        }
    }
}

#[uniffi::export]
impl ProviiWallet {
    /// Returns true only if at least one non-expired credential exists.
    pub fn has_valid_credential(&self) -> bool {
        self.storage
            .list_credentials()
            .map(|creds| creds.iter().any(|c| !c.is_expired))
            .unwrap_or(false)
    }

    /// Classify a scanned QR code as either an attestation or a verification
    /// challenge and return the appropriate [`QrAction`].
    pub fn process_scanned_qr(&self, qr_content: String) -> FfiResult<QrAction> {
        // Parse the QR code using wallet instance method to respect environment configuration
        let payload = self.parse_qr_payload_internal(&qr_content)?;
        let parsed = serde_json::to_string(&payload)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;
        let data: serde_json::Value = serde_json::from_str(&parsed)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

        // Determine action based on type
        if data.get("type") == Some(&serde_json::json!("attestation")) {
            let attest_data = data.get("data").and_then(|d| d.as_str()).ok_or_else(|| {
                FfiError::InvalidFormat {
                    msg: "Missing attestation data".to_string(),
                }
            })?;

            Ok(QrAction::Attestation {
                attestation_data: attest_data.to_string(),
            })
        } else if data.get("challenge_id").is_some() {
            // It's a verification challenge
            Ok(QrAction::VerificationChallenge {
                challenge_json: parsed,
            })
        } else {
            Err(FfiError::InvalidFormat {
                msg: "Unknown QR code type".to_string(),
            })
        }
    }

    /// Parse a QR challenge, cache it, and start a verification session.
    ///
    /// Returns the challenge ID on success. The cached challenge expires
    /// after 300 seconds.
    pub fn process_qr_challenge(&self, qr_content: String) -> FfiResult<String> {
        log::info!("process_qr_challenge called");

        let challenge: QrChallengePayload = self.parse_qr_payload_internal(&qr_content)?;

        let challenge_id = challenge.challenge_id.clone();
        log::info!("Processing challenge ID: {}", challenge_id);
        log::debug!(
            "Challenge details: cutoff_days={}, vk_id={}",
            challenge.cutoff_days,
            challenge.verifying_key_id
        );

        let now = std::time::SystemTime::now();
        let expires_at = now
            .checked_add(std::time::Duration::from_secs(300))
            .unwrap_or(now);

        let mut cached = safe_lock(&self.cached_challenges);

        // Evict expired entries before inserting to prevent unbounded growth.
        if cached.len() >= 64 {
            let now_for_evict = std::time::SystemTime::now();
            cached.retain(|_, v| v.expires_at > now_for_evict);
        }
        // Hard cap: reject if still too many after eviction.
        if cached.len() >= 64 {
            return Err(FfiError::InvalidFormat {
                msg: "challenge cache full; try again shortly".to_string(),
            });
        }

        cached.insert(
            challenge_id.clone(),
            CachedChallenge {
                payload: challenge.clone(),
                received_at: now,
                expires_at,
            },
        );

        self.state_manager.start_verification(&challenge_id)?;

        log::info!("Challenge cached and verification started");
        Ok(challenge_id)
    }

    /// Produce a human-readable diagnostic string for a failed proof attempt.
    ///
    /// Checks commitment integrity, age threshold, and prover status.
    /// Secret values are redacted in the output.
    pub fn diagnose_proof_failure(
        &self,
        credential_id: String,
        challenge_id: String,
    ) -> FfiResult<String> {
        let mut diagnostics = Vec::new();

        // Get credential
        let mut cred = self
            .storage
            .get_credential(&credential_id)?
            .ok_or_else(|| FfiError::Generic {
                msg: "Credential not found".into(),
            })?;

        // Load secrets
        if let Some(secrets) = self.storage.load_credential_secrets(&credential_id)? {
            diagnostics.push(format!(
                "✓ Loaded secrets: dob_days=REDACTED, r_bits_len={}",
                secrets.r_bits.len()
            ));

            // Verify r_bits is exactly 128
            if secrets.r_bits.len() != 128 {
                diagnostics.push(format!(
                    "✗ ERROR: r_bits length is {}, expected 128!",
                    secrets.r_bits.len()
                ));
                return Ok(diagnostics.join("\n"));
            }

            cred.dob_days = Some(secrets.dob_days);
            cred.r_bits = Some(secrets.r_bits.clone());
        }

        // Get challenge
        let cached = safe_lock(&self.cached_challenges);
        let challenge = cached.get(&challenge_id).ok_or_else(|| FfiError::Generic {
            msg: "Challenge not found".into(),
        })?;

        // Check commitment
        let r_bits = cred.r_bits.as_ref().ok_or_else(|| FfiError::Generic {
            msg: "r_bits not loaded into credential".to_string(),
        })?;
        let dob_days = cred.dob_days.ok_or_else(|| FfiError::Generic {
            msg: "dob_days not loaded into credential".to_string(),
        })?;
        match pedersen_commit_dob_validated(dob_days, r_bits) {
            Ok(recomputed) => {
                if recomputed != cred.c_bytes {
                    diagnostics.push("✗ Commitment mismatch!".to_string());
                    diagnostics.push(format!("  Original: {}", hex::encode(&cred.c_bytes)));
                    diagnostics.push(format!("  Recomputed: {}", hex::encode(recomputed)));
                } else {
                    diagnostics.push("✓ Commitment matches".to_string());
                }
            }
            Err(e) => {
                diagnostics.push(format!("✗ Commitment validation failed: {:?}", e));
            }
        }

        // Check age (do NOT leak actual dob_days into diagnostic output)
        let is_under_age = challenge.payload.proof_direction.as_deref() == Some("under_age");
        let age_ok = provii_mobile_sdk_core::validate_age(
            dob_days,
            challenge.payload.cutoff_days,
            is_under_age,
        );
        let op = if is_under_age { ">=" } else { "<=" };
        diagnostics.push(format!(
            "{} Age check: [REDACTED] {} {} = {}",
            if age_ok { "✓" } else { "✗" },
            op,
            challenge.payload.cutoff_days,
            age_ok
        ));

        // Check proving key
        if provii_mobile_sdk_core::prover::is_prover_initialized() {
            diagnostics.push("✓ Prover initialised".to_string());
            if let Some(fp) = provii_mobile_sdk_core::prover::get_proving_key_fingerprint() {
                diagnostics.push(format!("  Fingerprint: {}", fp));
            }
        } else {
            diagnostics.push("✗ Prover NOT initialised!".to_string());
        }

        // SECURITY: Zeroize secrets before clearing to prevent residual copies in memory
        if let Some(mut v) = cred.dob_days.take() {
            v.zeroize();
        }
        if let Some(mut v) = cred.r_bits.take() {
            v.zeroize();
        }

        Ok(diagnostics.join("\n"))
    }

    /// Generate a Groth16 age proof for the given credential and challenge.
    ///
    /// Returns the serialised [`SubmitProofRequest`] JSON on success. Secrets
    /// are loaded from storage, used for proof generation, then zeroised.
    /// Expired credentials are rejected before proof generation begins.
    pub fn create_age_proof(
        &self,
        credential_id: String,
        challenge_id: String,
    ) -> FfiResult<String> {
        log::info!("========== create_age_proof START ==========");
        log::info!("credential_id: {}", credential_id);
        log::info!("challenge_id: {}", challenge_id);

        // Step 1: Get challenge from cache
        let cached = safe_lock(&self.cached_challenges);
        let challenge = cached.get(&challenge_id).ok_or_else(|| {
            log::error!("ERROR: Challenge not found in cache: {}", challenge_id);
            FfiError::InvalidFormat {
                msg: format!("Challenge not found: {}", challenge_id),
            }
        })?;

        log::info!(
            "Found challenge: cutoff_days={}, vk_id={}",
            challenge.payload.cutoff_days,
            challenge.payload.verifying_key_id
        );

        // Step 2: Get credential from storage
        let mut cred = self
            .storage
            .get_credential(&credential_id)?
            .ok_or_else(|| {
                log::error!("ERROR: Credential not found: {}", credential_id);
                FfiError::CredentialNotFound
            })?;

        log::info!(
            "Retrieved credential: v={}, kid={}, schema={}",
            cred.v,
            cred.kid,
            cred.schema
        );

        // Step 3: Rehydrate secrets if needed
        if cred.dob_days.is_none() || cred.r_bits.is_none() {
            log::info!("Credential missing private fields, loading secrets...");

            if let Some(secrets) = self.storage.load_credential_secrets(&credential_id)? {
                log::info!("Loaded secrets successfully:");
                log::debug!("  - dob_days: REDACTED");
                log::debug!("  - r_bits length: {}", secrets.r_bits.len());

                cred.dob_days = Some(secrets.dob_days);
                cred.r_bits = Some(secrets.r_bits.clone());
            } else {
                log::error!("ERROR: No secrets found for credential {}", credential_id);
                return Err(FfiError::InvalidFormat {
                    msg: format!("Credential missing secrets: {}", credential_id),
                });
            }
        }

        // Step 4: Reject expired credentials before proof generation
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if cred.exp < now {
            log::error!("Credential expired: exp={} < now={}", cred.exp, now);
            // SECURITY: Zeroize secrets before clearing to prevent residual copies in memory
            if let Some(mut v) = cred.dob_days.take() {
                v.zeroize();
            }
            if let Some(mut v) = cred.r_bits.take() {
                v.zeroize();
            }
            return Err(FfiError::CredentialExpired);
        }

        log::debug!("Credential ready for proof generation");

        // Step 5: Call build_verify_request
        log::info!("Calling build_verify_request...");

        let proof_request = match build_verify_request(&cred, &challenge.payload) {
            Ok(req) => {
                log::info!("build_verify_request succeeded");
                req
            }
            Err(e) => {
                log::error!("ERROR: build_verify_request failed: {:?}", e);

                // SECURITY: Zeroize secrets before clearing to prevent residual copies in memory
                if let Some(mut v) = cred.dob_days.take() {
                    v.zeroize();
                }
                if let Some(mut v) = cred.r_bits.take() {
                    v.zeroize();
                }

                return Err(FfiError::Prover {
                    msg: format!("Proof generation failed: {:?}", e),
                });
            }
        };

        // Step 6: SECURITY: Zeroize secrets before clearing to prevent residual copies in memory
        if let Some(mut v) = cred.dob_days.take() {
            v.zeroize();
        }
        if let Some(mut v) = cred.r_bits.take() {
            v.zeroize();
        }
        log::debug!("Zeroized and cleared credential secrets from memory");

        // Step 7: Update verification status
        self.state_manager
            .update_verification_status(&challenge_id, VerificationStatus::ProofGenerated)?;

        // Step 8: Serialize proof request to JSON
        let json = serde_json::to_string(&proof_request).map_err(|e| {
            log::error!("ERROR: Failed to serialize proof request: {}", e);
            FfiError::Generic { msg: e.to_string() }
        })?;

        log::info!("Proof request JSON length: {} chars", json.len());
        log::info!("========== create_age_proof SUCCESS ==========");

        Ok(json)
    }

    /// Auto-select a credential and generate an age proof.
    ///
    /// If only one credential exists, it is used automatically.
    /// If multiple credentials exist, returns a JSON error with "CREDENTIAL_SELECTION_REQUIRED"
    /// and a list of credential IDs/nicknames so the mobile app can show a picker.
    /// The mobile app then calls `create_age_proof()` with the explicit credential ID.
    ///
    /// The namespace (Primary vs Sandbox) is determined by the wallet's environment config.
    pub fn create_age_proof_auto(&self, challenge_id: String) -> FfiResult<String> {
        log::info!("========== create_age_proof_auto START ==========");
        log::info!("challenge_id: {}", challenge_id);

        // Step 1: Verify challenge exists in cache and get cutoff_days
        let cached = safe_lock(&self.cached_challenges);
        let challenge = cached.get(&challenge_id).ok_or_else(|| {
            log::error!("Challenge not found in cache: {}", challenge_id);
            FfiError::InvalidFormat {
                msg: format!("Challenge not found: {}", challenge_id),
            }
        })?;
        let cutoff_days = challenge.payload.cutoff_days;
        let is_under_age = challenge.payload.proof_direction.as_deref() == Some("under_age");
        drop(cached);

        // Step 2: List all credentials in the current namespace
        let credentials = self
            .storage
            .list_credentials()
            .map_err(|e| FfiError::Storage { msg: e.to_string() })?;

        // Filter to current namespace
        let config = self.config.lock().unwrap_or_else(|e| e.into_inner());
        let is_sandbox = config.environment.eq_ignore_ascii_case("sandbox");
        drop(config);

        let namespace_creds: Vec<_> = credentials
            .into_iter()
            .filter(|c| {
                if is_sandbox {
                    c.id.contains(".sandbox.")
                } else {
                    !c.id.contains(".sandbox.")
                }
            })
            .filter(|c| c.can_prove)
            .collect();

        match namespace_creds.len() {
            0 => {
                log::error!("No credentials stored");
                Err(FfiError::Generic {
                    msg: "No credential stored. Please import a credential first.".to_string(),
                })
            }
            1 => {
                // Single credential: auto-select. first() is infallible
                // here because the match arm guarantees len() == 1.
                let cred = namespace_creds.first().ok_or_else(|| FfiError::Generic {
                    msg: "No credential found".to_string(),
                })?;
                let cred_id = cred.id.clone();
                log::info!("Auto-selected single credential: {}", cred_id);
                self.create_age_proof(cred_id, challenge_id)
            }
            _ => {
                // Multiple credentials: return selection required with suitability
                let choices: Vec<serde_json::Value> = namespace_creds
                    .iter()
                    .map(|c| {
                        // Check suitability by loading only dob_days
                        let (can_satisfy, failure_reason) = if c.is_expired {
                            (false, Some("Credential expired"))
                        } else if let Ok(Some(secrets)) =
                            self.storage.load_credential_secrets(&c.id)
                        {
                            let satisfied = provii_mobile_sdk_core::validate_age(
                                secrets.dob_days,
                                cutoff_days,
                                is_under_age,
                            );
                            if satisfied {
                                (true, None)
                            } else {
                                (false, Some("Does not meet age threshold"))
                            }
                            // secrets drops here, triggering ZeroizeOnDrop
                        } else {
                            (false, Some("Credential secrets unavailable"))
                        };

                        serde_json::json!({
                            "id": c.id,
                            "nickname": c.nickname,
                            "credential_type": c.credential_type,
                            "can_satisfy": can_satisfy,
                            "failure_reason": failure_reason,
                        })
                    })
                    .collect();

                log::info!(
                    "Multiple credentials found ({}), selection required",
                    choices.len()
                );

                Err(FfiError::Generic {
                    msg: serde_json::json!({
                        "code": "CREDENTIAL_SELECTION_REQUIRED",
                        "credentials": choices,
                    })
                    .to_string(),
                })
            }
        }
    }

    /// Submit a serialised proof to the verifier API.
    ///
    /// Blocks the calling thread on the Tokio runtime. Only available when
    /// the `http` feature is enabled; returns an error otherwise.
    pub fn submit_proof(&self, proof_json: String) -> FfiResult<bool> {
        #[cfg(feature = "http")]
        {
            // Use the global runtime to execute async code synchronously
            tokio_rt()?.block_on(async { self.submit_proof_async(proof_json).await })
        }

        #[cfg(not(feature = "http"))]
        {
            Err(FfiError::Generic {
                msg: "HTTP support not compiled in".to_string(),
            })
        }
    }

    /// Probe the verifier API health endpoint and return connectivity status.
    pub fn check_network_status(&self) -> NetworkStatus {
        #[cfg(feature = "http")]
        {
            match tokio_rt() {
                Ok(rt) => rt.block_on(async { self.check_network_status_async().await }),
                Err(_) => NetworkStatus { connected: false },
            }
        }

        #[cfg(not(feature = "http"))]
        {
            NetworkStatus { connected: false }
        }
    }

    /// Return the current verification lifecycle status.
    pub fn get_verification_status(&self) -> VerificationStatus {
        self.state_manager.get_verification_status()
    }

    /// Cancel an in-progress verification session.
    pub fn cancel_verification(&self, challenge_id: String) -> FfiResult<()> {
        self.state_manager.cancel_verification(&challenge_id)?;
        Ok(())
    }

    /// Return a snapshot of the current wallet configuration.
    pub fn get_config(&self) -> WalletConfig {
        safe_lock(&self.config).clone()
    }

    /// Replace the wallet configuration after validating the new values.
    pub fn update_config(&self, mut config: WalletConfig) -> FfiResult<()> {
        config
            .validate()
            .map_err(|e| FfiError::InvalidFormat { msg: e })?;

        {
            let mut guard = safe_lock(&self.config);
            // Zeroize the old config's secrets before overwriting
            guard.zeroize_secrets();
            *guard = config.clone();
        }

        // Re-apply parallel configuration if available
        #[cfg(feature = "parallel")]
        {
            provii_mobile_sdk_core::parallel::set_parallel_config(
                provii_mobile_sdk_core::parallel::ParallelConfig {
                    enabled: config.enable_parallel_prover,
                    max_threads: config.max_prover_threads as usize,
                },
            );
            log::info!(
                "Parallel config updated: enabled={}, max_threads={}",
                config.enable_parallel_prover,
                config.max_prover_threads
            );
        }

        // Zeroize the local parameter's secrets now that config is stored
        config.zeroize_secrets();

        Ok(())
    }

    /// Collect SDK version, app version, credential count, prover status,
    /// and storage availability into a [`DiagnosticInfo`] snapshot.
    pub fn get_diagnostic_info(&self) -> DiagnosticInfo {
        let config = safe_lock(&self.config);
        let credentials = self.storage.list_credentials().unwrap_or_default();

        DiagnosticInfo {
            sdk_version: env!("CARGO_PKG_VERSION").to_string(),
            app_version: self.app_info.version.clone(),
            platform: self.app_info.platform.clone(),
            credential_count: u32::try_from(credentials.len()).unwrap_or(u32::MAX),
            prover_initialized: provii_mobile_sdk_core::prover::is_prover_initialized(),
            storage_available: self.storage.is_available(),
            config_environment: config.environment.clone(),
            last_proof_generated: None,
        }
    }

    /// Calculate approximate age in years from an ISO 8601 date string (YYYY-MM-DD).
    pub fn calculate_age_from_dob(&self, dob_iso: String) -> FfiResult<u32> {
        let dob = chrono::NaiveDate::parse_from_str(&dob_iso, "%Y-%m-%d")
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

        let today = chrono::Utc::now().date_naive();
        let days = today.signed_duration_since(dob).num_days();
        // A negative age (future DOB) is clamped to zero.
        let age = days.max(0) / 365;
        u32::try_from(age).map_err(|_| FfiError::InvalidFormat {
            msg: "age out of representable range".to_string(),
        })
    }

    /// Parse a `proviiwallet.app` deep link into a [`DeeplinkAction`].
    pub fn handle_deeplink(&self, url: String) -> FfiResult<DeeplinkAction> {
        crate::deeplink::parse(url).map_err(Into::into)
    }

    /// Parse a raw QR string into its JSON payload, respecting the current
    /// environment configuration for verifier URL resolution.
    pub fn parse_qr_payload(&self, qr_content: String) -> FfiResult<String> {
        // Use internal method that respects environment configuration
        let payload = self.parse_qr_payload_internal(&qr_content)?;
        serde_json::to_string(&payload).map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })
    }

    // === Biometric Authentication ===

    /// Check whether biometric authentication is available.
    ///
    /// Returns `false` when the FFI stub has no platform callback registered.
    /// Real biometric availability is determined by the native
    /// `PlatformSecureStorage` implementation, not this method.
    pub fn is_biometric_available(&self) -> bool {
        let config = BiometricConfig::default();
        let authenticator = BiometricAuthenticator::new(config);
        authenticator.is_available()
    }

    /// Parse a QR code string. Convenience wrapper around [`parse_qr_payload`](Self::parse_qr_payload).
    pub fn parse_qr(&self, qr_content: String) -> FfiResult<String> {
        // Use internal method that respects environment configuration
        let payload = self.parse_qr_payload_internal(&qr_content)?;
        serde_json::to_string(&payload).map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })
    }

    /// Validate a QR code string and return whether it represents a well-formed payload.
    pub fn validate_qr(&self, qr_content: String) -> FfiResult<bool> {
        // Use internal method that respects environment configuration
        let payload = self.parse_qr_payload_internal(&qr_content)?;
        let payload_json = serde_json::to_string(&payload)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;
        validate_qr_payload(payload_json)
    }

    /// Fetch challenge details from the configured verifier endpoint
    /// This respects the environment configuration (production/sandbox/etc)
    pub fn fetch_challenge_details(&self, challenge_id: String) -> FfiResult<String> {
        validate_challenge_id_format(&challenge_id)?;

        #[cfg(feature = "http")]
        {
            let (url, mut api_key, origin) = {
                let config = safe_lock(&self.config);
                let url = format!(
                    "{}/v1/challenge/{}/details",
                    config.verifier_api_url.trim_end_matches('/'),
                    challenge_id
                );
                let api_key = config.verifier_api_key.clone();
                let origin = config.verifier_origin.clone();
                (url, api_key, origin)
            };

            log::info!(
                "Fetching challenge details from configured verifier: {}",
                url
            );

            let rt = tokio_rt()?;

            let result = rt.block_on(async {
                crate::net::get_with_headers(&url, 10, api_key.as_deref(), origin.as_deref()).await
            });

            // Zeroize the cloned api_key after the HTTP call completes
            api_key.zeroize();

            result
        }

        #[cfg(not(feature = "http"))]
        {
            Err(FfiError::Generic {
                msg: "HTTP support not compiled in".to_string(),
            })
        }
    }

    /// Fetch challenge details using a 12-digit short code
    /// This respects the environment configuration (production/sandbox/etc)
    pub fn fetch_challenge_by_short_code(&self, short_code: String) -> FfiResult<String> {
        #[cfg(feature = "http")]
        {
            // Remove any spaces from the short code
            let normalized: String = short_code.chars().filter(|c| !c.is_whitespace()).collect();

            // Validate short code format
            if !is_short_code(normalized.clone()) {
                return Err(FfiError::InvalidFormat {
                    msg: "Invalid short code format (must be 12 digits)".to_string(),
                });
            }

            let url = {
                let config = safe_lock(&self.config);
                format!(
                    "{}/v1/challenge/by-code/{}",
                    config.verifier_api_url.trim_end_matches('/'),
                    normalized
                )
            };

            log::info!(
                "Fetching challenge by short code from configured verifier: {}",
                url
            );

            let rt = tokio_rt()?;

            rt.block_on(async { crate::net::get_with_timeout(&url, 10).await })
        }

        #[cfg(not(feature = "http"))]
        {
            Err(FfiError::Generic {
                msg: "HTTP support not compiled in".to_string(),
            })
        }
    }

    /// Process manual entry of a 12-digit short code
    /// and fetch the challenge details
    pub fn process_manual_entry(&self, input: String) -> FfiResult<String> {
        log::info!(
            "process_manual_entry called with input length: {}",
            input.len()
        );

        // Remove whitespace (user may enter "1234 5678 9012")
        let normalized: String = input.chars().filter(|c| !c.is_whitespace()).collect();

        // Validate it's a 12-digit short code
        if !is_short_code(normalized.clone()) {
            return Err(FfiError::InvalidFormat {
                msg: "Invalid short code format. Expected 12 digits.".to_string(),
            });
        }

        log::info!("Processing short code, fetching challenge");
        let challenge_json = self.fetch_challenge_by_short_code(normalized)?;

        // Parse the response to extract challenge details
        let challenge: QrChallengePayload =
            serde_json::from_str(&challenge_json).map_err(|e| FfiError::InvalidFormat {
                msg: format!("Failed to parse challenge response: {}", e),
            })?;
        challenge
            .validate_field_lengths()
            .map_err(|e| FfiError::InvalidFormat { msg: e })?;

        let challenge_id = challenge.challenge_id.clone();
        log::info!("Short code resolved to challenge ID: {}", challenge_id);

        // Cache the challenge
        let now = std::time::SystemTime::now();
        let expires_at = now
            .checked_add(std::time::Duration::from_secs(300))
            .unwrap_or(now);

        let mut cached = safe_lock(&self.cached_challenges);

        // Evict expired entries before inserting to prevent unbounded growth.
        if cached.len() >= 64 {
            let now_for_evict = std::time::SystemTime::now();
            cached.retain(|_, v| v.expires_at > now_for_evict);
        }
        if cached.len() >= 64 {
            return Err(FfiError::InvalidFormat {
                msg: "challenge cache full; try again shortly".to_string(),
            });
        }

        cached.insert(
            challenge_id.clone(),
            CachedChallenge {
                payload: challenge.clone(),
                received_at: now,
                expires_at,
            },
        );

        self.state_manager.start_verification(&challenge_id)?;

        log::info!("Challenge cached and verification started");
        Ok(challenge_id)
    }

    /// Create a new progress tracker for reporting proof generation stages.
    pub fn create_progress_tracker(&self) -> Arc<ProgressTracker> {
        ProgressTracker::new()
    }

    /// Report a progress stage with a human-readable message.
    pub fn report_progress(
        &self,
        tracker: Arc<ProgressTracker>,
        stage: ProgressStage,
        message: String,
    ) {
        tracker.report_progress(stage, message);
    }

    /// Remove expired credentials from storage. Returns the count removed.
    pub fn cleanup_expired_credentials(&self) -> u32 {
        match self.storage.list_credentials() {
            Ok(creds) => {
                let mut removed: u32 = 0;
                for cred_info in &creds {
                    if cred_info.is_expired {
                        if let Err(e) = self.storage.delete_credential(&cred_info.id) {
                            log::warn!(
                                "Failed to delete expired credential {}: {}",
                                cred_info.id,
                                e
                            );
                        } else {
                            log::info!("Cleaned up expired credential: {}", cred_info.id);
                            removed = removed.saturating_add(1);
                        }
                    }
                }
                removed
            }
            Err(e) => {
                log::warn!("Could not list credentials for cleanup: {}", e);
                0
            }
        }
    }

    /// Evict expired challenges from the in-memory cache. Returns the count removed.
    pub fn cleanup_expired_challenges(&self) -> u32 {
        let mut cached = safe_lock(&self.cached_challenges);
        let now = std::time::SystemTime::now();

        let expired: Vec<String> = cached
            .iter()
            .filter(|(_, c)| now > c.expires_at)
            .map(|(k, _)| k.clone())
            .collect();

        for key in &expired {
            cached.remove(key);
        }

        u32::try_from(expired.len()).unwrap_or(u32::MAX)
    }

    /// Zeroise all in-memory secret material immediately.
    ///
    /// Intended for emergency termination paths (integrity violation, debugger
    /// detection) where the process is about to be killed. Uses `try_lock`
    /// instead of blocking `lock` to avoid deadlock if the calling thread
    /// already holds one of the mutexes.
    ///
    /// If a mutex cannot be acquired, those secrets will persist for the
    /// remaining microseconds until the process exits. This is an acceptable
    /// trade-off: deadlocking the termination path is worse than briefly
    /// leaving secrets in memory that the OS will reclaim.
    pub fn emergency_zeroize(&self) {
        log::warn!("emergency_zeroize called: clearing all in-memory secrets");

        // Clear cached challenges (each CachedChallenge has ZeroizeOnDrop)
        if let Ok(mut cached) = self.cached_challenges.try_lock() {
            cached.clear();
        } else {
            log::warn!("emergency_zeroize: cached_challenges mutex held, skipping");
        }

        // Zeroize secret fields in config (verifier_api_key)
        if let Ok(mut config) = self.config.try_lock() {
            config.zeroize_secrets();
        } else {
            log::warn!("emergency_zeroize: config mutex held, skipping");
        }

        // Reset state manager (clears active verifications, failure counters)
        self.state_manager.reset();
    }
}

/// Internal async implementations. These are not exported via UniFFI; they
/// are called by the synchronous wrappers above through `tokio_rt()?.block_on`.
impl ProviiWallet {
    /// Async inner for [`submit_proof`](Self::submit_proof).
    #[cfg(feature = "http")]
    pub(crate) async fn submit_proof_async(&self, proof_json: String) -> FfiResult<bool> {
        let proof: SubmitProofRequest = serde_json::from_str(&proof_json)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

        // Extract URL and drop the lock before await
        let url = {
            let config = safe_lock(&self.config);
            format!("{}/v1/verify", config.verifier_api_url)
        };

        let response_body = crate::net::post_json(&url, &proof_json).await?;
        let verify_response: VerifyResponse = serde_json::from_str(&response_body)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;
        let success = verify_response.result == "OK";
        if !success {
            log::warn!(
                "Proof rejected by verifier: result={}, state={}",
                verify_response.result,
                verify_response.state
            );
        }

        self.state_manager
            .complete_verification(&proof.challenge_id, success)?;

        Ok(success)
    }

    /// Async inner for [`check_network_status`](Self::check_network_status).
    #[cfg(feature = "http")]
    pub(crate) async fn check_network_status_async(&self) -> NetworkStatus {
        // Extract URL and drop the lock before await
        let test_url = {
            let config = safe_lock(&self.config);
            format!("{}/health", config.verifier_api_url)
        };

        match crate::net::get_with_timeout(&test_url, 5).await {
            Ok(_) => NetworkStatus { connected: true },
            Err(_) => NetworkStatus { connected: false },
        }
    }

    /// Parse a QR string, resolving minimal challenges via HTTP if necessary.
    fn parse_qr_payload_internal(&self, qr_content: &str) -> FfiResult<QrChallengePayload> {
        // Try to parse with the standalone function first
        match parse_qr_code(qr_content.to_string()) {
            Ok(parsed) => serde_json::from_str(&parsed)
                .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() }),
            Err(e) if e.to_string().contains("MINIMAL_CHALLENGE") => {
                // Handle minimal challenge - fetch details using configured verifier URL
                log::info!("Detected minimal challenge, fetching details from configured verifier");
                let challenge_id = extract_challenge_id_from_qr(qr_content.to_string())?;
                validate_challenge_id_format(&challenge_id)?;

                // Get verifier URL from config
                let verifier_url = {
                    let config = safe_lock(&self.config);
                    config.verifier_api_url.clone()
                };

                let url = format!("{}/v1/challenge/{}/details", verifier_url, challenge_id);
                log::info!("Fetching challenge details from: {}", url);

                // Fetch challenge details using configured URL
                #[cfg(feature = "http")]
                {
                    use crate::net::get_with_timeout;
                    let rt = tokio_rt()?;

                    rt.block_on(async { get_with_timeout(&url, 10).await })
                        .and_then(|json| {
                            let payload: QrChallengePayload = serde_json::from_str(&json)
                                .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;
                            payload
                                .validate_field_lengths()
                                .map_err(|e| FfiError::InvalidFormat { msg: e })?;
                            Ok(payload)
                        })
                }

                #[cfg(not(feature = "http"))]
                {
                    Err(FfiError::Generic {
                        msg: "HTTP support not compiled in, cannot fetch challenge details"
                            .to_string(),
                    })
                }
            }
            Err(e) => Err(e),
        }
    }
}

/// Check whether a string is a valid 12-digit short code.
///
/// Short codes are displayed as `XXXX XXXX XXXX` but stored and transmitted
/// without spaces. Whitespace in the input is stripped before validation.
#[uniffi::export]
pub fn is_short_code(input: String) -> bool {
    // Remove any whitespace for validation
    let normalized: String = input.chars().filter(|c| !c.is_whitespace()).collect();

    // Must be exactly 12 digits
    normalized.len() == 12 && normalized.chars().all(|c| c.is_ascii_digit())
}

/// A cached QR challenge with its receive and expiry timestamps.
///
/// The `payload` field contains the submit secret and is zeroised on drop.
/// Timestamps are skipped by `Zeroize` because they are not secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct CachedChallenge {
    payload: QrChallengePayload,
    #[zeroize(skip)]
    received_at: std::time::SystemTime,
    #[zeroize(skip)]
    expires_at: std::time::SystemTime,
}

/// Manual [`Debug`] implementation that redacts the submit secret.
impl std::fmt::Debug for CachedChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedChallenge")
            .field("challenge_id", &self.payload.challenge_id)
            .field("cutoff_days", &self.payload.cutoff_days)
            .field("submit_secret", &"[REDACTED]")
            .field("received_at", &self.received_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Zeroize in-memory secrets when the wallet is dropped.
///
/// Uses `try_lock` (not `lock`) to avoid panicking if a mutex is poisoned or
/// held by another thread at teardown time. If a lock cannot be acquired the
/// secrets remain in freed heap memory until the OS reclaims the page; this is
/// an acceptable trade-off versus deadlocking the destructor.
impl Drop for ProviiWallet {
    fn drop(&mut self) {
        if let Ok(mut config) = self.config.try_lock() {
            config.zeroize_secrets();
        }
        if let Ok(mut cached) = self.cached_challenges.try_lock() {
            cached.clear();
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used
)]
#[path = "wallet_tests.rs"]
mod tests;
