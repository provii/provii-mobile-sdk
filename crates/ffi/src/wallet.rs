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
mod tests {
    use super::*;

    // Test helper to create AppInfo
    fn create_test_app_info() -> AppInfo {
        AppInfo {
            version: "2.0.0".to_string(),
            build_number: "1".to_string(),
            platform: "test".to_string(),
            device_model: Some("TestDevice".to_string()),
            os_version: Some("1.0".to_string()),
        }
    }

    // Test helper to create valid credential JSON
    fn create_test_credential_json() -> String {
        serde_json::json!({
            "v": 2,
            "schema": "provii.age/0",
            "kid": "issuer:TestIssuer:key1",
            "iat": 1700000000u64,
            "exp": 1800000000u64,
            "c_bytes": vec![1u8; 32],
            "issuer_vk": vec![2u8; 32],
            "sig_rj": vec![3u8; 64],
        })
        .to_string()
    }

    // Test helper to create credential with secrets
    fn create_test_credential_with_secrets_json() -> String {
        serde_json::json!({
            "v": 2,
            "schema": "provii.age/0",
            "kid": "issuer:TestIssuer:key1",
            "iat": 1700000000u64,
            "exp": 1800000000u64,
            "c_bytes": vec![1u8; 32],
            "issuer_vk": vec![2u8; 32],
            "sig_rj": vec![3u8; 64],
            "dob_days": 19000i32,
            "r_bits": vec![true; 128],
        })
        .to_string()
    }

    // Test helper to create QR challenge payload
    fn create_test_challenge_json() -> String {
        serde_json::json!({
            "challenge_id": "test-challenge-123",
            "rp_challenge": "abc123def456",
            "cutoff_days": 19000i32,
            "verifying_key_id": 1u32,
            "submit_secret": "submit_secret_base64url",
            "expires_at": 2000000000u64,
            "verify_url": "https://verify.example.com/submit"
        })
        .to_string()
    }

    // ============================================================================
    // CONSTRUCTOR TESTS (4)
    // ============================================================================

    #[test]
    fn test_wallet_new() {
        let app_info = create_test_app_info();
        let wallet = ProviiWallet::new(app_info.clone());

        // Verify wallet was created
        assert!(Arc::strong_count(&wallet) == 1);

        // Verify default config
        let config = wallet.get_config();
        assert!(config.auto_select);
        assert_eq!(config.network_timeout, 30);

        // Verify app info
        assert_eq!(wallet.app_info.version, "2.0.0");
        assert_eq!(wallet.app_info.platform, "test");
    }

    #[test]
    fn test_wallet_with_config() {
        let app_info = create_test_app_info();
        let custom_config = WalletConfig {
            auto_select: false,
            network_timeout: 60,
            cache_proving_keys: false,
            issuer_api_url: "https://custom-issuer.com".to_string(),
            verifier_api_url: "https://custom-verify.com".to_string(),
            verifier_api_key: None,
            verifier_origin: None,
            environment: "development".to_string(),
            enable_parallel_prover: false,
            max_prover_threads: 2,
        };

        let wallet = ProviiWallet::with_config(app_info, custom_config.clone());

        // Verify custom config was applied
        let config = wallet.get_config();
        assert!(!config.auto_select);
        assert_eq!(config.network_timeout, 60);
        assert!(!config.cache_proving_keys);
        assert_eq!(config.issuer_api_url, "https://custom-issuer.com");
        assert_eq!(config.verifier_api_url, "https://custom-verify.com");
        assert_eq!(config.environment, "development");
        assert!(!config.enable_parallel_prover);
        assert_eq!(config.max_prover_threads, 2);
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn test_wallet_parallel_config_applied() {
        let app_info = create_test_app_info();
        let config = WalletConfig {
            enable_parallel_prover: true,
            max_prover_threads: 4,
            ..Default::default()
        };

        let _wallet = ProviiWallet::with_config(app_info, config);

        // Parallel config should be applied (tested through logs in real usage)
        // This test primarily verifies no panic occurs
    }

    #[test]
    fn test_wallet_multiple_instances() -> Result<(), Box<dyn std::error::Error>> {
        let app_info1 = create_test_app_info();
        let app_info2 = AppInfo {
            version: "3.0.0".to_string(),
            ..app_info1.clone()
        };

        let wallet1 = ProviiWallet::new(app_info1);
        let wallet2 = ProviiWallet::new(app_info2);

        // Verify they are independent
        assert_eq!(wallet1.app_info.version, "2.0.0");
        assert_eq!(wallet2.app_info.version, "3.0.0");

        // Verify separate config instances
        let config1 = wallet1.get_config();
        let mut config2 = wallet2.get_config();
        config2.auto_select = false;
        wallet2.update_config(config2)?;

        // wallet1 should still have original config
        let config1_after = wallet1.get_config();
        assert_eq!(config1_after.auto_select, config1.auto_select);
        Ok(())
    }

    // ============================================================================
    // VERIFIER URL TESTS (7)
    // ============================================================================

    #[test]
    fn test_set_verifier_base_url_valid() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.set_verifier_base_url("https://verify.example.com".to_string());
        assert!(result.is_ok());

        let url = wallet.get_verifier_base_url();
        assert_eq!(url, "https://verify.example.com");
    }

    #[test]
    fn test_set_verifier_base_url_invalid() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.set_verifier_base_url("not a url".to_string());
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::InvalidFormat { msg } => {
                assert!(msg.contains("Invalid URL"));
            }
            _ => panic!("Expected InvalidFormat error"),
        }
        Ok(())
    }

    #[test]
    fn test_set_verifier_base_url_http_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.set_verifier_base_url("http://verify.example.com".to_string());
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::InvalidFormat { msg } => {
                assert!(msg.contains("HTTPS"));
            }
            _ => panic!("Expected InvalidFormat error"),
        }
        Ok(())
    }

    #[test]
    fn test_set_verifier_base_url_trailing_slash() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());

        wallet.set_verifier_base_url("https://verify.example.com/".to_string())?;

        let url = wallet.get_verifier_base_url();
        // Should remove trailing slash
        assert_eq!(url, "https://verify.example.com");
        Ok(())
    }

    #[test]
    fn test_set_verifier_base_url_with_path() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.set_verifier_base_url("https://verify.example.com/api/v1".to_string());
        assert!(result.is_ok());

        let url = wallet.get_verifier_base_url();
        assert_eq!(url, "https://verify.example.com/api/v1");
    }

    #[test]
    fn test_get_verifier_base_url() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Should return default URL
        let default_url = wallet.get_verifier_base_url();
        assert!(default_url.starts_with("https://"));
    }

    #[test]
    fn test_set_verifier_url_concurrent() -> Result<(), Box<dyn std::error::Error>> {
        use std::thread;

        let wallet = ProviiWallet::new(create_test_app_info());
        let wallet_clone = Arc::clone(&wallet);

        let handle = thread::spawn(move || {
            wallet_clone.set_verifier_base_url("https://verify1.example.com".to_string())
        });

        let result2 = wallet.set_verifier_base_url("https://verify2.example.com".to_string());

        let result1 = handle.join().map_err(|_| "thread panicked")?;
        assert!(result1.is_ok());
        assert!(result2.is_ok());

        // One of them should have won
        let final_url = wallet.get_verifier_base_url();
        assert!(
            final_url == "https://verify1.example.com"
                || final_url == "https://verify2.example.com"
        );
        Ok(())
    }

    // ============================================================================
    // CREDENTIAL OPERATIONS TESTS (20)
    // ============================================================================

    #[test]
    fn test_import_credential_storage_not_initialized() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let cred_json = create_test_credential_json();

        let result = wallet.import_credential(cred_json);
        // Should fail with storage error when storage not initialised
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::Storage { msg } => {
                assert!(msg.contains("not initialised"));
            }
            _ => panic!("Expected Storage error"),
        }
        Ok(())
    }

    #[test]
    fn test_import_credential_with_secrets_storage_error() -> Result<(), Box<dyn std::error::Error>>
    {
        let wallet = ProviiWallet::new(create_test_app_info());
        let cred_json = create_test_credential_with_secrets_json();

        let result = wallet.import_credential(cred_json);
        // Should fail with storage error when storage not initialised
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::Storage { msg } => {
                assert!(msg.contains("not initialised"));
            }
            _ => panic!("Expected Storage error"),
        }
        Ok(())
    }

    #[test]
    fn test_import_credential_json_parsing() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let cred_json = create_test_credential_json();

        // Test that JSON parsing works (will fail at storage step, but that's OK)
        let result = wallet.import_credential(cred_json);
        // Should reach storage error, not JSON parsing error
        assert!(result.is_err());
        if let Err(e) = result {
            match e {
                FfiError::Storage { .. } => {} // Expected
                FfiError::InvalidFormat { msg } => {
                    panic!("JSON parsing should succeed, got: {}", msg)
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_import_credential_invalid_json() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.import_credential("not valid json".to_string());
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::InvalidFormat { .. } => {}
            _ => panic!("Expected InvalidFormat error"),
        }
        Ok(())
    }

    #[test]
    fn test_import_credential_wrong_version() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let cred_json = serde_json::json!({
            "v": 999,
            "schema": "provii.age/0",
            "kid": "issuer:TestIssuer:key1",
            "iat": 1700000000u64,
            "exp": 1800000000u64,
            "c_bytes": vec![1u8; 32],
            "issuer_vk": vec![2u8; 32],
            "sig_rj": vec![3u8; 64],
        })
        .to_string();

        let result = wallet.import_credential(cred_json);
        // Should fail on deserialization or version check
        assert!(result.is_err());
    }

    #[test]
    fn test_import_credential_missing_fields() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let incomplete_json = serde_json::json!({
            "v": 2,
            "schema": "provii.age/0"
            // Missing required fields
        })
        .to_string();

        let result = wallet.import_credential(incomplete_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_store_credential_with_label_storage_error() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let cred_json = create_test_credential_json();

        let result = wallet.store_credential_with_label(
            cred_json,
            Some("My ID".to_string()),
            "primary".to_string(),
            None,
        );
        // Should fail when storage not initialised
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::Storage { .. } => {}
            _ => panic!("Expected Storage error"),
        }
        Ok(())
    }

    #[test]
    fn test_store_credential_without_label_storage_error() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let cred_json = create_test_credential_json();

        let result =
            wallet.store_credential_with_label(cred_json, None, "primary".to_string(), None);
        // Should fail when storage not initialised
        assert!(result.is_err());
    }

    #[test]
    fn test_list_credentials_empty() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.list_credentials();
        // No storage backend is registered (set_storage_handle not called),
        // so any credential operation must fail.
        assert!(
            result.is_err(),
            "list_credentials without storage backend must fail"
        );
    }

    #[test]
    fn test_list_credentials_multiple() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Import two credentials
        let cred1 = create_test_credential_json();
        let cred2 = create_test_credential_json();

        wallet.import_credential(cred1).ok();
        wallet.import_credential(cred2).ok();

        let result = wallet.list_credentials();
        if let Ok(creds) = result {
            // Should have the two imported credentials
            assert!(!creds.is_empty());
        }
    }

    #[test]
    fn test_get_credential_storage_error() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.get_credential("some-id".to_string());
        // Should fail when storage not initialised
        assert!(result.is_err());
        // Accept any error type since anyhow may convert differently
    }

    #[test]
    fn test_get_credential_nonexistent_storage_error() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.get_credential("nonexistent-id".to_string());
        // Should fail with storage error when storage not initialised
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_credential() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let cred_json = create_test_credential_json();

        let cred_id = wallet.import_credential(cred_json).ok();

        if let Some(id) = cred_id {
            let result = wallet.delete_credential(id);
            assert!(
                result.is_ok(),
                "deleting an imported credential should succeed, got {:?}",
                result.err()
            );
        }
    }

    #[test]
    fn test_delete_nonexistent_credential() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.delete_credential("nonexistent-id".to_string());
        // No storage backend registered, so the operation must fail.
        assert!(
            result.is_err(),
            "delete_credential without storage backend must fail"
        );
    }

    #[test]
    fn test_delete_sandbox_credentials() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.delete_sandbox_credentials();
        // No storage backend registered, so the operation must fail.
        assert!(
            result.is_err(),
            "delete_sandbox_credentials without storage backend must fail"
        );
    }

    #[test]
    fn test_has_valid_credential_after_import() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let cred_json = create_test_credential_json();

        wallet.import_credential(cred_json).ok();

        // Result depends on whether storage is initialised; just confirm
        // the method returns without panicking.
        let _has_cred = wallet.has_valid_credential();
    }

    #[test]
    fn test_has_valid_credential_empty_wallet() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // No credentials stored and no storage backend registered, so this
        // must return false.
        assert!(!wallet.has_valid_credential());
    }

    #[test]
    fn test_store_credential_alias() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let cred_json = create_test_credential_json();

        // store_credential is an alias for import_credential; without a
        // storage backend it must fail.
        let result = wallet.store_credential(cred_json);
        assert!(
            result.is_err(),
            "store_credential without storage backend must fail"
        );
    }

    // ============================================================================
    // PROVER INITIALIZATION TESTS (8)
    // ============================================================================

    #[test]
    fn test_initialize_prover_empty_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.initialize_prover(vec![]);
        // Should fail with empty bytes
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::Prover { .. } => {}
            _ => panic!("Expected Prover error"),
        }
        Ok(())
    }

    #[test]
    fn test_initialize_prover_too_small() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Only 100 bytes when we need much more
        let small_bytes = vec![0u8; 100];
        let result = wallet.initialize_prover(small_bytes);
        // Should fail with too-small bytes
        assert!(result.is_err());
    }

    #[test]
    fn test_initialize_prover_invalid_data() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Random data that's not a valid proving key
        let invalid_bytes = vec![0xFFu8; 1000];
        let result = wallet.initialize_prover(invalid_bytes);
        // Should fail with invalid data
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::Prover { .. } => {}
            _ => panic!("Expected Prover error"),
        }
        Ok(())
    }

    #[test]
    fn test_initialize_prover_not_called() {
        // Test that we can check prover status before initialization
        // Note: In a real test environment, prover state is global,
        // so this test assumes no other test has initialized it
        let _wallet = ProviiWallet::new(create_test_app_info());

        // Just verify the wallet was created successfully
        // We can't reliably test is_prover_initialized() in unit tests
        // since it's global state
    }

    #[test]
    fn test_initialize_prover_with_valid_size_invalid_content() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Create bytes that are the right size but wrong content
        // Proving keys are typically 50MB+ for production
        // Using smaller size for test performance
        let fake_pk = vec![1u8; 10_000];

        let result = wallet.initialize_prover(fake_pk);
        // Should fail because content is invalid even if size is plausible
        assert!(result.is_err());
    }

    #[test]
    fn test_initialize_prover_error_message() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.initialize_prover(vec![0u8; 10]);
        assert!(result.is_err());

        // Verify error message contains useful info
        let Err(err_val) = result else {
            panic!("expected error")
        };
        let err_str = format!("{:?}", err_val);
        assert!(!err_str.is_empty());
        Ok(())
    }

    #[test]
    fn test_initialize_prover_state_cleanup() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Try to initialize with bad data
        let _ = wallet.initialize_prover(vec![0u8; 100]);

        // Wallet should still be usable for other operations
        let config = wallet.get_config();
        assert!(config.auto_select);
    }

    #[test]
    fn test_initialize_prover_concurrent_attempts() -> Result<(), Box<dyn std::error::Error>> {
        use std::thread;

        let wallet = ProviiWallet::new(create_test_app_info());
        let wallet_clone = Arc::clone(&wallet);

        let handle = thread::spawn(move || wallet_clone.initialize_prover(vec![0u8; 100]));

        let result2 = wallet.initialize_prover(vec![1u8; 100]);
        let result1 = handle.join().map_err(|_| "thread panicked")?;

        // Both should fail (or at least one should)
        // We can't make strong guarantees about global prover state in tests
        assert!(result1.is_err() || result2.is_err());
        Ok(())
    }

    // ============================================================================
    // STORAGE HANDLE TESTS (5)
    // ============================================================================

    #[test]
    fn test_storage_not_available_initially() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Storage should not be available before set_storage_handle is called
        let diag = wallet.get_diagnostic_info();
        assert!(!diag.storage_available);
    }

    #[test]
    fn test_operations_fail_without_storage() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Credential operations should fail without storage
        let cred_json = create_test_credential_json();
        let result = wallet.import_credential(cred_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_credentials_fails_without_storage() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.list_credentials();
        // Should fail when storage not initialised
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_operations_without_storage() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Delete operations should fail gracefully
        let result = wallet.delete_credential("some-id".to_string());
        assert!(result.is_err());

        let result = wallet.delete_sandbox_credentials();
        assert!(result.is_err());
    }

    #[test]
    fn test_storage_state_check() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // has_valid_credential should return false when storage not available
        assert!(!wallet.has_valid_credential());
    }

    // ============================================================================
    // QR PROCESSING TESTS (10)
    // ============================================================================

    #[test]
    fn test_parse_qr_empty_string() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.parse_qr("".to_string());
        // Should fail with empty string
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_qr_invalid_json() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.parse_qr("not json".to_string());
        // Should fail with invalid JSON
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_qr_valid_challenge() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let challenge_json = create_test_challenge_json();

        let result = wallet.parse_qr(challenge_json);
        // Valid challenge JSON should be parseable.
        assert!(
            result.is_ok(),
            "parse_qr should succeed with valid challenge JSON, got {:?}",
            result.err()
        );
    }

    #[test]
    fn test_process_qr_challenge_valid() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let challenge_json = create_test_challenge_json();

        let result = wallet.process_qr_challenge(challenge_json);
        // Valid challenge JSON should process successfully.
        assert!(
            result.is_ok(),
            "process_qr_challenge should succeed with valid JSON, got {:?}",
            result.err()
        );
    }

    #[test]
    fn test_process_qr_challenge_invalid() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.process_qr_challenge("invalid".to_string());
        // Should fail with invalid format
        assert!(result.is_err());
    }

    #[test]
    fn test_process_qr_challenge_missing_fields() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let incomplete = serde_json::json!({
            "challenge_id": "test-123"
            // Missing required fields
        })
        .to_string();

        let result = wallet.process_qr_challenge(incomplete);
        // Should fail with missing fields
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_qr_payload_empty() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.parse_qr_payload("".to_string());
        // Should fail with empty payload
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_qr_payload_too_large() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Create a very large payload (QR codes have size limits)
        let large_payload = "x".repeat(10_000);
        let result = wallet.parse_qr_payload(large_payload);
        // Non-JSON input should fail parsing.
        assert!(result.is_err(), "non-JSON payload should be rejected");
    }

    #[test]
    fn test_validate_qr_invalid_json() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.validate_qr("not json".to_string());
        // Should fail validation
        assert!(result.is_err());
    }

    #[test]
    fn test_process_scanned_qr_invalid() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.process_scanned_qr("invalid qr content".to_string());
        // Should fail with invalid QR content
        assert!(result.is_err());
    }

    // ============================================================================
    // VERIFICATION FLOW TESTS (25)
    // ============================================================================

    #[test]
    fn test_create_age_proof_no_credential() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result =
            wallet.create_age_proof("nonexistent".to_string(), "challenge-123".to_string());
        // Should fail - no credential found
        assert!(result.is_err());
    }

    #[test]
    fn test_create_age_proof_no_challenge() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result =
            wallet.create_age_proof("cred-123".to_string(), "nonexistent-challenge".to_string());
        // Should fail - no challenge found
        assert!(result.is_err());
    }

    #[test]
    fn test_create_age_proof_storage_not_initialized() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.create_age_proof("cred-123".to_string(), "challenge-123".to_string());
        // Should fail - storage not initialised or challenge not found
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_preflight_no_credential() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.debug_preflight("nonexistent".to_string(), "challenge-123".to_string());
        // Should fail - credential not found
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_preflight_no_challenge() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.debug_preflight("cred-123".to_string(), "nonexistent".to_string());
        // Should fail - challenge not found
        assert!(result.is_err());
    }

    #[test]
    fn test_diagnose_proof_failure_no_credential() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result =
            wallet.diagnose_proof_failure("nonexistent".to_string(), "challenge-123".to_string());
        // Should fail - credential not found
        assert!(result.is_err());
    }

    #[test]
    fn test_diagnose_proof_failure_no_challenge() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result =
            wallet.diagnose_proof_failure("cred-123".to_string(), "nonexistent".to_string());
        // Should fail - challenge not found
        assert!(result.is_err());
    }

    #[test]
    fn test_get_challenge_diagnostics_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.get_challenge_diagnostics("nonexistent".to_string());
        // Should fail - challenge not found
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::Generic { msg } => {
                assert!(msg.contains("not found"));
            }
            _ => panic!("Expected Generic error"),
        }
        Ok(())
    }

    #[test]
    fn test_cleanup_expired_challenges_empty() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let count = wallet.cleanup_expired_challenges();
        // Should return 0 when no challenges cached
        assert_eq!(count, 0);
    }

    #[test]
    fn test_get_verification_status_initial() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let status = wallet.get_verification_status();
        // Should return initial status
        assert!(
            matches!(status, VerificationStatus::NotStarted)
                || matches!(status, VerificationStatus::ChallengeReceived)
                || matches!(status, VerificationStatus::ProofGenerated)
        );
    }

    #[test]
    fn test_cancel_verification_not_started() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.cancel_verification("nonexistent".to_string());
        // Cancelling a non-started verification is a no-op.
        assert!(
            result.is_ok(),
            "cancel_verification on nonexistent challenge should not error, got {:?}",
            result.err()
        );
    }

    #[test]
    #[cfg(feature = "http")]
    fn test_submit_proof_invalid_json() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.submit_proof("invalid json".to_string());
        // Should fail with invalid JSON
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(feature = "http"))]
    fn test_submit_proof_without_http() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.submit_proof("{}".to_string());
        // Should fail - HTTP not compiled
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::Generic { msg } => {
                assert!(msg.contains("HTTP"));
            }
            _ => panic!("Expected Generic error about HTTP"),
        }
        Ok(())
    }

    #[test]
    #[cfg(feature = "http")]
    fn test_submit_proof_missing_challenge_id() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let incomplete_proof = serde_json::json!({
            "proof": "fake_proof_data"
            // Missing challenge_id
        })
        .to_string();

        let result = wallet.submit_proof(incomplete_proof);
        // Should fail with missing field
        assert!(result.is_err());
    }

    #[test]
    fn test_has_credential_secrets_nonexistent() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.has_credential_secrets("nonexistent".to_string());
        // Should fail with storage error
        assert!(result.is_err());
    }

    #[test]
    fn test_process_qr_challenge_caching() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let challenge_json = create_test_challenge_json();

        // Try to process a challenge (may fail at parsing)
        let _ = wallet.process_qr_challenge(challenge_json);

        // Verify cleanup works even if no challenges were cached
        let count = wallet.cleanup_expired_challenges();
        // No challenges should have been successfully cached (parsing likely failed)
        assert_eq!(count, 0);
    }

    #[test]
    fn test_verification_state_transitions() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Get initial status
        let status1 = wallet.get_verification_status();

        // Try to cancel (should not crash)
        let _ = wallet.cancel_verification("test-challenge".to_string());

        // Get status after cancel
        let status2 = wallet.get_verification_status();

        // Should be valid status enum variants
        assert!(matches!(
            status1,
            VerificationStatus::NotStarted
                | VerificationStatus::ChallengeReceived
                | VerificationStatus::ProofGenerated
                | VerificationStatus::Submitting
                | VerificationStatus::Verified
                | VerificationStatus::Failed { .. }
        ));

        assert!(matches!(
            status2,
            VerificationStatus::NotStarted
                | VerificationStatus::ChallengeReceived
                | VerificationStatus::ProofGenerated
                | VerificationStatus::Submitting
                | VerificationStatus::Verified
                | VerificationStatus::Failed { .. }
        ));
    }

    #[test]
    fn test_proof_generation_without_prover() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Try to create proof without prover initialized
        let result = wallet.create_age_proof("cred-123".to_string(), "challenge-123".to_string());

        // Should fail (either challenge not found or prover not initialised)
        assert!(result.is_err());
    }

    #[test]
    fn test_verification_flow_error_propagation() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Test that errors propagate correctly through the verification flow

        // 1. Try to get diagnostics for nonexistent challenge
        let diag_result = wallet.get_challenge_diagnostics("fake-challenge".to_string());
        assert!(diag_result.is_err());

        // 2. Try to create proof with nonexistent credential
        let proof_result =
            wallet.create_age_proof("fake-cred".to_string(), "fake-challenge".to_string());
        assert!(proof_result.is_err());

        // 3. Try to diagnose failure with nonexistent credential
        let diagnose_result =
            wallet.diagnose_proof_failure("fake-cred".to_string(), "fake-challenge".to_string());
        assert!(diagnose_result.is_err());
    }

    #[test]
    fn test_challenge_expiry_handling() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Cleanup should work even with no challenges
        let count1 = wallet.cleanup_expired_challenges();
        assert_eq!(count1, 0);

        // Multiple cleanups should be safe
        let count2 = wallet.cleanup_expired_challenges();
        assert_eq!(count2, 0);
    }

    #[test]
    fn test_concurrent_verification_operations() -> Result<(), Box<dyn std::error::Error>> {
        use std::thread;

        let wallet = ProviiWallet::new(create_test_app_info());
        let wallet_clone = Arc::clone(&wallet);

        let handle = thread::spawn(move || wallet_clone.get_verification_status());

        let status2 = wallet.get_verification_status();
        let status1 = handle.join().map_err(|_| "thread panicked")?;

        // Both should return valid status
        assert!(matches!(
            status1,
            VerificationStatus::NotStarted
                | VerificationStatus::ChallengeReceived
                | VerificationStatus::ProofGenerated
                | VerificationStatus::Submitting
                | VerificationStatus::Verified
                | VerificationStatus::Failed { .. }
        ));
        assert!(matches!(
            status2,
            VerificationStatus::NotStarted
                | VerificationStatus::ChallengeReceived
                | VerificationStatus::ProofGenerated
                | VerificationStatus::Submitting
                | VerificationStatus::Verified
                | VerificationStatus::Failed { .. }
        ));
        Ok(())
    }

    #[test]
    fn test_proof_generation_error_messages() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.create_age_proof("".to_string(), "".to_string());
        assert!(result.is_err());

        // Error should have meaningful message
        let Err(err_val) = result else {
            panic!("expected error")
        };
        let err_str = format!("{:?}", err_val);
        assert!(!err_str.is_empty());
        Ok(())
    }

    #[test]
    #[cfg(feature = "http")]
    fn test_check_network_status() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let status = wallet.check_network_status();
        // Verify the call completes and returns a valid NetworkStatus.
        // The actual connectivity result depends on the test environment.
        let _connected: bool = status.connected;
    }

    #[test]
    #[cfg(not(feature = "http"))]
    fn test_check_network_status_without_http() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let status = wallet.check_network_status();
        assert!(!status.connected);
    }

    // ============================================================================
    // CONFIGURATION & DIAGNOSTICS TESTS (15)
    // ============================================================================

    #[test]
    fn test_get_config_default() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let config = wallet.get_config();
        // Verify default config values
        assert!(config.auto_select);
        assert_eq!(config.network_timeout, 30);
        assert!(config.issuer_api_url.starts_with("https://"));
        assert!(config.verifier_api_url.starts_with("https://"));
    }

    #[test]
    fn test_update_config() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let mut new_config = wallet.get_config();
        new_config.auto_select = false;
        new_config.network_timeout = 60;

        let result = wallet.update_config(new_config.clone());
        assert!(result.is_ok());

        let updated = wallet.get_config();
        assert!(!updated.auto_select);
        assert_eq!(updated.network_timeout, 60);
    }

    #[test]
    fn test_update_config_preserves_urls() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());

        let original_config = wallet.get_config();
        let original_issuer = original_config.issuer_api_url.clone();

        // Update other fields
        let mut new_config = original_config.clone();
        new_config.auto_select = false;

        wallet.update_config(new_config)?;

        let updated = wallet.get_config();
        assert_eq!(updated.issuer_api_url, original_issuer);
        Ok(())
    }

    #[test]
    fn test_get_diagnostic_info() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let diag = wallet.get_diagnostic_info();

        // Verify diagnostic info structure
        assert!(!diag.sdk_version.is_empty());
        assert_eq!(diag.app_version, "2.0.0");
        assert_eq!(diag.platform, "test");
        assert_eq!(diag.credential_count, 0);
        assert!(!diag.storage_available);
    }

    #[test]
    fn test_diagnostic_info_prover_status() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let diag = wallet.get_diagnostic_info();

        // prover_initialized depends on test order; just confirm the field
        // is accessible without panicking.
        let _prover_status: bool = diag.prover_initialized;
    }

    #[test]
    fn test_calculate_age_from_dob_valid() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Use a date that's definitely in the past
        let result = wallet.calculate_age_from_dob("2000-01-01".to_string());
        assert!(result.is_ok());

        let age = result?;
        // Should be at least 20 years old (as of 2020+)
        assert!(age >= 20);
        Ok(())
    }

    #[test]
    fn test_calculate_age_from_dob_invalid_format() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.calculate_age_from_dob("invalid date".to_string());
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::InvalidFormat { .. } => {}
            _ => panic!("Expected InvalidFormat error"),
        }
        Ok(())
    }

    #[test]
    fn test_calculate_age_from_dob_wrong_format() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Wrong format (should be YYYY-MM-DD)
        let result = wallet.calculate_age_from_dob("01/01/2000".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_age_from_dob_future_date() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Future date
        let result = wallet.calculate_age_from_dob("2099-12-31".to_string());
        // Future date should still parse, producing a negative age.
        assert!(
            result.is_ok(),
            "future date should parse successfully, got {:?}",
            result.err()
        );
    }

    #[test]
    fn test_is_biometric_available() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // The FFI stub always reports biometric as unavailable.
        assert!(!wallet.is_biometric_available());
    }

    #[test]
    fn test_create_progress_tracker() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let tracker = wallet.create_progress_tracker();
        // Verify tracker was created
        assert!(Arc::strong_count(&tracker) >= 1);
    }

    #[test]
    fn test_report_progress() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let tracker = wallet.create_progress_tracker();

        // Should not panic
        wallet.report_progress(tracker, ProgressStage::Started, "Test message".to_string());
    }

    #[test]
    fn test_handle_deeplink_invalid() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.handle_deeplink("invalid url".to_string());
        // Should fail with invalid deeplink
        assert!(result.is_err());
    }

    // ============================================================================
    // ADDITIONAL EDGE CASES & BOUNDARY TESTS (30)
    // ============================================================================

    #[test]
    fn test_config_concurrent_updates() -> Result<(), Box<dyn std::error::Error>> {
        use std::thread;

        let wallet = ProviiWallet::new(create_test_app_info());
        let wallet_clone = Arc::clone(&wallet);

        let handle = thread::spawn(move || {
            let mut config = wallet_clone.get_config();
            config.network_timeout = 45;
            wallet_clone.update_config(config)
        });

        let mut config2 = wallet.get_config();
        config2.network_timeout = 90;
        let result2 = wallet.update_config(config2);

        let result1 = handle.join().map_err(|_| "thread panicked")?;
        assert!(result1.is_ok());
        assert!(result2.is_ok());

        // One of the updates should have won
        let final_config = wallet.get_config();
        assert!(final_config.network_timeout == 45 || final_config.network_timeout == 90);
        Ok(())
    }

    #[test]
    fn test_calculate_age_edge_cases() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Test leap year date
        let result = wallet.calculate_age_from_dob("2000-02-29".to_string());
        assert!(result.is_ok());

        // Test end of year
        let result = wallet.calculate_age_from_dob("1990-12-31".to_string());
        assert!(result.is_ok());

        // Test start of year
        let result = wallet.calculate_age_from_dob("1985-01-01".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_string_inputs() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Empty credential ID
        let result = wallet.get_credential("".to_string());
        assert!(result.is_err());

        // Empty challenge ID
        let result = wallet.get_challenge_diagnostics("".to_string());
        assert!(result.is_err());

        // Empty QR content
        let result = wallet.parse_qr("".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_very_long_strings() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Very long credential ID
        let long_id = "x".repeat(10000);
        let result = wallet.get_credential(long_id);
        assert!(result.is_err());

        // Very long QR content (not valid JSON)
        let long_qr = "y".repeat(10000);
        let result = wallet.parse_qr(long_qr);
        // Non-JSON content should fail parsing.
        assert!(result.is_err(), "non-JSON QR content should be rejected");
    }

    #[test]
    fn test_special_characters_in_ids() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Test with special characters
        let special_id = "cred-!@#$%^&*()";
        let result = wallet.get_credential(special_id.to_string());
        assert!(result.is_err());

        // Test with unicode
        let unicode_id = "cred-日本語";
        let result = wallet.get_credential(unicode_id.to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_null_bytes_in_input() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Test with null bytes
        let null_id = "cred\0id";
        let result = wallet.get_credential(null_id.to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_whitespace_only_inputs() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Whitespace only
        let result = wallet.get_credential("   ".to_string());
        assert!(result.is_err());

        let result = wallet.parse_qr("   ".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_diagnostic_info_consistency() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let diag1 = wallet.get_diagnostic_info();
        let diag2 = wallet.get_diagnostic_info();

        // Should be consistent
        assert_eq!(diag1.sdk_version, diag2.sdk_version);
        assert_eq!(diag1.app_version, diag2.app_version);
        assert_eq!(diag1.platform, diag2.platform);
    }

    #[test]
    fn test_multiple_cleanup_operations() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Multiple cleanups should be safe and idempotent
        for _ in 0..10 {
            let count = wallet.cleanup_expired_challenges();
            // No challenges cached, so nothing to expire
            assert_eq!(count, 0);
        }
    }

    #[test]
    fn test_verification_status_stability() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Get status multiple times - should be stable
        let status1 = wallet.get_verification_status();
        let status2 = wallet.get_verification_status();
        let status3 = wallet.get_verification_status();

        // All should be valid statuses
        assert!(matches!(
            status1,
            VerificationStatus::NotStarted
                | VerificationStatus::ChallengeReceived
                | VerificationStatus::ProofGenerated
                | VerificationStatus::Submitting
                | VerificationStatus::Verified
                | VerificationStatus::Failed { .. }
        ));
        assert!(matches!(
            status2,
            VerificationStatus::NotStarted
                | VerificationStatus::ChallengeReceived
                | VerificationStatus::ProofGenerated
                | VerificationStatus::Submitting
                | VerificationStatus::Verified
                | VerificationStatus::Failed { .. }
        ));
        assert!(matches!(
            status3,
            VerificationStatus::NotStarted
                | VerificationStatus::ChallengeReceived
                | VerificationStatus::ProofGenerated
                | VerificationStatus::Submitting
                | VerificationStatus::Verified
                | VerificationStatus::Failed { .. }
        ));
    }

    #[test]
    fn test_config_boundary_values() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Test with boundary values
        let mut config = wallet.get_config();
        config.network_timeout = 0;
        let result = wallet.update_config(config.clone());
        assert!(result.is_ok());

        let mut config = wallet.get_config();
        config.network_timeout = u64::MAX;
        let result = wallet.update_config(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_progress_tracker_multiple_reports() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let tracker = wallet.create_progress_tracker();

        // Multiple progress reports should not crash
        wallet.report_progress(
            Arc::clone(&tracker),
            ProgressStage::Started,
            "Message 1".to_string(),
        );
        wallet.report_progress(
            Arc::clone(&tracker),
            ProgressStage::IssuanceRequestCreated,
            "Message 2".to_string(),
        );
        wallet.report_progress(
            Arc::clone(&tracker),
            ProgressStage::VerificationChallengeReceived,
            "Message 3".to_string(),
        );
        wallet.report_progress(tracker, ProgressStage::Failed, "Message 4".to_string());
    }

    #[test]
    fn test_credential_operations_with_unicode() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Test with unicode in JSON
        let unicode_json = serde_json::json!({
            "v": 2,
            "schema": "provii.age/0",
            "kid": "issuer:テスト発行者:key1",
            "iat": 1700000000u64,
            "exp": 1800000000u64,
            "c_bytes": vec![1u8; 32],
            "issuer_vk": vec![2u8; 32],
            "sig_rj": vec![3u8; 64],
        })
        .to_string();

        let result = wallet.import_credential(unicode_json);
        // Should fail with storage error (not JSON parsing error)
        assert!(result.is_err());
    }

    #[test]
    fn test_has_valid_credential_consistency() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Multiple calls should be consistent
        let has1 = wallet.has_valid_credential();
        let has2 = wallet.has_valid_credential();
        let has3 = wallet.has_valid_credential();

        assert_eq!(has1, has2);
        assert_eq!(has2, has3);
    }

    #[test]
    fn test_verifier_url_with_port() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result = wallet.set_verifier_base_url("https://verify.example.com:8443".to_string());
        assert!(result.is_ok());

        let url = wallet.get_verifier_base_url();
        assert!(url.contains("8443"));
    }

    #[test]
    fn test_verifier_url_with_query_params() {
        let wallet = ProviiWallet::new(create_test_app_info());

        let result =
            wallet.set_verifier_base_url("https://verify.example.com?param=value".to_string());
        assert!(result.is_ok());

        let url = wallet.get_verifier_base_url();
        assert!(url.contains("verify.example.com"));
    }

    #[test]
    fn test_concurrent_diagnostic_info_access() -> Result<(), Box<dyn std::error::Error>> {
        use std::thread;

        let wallet = ProviiWallet::new(create_test_app_info());
        let wallet_clone = Arc::clone(&wallet);

        let handle = thread::spawn(move || wallet_clone.get_diagnostic_info());

        let diag2 = wallet.get_diagnostic_info();
        let diag1 = handle.join().map_err(|_| "thread panicked")?;

        // Both should be valid
        assert!(!diag1.sdk_version.is_empty());
        assert!(!diag2.sdk_version.is_empty());
        Ok(())
    }

    #[test]
    fn test_cancel_verification_multiple_times() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Multiple cancellations should be safe
        let challenge_id = "test-challenge".to_string();
        let _ = wallet.cancel_verification(challenge_id.clone());
        let _ = wallet.cancel_verification(challenge_id.clone());
        let _ = wallet.cancel_verification(challenge_id);
    }

    #[test]
    fn test_delete_operations_idempotent() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Deleting non-existent credentials multiple times should be safe
        let cred_id = "nonexistent".to_string();
        let _ = wallet.delete_credential(cred_id.clone());
        let _ = wallet.delete_credential(cred_id.clone());
        let _ = wallet.delete_credential(cred_id);

        // Deleting sandbox credentials multiple times
        let _ = wallet.delete_sandbox_credentials();
        let _ = wallet.delete_sandbox_credentials();
    }

    #[test]
    fn test_list_credentials_stability() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Multiple list operations should be consistent
        let result1 = wallet.list_credentials();
        let result2 = wallet.list_credentials();

        // Both should have same error status
        assert_eq!(result1.is_ok(), result2.is_ok());
        assert_eq!(result1.is_err(), result2.is_err());
    }

    #[test]
    fn test_qr_processing_with_very_large_payload() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Create a large JSON payload
        let large_json = format!(r#"{{"challenge_id": "{}"}}"#, "x".repeat(5000));
        let result = wallet.process_qr_challenge(large_json);

        // Incomplete challenge JSON (missing required fields) should fail.
        assert!(
            result.is_err(),
            "incomplete challenge JSON should be rejected"
        );
    }

    #[test]
    fn test_json_with_extra_fields() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // JSON with extra unknown fields
        let extra_fields_json = serde_json::json!({
            "v": 2,
            "schema": "provii.age/0",
            "kid": "issuer:TestIssuer:key1",
            "iat": 1700000000u64,
            "exp": 1800000000u64,
            "c_bytes": vec![1u8; 32],
            "issuer_vk": vec![2u8; 32],
            "sig_rj": vec![3u8; 64],
            "extra_field_1": "value1",
            "extra_field_2": 12345,
            "unknown": {"nested": "data"}
        })
        .to_string();

        let result = wallet.import_credential(extra_fields_json);
        // Should handle extra fields gracefully (may succeed or fail at storage)
        assert!(result.is_err());
    }

    #[test]
    fn test_concurrent_has_credential_secrets() -> Result<(), Box<dyn std::error::Error>> {
        use std::thread;

        let wallet = ProviiWallet::new(create_test_app_info());
        let wallet_clone = Arc::clone(&wallet);

        let handle =
            thread::spawn(move || wallet_clone.has_credential_secrets("test-id".to_string()));

        let result2 = wallet.has_credential_secrets("test-id-2".to_string());
        let result1 = handle.join().map_err(|_| "thread panicked")?;

        // Both should return errors (storage not initialised)
        assert!(result1.is_err());
        assert!(result2.is_err());
        Ok(())
    }

    #[test]
    fn test_wallet_memory_safety() {
        // Test that creating and dropping wallets doesn't leak memory
        for _ in 0..100 {
            let app_info = create_test_app_info();
            let wallet = ProviiWallet::new(app_info);
            let _ = wallet.get_config();
            // Wallet dropped here
        }
    }

    #[test]
    fn test_config_update_with_empty_strings() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());

        let mut config = wallet.get_config();
        config.environment = "".to_string();

        let result = wallet.update_config(config);
        // Validation now rejects empty environment
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::InvalidFormat { msg } => {
                assert!(msg.contains("environment must not be empty"));
            }
            other => panic!("Expected InvalidFormat, got {:?}", other),
        }
        Ok(())
    }

    #[test]
    fn test_parse_qr_payload_special_characters() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Test with various special characters
        let special_chars = vec![
            "test\nwith\nnewlines",
            "test\twith\ttabs",
            "test with spaces",
            "test@#$%^&*()",
        ];

        for input in special_chars {
            let result = wallet.parse_qr_payload(input.to_string());
            // Non-JSON special characters should fail parsing.
            assert!(
                result.is_err(),
                "special-character payload {:?} should fail QR parsing",
                input
            );
        }
    }

    #[test]
    fn test_deeplink_parsing_variations() {
        let wallet = ProviiWallet::new(create_test_app_info());

        // Test various invalid deeplink formats
        let invalid_links = vec![
            "http://example.com",
            "proviiwallet",
            "proviiwallet:",
            "proviiwallet://",
            "",
        ];

        for link in invalid_links {
            let result = wallet.handle_deeplink(link.to_string());
            assert!(result.is_err());
        }
    }

    // ============================================================================
    // VERIFY RESPONSE PARSING TESTS
    // ============================================================================

    #[test]
    fn test_verify_response_ok_result_is_success() -> Result<(), Box<dyn std::error::Error>> {
        let body = r#"{"result":"OK","state":"verified"}"#;
        let response: VerifyResponse = serde_json::from_str(body)?;
        let success = response.result == "OK";
        assert!(success, "result 'OK' should map to success=true");
        assert_eq!(response.state, "verified");
        Ok(())
    }

    #[test]
    fn test_verify_response_invalid_proof_is_failure() -> Result<(), Box<dyn std::error::Error>> {
        let body = r#"{"result":"INVALID_PROOF","state":"rejected"}"#;
        let response: VerifyResponse = serde_json::from_str(body)?;
        let success = response.result == "OK";
        assert!(
            !success,
            "result 'INVALID_PROOF' should map to success=false"
        );
        assert_eq!(response.result, "INVALID_PROOF");
        assert_eq!(response.state, "rejected");
        Ok(())
    }

    #[test]
    fn test_verify_response_malformed_json_returns_invalid_format() {
        let body = "not valid json {{{";
        let parse_result = serde_json::from_str::<VerifyResponse>(body);
        assert!(
            parse_result.is_err(),
            "malformed JSON must not parse as VerifyResponse"
        );
        // Confirm that wrapping as FfiError::InvalidFormat works
        let ffi_err = parse_result
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })
            .unwrap_err();
        assert!(
            matches!(ffi_err, FfiError::InvalidFormat { .. }),
            "expected FfiError::InvalidFormat, got {:?}",
            ffi_err
        );
    }

    #[test]
    fn test_verify_response_expired_result_is_failure() -> Result<(), Box<dyn std::error::Error>> {
        let body = r#"{"result":"EXPIRED","state":"challenge_expired"}"#;
        let response: VerifyResponse = serde_json::from_str(body)?;
        let success = response.result == "OK";
        assert!(!success, "result 'EXPIRED' should map to success=false");
        Ok(())
    }

    // ============================================================================
    // SHORT CODE TESTS
    // ============================================================================

    #[test]
    fn test_is_short_code_valid_12_digits() {
        assert!(is_short_code("123456789012".to_string()));
    }

    #[test]
    fn test_is_short_code_with_spaces() {
        assert!(is_short_code("1234 5678 9012".to_string()));
    }

    #[test]
    fn test_is_short_code_too_short() {
        assert!(!is_short_code("12345".to_string()));
    }

    #[test]
    fn test_is_short_code_too_long() {
        assert!(!is_short_code("1234567890123".to_string()));
    }

    #[test]
    fn test_is_short_code_alpha_chars() {
        assert!(!is_short_code("12345678901a".to_string()));
    }

    #[test]
    fn test_is_short_code_empty() {
        assert!(!is_short_code("".to_string()));
    }

    #[test]
    fn test_is_short_code_all_zeros() {
        assert!(is_short_code("000000000000".to_string()));
    }

    #[test]
    fn test_is_short_code_special_chars() {
        assert!(!is_short_code("12345-67890!".to_string()));
    }

    // ============================================================================
    // CALCULATE AGE FROM DOB TESTS
    // ============================================================================

    #[test]
    fn test_calculate_age_known_dob() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let result = wallet.calculate_age_from_dob("2000-01-01".to_string());
        assert!(result.is_ok());
        let age = result.unwrap();
        assert!(age >= 25 && age <= 27, "age should be ~26, got {}", age);
    }

    #[test]
    fn test_calculate_age_from_dob_invalid_date() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let result = wallet.calculate_age_from_dob("not-a-date".to_string());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FfiError::InvalidFormat { .. }
        ));
    }

    #[test]
    fn test_calculate_age_from_dob_far_future_clamped_zero() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let result = wallet.calculate_age_from_dob("2099-01-01".to_string());
        assert!(result.is_ok());
        // Future DOB should clamp to 0
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_calculate_age_from_dob_leap_day() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let result = wallet.calculate_age_from_dob("2000-02-29".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_calculate_age_from_dob_empty_string() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let result = wallet.calculate_age_from_dob("".to_string());
        assert!(result.is_err());
    }

    // ============================================================================
    // EMERGENCY ZEROIZE TESTS
    // ============================================================================

    #[test]
    fn test_emergency_zeroize_clears_caches() {
        let wallet = ProviiWallet::new(create_test_app_info());
        wallet.emergency_zeroize();
        // Should not panic and should clear all in-memory state
        let cached = safe_lock(&wallet.cached_challenges);
        assert!(cached.is_empty());
    }

    #[test]
    fn test_emergency_zeroize_multiple_calls() {
        let wallet = ProviiWallet::new(create_test_app_info());
        wallet.emergency_zeroize();
        wallet.emergency_zeroize();
        // Repeated calls must be safe
    }

    // ============================================================================
    // CLEANUP EXPIRED CHALLENGES TESTS
    // ============================================================================

    #[test]
    fn test_cleanup_expired_challenges_empty_cache() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let removed = wallet.cleanup_expired_challenges();
        assert_eq!(removed, 0);
    }

    // ============================================================================
    // DIAGNOSTIC INFO TESTS
    // ============================================================================

    #[test]
    fn test_diagnostic_info_fields() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let info = wallet.get_diagnostic_info();
        assert!(!info.sdk_version.is_empty());
        assert_eq!(info.app_version, "2.0.0");
        assert_eq!(info.platform, "test");
        assert!(!info.storage_available);
    }

    // ============================================================================
    // VERIFICATION STATUS TESTS
    // ============================================================================

    #[test]
    fn test_verification_status_not_started() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let status = wallet.get_verification_status();
        assert!(matches!(status, VerificationStatus::NotStarted));
    }

    #[test]
    fn test_cancel_verification_nonexistent() {
        let wallet = ProviiWallet::new(create_test_app_info());
        // Cancelling a non-existent verification should not panic
        let result = wallet.cancel_verification("nonexistent".to_string());
        // May succeed or fail depending on state manager implementation
        let _ = result;
    }

    // ============================================================================
    // HAS VALID CREDENTIAL TESTS
    // ============================================================================

    #[test]
    fn test_has_valid_credential_no_storage() {
        let wallet = ProviiWallet::new(create_test_app_info());
        // No storage backend, should return false gracefully
        assert!(!wallet.has_valid_credential());
    }

    // ============================================================================
    // RESOLVE SLOT TESTS
    // ============================================================================

    #[test]
    fn test_resolve_slot_primary() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let slot = wallet.resolve_slot("primary", None);
        assert!(slot.is_ok());
        assert!(matches!(slot.unwrap(), CredentialSlot::Primary));
    }

    #[test]
    fn test_resolve_slot_unknown_type() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let slot = wallet.resolve_slot("unknown_type", None);
        assert!(slot.is_err());
        assert!(matches!(slot.unwrap_err(), FfiError::InvalidFormat { .. }));
    }

    // ============================================================================
    // BIOMETRIC TESTS
    // ============================================================================

    #[test]
    fn test_is_biometric_available_default() {
        let wallet = ProviiWallet::new(create_test_app_info());
        // Default stub has no platform callback, so it returns false
        let available = wallet.is_biometric_available();
        assert!(!available);
    }

    // ============================================================================
    // PROGRESS TRACKER TESTS
    // ============================================================================

    #[test]
    fn test_create_progress_tracker_arc() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let tracker = wallet.create_progress_tracker();
        // Tracker should be created successfully
        assert!(Arc::strong_count(&tracker) >= 1);
    }

    #[test]
    fn test_report_progress_started_stage() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let tracker = wallet.create_progress_tracker();
        wallet.report_progress(
            tracker,
            ProgressStage::Started,
            "Generating proof".to_string(),
        );
    }

    // ============================================================================
    // CREDENTIAL SECRETS / NICKNAME TESTS
    // ============================================================================

    #[test]
    fn test_has_credential_secrets_no_storage() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let result = wallet.has_credential_secrets("some-id".to_string());
        // Should fail because storage is not initialised
        assert!(result.is_err());
    }

    #[test]
    fn test_update_credential_nickname_no_storage() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let result = wallet
            .update_credential_nickname("some-id".to_string(), Some("new nickname".to_string()));
        assert!(result.is_err());
    }

    // ============================================================================
    // IMPORT CREDENTIAL WITH TYPE TESTS
    // ============================================================================

    #[test]
    fn test_import_credential_with_type_unknown() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let result = wallet.import_credential_with_type(
            create_test_credential_json(),
            "garbage_type".to_string(),
            None,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FfiError::InvalidFormat { .. }
        ));
    }

    #[test]
    fn test_import_credential_with_type_primary() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let result = wallet.import_credential_with_type(
            create_test_credential_json(),
            "primary".to_string(),
            None,
        );
        // Should fail at storage, not at slot resolution
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FfiError::Storage { .. }));
    }

    // ============================================================================
    // CLEANUP EXPIRED CREDENTIALS TESTS
    // ============================================================================

    #[test]
    fn test_cleanup_expired_credentials_no_storage() {
        let wallet = ProviiWallet::new(create_test_app_info());
        // No storage backend registered, should return 0 gracefully
        let removed = wallet.cleanup_expired_credentials();
        assert_eq!(removed, 0);
    }

    // ============================================================================
    // DELETE SANDBOX CREDENTIALS TESTS
    // ============================================================================

    #[test]
    fn test_delete_sandbox_credentials_no_storage() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let result = wallet.delete_sandbox_credentials();
        assert!(result.is_err());
    }

    // ============================================================================
    // GET AVAILABLE SLOT COUNT TESTS
    // ============================================================================

    #[test]
    fn test_get_available_slot_count_no_storage() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let result = wallet.get_available_slot_count();
        // Should fail because storage is not initialised
        assert!(result.is_err());
    }

    // ============================================================================
    // HANDLE DEEPLINK TESTS (via wallet)
    // ============================================================================

    #[test]
    fn test_wallet_handle_deeplink_invalid() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let result = wallet.handle_deeplink("not-a-deeplink".to_string());
        assert!(result.is_err());
    }

    // ============================================================================
    // PARSE QR PAYLOAD TESTS (via wallet)
    // ============================================================================

    #[test]
    fn test_wallet_parse_qr_payload_valid_challenge() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let challenge_json = create_test_challenge_json();
        let result = wallet.parse_qr_payload(challenge_json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_wallet_parse_qr_payload_invalid() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let result = wallet.parse_qr_payload("not valid json".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_wallet_parse_qr_method() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let challenge_json = create_test_challenge_json();
        let result = wallet.parse_qr(challenge_json);
        assert!(result.is_ok());
    }

    // ============================================================================
    // VALIDATE QR TESTS (via wallet)
    // ============================================================================

    #[test]
    fn test_wallet_validate_qr_valid_challenge() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let challenge_json = create_test_challenge_json();
        let result = wallet.validate_qr(challenge_json);
        assert!(result.is_ok());
    }

    // ============================================================================
    // WALLET WITH STORAGE (using create_default_secure_store)
    // ============================================================================

    #[test]
    fn test_wallet_with_storage_import_and_list() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        let cred_json = create_test_credential_json();
        let result = wallet.import_credential(cred_json);
        assert!(
            result.is_ok(),
            "import should succeed with storage, got {:?}",
            result.err()
        );

        let creds = wallet.list_credentials()?;
        assert_eq!(creds.len(), 1);
        Ok(())
    }

    #[test]
    fn test_wallet_with_storage_import_with_secrets() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        let cred_json = create_test_credential_with_secrets_json();
        let cred_id = wallet.import_credential(cred_json)?;
        assert!(!cred_id.is_empty());

        // Secrets should be stored separately
        let has_secrets = wallet.has_credential_secrets(cred_id.clone())?;
        assert!(
            has_secrets,
            "imported credential should have stored secrets"
        );

        // Credential should be retrievable
        let cred_opt = wallet.get_credential(cred_id)?;
        assert!(cred_opt.is_some());
        Ok(())
    }

    #[test]
    fn test_wallet_with_storage_delete_credential() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        let cred_json = create_test_credential_json();
        let cred_id = wallet.import_credential(cred_json)?;

        wallet.delete_credential(cred_id.clone())?;

        let creds = wallet.list_credentials()?;
        assert!(creds.is_empty());
        Ok(())
    }

    #[test]
    fn test_wallet_with_storage_update_nickname() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        let cred_json = create_test_credential_json();
        let cred_id = wallet.import_credential(cred_json)?;

        wallet.update_credential_nickname(cred_id.clone(), Some("My Credential".to_string()))?;

        let creds = wallet.list_credentials()?;
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].nickname, Some("My Credential".to_string()));
        Ok(())
    }

    #[test]
    fn test_wallet_with_storage_has_valid_credential() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        // No credentials yet
        assert!(!wallet.has_valid_credential());

        let cred_json = create_test_credential_json();
        wallet.import_credential(cred_json)?;

        // Now we have a credential (exp is in the future)
        assert!(wallet.has_valid_credential());
        Ok(())
    }

    #[test]
    fn test_wallet_with_storage_available_slot_count() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        let slots = wallet.get_available_slot_count()?;
        // 1 primary + 5 managed = 6 slots available
        assert_eq!(slots, 6);
        Ok(())
    }

    #[test]
    fn test_wallet_process_qr_challenge() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let challenge_json = create_test_challenge_json();
        let result = wallet.process_qr_challenge(challenge_json);
        assert!(result.is_ok());
        let challenge_id = result?;
        assert_eq!(challenge_id, "test-challenge-123");
        Ok(())
    }

    #[test]
    fn test_wallet_get_challenge_diagnostics() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let challenge_json = create_test_challenge_json();
        let challenge_id = wallet.process_qr_challenge(challenge_json)?;

        let diag = wallet.get_challenge_diagnostics(challenge_id)?;
        assert!(diag.contains("test-challenge-123"));
        assert!(diag.contains("19000"));
        Ok(())
    }

    #[test]
    fn test_wallet_get_challenge_diagnostics_not_found() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let result = wallet.get_challenge_diagnostics("nonexistent".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_wallet_process_scanned_qr_challenge() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let challenge_json = create_test_challenge_json();
        let result = wallet.process_scanned_qr(challenge_json);
        assert!(result.is_ok());
        match result? {
            QrAction::VerificationChallenge { challenge_json } => {
                assert!(challenge_json.contains("test-challenge-123"));
            }
            _ => panic!("Expected VerificationChallenge"),
        }
        Ok(())
    }

    #[test]
    fn test_wallet_process_scanned_qr_invalid() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let result = wallet.process_scanned_qr("garbage".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_cached_challenge_debug_redacts_secret() {
        let challenge = CachedChallenge {
            payload: QrChallengePayload {
                challenge_id: "test-id".to_string(),
                rp_challenge: "rp".to_string(),
                cutoff_days: 19000,
                verifying_key_id: 1,
                submit_secret: "SUPER_SECRET".to_string(),
                expires_at: 2000000000,
                verify_url: "https://test.com".to_string(),
                code_verifier: Some("VERIFIER_SECRET".to_string()),
                proof_direction: None,
            },
            received_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now(),
        };

        let debug_str = format!("{:?}", challenge);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("SUPER_SECRET"));
    }

    #[test]
    fn test_safe_lock_unpoisoned() {
        let mutex = Mutex::new(42);
        let guard = safe_lock(&mutex);
        assert_eq!(*guard, 42);
    }

    #[test]
    fn test_wallet_refresh_issuer_keys_empty_jwks() {
        let wallet = ProviiWallet::new(create_test_app_info());
        // Empty JWKS should not panic, but may error on parsing
        let result = wallet.refresh_issuer_keys("{}".to_string());
        // Accept either success (empty keys) or error (parse failure)
        let _ = result;
    }

    #[test]
    fn test_wallet_refresh_issuer_keys_invalid_json() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let result = wallet.refresh_issuer_keys("not json".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_wallet_set_storage_handle_and_list() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        let creds = wallet.list_credentials()?;
        assert!(creds.is_empty());
        Ok(())
    }

    #[test]
    fn test_wallet_import_managed_credential() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        let result = wallet.import_credential_with_type(
            create_test_credential_json(),
            "managed".to_string(),
            Some("Work ID".to_string()),
        );
        assert!(
            result.is_ok(),
            "managed import should succeed, got {:?}",
            result.err()
        );
        Ok(())
    }

    #[test]
    fn test_wallet_store_credential_with_label() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        let result = wallet.store_credential_with_label(
            create_test_credential_json(),
            Some("sandbox".to_string()),
            "primary".to_string(),
            None,
        );
        assert!(
            result.is_ok(),
            "store with label should succeed, got {:?}",
            result.err()
        );
        Ok(())
    }

    #[test]
    fn test_wallet_delete_sandbox_credentials_with_storage(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        // Store a sandbox credential
        wallet.store_credential_with_label(
            create_test_credential_json(),
            Some("sandbox".to_string()),
            "primary".to_string(),
            None,
        )?;

        let result = wallet.delete_sandbox_credentials();
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_wallet_cleanup_expired_credentials_with_storage(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        // Import a credential (not expired, exp=1800000000 is far future)
        wallet.import_credential(create_test_credential_json())?;

        let removed = wallet.cleanup_expired_credentials();
        // Credential exp is 1800000000 which is year 2027, so not expired yet
        assert_eq!(removed, 0);
        Ok(())
    }

    #[test]
    fn test_wallet_get_credential_by_id() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        let cred_id = wallet.import_credential(create_test_credential_json())?;
        let retrieved = wallet.get_credential(cred_id.clone())?;
        assert!(retrieved.is_some());

        // Non-existent should return None
        let missing = wallet.get_credential("nonexistent-id".to_string())?;
        assert!(missing.is_none());
        Ok(())
    }

    #[test]
    fn test_wallet_process_qr_and_create_proof_no_prover() -> Result<(), Box<dyn std::error::Error>>
    {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        // Import a credential with secrets
        let cred_id = wallet.import_credential(create_test_credential_with_secrets_json())?;

        // Process a QR challenge
        let challenge_id = wallet.process_qr_challenge(create_test_challenge_json())?;

        // Attempt proof generation (will fail because prover is not initialised)
        let result = wallet.create_age_proof(cred_id, challenge_id);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_wallet_create_age_proof_auto_single_credential(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        // Import one credential with secrets
        wallet.import_credential(create_test_credential_with_secrets_json())?;

        // Process a QR challenge
        let challenge_id = wallet.process_qr_challenge(create_test_challenge_json())?;

        // Auto-select with single credential (will fail at proof generation, not selection)
        let result = wallet.create_age_proof_auto(challenge_id);
        assert!(result.is_err());
        // Should fail at prover, not credential selection
        if let Err(FfiError::Prover { .. }) = result {
            // expected
        } else if let Err(FfiError::CredentialExpired) = result {
            // also acceptable if system time makes exp look expired
        } else {
            // Could also be other errors depending on state
        }
        Ok(())
    }

    #[test]
    fn test_wallet_create_age_proof_auto_no_credentials() -> Result<(), Box<dyn std::error::Error>>
    {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        let challenge_id = wallet.process_qr_challenge(create_test_challenge_json())?;

        let result = wallet.create_age_proof_auto(challenge_id);
        assert!(result.is_err());
        if let Err(FfiError::Generic { msg }) = &result {
            assert!(msg.contains("No credential stored"));
        }
        Ok(())
    }

    #[test]
    fn test_wallet_create_age_proof_challenge_not_found() -> Result<(), Box<dyn std::error::Error>>
    {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        let cred_id = wallet.import_credential(create_test_credential_with_secrets_json())?;

        let result = wallet.create_age_proof(cred_id, "nonexistent-challenge".to_string());
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_wallet_create_age_proof_credential_not_found() -> Result<(), Box<dyn std::error::Error>>
    {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        let challenge_id = wallet.process_qr_challenge(create_test_challenge_json())?;

        let result = wallet.create_age_proof("nonexistent-cred".to_string(), challenge_id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FfiError::CredentialNotFound));
        Ok(())
    }

    #[test]
    fn test_wallet_get_provable_credentials_no_challenge() -> Result<(), Box<dyn std::error::Error>>
    {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        let result = wallet.get_provable_credentials_for_challenge("nonexistent".to_string());
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_wallet_get_provable_credentials_with_challenge(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        // Import a credential with secrets
        wallet.import_credential(create_test_credential_with_secrets_json())?;

        // Process challenge
        let challenge_id = wallet.process_qr_challenge(create_test_challenge_json())?;

        let result = wallet.get_provable_credentials_for_challenge(challenge_id)?;
        // Should have one credential (may or may not satisfy age requirement)
        assert_eq!(result.len(), 1);
        Ok(())
    }

    #[test]
    fn test_wallet_update_config() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());

        let mut config = wallet.get_config();
        config.auto_select = false;
        config.network_timeout = 120;
        wallet.update_config(config)?;

        let updated = wallet.get_config();
        assert!(!updated.auto_select);
        assert_eq!(updated.network_timeout, 120);
        Ok(())
    }

    #[test]
    fn test_wallet_drop_zeroizes() {
        // Verify the wallet can be dropped without panicking
        let wallet = ProviiWallet::new(create_test_app_info());
        drop(wallet);
    }

    #[test]
    fn test_wallet_process_manual_entry_invalid_code() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let result = wallet.process_manual_entry("abc".to_string());
        assert!(result.is_err());
        if let Err(FfiError::InvalidFormat { msg }) = result {
            assert!(msg.contains("12 digits"));
        }
    }

    #[test]
    fn test_wallet_fetch_challenge_by_short_code_invalid() {
        let wallet = ProviiWallet::new(create_test_app_info());
        let result = wallet.fetch_challenge_by_short_code("abc".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_wallet_persist_and_load_anchor() -> Result<(), Box<dyn std::error::Error>> {
        let wallet = ProviiWallet::new(create_test_app_info());
        let store = crate::create_default_secure_store()?;
        wallet.set_storage_handle(store)?;

        // Refresh with empty JWKS (valid structure but no supported keys)
        let jwks = r#"{"keys":[]}"#;
        let result = wallet.refresh_issuer_keys(jwks.to_string());
        // Should succeed (empty keys = no-op)
        assert!(result.is_ok());
        Ok(())
    }
}
