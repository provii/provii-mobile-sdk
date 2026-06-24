// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Wallet construction, configuration, prover/storage setup, issuer key
//! refresh, and diagnostic accessors for [`ProviiWallet`].

use super::*;
use crate::biometric::{BiometricAuthenticator, BiometricConfig};
use provii_mobile_sdk_core::issuance as core_issuance;
use provii_mobile_sdk_core::prover::{init_prover_with_pk_bytes, preflight_report};

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
}
