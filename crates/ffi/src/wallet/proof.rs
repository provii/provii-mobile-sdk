// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Proof generation, verification submission, and network/status helpers for
//! [`ProviiWallet`].

use super::*;
use crate::tokio_rt;
use provii_mobile_sdk_core::prover::{build_verify_request, pedersen_commit_dob_validated};
#[cfg(feature = "http")]
use provii_mobile_sdk_core::types::SubmitProofRequest;

#[uniffi::export]
impl ProviiWallet {
    /// Returns true only if at least one non-expired credential exists.
    pub fn has_valid_credential(&self) -> bool {
        self.storage
            .list_credentials()
            .map(|creds| creds.iter().any(|c| !c.is_expired))
            .unwrap_or(false)
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
}
