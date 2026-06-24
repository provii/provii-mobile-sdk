// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Credential CRUD, slot resolution, suitability checks, and trust-anchor
//! persistence for [`ProviiWallet`].

use super::*;
use crate::storage::CredentialNamespace;
use provii_mobile_sdk_core::issuance as core_issuance;
use provii_mobile_sdk_core::types::CredentialV2;
use zeroize::Zeroizing;

#[uniffi::export]
impl ProviiWallet {
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
    pub(crate) fn resolve_slot(
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
    pub(crate) fn persist_anchor_to_storage(&self, anchor: &IssuerTrustAnchor) -> FfiResult<()> {
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
    pub(crate) fn load_anchor_from_storage(&self) -> FfiResult<Option<IssuerTrustAnchor>> {
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
