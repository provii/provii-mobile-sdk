// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Credential storage layer for the FFI surface.
//!
//! This module manages serialisation, namespacing, and slot allocation for
//! age credentials stored in platform secure storage (iOS Keychain, Android
//! Keystore). Every credential occupies two storage keys:
//!
//! * A **public record** (`provii.cred.*`) containing the signed credential
//!   blob and metadata. No biometric gate is required to read this.
//! * A **secrets record** (`provii.credsec.*`) containing `dob_days` and
//!   `r_bits` used during proof generation. Reading secrets requires
//!   biometric authentication.
//!
//! Credentials are further partitioned by **namespace** (production vs
//! sandbox) and **slot** (primary vs managed). The slot-aware key scheme
//! looks like this:
//!
//! ```text
//! Primary credential (one per namespace):
//!   provii.cred.primary.{base_id}        / provii.credsec.primary.{base_id}
//!   provii.sandbox.cred.primary.{base_id} / provii.sandbox.credsec.primary.{base_id}
//!
//! Managed credentials (up to 5, index 0-4):
//!   provii.cred.managed.{index}.{base_id}        / provii.credsec.managed.{index}.{base_id}
//!   provii.sandbox.cred.managed.{index}.{base_id} / provii.sandbox.credsec.managed.{index}.{base_id}
//! ```

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use provii_mobile_sdk_platform_storage::BiometricRequirement;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

use crate::types::{
    CredentialInfo, CredentialMetadata, CredentialSecrets, CredentialStatus, StoredCredential,
};
use provii_crypto_commit::pedersen_nullifier;
use provii_mobile_sdk_core::types::CredentialV2;

use crate::types::CredentialSlot;

// Primary credential prefixes
const PRIMARY_CRED_PRIMARY_PREFIX: &str = "provii.cred.primary.";
const PRIMARY_CREDSEC_PRIMARY_PREFIX: &str = "provii.credsec.primary.";
const SANDBOX_CRED_PRIMARY_PREFIX: &str = "provii.sandbox.cred.primary.";
const SANDBOX_CREDSEC_PRIMARY_PREFIX: &str = "provii.sandbox.credsec.primary.";

// Managed credential prefixes (index appended dynamically)
const PRIMARY_CRED_MANAGED_PREFIX: &str = "provii.cred.managed.";
const PRIMARY_CREDSEC_MANAGED_PREFIX: &str = "provii.credsec.managed.";
const SANDBOX_CRED_MANAGED_PREFIX: &str = "provii.sandbox.cred.managed.";
const SANDBOX_CREDSEC_MANAGED_PREFIX: &str = "provii.sandbox.credsec.managed.";

/// Maximum number of managed credential slots
const MAX_MANAGED_SLOTS: u8 = 15;

/// All credential key prefixes (for listing/detection)
const ALL_CRED_PREFIXES: &[&str] = &[
    PRIMARY_CRED_PRIMARY_PREFIX,
    PRIMARY_CRED_MANAGED_PREFIX,
    SANDBOX_CRED_PRIMARY_PREFIX,
    SANDBOX_CRED_MANAGED_PREFIX,
];

/// All secrets key prefixes (for detection)
const ALL_CREDSEC_PREFIXES: &[&str] = &[
    PRIMARY_CREDSEC_PRIMARY_PREFIX,
    PRIMARY_CREDSEC_MANAGED_PREFIX,
    SANDBOX_CREDSEC_PRIMARY_PREFIX,
    SANDBOX_CREDSEC_MANAGED_PREFIX,
];

/// Namespace that determines the storage key prefix for a credential.
///
/// Production credentials live under `provii.cred.*` while sandbox
/// credentials live under `provii.sandbox.cred.*`. The `Unknown` variant
/// falls back to `Primary` when resolving prefixes.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum CredentialNamespace {
    /// Production namespace (`provii.cred.*` / `provii.credsec.*`).
    Primary,
    /// Sandbox namespace (`provii.sandbox.cred.*` / `provii.sandbox.credsec.*`).
    Sandbox,
    /// Unrecognised key format; treated as [`Primary`](Self::Primary).
    Unknown,
}

impl CredentialNamespace {
    /// Returns (cred_prefix, credsec_prefix) for a given slot.
    /// For managed slots, the prefix includes the index: "provii.cred.managed.{index}."
    fn prefixes_for_slot(self, slot: CredentialSlot) -> (String, String) {
        match (self, slot) {
            (CredentialNamespace::Primary, CredentialSlot::Primary) => (
                PRIMARY_CRED_PRIMARY_PREFIX.to_string(),
                PRIMARY_CREDSEC_PRIMARY_PREFIX.to_string(),
            ),
            (CredentialNamespace::Primary, CredentialSlot::Managed { index }) => (
                format!("{}{index}.", PRIMARY_CRED_MANAGED_PREFIX),
                format!("{}{index}.", PRIMARY_CREDSEC_MANAGED_PREFIX),
            ),
            (CredentialNamespace::Sandbox, CredentialSlot::Primary) => (
                SANDBOX_CRED_PRIMARY_PREFIX.to_string(),
                SANDBOX_CREDSEC_PRIMARY_PREFIX.to_string(),
            ),
            (CredentialNamespace::Sandbox, CredentialSlot::Managed { index }) => (
                format!("{}{index}.", SANDBOX_CRED_MANAGED_PREFIX),
                format!("{}{index}.", SANDBOX_CREDSEC_MANAGED_PREFIX),
            ),
            (CredentialNamespace::Unknown, slot) => {
                CredentialNamespace::Primary.prefixes_for_slot(slot)
            }
        }
    }

    pub(crate) fn from_label(label: Option<&str>) -> Self {
        match label {
            Some(l) if l.eq_ignore_ascii_case("sandbox") => CredentialNamespace::Sandbox,
            _ => CredentialNamespace::Primary,
        }
    }

    fn from_credential_id(id: &str) -> (Self, CredentialSlot) {
        // Sandbox managed: provii.sandbox.cred.managed.{index}.{base_id}
        if id.starts_with(SANDBOX_CRED_MANAGED_PREFIX)
            || id.starts_with(SANDBOX_CREDSEC_MANAGED_PREFIX)
        {
            let index = parse_managed_index_from_key(id, true);
            return (
                CredentialNamespace::Sandbox,
                CredentialSlot::Managed { index },
            );
        }
        // Sandbox primary: provii.sandbox.cred.primary.{base_id}
        if id.starts_with(SANDBOX_CRED_PRIMARY_PREFIX)
            || id.starts_with(SANDBOX_CREDSEC_PRIMARY_PREFIX)
        {
            return (CredentialNamespace::Sandbox, CredentialSlot::Primary);
        }
        // Primary managed: provii.cred.managed.{index}.{base_id}
        if id.starts_with(PRIMARY_CRED_MANAGED_PREFIX)
            || id.starts_with(PRIMARY_CREDSEC_MANAGED_PREFIX)
        {
            let index = parse_managed_index_from_key(id, false);
            return (
                CredentialNamespace::Primary,
                CredentialSlot::Managed { index },
            );
        }
        // Primary primary: provii.cred.primary.{base_id}
        if id.starts_with(PRIMARY_CRED_PRIMARY_PREFIX)
            || id.starts_with(PRIMARY_CREDSEC_PRIMARY_PREFIX)
        {
            return (CredentialNamespace::Primary, CredentialSlot::Primary);
        }
        (CredentialNamespace::Unknown, CredentialSlot::Primary)
    }
}

/// Extract the managed index from a storage key.
/// For sandbox: "provii.sandbox.cred.managed.{index}.{base_id}" or "provii.sandbox.credsec.managed.{index}.{base_id}"
/// For primary: "provii.cred.managed.{index}.{base_id}" or "provii.credsec.managed.{index}.{base_id}"
fn parse_managed_index_from_key(key: &str, sandbox: bool) -> u8 {
    let prefix = if sandbox {
        // Could be cred or credsec
        if key.starts_with(SANDBOX_CRED_MANAGED_PREFIX) {
            SANDBOX_CRED_MANAGED_PREFIX
        } else {
            SANDBOX_CREDSEC_MANAGED_PREFIX
        }
    } else if key.starts_with(PRIMARY_CRED_MANAGED_PREFIX) {
        PRIMARY_CRED_MANAGED_PREFIX
    } else {
        PRIMARY_CREDSEC_MANAGED_PREFIX
    };
    // After stripping prefix, remainder is "{index}.{base_id}"
    let remainder = key.strip_prefix(prefix).unwrap_or("0");
    remainder
        .split('.')
        .next()
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or(0)
}

/// Returns true if a storage key is a credential key (not a secrets key).
fn is_credential_key(key: &str) -> bool {
    // Must match a cred prefix but NOT a credsec prefix
    for prefix in ALL_CRED_PREFIXES {
        if key.starts_with(prefix) {
            // Make sure it's not a credsec key that happens to share a prefix
            for sec_prefix in ALL_CREDSEC_PREFIXES {
                if key.starts_with(sec_prefix) {
                    return false;
                }
            }
            return true;
        }
    }
    false
}

/// Thread-safe credential store backed by a platform-specific
/// [`PlatformSecureStorage`](provii_mobile_sdk_platform_storage::PlatformSecureStorage)
/// implementation.
///
/// Call [`set_backend`](Self::set_backend) once at startup to inject the
/// iOS Keychain or Android Keystore adapter. All subsequent operations
/// return an error if the backend has not been set.
pub struct Storage {
    backend: Mutex<Option<Arc<dyn provii_mobile_sdk_platform_storage::PlatformSecureStorage>>>,
}

impl Storage {
    /// Create a new `Storage` with no backend attached.
    pub fn new() -> Self {
        Self {
            backend: Mutex::new(None),
        }
    }

    /// Inject the platform secure storage backend.
    ///
    /// Must be called exactly once during application startup, before any
    /// credential operations.
    pub fn set_backend(
        &self,
        backend: Arc<dyn provii_mobile_sdk_platform_storage::PlatformSecureStorage>,
    ) {
        *self.backend.lock().unwrap_or_else(|e| e.into_inner()) = Some(backend);
    }

    /// Returns `true` if a storage backend has been set.
    pub fn is_available(&self) -> bool {
        self.backend
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    /// Acquire a lock guard over the inner backend option.
    ///
    /// The caller can dereference to obtain an `Option<Arc<dyn PlatformSecureStorage>>`.
    /// Used by wallet methods that need direct backend access outside the
    /// credential namespace abstraction (for example, persisting the trust anchor).
    pub fn backend_ref(
        &self,
    ) -> std::sync::MutexGuard<
        '_,
        Option<Arc<dyn provii_mobile_sdk_platform_storage::PlatformSecureStorage>>,
    > {
        self.backend.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Store a credential in the primary slot for the given namespace.
    ///
    /// Equivalent to calling [`store_credential_with_slot`](Self::store_credential_with_slot)
    /// with [`CredentialSlot::Primary`] and no nickname.
    #[allow(dead_code)] // Convenience wrapper; used in tests
    pub fn store_credential(
        &self,
        credential: &CredentialV2,
        label: Option<&str>,
    ) -> Result<String> {
        self.store_credential_with_slot(credential, label, CredentialSlot::Primary, None)
    }

    /// Store a credential in a specific namespace and slot.
    ///
    /// Any existing credential in the same namespace+slot is deleted first
    /// (both public record and secrets). Returns the storage key of the
    /// newly written public record.
    pub fn store_credential_with_slot(
        &self,
        credential: &CredentialV2,
        label: Option<&str>,
        slot: CredentialSlot,
        nickname: Option<&str>,
    ) -> Result<String> {
        let backend = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        let backend = backend
            .as_ref()
            .ok_or_else(|| anyhow!("Storage not initialised"))?;
        let namespace = CredentialNamespace::from_label(label);
        let (cred_prefix, credsec_prefix) = namespace.prefixes_for_slot(slot);

        // Delete existing credentials in the same namespace+slot only
        let keys = backend
            .list_keys()
            .map_err(|e| anyhow!("Failed to list keys: {}", e))?;

        for key in keys {
            if key.starts_with(&cred_prefix) || key.starts_with(&credsec_prefix) {
                backend
                    .delete(&key)
                    .map_err(|e| anyhow!("Failed to delete existing credential: {}", e))?;
            }
        }

        let (credential_type, managed_index) = match slot {
            CredentialSlot::Primary => ("primary".to_string(), None),
            CredentialSlot::Managed { index } => ("managed".to_string(), Some(index)),
        };

        let stored = StoredCredential {
            credential: credential.clone(),
            metadata: CredentialMetadata {
                #[allow(clippy::cast_sign_loss)]
                imported_at: chrono::Utc::now().timestamp().max(0) as u64,
                last_used: None,
                use_count: 0,
                label: label.map(|s| s.to_string()),
                credential_type,
                nickname: nickname.map(|s| s.to_string()),
                managed_index,
            },
        };

        let base_id = self.compute_base_id(credential);
        let key = format!("{}{}", cred_prefix, base_id);
        let data = postcard::to_allocvec(&stored)
            .map_err(|e| anyhow!("Failed to serialize credential: {}", e))?;

        // Public credential data (no secrets) -- no biometric required.
        backend
            .store(&key, &data, BiometricRequirement::None)
            .map_err(|e| anyhow!("Failed to store credential: {}", e))?;

        Ok(key)
    }

    /// Store credential secrets (dob_days, r_bits) behind the biometric gate.
    ///
    /// The `cred_id` must be a storage key returned by
    /// [`store_credential`](Self::store_credential) or
    /// [`store_credential_with_slot`](Self::store_credential_with_slot).
    /// The secrets blob is zeroised in memory after serialisation.
    pub fn store_credential_secrets(
        &self,
        cred_id: &str,
        secrets: &CredentialSecrets,
    ) -> Result<()> {
        let backend = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        let backend = backend
            .as_ref()
            .ok_or_else(|| anyhow!("Storage not initialised"))?;

        let (namespace, slot) = CredentialNamespace::from_credential_id(cred_id);
        let (cred_prefix, credsec_prefix) = namespace.prefixes_for_slot(slot);

        let base_id = cred_id.strip_prefix(&cred_prefix).unwrap_or(cred_id);

        let key = format!("{}{}", credsec_prefix, base_id);
        // Wrap serialised bytes in Zeroizing (contains dob_days, r_bits)
        let body = Zeroizing::new(
            postcard::to_allocvec(secrets)
                .map_err(|e| anyhow!("Failed to serialize secrets: {}", e))?,
        );

        // Credential secrets (dob_days, r_bits) -- biometric required.
        backend
            .store(&key, &body, BiometricRequirement::for_credential_secrets())
            .map_err(|e| anyhow!("Failed to store secrets: {}", e))
    }

    /// Check whether credential secrets exist in storage without loading them.
    ///
    /// Uses the backend `exists()` method, which does not trigger biometric
    /// authentication and does not load data into memory. Returns `true` if
    /// a secrets record is present for the given credential key.
    pub fn credential_secrets_exist(&self, cred_id: &str) -> Result<bool> {
        let backend = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        let backend = backend
            .as_ref()
            .ok_or_else(|| anyhow!("Storage not initialised"))?;

        let (namespace, slot) = CredentialNamespace::from_credential_id(cred_id);
        let (cred_prefix, credsec_prefix) = namespace.prefixes_for_slot(slot);

        let base_id = cred_id.strip_prefix(&cred_prefix).unwrap_or(cred_id);

        let key = format!("{}{}", credsec_prefix, base_id);

        backend
            .exists(&key)
            .map_err(|e| anyhow!("Failed to check secrets existence: {}", e))
    }

    /// Load credential secrets from behind the biometric gate.
    ///
    /// Returns `Ok(None)` if no secrets record exists for the given
    /// credential (rather than returning an error).
    pub fn load_credential_secrets(&self, cred_id: &str) -> Result<Option<CredentialSecrets>> {
        let backend = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        let backend = backend
            .as_ref()
            .ok_or_else(|| anyhow!("Storage not initialised"))?;

        let (namespace, slot) = CredentialNamespace::from_credential_id(cred_id);
        let (cred_prefix, credsec_prefix) = namespace.prefixes_for_slot(slot);

        let base_id = cred_id.strip_prefix(&cred_prefix).unwrap_or(cred_id);

        let key = format!("{}{}", credsec_prefix, base_id);

        // Credential secrets -- biometric required.
        match backend.retrieve(&key, BiometricRequirement::for_credential_secrets()) {
            Ok(data) => {
                // data is already Zeroizing<Vec<u8>> from the trait, so it
                // will be wiped on drop. Contains dob_days and r_bits.
                Ok(Some(
                    postcard::from_bytes::<CredentialSecrets>(&data)
                        .map_err(|e| anyhow!("Failed to parse secrets: {}", e))?,
                ))
            }
            Err(e) if e.to_string().contains("NotFound") => Ok(None),
            Err(e) => Err(anyhow!("Failed to retrieve secrets: {}", e)),
        }
    }

    /// Retrieve a single credential by its storage key.
    ///
    /// Returns `Ok(None)` if the key does not exist.
    pub fn get_credential(&self, credential_id: &str) -> Result<Option<CredentialV2>> {
        let backend = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        let backend = backend
            .as_ref()
            .ok_or_else(|| anyhow!("Storage not initialised"))?;

        // Public credential data -- no biometric required.
        match backend.retrieve(credential_id, BiometricRequirement::None) {
            Ok(data) => {
                let stored: StoredCredential = postcard::from_bytes(&data)
                    .map_err(|e| anyhow!("Failed to parse credential: {}", e))?;
                Ok(Some(stored.credential))
            }
            Err(e) if e.to_string().contains("NotFound") => Ok(None),
            Err(e) => Err(anyhow!("Failed to retrieve credential: {}", e)),
        }
    }

    /// List all stored credentials across every namespace and slot.
    ///
    /// Secrets keys are filtered out; only public credential records appear
    /// in the result. Each [`CredentialInfo`] includes expiry status, issuer
    /// name, slot type, and whether secrets are available for proof
    /// generation.
    pub fn list_credentials(&self) -> Result<Vec<CredentialInfo>> {
        let backend = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        let backend = backend
            .as_ref()
            .ok_or_else(|| anyhow!("Storage not initialised"))?;

        let keys = backend
            .list_keys()
            .map_err(|e| anyhow!("Failed to list keys: {}", e))?;

        let mut credentials = Vec::new();
        for key in keys {
            if !is_credential_key(&key) {
                continue;
            }
            // Public credential data -- no biometric required.
            if let Ok(data) = backend.retrieve(&key, BiometricRequirement::None) {
                if let Ok(stored) = postcard::from_bytes::<StoredCredential>(&data) {
                    #[allow(clippy::cast_sign_loss)]
                    let now = chrono::Utc::now().timestamp().max(0) as u64;
                    let status = if stored.credential.exp < now {
                        CredentialStatus::Expired
                    } else {
                        CredentialStatus::Valid
                    };

                    let issuer_name = if stored.credential.kid.contains("issuer:") {
                        stored
                            .credential
                            .kid
                            .split(':')
                            .nth(1)
                            .unwrap_or("Unknown Issuer")
                            .to_string()
                    } else {
                        "Unknown Issuer".to_string()
                    };

                    let mut display_issuer = issuer_name.clone();
                    if let Some(label) = &stored.metadata.label {
                        if label.eq_ignore_ascii_case("sandbox") {
                            display_issuer = format!("{} (Sandbox)", display_issuer);
                        }
                    }

                    // Check if secrets exist (existence check only, no biometric
                    // needed since we call exists() on the backend, but the trait
                    // only exposes retrieve/store with bio). Use None here because
                    // this is a presence check that does not expose secret material.
                    let (namespace, slot) = CredentialNamespace::from_credential_id(&key);
                    let (cred_prefix, credsec_prefix) = namespace.prefixes_for_slot(slot);
                    let base_id = key.strip_prefix(&cred_prefix).unwrap_or(&key);
                    let secrets_key = format!("{}{}", credsec_prefix, base_id);
                    let has_secrets = backend.exists(&secrets_key).unwrap_or(false);

                    credentials.push(CredentialInfo {
                        id: key.clone(),
                        issuer_name: display_issuer,
                        issuer_kid: stored.credential.kid.clone(),
                        issued_at: stored.credential.iat,
                        expires_at: stored.credential.exp,
                        is_expired: stored.credential.exp < now,
                        can_prove: stored.credential.exp >= now && has_secrets,
                        schema: stored.credential.schema.clone(),
                        status,
                        credential_type: stored.metadata.credential_type.clone(),
                        nickname: stored.metadata.nickname.clone(),
                        managed_index: stored.metadata.managed_index,
                    });
                }
            }
        }

        Ok(credentials)
    }

    /// Get the credential stored in a specific namespace+slot.
    /// Returns None if no credential exists in that slot.
    #[allow(dead_code)] // Public API for slot-based credential lookup
    pub fn get_credential_for_slot(
        &self,
        namespace: CredentialNamespace,
        slot: CredentialSlot,
    ) -> Result<Option<(String, CredentialV2)>> {
        let backend = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        let backend = backend
            .as_ref()
            .ok_or_else(|| anyhow!("Storage not initialised"))?;

        let (cred_prefix, _) = namespace.prefixes_for_slot(slot);

        let keys = backend
            .list_keys()
            .map_err(|e| anyhow!("Failed to list keys: {}", e))?;

        for key in keys {
            if key.starts_with(&cred_prefix) {
                // Public credential data -- no biometric required.
                if let Ok(data) = backend.retrieve(&key, BiometricRequirement::None) {
                    if let Ok(stored) = postcard::from_bytes::<StoredCredential>(&data) {
                        return Ok(Some((key, stored.credential)));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Find the next available managed credential index (0-4) in a namespace.
    /// Returns an error if all 5 managed slots are full.
    pub fn next_available_managed_index(&self, namespace: CredentialNamespace) -> Result<u8> {
        let backend = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        let backend = backend
            .as_ref()
            .ok_or_else(|| anyhow!("Storage not initialised"))?;

        let keys = backend
            .list_keys()
            .map_err(|e| anyhow!("Failed to list keys: {}", e))?;

        let managed_cred_prefix = match namespace {
            CredentialNamespace::Sandbox => SANDBOX_CRED_MANAGED_PREFIX,
            _ => PRIMARY_CRED_MANAGED_PREFIX,
        };

        // Track which indices are occupied
        let mut occupied = [false; MAX_MANAGED_SLOTS as usize];
        for key in &keys {
            if key.starts_with(managed_cred_prefix) {
                let remainder = key.strip_prefix(managed_cred_prefix).unwrap_or("0");
                if let Some(idx) = remainder
                    .split('.')
                    .next()
                    .and_then(|s| s.parse::<u8>().ok())
                {
                    if let Some(slot) = occupied.get_mut(idx as usize) {
                        *slot = true;
                    }
                }
            }
        }

        for i in 0..MAX_MANAGED_SLOTS {
            if let Some(&is_occupied) = occupied.get(i as usize) {
                if !is_occupied {
                    return Ok(i);
                }
            }
        }

        Err(anyhow!(
            "All {} managed credential slots are full",
            MAX_MANAGED_SLOTS
        ))
    }

    /// Update the nickname of a stored credential.
    /// SAFETY: This performs a targeted read-modify-write on the StoredCredential blob only.
    /// It does NOT use store_credential_with_slot (which deletes all slot keys including secrets).
    pub fn update_credential_nickname(
        &self,
        credential_id: &str,
        nickname: Option<&str>,
    ) -> Result<()> {
        let backend = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        let backend = backend
            .as_ref()
            .ok_or_else(|| anyhow!("Storage not initialised"))?;

        // Read existing StoredCredential (public data -- no biometric required).
        let data = backend
            .retrieve(credential_id, BiometricRequirement::None)
            .map_err(|e| anyhow!("Credential not found: {}", e))?;

        let mut stored: StoredCredential = postcard::from_bytes(&data)
            .map_err(|e| anyhow!("Failed to parse credential: {}", e))?;

        // Update only the nickname field
        stored.metadata.nickname = nickname.map(|s| s.to_string());

        // Write back to the SAME key (no slot deletion, no credsec touch)
        let updated_data = postcard::to_allocvec(&stored)
            .map_err(|e| anyhow!("Failed to serialize credential: {}", e))?;
        // Public credential metadata -- no biometric required.
        backend
            .store(credential_id, &updated_data, BiometricRequirement::None)
            .map_err(|e| anyhow!("Failed to update credential: {}", e))?;

        Ok(())
    }

    /// Delete all credentials (and their secrets) in the sandbox namespace.
    ///
    /// Production credentials are not affected. Returns the number of
    /// storage keys deleted.
    pub fn delete_sandbox_credentials(&self) -> Result<usize> {
        self.delete_all_in_namespace(CredentialNamespace::Sandbox)
    }

    /// Delete a credential and its associated secrets record.
    ///
    /// The secrets key is derived from the credential key by swapping the
    /// `cred` segment for `credsec`. Missing secrets are silently ignored.
    pub fn delete_credential(&self, credential_id: &str) -> Result<()> {
        let backend = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        let backend = backend
            .as_ref()
            .ok_or_else(|| anyhow!("Storage not initialised"))?;

        let (namespace, slot) = CredentialNamespace::from_credential_id(credential_id);
        let (cred_prefix, credsec_prefix) = namespace.prefixes_for_slot(slot);

        // Delete public record
        backend
            .delete(credential_id)
            .map_err(|e| anyhow!("Failed to delete credential: {}", e))?;

        // Delete secrets if present
        let base_id = credential_id
            .strip_prefix(&cred_prefix)
            .unwrap_or(credential_id);
        let sec_key = format!("{}{}", credsec_prefix, base_id);

        // Ignore NotFound errors for secrets
        let _ = backend.delete(&sec_key);

        Ok(())
    }

    fn delete_all_in_namespace(&self, namespace: CredentialNamespace) -> Result<usize> {
        let backend = self.backend.lock().unwrap_or_else(|e| e.into_inner());
        let backend = backend
            .as_ref()
            .ok_or_else(|| anyhow!("Storage not initialised"))?;

        // Collect all prefixes for this namespace (primary + all managed indices)
        let (primary_cred, primary_sec) = namespace.prefixes_for_slot(CredentialSlot::Primary);
        let managed_cred_prefix = match namespace {
            CredentialNamespace::Sandbox => SANDBOX_CRED_MANAGED_PREFIX,
            _ => PRIMARY_CRED_MANAGED_PREFIX,
        };
        let managed_sec_prefix = match namespace {
            CredentialNamespace::Sandbox => SANDBOX_CREDSEC_MANAGED_PREFIX,
            _ => PRIMARY_CREDSEC_MANAGED_PREFIX,
        };

        let keys = backend
            .list_keys()
            .map_err(|e| anyhow!("Failed to list keys: {}", e))?;

        let mut deleted = 0usize;
        for key in keys {
            let matches = key.starts_with(&primary_cred)
                || key.starts_with(&primary_sec)
                || key.starts_with(managed_cred_prefix)
                || key.starts_with(managed_sec_prefix);

            if matches && backend.delete(&key).is_ok() {
                deleted = deleted.saturating_add(1);
            }
        }

        Ok(deleted)
    }

    fn compute_base_id(&self, credential: &CredentialV2) -> String {
        let nullifier = pedersen_nullifier(&credential.c_bytes);
        B64.encode(nullifier)
    }

    /// Returns `true` if at least one credential exists in any namespace.
    #[allow(dead_code)] // Convenience query; used in tests
    pub fn has_credential(&self) -> Result<bool> {
        let credentials = self.list_credentials()?;
        Ok(!credentials.is_empty())
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
#[path = "storage_tests.rs"]
mod tests;
