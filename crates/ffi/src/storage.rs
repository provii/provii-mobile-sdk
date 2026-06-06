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
mod tests {
    use super::*;
    use provii_mobile_sdk_platform_storage::PlatformSecureStorage;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    // Mock storage backend for testing
    struct MockStorage {
        data: StdMutex<HashMap<String, Vec<u8>>>,
    }

    impl MockStorage {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                data: StdMutex::new(HashMap::new()),
            })
        }
    }

    impl provii_mobile_sdk_platform_storage::PlatformSecureStorage for MockStorage {
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
        ) -> provii_mobile_sdk_platform_storage::Result<zeroize::Zeroizing<Vec<u8>>> {
            self.data
                .lock()
                .map_err(
                    |_| provii_mobile_sdk_platform_storage::WalletError::Storage {
                        msg: "mutex poisoned".to_string(),
                    },
                )?
                .get(key)
                .cloned()
                .map(zeroize::Zeroizing::new)
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

    // Helper to create test credential
    fn create_test_credential() -> CredentialV2 {
        CredentialV2 {
            v: 2,
            schema: "provii.age/0".to_string(),
            kid: "issuer:TestIssuer:key1".to_string(),
            iat: 1700000000,
            exp: 1800000000,
            c_bytes: [1u8; 32],
            issuer_vk: [2u8; 32],
            sig_rj: [3u8; 64],
            dob_days: None,
            r_bits: None,
        }
    }

    fn create_test_secrets() -> CredentialSecrets {
        CredentialSecrets {
            dob_days: 19000,
            r_bits: vec![true; 128],
        }
    }

    // ========================================================================
    // Namespace Isolation Tests
    // ========================================================================

    #[test]
    fn test_primary_namespace_store() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let result = storage.store_credential(&cred, None);

        assert!(result.is_ok());
        let key = result?;
        assert!(key.starts_with(PRIMARY_CRED_PRIMARY_PREFIX));
        Ok(())
    }

    #[test]
    fn test_sandbox_namespace_store() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let result = storage.store_credential(&cred, Some("sandbox"));

        assert!(result.is_ok());
        let key = result?;
        assert!(key.starts_with(SANDBOX_CRED_PRIMARY_PREFIX));
        Ok(())
    }

    #[test]
    fn test_namespace_isolation() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred1 = create_test_credential();
        let cred2 = create_test_credential();

        let primary_key = storage.store_credential(&cred1, None)?;
        let sandbox_key = storage.store_credential(&cred2, Some("sandbox"))?;

        assert_ne!(primary_key, sandbox_key);
        assert!(primary_key.starts_with(PRIMARY_CRED_PRIMARY_PREFIX));
        assert!(sandbox_key.starts_with(SANDBOX_CRED_PRIMARY_PREFIX));
        Ok(())
    }

    #[test]
    fn test_primary_prefix_format() {
        assert_eq!(PRIMARY_CRED_PRIMARY_PREFIX, "provii.cred.primary.");
    }

    #[test]
    fn test_primary_secret_prefix_format() {
        assert_eq!(PRIMARY_CREDSEC_PRIMARY_PREFIX, "provii.credsec.primary.");
    }

    #[test]
    fn test_sandbox_primary_prefix_format() {
        assert_eq!(SANDBOX_CRED_PRIMARY_PREFIX, "provii.sandbox.cred.primary.");
    }

    #[test]
    fn test_sandbox_primary_secret_prefix_format() {
        assert_eq!(
            SANDBOX_CREDSEC_PRIMARY_PREFIX,
            "provii.sandbox.credsec.primary."
        );
    }

    #[test]
    fn test_managed_slot_prefixes() {
        assert_eq!(PRIMARY_CRED_MANAGED_PREFIX, "provii.cred.managed.");
        assert_eq!(PRIMARY_CREDSEC_MANAGED_PREFIX, "provii.credsec.managed.");
        assert_eq!(SANDBOX_CRED_MANAGED_PREFIX, "provii.sandbox.cred.managed.");
        assert_eq!(
            SANDBOX_CREDSEC_MANAGED_PREFIX,
            "provii.sandbox.credsec.managed."
        );
    }

    #[test]
    fn test_list_credentials_filters_secrets() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let cred_id = storage.store_credential(&cred, None)?;
        storage.store_credential_secrets(&cred_id, &create_test_secrets())?;

        let credentials = storage.list_credentials()?;
        // Should only list credentials, not secrets
        assert_eq!(credentials.len(), 1);
        Ok(())
    }

    // ========================================================================
    // Store and Retrieve Tests (8 tests)
    // ========================================================================

    #[test]
    fn test_store_credential_no_secrets() {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let result = storage.store_credential(&cred, None);

        assert!(result.is_ok());
    }

    #[test]
    fn test_store_credential_with_secrets() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let cred_id = storage.store_credential(&cred, None)?;
        let secrets = create_test_secrets();

        let result = storage.store_credential_secrets(&cred_id, &secrets);
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_get_credential_exists() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let cred_id = storage.store_credential(&cred, None)?;

        let retrieved = storage.get_credential(&cred_id)?;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.ok_or("expected credential")?.kid, cred.kid);
        Ok(())
    }

    #[test]
    fn test_get_credential_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let result = storage.get_credential("nonexistent");
        assert!(result.is_ok());
        assert!(result?.is_none());
        Ok(())
    }

    #[test]
    fn test_load_secrets_exists() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let cred_id = storage.store_credential(&cred, None)?;
        let secrets = create_test_secrets();
        storage.store_credential_secrets(&cred_id, &secrets)?;

        let loaded = storage.load_credential_secrets(&cred_id)?;
        assert!(loaded.is_some());
        assert_eq!(loaded.ok_or("expected secrets")?.dob_days, secrets.dob_days);
        Ok(())
    }

    #[test]
    fn test_load_secrets_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let result = storage.load_credential_secrets("provii.cred.nonexistent");
        assert!(result.is_ok());
        assert!(result?.is_none());
        Ok(())
    }

    #[test]
    fn test_load_sandbox_secrets() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        // Store sandbox credential with secrets
        let cred = create_test_credential();
        let cred_id = storage.store_credential(&cred, Some("sandbox"))?;
        let secrets = create_test_secrets();
        storage.store_credential_secrets(&cred_id, &secrets)?;

        // Load secrets - this was the bug! It should use sandbox prefix
        let loaded = storage.load_credential_secrets(&cred_id)?;
        assert!(loaded.is_some(), "Sandbox secrets should be loadable");
        assert_eq!(loaded.ok_or("expected secrets")?.dob_days, secrets.dob_days);
        Ok(())
    }

    #[test]
    fn test_credential_id_computation() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let cred_id = storage.store_credential(&cred, None)?;

        // Should be deterministic based on c_bytes
        assert!(cred_id.starts_with(PRIMARY_CRED_PRIMARY_PREFIX));
        assert!(cred_id.len() > PRIMARY_CRED_PRIMARY_PREFIX.len());
        Ok(())
    }

    #[test]
    fn test_credential_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let cred_id = storage.store_credential(&cred, None)?;
        let retrieved = storage
            .get_credential(&cred_id)?
            .ok_or("expected credential")?;

        assert_eq!(retrieved.v, cred.v);
        assert_eq!(retrieved.schema, cred.schema);
        assert_eq!(retrieved.kid, cred.kid);
        assert_eq!(retrieved.c_bytes, cred.c_bytes);
        Ok(())
    }

    // ========================================================================
    // Label Handling Tests (5 tests)
    // ========================================================================

    #[test]
    fn test_label_sandbox_case_insensitive() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();

        let key1 = storage.store_credential(&cred, Some("sandbox"))?;
        let key2 = storage.store_credential(&cred, Some("Sandbox"))?;
        let key3 = storage.store_credential(&cred, Some("SANDBOX"))?;

        // All should go to sandbox namespace
        assert!(key1.starts_with(SANDBOX_CRED_PRIMARY_PREFIX));
        assert!(key2.starts_with(SANDBOX_CRED_PRIMARY_PREFIX));
        assert!(key3.starts_with(SANDBOX_CRED_PRIMARY_PREFIX));
        Ok(())
    }

    #[test]
    fn test_label_none_default_primary() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let key = storage.store_credential(&cred, None)?;

        assert!(key.starts_with(PRIMARY_CRED_PRIMARY_PREFIX));
        Ok(())
    }

    #[test]
    fn test_label_custom_primary() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let key = storage.store_credential(&cred, Some("my-custom-label"))?;

        // Custom labels go to primary namespace
        assert!(key.starts_with(PRIMARY_CRED_PRIMARY_PREFIX));
        Ok(())
    }

    #[test]
    fn test_label_custom_sandbox() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let key = storage.store_credential(&cred, Some("sandbox"))?;

        assert!(key.starts_with(SANDBOX_CRED_PRIMARY_PREFIX));
        Ok(())
    }

    #[test]
    fn test_label_stored_in_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let _cred_id = storage.store_credential(&cred, Some("test-label"))?;

        let credentials = storage.list_credentials()?;
        assert_eq!(credentials.len(), 1);
        // Metadata is internal, but we can verify the credential was stored
        Ok(())
    }

    // ========================================================================
    // List Credentials Tests (6 tests)
    // ========================================================================

    #[test]
    fn test_list_credentials_empty() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let credentials = storage.list_credentials()?;
        assert_eq!(credentials.len(), 0);
        Ok(())
    }

    #[test]
    fn test_list_credentials_multiple_primary() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        let backend = MockStorage::new();
        storage.set_backend(backend.clone());

        let cred1 = create_test_credential();
        let mut cred2 = create_test_credential();
        cred2.c_bytes = [2u8; 32]; // Different c_bytes for unique ID

        storage.store_credential(&cred1, None)?;

        // Clear storage to allow second credential
        storage.set_backend(MockStorage::new());
        storage.store_credential(&cred2, None)?;

        let credentials = storage.list_credentials()?;
        assert_eq!(credentials.len(), 1);
        Ok(())
    }

    #[test]
    fn test_list_credentials_multiple_sandbox() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        storage.store_credential(&cred, Some("sandbox"))?;

        let credentials = storage.list_credentials()?;
        assert_eq!(credentials.len(), 1);
        Ok(())
    }

    #[test]
    fn test_list_credentials_mixed() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        let backend = MockStorage::new();
        storage.set_backend(backend.clone());

        let cred1 = create_test_credential();
        let mut cred2 = create_test_credential();
        cred2.c_bytes = [2u8; 32];

        storage.store_credential(&cred1, None)?;
        storage.store_credential(&cred2, Some("sandbox"))?;

        let credentials = storage.list_credentials()?;
        // Should have both primary and sandbox
        assert_eq!(credentials.len(), 2);
        Ok(())
    }

    #[test]
    fn test_list_credentials_expired_detected() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let mut cred = create_test_credential();
        cred.exp = 1000000000; // Past timestamp

        storage.store_credential(&cred, None)?;

        let credentials = storage.list_credentials()?;
        assert_eq!(credentials.len(), 1);
        assert!(credentials[0].is_expired);
        assert!(matches!(credentials[0].status, CredentialStatus::Expired));
        Ok(())
    }

    #[test]
    fn test_list_credentials_issuer_name_parsed() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        storage.store_credential(&cred, None)?;

        let credentials = storage.list_credentials()?;
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].issuer_name, "TestIssuer");
        Ok(())
    }

    // ========================================================================
    // Delete Operations Tests (5 tests)
    // ========================================================================

    #[test]
    fn test_delete_credential_cascade() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let cred_id = storage.store_credential(&cred, None)?;
        storage.store_credential_secrets(&cred_id, &create_test_secrets())?;

        storage.delete_credential(&cred_id)?;

        assert!(storage.get_credential(&cred_id)?.is_none());
        assert!(storage.load_credential_secrets(&cred_id)?.is_none());
        Ok(())
    }

    #[test]
    fn test_delete_credential_not_found() {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        // Deleting non-existent succeeds silently (idempotent operation)
        let result = storage.delete_credential("provii.cred.nonexistent");
        // MockStorage.delete() always succeeds, even for non-existent keys
        assert!(result.is_ok());
    }

    #[test]
    fn test_delete_sandbox_credentials_all() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred1 = create_test_credential();
        let mut cred2 = create_test_credential();
        cred2.c_bytes = [2u8; 32];

        storage.store_credential(&cred1, Some("sandbox"))?;
        storage.store_credential(&cred2, Some("sandbox"))?;

        let count = storage.delete_sandbox_credentials()?;
        assert!(count > 0);
        Ok(())
    }

    #[test]
    fn test_delete_sandbox_preserves_primary() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred1 = create_test_credential();
        let mut cred2 = create_test_credential();
        cred2.c_bytes = [2u8; 32];

        storage.store_credential(&cred1, None)?;
        storage.store_credential(&cred2, Some("sandbox"))?;

        storage.delete_sandbox_credentials()?;

        let credentials = storage.list_credentials()?;
        // Primary should remain
        assert!(credentials
            .iter()
            .any(|c| !c.issuer_name.contains("Sandbox")));
        Ok(())
    }

    #[test]
    fn test_delete_sandbox_count() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        storage.store_credential(&cred, Some("sandbox"))?;

        let count = storage.delete_sandbox_credentials()?;
        assert!(count >= 1);
        Ok(())
    }

    // ========================================================================
    // Storage State Tests (4 tests)
    // ========================================================================

    #[test]
    fn test_storage_not_initialized() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();

        let cred = create_test_credential();
        let result = storage.store_credential(&cred, None);

        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        assert!(err_val.to_string().contains("not initialised"));
        Ok(())
    }

    #[test]
    fn test_storage_is_available_true() {
        let storage = Storage::new();
        assert!(!storage.is_available());

        storage.set_backend(MockStorage::new());
        assert!(storage.is_available());
    }

    #[test]
    fn test_storage_is_available_false() {
        let storage = Storage::new();
        assert!(!storage.is_available());
    }

    #[test]
    fn test_has_credential_true_false() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        assert!(!storage.has_credential()?);

        let cred = create_test_credential();
        storage.store_credential(&cred, None)?;

        assert!(storage.has_credential()?);
        Ok(())
    }

    // ========================================================================
    // Error Handling Tests (4 tests)
    // ========================================================================

    #[test]
    fn test_storage_error_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let result = storage.get_credential("nonexistent");
        assert!(result.is_ok());
        assert!(result?.is_none());
        Ok(())
    }

    #[test]
    fn test_storage_error_serialization() {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let result = storage.store_credential(&cred, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_storage_error_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        let backend = MockStorage::new();
        storage.set_backend(backend.clone());

        // Manually insert bad data
        backend.store(
            "provii.cred.bad",
            b"not json",
            provii_mobile_sdk_platform_storage::BiometricRequirement::None,
        )?;

        let result = storage.get_credential("provii.cred.bad");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_credential_namespace_from_label() {
        let ns_primary = CredentialNamespace::from_label(None);
        let ns_sandbox = CredentialNamespace::from_label(Some("sandbox"));
        let ns_custom = CredentialNamespace::from_label(Some("custom"));

        assert_eq!(ns_primary, CredentialNamespace::Primary);
        assert_eq!(ns_sandbox, CredentialNamespace::Sandbox);
        assert_eq!(ns_custom, CredentialNamespace::Primary);
    }

    // ========================================================================
    // Primary + Managed Slot Tests
    // ========================================================================

    #[test]
    fn test_store_managed_slot_primary() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let key = storage.store_credential_with_slot(
            &cred,
            None,
            CredentialSlot::Managed { index: 0 },
            Some("Child Alice"),
        )?;

        assert!(key.starts_with("provii.cred.managed.0."));
        Ok(())
    }

    #[test]
    fn test_store_managed_slot_sandbox() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let key = storage.store_credential_with_slot(
            &cred,
            Some("sandbox"),
            CredentialSlot::Managed { index: 2 },
            Some("Child Bob"),
        )?;

        assert!(key.starts_with("provii.sandbox.cred.managed.2."));
        Ok(())
    }

    #[test]
    fn test_slot_isolation_primary_and_managed() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred1 = create_test_credential();
        let mut cred2 = create_test_credential();
        cred2.c_bytes = [5u8; 32];

        // Store in primary slot
        let primary_key =
            storage.store_credential_with_slot(&cred1, None, CredentialSlot::Primary, None)?;
        // Store in managed slot 0
        let managed_key = storage.store_credential_with_slot(
            &cred2,
            None,
            CredentialSlot::Managed { index: 0 },
            Some("Child"),
        )?;

        // Both should exist
        assert!(storage.get_credential(&primary_key)?.is_some());
        assert!(storage.get_credential(&managed_key)?.is_some());

        // List should show both
        let credentials = storage.list_credentials()?;
        assert_eq!(credentials.len(), 2);

        // Verify types
        let primary_cred = credentials
            .iter()
            .find(|c| c.credential_type == "primary")
            .ok_or("expected primary credential")?;
        let managed_cred = credentials
            .iter()
            .find(|c| c.credential_type == "managed")
            .ok_or("expected managed credential")?;
        assert!(primary_cred.id.starts_with(PRIMARY_CRED_PRIMARY_PREFIX));
        assert!(managed_cred.id.starts_with("provii.cred.managed.0."));
        assert_eq!(managed_cred.nickname, Some("Child".to_string()));
        assert_eq!(managed_cred.managed_index, Some(0));
        Ok(())
    }

    #[test]
    fn test_store_primary_does_not_delete_managed() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred_child = create_test_credential();
        let mut cred_adult = create_test_credential();
        cred_adult.c_bytes = [9u8; 32];

        // Store managed credential first
        let managed_key = storage.store_credential_with_slot(
            &cred_child,
            None,
            CredentialSlot::Managed { index: 0 },
            Some("Child"),
        )?;

        // Store primary credential
        let primary_key =
            storage.store_credential_with_slot(&cred_adult, None, CredentialSlot::Primary, None)?;

        // Managed credential should still exist
        assert!(storage.get_credential(&managed_key)?.is_some());
        assert!(storage.get_credential(&primary_key)?.is_some());
        Ok(())
    }

    #[test]
    fn test_store_managed_replaces_same_index() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred1 = create_test_credential();
        let mut cred2 = create_test_credential();
        cred2.c_bytes = [7u8; 32];

        // Store first managed credential at index 0
        storage.store_credential_with_slot(
            &cred1,
            None,
            CredentialSlot::Managed { index: 0 },
            Some("Alice"),
        )?;

        // Store second managed credential at same index (should replace first)
        storage.store_credential_with_slot(
            &cred2,
            None,
            CredentialSlot::Managed { index: 0 },
            Some("Bob"),
        )?;

        // Should have exactly 1 managed credential
        let creds = storage.list_credentials()?;
        let managed_creds: Vec<_> = creds
            .iter()
            .filter(|c| c.credential_type == "managed")
            .collect();
        assert_eq!(managed_creds.len(), 1);
        assert_eq!(managed_creds[0].nickname, Some("Bob".to_string()));
        Ok(())
    }

    #[test]
    fn test_multiple_managed_slots() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        // Store primary + 3 managed
        let mut cred0 = create_test_credential();
        cred0.c_bytes = [10u8; 32];
        let mut cred1 = create_test_credential();
        cred1.c_bytes = [11u8; 32];
        let mut cred2 = create_test_credential();
        cred2.c_bytes = [12u8; 32];
        let mut cred3 = create_test_credential();
        cred3.c_bytes = [13u8; 32];

        storage.store_credential_with_slot(&cred0, None, CredentialSlot::Primary, None)?;
        storage.store_credential_with_slot(
            &cred1,
            None,
            CredentialSlot::Managed { index: 0 },
            Some("Alice"),
        )?;
        storage.store_credential_with_slot(
            &cred2,
            None,
            CredentialSlot::Managed { index: 1 },
            Some("Bob"),
        )?;
        storage.store_credential_with_slot(
            &cred3,
            None,
            CredentialSlot::Managed { index: 2 },
            Some("Carol"),
        )?;

        let creds = storage.list_credentials()?;
        assert_eq!(creds.len(), 4);

        let managed: Vec<_> = creds
            .iter()
            .filter(|c| c.credential_type == "managed")
            .collect();
        assert_eq!(managed.len(), 3);
        Ok(())
    }

    #[test]
    fn test_delete_sandbox_preserves_all_primary_slots() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let mut cred1 = create_test_credential();
        cred1.c_bytes = [20u8; 32];
        let mut cred2 = create_test_credential();
        cred2.c_bytes = [21u8; 32];
        let mut cred3 = create_test_credential();
        cred3.c_bytes = [22u8; 32];

        // Store primary + managed credential
        storage.store_credential_with_slot(&cred1, None, CredentialSlot::Primary, None)?;
        storage.store_credential_with_slot(
            &cred2,
            None,
            CredentialSlot::Managed { index: 0 },
            Some("Child"),
        )?;
        // Store sandbox primary
        storage.store_credential_with_slot(
            &cred3,
            Some("sandbox"),
            CredentialSlot::Primary,
            None,
        )?;

        // Delete sandbox
        storage.delete_sandbox_credentials()?;

        // Primary + managed should remain
        let creds = storage.list_credentials()?;
        assert_eq!(creds.len(), 2);
        assert!(creds.iter().all(|c| !c.issuer_name.contains("Sandbox")));
        Ok(())
    }

    #[test]
    fn test_get_credential_for_slot_primary_and_managed() -> Result<(), Box<dyn std::error::Error>>
    {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let mut cred_primary = create_test_credential();
        cred_primary.c_bytes = [30u8; 32];
        let mut cred_managed = create_test_credential();
        cred_managed.c_bytes = [31u8; 32];

        storage.store_credential_with_slot(&cred_primary, None, CredentialSlot::Primary, None)?;
        storage.store_credential_with_slot(
            &cred_managed,
            None,
            CredentialSlot::Managed { index: 0 },
            Some("Child"),
        )?;

        let primary = storage
            .get_credential_for_slot(CredentialNamespace::Primary, CredentialSlot::Primary)?;
        assert!(primary.is_some());
        assert_eq!(primary.ok_or("expected primary")?.1.c_bytes, [30u8; 32]);

        let managed = storage.get_credential_for_slot(
            CredentialNamespace::Primary,
            CredentialSlot::Managed { index: 0 },
        )?;
        assert!(managed.is_some());
        assert_eq!(managed.ok_or("expected managed")?.1.c_bytes, [31u8; 32]);

        // No sandbox credentials
        let sandbox = storage
            .get_credential_for_slot(CredentialNamespace::Sandbox, CredentialSlot::Primary)?;
        assert!(sandbox.is_none());
        Ok(())
    }

    #[test]
    fn test_secrets_roundtrip_managed_slot() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let cred_id = storage.store_credential_with_slot(
            &cred,
            None,
            CredentialSlot::Managed { index: 0 },
            Some("Child"),
        )?;

        let secrets = create_test_secrets();
        storage.store_credential_secrets(&cred_id, &secrets)?;

        let loaded = storage.load_credential_secrets(&cred_id)?;
        assert!(loaded.is_some());
        assert_eq!(loaded.ok_or("expected secrets")?.dob_days, secrets.dob_days);
        Ok(())
    }

    #[test]
    fn test_slot_from_credential_id() {
        let (ns, slot) = CredentialNamespace::from_credential_id("provii.cred.primary.abc123");
        assert_eq!(ns, CredentialNamespace::Primary);
        assert_eq!(slot, CredentialSlot::Primary);

        let (ns, slot) = CredentialNamespace::from_credential_id("provii.cred.managed.2.abc123");
        assert_eq!(ns, CredentialNamespace::Primary);
        assert_eq!(slot, CredentialSlot::Managed { index: 2 });

        let (ns, slot) =
            CredentialNamespace::from_credential_id("provii.sandbox.cred.primary.abc123");
        assert_eq!(ns, CredentialNamespace::Sandbox);
        assert_eq!(slot, CredentialSlot::Primary);

        let (ns, slot) =
            CredentialNamespace::from_credential_id("provii.sandbox.cred.managed.4.abc123");
        assert_eq!(ns, CredentialNamespace::Sandbox);
        assert_eq!(slot, CredentialSlot::Managed { index: 4 });
    }

    #[test]
    fn test_is_credential_key_fn() {
        assert!(is_credential_key("provii.cred.primary.abc123"));
        assert!(is_credential_key("provii.cred.managed.0.abc123"));
        assert!(is_credential_key("provii.sandbox.cred.primary.abc123"));
        assert!(is_credential_key("provii.sandbox.cred.managed.3.abc123"));
        // Secrets keys should NOT match
        assert!(!is_credential_key("provii.credsec.primary.abc123"));
        assert!(!is_credential_key(
            "provii.sandbox.credsec.managed.0.abc123"
        ));
    }

    #[test]
    fn test_list_credentials_returns_type_info() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        storage.store_credential_with_slot(
            &cred,
            None,
            CredentialSlot::Managed { index: 1 },
            Some("Test Child"),
        )?;

        let creds = storage.list_credentials()?;
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].credential_type, "managed");
        assert_eq!(creds[0].nickname, Some("Test Child".to_string()));
        assert_eq!(creds[0].managed_index, Some(1));
        Ok(())
    }

    // ========================================================================
    // next_available_managed_index Tests
    // ========================================================================

    #[test]
    fn test_next_available_managed_index_empty() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let idx = storage.next_available_managed_index(CredentialNamespace::Primary)?;
        assert_eq!(idx, 0);
        Ok(())
    }

    #[test]
    fn test_next_available_managed_index_after_one() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        storage.store_credential_with_slot(
            &cred,
            None,
            CredentialSlot::Managed { index: 0 },
            Some("Alice"),
        )?;

        let idx = storage.next_available_managed_index(CredentialNamespace::Primary)?;
        assert_eq!(idx, 1);
        Ok(())
    }

    #[test]
    fn test_next_available_managed_index_with_gap() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let mut cred0 = create_test_credential();
        cred0.c_bytes = [50u8; 32];
        let mut cred2 = create_test_credential();
        cred2.c_bytes = [52u8; 32];

        // Occupy index 0 and 2, leaving 1 free
        storage.store_credential_with_slot(
            &cred0,
            None,
            CredentialSlot::Managed { index: 0 },
            Some("Alice"),
        )?;
        storage.store_credential_with_slot(
            &cred2,
            None,
            CredentialSlot::Managed { index: 2 },
            Some("Carol"),
        )?;

        let idx = storage.next_available_managed_index(CredentialNamespace::Primary)?;
        assert_eq!(idx, 1);
        Ok(())
    }

    #[test]
    fn test_next_available_managed_index_all_full() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        // Fill all 15 managed slots
        for i in 0..15u8 {
            let mut cred = create_test_credential();
            cred.c_bytes = [40 + i; 32];
            storage.store_credential_with_slot(
                &cred,
                None,
                CredentialSlot::Managed { index: i },
                Some(&format!("Child {}", i)),
            )?;
        }

        let result = storage.next_available_managed_index(CredentialNamespace::Primary);
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        assert!(err_val.to_string().contains("full"));
        Ok(())
    }

    // ========================================================================
    // update_credential_nickname Tests
    // ========================================================================

    #[test]
    fn test_update_nickname_basic() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let cred_id = storage.store_credential_with_slot(
            &cred,
            None,
            CredentialSlot::Managed { index: 0 },
            Some("Alice"),
        )?;

        // Rename to "Bob"
        storage.update_credential_nickname(&cred_id, Some("Bob"))?;

        let creds = storage.list_credentials()?;
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].nickname, Some("Bob".to_string()));
        Ok(())
    }

    #[test]
    fn test_update_nickname_to_none() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let cred_id = storage.store_credential_with_slot(
            &cred,
            None,
            CredentialSlot::Managed { index: 0 },
            Some("Alice"),
        )?;

        // Clear nickname
        storage.update_credential_nickname(&cred_id, None)?;

        let creds = storage.list_credentials()?;
        assert_eq!(creds[0].nickname, None);
        Ok(())
    }

    #[test]
    fn test_update_nickname_preserves_secrets() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let cred_id = storage.store_credential_with_slot(
            &cred,
            None,
            CredentialSlot::Managed { index: 0 },
            Some("Alice"),
        )?;

        let secrets = create_test_secrets();
        storage.store_credential_secrets(&cred_id, &secrets)?;

        // Rename
        storage.update_credential_nickname(&cred_id, Some("Bob"))?;

        // Verify secrets are still intact
        let loaded_secrets = storage.load_credential_secrets(&cred_id)?;
        assert!(loaded_secrets.is_some());
        assert_eq!(
            loaded_secrets.ok_or("expected secrets")?.dob_days,
            secrets.dob_days
        );
        Ok(())
    }

    #[test]
    fn test_update_nickname_preserves_other_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let cred_id = storage.store_credential_with_slot(
            &cred,
            None,
            CredentialSlot::Managed { index: 1 },
            Some("Alice"),
        )?;

        // Rename
        storage.update_credential_nickname(&cred_id, Some("Bob"))?;

        // Verify other metadata preserved
        let creds = storage.list_credentials()?;
        assert_eq!(creds[0].credential_type, "managed");
        assert_eq!(creds[0].managed_index, Some(1));
        assert_eq!(creds[0].nickname, Some("Bob".to_string()));
        Ok(())
    }

    #[test]
    fn test_update_nickname_not_found() {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let result = storage.update_credential_nickname("provii.cred.nonexistent", Some("Bob"));
        assert!(result.is_err());
    }

    // ========================================================================
    // credential_secrets_exist Tests
    // ========================================================================

    #[test]
    fn test_credential_secrets_exist_true() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let cred_id = storage.store_credential(&cred, None)?;
        storage.store_credential_secrets(&cred_id, &create_test_secrets())?;

        assert!(storage.credential_secrets_exist(&cred_id)?);
        Ok(())
    }

    #[test]
    fn test_credential_secrets_exist_false_no_secrets() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let cred_id = storage.store_credential(&cred, None)?;

        assert!(!storage.credential_secrets_exist(&cred_id)?);
        Ok(())
    }

    #[test]
    fn test_credential_secrets_exist_false_nonexistent() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        assert!(!storage.credential_secrets_exist("provii.cred.primary.nonexistent")?);
        Ok(())
    }

    #[test]
    fn test_credential_secrets_exist_sandbox() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let cred_id = storage.store_credential(&cred, Some("sandbox"))?;
        storage.store_credential_secrets(&cred_id, &create_test_secrets())?;

        assert!(storage.credential_secrets_exist(&cred_id)?);
        Ok(())
    }

    #[test]
    fn test_credential_secrets_exist_managed_slot() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let cred_id = storage.store_credential_with_slot(
            &cred,
            None,
            CredentialSlot::Managed { index: 2 },
            Some("Child"),
        )?;
        storage.store_credential_secrets(&cred_id, &create_test_secrets())?;

        assert!(storage.credential_secrets_exist(&cred_id)?);
        Ok(())
    }

    #[test]
    fn test_credential_secrets_exist_after_delete() -> Result<(), Box<dyn std::error::Error>> {
        let storage = Storage::new();
        storage.set_backend(MockStorage::new());

        let cred = create_test_credential();
        let cred_id = storage.store_credential(&cred, None)?;
        storage.store_credential_secrets(&cred_id, &create_test_secrets())?;

        assert!(storage.credential_secrets_exist(&cred_id)?);

        storage.delete_credential(&cred_id)?;

        assert!(!storage.credential_secrets_exist(&cred_id)?);
        Ok(())
    }

    #[test]
    fn test_credential_secrets_exist_not_initialized() {
        let storage = Storage::new();

        let result = storage.credential_secrets_exist("provii.cred.primary.abc");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not initialised"));
    }
}
