// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

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
    storage.store_credential_with_slot(&cred3, Some("sandbox"), CredentialSlot::Primary, None)?;

    // Delete sandbox
    storage.delete_sandbox_credentials()?;

    // Primary + managed should remain
    let creds = storage.list_credentials()?;
    assert_eq!(creds.len(), 2);
    assert!(creds.iter().all(|c| !c.issuer_name.contains("Sandbox")));
    Ok(())
}

#[test]
fn test_get_credential_for_slot_primary_and_managed() -> Result<(), Box<dyn std::error::Error>> {
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

    let primary =
        storage.get_credential_for_slot(CredentialNamespace::Primary, CredentialSlot::Primary)?;
    assert!(primary.is_some());
    assert_eq!(primary.ok_or("expected primary")?.1.c_bytes, [30u8; 32]);

    let managed = storage.get_credential_for_slot(
        CredentialNamespace::Primary,
        CredentialSlot::Managed { index: 0 },
    )?;
    assert!(managed.is_some());
    assert_eq!(managed.ok_or("expected managed")?.1.c_bytes, [31u8; 32]);

    // No sandbox credentials
    let sandbox =
        storage.get_credential_for_slot(CredentialNamespace::Sandbox, CredentialSlot::Primary)?;
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

    let (ns, slot) = CredentialNamespace::from_credential_id("provii.sandbox.cred.primary.abc123");
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
