// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust
//!
//! Storage abstraction for wallet credentials.
//!
//! This module provides the [`SecureStore`] trait, an in-memory implementation
//! for testing, and [`helpers`] for common credential queries (find best match,
//! count active credentials, cleanup expired, filter by schema).
//!
//! # Security
//!
//! Platform storage implementations (iOS Keychain, Android Keystore) provide encryption
//! at rest. Secret fields are zeroised on drop so they do not linger in process memory.

#![forbid(unsafe_code)]

use crate::types::{CredentialMetadata, CredentialV2};
use thiserror::Error;

/// Test-only storage format that preserves all credential fields, including secrets.
///
/// [`CredentialV2`] uses `#[serde(skip)]` on `dob_days` and `r_bits` to prevent
/// accidental leakage through JSON or other serde-based formats. Because postcard
/// also uses serde, this separate struct explicitly serialises every field so that
/// secrets survive a store/load round-trip (required for proof generation).
///
/// Production storage is handled by platform keystores (iOS Keychain, Android
/// Keystore) which provide their own encryption at rest. This type exists only
/// for `MemoryStore` in tests.
#[cfg(test)]
mod storage_data {
    use super::*;
    use serde::{Deserialize, Serialize};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    #[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
    pub(crate) struct CredentialStorageData {
        #[zeroize(skip)]
        pub v: u8,
        #[zeroize(skip)]
        pub kid: String,
        #[zeroize(skip)]
        pub issuer_vk: [u8; 32],
        /// RedJubjub signature as `Vec<u8>` (64 bytes) -- serde doesn't support `[u8; 64]`
        #[zeroize(skip)]
        pub sig_rj: Vec<u8>,
        #[zeroize(skip)]
        pub c_bytes: [u8; 32],
        #[zeroize(skip)]
        pub iat: u64,
        #[zeroize(skip)]
        pub exp: u64,
        #[zeroize(skip)]
        pub schema: String,
        /// Secret: date of birth as days since epoch
        pub dob_days: Option<i32>,
        /// Secret: randomness bits used in the Pedersen commitment
        pub r_bits: Option<Vec<bool>>,
    }

    impl CredentialStorageData {
        /// Convert a [`CredentialV2`] into the storage format, capturing secret fields
        /// (`dob_days`, `r_bits`) that the credential's serde impl would otherwise skip.
        pub fn from_credential(cred: &CredentialV2) -> Self {
            Self {
                v: cred.v,
                kid: cred.kid.clone(),
                issuer_vk: cred.issuer_vk,
                sig_rj: cred.sig_rj.to_vec(),
                c_bytes: cred.c_bytes,
                iat: cred.iat,
                exp: cred.exp,
                schema: cred.schema.clone(),
                dob_days: cred.dob_days,
                r_bits: cred.r_bits.clone(),
            }
        }

        /// Convert the storage format back into a [`CredentialV2`], restoring secrets.
        ///
        /// # Errors
        ///
        /// Returns [`StorageError::SerializationError`] if `sig_rj` is not exactly
        /// 64 bytes, which indicates corrupted storage data.
        pub fn into_credential(mut self) -> Result<CredentialV2, StorageError> {
            let sig_rj: [u8; 64] = self.sig_rj.clone().try_into().map_err(|_| {
                StorageError::SerializationError(format!(
                    "sig_rj must be exactly 64 bytes, got {}",
                    self.sig_rj.len()
                ))
            })?;

            Ok(CredentialV2 {
                v: self.v,
                kid: std::mem::take(&mut self.kid),
                issuer_vk: self.issuer_vk,
                sig_rj,
                c_bytes: self.c_bytes,
                iat: self.iat,
                exp: self.exp,
                schema: std::mem::take(&mut self.schema),
                dob_days: self.dob_days.take(),
                r_bits: self.r_bits.take(),
            })
            // self drops here: ZeroizeOnDrop clears remaining fields
        }
    }
}

#[cfg(test)]
pub(crate) use storage_data::CredentialStorageData;
#[cfg(test)]
use zeroize::Zeroize;

/// Errors returned by [`SecureStore`] operations.
///
/// All variants carry enough context for callers to distinguish between
/// transient failures (`OperationFailed`), missing data (`NotFound`),
/// capacity limits (`StorageFull`), and data-format problems
/// (`SerializationError`). `AlreadyExists` is reserved for backends
/// that enforce uniqueness at the storage layer.
#[derive(Debug, Error)]
pub enum StorageError {
    /// A platform-level storage operation failed (I/O, keychain, keystore, HSM).
    #[error("storage operation failed: {0}")]
    OperationFailed(String),

    /// The requested credential does not exist in the store.
    #[error("credential not found")]
    NotFound,

    /// A credential with the same identifier already exists.
    #[error("credential already exists")]
    AlreadyExists,

    /// The store has reached its configured capacity limit.
    #[error("storage is full")]
    StorageFull,

    /// Postcard serialisation or deserialisation failed.
    #[error("serialisation error: {0}")]
    SerializationError(String),
}

/// Platform-agnostic secure storage for credentials and arbitrary byte blobs.
///
/// Implementations back onto a platform keystore (iOS Keychain, Android Keystore)
/// or, for testing, an in-memory map. Every method returns [`Result`] so that I/O
/// and serialisation failures propagate without panicking.
///
/// # Thread safety
///
/// All implementations must be `Send + Sync` so that the store can be shared
/// across async tasks and worker threads.
pub trait SecureStore: Send + Sync {
    /// Persist a credential together with its metadata.
    ///
    /// If a credential with the same `metadata.id` already exists, it is
    /// overwritten. Returns [`StorageError::StorageFull`] when the backend
    /// has reached its capacity limit.
    fn put_credential(
        &self,
        cred: &CredentialV2,
        metadata: &CredentialMetadata,
    ) -> Result<(), StorageError>;

    /// Retrieve a credential by its identifier, or `None` if it does not exist.
    fn get_credential(&self, id: &str) -> Result<Option<CredentialV2>, StorageError>;

    /// Delete a credential by its identifier.
    ///
    /// Returns `true` if the credential existed and was removed, `false` if it
    /// was not present.
    fn delete_credential(&self, id: &str) -> Result<bool, StorageError>;

    /// List metadata for every credential currently held in the store.
    fn list_credentials(&self) -> Result<Vec<CredentialMetadata>, StorageError>;

    /// Read raw bytes by key (generic key-value access).
    fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError>;

    /// Write raw bytes by key (generic key-value access).
    fn put_bytes(&self, key: &str, value: &[u8]) -> Result<(), StorageError>;

    /// Delete a raw key. Returns `true` if the key existed.
    fn delete(&self, key: &str) -> Result<bool, StorageError>;

    /// Remove all stored data. Use with caution: this is irreversible.
    fn clear_all(&self) -> Result<(), StorageError>;
}

/// In-memory [`SecureStore`] backed by `BTreeMap`, intended for tests and
/// development only.
///
/// Credentials are serialised to postcard bytes and stored alongside their
/// metadata. A configurable `max_credentials` cap prevents unbounded growth
/// during fuzz and property-based tests. The default capacity is 32.
///
/// Serialised credential bytes are zeroised on deletion and on
/// [`clear_all`](SecureStore::clear_all).
#[cfg(test)]
pub struct MemoryStore {
    data: std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>>,
    metadata:
        std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, CredentialMetadata>>>,
    max_credentials: usize,
}

#[cfg(test)]
impl MemoryStore {
    /// Create a new in-memory store with the default capacity of 32 credentials.
    pub fn new() -> Self {
        use std::collections::BTreeMap;
        use std::sync::{Arc, Mutex};
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
            metadata: Arc::new(Mutex::new(BTreeMap::new())),
            max_credentials: 32,
        }
    }

    /// Create a new in-memory store limited to `max_credentials` entries.
    pub fn with_capacity(max_credentials: usize) -> Self {
        use std::collections::BTreeMap;
        use std::sync::{Arc, Mutex};
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
            metadata: Arc::new(Mutex::new(BTreeMap::new())),
            max_credentials,
        }
    }
}

#[cfg(test)]
impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl SecureStore for MemoryStore {
    fn put_credential(
        &self,
        cred: &CredentialV2,
        metadata: &CredentialMetadata,
    ) -> Result<(), StorageError> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| StorageError::OperationFailed("data mutex poisoned".into()))?;
        let mut meta_store = self
            .metadata
            .lock()
            .map_err(|_| StorageError::OperationFailed("metadata mutex poisoned".into()))?;

        // Check capacity
        if meta_store.len() >= self.max_credentials && !meta_store.contains_key(&metadata.id) {
            return Err(StorageError::StorageFull);
        }

        // Convert to storage format (captures secrets) and serialise with postcard
        let storage_data = CredentialStorageData::from_credential(cred);
        let cred_bytes = postcard::to_allocvec(&storage_data)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;

        // Store credential and metadata
        let key = format!("cred:{}", metadata.id);
        data.insert(key, cred_bytes);
        meta_store.insert(metadata.id.clone(), metadata.clone());

        Ok(())
    }

    fn get_credential(&self, id: &str) -> Result<Option<CredentialV2>, StorageError> {
        let data = self
            .data
            .lock()
            .map_err(|_| StorageError::OperationFailed("data mutex poisoned".into()))?;
        let key = format!("cred:{}", id);

        match data.get(&key) {
            Some(bytes) => {
                // Deserialise storage format and convert back to CredentialV2 (restores secrets)
                let storage_data: CredentialStorageData = postcard::from_bytes(bytes)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(storage_data.into_credential()?))
            }
            None => Ok(None),
        }
    }

    fn delete_credential(&self, id: &str) -> Result<bool, StorageError> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| StorageError::OperationFailed("data mutex poisoned".into()))?;
        let mut metadata = self
            .metadata
            .lock()
            .map_err(|_| StorageError::OperationFailed("metadata mutex poisoned".into()))?;

        let key = format!("cred:{}", id);
        let removed_data = if let Some(mut v) = data.remove(&key) {
            v.zeroize();
            true
        } else {
            false
        };
        let removed_meta = metadata.remove(id).is_some();

        Ok(removed_data || removed_meta)
    }

    fn list_credentials(&self) -> Result<Vec<CredentialMetadata>, StorageError> {
        let metadata = self
            .metadata
            .lock()
            .map_err(|_| StorageError::OperationFailed("metadata mutex poisoned".into()))?;
        Ok(metadata.values().cloned().collect())
    }

    fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let data = self
            .data
            .lock()
            .map_err(|_| StorageError::OperationFailed("data mutex poisoned".into()))?;
        Ok(data.get(key).cloned())
    }

    fn put_bytes(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| StorageError::OperationFailed("data mutex poisoned".into()))?;
        data.insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<bool, StorageError> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| StorageError::OperationFailed("data mutex poisoned".into()))?;
        if let Some(mut v) = data.remove(key) {
            v.zeroize();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn clear_all(&self) -> Result<(), StorageError> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| StorageError::OperationFailed("data mutex poisoned".into()))?;
        let mut metadata = self
            .metadata
            .lock()
            .map_err(|_| StorageError::OperationFailed("metadata mutex poisoned".into()))?;
        // Zeroize all serialised credential bytes before releasing memory
        for v in data.values_mut() {
            v.zeroize();
        }
        data.clear();
        metadata.clear();
        Ok(())
    }
}

/// Convenience functions for common credential queries and maintenance.
///
/// These operate on any [`SecureStore`] implementation and keep higher-level
/// logic (age-match selection, expiry cleanup) out of the trait itself.
pub mod helpers {
    use super::*;

    /// Return the first credential whose `dob_days` satisfies the given
    /// `cutoff_days` threshold, or `None` if no credential qualifies.
    ///
    /// When `is_under_age` is `false` (default), uses "old enough" semantics
    /// (`dob_days <= cutoff_days`). When `true`, uses "young enough" semantics
    /// (`dob_days >= cutoff_days`).
    pub fn find_best_credential(
        store: &dyn SecureStore,
        cutoff_days: i32,
        is_under_age: bool,
    ) -> Result<Option<CredentialV2>, StorageError> {
        let metadata_list = store.list_credentials()?;

        for meta in metadata_list {
            if let Some(cred) = store.get_credential(&meta.id)? {
                // Check if credential can satisfy the age requirement
                if let Some(dob_days) = cred.dob_days {
                    if crate::validate_age(dob_days, cutoff_days, is_under_age) {
                        return Ok(Some(cred));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Return the total number of credentials currently held in `store`.
    pub fn count_credentials(store: &dyn SecureStore) -> Result<usize, StorageError> {
        Ok(store.list_credentials()?.len())
    }

    /// Delete every credential whose `exp` timestamp is strictly less than
    /// `current_timestamp`. Returns the number of credentials removed.
    pub fn cleanup_expired(
        store: &dyn SecureStore,
        current_timestamp: u64,
    ) -> Result<usize, StorageError> {
        let metadata_list = store.list_credentials()?;
        let mut removed: usize = 0;

        for meta in metadata_list {
            if let Some(cred) = store.get_credential(&meta.id)? {
                if cred.exp < current_timestamp {
                    store.delete_credential(&meta.id)?;
                    removed = removed.saturating_add(1);
                }
            }
        }

        Ok(removed)
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

    fn create_test_credential(_id: &str, dob_days: Option<i32>, exp: u64) -> CredentialV2 {
        CredentialV2 {
            v: 2,
            kid: "test_issuer".to_string(),
            issuer_vk: [1u8; 32],
            sig_rj: [2u8; 64],
            c_bytes: [3u8; 32],
            iat: 1000000,
            exp,
            schema: "provii.age/0".to_string(),
            dob_days,
            r_bits: Some(vec![true, false]),
        }
    }

    fn create_test_metadata(id: &str) -> CredentialMetadata {
        CredentialMetadata {
            id: id.to_string(),
            label: Some(format!("Test Credential {}", id)),
            imported_at: 1600000000,
            issuer_name: Some("Test Issuer".to_string()),
        }
    }

    #[test]
    fn test_memory_store_new() -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryStore::new();
        let list = store.list_credentials()?;
        assert_eq!(list.len(), 0);
        Ok(())
    }

    #[test]
    fn test_memory_store_with_capacity() -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryStore::with_capacity(5);
        assert_eq!(store.max_credentials, 5);
        Ok(())
    }

    #[test]
    fn test_memory_store_default() -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryStore::default();
        let list = store.list_credentials()?;
        assert_eq!(list.len(), 0);
        Ok(())
    }

    #[test]
    fn test_put_and_get_credential() -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryStore::new();
        let cred = create_test_credential("cred1", Some(18000), 2000000);
        let metadata = create_test_metadata("cred1");

        // Put credential
        store.put_credential(&cred, &metadata)?;

        // Get credential
        let retrieved = store.get_credential("cred1")?;
        assert!(retrieved.is_some());
        let retrieved_cred = retrieved.ok_or("expected credential")?;
        assert_eq!(retrieved_cred.kid, cred.kid);
        // Secrets ARE preserved through postcard storage (required for proof generation)
        assert_eq!(
            retrieved_cred.dob_days,
            Some(18000),
            "dob_days must be preserved"
        );
        assert_eq!(
            retrieved_cred.r_bits,
            Some(vec![true, false]),
            "r_bits must be preserved"
        );
        Ok(())
    }

    #[test]
    fn test_get_nonexistent_credential() -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryStore::new();
        let result = store.get_credential("nonexistent")?;
        assert!(result.is_none());
        Ok(())
    }

    #[test]
    fn test_delete_credential() -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryStore::new();
        let cred = create_test_credential("cred1", Some(18000), 2000000);
        let metadata = create_test_metadata("cred1");

        store.put_credential(&cred, &metadata)?;

        // Delete
        let deleted = store.delete_credential("cred1")?;
        assert!(deleted);

        // Verify it's gone
        let result = store.get_credential("cred1")?;
        assert!(result.is_none());
        Ok(())
    }

    #[test]
    fn test_delete_nonexistent_credential() -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryStore::new();
        let deleted = store.delete_credential("nonexistent")?;
        assert!(!deleted);
        Ok(())
    }

    #[test]
    fn test_list_credentials() -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryStore::new();

        // Add multiple credentials
        for i in 1..=3 {
            let id = format!("cred{}", i);
            let cred = create_test_credential(&id, Some(18000 + i), 2000000);
            let metadata = create_test_metadata(&id);
            store.put_credential(&cred, &metadata)?;
        }

        let list = store.list_credentials()?;
        assert_eq!(list.len(), 3);
        Ok(())
    }

    #[test]
    fn test_storage_capacity_limit() -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryStore::with_capacity(2);

        // Add 2 credentials (at limit)
        for i in 1..=2 {
            let id = format!("cred{}", i);
            let cred = create_test_credential(&id, Some(18000), 2000000);
            let metadata = create_test_metadata(&id);
            store.put_credential(&cred, &metadata)?;
        }

        // Try to add a third (should fail)
        let cred3 = create_test_credential("cred3", Some(18000), 2000000);
        let metadata3 = create_test_metadata("cred3");
        let result = store.put_credential(&cred3, &metadata3);

        assert!(result.is_err());
        match result {
            Err(StorageError::StorageFull) => {}
            _ => panic!("Expected StorageFull error"),
        }
        Ok(())
    }

    #[test]
    fn test_update_existing_credential() -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryStore::new();
        let cred = create_test_credential("cred1", Some(18000), 2000000);
        let metadata = create_test_metadata("cred1");

        // Put initial
        store.put_credential(&cred, &metadata)?;

        // Update with modified credential (same ID)
        let updated_cred = create_test_credential("cred1", Some(19000), 3000000);
        store.put_credential(&updated_cred, &metadata)?;

        // Verify update - all fields including secrets should be preserved
        let retrieved = store.get_credential("cred1")?.ok_or("expected Some")?;
        assert_eq!(
            retrieved.dob_days,
            Some(19000),
            "dob_days must survive storage"
        );
        assert_eq!(retrieved.exp, 3000000);
        Ok(())
    }

    #[test]
    fn test_put_and_get_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryStore::new();
        let data = b"test data";

        // Put bytes
        store.put_bytes("test_key", data)?;

        // Get bytes
        let retrieved = store.get_bytes("test_key")?;
        assert_eq!(retrieved, Some(data.to_vec()));
        Ok(())
    }

    #[test]
    fn test_get_nonexistent_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryStore::new();
        let result = store.get_bytes("nonexistent")?;
        assert!(result.is_none());
        Ok(())
    }

    #[test]
    fn test_delete_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryStore::new();
        let data = b"test data";

        store.put_bytes("test_key", data)?;

        // Delete
        let deleted = store.delete("test_key")?;
        assert!(deleted);

        // Verify it's gone
        let result = store.get_bytes("test_key")?;
        assert!(result.is_none());
        Ok(())
    }

    #[test]
    fn test_clear_all() -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryStore::new();

        // Add credentials
        for i in 1..=3 {
            let id = format!("cred{}", i);
            let cred = create_test_credential(&id, Some(18000), 2000000);
            let metadata = create_test_metadata(&id);
            store.put_credential(&cred, &metadata)?;
        }

        // Add raw bytes
        store.put_bytes("key1", b"data1")?;

        // Clear all
        store.clear_all()?;

        // Verify everything is gone
        assert_eq!(store.list_credentials()?.len(), 0);
        assert!(store.get_bytes("key1")?.is_none());
        Ok(())
    }

    #[test]
    fn test_helpers_find_best_credential_secrets_preserved(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Postcard storage preserves secrets (dob_days, r_bits) needed for proof generation
        let store = MemoryStore::new();

        // Add credentials with different DOB days
        let cred1 = create_test_credential("cred1", Some(17000), 2000000);
        let cred2 = create_test_credential("cred2", Some(19000), 2000000);

        store.put_credential(&cred1, &create_test_metadata("cred1"))?;
        store.put_credential(&cred2, &create_test_metadata("cred2"))?;

        // Secrets preserved through postcard storage, so find_best_credential works
        let result = helpers::find_best_credential(&store, 18500, false)?;
        assert!(
            result.is_some(),
            "dob_days stored, credential should be found"
        );
        // cred1 has dob_days=17000 which is <= 18500 cutoff
        assert_eq!(result.ok_or("expected credential")?.dob_days, Some(17000));
        Ok(())
    }

    #[test]
    fn test_helpers_find_best_credential_none_satisfy() -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryStore::new();

        // Add credential that's too young
        let cred = create_test_credential("cred1", Some(19000), 2000000);
        store.put_credential(&cred, &create_test_metadata("cred1"))?;

        // Try to find credential for cutoff that's too old
        let result = helpers::find_best_credential(&store, 18000, false)?;
        assert!(result.is_none());
        Ok(())
    }

    #[test]
    fn test_helpers_count_credentials() -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryStore::new();

        // Initially empty
        let count = helpers::count_credentials(&store)?;
        assert_eq!(count, 0);

        // Add some credentials
        for i in 1..=5 {
            let id = format!("cred{}", i);
            let cred = create_test_credential(&id, Some(18000), 2000000);
            store.put_credential(&cred, &create_test_metadata(&id))?;
        }

        let count = helpers::count_credentials(&store)?;
        assert_eq!(count, 5);
        Ok(())
    }

    #[test]
    fn test_helpers_cleanup_expired() -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryStore::new();
        // Unix timestamp in seconds (mid-2027). Previous value (1500000) was
        // only ~17 days after the epoch, which is not a plausible timestamp.
        let current_time = 1_800_000_000;

        // Add mix of expired and valid credentials
        let expired1 = create_test_credential("exp1", Some(18000), current_time - 1000); // Expired
        let expired2 = create_test_credential("exp2", Some(18000), current_time - 500); // Expired
        let valid1 = create_test_credential("valid1", Some(18000), current_time + 1000); // Valid
        let valid2 = create_test_credential("valid2", Some(18000), current_time + 5000); // Valid

        store.put_credential(&expired1, &create_test_metadata("exp1"))?;
        store.put_credential(&expired2, &create_test_metadata("exp2"))?;
        store.put_credential(&valid1, &create_test_metadata("valid1"))?;
        store.put_credential(&valid2, &create_test_metadata("valid2"))?;

        // Cleanup expired
        let removed = helpers::cleanup_expired(&store, current_time)?;
        assert_eq!(removed, 2);

        // Verify only valid credentials remain
        let remaining = store.list_credentials()?;
        assert_eq!(remaining.len(), 2);
        Ok(())
    }

    #[test]
    fn test_credential_serialization_in_storage() -> Result<(), Box<dyn std::error::Error>> {
        // Bincode storage preserves all fields including secrets (required for proof generation)
        let store = MemoryStore::new();

        // Create credential with private fields
        let cred = create_test_credential("cred1", Some(18000), 2000000);
        let metadata = create_test_metadata("cred1");

        store.put_credential(&cred, &metadata)?;

        // Verify all fields including secrets ARE preserved through postcard
        let retrieved = store.get_credential("cred1")?.ok_or("expected Some")?;
        assert_eq!(retrieved.dob_days, Some(18000), "dob_days must be stored");
        assert_eq!(
            retrieved.r_bits,
            Some(vec![true, false]),
            "r_bits must be stored"
        );
        Ok(())
    }

    // Property-based tests
    mod proptests {
        use super::*;
        use proptest::prelude::*;
        use proptest::test_runner::TestCaseError;

        proptest! {
            // Property: Store and retrieve roundtrip preserves ALL data including secrets
            // Bincode storage preserves dob_days and r_bits (required for proof generation)
            #[test]
            fn prop_credential_roundtrip(
                id in "[a-z0-9]{5,20}",
                dob_days in any::<Option<i32>>(),
                exp in 1000000u64..3000000u64,
            ) {
                let store = MemoryStore::new();
                let cred = create_test_credential(&id, dob_days, exp);
                let metadata = create_test_metadata(&id);

                store.put_credential(&cred, &metadata).map_err(|e| TestCaseError::fail(format!("{e}")))?;

                let retrieved = store.get_credential(&id)
                    .map_err(|e| TestCaseError::fail(format!("{e}")))?
                    .ok_or_else(|| TestCaseError::fail("expected credential"))?;

                prop_assert_eq!(&retrieved.kid, &cred.kid);
                // Postcard storage preserves secrets
                prop_assert_eq!(&retrieved.dob_days, &dob_days);
                prop_assert_eq!(retrieved.exp, cred.exp);
            }

            // Property: Delete actually removes the credential
            #[test]
            fn prop_delete_removes_credential(
                id in "[a-z0-9]{5,20}",
            ) {
                let store = MemoryStore::new();
                let cred = create_test_credential(&id, Some(18000), 2000000);
                let metadata = create_test_metadata(&id);

                store.put_credential(&cred, &metadata).map_err(|e| TestCaseError::fail(format!("{e}")))?;
                store.delete_credential(&id).map_err(|e| TestCaseError::fail(format!("{e}")))?;

                let retrieved = store.get_credential(&id).map_err(|e| TestCaseError::fail(format!("{e}")))?;
                prop_assert!(retrieved.is_none());
            }

            // Property: put_bytes and get_bytes roundtrip
            #[test]
            fn prop_bytes_roundtrip(
                key in "[a-z0-9]{5,20}",
                value: Vec<u8>,
            ) {
                let store = MemoryStore::new();

                store.put_bytes(&key, &value).map_err(|e| TestCaseError::fail(format!("{e}")))?;
                let retrieved = store.get_bytes(&key)
                    .map_err(|e| TestCaseError::fail(format!("{e}")))?
                    .ok_or_else(|| TestCaseError::fail("expected value"))?;

                prop_assert_eq!(retrieved, value);
            }

            // Property: List credentials returns all stored credentials
            #[test]
            fn prop_list_returns_all_credentials(ids in prop::collection::vec("[a-z0-9]{5,10}", 1..10)) {
                let store = MemoryStore::new();
                let unique_ids: std::collections::HashSet<_> = ids.iter().collect();

                for id in &unique_ids {
                    let cred = create_test_credential(id, Some(18000), 2000000);
                    let metadata = create_test_metadata(id);
                    store.put_credential(&cred, &metadata).map_err(|e| TestCaseError::fail(format!("{e}")))?;
                }

                let list = store.list_credentials().map_err(|e| TestCaseError::fail(format!("{e}")))?;
                prop_assert_eq!(list.len(), unique_ids.len());
            }

            // Property: Storage respects capacity limits
            #[test]
            fn prop_storage_capacity_enforced(capacity in 1usize..5usize, extra in 1usize..3usize) {
                let store = MemoryStore::with_capacity(capacity);

                // Fill to capacity
                for i in 0..capacity {
                    let id = format!("cred{}", i);
                    let cred = create_test_credential(&id, Some(18000), 2000000);
                    let metadata = create_test_metadata(&id);
                    store.put_credential(&cred, &metadata).map_err(|e| TestCaseError::fail(format!("{e}")))?;
                }

                // Try to add more
                let overflow_id = format!("overflow{}", extra);
                let overflow_cred = create_test_credential(&overflow_id, Some(18000), 2000000);
                let overflow_metadata = create_test_metadata(&overflow_id);
                let result = store.put_credential(&overflow_cred, &overflow_metadata);

                prop_assert!(result.is_err());
            }

            // Property: Clear all removes everything
            #[test]
            fn prop_clear_all_removes_everything(ids in prop::collection::vec("[a-z0-9]{5,10}", 1..10)) {
                let store = MemoryStore::new();

                for id in &ids {
                    let cred = create_test_credential(id, Some(18000), 2000000);
                    let metadata = create_test_metadata(id);
                    store.put_credential(&cred, &metadata).ok();
                }

                store.clear_all().map_err(|e| TestCaseError::fail(format!("{e}")))?;

                let list = store.list_credentials().map_err(|e| TestCaseError::fail(format!("{e}")))?;
                prop_assert_eq!(list.len(), 0);
            }

            // Property: Update preserves credential under same ID (all fields including secrets)
            #[test]
            fn prop_update_preserves_id(
                id in "[a-z0-9]{5,20}",
                exp1 in 1000000u64..2000000u64,
                exp2 in 2000000u64..3000000u64,
            ) {
                let store = MemoryStore::new();
                let metadata = create_test_metadata(&id);

                // Store first version
                let cred1 = create_test_credential(&id, Some(10000), exp1);
                store.put_credential(&cred1, &metadata).map_err(|e| TestCaseError::fail(format!("{e}")))?;

                // Update with second version
                let cred2 = create_test_credential(&id, Some(20000), exp2);
                store.put_credential(&cred2, &metadata).map_err(|e| TestCaseError::fail(format!("{e}")))?;

                // Should have only one credential
                let list = store.list_credentials().map_err(|e| TestCaseError::fail(format!("{e}")))?;
                prop_assert_eq!(list.len(), 1);

                // Should be the updated version (all fields including secrets)
                let retrieved = store.get_credential(&id).map_err(|e| TestCaseError::fail(format!("{e}")))?.ok_or_else(|| TestCaseError::fail("expected Some"))?;
                // Postcard storage preserves secrets
                prop_assert_eq!(&retrieved.dob_days, &Some(20000i32));
                prop_assert_eq!(retrieved.exp, exp2);
            }

            // Property: Helpers - cleanup_expired removes only expired credentials
            #[test]
            fn prop_cleanup_expired_removes_only_expired(
                current_time in 1500000u64..2000000u64,
                expired_count in 0usize..5usize,
                valid_count in 0usize..5usize,
            ) {
                let store = MemoryStore::new();

                // Add expired credentials
                for i in 0..expired_count {
                    let id = format!("expired{}", i);
                    let exp_time = current_time - (i as u64 + 1) * 1000;
                    let cred = create_test_credential(&id, Some(18000), exp_time);
                    let metadata = create_test_metadata(&id);
                    store.put_credential(&cred, &metadata).map_err(|e| TestCaseError::fail(format!("{e}")))?;
                }

                // Add valid credentials
                for i in 0..valid_count {
                    let id = format!("valid{}", i);
                    let exp_time = current_time + (i as u64 + 1) * 1000;
                    let cred = create_test_credential(&id, Some(18000), exp_time);
                    let metadata = create_test_metadata(&id);
                    store.put_credential(&cred, &metadata).map_err(|e| TestCaseError::fail(format!("{e}")))?;
                }

                // Cleanup expired
                let removed = helpers::cleanup_expired(&store, current_time).map_err(|e| TestCaseError::fail(format!("{e}")))?;

                // Should have removed exactly expired_count credentials
                prop_assert_eq!(removed, expired_count);

                // Should have exactly valid_count credentials remaining
                let remaining = store.list_credentials().map_err(|e| TestCaseError::fail(format!("{e}")))?;
                prop_assert_eq!(remaining.len(), valid_count);
            }

            // Property: Helpers - count_credentials matches list length
            #[test]
            fn prop_count_matches_list_length(ids in prop::collection::vec("[a-z0-9]{5,10}", 0..10)) {
                let store = MemoryStore::new();
                let unique_ids: std::collections::HashSet<_> = ids.iter().collect();

                for id in &unique_ids {
                    let cred = create_test_credential(id, Some(18000), 2000000);
                    let metadata = create_test_metadata(id);
                    store.put_credential(&cred, &metadata).ok();
                }

                let count = helpers::count_credentials(&store).map_err(|e| TestCaseError::fail(format!("{e}")))?;
                let list_len = store.list_credentials().map_err(|e| TestCaseError::fail(format!("{e}")))?.len();

                prop_assert_eq!(count, list_len);
            }

            // Property: Delete is idempotent (can delete multiple times)
            #[test]
            fn prop_delete_idempotent(id in "[a-z0-9]{5,20}") {
                let store = MemoryStore::new();
                let cred = create_test_credential(&id, Some(18000), 2000000);
                let metadata = create_test_metadata(&id);

                store.put_credential(&cred, &metadata).map_err(|e| TestCaseError::fail(format!("{e}")))?;

                // First delete should return true
                let first = store.delete_credential(&id).map_err(|e| TestCaseError::fail(format!("{e}")))?;
                prop_assert!(first);

                // Second delete should return false (already deleted)
                let second = store.delete_credential(&id).map_err(|e| TestCaseError::fail(format!("{e}")))?;
                prop_assert!(!second);

                // Third delete should also return false
                let third = store.delete_credential(&id).map_err(|e| TestCaseError::fail(format!("{e}")))?;
                prop_assert!(!third);
            }
        }
    }

    // ============================================================
    // Comprehensive Tests
    // ============================================================

    mod comprehensive_tests {
        use super::*;
        use std::sync::Arc;
        use std::thread;

        // ============================================================
        // Section 1: StorageError tests (10 tests)
        // ============================================================

        #[test]
        fn test_storage_error_operation_failed_display() -> Result<(), Box<dyn std::error::Error>> {
            let err = StorageError::OperationFailed("disk error".to_string());
            let display = format!("{}", err);
            assert!(display.contains("storage operation failed"));
            assert!(display.contains("disk error"));
            Ok(())
        }

        #[test]
        fn test_storage_error_not_found_display() -> Result<(), Box<dyn std::error::Error>> {
            let err = StorageError::NotFound;
            let display = format!("{}", err);
            assert_eq!(display, "credential not found");
            Ok(())
        }

        #[test]
        fn test_storage_error_already_exists_display() -> Result<(), Box<dyn std::error::Error>> {
            let err = StorageError::AlreadyExists;
            let display = format!("{}", err);
            assert_eq!(display, "credential already exists");
            Ok(())
        }

        #[test]
        fn test_storage_error_storage_full_display() -> Result<(), Box<dyn std::error::Error>> {
            let err = StorageError::StorageFull;
            let display = format!("{}", err);
            assert_eq!(display, "storage is full");
            Ok(())
        }

        #[test]
        fn test_storage_error_serialization_display() -> Result<(), Box<dyn std::error::Error>> {
            let err = StorageError::SerializationError("invalid json".to_string());
            let display = format!("{}", err);
            assert!(display.contains("serialisation error"));
            assert!(display.contains("invalid json"));
            Ok(())
        }

        #[test]
        fn test_storage_error_debug_format() -> Result<(), Box<dyn std::error::Error>> {
            let err = StorageError::NotFound;
            let debug = format!("{:?}", err);
            assert!(debug.contains("NotFound"));
            Ok(())
        }

        #[test]
        fn test_storage_error_variants() -> Result<(), Box<dyn std::error::Error>> {
            // Test that all variants can be created
            let errors = [
                StorageError::OperationFailed("test".to_string()),
                StorageError::NotFound,
                StorageError::AlreadyExists,
                StorageError::StorageFull,
                StorageError::SerializationError("test".to_string()),
            ];

            assert_eq!(errors.len(), 5);
            Ok(())
        }

        #[test]
        fn test_storage_error_operation_failed_with_unicode(
        ) -> Result<(), Box<dyn std::error::Error>> {
            let err = StorageError::OperationFailed("エラー 错误 🔥".to_string());
            let display = format!("{}", err);
            assert!(display.contains("エラー"));
            assert!(display.contains("错误"));
            Ok(())
        }

        #[test]
        fn test_storage_error_serialization_empty_message() -> Result<(), Box<dyn std::error::Error>>
        {
            let err = StorageError::SerializationError("".to_string());
            let display = format!("{}", err);
            assert!(display.contains("serialisation error"));
            Ok(())
        }

        #[test]
        fn test_storage_error_operation_failed_long_message(
        ) -> Result<(), Box<dyn std::error::Error>> {
            let long_msg = "a".repeat(1000);
            let err = StorageError::OperationFailed(long_msg.clone());
            let display = format!("{}", err);
            assert!(display.contains(&long_msg));
            Ok(())
        }

        // ============================================================
        // Section 2: MemoryStore construction edge cases (15 tests)
        // ============================================================

        #[test]
        fn test_memory_store_zero_capacity() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::with_capacity(0);
            assert_eq!(store.max_credentials, 0);

            // Try to add credential (should fail immediately)
            let cred = create_test_credential("c1", Some(18000), 2000000);
            let metadata = create_test_metadata("c1");
            let result = store.put_credential(&cred, &metadata);

            assert!(result.is_err());
            assert!(matches!(result, Err(StorageError::StorageFull)));
            Ok(())
        }

        #[test]
        fn test_memory_store_capacity_one() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::with_capacity(1);
            assert_eq!(store.max_credentials, 1);

            // Should accept one credential
            let cred = create_test_credential("c1", Some(18000), 2000000);
            let metadata = create_test_metadata("c1");
            assert!(store.put_credential(&cred, &metadata).is_ok());

            // Should reject second
            let cred2 = create_test_credential("c2", Some(18000), 2000000);
            let metadata2 = create_test_metadata("c2");
            let result = store.put_credential(&cred2, &metadata2);
            assert!(result.is_err());
            Ok(())
        }

        #[test]
        fn test_memory_store_large_capacity() -> Result<(), Box<dyn std::error::Error>> {
            let large_cap = 10_000;
            let store = MemoryStore::with_capacity(large_cap);
            assert_eq!(store.max_credentials, large_cap);
            Ok(())
        }

        #[test]
        fn test_memory_store_default_capacity() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::default();
            assert_eq!(store.max_credentials, 32);
            Ok(())
        }

        #[test]
        fn test_memory_store_thread_safety_arc() -> Result<(), Box<dyn std::error::Error>> {
            let store = Arc::new(MemoryStore::new());

            // Clone Arc for another thread
            let store_clone = Arc::clone(&store);

            let handle = thread::spawn(move || -> Result<(), StorageError> {
                let cred = create_test_credential("c1", Some(18000), 2000000);
                let metadata = create_test_metadata("c1");
                store_clone.put_credential(&cred, &metadata)?;
                Ok(())
            });

            handle.join().map_err(|_| "thread panicked")??;

            // Verify from original Arc
            let result = store.get_credential("c1")?;
            assert!(result.is_some());
            Ok(())
        }

        #[test]
        fn test_memory_store_concurrent_construction() -> Result<(), Box<dyn std::error::Error>> {
            // Create multiple stores concurrently
            let handles: Vec<_> = (0..10)
                .map(|_| {
                    thread::spawn(|| {
                        let store = MemoryStore::new();
                        assert_eq!(store.max_credentials, 32);
                    })
                })
                .collect();

            for handle in handles {
                handle.join().map_err(|_| "thread panicked")?;
            }
            Ok(())
        }

        #[test]
        fn test_memory_store_initial_state() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();

            // Should be empty
            assert_eq!(store.list_credentials()?.len(), 0);

            // Should be able to query non-existent credentials
            assert!(store.get_credential("nonexistent")?.is_none());
            Ok(())
        }

        #[test]
        fn test_memory_store_with_capacity_preserves_value(
        ) -> Result<(), Box<dyn std::error::Error>> {
            for cap in [1, 5, 10, 100, 1000] {
                let store = MemoryStore::with_capacity(cap);
                assert_eq!(store.max_credentials, cap);
            }
            Ok(())
        }

        #[test]
        fn test_memory_store_new_vs_default() -> Result<(), Box<dyn std::error::Error>> {
            let store1 = MemoryStore::new();
            let store2 = MemoryStore::default();

            assert_eq!(store1.max_credentials, store2.max_credentials);
            Ok(())
        }

        #[test]
        fn test_memory_store_btreemap_ordering() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();

            // Add credentials in non-sorted order
            for id in ["zebra", "alpha", "beta", "gamma"].iter() {
                let cred = create_test_credential(id, Some(18000), 2000000);
                let metadata = create_test_metadata(id);
                store.put_credential(&cred, &metadata)?;
            }

            // BTreeMap should maintain sorted order
            let list = store.list_credentials()?;
            let ids: Vec<String> = list.iter().map(|m| m.id.clone()).collect();

            // Should be alphabetically sorted
            assert_eq!(ids, vec!["alpha", "beta", "gamma", "zebra"]);
            Ok(())
        }

        #[test]
        fn test_memory_store_empty_after_construction() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::with_capacity(100);

            let list = store.list_credentials()?;
            assert_eq!(list.len(), 0);

            let bytes = store.get_bytes("any_key")?;
            assert!(bytes.is_none());
            Ok(())
        }

        #[test]
        fn test_memory_store_mutex_not_poisoned() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();

            // Multiple operations should not poison the mutex
            for i in 0..100 {
                let id = format!("c{}", i);
                let cred = create_test_credential(&id, Some(18000), 2000000);
                let metadata = create_test_metadata(&id);
                store.put_credential(&cred, &metadata).ok();
            }

            // Should still be accessible
            let list = store.list_credentials()?;
            assert_eq!(list.len(), 32); // limited by default capacity
            Ok(())
        }

        #[test]
        fn test_memory_store_arc_mutex_interior_mutability(
        ) -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();

            // Can mutate through & reference (Arc<Mutex<>> provides interior mutability)
            let cred = create_test_credential("c1", Some(18000), 2000000);
            let metadata = create_test_metadata("c1");
            store.put_credential(&cred, &metadata)?;

            let retrieved = store.get_credential("c1")?;
            assert!(retrieved.is_some());
            Ok(())
        }

        #[test]
        fn test_memory_store_capacity_edge_values() -> Result<(), Box<dyn std::error::Error>> {
            // Test edge values for capacity
            for cap in [0, 1, 2, 31, 32, 33, 100, 1000] {
                let store = MemoryStore::with_capacity(cap);
                assert_eq!(store.max_credentials, cap);
            }
            Ok(())
        }

        #[test]
        fn test_memory_store_new_is_send_sync() -> Result<(), Box<dyn std::error::Error>> {
            // This test verifies MemoryStore implements Send + Sync
            fn assert_send_sync<T: Send + Sync>() {}
            assert_send_sync::<MemoryStore>();
            Ok(())
        }

        // ============================================================
        // Section 3: put_credential edge cases (25 tests)
        // ============================================================

        #[test]
        fn test_put_credential_empty_id() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let cred = create_test_credential("", Some(18000), 2000000);
            let metadata = create_test_metadata("");

            let result = store.put_credential(&cred, &metadata);
            assert!(result.is_ok());

            let retrieved = store.get_credential("")?;
            assert!(retrieved.is_some());
            Ok(())
        }

        #[test]
        fn test_put_credential_very_long_id() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let long_id = "a".repeat(1000);
            let cred = create_test_credential(&long_id, Some(18000), 2000000);
            let metadata = create_test_metadata(&long_id);

            let result = store.put_credential(&cred, &metadata);
            assert!(result.is_ok());

            let retrieved = store.get_credential(&long_id)?;
            assert!(retrieved.is_some());
            Ok(())
        }

        #[test]
        fn test_put_credential_unicode_id() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let unicode_id = "credential_日本語_🔐_测试";
            let cred = create_test_credential(unicode_id, Some(18000), 2000000);
            let metadata = create_test_metadata(unicode_id);

            let result = store.put_credential(&cred, &metadata);
            assert!(result.is_ok());

            let retrieved = store.get_credential(unicode_id)?;
            assert!(retrieved.is_some());
            Ok(())
        }

        #[test]
        fn test_put_credential_special_characters() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();

            for id in ["cred:123", "cred/456", "cred@789", "cred#abc", "cred|def"].iter() {
                let cred = create_test_credential(id, Some(18000), 2000000);
                let metadata = create_test_metadata(id);
                assert!(store.put_credential(&cred, &metadata).is_ok());
            }
            Ok(())
        }

        #[test]
        fn test_put_credential_duplicate_updates() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let id = "cred1";

            // First put
            let cred1 = create_test_credential(id, Some(18000), 2000000);
            let metadata1 = create_test_metadata(id);
            store.put_credential(&cred1, &metadata1)?;

            // Second put with same ID (update)
            let cred2 = create_test_credential(id, Some(19000), 3000000);
            let metadata2 = create_test_metadata(id);
            store.put_credential(&cred2, &metadata2)?;

            // Should only have 1 credential
            let list = store.list_credentials()?;
            assert_eq!(list.len(), 1);

            // Should be the updated version (all fields including secrets)
            let retrieved = store.get_credential(id)?.ok_or("expected Some")?;
            // Postcard storage preserves secrets
            assert_eq!(retrieved.dob_days, Some(19000));
            assert_eq!(retrieved.exp, 3000000);
            Ok(())
        }

        #[test]
        fn test_put_credential_at_capacity_boundary() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::with_capacity(3);

            // Add 3 credentials (at limit)
            for i in 1..=3 {
                let id = format!("c{}", i);
                let cred = create_test_credential(&id, Some(18000), 2000000);
                let metadata = create_test_metadata(&id);
                assert!(store.put_credential(&cred, &metadata).is_ok());
            }

            // 4th should fail
            let cred4 = create_test_credential("c4", Some(18000), 2000000);
            let metadata4 = create_test_metadata("c4");
            let result = store.put_credential(&cred4, &metadata4);
            assert!(result.is_err());
            assert!(matches!(result, Err(StorageError::StorageFull)));
            Ok(())
        }

        #[test]
        fn test_put_credential_secrets_are_stored() -> Result<(), Box<dyn std::error::Error>> {
            // Postcard storage preserves secrets (dob_days, r_bits) needed for proof generation
            let store = MemoryStore::new();

            let mut cred = create_test_credential("c1", Some(18000), 2000000);
            cred.dob_days = Some(12345);
            cred.r_bits = Some(vec![true, false, true, true]);

            let metadata = create_test_metadata("c1");
            store.put_credential(&cred, &metadata)?;

            let retrieved = store.get_credential("c1")?.ok_or("expected Some")?;
            // Secrets ARE preserved through postcard storage
            assert_eq!(retrieved.dob_days, Some(12345), "dob_days must be stored");
            assert_eq!(
                retrieved.r_bits,
                Some(vec![true, false, true, true]),
                "r_bits must be stored"
            );
            Ok(())
        }

        #[test]
        fn test_put_credential_preserves_all_byte_arrays() -> Result<(), Box<dyn std::error::Error>>
        {
            let store = MemoryStore::new();

            let mut cred = create_test_credential("c1", Some(18000), 2000000);
            cred.issuer_vk = [99u8; 32];
            cred.sig_rj = [88u8; 64];
            cred.c_bytes = [77u8; 32];

            let metadata = create_test_metadata("c1");
            store.put_credential(&cred, &metadata)?;

            let retrieved = store.get_credential("c1")?.ok_or("expected Some")?;
            assert_eq!(retrieved.issuer_vk, [99u8; 32]);
            assert_eq!(retrieved.sig_rj, [88u8; 64]);
            assert_eq!(retrieved.c_bytes, [77u8; 32]);
            Ok(())
        }

        #[test]
        fn test_put_credential_with_none_dob_days() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let cred = create_test_credential("c1", None, 2000000);
            let metadata = create_test_metadata("c1");

            store.put_credential(&cred, &metadata)?;

            let retrieved = store.get_credential("c1")?.ok_or("expected Some")?;
            assert_eq!(retrieved.dob_days, None);
            Ok(())
        }

        #[test]
        fn test_put_credential_with_none_r_bits() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();

            let mut cred = create_test_credential("c1", Some(18000), 2000000);
            cred.r_bits = None;

            let metadata = create_test_metadata("c1");
            store.put_credential(&cred, &metadata)?;

            let retrieved = store.get_credential("c1")?.ok_or("expected Some")?;
            assert_eq!(retrieved.r_bits, None);
            Ok(())
        }

        #[test]
        fn test_put_credential_concurrent_puts_different_ids(
        ) -> Result<(), Box<dyn std::error::Error>> {
            let store = Arc::new(MemoryStore::with_capacity(100));
            let mut handles = vec![];

            for i in 0..10 {
                let store_clone = Arc::clone(&store);
                let handle = thread::spawn(move || -> Result<(), StorageError> {
                    let id = format!("c{}", i);
                    let cred = create_test_credential(&id, Some(18000), 2000000);
                    let metadata = create_test_metadata(&id);
                    store_clone.put_credential(&cred, &metadata)?;
                    Ok(())
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join().map_err(|_| "thread panicked")??;
            }

            let list = store.list_credentials()?;
            assert_eq!(list.len(), 10);
            Ok(())
        }

        #[test]
        fn test_put_credential_concurrent_puts_same_id() -> Result<(), Box<dyn std::error::Error>> {
            let store = Arc::new(MemoryStore::new());
            let mut handles = vec![];

            // Multiple threads try to update same credential
            for i in 0..10 {
                let store_clone = Arc::clone(&store);
                let handle = thread::spawn(move || {
                    let cred = create_test_credential("same_id", Some(18000 + i), 2000000);
                    let metadata = create_test_metadata("same_id");
                    store_clone.put_credential(&cred, &metadata).ok();
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join().map_err(|_| "thread panicked")?;
            }

            // Should have exactly 1 credential
            let list = store.list_credentials()?;
            assert_eq!(list.len(), 1);
            Ok(())
        }

        #[test]
        fn test_put_credential_max_u64_timestamps() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();

            let mut cred = create_test_credential("c1", Some(18000), u64::MAX);
            cred.iat = u64::MAX;

            let metadata = create_test_metadata("c1");
            store.put_credential(&cred, &metadata)?;

            let retrieved = store.get_credential("c1")?.ok_or("expected Some")?;
            assert_eq!(retrieved.iat, u64::MAX);
            assert_eq!(retrieved.exp, u64::MAX);
            Ok(())
        }

        #[test]
        fn test_put_credential_max_i32_dob_is_stored() -> Result<(), Box<dyn std::error::Error>> {
            // Bincode storage preserves dob_days including extreme values
            let store = MemoryStore::new();
            let cred = create_test_credential("c1", Some(i32::MAX), 2000000);
            let metadata = create_test_metadata("c1");

            store.put_credential(&cred, &metadata)?;

            let retrieved = store.get_credential("c1")?.ok_or("expected Some")?;
            assert_eq!(
                retrieved.dob_days,
                Some(i32::MAX),
                "dob_days must survive storage"
            );
            Ok(())
        }

        #[test]
        fn test_put_credential_metadata_label_preservation(
        ) -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let cred = create_test_credential("c1", Some(18000), 2000000);

            let mut metadata = create_test_metadata("c1");
            metadata.label = Some("My Important Credential 🔑".to_string());

            store.put_credential(&cred, &metadata)?;

            let list = store.list_credentials()?;
            assert_eq!(
                list[0].label,
                Some("My Important Credential 🔑".to_string())
            );
            Ok(())
        }

        #[test]
        fn test_put_credential_metadata_issuer_name() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let cred = create_test_credential("c1", Some(18000), 2000000);

            let mut metadata = create_test_metadata("c1");
            metadata.issuer_name = Some("Trusted Issuer Inc.".to_string());

            store.put_credential(&cred, &metadata)?;

            let list = store.list_credentials()?;
            assert_eq!(list[0].issuer_name, Some("Trusted Issuer Inc.".to_string()));
            Ok(())
        }

        #[test]
        fn test_put_credential_metadata_timestamps() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let cred = create_test_credential("c1", Some(18000), 2000000);

            let mut metadata = create_test_metadata("c1");
            metadata.imported_at = 1234567890;

            store.put_credential(&cred, &metadata)?;

            let list = store.list_credentials()?;
            assert_eq!(list[0].imported_at, 1234567890);
            Ok(())
        }

        #[test]
        fn test_put_credential_large_r_bits_is_stored() -> Result<(), Box<dyn std::error::Error>> {
            // Bincode storage preserves r_bits including large vectors
            let store = MemoryStore::new();

            let mut cred = create_test_credential("c1", Some(18000), 2000000);
            cred.r_bits = Some(vec![true; 1000]); // Large vector

            let metadata = create_test_metadata("c1");
            store.put_credential(&cred, &metadata)?;

            let retrieved = store.get_credential("c1")?.ok_or("expected Some")?;
            assert_eq!(
                retrieved.r_bits,
                Some(vec![true; 1000]),
                "r_bits must survive storage"
            );
            Ok(())
        }

        #[test]
        fn test_put_credential_schema_variations() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::with_capacity(10);

            let long_schema = "a".repeat(100);
            let schemas: [&str; 5] = [
                "provii.age.v1",
                "provii.age/0",
                "custom.schema",
                "",
                &long_schema,
            ];

            for (i, schema) in schemas.iter().enumerate() {
                let id = format!("c{}", i);
                let mut cred = create_test_credential(&id, Some(18000), 2000000);
                cred.schema = schema.to_string();

                let metadata = create_test_metadata(&id);
                store.put_credential(&cred, &metadata)?;

                let retrieved = store.get_credential(&id)?.ok_or("expected Some")?;
                assert_eq!(retrieved.schema, *schema);
            }
            Ok(())
        }

        #[test]
        fn test_put_credential_kid_variations() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::with_capacity(10);

            let kids = [
                "key1",
                "key-with-dashes",
                "key_with_underscores",
                "🔑_emoji_key",
                "",
            ];

            for (i, kid) in kids.iter().enumerate() {
                let id = format!("c{}", i);
                let mut cred = create_test_credential(&id, Some(18000), 2000000);
                cred.kid = kid.to_string();

                let metadata = create_test_metadata(&id);
                store.put_credential(&cred, &metadata)?;

                let retrieved = store.get_credential(&id)?.ok_or("expected Some")?;
                assert_eq!(retrieved.kid, *kid);
            }
            Ok(())
        }

        #[test]
        fn test_put_credential_version_field() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();

            for version in [1, 2, 99, 255] {
                let id = format!("c_v{}", version);
                let mut cred = create_test_credential(&id, Some(18000), 2000000);
                cred.v = version;

                let metadata = create_test_metadata(&id);
                store.put_credential(&cred, &metadata)?;

                let retrieved = store.get_credential(&id)?.ok_or("expected Some")?;
                assert_eq!(retrieved.v, version);
            }
            Ok(())
        }

        #[test]
        fn test_put_credential_zero_timestamps() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();

            let mut cred = create_test_credential("c1", Some(18000), 0);
            cred.iat = 0;

            let metadata = create_test_metadata("c1");
            store.put_credential(&cred, &metadata)?;

            let retrieved = store.get_credential("c1")?.ok_or("expected Some")?;
            assert_eq!(retrieved.iat, 0);
            assert_eq!(retrieved.exp, 0);
            Ok(())
        }

        #[test]
        fn test_put_credential_doesnt_affect_bytes_storage(
        ) -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();

            // Put some bytes
            store.put_bytes("test_key", b"test_data")?;

            // Put credential
            let cred = create_test_credential("c1", Some(18000), 2000000);
            let metadata = create_test_metadata("c1");
            store.put_credential(&cred, &metadata)?;

            // Bytes should still be there
            let bytes = store.get_bytes("test_key")?;
            assert_eq!(bytes, Some(b"test_data".to_vec()));
            Ok(())
        }

        // ============================================================
        // Section 4: get_credential edge cases (20 tests)
        // ============================================================

        #[test]
        fn test_get_credential_nonexistent() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let result = store.get_credential("doesnt_exist")?;
            assert!(result.is_none());
            Ok(())
        }

        #[test]
        fn test_get_credential_empty_id() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let cred = create_test_credential("", Some(18000), 2000000);
            let metadata = create_test_metadata("");
            store.put_credential(&cred, &metadata)?;

            let retrieved = store.get_credential("")?;
            assert!(retrieved.is_some());
            Ok(())
        }

        #[test]
        fn test_get_credential_unicode_id() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let unicode_id = "測試_🔐_테스트";
            let cred = create_test_credential(unicode_id, Some(18000), 2000000);
            let metadata = create_test_metadata(unicode_id);
            store.put_credential(&cred, &metadata)?;

            let retrieved = store.get_credential(unicode_id)?;
            assert!(retrieved.is_some());
            assert_eq!(
                retrieved.ok_or("expected credential")?.credential_id(),
                cred.credential_id()
            );
            Ok(())
        }

        #[test]
        fn test_get_credential_after_update() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let id = "c1";

            // Put first version
            let cred1 = create_test_credential(id, Some(18000), 2000000);
            let metadata = create_test_metadata(id);
            store.put_credential(&cred1, &metadata)?;

            // Update
            let cred2 = create_test_credential(id, Some(25000), 3000000);
            store.put_credential(&cred2, &metadata)?;

            // Get should return updated version (all fields including secrets)
            let retrieved = store.get_credential(id)?.ok_or("expected Some")?;
            // Postcard storage preserves secrets
            assert_eq!(retrieved.dob_days, Some(25000));
            assert_eq!(retrieved.exp, 3000000);
            Ok(())
        }

        #[test]
        fn test_get_credential_after_delete() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let cred = create_test_credential("c1", Some(18000), 2000000);
            let metadata = create_test_metadata("c1");
            store.put_credential(&cred, &metadata)?;

            store.delete_credential("c1")?;

            let retrieved = store.get_credential("c1")?;
            assert!(retrieved.is_none());
            Ok(())
        }

        #[test]
        fn test_get_credential_concurrent_reads() -> Result<(), Box<dyn std::error::Error>> {
            let store = Arc::new(MemoryStore::new());
            let cred = create_test_credential("c1", Some(18000), 2000000);
            let metadata = create_test_metadata("c1");
            store.put_credential(&cred, &metadata)?;

            let mut handles = vec![];
            for _ in 0..10 {
                let store_clone = Arc::clone(&store);
                let handle = thread::spawn(move || -> Result<(), StorageError> {
                    let retrieved = store_clone.get_credential("c1")?;
                    assert!(retrieved.is_some());
                    Ok(())
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join().map_err(|_| "thread panicked")??;
            }
            Ok(())
        }

        #[test]
        fn test_get_credential_multiple_different_ids() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();

            // Store multiple credentials with different dob_days and exp values
            for i in 0..10u64 {
                let id = format!("c{}", i);
                let cred = create_test_credential(&id, Some(18000 + i as i32), 2000000 + i);
                let metadata = create_test_metadata(&id);
                store.put_credential(&cred, &metadata)?;
            }

            // Retrieve each one and verify all fields including secrets
            for i in 0..10u64 {
                let id = format!("c{}", i);
                let retrieved = store.get_credential(&id)?;
                assert!(retrieved.is_some());
                let cred = retrieved.ok_or("expected credential")?;
                // Postcard storage preserves secrets
                assert_eq!(cred.dob_days, Some(18000 + i as i32));
                assert_eq!(cred.exp, 2000000 + i);
            }
            Ok(())
        }

        #[test]
        fn test_get_credential_similar_ids() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();

            let ids = ["cred", "cred1", "cred12", "cred123", "cred1234"];
            for id in ids.iter() {
                let cred = create_test_credential(id, Some(18000), 2000000);
                let metadata = create_test_metadata(id);
                store.put_credential(&cred, &metadata)?;
            }

            // Each should be retrievable independently
            for id in ids.iter() {
                let retrieved = store.get_credential(id)?;
                assert!(retrieved.is_some());
            }
            Ok(())
        }

        #[test]
        fn test_get_credential_special_chars_in_id() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();

            let ids = ["c:1", "c/2", "c@3", "c#4", "c|5", "c\\6"];
            for id in ids.iter() {
                let cred = create_test_credential(id, Some(18000), 2000000);
                let metadata = create_test_metadata(id);
                store.put_credential(&cred, &metadata)?;
            }

            for id in ids.iter() {
                let retrieved = store.get_credential(id)?;
                assert!(retrieved.is_some());
            }
            Ok(())
        }

        #[test]
        fn test_get_credential_preserves_all_data() -> Result<(), Box<dyn std::error::Error>> {
            // Postcard storage preserves all fields including secrets
            let store = MemoryStore::new();

            let mut cred = create_test_credential("c1", Some(12345), 2000000);
            cred.issuer_vk = [99u8; 32];
            cred.sig_rj = [88u8; 64];
            cred.c_bytes = [77u8; 32];
            cred.r_bits = Some(vec![true, false, true, false]);
            cred.iat = 123456;

            let metadata = create_test_metadata("c1");
            store.put_credential(&cred, &metadata)?;

            let retrieved = store.get_credential("c1")?.ok_or("expected Some")?;

            // All fields ARE preserved including secrets
            assert_eq!(retrieved.dob_days, Some(12345), "dob_days must be stored");
            assert_eq!(
                retrieved.r_bits,
                Some(vec![true, false, true, false]),
                "r_bits must be stored"
            );
            // Public fields also preserved
            assert_eq!(retrieved.issuer_vk, [99u8; 32]);
            assert_eq!(retrieved.sig_rj, [88u8; 64]);
            assert_eq!(retrieved.c_bytes, [77u8; 32]);
            assert_eq!(retrieved.iat, 123456);
            Ok(())
        }

        #[test]
        fn test_get_credential_empty_store() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();

            for id in ["c1", "c2", "anything"] {
                let result = store.get_credential(id)?;
                assert!(result.is_none());
            }
            Ok(())
        }

        #[test]
        fn test_get_credential_wrong_id() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let cred = create_test_credential("correct_id", Some(18000), 2000000);
            let metadata = create_test_metadata("correct_id");
            store.put_credential(&cred, &metadata)?;

            // Try to get with wrong ID
            let result = store.get_credential("wrong_id")?;
            assert!(result.is_none());
            Ok(())
        }

        #[test]
        fn test_get_credential_case_sensitive() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let cred = create_test_credential("MyCredential", Some(18000), 2000000);
            let metadata = create_test_metadata("MyCredential");
            store.put_credential(&cred, &metadata)?;

            // Case matters
            assert!(store.get_credential("MyCredential")?.is_some());
            assert!(store.get_credential("mycredential")?.is_none());
            assert!(store.get_credential("MYCREDENTIAL")?.is_none());
            Ok(())
        }

        #[test]
        fn test_get_credential_whitespace_matters() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let cred = create_test_credential("cred1", Some(18000), 2000000);
            let metadata = create_test_metadata("cred1");
            store.put_credential(&cred, &metadata)?;

            // Exact match required
            assert!(store.get_credential("cred1")?.is_some());
            assert!(store.get_credential(" cred1")?.is_none());
            assert!(store.get_credential("cred1 ")?.is_none());
            assert!(store.get_credential(" cred1 ")?.is_none());
            Ok(())
        }

        #[test]
        fn test_get_credential_very_long_id() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let long_id = "a".repeat(10000);
            let cred = create_test_credential(&long_id, Some(18000), 2000000);
            let metadata = create_test_metadata(&long_id);
            store.put_credential(&cred, &metadata)?;

            let retrieved = store.get_credential(&long_id)?;
            assert!(retrieved.is_some());
            Ok(())
        }

        #[test]
        fn test_get_credential_after_clear() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let cred = create_test_credential("c1", Some(18000), 2000000);
            let metadata = create_test_metadata("c1");
            store.put_credential(&cred, &metadata)?;

            store.clear_all()?;

            let retrieved = store.get_credential("c1")?;
            assert!(retrieved.is_none());
            Ok(())
        }

        #[test]
        fn test_get_credential_mixed_operations() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();

            // Add credential
            let cred = create_test_credential("c1", Some(18000), 2000000);
            let metadata = create_test_metadata("c1");
            store.put_credential(&cred, &metadata)?;

            // Can get it
            assert!(store.get_credential("c1")?.is_some());

            // Add some bytes
            store.put_bytes("key1", b"data")?;

            // Can still get credential
            assert!(store.get_credential("c1")?.is_some());

            // Delete bytes
            store.delete("key1")?;

            // Can still get credential
            assert!(store.get_credential("c1")?.is_some());
            Ok(())
        }

        #[test]
        fn test_get_credential_concurrent_read_write() -> Result<(), Box<dyn std::error::Error>> {
            let store = Arc::new(MemoryStore::with_capacity(100));

            let mut handles = vec![];

            // Writer threads
            for i in 0..5 {
                let store_clone = Arc::clone(&store);
                let handle = thread::spawn(move || {
                    let id = format!("c{}", i);
                    let cred = create_test_credential(&id, Some(18000), 2000000);
                    let metadata = create_test_metadata(&id);
                    store_clone.put_credential(&cred, &metadata).ok();
                });
                handles.push(handle);
            }

            // Reader threads
            for i in 0..5 {
                let store_clone = Arc::clone(&store);
                let handle = thread::spawn(move || {
                    let id = format!("c{}", i);
                    // May or may not exist depending on timing
                    store_clone.get_credential(&id).ok();
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join().map_err(|_| "thread panicked")?;
            }
            Ok(())
        }

        #[test]
        fn test_get_credential_returns_clone() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let cred = create_test_credential("c1", Some(18000), 2000000);
            let metadata = create_test_metadata("c1");
            store.put_credential(&cred, &metadata)?;

            // Get twice
            let retrieved1 = store.get_credential("c1")?.ok_or("expected Some")?;
            let retrieved2 = store.get_credential("c1")?.ok_or("expected Some")?;

            // Should be equal but independent
            assert_eq!(retrieved1.credential_id(), retrieved2.credential_id());
            Ok(())
        }

        #[test]
        fn test_get_credential_max_capacity_store() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::with_capacity(32);

            // Fill to capacity
            for i in 0..32 {
                let id = format!("c{}", i);
                let cred = create_test_credential(&id, Some(18000), 2000000);
                let metadata = create_test_metadata(&id);
                store.put_credential(&cred, &metadata)?;
            }

            // All should be retrievable
            for i in 0..32 {
                let id = format!("c{}", i);
                let retrieved = store.get_credential(&id)?;
                assert!(retrieved.is_some());
            }
            Ok(())
        }

        // ============================================================
        // Section 5: delete_credential edge cases (20 tests)
        // ============================================================

        #[test]
        fn test_delete_credential_nonexistent() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let deleted = store.delete_credential("doesnt_exist")?;
            assert!(!deleted);
            Ok(())
        }

        #[test]
        fn test_delete_credential_success() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let cred = create_test_credential("c1", Some(18000), 2000000);
            let metadata = create_test_metadata("c1");
            store.put_credential(&cred, &metadata)?;

            let deleted = store.delete_credential("c1")?;
            assert!(deleted);

            let retrieved = store.get_credential("c1")?;
            assert!(retrieved.is_none());
            Ok(())
        }

        #[test]
        fn test_delete_credential_twice() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let cred = create_test_credential("c1", Some(18000), 2000000);
            let metadata = create_test_metadata("c1");
            store.put_credential(&cred, &metadata)?;

            // First delete succeeds
            let first = store.delete_credential("c1")?;
            assert!(first);

            // Second delete fails (already gone)
            let second = store.delete_credential("c1")?;
            assert!(!second);
            Ok(())
        }

        #[test]
        fn test_delete_credential_idempotent() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let cred = create_test_credential("c1", Some(18000), 2000000);
            let metadata = create_test_metadata("c1");
            store.put_credential(&cred, &metadata)?;

            // Delete multiple times
            assert!(store.delete_credential("c1")?);
            assert!(!store.delete_credential("c1")?);
            assert!(!store.delete_credential("c1")?);
            Ok(())
        }

        #[test]
        fn test_delete_credential_removes_from_list() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let cred = create_test_credential("c1", Some(18000), 2000000);
            let metadata = create_test_metadata("c1");
            store.put_credential(&cred, &metadata)?;

            assert_eq!(store.list_credentials()?.len(), 1);

            store.delete_credential("c1")?;

            assert_eq!(store.list_credentials()?.len(), 0);
            Ok(())
        }

        #[test]
        fn test_delete_credential_selective() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();

            // Add 3 credentials
            for i in 1..=3 {
                let id = format!("c{}", i);
                let cred = create_test_credential(&id, Some(18000), 2000000);
                let metadata = create_test_metadata(&id);
                store.put_credential(&cred, &metadata)?;
            }

            // Delete middle one
            store.delete_credential("c2")?;

            // c1 and c3 should still exist
            assert!(store.get_credential("c1")?.is_some());
            assert!(store.get_credential("c2")?.is_none());
            assert!(store.get_credential("c3")?.is_some());

            assert_eq!(store.list_credentials()?.len(), 2);
            Ok(())
        }

        #[test]
        fn test_delete_credential_frees_capacity() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::with_capacity(2);

            // Fill to capacity
            for i in 1..=2 {
                let id = format!("c{}", i);
                let cred = create_test_credential(&id, Some(18000), 2000000);
                let metadata = create_test_metadata(&id);
                store.put_credential(&cred, &metadata)?;
            }

            // Can't add more
            let cred3 = create_test_credential("c3", Some(18000), 2000000);
            let metadata3 = create_test_metadata("c3");
            assert!(store.put_credential(&cred3, &metadata3).is_err());

            // Delete one
            store.delete_credential("c1")?;

            // Now can add
            assert!(store.put_credential(&cred3, &metadata3).is_ok());
            Ok(())
        }

        #[test]
        fn test_delete_credential_unicode_id() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let unicode_id = "クレデンシャル_🗑️";
            let cred = create_test_credential(unicode_id, Some(18000), 2000000);
            let metadata = create_test_metadata(unicode_id);
            store.put_credential(&cred, &metadata)?;

            let deleted = store.delete_credential(unicode_id)?;
            assert!(deleted);
            Ok(())
        }

        #[test]
        fn test_delete_credential_empty_id() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let cred = create_test_credential("", Some(18000), 2000000);
            let metadata = create_test_metadata("");
            store.put_credential(&cred, &metadata)?;

            let deleted = store.delete_credential("")?;
            assert!(deleted);
            Ok(())
        }

        #[test]
        fn test_delete_credential_case_sensitive() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let cred = create_test_credential("MyCredential", Some(18000), 2000000);
            let metadata = create_test_metadata("MyCredential");
            store.put_credential(&cred, &metadata)?;

            // Wrong case doesn't delete
            let result1 = store.delete_credential("mycredential")?;
            assert!(!result1);

            // Correct case deletes
            let result2 = store.delete_credential("MyCredential")?;
            assert!(result2);
            Ok(())
        }

        #[test]
        fn test_delete_credential_concurrent() -> Result<(), Box<dyn std::error::Error>> {
            let store = Arc::new(MemoryStore::with_capacity(100));

            // Add credentials
            for i in 0..10 {
                let id = format!("c{}", i);
                let cred = create_test_credential(&id, Some(18000), 2000000);
                let metadata = create_test_metadata(&id);
                store.put_credential(&cred, &metadata)?;
            }

            let mut handles = vec![];

            // Delete concurrently
            for i in 0..10 {
                let store_clone = Arc::clone(&store);
                let handle = thread::spawn(move || -> Result<bool, StorageError> {
                    let id = format!("c{}", i);
                    store_clone.delete_credential(&id)
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join().map_err(|_| "thread panicked")??;
            }

            // All should be deleted
            assert_eq!(store.list_credentials()?.len(), 0);
            Ok(())
        }

        #[test]
        fn test_delete_credential_concurrent_same_id() -> Result<(), Box<dyn std::error::Error>> {
            let store = Arc::new(MemoryStore::new());
            let cred = create_test_credential("same_id", Some(18000), 2000000);
            let metadata = create_test_metadata("same_id");
            store.put_credential(&cred, &metadata)?;

            let mut handles = vec![];

            // Multiple threads try to delete same credential
            for _ in 0..10 {
                let store_clone = Arc::clone(&store);
                let handle = thread::spawn(move || store_clone.delete_credential("same_id").ok());
                handles.push(handle);
            }

            let mut results = Vec::new();
            for h in handles {
                results.push(h.join().map_err(|_| "thread panicked")?);
            }

            // Exactly one should have succeeded
            let success_count = results.iter().filter(|r| **r == Some(true)).count();
            assert_eq!(success_count, 1);
            Ok(())
        }

        #[test]
        fn test_delete_credential_doesnt_affect_bytes() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();

            // Add credential and bytes
            let cred = create_test_credential("c1", Some(18000), 2000000);
            let metadata = create_test_metadata("c1");
            store.put_credential(&cred, &metadata)?;
            store.put_bytes("key1", b"data")?;

            // Delete credential
            store.delete_credential("c1")?;

            // Bytes should still be there
            assert_eq!(store.get_bytes("key1")?, Some(b"data".to_vec()));
            Ok(())
        }

        #[test]
        fn test_delete_credential_all_one_by_one() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();

            // Add multiple
            for i in 0..10 {
                let id = format!("c{}", i);
                let cred = create_test_credential(&id, Some(18000), 2000000);
                let metadata = create_test_metadata(&id);
                store.put_credential(&cred, &metadata)?;
            }

            // Delete all
            for i in 0..10 {
                let id = format!("c{}", i);
                let deleted = store.delete_credential(&id)?;
                assert!(deleted);
            }

            assert_eq!(store.list_credentials()?.len(), 0);
            Ok(())
        }

        #[test]
        fn test_delete_credential_after_update() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let id = "c1";

            // Add
            let cred1 = create_test_credential(id, Some(18000), 2000000);
            let metadata = create_test_metadata(id);
            store.put_credential(&cred1, &metadata)?;

            // Update
            let cred2 = create_test_credential(id, Some(19000), 2000000);
            store.put_credential(&cred2, &metadata)?;

            // Delete
            let deleted = store.delete_credential(id)?;
            assert!(deleted);

            // Should be gone
            assert!(store.get_credential(id)?.is_none());
            Ok(())
        }

        #[test]
        fn test_delete_credential_and_readd() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let id = "c1";
            let cred = create_test_credential(id, Some(18000), 2000000);
            let metadata = create_test_metadata(id);

            // Add
            store.put_credential(&cred, &metadata)?;

            // Delete
            store.delete_credential(id)?;

            // Re-add
            let result = store.put_credential(&cred, &metadata);
            assert!(result.is_ok());

            // Should exist
            assert!(store.get_credential(id)?.is_some());
            Ok(())
        }

        #[test]
        fn test_delete_credential_very_long_id() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let long_id = "x".repeat(5000);
            let cred = create_test_credential(&long_id, Some(18000), 2000000);
            let metadata = create_test_metadata(&long_id);
            store.put_credential(&cred, &metadata)?;

            let deleted = store.delete_credential(&long_id)?;
            assert!(deleted);
            Ok(())
        }

        #[test]
        fn test_delete_credential_special_chars() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();
            let ids = ["c:1", "c/2", "c@3", "c\\4"];

            for id in ids.iter() {
                let cred = create_test_credential(id, Some(18000), 2000000);
                let metadata = create_test_metadata(id);
                store.put_credential(&cred, &metadata)?;
            }

            for id in ids.iter() {
                let deleted = store.delete_credential(id)?;
                assert!(deleted);
            }

            assert_eq!(store.list_credentials()?.len(), 0);
            Ok(())
        }

        #[test]
        fn test_delete_credential_empty_store() -> Result<(), Box<dyn std::error::Error>> {
            let store = MemoryStore::new();

            // Try to delete from empty store
            for id in ["c1", "c2", "anything"] {
                let deleted = store.delete_credential(id)?;
                assert!(!deleted);
            }
            Ok(())
        }

        #[test]
        fn test_delete_credential_data_only_no_metadata() -> Result<(), Box<dyn std::error::Error>>
        {
            let store = MemoryStore::new();
            store.put_bytes("cred:phantom", b"fake-credential-bytes")?;
            let deleted = store.delete_credential("phantom")?;
            assert!(
                deleted,
                "delete_credential must return true when data exists but metadata does not"
            );
            Ok(())
        }

        #[test]
        fn test_cleanup_expired_boundary_equal_timestamp() -> Result<(), Box<dyn std::error::Error>>
        {
            let store = MemoryStore::new();
            let boundary_ts: u64 = 1_500_000;

            let cred_at_boundary = create_test_credential("boundary", Some(18000), boundary_ts);
            store.put_credential(&cred_at_boundary, &create_test_metadata("boundary"))?;

            let removed = helpers::cleanup_expired(&store, boundary_ts)?;
            assert_eq!(
                removed, 0,
                "credential whose exp equals current_timestamp must NOT be removed"
            );

            let remaining = store.list_credentials()?;
            assert_eq!(remaining.len(), 1);
            Ok(())
        }
    }
}
