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
#[path = "storage_tests.rs"]
mod storage_tests;
