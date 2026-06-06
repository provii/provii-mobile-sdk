// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Platform-agnostic secure storage facade for Provii Wallet.
//!
//! Defines the [`PlatformSecureStorage`] trait that iOS (Keychain) and Android
//! (Keystore) backends implement, plus the [`SecureStore`] convenience wrapper
//! for serialisation with JSON, postcard, and biometric gating. All credential
//! serialisation is handled at the FFI layer.

#![forbid(unsafe_code)]

use std::sync::Arc;
use zeroize::Zeroizing;

/// Whether a storage operation requires biometric authentication.
///
/// Platform implementations (iOS Keychain, Android Keystore) use this to gate
/// access to sensitive entries behind a biometric prompt. Operations on
/// metadata, settings, and cache should pass `None`; operations on credential
/// secrets, export, or deletion should pass `Required`.
#[derive(Debug, Clone)]
pub enum BiometricRequirement {
    /// No biometric required (metadata, settings, cache).
    None,
    /// Biometric authentication required before this operation.
    Required { config: BiometricConfig },
}

/// Configuration for a biometric authentication prompt shown to the user.
#[derive(Debug, Clone)]
pub struct BiometricConfig {
    /// Human-readable reason displayed in the system prompt.
    pub reason: String,
    /// Maximum seconds to wait for the user to authenticate.
    pub timeout_seconds: u32,
}

impl Default for BiometricConfig {
    fn default() -> Self {
        Self {
            reason: "Access your credentials".to_string(),
            timeout_seconds: 30,
        }
    }
}

impl BiometricRequirement {
    /// Convenience constructor for credential secret operations.
    pub fn for_credential_secrets() -> Self {
        Self::Required {
            config: BiometricConfig {
                reason: "Authenticate to access credential secrets".to_string(),
                ..BiometricConfig::default()
            },
        }
    }

    /// Convenience constructor for credential export.
    pub fn for_export() -> Self {
        Self::Required {
            config: BiometricConfig {
                reason: "Authenticate to export credential".to_string(),
                ..BiometricConfig::default()
            },
        }
    }

    /// Convenience constructor for credential deletion.
    pub fn for_delete() -> Self {
        Self::Required {
            config: BiometricConfig {
                reason: "Authenticate to delete credential".to_string(),
                ..BiometricConfig::default()
            },
        }
    }
}

/// Platform-specific error type
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("Storage error: {msg}")]
    Storage { msg: String },

    #[error("Not found")]
    NotFound,

    #[error("Already exists")]
    AlreadyExists,

    #[error("Operation not supported")]
    NotSupported,

    #[error("Biometric authentication required")]
    BiometricRequired,

    #[error("Biometric authentication failed: {msg}")]
    BiometricFailed { msg: String },
}

/// Alias for `Result` with [`WalletError`] as the error type.
pub type Result<T> = std::result::Result<T, WalletError>;

/// Usage statistics for storage
#[derive(Debug, Default, Clone)]
pub struct UsageStats {
    pub total_keys: usize,
    pub total_bytes: usize,
    pub credentials_count: usize,
}

/// Low-level secure storage trait that each platform implements.
///
/// # Key format
///
/// Storage keys passed to [`store`](Self::store), [`retrieve`](Self::retrieve),
/// [`delete`](Self::delete), and [`exists`](Self::exists) must satisfy the
/// contract enforced by [`validate_key`](Self::validate_key):
///
/// - Non-empty
/// - At most 255 bytes
/// - ASCII alphanumeric characters, `_`, `.`, and `-` only
///
/// The default `validate_key` enforces these rules. Implementations may
/// override it to apply stricter platform-specific constraints but must
/// not weaken the baseline contract.
///
/// # Implementation requirements
///
/// - Thread-safe (`Send + Sync`)
/// - Use platform-specific secure storage (Keychain on iOS, Keystore on Android)
/// - Handle encryption transparently
/// - Support key-value operations only (no complex queries)
pub trait PlatformSecureStorage: Send + Sync {
    /// Store a value under the given key.
    ///
    /// When `bio` is `BiometricRequirement::Required`, the platform
    /// implementation must authenticate the user before writing.
    fn store(&self, key: &str, data: &[u8], bio: BiometricRequirement) -> Result<()>;

    /// Retrieve the value for a given key.
    ///
    /// Returns data wrapped in `Zeroizing` so that the buffer is cleared
    /// from memory when it is dropped. When `bio` is
    /// `BiometricRequirement::Required`, the platform implementation must
    /// authenticate the user before reading.
    fn retrieve(&self, key: &str, bio: BiometricRequirement) -> Result<Zeroizing<Vec<u8>>>;

    /// Delete a key-value pair.
    ///
    /// # Idempotent semantics
    ///
    /// Deleting a key that does not exist returns `Ok(())`. This is an
    /// intentional design choice: callers should not need to check existence
    /// before deletion, and concurrent or repeated deletes must not fail.
    ///
    /// # Biometric authentication
    ///
    /// Unlike `store` and `retrieve`, this method does not accept a
    /// [`BiometricRequirement`] parameter. The omission is a deliberate design
    /// choice, not an oversight. Deletion is a destructive action that removes
    /// data; it does not expose secret material to the caller. Platform
    /// keystores (iOS Keychain, Android Keystore) do not gate key deletion
    /// behind biometric prompts at the API level, so adding the parameter here
    /// would create a contract that the platform backends cannot fulfil without
    /// synthetic workarounds. The [`BiometricRequirement::for_delete`]
    /// constructor exists so that higher-level orchestration code (e.g. the
    /// wallet UI layer) can prompt the user before calling `delete`, but the
    /// trait itself does not enforce the prompt.
    fn delete(&self, key: &str) -> Result<()>;

    /// Check whether a key exists in storage.
    ///
    /// Returns `Ok(false)` when the key is absent, not `Err(NotFound)`.
    fn exists(&self, key: &str) -> Result<bool>;

    /// List all keys stored by this backend.
    ///
    /// Returns the full key set with no pagination. In practice the wallet
    /// stores fewer than 100 keys (credentials, settings, cache entries), so
    /// pagination is unnecessary. Callers that need a filtered view should use
    /// [`SecureStore::list_keys_with_prefix`] instead.
    fn list_keys(&self) -> Result<Vec<String>>;

    /// Validate a storage key before use.
    ///
    /// The default implementation enforces: non-empty, max 255 bytes, ASCII
    /// alphanumeric plus `_`, `.`, and `-` only. Implementations may override
    /// this to apply stricter or platform-specific rules.
    ///
    /// # Object safety
    ///
    /// This method carries a `where Self: Sized` bound, which means it cannot
    /// be called through a `dyn PlatformSecureStorage` trait object. This is
    /// intentional: without the bound the entire trait would become
    /// non-object-safe, and `SecureStore` (which holds an
    /// `Arc<dyn PlatformSecureStorage>`) would fail to compile. Each concrete
    /// platform implementation (iOS Keychain, Android Keystore) should call
    /// `Self::validate_key(key)?` at the top of its own `store`, `retrieve`,
    /// and `delete` methods rather than relying on the trait to call it
    /// automatically. The default trait methods (`wipe_all`, `rotate_master_key`,
    /// `usage_stats`) do not accept a key parameter, so they have no reason to
    /// invoke this validation.
    fn validate_key(key: &str) -> Result<()>
    where
        Self: Sized,
    {
        if key.is_empty() {
            return Err(WalletError::Storage {
                msg: "Key cannot be empty".to_string(),
            });
        }
        if key.len() > 255 {
            return Err(WalletError::Storage {
                msg: "Key too long (max 255 bytes)".to_string(),
            });
        }
        if !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
        {
            return Err(WalletError::Storage {
                msg: "Key contains invalid characters (allowed: ASCII alphanumeric, '_', '.', '-')"
                    .to_string(),
            });
        }
        Ok(())
    }

    /// Optional: Wipe all stored data (use with caution)
    fn wipe_all(&self) -> Result<()> {
        Err(WalletError::NotSupported)
    }

    /// Optional: Rotate the master encryption key
    fn rotate_master_key(&self) -> Result<()> {
        Ok(()) // No-op by default
    }

    /// Optional: Get storage usage statistics
    fn usage_stats(&self) -> Result<UsageStats> {
        Ok(UsageStats::default())
    }
}

/// Helper wrapper for convenient access patterns
#[derive(Clone)]
pub struct SecureStore {
    backend: Arc<dyn PlatformSecureStorage>,
}

impl SecureStore {
    /// Wrap a platform backend in the convenience API.
    pub fn new(backend: Arc<dyn PlatformSecureStorage>) -> Self {
        Self { backend }
    }

    /// Store a string value (no biometric, for metadata and settings).
    pub fn store_string(&self, key: &str, value: &str) -> Result<()> {
        self.backend
            .store(key, value.as_bytes(), BiometricRequirement::None)
    }

    /// Retrieve a string value (no biometric, for metadata and settings).
    ///
    /// Returns `Zeroizing<String>` so the caller's copy is cleared from
    /// memory when dropped, matching the byte-level zeroisation guarantee
    /// of the underlying `retrieve` call.
    pub fn retrieve_string(&self, key: &str) -> Result<Zeroizing<String>> {
        let bytes = self.backend.retrieve(key, BiometricRequirement::None)?;
        let s = std::str::from_utf8(&bytes)
            .map(|s| Zeroizing::new(s.to_owned()))
            .map_err(|e| WalletError::Storage {
                msg: format!("Invalid UTF-8: {}", e),
            })?;
        // bytes (Zeroizing<Vec<u8>>) dropped here, clearing memory
        Ok(s)
    }

    /// Store JSON-serializable data (no biometric, for metadata and settings).
    pub fn store_json<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let json = Zeroizing::new(serde_json::to_vec(value).map_err(|e| WalletError::Storage {
            msg: format!("JSON serialisation failed: {}", e),
        })?);
        self.backend.store(key, &json, BiometricRequirement::None)
        // json (Zeroizing<Vec<u8>>) dropped here, clearing serialised bytes
    }

    /// Retrieve and deserialize JSON data (no biometric, for metadata and settings).
    pub fn retrieve_json<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<T> {
        let bytes = self.backend.retrieve(key, BiometricRequirement::None)?;
        serde_json::from_slice(&bytes).map_err(|e| WalletError::Storage {
            msg: format!("JSON deserialisation failed: {}", e),
        })
    }

    /// Store postcard-serializable data (no biometric, for metadata and settings).
    ///
    /// Postcard is preferred over JSON for credential storage because:
    /// - More compact (less storage space)
    /// - Not human-readable (secrets aren't visible in hex dumps)
    /// - Platform keychain/keystore provides encryption at rest
    pub fn store_postcard<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let bytes =
            Zeroizing::new(
                postcard::to_allocvec(value).map_err(|e| WalletError::Storage {
                    msg: format!("Postcard serialisation failed: {}", e),
                })?,
            );
        self.backend.store(key, &bytes, BiometricRequirement::None)
        // bytes (Zeroizing<Vec<u8>>) dropped here, clearing serialised bytes
    }

    /// Retrieve and deserialize postcard data (no biometric, for metadata and settings).
    pub fn retrieve_postcard<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<T> {
        let bytes = self.backend.retrieve(key, BiometricRequirement::None)?;
        postcard::from_bytes(&bytes).map_err(|e| WalletError::Storage {
            msg: format!("Postcard deserialisation failed: {}", e),
        })
    }

    /// Store raw bytes with an explicit biometric requirement.
    ///
    /// Use this for credential secrets or other sensitive data that should
    /// require biometric authentication before writing.
    pub fn store_with_bio(&self, key: &str, data: &[u8], bio: BiometricRequirement) -> Result<()> {
        self.backend.store(key, data, bio)
    }

    /// Retrieve raw bytes with an explicit biometric requirement.
    ///
    /// Use this for credential secrets or other sensitive data that should
    /// require biometric authentication before reading.
    pub fn retrieve_with_bio(
        &self,
        key: &str,
        bio: BiometricRequirement,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.backend.retrieve(key, bio)
    }

    /// List keys with a given prefix
    pub fn list_keys_with_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let all_keys = self.backend.list_keys()?;
        Ok(all_keys
            .into_iter()
            .filter(|k| k.starts_with(prefix))
            .collect())
    }

    /// Delete all keys with a given prefix.
    ///
    /// Continues on error so that a single failed deletion does not prevent
    /// the remaining keys from being removed. Returns the first error
    /// encountered after attempting all deletions, or `Ok(count)` if every
    /// deletion succeeded.
    pub fn delete_prefix(&self, prefix: &str) -> Result<usize> {
        let keys = self.list_keys_with_prefix(prefix)?;
        let count = keys.len();
        let mut first_error: Option<WalletError> = None;
        for key in &keys {
            if let Err(e) = self.backend.delete(key) {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        if let Some(e) = first_error {
            return Err(e);
        }
        Ok(count)
    }

    /// Get the underlying backend for direct access
    pub fn backend(&self) -> Arc<dyn PlatformSecureStorage> {
        Arc::clone(&self.backend)
    }
}

/// Standard key prefixes used by the wallet
pub mod keys {
    /// Wallet identity/configuration
    pub const WALLET_PREFIX: &str = "provii.wallet.";

    /// Credentials storage
    pub const CREDENTIAL_PREFIX: &str = "provii.cred.";

    /// Temporary/cache data
    pub const CACHE_PREFIX: &str = "provii.cache.";

    /// Settings and preferences
    pub const SETTINGS_PREFIX: &str = "provii.settings.";
}

// Re-export for convenience
pub use crate::WalletError as Error;

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
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Mock implementation of PlatformSecureStorage for testing
    struct MockStorage {
        data: Mutex<HashMap<String, Vec<u8>>>,
        fail_next_operation: Mutex<bool>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
                fail_next_operation: Mutex::new(false),
            }
        }

        fn set_fail_next(&self, fail: bool) {
            let Ok(mut guard) = self.fail_next_operation.lock() else {
                return;
            };
            *guard = fail;
        }

        fn check_fail(&self) -> Result<()> {
            if *self
                .fail_next_operation
                .lock()
                .map_err(|_| WalletError::Storage {
                    msg: "mutex poisoned".to_string(),
                })?
            {
                *self
                    .fail_next_operation
                    .lock()
                    .map_err(|_| WalletError::Storage {
                        msg: "mutex poisoned".to_string(),
                    })? = false;
                return Err(WalletError::Storage {
                    msg: "Simulated failure".to_string(),
                });
            }
            Ok(())
        }
    }

    impl PlatformSecureStorage for MockStorage {
        fn store(&self, key: &str, data: &[u8], _bio: BiometricRequirement) -> Result<()> {
            self.check_fail()?;
            self.data
                .lock()
                .map_err(|_| WalletError::Storage {
                    msg: "mutex poisoned".to_string(),
                })?
                .insert(key.to_string(), data.to_vec());
            Ok(())
        }

        fn retrieve(&self, key: &str, _bio: BiometricRequirement) -> Result<Zeroizing<Vec<u8>>> {
            self.check_fail()?;
            self.data
                .lock()
                .map_err(|_| WalletError::Storage {
                    msg: "mutex poisoned".to_string(),
                })?
                .get(key)
                .cloned()
                .map(Zeroizing::new)
                .ok_or(WalletError::NotFound)
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.check_fail()?;
            self.data
                .lock()
                .map_err(|_| WalletError::Storage {
                    msg: "mutex poisoned".to_string(),
                })?
                .remove(key)
                .ok_or(WalletError::NotFound)?;
            Ok(())
        }

        fn exists(&self, key: &str) -> Result<bool> {
            self.check_fail()?;
            Ok(self
                .data
                .lock()
                .map_err(|_| WalletError::Storage {
                    msg: "mutex poisoned".to_string(),
                })?
                .contains_key(key))
        }

        fn list_keys(&self) -> Result<Vec<String>> {
            self.check_fail()?;
            Ok(self
                .data
                .lock()
                .map_err(|_| WalletError::Storage {
                    msg: "mutex poisoned".to_string(),
                })?
                .keys()
                .cloned()
                .collect())
        }

        fn wipe_all(&self) -> Result<()> {
            self.check_fail()?;
            self.data
                .lock()
                .map_err(|_| WalletError::Storage {
                    msg: "mutex poisoned".to_string(),
                })?
                .clear();
            Ok(())
        }

        fn usage_stats(&self) -> Result<UsageStats> {
            self.check_fail()?;
            let data = self.data.lock().map_err(|_| WalletError::Storage {
                msg: "mutex poisoned".to_string(),
            })?;
            let total_bytes: usize = data.values().map(|v| v.len()).sum();
            Ok(UsageStats {
                total_keys: data.len(),
                total_bytes,
                credentials_count: data
                    .keys()
                    .filter(|k| k.starts_with(keys::CREDENTIAL_PREFIX))
                    .count(),
            })
        }
    }

    // ========== WalletError Tests ==========

    #[test]
    fn test_wallet_error_storage() {
        let error = WalletError::Storage {
            msg: "Disk full".to_string(),
        };
        assert_eq!(error.to_string(), "Storage error: Disk full");
    }

    #[test]
    fn test_wallet_error_not_found() {
        let error = WalletError::NotFound;
        assert_eq!(error.to_string(), "Not found");
    }

    #[test]
    fn test_wallet_error_already_exists() {
        let error = WalletError::AlreadyExists;
        assert_eq!(error.to_string(), "Already exists");
    }

    #[test]
    fn test_wallet_error_not_supported() {
        let error = WalletError::NotSupported;
        assert_eq!(error.to_string(), "Operation not supported");
    }

    // ========== UsageStats Tests ==========

    #[test]
    fn test_usage_stats_default() {
        let stats = UsageStats::default();
        assert_eq!(stats.total_keys, 0);
        assert_eq!(stats.total_bytes, 0);
        assert_eq!(stats.credentials_count, 0);
    }

    #[test]
    fn test_usage_stats_clone() {
        let stats = UsageStats {
            total_keys: 10,
            total_bytes: 1024,
            credentials_count: 5,
        };
        let cloned = stats.clone();
        assert_eq!(cloned.total_keys, 10);
        assert_eq!(cloned.total_bytes, 1024);
        assert_eq!(cloned.credentials_count, 5);
    }

    // ========== PlatformSecureStorage Trait Tests ==========

    /// Shorthand used by tests to store without biometric.
    fn bio_none() -> BiometricRequirement {
        BiometricRequirement::None
    }

    #[test]
    fn test_store_and_retrieve() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        let data = b"test data";

        storage.store("key1", data, bio_none())?;
        let retrieved = storage.retrieve("key1", bio_none())?;

        assert_eq!(*retrieved, data);
        Ok(())
    }

    #[test]
    fn test_retrieve_nonexistent_key() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        let result = storage.retrieve("nonexistent", bio_none());

        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        assert!(matches!(err_val, WalletError::NotFound));
        Ok(())
    }

    #[test]
    fn test_delete_key() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        storage.store("key1", b"data", bio_none())?;

        assert!(storage.exists("key1")?);
        storage.delete("key1")?;
        assert!(!storage.exists("key1")?);
        Ok(())
    }

    #[test]
    fn test_delete_nonexistent_key() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        let result = storage.delete("nonexistent");

        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        assert!(matches!(err_val, WalletError::NotFound));
        Ok(())
    }

    #[test]
    fn test_exists() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();

        assert!(!storage.exists("key1")?);
        storage.store("key1", b"data", bio_none())?;
        assert!(storage.exists("key1")?);
        Ok(())
    }

    #[test]
    fn test_list_keys() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        storage.store("key1", b"data1", bio_none())?;
        storage.store("key2", b"data2", bio_none())?;
        storage.store("key3", b"data3", bio_none())?;

        let keys = storage.list_keys()?;
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));
        assert!(keys.contains(&"key3".to_string()));
        Ok(())
    }

    #[test]
    fn test_list_keys_empty() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        let keys = storage.list_keys()?;
        assert_eq!(keys.len(), 0);
        Ok(())
    }

    #[test]
    fn test_wipe_all() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        storage.store("key1", b"data1", bio_none())?;
        storage.store("key2", b"data2", bio_none())?;

        storage.wipe_all()?;

        let keys = storage.list_keys()?;
        assert_eq!(keys.len(), 0);
        Ok(())
    }

    #[test]
    fn test_usage_stats() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        storage.store(
            &format!("{}cred1", keys::CREDENTIAL_PREFIX),
            b"cred_data",
            bio_none(),
        )?;
        storage.store("other_key", b"other_data", bio_none())?;

        let stats = storage.usage_stats()?;
        assert_eq!(stats.total_keys, 2);
        assert_eq!(stats.total_bytes, "cred_data".len() + "other_data".len());
        assert_eq!(stats.credentials_count, 1);
        Ok(())
    }

    #[test]
    fn test_rotate_master_key_default() {
        let storage = MockStorage::new();
        // Default implementation should be no-op
        let result = storage.rotate_master_key();
        assert!(result.is_ok());
    }

    // ========== SecureStore Wrapper Tests ==========

    #[test]
    fn test_secure_store_new() {
        let backend = Arc::new(MockStorage::new());
        let store = SecureStore::new(backend);

        // Test backend accessor
        let _backend_ref = store.backend();
    }

    #[test]
    fn test_store_string() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        let store = SecureStore::new(backend);

        store.store_string("key1", "Hello, World!")?;
        let retrieved = store.retrieve_string("key1")?;

        assert_eq!(&*retrieved, "Hello, World!");
        Ok(())
    }

    #[test]
    fn test_retrieve_string_invalid_utf8() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        backend.store("key1", &[0xFF, 0xFE, 0xFD], bio_none())?;

        let store = SecureStore::new(backend);
        let result = store.retrieve_string("key1");

        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            WalletError::Storage { msg } => {
                assert!(msg.contains("Invalid UTF-8"));
            }
            _ => panic!("Expected Storage error"),
        }
        Ok(())
    }

    #[test]
    fn test_store_json() -> std::result::Result<(), Box<dyn std::error::Error>> {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct TestData {
            name: String,
            value: u32,
        }

        let backend = Arc::new(MockStorage::new());
        let store = SecureStore::new(backend);

        let data = TestData {
            name: "test".to_string(),
            value: 42,
        };

        store.store_json("key1", &data)?;
        let retrieved: TestData = store.retrieve_json("key1")?;

        assert_eq!(retrieved, data);
        Ok(())
    }

    #[test]
    fn test_retrieve_json_invalid() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        backend.store("key1", b"not valid json", bio_none())?;

        let store = SecureStore::new(backend);
        let result: Result<serde_json::Value> = store.retrieve_json("key1");

        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            WalletError::Storage { msg } => {
                assert!(msg.contains("JSON deserialisation failed"));
            }
            _ => panic!("Expected Storage error"),
        }
        Ok(())
    }

    #[test]
    fn test_list_keys_with_prefix() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        backend.store("provii.cred.1", b"data1", bio_none())?;
        backend.store("provii.cred.2", b"data2", bio_none())?;
        backend.store("provii.wallet.config", b"data3", bio_none())?;

        let store = SecureStore::new(backend);
        let cred_keys = store.list_keys_with_prefix(keys::CREDENTIAL_PREFIX)?;

        assert_eq!(cred_keys.len(), 2);
        assert!(cred_keys.contains(&"provii.cred.1".to_string()));
        assert!(cred_keys.contains(&"provii.cred.2".to_string()));
        Ok(())
    }

    #[test]
    fn test_list_keys_with_prefix_no_matches() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let backend = Arc::new(MockStorage::new());
        backend.store("other.key", b"data", bio_none())?;

        let store = SecureStore::new(backend);
        let keys = store.list_keys_with_prefix(keys::CREDENTIAL_PREFIX)?;

        assert_eq!(keys.len(), 0);
        Ok(())
    }

    #[test]
    fn test_delete_prefix() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        backend.store("provii.cred.1", b"data1", bio_none())?;
        backend.store("provii.cred.2", b"data2", bio_none())?;
        backend.store("provii.wallet.config", b"data3", bio_none())?;

        let store = SecureStore::new(backend.clone());
        let deleted = store.delete_prefix(keys::CREDENTIAL_PREFIX)?;

        assert_eq!(deleted, 2);
        assert!(!backend.exists("provii.cred.1")?);
        assert!(!backend.exists("provii.cred.2")?);
        assert!(backend.exists("provii.wallet.config")?);
        Ok(())
    }

    #[test]
    fn test_delete_prefix_no_matches() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        backend.store("other.key", b"data", bio_none())?;

        let store = SecureStore::new(backend);
        let deleted = store.delete_prefix(keys::CREDENTIAL_PREFIX)?;

        assert_eq!(deleted, 0);
        Ok(())
    }

    #[test]
    fn test_secure_store_clone() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        let store1 = SecureStore::new(backend);
        let store2 = store1.clone();

        store1.store_string("key1", "value1")?;
        let retrieved = store2.retrieve_string("key1")?;

        assert_eq!(&*retrieved, "value1");
        Ok(())
    }

    // ========== Error Propagation Tests ==========

    #[test]
    fn test_error_propagation_store() {
        let backend = Arc::new(MockStorage::new());
        backend.set_fail_next(true);

        let result = backend.store("key1", b"data", bio_none());
        assert!(result.is_err());
    }

    #[test]
    fn test_error_propagation_retrieve() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        backend.store("key1", b"data", bio_none())?;
        backend.set_fail_next(true);

        let result = backend.retrieve("key1", bio_none());
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_error_propagation_delete() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        backend.store("key1", b"data", bio_none())?;
        backend.set_fail_next(true);

        let result = backend.delete("key1");
        assert!(result.is_err());
        Ok(())
    }

    // ========== Key Prefix Constants Tests ==========

    #[test]
    fn test_key_prefixes() {
        assert_eq!(keys::WALLET_PREFIX, "provii.wallet.");
        assert_eq!(keys::CREDENTIAL_PREFIX, "provii.cred.");
        assert_eq!(keys::CACHE_PREFIX, "provii.cache.");
        assert_eq!(keys::SETTINGS_PREFIX, "provii.settings.");
    }

    #[test]
    fn test_key_prefix_usage() {
        let cred_key = format!("{}credential_123", keys::CREDENTIAL_PREFIX);
        assert_eq!(cred_key, "provii.cred.credential_123");

        let wallet_key = format!("{}config", keys::WALLET_PREFIX);
        assert_eq!(wallet_key, "provii.wallet.config");
    }

    // ========== Thread Safety Tests ==========

    #[test]
    fn test_concurrent_access() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::thread;

        let backend = Arc::new(MockStorage::new());
        let mut handles = vec![];

        // Spawn 10 threads that each store a value
        for i in 0..10 {
            let backend_clone = Arc::clone(&backend);
            let handle = thread::spawn(move || -> std::result::Result<(), WalletError> {
                let key = format!("key{}", i);
                let data = format!("data{}", i);
                backend_clone.store(&key, data.as_bytes(), BiometricRequirement::None)?;
                Ok(())
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle
                .join()
                .map_err(|_| "thread panicked")?
                .map_err(|e| e.to_string())?;
        }

        // Verify all keys were stored
        let keys = backend.list_keys()?;
        assert_eq!(keys.len(), 10);
        Ok(())
    }

    // ========== Integration Tests ==========

    #[test]
    fn test_full_workflow() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        let store = SecureStore::new(backend);

        // Store multiple credentials
        store.store_string(&format!("{}cred1", keys::CREDENTIAL_PREFIX), "credential_1")?;
        store.store_string(&format!("{}cred2", keys::CREDENTIAL_PREFIX), "credential_2")?;

        // Store wallet config
        store.store_string(&format!("{}config", keys::WALLET_PREFIX), "config_data")?;

        // List credentials
        let creds = store.list_keys_with_prefix(keys::CREDENTIAL_PREFIX)?;
        assert_eq!(creds.len(), 2);

        // Delete one credential
        store
            .backend()
            .delete(&format!("{}cred1", keys::CREDENTIAL_PREFIX))?;

        // Verify deletion
        let creds = store.list_keys_with_prefix(keys::CREDENTIAL_PREFIX)?;
        assert_eq!(creds.len(), 1);

        // Verify wallet config still exists
        let config = store.retrieve_string(&format!("{}config", keys::WALLET_PREFIX))?;
        assert_eq!(&*config, "config_data");
        Ok(())
    }

    // ========== Edge Case Tests - Keys ==========

    #[test]
    fn test_empty_key() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        storage.store("", b"data", bio_none())?;
        assert!(storage.exists("")?);
        let retrieved = storage.retrieve("", bio_none())?;
        assert_eq!(*retrieved, b"data");
        Ok(())
    }

    #[test]
    fn test_very_long_key() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        let long_key = "k".repeat(10000);
        storage.store(&long_key, b"data", bio_none())?;
        let retrieved = storage.retrieve(&long_key, bio_none())?;
        assert_eq!(*retrieved, b"data");
        Ok(())
    }

    #[test]
    fn test_unicode_key() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        let key = "キー-123-🔑";
        storage.store(key, b"data", bio_none())?;
        let retrieved = storage.retrieve(key, bio_none())?;
        assert_eq!(*retrieved, b"data");
        Ok(())
    }

    #[test]
    fn test_special_chars_key() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        let key = "key/with\\special:chars*?+&=<>[]{}|";
        storage.store(key, b"data", bio_none())?;
        assert!(storage.exists(key)?);
        Ok(())
    }

    #[test]
    fn test_whitespace_key() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        storage.store("  key with spaces  ", b"data", bio_none())?;
        let retrieved = storage.retrieve("  key with spaces  ", bio_none())?;
        assert_eq!(*retrieved, b"data");
        Ok(())
    }

    #[test]
    fn test_newline_in_key() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        let key = "key\nwith\nnewlines";
        storage.store(key, b"data", bio_none())?;
        assert!(storage.exists(key)?);
        Ok(())
    }

    // ========== Edge Case Tests - Data ==========

    #[test]
    fn test_empty_data() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        storage.store("key1", b"", bio_none())?;
        let retrieved = storage.retrieve("key1", bio_none())?;
        assert_eq!(retrieved.len(), 0);
        Ok(())
    }

    #[test]
    fn test_very_large_data() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        let large_data = vec![0xAB; 1_000_000]; // 1MB
        storage.store("key1", &large_data, bio_none())?;
        let retrieved = storage.retrieve("key1", bio_none())?;
        assert_eq!(retrieved.len(), 1_000_000);
        assert_eq!(*retrieved, large_data);
        Ok(())
    }

    #[test]
    fn test_binary_data() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        let binary_data: Vec<u8> = (0..=255).collect();
        storage.store("key1", &binary_data, bio_none())?;
        let retrieved = storage.retrieve("key1", bio_none())?;
        assert_eq!(*retrieved, binary_data);
        Ok(())
    }

    #[test]
    fn test_null_bytes_in_data() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        let data = vec![0x00, 0x01, 0x00, 0x02, 0x00];
        storage.store("key1", &data, bio_none())?;
        let retrieved = storage.retrieve("key1", bio_none())?;
        assert_eq!(*retrieved, data);
        Ok(())
    }

    #[test]
    fn test_overwrite_existing_key() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        storage.store("key1", b"original", bio_none())?;
        storage.store("key1", b"overwritten", bio_none())?;
        let retrieved = storage.retrieve("key1", bio_none())?;
        assert_eq!(*retrieved, b"overwritten");
        Ok(())
    }

    // ========== Edge Case Tests - SecureStore String Operations ==========

    #[test]
    fn test_store_string_empty() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        let store = SecureStore::new(backend);
        store.store_string("key1", "")?;
        let retrieved = store.retrieve_string("key1")?;
        assert_eq!(&*retrieved, "");
        Ok(())
    }

    #[test]
    fn test_store_string_very_long() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        let store = SecureStore::new(backend);
        let long_string = "x".repeat(100000);
        store.store_string("key1", &long_string)?;
        let retrieved = store.retrieve_string("key1")?;
        assert_eq!(retrieved.len(), 100000);
        Ok(())
    }

    #[test]
    fn test_store_string_unicode() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        let store = SecureStore::new(backend);
        let unicode = "日本語 🎌 Ελληνικά 🇬🇷 Русский 🇷🇺";
        store.store_string("key1", unicode)?;
        let retrieved = store.retrieve_string("key1")?;
        assert_eq!(&*retrieved, unicode);
        Ok(())
    }

    #[test]
    fn test_store_string_with_newlines() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        let store = SecureStore::new(backend);
        let multiline = "Line 1\nLine 2\r\nLine 3\n";
        store.store_string("key1", multiline)?;
        let retrieved = store.retrieve_string("key1")?;
        assert_eq!(&*retrieved, multiline);
        Ok(())
    }

    // ========== Edge Case Tests - JSON Operations ==========

    #[test]
    fn test_store_json_empty_object() -> std::result::Result<(), Box<dyn std::error::Error>> {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Empty {}

        let backend = Arc::new(MockStorage::new());
        let store = SecureStore::new(backend);
        let data = Empty {};
        store.store_json("key1", &data)?;
        let retrieved: Empty = store.retrieve_json("key1")?;
        assert_eq!(retrieved, data);
        Ok(())
    }

    #[test]
    fn test_store_json_nested() -> std::result::Result<(), Box<dyn std::error::Error>> {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Nested {
            outer: String,
            inner: Inner,
        }

        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Inner {
            value: i32,
        }

        let backend = Arc::new(MockStorage::new());
        let store = SecureStore::new(backend);
        let data = Nested {
            outer: "test".to_string(),
            inner: Inner { value: 42 },
        };
        store.store_json("key1", &data)?;
        let retrieved: Nested = store.retrieve_json("key1")?;
        assert_eq!(retrieved, data);
        Ok(())
    }

    #[test]
    fn test_store_json_with_unicode() -> std::result::Result<(), Box<dyn std::error::Error>> {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct UnicodeData {
            text: String,
        }

        let backend = Arc::new(MockStorage::new());
        let store = SecureStore::new(backend);
        let data = UnicodeData {
            text: "日本語 🎌".to_string(),
        };
        store.store_json("key1", &data)?;
        let retrieved: UnicodeData = store.retrieve_json("key1")?;
        assert_eq!(retrieved.text, "日本語 🎌");
        Ok(())
    }

    #[test]
    fn test_store_json_vec() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        let store = SecureStore::new(backend);
        let data = vec![1, 2, 3, 4, 5];
        store.store_json("key1", &data)?;
        let retrieved: Vec<i32> = store.retrieve_json("key1")?;
        assert_eq!(&*retrieved, data);
        Ok(())
    }

    #[test]
    fn test_store_json_empty_vec() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        let store = SecureStore::new(backend);
        let data: Vec<i32> = vec![];
        store.store_json("key1", &data)?;
        let retrieved: Vec<i32> = store.retrieve_json("key1")?;
        assert_eq!(retrieved.len(), 0);
        Ok(())
    }

    #[test]
    fn test_store_json_large_vec() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        let store = SecureStore::new(backend);
        let data: Vec<i32> = (0..10000).collect();
        store.store_json("key1", &data)?;
        let retrieved: Vec<i32> = store.retrieve_json("key1")?;
        assert_eq!(retrieved.len(), 10000);
        Ok(())
    }

    // ========== Edge Case Tests - Prefix Operations ==========

    #[test]
    fn test_list_keys_with_empty_prefix() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        backend.store("key1", b"data1", bio_none())?;
        backend.store("key2", b"data2", bio_none())?;

        let store = SecureStore::new(backend);
        let all_keys = store.list_keys_with_prefix("")?;
        assert_eq!(all_keys.len(), 2);
        Ok(())
    }

    #[test]
    fn test_list_keys_with_unicode_prefix() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        backend.store("日本-key1", b"data1", bio_none())?;
        backend.store("日本-key2", b"data2", bio_none())?;
        backend.store("other-key", b"data3", bio_none())?;

        let store = SecureStore::new(backend);
        let keys = store.list_keys_with_prefix("日本-")?;
        assert_eq!(keys.len(), 2);
        Ok(())
    }

    #[test]
    fn test_delete_prefix_empty() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        backend.store("key1", b"data1", bio_none())?;
        backend.store("key2", b"data2", bio_none())?;

        let store = SecureStore::new(backend);
        let deleted = store.delete_prefix("")?;
        assert_eq!(deleted, 2);
        Ok(())
    }

    #[test]
    fn test_delete_prefix_unicode() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        backend.store("日本-key1", b"data1", bio_none())?;
        backend.store("日本-key2", b"data2", bio_none())?;
        backend.store("other-key", b"data3", bio_none())?;

        let store = SecureStore::new(backend.clone());
        let deleted = store.delete_prefix("日本-")?;
        assert_eq!(deleted, 2);
        assert!(backend.exists("other-key")?);
        Ok(())
    }

    #[test]
    fn test_delete_prefix_with_many_keys() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        for i in 0..100 {
            backend.store(&format!("prefix-{}", i), b"data", bio_none())?;
        }
        backend.store("other-key", b"data", bio_none())?;

        let store = SecureStore::new(backend.clone());
        let deleted = store.delete_prefix("prefix-")?;
        assert_eq!(deleted, 100);
        assert!(backend.exists("other-key")?);
        Ok(())
    }

    // ========== Edge Case Tests - Usage Stats ==========

    #[test]
    fn test_usage_stats_zero_values() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        let stats = storage.usage_stats()?;
        assert_eq!(stats.total_keys, 0);
        assert_eq!(stats.total_bytes, 0);
        assert_eq!(stats.credentials_count, 0);
        Ok(())
    }

    #[test]
    fn test_usage_stats_with_large_data() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        storage.store("key1", &vec![0; 1_000_000], bio_none())?;
        let stats = storage.usage_stats()?;
        assert_eq!(stats.total_keys, 1);
        assert_eq!(stats.total_bytes, 1_000_000);
        Ok(())
    }

    #[test]
    fn test_usage_stats_mixed_prefixes() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        storage.store(
            &format!("{}cred1", keys::CREDENTIAL_PREFIX),
            b"data1",
            bio_none(),
        )?;
        storage.store(
            &format!("{}cred2", keys::CREDENTIAL_PREFIX),
            b"data2",
            bio_none(),
        )?;
        storage.store(
            &format!("{}config", keys::WALLET_PREFIX),
            b"data3",
            bio_none(),
        )?;
        storage.store(
            &format!("{}cache", keys::CACHE_PREFIX),
            b"data4",
            bio_none(),
        )?;

        let stats = storage.usage_stats()?;
        assert_eq!(stats.total_keys, 4);
        assert_eq!(stats.credentials_count, 2);
        Ok(())
    }

    #[test]
    fn test_usage_stats_after_delete() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();
        storage.store("key1", b"data1", bio_none())?;
        storage.store("key2", b"data2", bio_none())?;

        storage.delete("key1")?;

        let stats = storage.usage_stats()?;
        assert_eq!(stats.total_keys, 1);
        Ok(())
    }

    // ========== Edge Case Tests - Error Scenarios ==========

    #[test]
    fn test_multiple_failed_operations() {
        let backend = Arc::new(MockStorage::new());

        for _ in 0..5 {
            backend.set_fail_next(true);
            assert!(backend.store("key", b"data", bio_none()).is_err());
        }
    }

    #[test]
    fn test_error_then_success() {
        let backend = Arc::new(MockStorage::new());

        backend.set_fail_next(true);
        assert!(backend.store("key", b"data", bio_none()).is_err());

        // Next operation should succeed
        assert!(backend.store("key", b"data", bio_none()).is_ok());
    }

    #[test]
    fn test_retrieve_after_failed_store() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());

        backend.set_fail_next(true);
        let _ = backend.store("key", b"data", bio_none());

        let result = backend.retrieve("key", bio_none());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        assert!(matches!(err_val, WalletError::NotFound));
        Ok(())
    }

    // ========== Edge Case Tests - Concurrent Operations ==========

    #[test]
    fn test_concurrent_stores_same_key() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::thread;

        let backend = Arc::new(MockStorage::new());
        let mut handles = vec![];

        for i in 0..10 {
            let backend_clone = Arc::clone(&backend);
            let handle = thread::spawn(move || -> std::result::Result<(), WalletError> {
                let data = format!("data{}", i);
                backend_clone.store("shared_key", data.as_bytes(), BiometricRequirement::None)?;
                Ok(())
            });
            handles.push(handle);
        }

        for handle in handles {
            handle
                .join()
                .map_err(|_| "thread panicked")?
                .map_err(|e| e.to_string())?;
        }

        // Key should exist, value is from last writer
        assert!(backend.exists("shared_key")?);
        Ok(())
    }

    #[test]
    fn test_concurrent_delete_operations() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::thread;

        let backend = Arc::new(MockStorage::new());

        for i in 0..20 {
            backend.store(&format!("key{}", i), b"data", bio_none())?;
        }

        let mut handles = vec![];
        for i in 0..20 {
            let backend_clone = Arc::clone(&backend);
            let handle = thread::spawn(move || {
                let _ = backend_clone.delete(&format!("key{}", i));
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().map_err(|_| "thread panicked")?;
        }

        let keys = backend.list_keys()?;
        assert_eq!(keys.len(), 0);
        Ok(())
    }

    #[test]
    fn test_concurrent_list_operations() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::thread;

        let backend = Arc::new(MockStorage::new());

        for i in 0..10 {
            backend.store(&format!("key{}", i), b"data", bio_none())?;
        }

        let mut handles = vec![];
        for _ in 0..10 {
            let backend_clone = Arc::clone(&backend);
            let handle = thread::spawn(move || -> std::result::Result<(), WalletError> {
                let keys = backend_clone.list_keys()?;
                assert!(keys.len() <= 10);
                Ok(())
            });
            handles.push(handle);
        }

        for handle in handles {
            handle
                .join()
                .map_err(|_| "thread panicked")?
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    // ========== Edge Case Tests - Mixed Operations ==========

    #[test]
    fn test_store_retrieve_delete_cycle() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();

        for i in 0..100 {
            let key = format!("key{}", i);
            storage.store(&key, b"data", bio_none())?;
            let _ = storage.retrieve(&key, bio_none())?;
            storage.delete(&key)?;
            assert!(!storage.exists(&key)?);
        }
        Ok(())
    }

    #[test]
    fn test_wipe_all_then_store() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = MockStorage::new();

        storage.store("key1", b"data1", bio_none())?;
        storage.store("key2", b"data2", bio_none())?;

        storage.wipe_all()?;
        assert_eq!(storage.list_keys()?.len(), 0);

        // Should be able to store after wipe
        storage.store("key3", b"data3", bio_none())?;
        assert!(storage.exists("key3")?);
        Ok(())
    }

    #[test]
    fn test_multiple_prefixes_operations() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        let store = SecureStore::new(backend);

        // Store with different prefixes
        store.store_string(&format!("{}cred1", keys::CREDENTIAL_PREFIX), "cred")?;
        store.store_string(&format!("{}wallet", keys::WALLET_PREFIX), "wallet")?;
        store.store_string(&format!("{}cache", keys::CACHE_PREFIX), "cache")?;
        store.store_string(&format!("{}setting", keys::SETTINGS_PREFIX), "setting")?;

        // Delete one prefix
        let deleted = store.delete_prefix(keys::CACHE_PREFIX)?;
        assert_eq!(deleted, 1);

        // Verify others remain
        assert!(store.list_keys_with_prefix(keys::CREDENTIAL_PREFIX)?.len() == 1);
        assert!(store.list_keys_with_prefix(keys::WALLET_PREFIX)?.len() == 1);
        assert!(store.list_keys_with_prefix(keys::SETTINGS_PREFIX)?.len() == 1);
        assert!(store.list_keys_with_prefix(keys::CACHE_PREFIX)?.is_empty());
        Ok(())
    }

    #[test]
    fn test_error_display_messages() {
        let err1 = WalletError::Storage {
            msg: "Test error".to_string(),
        };
        assert!(err1.to_string().contains("Storage error"));
        assert!(err1.to_string().contains("Test error"));

        let err2 = WalletError::NotFound;
        assert_eq!(err2.to_string(), "Not found");

        let err3 = WalletError::AlreadyExists;
        assert_eq!(err3.to_string(), "Already exists");

        let err4 = WalletError::NotSupported;
        assert_eq!(err4.to_string(), "Operation not supported");
    }

    #[test]
    fn test_secure_store_backend_access() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        let store = SecureStore::new(backend.clone());

        backend.store("key1", b"data1", bio_none())?;

        let backend_ref = store.backend();
        let retrieved = backend_ref.retrieve("key1", bio_none())?;
        assert_eq!(*retrieved, b"data1");
        Ok(())
    }

    // ========== BiometricRequirement Tests ==========

    #[test]
    fn test_biometric_requirement_none() {
        let bio = BiometricRequirement::None;
        assert!(matches!(bio, BiometricRequirement::None));
    }

    #[test]
    fn test_biometric_requirement_required() {
        let bio = BiometricRequirement::Required {
            config: BiometricConfig::default(),
        };
        match &bio {
            BiometricRequirement::Required { config } => {
                assert_eq!(config.timeout_seconds, 30);
            }
            _ => panic!("Expected Required variant"),
        }
    }

    #[test]
    fn test_biometric_config_default() {
        let config = BiometricConfig::default();
        assert_eq!(config.reason, "Access your credentials");
        assert_eq!(config.timeout_seconds, 30);
    }

    #[test]
    fn test_biometric_for_credential_secrets() {
        let bio = BiometricRequirement::for_credential_secrets();
        match &bio {
            BiometricRequirement::Required { config } => {
                assert!(config.reason.contains("credential secrets"));
            }
            _ => panic!("Expected Required variant"),
        }
    }

    #[test]
    fn test_biometric_for_export() {
        let bio = BiometricRequirement::for_export();
        match &bio {
            BiometricRequirement::Required { config } => {
                assert!(config.reason.contains("export"));
            }
            _ => panic!("Expected Required variant"),
        }
    }

    #[test]
    fn test_biometric_for_delete() {
        let bio = BiometricRequirement::for_delete();
        match &bio {
            BiometricRequirement::Required { config } => {
                assert!(config.reason.contains("delete"));
            }
            _ => panic!("Expected Required variant"),
        }
    }

    #[test]
    fn test_biometric_requirement_clone() {
        let bio = BiometricRequirement::for_credential_secrets();
        let cloned = bio.clone();
        match &cloned {
            BiometricRequirement::Required { config } => {
                assert!(config.reason.contains("credential secrets"));
            }
            _ => panic!("Expected Required variant"),
        }
    }

    #[test]
    fn test_wallet_error_biometric_required() {
        let error = WalletError::BiometricRequired;
        assert_eq!(error.to_string(), "Biometric authentication required");
    }

    #[test]
    fn test_wallet_error_biometric_failed() {
        let error = WalletError::BiometricFailed {
            msg: "User cancelled".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "Biometric authentication failed: User cancelled"
        );
    }

    #[test]
    fn test_store_with_bio() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let backend = Arc::new(MockStorage::new());
        let store = SecureStore::new(backend);

        store.store_with_bio(
            "secret_key",
            b"secret_data",
            BiometricRequirement::for_credential_secrets(),
        )?;

        let retrieved = store
            .retrieve_with_bio("secret_key", BiometricRequirement::for_credential_secrets())?;
        assert_eq!(*retrieved, b"secret_data");
        Ok(())
    }

    // ========== validate_key Tests ==========

    #[test]
    fn test_validate_key_valid() {
        assert!(MockStorage::validate_key("provii.cred.abc-123_def").is_ok());
    }

    #[test]
    fn test_validate_key_empty() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let Err(err) = MockStorage::validate_key("") else {
            panic!("expected error")
        };
        assert!(matches!(err, WalletError::Storage { .. }));
        Ok(())
    }

    #[test]
    fn test_validate_key_too_long() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let long = "a".repeat(256);
        let Err(err) = MockStorage::validate_key(&long) else {
            panic!("expected error")
        };
        assert!(matches!(err, WalletError::Storage { .. }));
        Ok(())
    }

    #[test]
    fn test_validate_key_max_length_ok() {
        let at_limit = "a".repeat(255);
        assert!(MockStorage::validate_key(&at_limit).is_ok());
    }

    #[test]
    fn test_validate_key_invalid_chars() {
        for bad in &[
            "key with space",
            "key/slash",
            "key:colon",
            "key*star",
            "key\nnewline",
        ] {
            assert!(
                MockStorage::validate_key(bad).is_err(),
                "should reject '{}'",
                bad
            );
        }
    }

    #[test]
    fn test_validate_key_allowed_chars() {
        assert!(MockStorage::validate_key("abc.def_ghi-123").is_ok());
        assert!(MockStorage::validate_key("A").is_ok());
        assert!(MockStorage::validate_key("0").is_ok());
    }
}
