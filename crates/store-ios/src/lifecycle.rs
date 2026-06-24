// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Construction, self-test, and storage-maintenance lifecycle methods for
//! the iOS Keychain backend.

use super::*;
use log::{error, info, warn};

impl IOSKeychainStorage {
    /// Create a new iOS Keychain storage instance with default configuration
    pub fn new() -> Arc<Self> {
        Self::new_with_config(StorageConfig::default())
    }

    /// Create a new iOS Keychain storage instance with custom configuration
    pub fn new_with_config(config: StorageConfig) -> Arc<Self> {
        INIT.call_once(|| {
            info!(
                "Initializing Provii iOS Keychain Storage v{}",
                env!("CARGO_PKG_VERSION")
            );
        });

        let device_capabilities = DeviceCapabilities::default();
        info!("Device capabilities: {:?}", device_capabilities);

        let cache = Arc::new(Mutex::new(ItemCache {
            items: HashMap::new(),
            max_size: if config.enable_caching {
                config.max_cache_size
            } else {
                0
            },
        }));

        Arc::new(Self {
            config,
            device_capabilities,
            cache,
            metrics: Arc::new(Mutex::new(StorageMetrics::default())),
            audit_log: Arc::new(Mutex::new(std::collections::VecDeque::new())),
        })
    }

    /// Test Keychain connectivity
    pub fn test_keychain_access(&self) -> Result<()> {
        let test_key = "provii.test.access";
        let test_data = b"test_data";

        self.store_secure(test_key, test_data, false)?;
        let retrieved = self.retrieve_secure(test_key, false)?;
        self.delete_secure(test_key)?;

        if *retrieved != test_data[..] {
            return Err(WalletError::Storage {
                msg: "Keychain test data mismatch".to_string(),
            });
        }

        Ok(())
    }

    /// Delete all items belonging to this service
    pub fn wipe_all(&self) -> Result<()> {
        let keys = self.list_keys_secure()?;
        for key in keys {
            if let Err(e) = self.delete_secure(&key) {
                warn!("Failed to delete key {}: {}", safe_key_label(&key), e);
            }
        }
        self.clear_cache();
        Ok(())
    }

    /// Rotate encryption keys (re-encrypt all items).
    ///
    /// Uses a backup-first pattern: all items are read into memory, then
    /// re-stored from the backup. Originals are only deleted after the
    /// re-store succeeds, so a crash mid-rotation cannot lose data.
    ///
    /// Decrypted credential data is held in `Zeroizing<Vec<u8>>` so that
    /// plaintext is cleared from memory after re-encryption.
    ///
    /// Each item is re-stored with its original biometric requirement
    /// preserved. Non-biometric items are read first, then biometric-protected
    /// items are read (triggering a single biometric prompt). Items whose
    /// biometric status cannot be determined are skipped to avoid downgrading
    /// their ACL.
    pub fn rotate_master_key(&self) -> Result<()> {
        let keys = self.list_keys_secure()?;

        // Phase 1a: Read all non-biometric items into an in-memory backup.
        // Items protected by biometric ACL will fail with errSecAuthFailed
        // when read without biometrics, so they are collected separately.
        let mut backup: Vec<(String, Zeroizing<Vec<u8>>, bool)> = Vec::with_capacity(keys.len());
        let mut bio_keys: Vec<String> = Vec::new();
        for key in &keys {
            match self.retrieve_secure(key, false) {
                Ok(data) => backup.push((key.clone(), data, false)),
                Err(_) => {
                    // Could not read without biometrics. This item is likely
                    // biometric-protected; collect it for phase 1b.
                    bio_keys.push(key.clone());
                }
            }
        }

        // Phase 1b: Read biometric-protected items. This will trigger a
        // biometric prompt on the first item; subsequent reads within the
        // same Keychain authentication session may succeed silently.
        for key in &bio_keys {
            match self.retrieve_secure(key, true) {
                Ok(data) => backup.push((key.clone(), data, true)),
                Err(e) => {
                    // Genuinely inaccessible (user cancelled, hardware error).
                    // Skip to avoid data loss; the item's Keychain ACL remains.
                    warn!(
                        "Key rotation: skip bio-protected key {}: {}",
                        safe_key_label(key),
                        e
                    );
                }
            }
        }

        // Phase 2: Re-store each item from backup with its ORIGINAL biometric
        // requirement. store_secure handles overwrite (delete+re-add for bio
        // items, update for non-bio items), so the old data is preserved until
        // the new write succeeds.
        let mut restore_failures = 0u32;
        for (key, data, was_bio) in &backup {
            if let Err(e) = self.store_secure(key, data, *was_bio) {
                error!(
                    "Key rotation: re-store failed for '{}' (original preserved): {}",
                    safe_key_label(key),
                    e
                );
                restore_failures += 1;
            }
        }
        // backup dropped here: Zeroizing clears all decrypted bytes

        if restore_failures > 0 {
            // Store rotation timestamp before returning the error so that
            // partial progress is recorded.
            let ts_bytes = current_timestamp().to_le_bytes();
            let _ = self.store_secure("__provii.rotated_at", &ts_bytes, false);

            self.log_security_event(
                SecurityEventType::KeyRotation,
                &format!(
                    "Master key rotation completed with {} re-store failure(s)",
                    restore_failures
                ),
                RiskLevel::High,
            );

            return Err(WalletError::Storage {
                msg: format!(
                    "Key rotation: {} of {} items failed to re-store",
                    restore_failures,
                    backup.len()
                ),
            });
        }

        // Store rotation timestamp
        let ts_bytes = current_timestamp().to_le_bytes();
        let _ = self.store_secure("__provii.rotated_at", &ts_bytes, false);

        // Log security event
        self.log_security_event(
            SecurityEventType::KeyRotation,
            "Master key rotation completed",
            RiskLevel::Low,
        );

        Ok(())
    }

    /// Get usage statistics
    pub fn usage_stats(&self) -> Result<UsageStats> {
        let keys = self.list_keys_secure()?;
        let mut total_size: usize = 0;
        let mut cred_count: usize = 0;

        for key in &keys {
            if let Ok(data) = self.retrieve_secure(key, false) {
                total_size += data.len();
                if key.starts_with(CREDENTIAL_KEY_PREFIX) {
                    cred_count += 1;
                }
            }
        }

        Ok(UsageStats {
            total_keys: keys.len(),
            total_bytes: total_size,
            credentials_count: cred_count,
        })
    }
}
