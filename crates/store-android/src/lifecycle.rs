// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Construction, initialisation, self-test, and storage-maintenance
//! lifecycle methods for the Android Keystore backend.

use super::*;

impl AndroidSecureStorage {
    /// Create a new storage instance with the given configuration.
    ///
    /// Initialises the JNI environment, assesses hardware security features,
    /// and validates that the device meets minimum requirements (API 29+,
    /// hardware keystore present unless `allow_software_keystore` is set).
    pub fn new_with_config(config: StorageConfig) -> Result<Arc<Self>> {
        INIT.call_once(|| {
            // Initialize Android logging
            #[cfg(target_os = "android")]
            android_logger::init_once(
                android_logger::Config::default().with_max_level(log::LevelFilter::Debug),
            );
        });

        let temp_self = Arc::new(Self {
            config,
            device_profile: Arc::new(RwLock::new(None)),
            keystore_bridge: Arc::new(Mutex::new(None)),
            audit_log: Arc::new(Mutex::new(VecDeque::new())),
            metrics: Arc::new(Mutex::new(StorageMetrics::default())),
            operation_cache: Arc::new(RwLock::new(HashMap::new())),
        });

        // Initialize hardware features assessment
        temp_self.initialize()?;
        Ok(temp_self)
    }

    fn initialize(&self) -> Result<()> {
        let mut guard = self.get_jni_env()?;
        let env = &mut *guard;

        let device_profile = self.assess_hardware_features(env)?;
        Self::validate_hardware_requirements(&device_profile, &self.config)?;

        *self
            .device_profile
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(device_profile);
        Ok(())
    }

    /* ---------------------------------------------------------------
    Public Diagnostic Methods
    ------------------------------------------------------------- */

    /// Test keystore connectivity and functionality
    pub fn test_keystore_functionality(&self) -> Result<()> {
        let test_key = "provii_test_connectivity";
        let test_data = b"test_data_12345";

        // Test store operation
        self.store_secure(test_key, test_data, false)?;

        // Test retrieve operation
        let retrieved = self.retrieve_secure(test_key, false)?;
        if *retrieved != test_data[..] {
            return Err(WalletError::Storage {
                msg: "Keystore test data mismatch".to_string(),
            });
        }

        // Test delete operation
        self.delete_secure(test_key)?;

        // Verify deletion
        match self.retrieve_secure(test_key, false) {
            Err(WalletError::Storage { msg }) if msg == "NotFound" => Ok(()),
            _ => Err(WalletError::Storage {
                msg: "Keystore delete test failed".to_string(),
            }),
        }
    }

    /* ---------------------------------------------------------------
    Storage-maintenance helpers (parity with iOS backend)
    ------------------------------------------------------------- */

    /// Remove **all** Provii entries from the Android Keystore and cache.
    pub fn wipe_all(&self) -> Result<()> {
        let keys = self.list_keys_secure()?;
        for k in keys {
            if let Err(e) = self.delete_secure(&k) {
                log::warn!(
                    "Failed to delete key {} during wipe_all: {:?}",
                    safe_key_label(&k),
                    e
                );
            }
        }
        self.clear_cache();
        Ok(())
    }

    /// Re-encrypt every item with a *new* AES-GCM master key.
    ///
    /// Decrypted credential data is held in `Zeroizing<Vec<u8>>` so that the
    /// plaintext backup is cleared from memory once re-encryption completes.
    ///
    /// Each item is re-stored with its original biometric requirement
    /// preserved. Non-biometric items are read first, then biometric-protected
    /// items are read (triggering a biometric prompt). Items whose biometric
    /// status cannot be determined are skipped to avoid downgrading their ACL.
    ///
    /// ## Data loss window
    ///
    /// The Java-side `rotateMasterKey()` atomically destroys the old master
    /// key and creates a new one. There is a window between the key swap and
    /// the re-store loop where a crash would leave items encrypted under a
    /// destroyed key. A true two-phase rotation (store under new key first,
    /// delete old key after verification) would require changes to the Kotlin
    /// `KeystoreBridge`. This limitation is accepted for now. The backup is
    /// verified before proceeding, and a failure count is returned so callers
    /// can detect partial data loss.
    pub(crate) fn rotate_master_key(&self) -> Result<()> {
        let mut guard = self.get_jni_env()?;
        let env = &mut *guard;

        let keys = self.list_keys_secure()?;

        // Phase 1a: Read all non-biometric items. Biometric-protected items
        // will fail here and are collected for a second pass.
        let mut backup: Vec<(String, Zeroizing<Vec<u8>>, bool)> = Vec::new();
        let mut bio_keys: Vec<String> = Vec::new();
        for k in &keys {
            match self.retrieve_secure(k, false) {
                Ok(d) => backup.push((k.clone(), d, false)),
                Err(_) => bio_keys.push(k.clone()),
            }
        }

        // Phase 1b: Read biometric-protected items (triggers biometric prompt).
        for k in &bio_keys {
            match self.retrieve_secure(k, true) {
                Ok(d) => backup.push((k.clone(), d, true)),
                Err(e) => {
                    log::warn!(
                        "Key rotation: skip bio-protected key {}: {}",
                        safe_key_label(k),
                        e
                    );
                }
            }
        }

        // Phase 2: Verify that every non-skipped key was successfully backed
        // up before performing the destructive master key swap. If the backup
        // is empty but keys existed, something went wrong and we must not
        // proceed.
        let expected_count = keys.len();
        let skipped = expected_count.saturating_sub(backup.len());
        if backup.is_empty() && expected_count > 0 {
            return Err(WalletError::Storage {
                msg: "Key rotation aborted: could not read any items for backup".to_string(),
            });
        }
        if skipped > 0 {
            log::warn!(
                "Key rotation: {} of {} items could not be backed up and will be skipped",
                skipped,
                expected_count
            );
        }

        // Phase 3: Rotate the master key. This is the destructive operation.
        // Items encrypted under the old key become unreadable after this point.
        let bridge = self.get_keystore_bridge(env)?;
        let recreated = Self::jni_safe_call(env, |e| {
            e.call_method(&bridge, "rotateMasterKey", "()Z", &[])
                .and_then(|v| v.z())
        })?;

        if !recreated {
            return Err(WalletError::Storage {
                msg: "Failed to rotate master key".into(),
            });
        }

        // Phase 4: Re-store each item under the new master key with its
        // ORIGINAL biometric requirement preserved. Count failures so the
        // caller knows data was lost.
        let backup_len = backup.len();
        let mut failures = 0u32;
        for (k, d, was_bio) in &backup {
            if let Err(e) = self.store_secure(k, d, *was_bio) {
                log::error!(
                    "Key rotation: re-store failed for '{}': {}",
                    safe_key_label(k),
                    e
                );
                failures += 1;
            }
        }
        // backup dropped here: Zeroizing clears all decrypted data from memory

        if failures > 0 {
            return Err(WalletError::Storage {
                msg: format!(
                    "Key rotation: {} of {} items failed to re-store (data may be lost)",
                    failures, backup_len
                ),
            });
        }

        Ok(())
    }

    /// Provide lightweight usage metrics for the SDK settings screen.
    pub fn usage_stats(&self) -> Result<UsageStats> {
        let keys = self.list_keys_secure()?;
        let mut total_size: usize = 0;
        let mut cred_cnt: usize = 0;

        for k in &keys {
            if let Ok(d) = self.retrieve_secure(k, false) {
                total_size += d.len();
                if k.starts_with(CREDENTIAL_KEY_PREFIX) {
                    cred_cnt += 1;
                }
            }
        }

        Ok(UsageStats {
            total_keys: keys.len(),
            total_bytes: total_size,
            credentials_count: cred_cnt,
        })
    }
}
