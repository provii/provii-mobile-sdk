// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Core Keychain Services operations, the public secure-access wrappers,
//! and the PlatformSecureStorage trait implementation for iOS.

use super::*;
use log::debug;

impl IOSKeychainStorage {
    /* ---------------------------------------------------------------
    Core Keychain Operations
    ------------------------------------------------------------- */

    fn store_item_internal(&self, key: &str, data: &[u8], require_bio: bool) -> Result<()> {
        // Build keychain query - use void pointers for generic dictionary
        let mut query: CFMutableDictionary<CFString, CFType> = CFMutableDictionary::new();

        // SAFETY: kSecClass is a framework-owned global constant. wrap_under_get_rule is
        // correct because we do not own this reference (the Security framework does).
        let class_key = unsafe { CFString::wrap_under_get_rule(kSecClass) };
        // SAFETY: kSecClassGenericPassword is a framework-owned global constant.
        // wrap_under_get_rule is correct because we do not own this reference.
        let class_value = unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) };
        query.set(class_key, class_value.as_CFType());

        // SAFETY: kSecAttrService is a framework-owned global constant. wrap_under_get_rule
        // is correct because we do not own this reference (the Security framework does).
        let service_key = unsafe { CFString::wrap_under_get_rule(kSecAttrService) };
        let service_value = CFString::new(&self.config.service_name);
        query.set(service_key, service_value.as_CFType());

        // SAFETY: kSecAttrAccount is a framework-owned global constant. wrap_under_get_rule
        // is correct because we do not own this reference (the Security framework does).
        let account_key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) };
        let account_value = CFString::new(key);
        query.set(account_key, account_value.as_CFType());

        // SAFETY: kSecValueData is a framework-owned global constant. wrap_under_get_rule
        // is correct because we do not own this reference (the Security framework does).
        let data_key = unsafe { CFString::wrap_under_get_rule(kSecValueData) };
        let data_value = CFData::from_buffer(data);
        query.set(data_key, data_value.as_CFType());

        // Explicitly disable iCloud Keychain synchronisation. Without this attribute the
        // default behaviour depends on the device's iCloud Keychain setting, which could
        // cause secret key material to be synced to Apple's servers.
        // SAFETY: kSecAttrSynchronizable is a framework-owned global constant.
        // wrap_under_get_rule is correct because we do not own this reference.
        let sync_key = unsafe { CFString::wrap_under_get_rule(kSecAttrSynchronizable) };
        query.set(sync_key, CFBoolean::false_value().as_CFType());

        // Set data protection: biometric access control OR kSecAttrAccessible.
        // iOS does not allow both kSecAttrAccessControl and kSecAttrAccessible
        // on the same Keychain item.
        if require_bio {
            // Create SecAccessControlRef with BiometryCurrentSet policy.
            // BiometryCurrentSet invalidates the item if biometrics are
            // re-enrolled, which is the stricter (correct) choice.
            let mut error: CFErrorRef = ptr::null_mut();
            // SAFETY: All arguments are valid: null allocator (uses default), a framework-owned
            // protection constant, an integer flag, and a pointer to a null-initialised error.
            // Returns a +1 retained SecAccessControlRef or null on failure.
            let access_control = unsafe {
                SecAccessControlCreateWithFlags(
                    ptr::null(),
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly as CFTypeRef,
                    KSEC_ACCESS_CONTROL_BIOMETRY_CURRENT_SET,
                    &mut error,
                )
            };

            // SAFETY: Release any CFError produced by SecAccessControlCreateWithFlags,
            // regardless of whether the call succeeded. Apple docs state the error
            // output may be populated even on success.
            if !error.is_null() {
                unsafe { CFRelease(error as CFTypeRef) };
            }

            if access_control.is_null() {
                return Err(WalletError::Storage {
                    msg: "Failed to create biometric access control".to_string(),
                });
            }
            // SAFETY: kSecAttrAccessControl is a framework-owned global constant.
            // wrap_under_get_rule is correct because we do not own this reference.
            let ac_key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) };
            // SAFETY: access_control is a +1 retained SecAccessControlRef returned by
            // SecAccessControlCreateWithFlags. wrap_under_create_rule takes ownership,
            // so we transfer the +1 retain to core-foundation's release-on-drop.
            let ac_value = unsafe { CFType::wrap_under_create_rule(access_control as CFTypeRef) };
            query.set(ac_key, ac_value);
        } else {
            // No biometrics: set explicit data protection class so the item
            // is only accessible while the device is unlocked and is excluded
            // from backups / device migration.
            // SAFETY: kSecAttrAccessible is a framework-owned global constant.
            // wrap_under_get_rule is correct because we do not own this reference.
            let accessible_key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccessible) };
            // SAFETY: kSecAttrAccessibleWhenUnlockedThisDeviceOnly is a framework-owned
            // global constant. wrap_under_get_rule is correct because we do not own this
            // reference (the Security framework does).
            let accessible_value = unsafe {
                CFType::wrap_under_get_rule(
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly as CFTypeRef,
                )
            };
            query.set(accessible_key, accessible_value);
        }

        let query_dict = query.as_concrete_TypeRef();

        // Try to add the item
        // SAFETY: query_dict is a valid CFDictionary constructed above. The null_mut() result
        // pointer indicates we do not need the persistent reference to the added item.
        let status = unsafe { SecItemAdd(query_dict as CFDictionaryRef, ptr::null_mut()) };

        match status {
            e if e == errSecSuccess => Ok(()),
            e if e == errSecDuplicateItem => {
                if require_bio {
                    // SecItemUpdate cannot modify kSecAttrAccessControl, so a plain
                    // update would silently drop the biometric ACL. Delete the
                    // existing item first, then re-add with the full ACL.
                    self.delete_item_internal(key)?;
                    // SAFETY: query_dict is still valid on the stack. Re-add the
                    // item with the biometric access control that was set above.
                    let re_add_status =
                        unsafe { SecItemAdd(query_dict as CFDictionaryRef, ptr::null_mut()) };
                    if re_add_status == errSecSuccess {
                        Ok(())
                    } else {
                        Err(self.map_keychain_error(re_add_status))
                    }
                } else {
                    // No biometric ACL to preserve; plain update is safe.
                    self.update_item_internal(key, data)
                }
            }
            _ => Err(self.map_keychain_error(status)),
        }
    }

    fn update_item_internal(&self, key: &str, data: &[u8]) -> Result<()> {
        let query = self.create_base_query(key);

        let mut update: CFMutableDictionary<CFString, CFType> = CFMutableDictionary::new();
        // SAFETY: kSecValueData is a framework-owned global constant. wrap_under_get_rule is
        // correct because we do not own this reference.
        let data_key = unsafe { CFString::wrap_under_get_rule(kSecValueData) };
        let data_value = CFData::from_buffer(data);
        update.set(data_key, data_value.as_CFType());

        // SAFETY: Both query and update_dict are valid CFDictionaries on the stack.
        // SecItemUpdate reads the query to find the item and applies the update dictionary.
        let status = unsafe {
            SecItemUpdate(
                query.as_concrete_TypeRef() as CFDictionaryRef,
                update.as_concrete_TypeRef() as CFDictionaryRef,
            )
        };

        if status == errSecSuccess {
            Ok(())
        } else {
            Err(self.map_keychain_error(status))
        }
    }

    fn retrieve_item_internal(&self, key: &str, require_bio: bool) -> Result<Zeroizing<Vec<u8>>> {
        let mut query = self.create_base_query(key);

        // Request data to be returned
        // SAFETY: kSecReturnData is a framework-owned global constant. wrap_under_get_rule is
        // correct because we do not own this reference.
        let return_data_key = unsafe { CFString::wrap_under_get_rule(kSecReturnData) };
        query.set(return_data_key, CFBoolean::true_value().as_CFType());

        if require_bio {
            // Set an operation prompt so the Keychain presents the biometric UI
            // when the item's ACL requires it. Without this, items protected by
            // BiometryCurrentSet may fail with errSecInteractionNotAllowed in
            // contexts where the system does not automatically prompt.
            // SAFETY: kSecUseOperationPrompt is a framework-owned global constant.
            // wrap_under_get_rule is correct because we do not own this reference.
            let prompt_key = unsafe { CFString::wrap_under_get_rule(kSecUseOperationPrompt) };
            let prompt_value = CFString::new("Authenticate to access credentials");
            query.set(prompt_key, prompt_value.as_CFType());
        }

        let mut result: CFTypeRef = ptr::null();
        // SAFETY: query is a valid CFDictionary (alive on the stack). result is initialised
        // to null. On success, SecItemCopyMatching returns a +1 retained CFTypeRef that the
        // caller must release. wrap_under_create_rule handles this ownership transfer.
        let status = unsafe {
            SecItemCopyMatching(query.as_concrete_TypeRef() as CFDictionaryRef, &mut result)
        };

        if status == errSecSuccess {
            if !result.is_null() {
                // Verify the returned type is actually CFData before downcasting
                // SAFETY: result is non-null (checked above) and is a valid +1 retained
                // CFTypeRef returned by SecItemCopyMatching.
                let type_id = unsafe { CFGetTypeID(result) };
                // SAFETY: CFDataGetTypeID is a pure function returning the type ID constant.
                let data_type_id = unsafe { CFDataGetTypeID() };
                if type_id != data_type_id {
                    // SAFETY: result is a valid +1 retained CFTypeRef. We must release it
                    // before returning an error to avoid a leak.
                    unsafe { CFRelease(result) };
                    return Err(WalletError::Storage {
                        msg: "SecItemCopyMatching returned unexpected CFType (expected CFData)"
                            .to_string(),
                    });
                }
                // SAFETY: We have verified result is a +1 retained CFDataRef via
                // CFGetTypeID check above. wrap_under_create_rule takes ownership.
                let data = unsafe { CFData::wrap_under_create_rule(result as *const _) };
                Ok(Zeroizing::new(data.bytes().to_vec()))
            } else {
                Err(WalletError::Storage {
                    msg: "Keychain returned null data".to_string(),
                })
            }
        } else if status == errSecItemNotFound {
            Err(WalletError::Storage {
                msg: "NotFound".to_string(),
            })
        } else {
            Err(self.map_keychain_error(status))
        }
    }

    fn delete_item_internal(&self, key: &str) -> Result<()> {
        let query = self.create_base_query(key);

        // SAFETY: query is a valid CFDictionary constructed by create_base_query.
        // SecItemDelete reads the query to identify and remove the matching Keychain item.
        let status = unsafe { SecItemDelete(query.as_concrete_TypeRef() as CFDictionaryRef) };

        match status {
            e if e == errSecSuccess => Ok(()),
            e if e == errSecItemNotFound => Ok(()), // Not an error
            _ => Err(self.map_keychain_error(status)),
        }
    }

    fn list_keys_internal(&self) -> Result<Vec<String>> {
        let mut query: CFMutableDictionary<CFString, CFType> = CFMutableDictionary::new();

        // SAFETY: All kSec* constants below are framework-owned global CFStringRef values.
        // wrap_under_get_rule is correct because we do not own these references.
        let class_key = unsafe { CFString::wrap_under_get_rule(kSecClass) };
        let class_value = unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) };
        query.set(class_key, class_value.as_CFType());

        let service_key = unsafe { CFString::wrap_under_get_rule(kSecAttrService) };
        let service_value = CFString::new(&self.config.service_name);
        query.set(service_key, service_value.as_CFType());

        let return_attrs_key = unsafe { CFString::wrap_under_get_rule(kSecReturnAttributes) };
        query.set(return_attrs_key, CFBoolean::true_value().as_CFType());

        let match_limit_key = unsafe { CFString::wrap_under_get_rule(kSecMatchLimit) };
        let match_limit_all = unsafe { CFString::wrap_under_get_rule(kSecMatchLimitAll) };
        query.set(match_limit_key, match_limit_all.as_CFType());

        let mut result: CFTypeRef = ptr::null();
        // SAFETY: query is a valid CFDictionary (alive on the stack). result is initialised
        // to null. On success, SecItemCopyMatching returns a +1 retained CFTypeRef that the
        // caller must release. wrap_under_create_rule handles this ownership transfer.
        let status = unsafe {
            SecItemCopyMatching(query.as_concrete_TypeRef() as CFDictionaryRef, &mut result)
        };

        if status == errSecItemNotFound {
            return Ok(Vec::new());
        }

        if status != errSecSuccess {
            return Err(self.map_keychain_error(status));
        }

        // Parse the results
        let mut keys = Vec::new();
        if !result.is_null() {
            // Verify the returned type is actually CFArray before downcasting
            // SAFETY: result is non-null (checked above) and is a valid +1 retained
            // CFTypeRef returned by SecItemCopyMatching.
            let type_id = unsafe { CFGetTypeID(result) };
            // SAFETY: CFArrayGetTypeID is a pure function returning the type ID constant.
            let array_type_id = unsafe { CFArrayGetTypeID() };
            if type_id != array_type_id {
                // SAFETY: result is a valid +1 retained CFTypeRef. We must release it
                // before returning an error to avoid a leak.
                unsafe { CFRelease(result) };
                return Err(WalletError::Storage {
                    msg: "SecItemCopyMatching returned unexpected CFType (expected CFArray)"
                        .to_string(),
                });
            }
            // SAFETY: We have verified result is a +1 retained CFArrayRef via
            // CFGetTypeID check above. wrap_under_create_rule takes ownership.
            let array = unsafe {
                CFArray::<CFDictionary<CFString, CFType>>::wrap_under_create_rule(
                    result as *const _,
                )
            };

            // SAFETY: kSecAttrAccount is a framework-owned global constant.
            // wrap_under_get_rule is correct because we do not own this reference.
            let account_key_cf = unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) };

            for i in 0..array.len() {
                if let Some(item_dict) = array.get(i) {
                    // Find the account value in the dictionary
                    if let Some(account_value_ref) = item_dict.find(account_key_cf.clone()) {
                        // The value is already a reference to a CFType, extract as CFString
                        if let Some(account_cfstring) = account_value_ref.downcast::<CFString>() {
                            keys.push(account_cfstring.to_string());
                        }
                    }
                }
            }
        }

        Ok(keys)
    }

    /* ---------------------------------------------------------------
    Helper Methods
    ------------------------------------------------------------- */

    fn create_base_query(&self, key: &str) -> CFMutableDictionary<CFString, CFType> {
        let mut query = CFMutableDictionary::new();

        // SAFETY: All kSec* constants below are framework-owned global CFStringRef values.
        // wrap_under_get_rule is the correct ownership rule because we do not own these
        // references. The Security framework owns them and they remain valid for the process lifetime.
        let class_key = unsafe { CFString::wrap_under_get_rule(kSecClass) };
        let class_value = unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) };
        query.set(class_key, class_value.as_CFType());

        let service_key = unsafe { CFString::wrap_under_get_rule(kSecAttrService) };
        let service_value = CFString::new(&self.config.service_name);
        query.set(service_key, service_value.as_CFType());

        let account_key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) };
        let account_value = CFString::new(key);
        query.set(account_key, account_value.as_CFType());

        query
    }

    /// Metadata-only existence check. Queries the Keychain for attributes
    /// without requesting kSecReturnData, so the item is never decrypted.
    fn exists_internal(&self, key: &str) -> Result<bool> {
        let mut query = self.create_base_query(key);

        // Request attributes only, not the actual data
        // SAFETY: kSecReturnAttributes is a framework-owned global constant.
        // wrap_under_get_rule is correct because we do not own this reference.
        let return_attrs_key = unsafe { CFString::wrap_under_get_rule(kSecReturnAttributes) };
        query.set(return_attrs_key, CFBoolean::true_value().as_CFType());

        let mut result: CFTypeRef = ptr::null();
        // SAFETY: query is a valid CFDictionary on the stack. result is initialised
        // to null. SecItemCopyMatching reads the query to find a matching item.
        let status = unsafe {
            SecItemCopyMatching(query.as_concrete_TypeRef() as CFDictionaryRef, &mut result)
        };

        if !result.is_null() {
            // SAFETY: result is a valid +1 retained CFTypeRef. Release it since
            // we only care about the status code.
            unsafe { CFRelease(result) };
        }

        match status {
            e if e == errSecSuccess => Ok(true),
            e if e == errSecItemNotFound => Ok(false),
            _ => Err(self.map_keychain_error(status)),
        }
    }

    fn map_keychain_error(&self, status: i32) -> WalletError {
        let msg = match status {
            e if e == errSecItemNotFound => "NotFound",
            e if e == errSecDuplicateItem => "Duplicate item",
            e if e == errSecAuthFailed => "Authentication failed",
            e if e == ERRSEC_USER_CANCELED => "User cancelled",
            _ => "Keychain error",
        };

        WalletError::Storage {
            msg: format!("{} (OSStatus: {})", msg, status),
        }
    }

    /* ---------------------------------------------------------------
    Public Methods
    ------------------------------------------------------------- */

    /// Store a value in the Keychain with optional biometric protection.
    ///
    /// Validates the key and data, then writes to the Keychain with retry
    /// logic. When `require_bio` is true, the item is protected by
    /// `BiometryCurrentSet` access control.
    pub fn store_secure(&self, key: &str, data: &[u8], require_bio: bool) -> Result<()> {
        let start_time = current_timestamp();

        self.validate_key(key)?;
        self.validate_data(data)?;

        // Biometric operations must not be retried: a retry would re-prompt the
        // user and mask genuine authentication failures.
        let result = if require_bio {
            self.store_item_internal(key, data, require_bio)
        } else {
            self.with_retry(MAX_KEYCHAIN_RETRIES, || {
                self.store_item_internal(key, data, require_bio)
            })
        };

        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
            metrics.operations_count += 1;
            if result.is_err() {
                metrics.errors_count += 1;
                metrics.last_error = Some(format!("Store failed for key: {}", safe_key_label(key)));
            }
        }

        // Update global stats
        {
            let mut stats = OPERATION_STATS.lock().unwrap_or_else(|e| e.into_inner());
            stats.record_operation(result.is_ok(), require_bio);
        }

        // SECURITY: Only cache non-biometric items. Caching biometric-protected
        // items would allow subsequent retrieves to bypass the biometric gate,
        // defeating the purpose of biometric protection entirely.
        if result.is_ok() && self.config.enable_caching && !require_bio {
            self.add_to_cache(key, data);
        }

        // Log security event
        if result.is_ok() {
            self.log_security_event(
                SecurityEventType::KeychainAccess,
                &format!("Stored item: {}", safe_key_label(key)),
                RiskLevel::Low,
            );
        } else {
            self.log_security_event(
                SecurityEventType::FailedOperation,
                &format!("Failed to store: {}", safe_key_label(key)),
                RiskLevel::Medium,
            );
        }

        let elapsed = current_timestamp() - start_time;
        debug!("Store operation completed in {}ms", elapsed);

        result
    }

    /// Retrieve a value from the Keychain, checking the cache first.
    ///
    /// Returns the data wrapped in [`Zeroizing`] so memory is cleared on drop.
    /// When `require_bio` is true, the Keychain presents a biometric prompt.
    pub fn retrieve_secure(&self, key: &str, require_bio: bool) -> Result<Zeroizing<Vec<u8>>> {
        let start_time = current_timestamp();

        // SECURITY: Only serve from cache when biometric is NOT required.
        // Returning cached data would bypass the biometric gate.
        if !require_bio {
            if let Some(cached_data) = self.get_from_cache(key) {
                let mut metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
                metrics.cache_hits += 1;
                return Ok(cached_data);
            }
        }

        if self.config.enable_caching {
            let mut metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
            metrics.cache_misses += 1;
        }

        self.validate_key(key)?;

        // Biometric operations must not be retried: a retry would re-prompt the
        // user and mask genuine authentication failures.
        let result = if require_bio {
            self.retrieve_item_internal(key, require_bio)
        } else {
            self.with_retry(MAX_KEYCHAIN_RETRIES, || {
                self.retrieve_item_internal(key, require_bio)
            })
        };

        // Update metrics
        {
            let mut metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
            metrics.operations_count += 1;
            if result.is_err() {
                metrics.errors_count += 1;
                metrics.last_error =
                    Some(format!("Retrieve failed for key: {}", safe_key_label(key)));
            }
        }

        // SECURITY: Only cache non-biometric items. Caching biometric-protected
        // items would allow subsequent retrieves to bypass the biometric gate,
        // defeating the purpose of biometric protection entirely.
        if let Ok(ref data) = result {
            if self.config.enable_caching && !require_bio {
                self.add_to_cache(key, data);
            }
        }

        let elapsed = current_timestamp() - start_time;
        debug!("Retrieve operation completed in {}ms", elapsed);

        result
    }

    /// Delete a key from the Keychain and evict it from the cache.
    pub fn delete_secure(&self, key: &str) -> Result<()> {
        self.validate_key(key)?;

        let result = self.delete_item_internal(key);

        // Remove from cache
        if self.config.enable_caching {
            self.remove_from_cache(key);
        }

        // Log security event
        self.log_security_event(
            SecurityEventType::KeychainAccess,
            &format!("Deleted item: {}", safe_key_label(key)),
            RiskLevel::Low,
        );

        result
    }

    /// List all key names stored under this service in the Keychain.
    pub fn list_keys_secure(&self) -> Result<Vec<String>> {
        self.list_keys_internal()
    }
}

/* =======================================================================
PlatformSecureStorage Trait Implementation
=================================================================== */

impl PlatformSecureStorage for IOSKeychainStorage {
    fn store(&self, key: &str, data: &[u8], bio: BiometricRequirement) -> Result<()> {
        let require_bio = matches!(bio, BiometricRequirement::Required { .. });
        debug!(
            "Storing item with key: {} ({} bytes, bio={})",
            safe_key_label(key),
            data.len(),
            require_bio
        );
        self.store_secure(key, data, require_bio)
    }

    fn retrieve(&self, key: &str, bio: BiometricRequirement) -> Result<Zeroizing<Vec<u8>>> {
        let require_bio = matches!(bio, BiometricRequirement::Required { .. });
        debug!(
            "Retrieving item with key: {} (bio={})",
            safe_key_label(key),
            require_bio
        );
        self.retrieve_secure(key, require_bio)
    }

    fn delete(&self, key: &str) -> Result<()> {
        debug!("Deleting item with key: {}", safe_key_label(key));
        self.delete_secure(key)
    }

    fn exists(&self, key: &str) -> Result<bool> {
        self.validate_key(key)?;
        self.exists_internal(key)
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        self.list_keys_secure()
    }

    fn wipe_all(&self) -> Result<()> {
        self.wipe_all()
    }

    fn rotate_master_key(&self) -> Result<()> {
        self.rotate_master_key()
    }

    fn usage_stats(&self) -> Result<UsageStats> {
        self.usage_stats()
    }
}

/* =======================================================================
Utility Functions
=================================================================== */

pub(crate) fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Return a privacy-safe representation of a storage key for logging.
///
/// Shows only the prefix (up to the first dot or underscore after position 6)
/// and a truncated hash, so credential identifiers never appear in logs.
pub(crate) fn safe_key_label(key: &str) -> String {
    let prefix_end = key[..key.len().min(20)]
        .find('.')
        .or_else(|| key[..key.len().min(20)].find('_'))
        .map(|i| i + 1)
        .unwrap_or(key.len().min(8));
    let hash = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        key.hash(&mut h);
        format!("{:08x}", h.finish() & 0xFFFF_FFFF)
    };
    format!("{}..{}", &key[..prefix_end], hash)
}
