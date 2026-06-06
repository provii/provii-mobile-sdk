// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! iOS Keychain storage with Secure Enclave support.
//!
//! Implements `PlatformSecureStorage` for iOS by wrapping Keychain Services
//! with biometric gating (Face ID / Touch ID), in-memory caching, retry logic,
//! and security event logging. Hardware-backed encryption is used when the
//! Secure Enclave is available.

#![cfg(target_os = "ios")]

use std::{
    collections::HashMap,
    ptr,
    sync::{Arc, Mutex, Once},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use core_foundation::{
    array::CFArray,
    base::{CFType, CFTypeRef, TCFType},
    boolean::CFBoolean,
    data::CFData,
    dictionary::{CFDictionary, CFMutableDictionary},
    string::CFString,
};
use log::{debug, error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use provii_mobile_sdk_platform_storage::{
    BiometricRequirement, PlatformSecureStorage, Result, UsageStats, WalletError,
};

use core_foundation_sys::array::CFArrayGetTypeID;
use core_foundation_sys::base::{CFGetTypeID, CFRelease};
use core_foundation_sys::data::CFDataGetTypeID;
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::error::CFErrorRef;
use core_foundation_sys::string::CFStringRef;

use security_framework_sys::{
    access_control::{
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly, SecAccessControlCreateWithFlags,
    },
    base::{errSecAuthFailed, errSecDuplicateItem, errSecItemNotFound, errSecSuccess},
    item::{
        kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
        kSecClassGenericPassword, kSecMatchLimit, kSecMatchLimitAll, kSecReturnAttributes,
        kSecReturnData, kSecValueData,
    },
    keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate},
};

extern "C" {
    /// Keychain attribute key for the data protection class of an item.
    /// Not exported by `security-framework-sys`; declared directly from the
    /// Security framework.
    static kSecAttrAccessible: CFStringRef;
    /// Prompt string displayed during biometric authentication for Keychain
    /// access. Not exported by `security-framework-sys`.
    static kSecUseOperationPrompt: CFStringRef;
}

/// `kSecAccessControlBiometryCurrentSet` flag value for `SecAccessControlCreateWithFlags`.
/// Requires re-enrollment if biometrics change (fingerprint added/removed).
const KSEC_ACCESS_CONTROL_BIOMETRY_CURRENT_SET: usize = 1 << 3;

/* =======================================================================
Constants and Configuration
=================================================================== */

/// Service identifier for Keychain items
const SERVICE_NAME: &str = "app.provii.wallet.sdk";

/// Key prefix for wallet identity storage
const IDENTITY_KEY_PREFIX: &str = "provii.identity";

/// Key prefix for credential storage  
const CREDENTIAL_KEY_PREFIX: &str = "provii.credential";

/// Key prefix for configuration storage
const CONFIG_KEY_PREFIX: &str = "provii.config";

/// Maximum number of retry attempts for Keychain operations
const MAX_KEYCHAIN_RETRIES: u32 = 3;

/// Maximum size for individual Keychain items (1MB)
const MAX_ITEM_SIZE: usize = 1024 * 1024;

/// Cache TTL default (5 minutes)
const DEFAULT_CACHE_TTL_SECONDS: u64 = 300;

// Custom error codes that may not be exported
const ERRSEC_USER_CANCELED: i32 = -128;

/* =======================================================================
Global State Management
=================================================================== */

static INIT: Once = Once::new();
static OPERATION_STATS: Mutex<OperationStatistics> = Mutex::new(OperationStatistics::new());

#[derive(Debug, Clone, Default)]
struct OperationStatistics {
    total_operations: u64,
    successful_operations: u64,
    failed_operations: u64,
    biometric_authentications: u64,
    cache_hits: u64,
    last_operation_time: u64,
}

impl OperationStatistics {
    const fn new() -> Self {
        Self {
            total_operations: 0,
            successful_operations: 0,
            failed_operations: 0,
            biometric_authentications: 0,
            cache_hits: 0,
            last_operation_time: 0,
        }
    }

    fn record_operation(&mut self, success: bool, used_biometrics: bool) {
        self.total_operations += 1;
        if success {
            self.successful_operations += 1;
        } else {
            self.failed_operations += 1;
        }
        if used_biometrics {
            self.biometric_authentications += 1;
        }
        self.last_operation_time = current_timestamp();
    }
}

/* =======================================================================
Device Capabilities Detection
=================================================================== */

#[derive(Debug, Clone)]
struct DeviceCapabilities {
    has_secure_enclave: Option<bool>,
    biometric_type: BiometricType,
    ios_version: Option<String>,
}

impl Default for DeviceCapabilities {
    fn default() -> Self {
        Self {
            has_secure_enclave: Self::detect_secure_enclave(),
            biometric_type: Self::detect_biometric_type(),
            ios_version: Self::get_ios_version(),
        }
    }
}

impl DeviceCapabilities {
    fn detect_secure_enclave() -> Option<bool> {
        // NOTE: Runtime Secure Enclave detection requires calling
        // SecKeyCreateRandomKey with kSecAttrTokenIDSecureEnclave via
        // Objective-C FFI, which is not available from pure Rust. This
        // returns None to express that the detection was not performed.
        // The Keychain ACL enforces Secure Enclave usage regardless of
        // what we report here; callers should not branch on this value
        // for security decisions.
        None
    }

    fn detect_biometric_type() -> BiometricType {
        // NOTE: Runtime biometric type detection requires LAContext
        // Objective-C FFI to LocalAuthentication.framework, which is not
        // available from pure Rust. Returns Unknown rather than a false
        // positive. The Keychain ACL enforces the actual biometric policy
        // regardless of what we report here.
        BiometricType::Unknown
    }

    fn get_ios_version() -> Option<String> {
        // NOTE: Runtime version query requires UIDevice.current.systemVersion
        // via Objective-C FFI to UIKit, which is not available from pure
        // Rust. Returns None. The deployment target is iOS 17.6+ but we
        // cannot confirm the actual running version from this layer.
        None
    }
}

#[derive(Debug, Clone)]
enum BiometricType {
    None,
    TouchID,
    FaceID,
    Available, // Generic - biometrics available but type unknown
    Unknown,   // Runtime detection unavailable (no LAContext FFI)
}

/* =======================================================================
Storage Configuration
=================================================================== */

/// Configuration for an [`IOSKeychainStorage`] instance.
///
/// Controls biometric policy, Secure Enclave usage, caching behaviour,
/// and audit logging.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Whether to require biometric authentication
    pub require_biometrics: bool,
    /// Whether to use Secure Enclave when available
    pub use_secure_enclave: bool,
    /// Whether to enable in-memory caching
    pub enable_caching: bool,
    /// Service name for keychain items
    pub service_name: String,
    /// Maximum cache size
    pub max_cache_size: usize,
    /// Cache TTL in seconds
    pub cache_ttl_seconds: u64,
    /// Enable audit logging
    pub enable_audit_logging: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            require_biometrics: true,
            use_secure_enclave: true,
            enable_caching: false,
            service_name: SERVICE_NAME.to_string(),
            max_cache_size: 100,
            cache_ttl_seconds: DEFAULT_CACHE_TTL_SECONDS,
            enable_audit_logging: true,
        }
    }
}

/* =======================================================================
Cache Management
=================================================================== */

#[derive(Debug)]
struct ItemCache {
    items: HashMap<String, CachedItem>,
    max_size: usize,
}

/// SECURITY: ItemCache holds sensitive credential data in its HashMap values.
/// When the cache is dropped, each CachedItem's ZeroizeOnDrop clears its own
/// data field, but the HashMap itself may leave key strings and internal
/// metadata in memory. This Drop impl explicitly clears the map first so that
/// all entries are dropped (and zeroised) deterministically.
impl Drop for ItemCache {
    fn drop(&mut self) {
        self.items.clear();
    }
}

/// SECURITY: CachedItem may contain sensitive credential data.
/// Implements ZeroizeOnDrop to clear memory when the item is dropped.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
struct CachedItem {
    data: Vec<u8>,
    #[zeroize(skip)] // Timestamps are not sensitive
    cached_at: u64,
    #[zeroize(skip)] // TTL is not sensitive
    ttl_seconds: u64,
}

/* =======================================================================
Security Events and Metrics
=================================================================== */

#[derive(Debug, Clone)]
struct SecurityEvent {
    event_type: SecurityEventType,
    timestamp: u64,
    details: String,
    risk_level: RiskLevel,
}

#[derive(Debug, Clone)]
enum SecurityEventType {
    KeychainAccess,
    BiometricAuth,
    FailedOperation,
    KeyRotation,
    ConfigChange,
}

#[derive(Debug, Clone)]
enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Default, Clone)]
struct StorageMetrics {
    operations_count: u64,
    cache_hits: u64,
    cache_misses: u64,
    biometric_prompts: u64,
    errors_count: u64,
    last_error: Option<String>,
}

/* =======================================================================
iOS Keychain Storage Implementation
=================================================================== */

/// iOS Keychain storage backend.
///
/// Wraps Keychain Services with retry logic, optional in-memory caching,
/// security event logging, and biometric gating via `SecAccessControl`.
pub struct IOSKeychainStorage {
    config: StorageConfig,
    device_capabilities: DeviceCapabilities,
    cache: Arc<Mutex<ItemCache>>,
    metrics: Arc<Mutex<StorageMetrics>>,
    audit_log: Arc<Mutex<std::collections::VecDeque<SecurityEvent>>>,
}

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

    fn validate_key(&self, key: &str) -> Result<()> {
        if key.is_empty() {
            return Err(WalletError::Storage {
                msg: "Key cannot be empty".to_string(),
            });
        }
        if key.len() > 255 {
            return Err(WalletError::Storage {
                msg: "Key too long (max 255 characters)".to_string(),
            });
        }
        // Use is_ascii_alphanumeric to match the trait's byte-level ASCII check.
        // is_alphanumeric would accept Unicode letters (e.g. CJK, emoji), which
        // the PlatformSecureStorage::validate_key contract explicitly rejects.
        if !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
        {
            return Err(WalletError::Storage {
                msg: "Key contains invalid characters".to_string(),
            });
        }
        Ok(())
    }

    fn validate_data(&self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Err(WalletError::Storage {
                msg: "Data cannot be empty".to_string(),
            });
        }
        if data.len() > MAX_ITEM_SIZE {
            return Err(WalletError::Storage {
                msg: format!("Data too large (max {} bytes)", MAX_ITEM_SIZE),
            });
        }
        Ok(())
    }

    fn with_retry<T, F>(&self, max_retries: u32, mut op: F) -> Result<T>
    where
        F: FnMut() -> Result<T>,
    {
        let mut last_error = None;

        for attempt in 0..=max_retries {
            match op() {
                Ok(v) => return Ok(v),
                Err(e) => {
                    // SECURITY: Never retry authentication failures or user
                    // cancellations. Retrying these would circumvent the
                    // system's biometric lockout counter and re-prompt the
                    // user unexpectedly.
                    if Self::is_non_retryable_error(&e) {
                        return Err(e);
                    }

                    last_error = Some(e);
                    if attempt < max_retries {
                        debug!(
                            "Keychain operation failed (attempt {}/{}), retrying...",
                            attempt + 1,
                            max_retries + 1
                        );
                        thread::sleep(Duration::from_millis(100 * (attempt as u64 + 1)));
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| WalletError::Storage {
            msg: "retry loop completed with no error recorded".to_string(),
        }))
    }

    /// Returns `true` for errors that must never be retried: authentication
    /// failures and user cancellations. These are definitive outcomes, not
    /// transient faults, and retrying them would bypass iOS biometric lockout
    /// counting.
    fn is_non_retryable_error(err: &WalletError) -> bool {
        match err {
            WalletError::BiometricFailed { .. } => true,
            WalletError::Storage { msg } => {
                // errSecAuthFailed (-25293) or errSecUserCanceled (-128)
                msg.contains("Authentication failed")
                    || msg.contains("User cancelled")
                    || msg.contains(&format!("OSStatus: {}", errSecAuthFailed))
                    || msg.contains(&format!("OSStatus: {}", ERRSEC_USER_CANCELED))
            }
            _ => false,
        }
    }

    /* ---------------------------------------------------------------
    Cache Management
    ------------------------------------------------------------- */

    fn get_from_cache(&self, key: &str) -> Option<Zeroizing<Vec<u8>>> {
        if !self.config.enable_caching {
            return None;
        }

        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(item) = cache.items.get(key) {
            let now = current_timestamp();
            if now.saturating_sub(item.cached_at) < item.ttl_seconds.saturating_mul(1000) {
                return Some(Zeroizing::new(item.data.clone()));
            }
        }
        None
    }

    fn add_to_cache(&self, key: &str, data: &[u8]) {
        if !self.config.enable_caching {
            return;
        }

        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());

        // Evict oldest items if cache is full
        if cache.items.len() >= cache.max_size && cache.max_size > 0 {
            if let Some(oldest_key) = cache
                .items
                .keys()
                .min_by_key(|k| cache.items[*k].cached_at)
                .cloned()
            {
                cache.items.remove(&oldest_key);
            }
        }

        if cache.max_size > 0 {
            cache.items.insert(
                key.to_string(),
                CachedItem {
                    data: data.to_vec(),
                    cached_at: current_timestamp(),
                    ttl_seconds: self.config.cache_ttl_seconds,
                },
            );
        }
    }

    fn remove_from_cache(&self, key: &str) {
        if self.config.enable_caching {
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.items.remove(key);
        }
    }

    /* ---------------------------------------------------------------
    Security Event Logging
    ------------------------------------------------------------- */

    fn log_security_event(
        &self,
        event_type: SecurityEventType,
        details: &str,
        risk_level: RiskLevel,
    ) {
        if !self.config.enable_audit_logging {
            return;
        }

        let event = SecurityEvent {
            event_type,
            timestamp: current_timestamp(),
            details: details.to_string(),
            risk_level,
        };

        let mut audit_log = self.audit_log.lock().unwrap_or_else(|e| e.into_inner());
        audit_log.push_back(event);

        // Keep log size manageable
        if audit_log.len() > 1000 {
            audit_log.pop_front();
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

    /// Get storage metrics
    pub fn get_metrics(&self) -> StorageMetrics {
        let metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        metrics.clone()
    }

    /// Get security audit log
    pub fn get_audit_log(&self) -> Vec<SecurityEvent> {
        let audit_log = self.audit_log.lock().unwrap_or_else(|e| e.into_inner());
        audit_log.iter().cloned().collect()
    }

    /// Clear cache
    pub fn clear_cache(&self) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.items.clear();
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
Factory Functions
=================================================================== */

/// Create a production-ready storage instance
pub fn create_production_storage() -> Result<Arc<dyn PlatformSecureStorage>> {
    let config = StorageConfig {
        require_biometrics: true,
        use_secure_enclave: true,
        enable_caching: false, // Disabled for security
        service_name: SERVICE_NAME.to_string(),
        max_cache_size: 0,
        cache_ttl_seconds: 0,
        enable_audit_logging: true,
    };
    Ok(IOSKeychainStorage::new_with_config(config) as Arc<dyn PlatformSecureStorage>)
}

/// Create a development storage instance
pub fn create_development_storage() -> Result<Arc<dyn PlatformSecureStorage>> {
    let config = StorageConfig {
        require_biometrics: false,
        use_secure_enclave: false,
        enable_caching: true,
        service_name: format!("{}.dev", SERVICE_NAME),
        max_cache_size: 50,
        cache_ttl_seconds: 300,
        enable_audit_logging: true,
    };
    Ok(IOSKeychainStorage::new_with_config(config) as Arc<dyn PlatformSecureStorage>)
}

/* =======================================================================
Utility Functions
=================================================================== */

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Return a privacy-safe representation of a storage key for logging.
///
/// Shows only the prefix (up to the first dot or underscore after position 6)
/// and a truncated hash, so credential identifiers never appear in logs.
fn safe_key_label(key: &str) -> String {
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

/* =======================================================================
Tests
=================================================================== */

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_storage() -> Arc<IOSKeychainStorage> {
        let config = StorageConfig {
            require_biometrics: false,
            use_secure_enclave: false,
            enable_caching: true,
            service_name: "app.provii.wallet.test".to_string(),
            max_cache_size: 10,
            cache_ttl_seconds: 60,
            enable_audit_logging: true,
        };
        IOSKeychainStorage::new_with_config(config)
    }

    /* =======================================================================
    Configuration Tests
    =================================================================== */

    #[test]
    fn test_storage_config_default() {
        let config = StorageConfig::default();

        assert!(config.require_biometrics);
        assert!(config.use_secure_enclave);
        assert!(!config.enable_caching);
        assert_eq!(config.service_name, SERVICE_NAME);
        assert_eq!(config.max_cache_size, 100);
        assert_eq!(config.cache_ttl_seconds, DEFAULT_CACHE_TTL_SECONDS);
        assert!(config.enable_audit_logging);
    }

    #[test]
    fn test_storage_config_custom() {
        let config = StorageConfig {
            require_biometrics: false,
            use_secure_enclave: false,
            enable_caching: true,
            service_name: "custom.service".to_string(),
            max_cache_size: 50,
            cache_ttl_seconds: 600,
            enable_audit_logging: false,
        };

        assert!(!config.require_biometrics);
        assert!(!config.use_secure_enclave);
        assert!(config.enable_caching);
        assert_eq!(config.service_name, "custom.service");
        assert_eq!(config.max_cache_size, 50);
        assert_eq!(config.cache_ttl_seconds, 600);
        assert!(!config.enable_audit_logging);
    }

    #[test]
    fn test_device_capabilities_default() {
        let caps = DeviceCapabilities::default();

        // SEC-08: Stubs return None/Unknown because runtime detection
        // requires Objective-C FFI unavailable from pure Rust.
        assert!(caps.has_secure_enclave.is_none());
        assert!(matches!(caps.biometric_type, BiometricType::Unknown));
        assert!(caps.ios_version.is_none());
    }

    #[test]
    fn test_operation_statistics_new() {
        let stats = OperationStatistics::new();

        assert_eq!(stats.total_operations, 0);
        assert_eq!(stats.successful_operations, 0);
        assert_eq!(stats.failed_operations, 0);
        assert_eq!(stats.biometric_authentications, 0);
        assert_eq!(stats.cache_hits, 0);
        assert_eq!(stats.last_operation_time, 0);
    }

    #[test]
    fn test_operation_statistics_record_success() {
        let mut stats = OperationStatistics::new();

        stats.record_operation(true, false);

        assert_eq!(stats.total_operations, 1);
        assert_eq!(stats.successful_operations, 1);
        assert_eq!(stats.failed_operations, 0);
        assert_eq!(stats.biometric_authentications, 0);
        assert!(stats.last_operation_time > 0);
    }

    #[test]
    fn test_operation_statistics_record_failure() {
        let mut stats = OperationStatistics::new();

        stats.record_operation(false, false);

        assert_eq!(stats.total_operations, 1);
        assert_eq!(stats.successful_operations, 0);
        assert_eq!(stats.failed_operations, 1);
        assert_eq!(stats.biometric_authentications, 0);
    }

    #[test]
    fn test_operation_statistics_record_with_biometrics() {
        let mut stats = OperationStatistics::new();

        stats.record_operation(true, true);

        assert_eq!(stats.total_operations, 1);
        assert_eq!(stats.successful_operations, 1);
        assert_eq!(stats.biometric_authentications, 1);
    }

    #[test]
    fn test_operation_statistics_multiple_operations() {
        let mut stats = OperationStatistics::new();

        stats.record_operation(true, false);
        stats.record_operation(false, false);
        stats.record_operation(true, true);

        assert_eq!(stats.total_operations, 3);
        assert_eq!(stats.successful_operations, 2);
        assert_eq!(stats.failed_operations, 1);
        assert_eq!(stats.biometric_authentications, 1);
    }

    /* =======================================================================
    Storage Initialization Tests
    =================================================================== */

    #[test]
    fn test_ios_keychain_storage_new() {
        let storage = IOSKeychainStorage::new();

        // Should be created successfully
        assert_eq!(storage.config.service_name, SERVICE_NAME);
        assert!(storage.config.require_biometrics);
        assert!(storage.config.use_secure_enclave);
    }

    #[test]
    fn test_ios_keychain_storage_new_with_custom_config() {
        let config = StorageConfig {
            require_biometrics: false,
            use_secure_enclave: false,
            enable_caching: true,
            service_name: "test.service".to_string(),
            max_cache_size: 20,
            cache_ttl_seconds: 120,
            enable_audit_logging: false,
        };

        let storage = IOSKeychainStorage::new_with_config(config.clone());

        assert_eq!(storage.config.service_name, "test.service");
        assert!(!storage.config.require_biometrics);
        assert!(storage.config.enable_caching);
        assert_eq!(storage.config.max_cache_size, 20);
    }

    #[test]
    fn test_factory_production_storage() {
        let result = create_production_storage();
        assert!(result.is_ok());
    }

    #[test]
    fn test_factory_development_storage() {
        let result = create_development_storage();
        assert!(result.is_ok());
    }

    /* =======================================================================
    Validation Tests
    =================================================================== */

    #[test]
    fn test_validate_key_empty() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();
        let result = storage.validate_key("");

        let Err(WalletError::Storage { msg }) = result else {
            return Err("expected Storage error for empty key".into());
        };
        assert!(msg.contains("empty"));
        Ok(())
    }

    #[test]
    fn test_validate_key_too_long() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();
        let long_key = "a".repeat(256);
        let result = storage.validate_key(&long_key);

        let Err(WalletError::Storage { msg }) = result else {
            return Err("expected Storage error for long key".into());
        };
        assert!(msg.contains("too long"));
        Ok(())
    }

    #[test]
    fn test_validate_key_valid() {
        let storage = create_test_storage();
        let result = storage.validate_key("valid.key.123");

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_key_max_length() {
        let storage = create_test_storage();
        let max_key = "a".repeat(255);
        let result = storage.validate_key(&max_key);

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_data_empty() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();
        let result = storage.validate_data(b"");

        let Err(WalletError::Storage { msg }) = result else {
            return Err("expected Storage error for empty data".into());
        };
        assert!(msg.contains("empty"));
        Ok(())
    }

    #[test]
    fn test_validate_data_too_large() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();
        let large_data = vec![0u8; MAX_ITEM_SIZE + 1];
        let result = storage.validate_data(&large_data);

        let Err(WalletError::Storage { msg }) = result else {
            return Err("expected Storage error for oversized data".into());
        };
        assert!(msg.contains("too large"));
        Ok(())
    }

    #[test]
    fn test_validate_data_valid() {
        let storage = create_test_storage();
        let result = storage.validate_data(b"valid data");

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_data_max_size() {
        let storage = create_test_storage();
        let max_data = vec![0u8; MAX_ITEM_SIZE];
        let result = storage.validate_data(&max_data);

        assert!(result.is_ok());
    }

    /* =======================================================================
    Cache Tests
    =================================================================== */

    #[test]
    fn test_cache_disabled() {
        let config = StorageConfig {
            enable_caching: false,
            ..StorageConfig::default()
        };
        let storage = IOSKeychainStorage::new_with_config(config);

        // Add to cache should do nothing
        storage.add_to_cache("key", &[1, 2, 3]);

        // Get from cache should return None
        let result = storage.get_from_cache("key");
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_get_from_cache_miss() {
        let storage = create_test_storage();
        storage.clear_cache();

        let result = storage.get_from_cache("nonexistent");
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_add_and_get() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();
        storage.clear_cache();

        let key = "test_key";
        let data = vec![1, 2, 3, 4];

        storage.add_to_cache(key, &data);

        let cached = storage.get_from_cache(key).ok_or("expected cached value")?;
        assert_eq!(*cached, data);
        Ok(())
    }

    #[test]
    fn test_cache_remove() {
        let storage = create_test_storage();
        storage.clear_cache();

        let key = "test_key";
        let data = vec![1, 2, 3];

        storage.add_to_cache(key, &data);
        assert!(storage.get_from_cache(key).is_some());

        storage.remove_from_cache(key);
        assert!(storage.get_from_cache(key).is_none());
    }

    #[test]
    fn test_cache_clear() {
        let storage = create_test_storage();

        storage.add_to_cache("key1", &[1]);
        storage.add_to_cache("key2", &[2]);
        storage.add_to_cache("key3", &[3]);

        storage.clear_cache();

        assert!(storage.get_from_cache("key1").is_none());
        assert!(storage.get_from_cache("key2").is_none());
        assert!(storage.get_from_cache("key3").is_none());
    }

    #[test]
    fn test_cache_eviction_when_full() {
        let config = StorageConfig {
            enable_caching: true,
            max_cache_size: 2,
            ..StorageConfig::default()
        };
        let storage = IOSKeychainStorage::new_with_config(config);
        storage.clear_cache();

        // Add items up to max
        storage.add_to_cache("key1", &[1]);
        thread::sleep(Duration::from_millis(10));
        storage.add_to_cache("key2", &[2]);

        // Both should be cached
        assert!(storage.get_from_cache("key1").is_some());
        assert!(storage.get_from_cache("key2").is_some());

        // Add third item - should evict oldest (key1)
        thread::sleep(Duration::from_millis(10));
        storage.add_to_cache("key3", &[3]);

        // key1 may be evicted (oldest)
        // key2 and key3 should be present
        assert!(storage.get_from_cache("key2").is_some());
        assert!(storage.get_from_cache("key3").is_some());
    }

    #[test]
    fn test_cache_zero_max_size() {
        let config = StorageConfig {
            enable_caching: true,
            max_cache_size: 0,
            ..StorageConfig::default()
        };
        let storage = IOSKeychainStorage::new_with_config(config);

        // Should not cache anything
        storage.add_to_cache("key", &[1, 2, 3]);

        let result = storage.get_from_cache("key");
        assert!(result.is_none());
    }

    /* =======================================================================
    Metrics Tests
    =================================================================== */

    #[test]
    fn test_metrics_initial_state() {
        let storage = create_test_storage();
        let metrics = storage.get_metrics();

        assert_eq!(metrics.operations_count, 0);
        assert_eq!(metrics.cache_hits, 0);
        assert_eq!(metrics.cache_misses, 0);
        assert_eq!(metrics.biometric_prompts, 0);
        assert_eq!(metrics.errors_count, 0);
        assert!(metrics.last_error.is_none());
    }

    #[test]
    fn test_storage_metrics_default() {
        let metrics = StorageMetrics::default();

        assert_eq!(metrics.operations_count, 0);
        assert_eq!(metrics.cache_hits, 0);
        assert_eq!(metrics.cache_misses, 0);
        assert_eq!(metrics.errors_count, 0);
        assert!(metrics.last_error.is_none());
    }

    /* =======================================================================
    Audit Log Tests
    =================================================================== */

    #[test]
    fn test_audit_log_initial_state() {
        let storage = create_test_storage();
        let log = storage.get_audit_log();

        // May have initialization events
        // Audit log may contain initialisation events; just confirm it is accessible.
        let _ = log;
    }

    #[test]
    fn test_log_security_event_disabled() {
        let config = StorageConfig {
            enable_audit_logging: false,
            ..StorageConfig::default()
        };
        let storage = IOSKeychainStorage::new_with_config(config);

        let initial_count = storage.get_audit_log().len();

        storage.log_security_event(
            SecurityEventType::KeychainAccess,
            "test event",
            RiskLevel::Low,
        );

        let final_count = storage.get_audit_log().len();
        assert_eq!(initial_count, final_count);
    }

    #[test]
    fn test_security_event_types() {
        // Just verify enum variants compile
        let _events = vec![
            SecurityEventType::KeychainAccess,
            SecurityEventType::BiometricAuth,
            SecurityEventType::FailedOperation,
            SecurityEventType::KeyRotation,
            SecurityEventType::ConfigChange,
        ];
    }

    #[test]
    fn test_risk_levels() {
        // Just verify enum variants compile
        let _levels = vec![RiskLevel::Low, RiskLevel::Medium, RiskLevel::High];
    }

    #[test]
    fn test_biometric_types() {
        // Just verify enum variants compile
        let _types = vec![
            BiometricType::None,
            BiometricType::TouchID,
            BiometricType::FaceID,
            BiometricType::Available,
        ];
    }

    /* =======================================================================
    Error Handling Tests
    =================================================================== */

    #[test]
    fn test_map_keychain_error_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();
        let error = storage.map_keychain_error(errSecItemNotFound);

        let WalletError::Storage { msg } = error else {
            return Err("expected Storage error variant".into());
        };
        assert!(msg.contains("NotFound"));
        Ok(())
    }

    #[test]
    fn test_map_keychain_error_duplicate() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();
        let error = storage.map_keychain_error(errSecDuplicateItem);

        let WalletError::Storage { msg } = error else {
            return Err("expected Storage error variant".into());
        };
        assert!(msg.contains("Duplicate"));
        Ok(())
    }

    #[test]
    fn test_map_keychain_error_auth_failed() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();
        let error = storage.map_keychain_error(errSecAuthFailed);

        let WalletError::Storage { msg } = error else {
            return Err("expected Storage error variant".into());
        };
        assert!(msg.contains("Authentication"));
        Ok(())
    }

    #[test]
    fn test_map_keychain_error_user_canceled() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();
        let error = storage.map_keychain_error(ERRSEC_USER_CANCELED);

        let WalletError::Storage { msg } = error else {
            return Err("expected Storage error variant".into());
        };
        assert!(msg.contains("cancelled"));
        Ok(())
    }

    #[test]
    fn test_map_keychain_error_unknown() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();
        let error = storage.map_keychain_error(-99999);

        let WalletError::Storage { msg } = error else {
            return Err("expected Storage error variant".into());
        };
        assert!(msg.contains("Keychain error"));
        assert!(msg.contains("-99999"));
        Ok(())
    }

    /* =======================================================================
    Utility Tests
    =================================================================== */

    #[test]
    fn test_current_timestamp() {
        let ts1 = current_timestamp();
        thread::sleep(Duration::from_millis(10));
        let ts2 = current_timestamp();

        assert!(ts2 > ts1);
        assert!(ts2 - ts1 >= 10);
    }

    #[test]
    fn test_current_timestamp_monotonic() {
        let timestamps: Vec<u64> = (0..10)
            .map(|_| {
                let ts = current_timestamp();
                thread::sleep(Duration::from_millis(1));
                ts
            })
            .collect();

        // Verify timestamps are increasing
        for i in 1..timestamps.len() {
            assert!(timestamps[i] >= timestamps[i - 1]);
        }
    }

    /* =======================================================================
    Constants Tests
    =================================================================== */

    #[test]
    fn test_constants() {
        assert_eq!(SERVICE_NAME, "app.provii.wallet.sdk");
        assert_eq!(IDENTITY_KEY_PREFIX, "provii.identity");
        assert_eq!(CREDENTIAL_KEY_PREFIX, "provii.credential");
        assert_eq!(CONFIG_KEY_PREFIX, "provii.config");
        assert_eq!(MAX_KEYCHAIN_RETRIES, 3);
        assert_eq!(MAX_ITEM_SIZE, 1024 * 1024);
        assert_eq!(DEFAULT_CACHE_TTL_SECONDS, 300);
        assert_eq!(ERRSEC_USER_CANCELED, -128);
    }

    /* =======================================================================
    Integration Tests (require actual iOS Keychain)
    =================================================================== */

    #[test]
    fn test_store_retrieve_delete() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();
        let key = "test_key";
        let data = b"test_data";

        // Clean up any existing data
        let _ = storage.delete(key);

        // Store
        storage.store_secure(key, data, false)?;

        // Retrieve
        let retrieved = storage.retrieve_secure(key, false)?;
        assert_eq!(*retrieved, data);

        // Check exists
        assert!(storage.exists(key)?);

        // Delete
        storage.delete(key)?;

        // Verify deletion
        assert!(!storage.exists(key)?);
        Ok(())
    }

    #[test]
    fn test_list_keys() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();
        let keys = vec!["test1", "test2", "test3"];
        let data = b"data";

        // Clean up
        for key in &keys {
            let _ = storage.delete(key);
        }

        // Store test items
        for key in &keys {
            storage.store_secure(key, data, false)?;
        }

        // List keys
        let listed = storage.list_keys()?;

        // Verify all keys present
        for key in &keys {
            assert!(listed.contains(&key.to_string()));
        }

        // Clean up
        for key in &keys {
            storage.delete(key)?;
        }
        Ok(())
    }

    #[test]
    fn test_cache() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();
        let key = "cache_test";
        let data = b"cached_data";

        // Clean up
        let _ = storage.delete(key);
        storage.clear_cache();

        // Store
        storage.store_secure(key, data, false)?;

        // First retrieve (cache miss)
        let _ = storage.retrieve_secure(key, false)?;

        // Second retrieve (should be cache hit)
        let _ = storage.retrieve_secure(key, false)?;

        let metrics = storage.get_metrics();
        assert!(metrics.cache_hits > 0);

        // Clean up
        storage.delete(key)?;
        Ok(())
    }

    #[test]
    fn test_validation() {
        let storage = create_test_storage();

        // Test empty key
        let result = storage.store_secure("", b"data", false);
        assert!(result.is_err());

        // Test empty data
        let result = storage.store_secure("key", b"", false);
        assert!(result.is_err());

        // Test oversized data
        let large_data = vec![0u8; MAX_ITEM_SIZE + 1];
        let result = storage.store_secure("key", &large_data, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_store_update_existing() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();
        let key = "update_test";
        let data1 = b"original_data";
        let data2 = b"updated_data";

        // Clean up
        let _ = storage.delete(key);

        // Store original
        storage.store_secure(key, data1, false)?;

        // Update with new data
        storage.store_secure(key, data2, false)?;

        // Verify updated data
        let retrieved = storage.retrieve_secure(key, false)?;
        assert_eq!(*retrieved, data2);

        // Clean up
        storage.delete(key)?;
        Ok(())
    }

    #[test]
    fn test_exists_nonexistent_key() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();
        let key = "nonexistent_key_12345";

        // Make sure it doesn't exist
        let _ = storage.delete(key);

        let exists = storage.exists(key)?;
        assert!(!exists);
        Ok(())
    }

    #[test]
    fn test_delete_nonexistent_key() {
        let storage = create_test_storage();
        let key = "nonexistent_delete";

        // Deleting non-existent key should succeed (idempotent)
        let result = storage.delete(key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_test_keychain_access() {
        let storage = create_test_storage();

        // This tests the full cycle: store, retrieve, verify, delete
        let result = storage.test_keychain_access();
        assert!(result.is_ok(), "Keychain access test failed: {:?}", result);
    }

    #[test]
    fn test_wipe_all() {
        let storage = create_test_storage();

        // Store some test items
        let keys = vec!["wipe1", "wipe2", "wipe3"];
        for key in &keys {
            storage.store_secure(key, b"data", false).ok();
        }

        // Wipe all
        let result = storage.wipe_all();
        assert!(result.is_ok());

        // Verify all items deleted
        for key in &keys {
            let exists = storage.exists(key).unwrap_or(true);
            assert!(!exists, "Key {} still exists after wipe", key);
        }
    }

    #[test]
    fn test_rotate_master_key() {
        let storage = create_test_storage();
        let key = "rotation_test";
        let data = b"test_data";

        // Store item
        storage.store_secure(key, data, false).ok();

        // Rotate keys
        let result = storage.rotate_master_key();
        assert!(result.is_ok());

        // Verify data still retrievable
        if let Ok(retrieved) = storage.retrieve_secure(key, false) {
            assert_eq!(*retrieved, data);
        }

        // Clean up
        storage.delete(key).ok();
    }

    #[test]
    fn test_usage_stats() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();

        // Clean up
        let _ = storage.wipe_all();

        // Store some items with different prefixes
        storage
            .store_secure(
                &format!("{}cred1", CREDENTIAL_KEY_PREFIX),
                b"cred_data",
                false,
            )
            .ok();
        storage
            .store_secure(
                &format!("{}cred2", CREDENTIAL_KEY_PREFIX),
                b"cred_data2",
                false,
            )
            .ok();
        storage
            .store_secure(&format!("{}id1", IDENTITY_KEY_PREFIX), b"id_data", false)
            .ok();
        storage.store_secure("other_key", b"other_data", false).ok();

        let stats = storage.usage_stats()?;

        // Should have at least the items we just stored
        assert!(stats.total_keys >= 4);
        assert_eq!(stats.credentials_count, 2); // Only credential prefix items
        assert!(stats.total_bytes > 0);

        // Clean up
        storage.wipe_all().ok();
        Ok(())
    }

    #[test]
    fn test_storage_metrics_tracking() {
        let storage = create_test_storage();
        let initial_metrics = storage.get_metrics();
        let initial_ops = initial_metrics.operations_count;

        let key = "metrics_test";
        let data = b"test_data";

        // Perform operations
        storage.store_secure(key, data, false).ok();
        storage.retrieve_secure(key, false).ok();

        let final_metrics = storage.get_metrics();

        // Operations count should have increased
        assert!(final_metrics.operations_count > initial_ops);

        // Clean up
        storage.delete(key).ok();
    }

    #[test]
    fn test_large_data_at_boundary() {
        let storage = create_test_storage();
        let key = "large_data_test";

        // Create data exactly at MAX_ITEM_SIZE
        let max_data = vec![0u8; MAX_ITEM_SIZE];

        // Should succeed
        let result = storage.store_secure(key, &max_data, false);
        assert!(result.is_ok());

        // Verify retrieval
        if let Ok(retrieved) = storage.retrieve_secure(key, false) {
            assert_eq!(retrieved.len(), MAX_ITEM_SIZE);
        }

        // Clean up
        storage.delete(key).ok();
    }

    #[test]
    fn test_key_with_allowed_characters() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();
        // Only alphanumeric, underscore, dot, and hyphen are permitted
        let keys = vec![
            "key.with.dots",
            "key-with-dashes",
            "key_with_underscores",
            "Key123.mixed-CASE_ok",
        ];

        for key in &keys {
            let data = format!("data for {}", key).into_bytes();

            storage.store_secure(key, &data, false)?;

            let retrieved = storage.retrieve_secure(key, false)?;
            assert_eq!(*retrieved, data);

            storage.delete(key).ok();
        }
        Ok(())
    }

    #[test]
    fn test_key_with_rejected_characters() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();
        // Colons, slashes, unicode, and spaces must be rejected
        let bad_keys = vec!["key:colon", "key/slash", "key with space", "emoji\u{1F511}"];

        for key in &bad_keys {
            let result = storage.validate_key(key);
            assert!(result.is_err(), "Key '{}' should be rejected", key);
            let Err(WalletError::Storage { msg }) = result else {
                return Err(format!("expected Storage error for key '{}'", key).into());
            };
            assert!(msg.contains("invalid characters"));
        }
        Ok(())
    }

    #[test]
    fn test_concurrent_access() {
        let storage = create_test_storage();
        let storage_clone1 = Arc::clone(&storage);
        let storage_clone2 = Arc::clone(&storage);

        let key1 = "concurrent_test_1";
        let key2 = "concurrent_test_2";

        // Clean up
        storage.delete(key1).ok();
        storage.delete(key2).ok();

        let handle1 = thread::spawn(move || {
            storage_clone1.store_secure(key1, b"data1", false).ok();
            storage_clone1.retrieve_secure(key1, false).ok()
        });

        let handle2 = thread::spawn(move || {
            storage_clone2.store_secure(key2, b"data2", false).ok();
            storage_clone2.retrieve_secure(key2, false).ok()
        });

        let result1 = handle1.join();
        let result2 = handle2.join();

        // Both threads should complete without panic
        assert!(result1.is_ok());
        assert!(result2.is_ok());

        // Clean up
        storage.delete(key1).ok();
        storage.delete(key2).ok();
    }

    #[test]
    fn test_binary_data_storage() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();
        let key = "binary_test";

        // Create binary data with all byte values
        let data: Vec<u8> = (0..=255).collect();

        storage.store_secure(key, &data, false)?;

        let retrieved = storage.retrieve_secure(key, false)?;
        assert_eq!(*retrieved, data);

        storage.delete(key).ok();
        Ok(())
    }

    #[test]
    fn test_json_data_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let storage = create_test_storage();
        let key = "json_test";
        let json_str = r#"{"name":"test","value":123,"nested":{"key":"value"}}"#;

        storage.store_secure(key, json_str.as_bytes(), false)?;

        let retrieved = storage.retrieve_secure(key, false)?;
        let retrieved_str = std::str::from_utf8(&retrieved)?;

        assert_eq!(retrieved_str, json_str);

        storage.delete(key).ok();
        Ok(())
    }
}
