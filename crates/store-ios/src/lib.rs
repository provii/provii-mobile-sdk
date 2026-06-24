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
Module wiring
=================================================================== */

mod cache;
mod device;
mod keychain_ops;
mod lifecycle;
mod metrics;
mod retry;

use crate::device::OperationStatistics;
use cache::ItemCache;
use device::DeviceCapabilities;
use keychain_ops::{current_timestamp, safe_key_label};
use metrics::{RiskLevel, SecurityEvent, SecurityEventType, StorageMetrics};

/* =======================================================================
Tests
=================================================================== */

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
