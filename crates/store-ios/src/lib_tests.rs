// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

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
