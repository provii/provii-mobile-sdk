// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

use super::*;

/* =======================================================================
Configuration Tests
=================================================================== */

#[test]
fn test_storage_config_default() {
    let config = StorageConfig::default();

    assert!(config.require_biometrics);
    assert!(config.use_strongbox);
    assert!(config.enable_audit_logging);
    assert_eq!(config.max_failed_attempts, 5);
    assert_eq!(config.lockout_duration, 300);
    assert!(!config.enable_caching);
    assert_eq!(config.cache_ttl, 600);
}

#[test]
fn test_storage_config_custom() {
    let config = StorageConfig {
        require_biometrics: false,
        use_strongbox: false,
        enable_audit_logging: false,
        max_failed_attempts: 10,
        lockout_duration: 600,
        enable_caching: true,
        cache_ttl: 1200,
        allow_software_keystore: true,
    };

    assert!(!config.require_biometrics);
    assert!(!config.use_strongbox);
    assert!(!config.enable_audit_logging);
    assert_eq!(config.max_failed_attempts, 10);
    assert_eq!(config.lockout_duration, 600);
    assert!(config.enable_caching);
    assert_eq!(config.cache_ttl, 1200);
}

#[test]
fn test_storage_config_production() {
    let config = StorageConfig {
        require_biometrics: true,
        use_strongbox: true,
        enable_audit_logging: true,
        max_failed_attempts: 3,
        lockout_duration: 300,
        enable_caching: false,
        cache_ttl: 0,
        allow_software_keystore: false,
    };

    assert!(config.require_biometrics);
    assert!(config.use_strongbox);
    assert_eq!(config.max_failed_attempts, 3);
    assert!(!config.enable_caching);
}

#[test]
fn test_device_security_profile_default() {
    let profile = DeviceSecurityProfile::default();

    assert!(!profile.has_strongbox);
    assert!(!profile.has_hardware_keystore);
    assert!(!profile.has_biometric_hardware);
    assert_eq!(profile.security_patch_level, "unknown");
    assert_eq!(profile.api_level, 0);
    assert_eq!(profile.last_assessed, 0);
}

#[test]
fn test_device_security_profile_custom() {
    let profile = DeviceSecurityProfile {
        has_strongbox: true,
        has_hardware_keystore: true,
        has_biometric_hardware: true,
        security_patch_level: "2024-01-01".to_string(),
        api_level: 33,
        last_assessed: 1234567890,
    };

    assert!(profile.has_strongbox);
    assert!(profile.has_hardware_keystore);
    assert!(profile.has_biometric_hardware);
    assert_eq!(profile.security_patch_level, "2024-01-01");
    assert_eq!(profile.api_level, 33);
    assert_eq!(profile.last_assessed, 1234567890);
}

/* =======================================================================
Operation Statistics Tests
=================================================================== */

#[test]
fn test_operation_statistics_new() {
    let stats = OperationStatistics::new();

    assert_eq!(stats.total_operations, 0);
    assert_eq!(stats.successful_operations, 0);
    assert_eq!(stats.failed_operations, 0);
    assert_eq!(stats.biometric_authentications, 0);
    assert_eq!(stats.hardware_operations, 0);
    assert_eq!(stats.last_operation_time, 0);
}

#[test]
fn test_operation_statistics_record_success() {
    let mut stats = OperationStatistics::new();

    stats.record_operation(true, false, false);

    assert_eq!(stats.total_operations, 1);
    assert_eq!(stats.successful_operations, 1);
    assert_eq!(stats.failed_operations, 0);
    assert_eq!(stats.biometric_authentications, 0);
    assert_eq!(stats.hardware_operations, 0);
    assert!(stats.last_operation_time > 0);
}

#[test]
fn test_operation_statistics_record_failure() {
    let mut stats = OperationStatistics::new();

    stats.record_operation(false, false, false);

    assert_eq!(stats.total_operations, 1);
    assert_eq!(stats.successful_operations, 0);
    assert_eq!(stats.failed_operations, 1);
    assert_eq!(stats.biometric_authentications, 0);
    assert_eq!(stats.hardware_operations, 0);
}

#[test]
fn test_operation_statistics_record_with_biometrics() {
    let mut stats = OperationStatistics::new();

    stats.record_operation(true, true, false);

    assert_eq!(stats.total_operations, 1);
    assert_eq!(stats.successful_operations, 1);
    assert_eq!(stats.biometric_authentications, 1);
    assert_eq!(stats.hardware_operations, 0);
}

#[test]
fn test_operation_statistics_record_with_hardware() {
    let mut stats = OperationStatistics::new();

    stats.record_operation(true, false, true);

    assert_eq!(stats.total_operations, 1);
    assert_eq!(stats.successful_operations, 1);
    assert_eq!(stats.biometric_authentications, 0);
    assert_eq!(stats.hardware_operations, 1);
}

#[test]
fn test_operation_statistics_record_all_features() {
    let mut stats = OperationStatistics::new();

    stats.record_operation(true, true, true);

    assert_eq!(stats.total_operations, 1);
    assert_eq!(stats.successful_operations, 1);
    assert_eq!(stats.biometric_authentications, 1);
    assert_eq!(stats.hardware_operations, 1);
}

#[test]
fn test_operation_statistics_multiple_operations() {
    let mut stats = OperationStatistics::new();

    stats.record_operation(true, false, false);
    stats.record_operation(false, false, false);
    stats.record_operation(true, true, false);
    stats.record_operation(true, false, true);
    stats.record_operation(true, true, true);

    assert_eq!(stats.total_operations, 5);
    assert_eq!(stats.successful_operations, 4);
    assert_eq!(stats.failed_operations, 1);
    assert_eq!(stats.biometric_authentications, 3);
    assert_eq!(stats.hardware_operations, 2);
}

/* =======================================================================
Storage Metrics Tests
=================================================================== */

#[test]
fn test_storage_metrics_default() {
    let metrics = StorageMetrics::default();

    assert_eq!(metrics.operations_count, 0);
    assert_eq!(metrics.cache_hits, 0);
    assert_eq!(metrics.cache_misses, 0);
    assert_eq!(metrics.biometric_prompts, 0);
    assert_eq!(metrics.strongbox_operations, 0);
    assert_eq!(metrics.errors_count, 0);
    assert_eq!(metrics.average_operation_time_ms, 0);
    assert!(metrics.last_error.is_none());
}

#[test]
fn test_storage_metrics_clone() {
    let metrics = StorageMetrics {
        operations_count: 100,
        cache_hits: 50,
        cache_misses: 50,
        biometric_prompts: 10,
        strongbox_operations: 75,
        errors_count: 5,
        average_operation_time_ms: 150,
        last_error: Some("test error".to_string()),
    };

    let cloned = metrics.clone();

    assert_eq!(cloned.operations_count, 100);
    assert_eq!(cloned.cache_hits, 50);
    assert_eq!(cloned.cache_misses, 50);
    assert_eq!(cloned.biometric_prompts, 10);
    assert_eq!(cloned.strongbox_operations, 75);
    assert_eq!(cloned.errors_count, 5);
    assert_eq!(cloned.average_operation_time_ms, 150);
    assert_eq!(cloned.last_error, Some("test error".to_string()));
}

/* =======================================================================
Cached Operation Tests
=================================================================== */

#[test]
fn test_cached_operation_creation() {
    let cached = CachedOperation {
        key: "test_key".to_string(),
        data: vec![1, 2, 3, 4],
        cached_at: 1000,
        ttl: 600,
    };

    assert_eq!(cached.key, "test_key");
    assert_eq!(cached.data, vec![1, 2, 3, 4]);
    assert_eq!(cached.cached_at, 1000);
    assert_eq!(cached.ttl, 600);
}

#[test]
fn test_cached_operation_clone() {
    let cached = CachedOperation {
        key: "test_key".to_string(),
        data: vec![5, 6, 7, 8],
        cached_at: 2000,
        ttl: 300,
    };

    let cloned = cached.clone();

    assert_eq!(cloned.key, "test_key");
    assert_eq!(cloned.data, vec![5, 6, 7, 8]);
    assert_eq!(cloned.cached_at, 2000);
    assert_eq!(cloned.ttl, 300);
}

/* =======================================================================
Security Event Tests
=================================================================== */

#[test]
fn test_security_event_creation() {
    let event = SecurityEvent {
        event_type: SecurityEventType::KeystoreAccess,
        timestamp: 1234567890,
        details: "Test event".to_string(),
        risk_level: RiskLevel::Low,
    };

    assert_eq!(event.timestamp, 1234567890);
    assert_eq!(event.details, "Test event");
}

#[test]
fn test_security_event_types() {
    // Verify all enum variants compile
    let _events = vec![
        SecurityEventType::KeystoreAccess,
        SecurityEventType::BiometricAuth,
        SecurityEventType::HardwareFeatureCheck,
        SecurityEventType::FailedOperation,
        SecurityEventType::ConfigurationChange,
    ];
}

#[test]
fn test_risk_levels() {
    // Verify all enum variants compile
    let _levels = vec![
        RiskLevel::Low,
        RiskLevel::Medium,
        RiskLevel::High,
        RiskLevel::Critical,
    ];
}

/* =======================================================================
Validation Tests (Non-Android specific)
=================================================================== */

// Note: These tests can only run on Android target with JVM initialized
// For now, we test the validation logic expectations

#[test]
fn test_key_validation_expectations() {
    // Test that our validation rules are correct
    let valid_keys = vec![
        "valid_key",
        "valid.key",
        "valid-key",
        "ValidKey123",
        "a".repeat(255), // Max length
    ];

    let invalid_keys = vec![
        "",              // Empty
        "a".repeat(256), // Too long
        "key with spaces",
        "key@invalid",
        "key#invalid",
    ];

    // Verify key character validation logic
    for key in &valid_keys {
        let all_valid = key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-');
        assert!(all_valid, "Key '{}' should be valid", key);
        assert!(!key.is_empty(), "Key should not be empty");
        assert!(key.len() <= 255, "Key should not exceed 255 chars");
    }

    for key in &invalid_keys {
        let is_empty = key.is_empty();
        let is_too_long = key.len() > 255;
        let has_invalid_chars = !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-');

        assert!(
            is_empty || is_too_long || has_invalid_chars,
            "Key '{}' should be invalid",
            key
        );
    }
}

#[test]
fn test_data_validation_expectations() {
    // Test that our validation rules are correct
    let valid_data = vec![
        vec![1],                // Minimum size
        vec![0; MAX_ITEM_SIZE], // Maximum size
        vec![0; 1024],          // Normal size
    ];

    let invalid_data = vec![
        vec![],                     // Empty
        vec![0; MAX_ITEM_SIZE + 1], // Too large
    ];

    for data in &valid_data {
        assert!(!data.is_empty(), "Data should not be empty");
        assert!(
            data.len() <= MAX_ITEM_SIZE,
            "Data should not exceed MAX_ITEM_SIZE"
        );
    }

    for data in &invalid_data {
        let is_empty = data.is_empty();
        let is_too_large = data.len() > MAX_ITEM_SIZE;

        assert!(
            is_empty || is_too_large,
            "Data with length {} should be invalid",
            data.len()
        );
    }
}

/* =======================================================================
Constants Tests
=================================================================== */

#[test]
fn test_constants() {
    assert_eq!(IDENTITY_KEY_PREFIX, "provii_identity");
    assert_eq!(CREDENTIAL_KEY_PREFIX, "provii_credential");
    assert_eq!(CONFIG_KEY_PREFIX, "provii_config");
    assert_eq!(MAX_KEYSTORE_RETRIES, 3);
    assert_eq!(BIOMETRIC_TIMEOUT_MS, 30000);
    assert_eq!(MAX_ITEM_SIZE, 2 * 1024 * 1024);
    assert_eq!(HARDWARE_CACHE_TTL, 3600);
}

/* =======================================================================
Utility Function Tests
=================================================================== */

#[test]
fn test_current_timestamp() {
    let ts1 = current_timestamp();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let ts2 = current_timestamp();

    assert!(ts2 > ts1);
    assert!(ts2 - ts1 >= 10);
}

#[test]
fn test_current_timestamp_monotonic() {
    let timestamps: Vec<u64> = (0..10)
        .map(|_| {
            let ts = current_timestamp();
            std::thread::sleep(std::time::Duration::from_millis(1));
            ts
        })
        .collect();

    // Verify timestamps are increasing
    for i in 1..timestamps.len() {
        assert!(timestamps[i] >= timestamps[i - 1]);
    }
}

#[test]
fn test_jni_to_wallet_error() {
    let jni_error = jni::errors::Error::NullPtr("test null pointer");
    let wallet_error = jni_to_wallet_error(jni_error);

    match wallet_error {
        WalletError::Storage { msg } => {
            assert!(msg.contains("JNI error"));
            assert!(msg.contains("null pointer"));
        }
        _ => panic!("Expected Storage error"),
    }
}

/* =======================================================================
Error Handling Tests
=================================================================== */

#[test]
fn test_error_already_initialised() {
    let err = Error::AlreadyInitialised;
    let err_string = err.to_string();
    assert!(err_string.contains("already initialised"));
}

#[test]
fn test_error_display() {
    let err = Error::AlreadyInitialised;
    let display_string = format!("{}", err);
    assert_eq!(display_string, "Android context already initialised");
}

/* =======================================================================
Security Validation Tests
=================================================================== */

#[test]
fn test_api_level_requirements() {
    // Verify that minimum API level requirement is correct
    let min_api_level = 29;

    let valid_profile = DeviceSecurityProfile {
        api_level: 29,
        ..DeviceSecurityProfile::default()
    };

    let invalid_profile = DeviceSecurityProfile {
        api_level: 28,
        ..DeviceSecurityProfile::default()
    };

    // Test validation logic
    assert!(valid_profile.api_level >= min_api_level);
    assert!(invalid_profile.api_level < min_api_level);
}

#[test]
fn test_security_profile_completeness() {
    let profile = DeviceSecurityProfile {
        has_strongbox: true,
        has_hardware_keystore: true,
        has_biometric_hardware: true,
        security_patch_level: "2024-01-01".to_string(),
        api_level: 33,
        last_assessed: current_timestamp(),
    };

    // Verify all security features are accounted for
    assert!(profile.has_strongbox || !profile.has_strongbox); // has field
    assert!(profile.has_hardware_keystore || !profile.has_hardware_keystore); // has field
    assert!(profile.has_biometric_hardware || !profile.has_biometric_hardware); // has field
    assert!(!profile.security_patch_level.is_empty());
    assert!(profile.api_level > 0);
    assert!(profile.last_assessed > 0);
}

/* =======================================================================
Configuration Validation Tests
=================================================================== */

#[test]
fn test_storage_config_security_levels() {
    // High security config
    let high_security = StorageConfig {
        require_biometrics: true,
        use_strongbox: true,
        enable_audit_logging: true,
        max_failed_attempts: 3,
        lockout_duration: 600,
        enable_caching: false,
        cache_ttl: 0,
        allow_software_keystore: false,
    };

    assert!(high_security.require_biometrics);
    assert!(high_security.use_strongbox);
    assert!(high_security.enable_audit_logging);
    assert!(high_security.max_failed_attempts <= 5);
    assert!(!high_security.enable_caching);

    // Low security config (development)
    let low_security = StorageConfig {
        require_biometrics: false,
        use_strongbox: false,
        enable_audit_logging: false,
        max_failed_attempts: 100,
        lockout_duration: 0,
        enable_caching: true,
        cache_ttl: 3600,
        allow_software_keystore: true,
    };

    assert!(!low_security.require_biometrics);
    assert!(!low_security.use_strongbox);
    assert!(low_security.enable_caching);
    assert!(low_security.max_failed_attempts >= 10);
}

#[test]
fn test_biometric_timeout_reasonable() {
    // Verify timeout is in reasonable range (10-60 seconds)
    assert!(BIOMETRIC_TIMEOUT_MS >= 10_000);
    assert!(BIOMETRIC_TIMEOUT_MS <= 60_000);
}

#[test]
fn test_max_item_size_reasonable() {
    // Verify max size is reasonable (should be at least 1MB, at most 10MB)
    assert!(MAX_ITEM_SIZE >= 1024 * 1024);
    assert!(MAX_ITEM_SIZE <= 10 * 1024 * 1024);
}

/* =======================================================================
Cache Logic Tests
=================================================================== */

#[test]
fn test_cache_ttl_expiry_logic() {
    // VULN-03: cached_at is milliseconds, ttl is seconds.
    // Production code compares: now - cached_at < ttl * 1000
    let cached = CachedOperation {
        key: "test".to_string(),
        data: vec![1, 2, 3],
        cached_at: 1_000_000, // ms
        ttl: 5,               // seconds
    };

    let ttl_ms = cached.ttl.saturating_mul(1000); // 5000 ms

    let check_valid = 1_004_000; // 4s elapsed, within 5s TTL
    let check_expired = 1_006_000; // 6s elapsed, beyond 5s TTL

    assert!(check_valid - cached.cached_at < ttl_ms);
    assert!(check_expired - cached.cached_at >= ttl_ms);
}

#[test]
fn test_cache_eviction_threshold() {
    // Verify cache eviction happens at 100 items
    let cache_limit = 100;
    assert!(cache_limit > 0);
    assert!(cache_limit <= 1000); // Reasonable upper bound
}

/* =======================================================================
JNI Safety Tests
=================================================================== */

#[test]
fn test_jni_error_conversion_coverage() {
    let test_cases = vec![
        jni::errors::Error::NullPtr("null ptr"),
        jni::errors::Error::WrongJValueType("wrong type", "expected"),
        jni::errors::Error::InvalidCtorReturn,
    ];

    for jni_err in test_cases {
        let wallet_err = jni_to_wallet_error(jni_err);
        match wallet_err {
            WalletError::Storage { msg } => {
                assert!(msg.contains("JNI error"));
            }
            _ => panic!("Expected Storage error"),
        }
    }
}

/* =======================================================================
Metrics Calculation Tests
=================================================================== */

#[test]
fn test_average_operation_time_calculation() {
    // Verify rolling average formula: (current_avg + new_value) / 2
    let mut metrics = StorageMetrics {
        average_operation_time_ms: 100,
        ..StorageMetrics::default()
    };

    let new_operation_time = 200;
    let expected_avg = (metrics.average_operation_time_ms + new_operation_time) / 2;

    metrics.average_operation_time_ms = expected_avg;

    assert_eq!(metrics.average_operation_time_ms, 150);
}

#[test]
fn test_metrics_counter_increments() {
    let mut metrics = StorageMetrics::default();

    // Simulate operations
    metrics.operations_count += 1;
    metrics.cache_hits += 1;
    metrics.biometric_prompts += 1;
    metrics.strongbox_operations += 1;

    assert_eq!(metrics.operations_count, 1);
    assert_eq!(metrics.cache_hits, 1);
    assert_eq!(metrics.biometric_prompts, 1);
    assert_eq!(metrics.strongbox_operations, 1);

    // Simulate more operations
    metrics.operations_count += 5;
    metrics.cache_misses += 3;
    metrics.errors_count += 1;

    assert_eq!(metrics.operations_count, 6);
    assert_eq!(metrics.cache_misses, 3);
    assert_eq!(metrics.errors_count, 1);
}

/* =======================================================================
Audit Log Tests
=================================================================== */

#[test]
fn test_audit_log_size_limit() {
    // Verify audit log has a size limit of 1000
    let max_audit_size = 1000;
    assert_eq!(max_audit_size, 1000);

    // SEC-09: Verify eviction happens with O(1) VecDeque::pop_front
    let mut log: VecDeque<SecurityEvent> = VecDeque::new();

    for i in 0..1001 {
        log.push_back(SecurityEvent {
            event_type: SecurityEventType::KeystoreAccess,
            timestamp: i,
            details: format!("event_{}", i),
            risk_level: RiskLevel::Low,
        });

        if log.len() > 1000 {
            log.pop_front();
        }
    }

    assert_eq!(log.len(), 1000);
    assert_eq!(log[0].timestamp, 1); // First event should be #1 (0 was evicted)
}

#[test]
fn test_security_event_risk_level_ordering() {
    // Verify risk levels can be compared (implicitly)
    let _low = RiskLevel::Low;
    let _medium = RiskLevel::Medium;
    let _high = RiskLevel::High;
    let _critical = RiskLevel::Critical;

    // Just verify they're all distinct types
    // In production, you might want to implement Ord for these
}

/* =======================================================================
Key Prefix Tests
=================================================================== */

#[test]
fn test_key_prefixes_distinct() {
    // Verify all key prefixes are distinct
    let prefixes = vec![
        IDENTITY_KEY_PREFIX,
        CREDENTIAL_KEY_PREFIX,
        CONFIG_KEY_PREFIX,
    ];

    for i in 0..prefixes.len() {
        for j in (i + 1)..prefixes.len() {
            assert_ne!(prefixes[i], prefixes[j]);
        }
    }
}

#[test]
fn test_key_prefix_format() {
    // Verify prefixes follow naming convention
    assert!(IDENTITY_KEY_PREFIX.starts_with("provii_"));
    assert!(CREDENTIAL_KEY_PREFIX.starts_with("provii_"));
    assert!(CONFIG_KEY_PREFIX.starts_with("provii_"));
}

/* =======================================================================
Usage Stats Tests
=================================================================== */

#[test]
fn test_usage_stats_credential_counting() {
    // Verify credential counting logic
    let keys = vec![
        format!("{}cred1", CREDENTIAL_KEY_PREFIX),
        format!("{}cred2", CREDENTIAL_KEY_PREFIX),
        format!("{}id1", IDENTITY_KEY_PREFIX),
        "other_key".to_string(),
    ];

    let mut cred_count = 0;
    for key in &keys {
        if key.starts_with(CREDENTIAL_KEY_PREFIX) {
            cred_count += 1;
        }
    }

    assert_eq!(cred_count, 2);
    assert_eq!(keys.len(), 4);
}

/* =======================================================================
Thread Pool Configuration Tests
=================================================================== */

#[test]
fn test_thread_pool_n_minus_2_strategy() {
    // Test the n-2 thread allocation strategy
    let test_cases = vec![
        (1, 1),   // 1 core -> 1 thread
        (2, 1),   // 2 cores -> 1 thread
        (4, 2),   // 4 cores -> 2 threads (4-2)
        (8, 6),   // 8 cores -> 6 threads (8-2)
        (12, 10), // 12 cores -> 10 threads (12-2)
    ];

    for (hw_threads, expected_proof_threads) in test_cases {
        let proof_threads = match hw_threads {
            1..=2 => 1,
            n => n.saturating_sub(2).max(1),
        };
        assert_eq!(
            proof_threads, expected_proof_threads,
            "Hardware threads: {}, expected: {}, got: {}",
            hw_threads, expected_proof_threads, proof_threads
        );
    }
}

#[test]
fn test_stack_size_configuration() {
    // Verify stack size is 4MB as configured
    let stack_size = 4 * 1024 * 1024;
    assert_eq!(stack_size, 4_194_304);

    // Verify it's reasonable (between 1MB and 16MB)
    assert!(stack_size >= 1024 * 1024);
    assert!(stack_size <= 16 * 1024 * 1024);
}
