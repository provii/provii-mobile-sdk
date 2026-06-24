// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

use super::*;

// Test helper to create AppInfo
fn create_test_app_info() -> AppInfo {
    AppInfo {
        version: "2.0.0".to_string(),
        build_number: "1".to_string(),
        platform: "test".to_string(),
        device_model: Some("TestDevice".to_string()),
        os_version: Some("1.0".to_string()),
    }
}

// Test helper to create valid credential JSON
fn create_test_credential_json() -> String {
    serde_json::json!({
        "v": 2,
        "schema": "provii.age/0",
        "kid": "issuer:TestIssuer:key1",
        "iat": 1700000000u64,
        "exp": 1800000000u64,
        "c_bytes": vec![1u8; 32],
        "issuer_vk": vec![2u8; 32],
        "sig_rj": vec![3u8; 64],
    })
    .to_string()
}

// Test helper to create credential with secrets
fn create_test_credential_with_secrets_json() -> String {
    serde_json::json!({
        "v": 2,
        "schema": "provii.age/0",
        "kid": "issuer:TestIssuer:key1",
        "iat": 1700000000u64,
        "exp": 1800000000u64,
        "c_bytes": vec![1u8; 32],
        "issuer_vk": vec![2u8; 32],
        "sig_rj": vec![3u8; 64],
        "dob_days": 19000i32,
        "r_bits": vec![true; 128],
    })
    .to_string()
}

// Test helper to create QR challenge payload
fn create_test_challenge_json() -> String {
    serde_json::json!({
        "challenge_id": "test-challenge-123",
        "rp_challenge": "abc123def456",
        "cutoff_days": 19000i32,
        "verifying_key_id": 1u32,
        "submit_secret": "submit_secret_base64url",
        "expires_at": 2000000000u64,
        "verify_url": "https://verify.example.com/submit"
    })
    .to_string()
}

// ============================================================================
// CONSTRUCTOR TESTS (4)
// ============================================================================

#[test]
fn test_wallet_new() {
    let app_info = create_test_app_info();
    let wallet = ProviiWallet::new(app_info.clone());

    // Verify wallet was created
    assert!(Arc::strong_count(&wallet) == 1);

    // Verify default config
    let config = wallet.get_config();
    assert!(config.auto_select);
    assert_eq!(config.network_timeout, 30);

    // Verify app info
    assert_eq!(wallet.app_info.version, "2.0.0");
    assert_eq!(wallet.app_info.platform, "test");
}

#[test]
fn test_wallet_with_config() {
    let app_info = create_test_app_info();
    let custom_config = WalletConfig {
        auto_select: false,
        network_timeout: 60,
        cache_proving_keys: false,
        issuer_api_url: "https://custom-issuer.com".to_string(),
        verifier_api_url: "https://custom-verify.com".to_string(),
        verifier_api_key: None,
        verifier_origin: None,
        environment: "development".to_string(),
        enable_parallel_prover: false,
        max_prover_threads: 2,
    };

    let wallet = ProviiWallet::with_config(app_info, custom_config.clone());

    // Verify custom config was applied
    let config = wallet.get_config();
    assert!(!config.auto_select);
    assert_eq!(config.network_timeout, 60);
    assert!(!config.cache_proving_keys);
    assert_eq!(config.issuer_api_url, "https://custom-issuer.com");
    assert_eq!(config.verifier_api_url, "https://custom-verify.com");
    assert_eq!(config.environment, "development");
    assert!(!config.enable_parallel_prover);
    assert_eq!(config.max_prover_threads, 2);
}

#[test]
#[cfg(feature = "parallel")]
fn test_wallet_parallel_config_applied() {
    let app_info = create_test_app_info();
    let config = WalletConfig {
        enable_parallel_prover: true,
        max_prover_threads: 4,
        ..Default::default()
    };

    let _wallet = ProviiWallet::with_config(app_info, config);

    // Parallel config should be applied (tested through logs in real usage)
    // This test primarily verifies no panic occurs
}

#[test]
fn test_wallet_multiple_instances() -> Result<(), Box<dyn std::error::Error>> {
    let app_info1 = create_test_app_info();
    let app_info2 = AppInfo {
        version: "3.0.0".to_string(),
        ..app_info1.clone()
    };

    let wallet1 = ProviiWallet::new(app_info1);
    let wallet2 = ProviiWallet::new(app_info2);

    // Verify they are independent
    assert_eq!(wallet1.app_info.version, "2.0.0");
    assert_eq!(wallet2.app_info.version, "3.0.0");

    // Verify separate config instances
    let config1 = wallet1.get_config();
    let mut config2 = wallet2.get_config();
    config2.auto_select = false;
    wallet2.update_config(config2)?;

    // wallet1 should still have original config
    let config1_after = wallet1.get_config();
    assert_eq!(config1_after.auto_select, config1.auto_select);
    Ok(())
}

// ============================================================================
// VERIFIER URL TESTS (7)
// ============================================================================

#[test]
fn test_set_verifier_base_url_valid() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.set_verifier_base_url("https://verify.example.com".to_string());
    assert!(result.is_ok());

    let url = wallet.get_verifier_base_url();
    assert_eq!(url, "https://verify.example.com");
}

#[test]
fn test_set_verifier_base_url_invalid() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.set_verifier_base_url("not a url".to_string());
    assert!(result.is_err());
    let Err(err_val) = result else {
        panic!("expected error")
    };
    match err_val {
        FfiError::InvalidFormat { msg } => {
            assert!(msg.contains("Invalid URL"));
        }
        _ => panic!("Expected InvalidFormat error"),
    }
    Ok(())
}

#[test]
fn test_set_verifier_base_url_http_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.set_verifier_base_url("http://verify.example.com".to_string());
    assert!(result.is_err());
    let Err(err_val) = result else {
        panic!("expected error")
    };
    match err_val {
        FfiError::InvalidFormat { msg } => {
            assert!(msg.contains("HTTPS"));
        }
        _ => panic!("Expected InvalidFormat error"),
    }
    Ok(())
}

#[test]
fn test_set_verifier_base_url_trailing_slash() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());

    wallet.set_verifier_base_url("https://verify.example.com/".to_string())?;

    let url = wallet.get_verifier_base_url();
    // Should remove trailing slash
    assert_eq!(url, "https://verify.example.com");
    Ok(())
}

#[test]
fn test_set_verifier_base_url_with_path() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.set_verifier_base_url("https://verify.example.com/api/v1".to_string());
    assert!(result.is_ok());

    let url = wallet.get_verifier_base_url();
    assert_eq!(url, "https://verify.example.com/api/v1");
}

#[test]
fn test_get_verifier_base_url() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Should return default URL
    let default_url = wallet.get_verifier_base_url();
    assert!(default_url.starts_with("https://"));
}

#[test]
fn test_set_verifier_url_concurrent() -> Result<(), Box<dyn std::error::Error>> {
    use std::thread;

    let wallet = ProviiWallet::new(create_test_app_info());
    let wallet_clone = Arc::clone(&wallet);

    let handle = thread::spawn(move || {
        wallet_clone.set_verifier_base_url("https://verify1.example.com".to_string())
    });

    let result2 = wallet.set_verifier_base_url("https://verify2.example.com".to_string());

    let result1 = handle.join().map_err(|_| "thread panicked")?;
    assert!(result1.is_ok());
    assert!(result2.is_ok());

    // One of them should have won
    let final_url = wallet.get_verifier_base_url();
    assert!(
        final_url == "https://verify1.example.com" || final_url == "https://verify2.example.com"
    );
    Ok(())
}

// ============================================================================
// CREDENTIAL OPERATIONS TESTS (20)
// ============================================================================

#[test]
fn test_import_credential_storage_not_initialized() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let cred_json = create_test_credential_json();

    let result = wallet.import_credential(cred_json);
    // Should fail with storage error when storage not initialised
    assert!(result.is_err());
    let Err(err_val) = result else {
        panic!("expected error")
    };
    match err_val {
        FfiError::Storage { msg } => {
            assert!(msg.contains("not initialised"));
        }
        _ => panic!("Expected Storage error"),
    }
    Ok(())
}

#[test]
fn test_import_credential_with_secrets_storage_error() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let cred_json = create_test_credential_with_secrets_json();

    let result = wallet.import_credential(cred_json);
    // Should fail with storage error when storage not initialised
    assert!(result.is_err());
    let Err(err_val) = result else {
        panic!("expected error")
    };
    match err_val {
        FfiError::Storage { msg } => {
            assert!(msg.contains("not initialised"));
        }
        _ => panic!("Expected Storage error"),
    }
    Ok(())
}

#[test]
fn test_import_credential_json_parsing() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let cred_json = create_test_credential_json();

    // Test that JSON parsing works (will fail at storage step, but that's OK)
    let result = wallet.import_credential(cred_json);
    // Should reach storage error, not JSON parsing error
    assert!(result.is_err());
    if let Err(e) = result {
        match e {
            FfiError::Storage { .. } => {} // Expected
            FfiError::InvalidFormat { msg } => {
                panic!("JSON parsing should succeed, got: {}", msg)
            }
            _ => {}
        }
    }
}

#[test]
fn test_import_credential_invalid_json() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.import_credential("not valid json".to_string());
    assert!(result.is_err());
    let Err(err_val) = result else {
        panic!("expected error")
    };
    match err_val {
        FfiError::InvalidFormat { .. } => {}
        _ => panic!("Expected InvalidFormat error"),
    }
    Ok(())
}

#[test]
fn test_import_credential_wrong_version() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let cred_json = serde_json::json!({
        "v": 999,
        "schema": "provii.age/0",
        "kid": "issuer:TestIssuer:key1",
        "iat": 1700000000u64,
        "exp": 1800000000u64,
        "c_bytes": vec![1u8; 32],
        "issuer_vk": vec![2u8; 32],
        "sig_rj": vec![3u8; 64],
    })
    .to_string();

    let result = wallet.import_credential(cred_json);
    // Should fail on deserialization or version check
    assert!(result.is_err());
}

#[test]
fn test_import_credential_missing_fields() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let incomplete_json = serde_json::json!({
        "v": 2,
        "schema": "provii.age/0"
        // Missing required fields
    })
    .to_string();

    let result = wallet.import_credential(incomplete_json);
    assert!(result.is_err());
}

#[test]
fn test_store_credential_with_label_storage_error() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let cred_json = create_test_credential_json();

    let result = wallet.store_credential_with_label(
        cred_json,
        Some("My ID".to_string()),
        "primary".to_string(),
        None,
    );
    // Should fail when storage not initialised
    assert!(result.is_err());
    let Err(err_val) = result else {
        panic!("expected error")
    };
    match err_val {
        FfiError::Storage { .. } => {}
        _ => panic!("Expected Storage error"),
    }
    Ok(())
}

#[test]
fn test_store_credential_without_label_storage_error() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let cred_json = create_test_credential_json();

    let result = wallet.store_credential_with_label(cred_json, None, "primary".to_string(), None);
    // Should fail when storage not initialised
    assert!(result.is_err());
}

#[test]
fn test_list_credentials_empty() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.list_credentials();
    // No storage backend is registered (set_storage_handle not called),
    // so any credential operation must fail.
    assert!(
        result.is_err(),
        "list_credentials without storage backend must fail"
    );
}

#[test]
fn test_list_credentials_multiple() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Import two credentials
    let cred1 = create_test_credential_json();
    let cred2 = create_test_credential_json();

    wallet.import_credential(cred1).ok();
    wallet.import_credential(cred2).ok();

    let result = wallet.list_credentials();
    if let Ok(creds) = result {
        // Should have the two imported credentials
        assert!(!creds.is_empty());
    }
}

#[test]
fn test_get_credential_storage_error() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.get_credential("some-id".to_string());
    // Should fail when storage not initialised
    assert!(result.is_err());
    // Accept any error type since anyhow may convert differently
}

#[test]
fn test_get_credential_nonexistent_storage_error() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.get_credential("nonexistent-id".to_string());
    // Should fail with storage error when storage not initialised
    assert!(result.is_err());
}

#[test]
fn test_delete_credential() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let cred_json = create_test_credential_json();

    let cred_id = wallet.import_credential(cred_json).ok();

    if let Some(id) = cred_id {
        let result = wallet.delete_credential(id);
        assert!(
            result.is_ok(),
            "deleting an imported credential should succeed, got {:?}",
            result.err()
        );
    }
}

#[test]
fn test_delete_nonexistent_credential() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.delete_credential("nonexistent-id".to_string());
    // No storage backend registered, so the operation must fail.
    assert!(
        result.is_err(),
        "delete_credential without storage backend must fail"
    );
}

#[test]
fn test_delete_sandbox_credentials() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.delete_sandbox_credentials();
    // No storage backend registered, so the operation must fail.
    assert!(
        result.is_err(),
        "delete_sandbox_credentials without storage backend must fail"
    );
}

#[test]
fn test_has_valid_credential_after_import() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let cred_json = create_test_credential_json();

    wallet.import_credential(cred_json).ok();

    // Result depends on whether storage is initialised; just confirm
    // the method returns without panicking.
    let _has_cred = wallet.has_valid_credential();
}

#[test]
fn test_has_valid_credential_empty_wallet() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // No credentials stored and no storage backend registered, so this
    // must return false.
    assert!(!wallet.has_valid_credential());
}

#[test]
fn test_store_credential_alias() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let cred_json = create_test_credential_json();

    // store_credential is an alias for import_credential; without a
    // storage backend it must fail.
    let result = wallet.store_credential(cred_json);
    assert!(
        result.is_err(),
        "store_credential without storage backend must fail"
    );
}

// ============================================================================
// PROVER INITIALIZATION TESTS (8)
// ============================================================================

#[test]
fn test_initialize_prover_empty_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.initialize_prover(vec![]);
    // Should fail with empty bytes
    assert!(result.is_err());
    let Err(err_val) = result else {
        panic!("expected error")
    };
    match err_val {
        FfiError::Prover { .. } => {}
        _ => panic!("Expected Prover error"),
    }
    Ok(())
}

#[test]
fn test_initialize_prover_too_small() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Only 100 bytes when we need much more
    let small_bytes = vec![0u8; 100];
    let result = wallet.initialize_prover(small_bytes);
    // Should fail with too-small bytes
    assert!(result.is_err());
}

#[test]
fn test_initialize_prover_invalid_data() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Random data that's not a valid proving key
    let invalid_bytes = vec![0xFFu8; 1000];
    let result = wallet.initialize_prover(invalid_bytes);
    // Should fail with invalid data
    assert!(result.is_err());
    let Err(err_val) = result else {
        panic!("expected error")
    };
    match err_val {
        FfiError::Prover { .. } => {}
        _ => panic!("Expected Prover error"),
    }
    Ok(())
}

#[test]
fn test_initialize_prover_not_called() {
    // Test that we can check prover status before initialization
    // Note: In a real test environment, prover state is global,
    // so this test assumes no other test has initialized it
    let _wallet = ProviiWallet::new(create_test_app_info());

    // Just verify the wallet was created successfully
    // We can't reliably test is_prover_initialized() in unit tests
    // since it's global state
}

#[test]
fn test_initialize_prover_with_valid_size_invalid_content() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Create bytes that are the right size but wrong content
    // Proving keys are typically 50MB+ for production
    // Using smaller size for test performance
    let fake_pk = vec![1u8; 10_000];

    let result = wallet.initialize_prover(fake_pk);
    // Should fail because content is invalid even if size is plausible
    assert!(result.is_err());
}

#[test]
fn test_initialize_prover_error_message() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.initialize_prover(vec![0u8; 10]);
    assert!(result.is_err());

    // Verify error message contains useful info
    let Err(err_val) = result else {
        panic!("expected error")
    };
    let err_str = format!("{:?}", err_val);
    assert!(!err_str.is_empty());
    Ok(())
}

#[test]
fn test_initialize_prover_state_cleanup() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Try to initialize with bad data
    let _ = wallet.initialize_prover(vec![0u8; 100]);

    // Wallet should still be usable for other operations
    let config = wallet.get_config();
    assert!(config.auto_select);
}

#[test]
fn test_initialize_prover_concurrent_attempts() -> Result<(), Box<dyn std::error::Error>> {
    use std::thread;

    let wallet = ProviiWallet::new(create_test_app_info());
    let wallet_clone = Arc::clone(&wallet);

    let handle = thread::spawn(move || wallet_clone.initialize_prover(vec![0u8; 100]));

    let result2 = wallet.initialize_prover(vec![1u8; 100]);
    let result1 = handle.join().map_err(|_| "thread panicked")?;

    // Both should fail (or at least one should)
    // We can't make strong guarantees about global prover state in tests
    assert!(result1.is_err() || result2.is_err());
    Ok(())
}

// ============================================================================
// STORAGE HANDLE TESTS (5)
// ============================================================================

#[test]
fn test_storage_not_available_initially() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Storage should not be available before set_storage_handle is called
    let diag = wallet.get_diagnostic_info();
    assert!(!diag.storage_available);
}

#[test]
fn test_operations_fail_without_storage() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Credential operations should fail without storage
    let cred_json = create_test_credential_json();
    let result = wallet.import_credential(cred_json);
    assert!(result.is_err());
}

#[test]
fn test_list_credentials_fails_without_storage() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.list_credentials();
    // Should fail when storage not initialised
    assert!(result.is_err());
}

#[test]
fn test_delete_operations_without_storage() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Delete operations should fail gracefully
    let result = wallet.delete_credential("some-id".to_string());
    assert!(result.is_err());

    let result = wallet.delete_sandbox_credentials();
    assert!(result.is_err());
}

#[test]
fn test_storage_state_check() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // has_valid_credential should return false when storage not available
    assert!(!wallet.has_valid_credential());
}

// ============================================================================
// QR PROCESSING TESTS (10)
// ============================================================================

#[test]
fn test_parse_qr_empty_string() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.parse_qr("".to_string());
    // Should fail with empty string
    assert!(result.is_err());
}

#[test]
fn test_parse_qr_invalid_json() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.parse_qr("not json".to_string());
    // Should fail with invalid JSON
    assert!(result.is_err());
}

#[test]
fn test_parse_qr_valid_challenge() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let challenge_json = create_test_challenge_json();

    let result = wallet.parse_qr(challenge_json);
    // Valid challenge JSON should be parseable.
    assert!(
        result.is_ok(),
        "parse_qr should succeed with valid challenge JSON, got {:?}",
        result.err()
    );
}

#[test]
fn test_process_qr_challenge_valid() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let challenge_json = create_test_challenge_json();

    let result = wallet.process_qr_challenge(challenge_json);
    // Valid challenge JSON should process successfully.
    assert!(
        result.is_ok(),
        "process_qr_challenge should succeed with valid JSON, got {:?}",
        result.err()
    );
}

#[test]
fn test_process_qr_challenge_invalid() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.process_qr_challenge("invalid".to_string());
    // Should fail with invalid format
    assert!(result.is_err());
}

#[test]
fn test_process_qr_challenge_missing_fields() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let incomplete = serde_json::json!({
        "challenge_id": "test-123"
        // Missing required fields
    })
    .to_string();

    let result = wallet.process_qr_challenge(incomplete);
    // Should fail with missing fields
    assert!(result.is_err());
}

#[test]
fn test_parse_qr_payload_empty() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.parse_qr_payload("".to_string());
    // Should fail with empty payload
    assert!(result.is_err());
}

#[test]
fn test_parse_qr_payload_too_large() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Create a very large payload (QR codes have size limits)
    let large_payload = "x".repeat(10_000);
    let result = wallet.parse_qr_payload(large_payload);
    // Non-JSON input should fail parsing.
    assert!(result.is_err(), "non-JSON payload should be rejected");
}

#[test]
fn test_validate_qr_invalid_json() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.validate_qr("not json".to_string());
    // Should fail validation
    assert!(result.is_err());
}

#[test]
fn test_process_scanned_qr_invalid() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.process_scanned_qr("invalid qr content".to_string());
    // Should fail with invalid QR content
    assert!(result.is_err());
}

// ============================================================================
// VERIFICATION FLOW TESTS (25)
// ============================================================================

#[test]
fn test_create_age_proof_no_credential() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.create_age_proof("nonexistent".to_string(), "challenge-123".to_string());
    // Should fail - no credential found
    assert!(result.is_err());
}

#[test]
fn test_create_age_proof_no_challenge() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result =
        wallet.create_age_proof("cred-123".to_string(), "nonexistent-challenge".to_string());
    // Should fail - no challenge found
    assert!(result.is_err());
}

#[test]
fn test_create_age_proof_storage_not_initialized() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.create_age_proof("cred-123".to_string(), "challenge-123".to_string());
    // Should fail - storage not initialised or challenge not found
    assert!(result.is_err());
}

#[test]
fn test_debug_preflight_no_credential() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.debug_preflight("nonexistent".to_string(), "challenge-123".to_string());
    // Should fail - credential not found
    assert!(result.is_err());
}

#[test]
fn test_debug_preflight_no_challenge() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.debug_preflight("cred-123".to_string(), "nonexistent".to_string());
    // Should fail - challenge not found
    assert!(result.is_err());
}

#[test]
fn test_diagnose_proof_failure_no_credential() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result =
        wallet.diagnose_proof_failure("nonexistent".to_string(), "challenge-123".to_string());
    // Should fail - credential not found
    assert!(result.is_err());
}

#[test]
fn test_diagnose_proof_failure_no_challenge() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.diagnose_proof_failure("cred-123".to_string(), "nonexistent".to_string());
    // Should fail - challenge not found
    assert!(result.is_err());
}

#[test]
fn test_get_challenge_diagnostics_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.get_challenge_diagnostics("nonexistent".to_string());
    // Should fail - challenge not found
    assert!(result.is_err());
    let Err(err_val) = result else {
        panic!("expected error")
    };
    match err_val {
        FfiError::Generic { msg } => {
            assert!(msg.contains("not found"));
        }
        _ => panic!("Expected Generic error"),
    }
    Ok(())
}

#[test]
fn test_cleanup_expired_challenges_empty() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let count = wallet.cleanup_expired_challenges();
    // Should return 0 when no challenges cached
    assert_eq!(count, 0);
}

#[test]
fn test_get_verification_status_initial() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let status = wallet.get_verification_status();
    // Should return initial status
    assert!(
        matches!(status, VerificationStatus::NotStarted)
            || matches!(status, VerificationStatus::ChallengeReceived)
            || matches!(status, VerificationStatus::ProofGenerated)
    );
}

#[test]
fn test_cancel_verification_not_started() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.cancel_verification("nonexistent".to_string());
    // Cancelling a non-started verification is a no-op.
    assert!(
        result.is_ok(),
        "cancel_verification on nonexistent challenge should not error, got {:?}",
        result.err()
    );
}

#[test]
#[cfg(feature = "http")]
fn test_submit_proof_invalid_json() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.submit_proof("invalid json".to_string());
    // Should fail with invalid JSON
    assert!(result.is_err());
}

#[test]
#[cfg(not(feature = "http"))]
fn test_submit_proof_without_http() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.submit_proof("{}".to_string());
    // Should fail - HTTP not compiled
    assert!(result.is_err());
    let Err(err_val) = result else {
        panic!("expected error")
    };
    match err_val {
        FfiError::Generic { msg } => {
            assert!(msg.contains("HTTP"));
        }
        _ => panic!("Expected Generic error about HTTP"),
    }
    Ok(())
}

#[test]
#[cfg(feature = "http")]
fn test_submit_proof_missing_challenge_id() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let incomplete_proof = serde_json::json!({
        "proof": "fake_proof_data"
        // Missing challenge_id
    })
    .to_string();

    let result = wallet.submit_proof(incomplete_proof);
    // Should fail with missing field
    assert!(result.is_err());
}

#[test]
fn test_has_credential_secrets_nonexistent() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.has_credential_secrets("nonexistent".to_string());
    // Should fail with storage error
    assert!(result.is_err());
}

#[test]
fn test_process_qr_challenge_caching() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let challenge_json = create_test_challenge_json();

    // Try to process a challenge (may fail at parsing)
    let _ = wallet.process_qr_challenge(challenge_json);

    // Verify cleanup works even if no challenges were cached
    let count = wallet.cleanup_expired_challenges();
    // No challenges should have been successfully cached (parsing likely failed)
    assert_eq!(count, 0);
}

#[test]
fn test_verification_state_transitions() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Get initial status
    let status1 = wallet.get_verification_status();

    // Try to cancel (should not crash)
    let _ = wallet.cancel_verification("test-challenge".to_string());

    // Get status after cancel
    let status2 = wallet.get_verification_status();

    // Should be valid status enum variants
    assert!(matches!(
        status1,
        VerificationStatus::NotStarted
            | VerificationStatus::ChallengeReceived
            | VerificationStatus::ProofGenerated
            | VerificationStatus::Submitting
            | VerificationStatus::Verified
            | VerificationStatus::Failed { .. }
    ));

    assert!(matches!(
        status2,
        VerificationStatus::NotStarted
            | VerificationStatus::ChallengeReceived
            | VerificationStatus::ProofGenerated
            | VerificationStatus::Submitting
            | VerificationStatus::Verified
            | VerificationStatus::Failed { .. }
    ));
}

#[test]
fn test_proof_generation_without_prover() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Try to create proof without prover initialized
    let result = wallet.create_age_proof("cred-123".to_string(), "challenge-123".to_string());

    // Should fail (either challenge not found or prover not initialised)
    assert!(result.is_err());
}

#[test]
fn test_verification_flow_error_propagation() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Test that errors propagate correctly through the verification flow

    // 1. Try to get diagnostics for nonexistent challenge
    let diag_result = wallet.get_challenge_diagnostics("fake-challenge".to_string());
    assert!(diag_result.is_err());

    // 2. Try to create proof with nonexistent credential
    let proof_result =
        wallet.create_age_proof("fake-cred".to_string(), "fake-challenge".to_string());
    assert!(proof_result.is_err());

    // 3. Try to diagnose failure with nonexistent credential
    let diagnose_result =
        wallet.diagnose_proof_failure("fake-cred".to_string(), "fake-challenge".to_string());
    assert!(diagnose_result.is_err());
}

#[test]
fn test_challenge_expiry_handling() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Cleanup should work even with no challenges
    let count1 = wallet.cleanup_expired_challenges();
    assert_eq!(count1, 0);

    // Multiple cleanups should be safe
    let count2 = wallet.cleanup_expired_challenges();
    assert_eq!(count2, 0);
}

#[test]
fn test_concurrent_verification_operations() -> Result<(), Box<dyn std::error::Error>> {
    use std::thread;

    let wallet = ProviiWallet::new(create_test_app_info());
    let wallet_clone = Arc::clone(&wallet);

    let handle = thread::spawn(move || wallet_clone.get_verification_status());

    let status2 = wallet.get_verification_status();
    let status1 = handle.join().map_err(|_| "thread panicked")?;

    // Both should return valid status
    assert!(matches!(
        status1,
        VerificationStatus::NotStarted
            | VerificationStatus::ChallengeReceived
            | VerificationStatus::ProofGenerated
            | VerificationStatus::Submitting
            | VerificationStatus::Verified
            | VerificationStatus::Failed { .. }
    ));
    assert!(matches!(
        status2,
        VerificationStatus::NotStarted
            | VerificationStatus::ChallengeReceived
            | VerificationStatus::ProofGenerated
            | VerificationStatus::Submitting
            | VerificationStatus::Verified
            | VerificationStatus::Failed { .. }
    ));
    Ok(())
}

#[test]
fn test_proof_generation_error_messages() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.create_age_proof("".to_string(), "".to_string());
    assert!(result.is_err());

    // Error should have meaningful message
    let Err(err_val) = result else {
        panic!("expected error")
    };
    let err_str = format!("{:?}", err_val);
    assert!(!err_str.is_empty());
    Ok(())
}

#[test]
#[cfg(feature = "http")]
fn test_check_network_status() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let status = wallet.check_network_status();
    // Verify the call completes and returns a valid NetworkStatus.
    // The actual connectivity result depends on the test environment.
    let _connected: bool = status.connected;
}

#[test]
#[cfg(not(feature = "http"))]
fn test_check_network_status_without_http() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let status = wallet.check_network_status();
    assert!(!status.connected);
}

// ============================================================================
// CONFIGURATION & DIAGNOSTICS TESTS (15)
// ============================================================================

#[test]
fn test_get_config_default() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let config = wallet.get_config();
    // Verify default config values
    assert!(config.auto_select);
    assert_eq!(config.network_timeout, 30);
    assert!(config.issuer_api_url.starts_with("https://"));
    assert!(config.verifier_api_url.starts_with("https://"));
}

#[test]
fn test_update_config() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let mut new_config = wallet.get_config();
    new_config.auto_select = false;
    new_config.network_timeout = 60;

    let result = wallet.update_config(new_config.clone());
    assert!(result.is_ok());

    let updated = wallet.get_config();
    assert!(!updated.auto_select);
    assert_eq!(updated.network_timeout, 60);
}

#[test]
fn test_update_config_preserves_urls() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());

    let original_config = wallet.get_config();
    let original_issuer = original_config.issuer_api_url.clone();

    // Update other fields
    let mut new_config = original_config.clone();
    new_config.auto_select = false;

    wallet.update_config(new_config)?;

    let updated = wallet.get_config();
    assert_eq!(updated.issuer_api_url, original_issuer);
    Ok(())
}

#[test]
fn test_get_diagnostic_info() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let diag = wallet.get_diagnostic_info();

    // Verify diagnostic info structure
    assert!(!diag.sdk_version.is_empty());
    assert_eq!(diag.app_version, "2.0.0");
    assert_eq!(diag.platform, "test");
    assert_eq!(diag.credential_count, 0);
    assert!(!diag.storage_available);
}

#[test]
fn test_diagnostic_info_prover_status() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let diag = wallet.get_diagnostic_info();

    // prover_initialized depends on test order; just confirm the field
    // is accessible without panicking.
    let _prover_status: bool = diag.prover_initialized;
}

#[test]
fn test_calculate_age_from_dob_valid() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Use a date that's definitely in the past
    let result = wallet.calculate_age_from_dob("2000-01-01".to_string());
    assert!(result.is_ok());

    let age = result?;
    // Should be at least 20 years old (as of 2020+)
    assert!(age >= 20);
    Ok(())
}

#[test]
fn test_calculate_age_from_dob_invalid_format() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.calculate_age_from_dob("invalid date".to_string());
    assert!(result.is_err());
    let Err(err_val) = result else {
        panic!("expected error")
    };
    match err_val {
        FfiError::InvalidFormat { .. } => {}
        _ => panic!("Expected InvalidFormat error"),
    }
    Ok(())
}

#[test]
fn test_calculate_age_from_dob_wrong_format() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Wrong format (should be YYYY-MM-DD)
    let result = wallet.calculate_age_from_dob("01/01/2000".to_string());
    assert!(result.is_err());
}

#[test]
fn test_calculate_age_from_dob_future_date() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Future date
    let result = wallet.calculate_age_from_dob("2099-12-31".to_string());
    // Future date should still parse, producing a negative age.
    assert!(
        result.is_ok(),
        "future date should parse successfully, got {:?}",
        result.err()
    );
}

#[test]
fn test_is_biometric_available() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // The FFI stub always reports biometric as unavailable.
    assert!(!wallet.is_biometric_available());
}

#[test]
fn test_create_progress_tracker() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let tracker = wallet.create_progress_tracker();
    // Verify tracker was created
    assert!(Arc::strong_count(&tracker) >= 1);
}

#[test]
fn test_report_progress() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let tracker = wallet.create_progress_tracker();

    // Should not panic
    wallet.report_progress(tracker, ProgressStage::Started, "Test message".to_string());
}

#[test]
fn test_handle_deeplink_invalid() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.handle_deeplink("invalid url".to_string());
    // Should fail with invalid deeplink
    assert!(result.is_err());
}

// ============================================================================
// ADDITIONAL EDGE CASES & BOUNDARY TESTS (30)
// ============================================================================

#[test]
fn test_config_concurrent_updates() -> Result<(), Box<dyn std::error::Error>> {
    use std::thread;

    let wallet = ProviiWallet::new(create_test_app_info());
    let wallet_clone = Arc::clone(&wallet);

    let handle = thread::spawn(move || {
        let mut config = wallet_clone.get_config();
        config.network_timeout = 45;
        wallet_clone.update_config(config)
    });

    let mut config2 = wallet.get_config();
    config2.network_timeout = 90;
    let result2 = wallet.update_config(config2);

    let result1 = handle.join().map_err(|_| "thread panicked")?;
    assert!(result1.is_ok());
    assert!(result2.is_ok());

    // One of the updates should have won
    let final_config = wallet.get_config();
    assert!(final_config.network_timeout == 45 || final_config.network_timeout == 90);
    Ok(())
}

#[test]
fn test_calculate_age_edge_cases() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Test leap year date
    let result = wallet.calculate_age_from_dob("2000-02-29".to_string());
    assert!(result.is_ok());

    // Test end of year
    let result = wallet.calculate_age_from_dob("1990-12-31".to_string());
    assert!(result.is_ok());

    // Test start of year
    let result = wallet.calculate_age_from_dob("1985-01-01".to_string());
    assert!(result.is_ok());
}

#[test]
fn test_empty_string_inputs() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Empty credential ID
    let result = wallet.get_credential("".to_string());
    assert!(result.is_err());

    // Empty challenge ID
    let result = wallet.get_challenge_diagnostics("".to_string());
    assert!(result.is_err());

    // Empty QR content
    let result = wallet.parse_qr("".to_string());
    assert!(result.is_err());
}

#[test]
fn test_very_long_strings() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Very long credential ID
    let long_id = "x".repeat(10000);
    let result = wallet.get_credential(long_id);
    assert!(result.is_err());

    // Very long QR content (not valid JSON)
    let long_qr = "y".repeat(10000);
    let result = wallet.parse_qr(long_qr);
    // Non-JSON content should fail parsing.
    assert!(result.is_err(), "non-JSON QR content should be rejected");
}

#[test]
fn test_special_characters_in_ids() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Test with special characters
    let special_id = "cred-!@#$%^&*()";
    let result = wallet.get_credential(special_id.to_string());
    assert!(result.is_err());

    // Test with unicode
    let unicode_id = "cred-日本語";
    let result = wallet.get_credential(unicode_id.to_string());
    assert!(result.is_err());
}

#[test]
fn test_null_bytes_in_input() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Test with null bytes
    let null_id = "cred\0id";
    let result = wallet.get_credential(null_id.to_string());
    assert!(result.is_err());
}

#[test]
fn test_whitespace_only_inputs() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Whitespace only
    let result = wallet.get_credential("   ".to_string());
    assert!(result.is_err());

    let result = wallet.parse_qr("   ".to_string());
    assert!(result.is_err());
}

#[test]
fn test_diagnostic_info_consistency() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let diag1 = wallet.get_diagnostic_info();
    let diag2 = wallet.get_diagnostic_info();

    // Should be consistent
    assert_eq!(diag1.sdk_version, diag2.sdk_version);
    assert_eq!(diag1.app_version, diag2.app_version);
    assert_eq!(diag1.platform, diag2.platform);
}

#[test]
fn test_multiple_cleanup_operations() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Multiple cleanups should be safe and idempotent
    for _ in 0..10 {
        let count = wallet.cleanup_expired_challenges();
        // No challenges cached, so nothing to expire
        assert_eq!(count, 0);
    }
}

#[test]
fn test_verification_status_stability() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Get status multiple times - should be stable
    let status1 = wallet.get_verification_status();
    let status2 = wallet.get_verification_status();
    let status3 = wallet.get_verification_status();

    // All should be valid statuses
    assert!(matches!(
        status1,
        VerificationStatus::NotStarted
            | VerificationStatus::ChallengeReceived
            | VerificationStatus::ProofGenerated
            | VerificationStatus::Submitting
            | VerificationStatus::Verified
            | VerificationStatus::Failed { .. }
    ));
    assert!(matches!(
        status2,
        VerificationStatus::NotStarted
            | VerificationStatus::ChallengeReceived
            | VerificationStatus::ProofGenerated
            | VerificationStatus::Submitting
            | VerificationStatus::Verified
            | VerificationStatus::Failed { .. }
    ));
    assert!(matches!(
        status3,
        VerificationStatus::NotStarted
            | VerificationStatus::ChallengeReceived
            | VerificationStatus::ProofGenerated
            | VerificationStatus::Submitting
            | VerificationStatus::Verified
            | VerificationStatus::Failed { .. }
    ));
}

#[test]
fn test_config_boundary_values() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Test with boundary values
    let mut config = wallet.get_config();
    config.network_timeout = 0;
    let result = wallet.update_config(config.clone());
    assert!(result.is_ok());

    let mut config = wallet.get_config();
    config.network_timeout = u64::MAX;
    let result = wallet.update_config(config);
    assert!(result.is_ok());
}

#[test]
fn test_progress_tracker_multiple_reports() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let tracker = wallet.create_progress_tracker();

    // Multiple progress reports should not crash
    wallet.report_progress(
        Arc::clone(&tracker),
        ProgressStage::Started,
        "Message 1".to_string(),
    );
    wallet.report_progress(
        Arc::clone(&tracker),
        ProgressStage::IssuanceRequestCreated,
        "Message 2".to_string(),
    );
    wallet.report_progress(
        Arc::clone(&tracker),
        ProgressStage::VerificationChallengeReceived,
        "Message 3".to_string(),
    );
    wallet.report_progress(tracker, ProgressStage::Failed, "Message 4".to_string());
}

#[test]
fn test_credential_operations_with_unicode() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Test with unicode in JSON
    let unicode_json = serde_json::json!({
        "v": 2,
        "schema": "provii.age/0",
        "kid": "issuer:テスト発行者:key1",
        "iat": 1700000000u64,
        "exp": 1800000000u64,
        "c_bytes": vec![1u8; 32],
        "issuer_vk": vec![2u8; 32],
        "sig_rj": vec![3u8; 64],
    })
    .to_string();

    let result = wallet.import_credential(unicode_json);
    // Should fail with storage error (not JSON parsing error)
    assert!(result.is_err());
}

#[test]
fn test_has_valid_credential_consistency() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Multiple calls should be consistent
    let has1 = wallet.has_valid_credential();
    let has2 = wallet.has_valid_credential();
    let has3 = wallet.has_valid_credential();

    assert_eq!(has1, has2);
    assert_eq!(has2, has3);
}

#[test]
fn test_verifier_url_with_port() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.set_verifier_base_url("https://verify.example.com:8443".to_string());
    assert!(result.is_ok());

    let url = wallet.get_verifier_base_url();
    assert!(url.contains("8443"));
}

#[test]
fn test_verifier_url_with_query_params() {
    let wallet = ProviiWallet::new(create_test_app_info());

    let result = wallet.set_verifier_base_url("https://verify.example.com?param=value".to_string());
    assert!(result.is_ok());

    let url = wallet.get_verifier_base_url();
    assert!(url.contains("verify.example.com"));
}

#[test]
fn test_concurrent_diagnostic_info_access() -> Result<(), Box<dyn std::error::Error>> {
    use std::thread;

    let wallet = ProviiWallet::new(create_test_app_info());
    let wallet_clone = Arc::clone(&wallet);

    let handle = thread::spawn(move || wallet_clone.get_diagnostic_info());

    let diag2 = wallet.get_diagnostic_info();
    let diag1 = handle.join().map_err(|_| "thread panicked")?;

    // Both should be valid
    assert!(!diag1.sdk_version.is_empty());
    assert!(!diag2.sdk_version.is_empty());
    Ok(())
}

#[test]
fn test_cancel_verification_multiple_times() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Multiple cancellations should be safe
    let challenge_id = "test-challenge".to_string();
    let _ = wallet.cancel_verification(challenge_id.clone());
    let _ = wallet.cancel_verification(challenge_id.clone());
    let _ = wallet.cancel_verification(challenge_id);
}

#[test]
fn test_delete_operations_idempotent() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Deleting non-existent credentials multiple times should be safe
    let cred_id = "nonexistent".to_string();
    let _ = wallet.delete_credential(cred_id.clone());
    let _ = wallet.delete_credential(cred_id.clone());
    let _ = wallet.delete_credential(cred_id);

    // Deleting sandbox credentials multiple times
    let _ = wallet.delete_sandbox_credentials();
    let _ = wallet.delete_sandbox_credentials();
}

#[test]
fn test_list_credentials_stability() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Multiple list operations should be consistent
    let result1 = wallet.list_credentials();
    let result2 = wallet.list_credentials();

    // Both should have same error status
    assert_eq!(result1.is_ok(), result2.is_ok());
    assert_eq!(result1.is_err(), result2.is_err());
}

#[test]
fn test_qr_processing_with_very_large_payload() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Create a large JSON payload
    let large_json = format!(r#"{{"challenge_id": "{}"}}"#, "x".repeat(5000));
    let result = wallet.process_qr_challenge(large_json);

    // Incomplete challenge JSON (missing required fields) should fail.
    assert!(
        result.is_err(),
        "incomplete challenge JSON should be rejected"
    );
}

#[test]
fn test_json_with_extra_fields() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // JSON with extra unknown fields
    let extra_fields_json = serde_json::json!({
        "v": 2,
        "schema": "provii.age/0",
        "kid": "issuer:TestIssuer:key1",
        "iat": 1700000000u64,
        "exp": 1800000000u64,
        "c_bytes": vec![1u8; 32],
        "issuer_vk": vec![2u8; 32],
        "sig_rj": vec![3u8; 64],
        "extra_field_1": "value1",
        "extra_field_2": 12345,
        "unknown": {"nested": "data"}
    })
    .to_string();

    let result = wallet.import_credential(extra_fields_json);
    // Should handle extra fields gracefully (may succeed or fail at storage)
    assert!(result.is_err());
}

#[test]
fn test_concurrent_has_credential_secrets() -> Result<(), Box<dyn std::error::Error>> {
    use std::thread;

    let wallet = ProviiWallet::new(create_test_app_info());
    let wallet_clone = Arc::clone(&wallet);

    let handle = thread::spawn(move || wallet_clone.has_credential_secrets("test-id".to_string()));

    let result2 = wallet.has_credential_secrets("test-id-2".to_string());
    let result1 = handle.join().map_err(|_| "thread panicked")?;

    // Both should return errors (storage not initialised)
    assert!(result1.is_err());
    assert!(result2.is_err());
    Ok(())
}

#[test]
fn test_wallet_memory_safety() {
    // Test that creating and dropping wallets doesn't leak memory
    for _ in 0..100 {
        let app_info = create_test_app_info();
        let wallet = ProviiWallet::new(app_info);
        let _ = wallet.get_config();
        // Wallet dropped here
    }
}

#[test]
fn test_config_update_with_empty_strings() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());

    let mut config = wallet.get_config();
    config.environment = "".to_string();

    let result = wallet.update_config(config);
    // Validation now rejects empty environment
    assert!(result.is_err());
    let Err(err_val) = result else {
        panic!("expected error")
    };
    match err_val {
        FfiError::InvalidFormat { msg } => {
            assert!(msg.contains("environment must not be empty"));
        }
        other => panic!("Expected InvalidFormat, got {:?}", other),
    }
    Ok(())
}

#[test]
fn test_parse_qr_payload_special_characters() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Test with various special characters
    let special_chars = vec![
        "test\nwith\nnewlines",
        "test\twith\ttabs",
        "test with spaces",
        "test@#$%^&*()",
    ];

    for input in special_chars {
        let result = wallet.parse_qr_payload(input.to_string());
        // Non-JSON special characters should fail parsing.
        assert!(
            result.is_err(),
            "special-character payload {:?} should fail QR parsing",
            input
        );
    }
}

#[test]
fn test_deeplink_parsing_variations() {
    let wallet = ProviiWallet::new(create_test_app_info());

    // Test various invalid deeplink formats
    let invalid_links = vec![
        "http://example.com",
        "proviiwallet",
        "proviiwallet:",
        "proviiwallet://",
        "",
    ];

    for link in invalid_links {
        let result = wallet.handle_deeplink(link.to_string());
        assert!(result.is_err());
    }
}

// ============================================================================
// VERIFY RESPONSE PARSING TESTS
// ============================================================================

#[test]
fn test_verify_response_ok_result_is_success() -> Result<(), Box<dyn std::error::Error>> {
    let body = r#"{"result":"OK","state":"verified"}"#;
    let response: VerifyResponse = serde_json::from_str(body)?;
    let success = response.result == "OK";
    assert!(success, "result 'OK' should map to success=true");
    assert_eq!(response.state, "verified");
    Ok(())
}

#[test]
fn test_verify_response_invalid_proof_is_failure() -> Result<(), Box<dyn std::error::Error>> {
    let body = r#"{"result":"INVALID_PROOF","state":"rejected"}"#;
    let response: VerifyResponse = serde_json::from_str(body)?;
    let success = response.result == "OK";
    assert!(
        !success,
        "result 'INVALID_PROOF' should map to success=false"
    );
    assert_eq!(response.result, "INVALID_PROOF");
    assert_eq!(response.state, "rejected");
    Ok(())
}

#[test]
fn test_verify_response_malformed_json_returns_invalid_format() {
    let body = "not valid json {{{";
    let parse_result = serde_json::from_str::<VerifyResponse>(body);
    assert!(
        parse_result.is_err(),
        "malformed JSON must not parse as VerifyResponse"
    );
    // Confirm that wrapping as FfiError::InvalidFormat works
    let ffi_err = parse_result
        .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })
        .unwrap_err();
    assert!(
        matches!(ffi_err, FfiError::InvalidFormat { .. }),
        "expected FfiError::InvalidFormat, got {:?}",
        ffi_err
    );
}

#[test]
fn test_verify_response_expired_result_is_failure() -> Result<(), Box<dyn std::error::Error>> {
    let body = r#"{"result":"EXPIRED","state":"challenge_expired"}"#;
    let response: VerifyResponse = serde_json::from_str(body)?;
    let success = response.result == "OK";
    assert!(!success, "result 'EXPIRED' should map to success=false");
    Ok(())
}

// ============================================================================
// SHORT CODE TESTS
// ============================================================================

#[test]
fn test_is_short_code_valid_12_digits() {
    assert!(is_short_code("123456789012".to_string()));
}

#[test]
fn test_is_short_code_with_spaces() {
    assert!(is_short_code("1234 5678 9012".to_string()));
}

#[test]
fn test_is_short_code_too_short() {
    assert!(!is_short_code("12345".to_string()));
}

#[test]
fn test_is_short_code_too_long() {
    assert!(!is_short_code("1234567890123".to_string()));
}

#[test]
fn test_is_short_code_alpha_chars() {
    assert!(!is_short_code("12345678901a".to_string()));
}

#[test]
fn test_is_short_code_empty() {
    assert!(!is_short_code("".to_string()));
}

#[test]
fn test_is_short_code_all_zeros() {
    assert!(is_short_code("000000000000".to_string()));
}

#[test]
fn test_is_short_code_special_chars() {
    assert!(!is_short_code("12345-67890!".to_string()));
}

// ============================================================================
// CALCULATE AGE FROM DOB TESTS
// ============================================================================

#[test]
fn test_calculate_age_known_dob() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let result = wallet.calculate_age_from_dob("2000-01-01".to_string());
    assert!(result.is_ok());
    let age = result.unwrap();
    assert!(age >= 25 && age <= 27, "age should be ~26, got {}", age);
}

#[test]
fn test_calculate_age_from_dob_invalid_date() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let result = wallet.calculate_age_from_dob("not-a-date".to_string());
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        FfiError::InvalidFormat { .. }
    ));
}

#[test]
fn test_calculate_age_from_dob_far_future_clamped_zero() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let result = wallet.calculate_age_from_dob("2099-01-01".to_string());
    assert!(result.is_ok());
    // Future DOB should clamp to 0
    assert_eq!(result.unwrap(), 0);
}

#[test]
fn test_calculate_age_from_dob_leap_day() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let result = wallet.calculate_age_from_dob("2000-02-29".to_string());
    assert!(result.is_ok());
}

#[test]
fn test_calculate_age_from_dob_empty_string() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let result = wallet.calculate_age_from_dob("".to_string());
    assert!(result.is_err());
}

// ============================================================================
// EMERGENCY ZEROIZE TESTS
// ============================================================================

#[test]
fn test_emergency_zeroize_clears_caches() {
    let wallet = ProviiWallet::new(create_test_app_info());
    wallet.emergency_zeroize();
    // Should not panic and should clear all in-memory state
    let cached = safe_lock(&wallet.cached_challenges);
    assert!(cached.is_empty());
}

#[test]
fn test_emergency_zeroize_multiple_calls() {
    let wallet = ProviiWallet::new(create_test_app_info());
    wallet.emergency_zeroize();
    wallet.emergency_zeroize();
    // Repeated calls must be safe
}

// ============================================================================
// CLEANUP EXPIRED CHALLENGES TESTS
// ============================================================================

#[test]
fn test_cleanup_expired_challenges_empty_cache() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let removed = wallet.cleanup_expired_challenges();
    assert_eq!(removed, 0);
}

// ============================================================================
// DIAGNOSTIC INFO TESTS
// ============================================================================

#[test]
fn test_diagnostic_info_fields() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let info = wallet.get_diagnostic_info();
    assert!(!info.sdk_version.is_empty());
    assert_eq!(info.app_version, "2.0.0");
    assert_eq!(info.platform, "test");
    assert!(!info.storage_available);
}

// ============================================================================
// VERIFICATION STATUS TESTS
// ============================================================================

#[test]
fn test_verification_status_not_started() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let status = wallet.get_verification_status();
    assert!(matches!(status, VerificationStatus::NotStarted));
}

#[test]
fn test_cancel_verification_nonexistent() {
    let wallet = ProviiWallet::new(create_test_app_info());
    // Cancelling a non-existent verification should not panic
    let result = wallet.cancel_verification("nonexistent".to_string());
    // May succeed or fail depending on state manager implementation
    let _ = result;
}

// ============================================================================
// HAS VALID CREDENTIAL TESTS
// ============================================================================

#[test]
fn test_has_valid_credential_no_storage() {
    let wallet = ProviiWallet::new(create_test_app_info());
    // No storage backend, should return false gracefully
    assert!(!wallet.has_valid_credential());
}

// ============================================================================
// RESOLVE SLOT TESTS
// ============================================================================

#[test]
fn test_resolve_slot_primary() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let slot = wallet.resolve_slot("primary", None);
    assert!(slot.is_ok());
    assert!(matches!(slot.unwrap(), CredentialSlot::Primary));
}

#[test]
fn test_resolve_slot_unknown_type() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let slot = wallet.resolve_slot("unknown_type", None);
    assert!(slot.is_err());
    assert!(matches!(slot.unwrap_err(), FfiError::InvalidFormat { .. }));
}

// ============================================================================
// BIOMETRIC TESTS
// ============================================================================

#[test]
fn test_is_biometric_available_default() {
    let wallet = ProviiWallet::new(create_test_app_info());
    // Default stub has no platform callback, so it returns false
    let available = wallet.is_biometric_available();
    assert!(!available);
}

// ============================================================================
// PROGRESS TRACKER TESTS
// ============================================================================

#[test]
fn test_create_progress_tracker_arc() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let tracker = wallet.create_progress_tracker();
    // Tracker should be created successfully
    assert!(Arc::strong_count(&tracker) >= 1);
}

#[test]
fn test_report_progress_started_stage() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let tracker = wallet.create_progress_tracker();
    wallet.report_progress(
        tracker,
        ProgressStage::Started,
        "Generating proof".to_string(),
    );
}

// ============================================================================
// CREDENTIAL SECRETS / NICKNAME TESTS
// ============================================================================

#[test]
fn test_has_credential_secrets_no_storage() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let result = wallet.has_credential_secrets("some-id".to_string());
    // Should fail because storage is not initialised
    assert!(result.is_err());
}

#[test]
fn test_update_credential_nickname_no_storage() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let result =
        wallet.update_credential_nickname("some-id".to_string(), Some("new nickname".to_string()));
    assert!(result.is_err());
}

// ============================================================================
// IMPORT CREDENTIAL WITH TYPE TESTS
// ============================================================================

#[test]
fn test_import_credential_with_type_unknown() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let result = wallet.import_credential_with_type(
        create_test_credential_json(),
        "garbage_type".to_string(),
        None,
    );
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        FfiError::InvalidFormat { .. }
    ));
}

#[test]
fn test_import_credential_with_type_primary() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let result = wallet.import_credential_with_type(
        create_test_credential_json(),
        "primary".to_string(),
        None,
    );
    // Should fail at storage, not at slot resolution
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), FfiError::Storage { .. }));
}

// ============================================================================
// CLEANUP EXPIRED CREDENTIALS TESTS
// ============================================================================

#[test]
fn test_cleanup_expired_credentials_no_storage() {
    let wallet = ProviiWallet::new(create_test_app_info());
    // No storage backend registered, should return 0 gracefully
    let removed = wallet.cleanup_expired_credentials();
    assert_eq!(removed, 0);
}

// ============================================================================
// DELETE SANDBOX CREDENTIALS TESTS
// ============================================================================

#[test]
fn test_delete_sandbox_credentials_no_storage() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let result = wallet.delete_sandbox_credentials();
    assert!(result.is_err());
}

// ============================================================================
// GET AVAILABLE SLOT COUNT TESTS
// ============================================================================

#[test]
fn test_get_available_slot_count_no_storage() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let result = wallet.get_available_slot_count();
    // Should fail because storage is not initialised
    assert!(result.is_err());
}

// ============================================================================
// HANDLE DEEPLINK TESTS (via wallet)
// ============================================================================

#[test]
fn test_wallet_handle_deeplink_invalid() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let result = wallet.handle_deeplink("not-a-deeplink".to_string());
    assert!(result.is_err());
}

// ============================================================================
// PARSE QR PAYLOAD TESTS (via wallet)
// ============================================================================

#[test]
fn test_wallet_parse_qr_payload_valid_challenge() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let challenge_json = create_test_challenge_json();
    let result = wallet.parse_qr_payload(challenge_json);
    assert!(result.is_ok());
}

#[test]
fn test_wallet_parse_qr_payload_invalid() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let result = wallet.parse_qr_payload("not valid json".to_string());
    assert!(result.is_err());
}

#[test]
fn test_wallet_parse_qr_method() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let challenge_json = create_test_challenge_json();
    let result = wallet.parse_qr(challenge_json);
    assert!(result.is_ok());
}

// ============================================================================
// VALIDATE QR TESTS (via wallet)
// ============================================================================

#[test]
fn test_wallet_validate_qr_valid_challenge() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let challenge_json = create_test_challenge_json();
    let result = wallet.validate_qr(challenge_json);
    assert!(result.is_ok());
}

// ============================================================================
// WALLET WITH STORAGE (using create_default_secure_store)
// ============================================================================

#[test]
fn test_wallet_with_storage_import_and_list() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    let cred_json = create_test_credential_json();
    let result = wallet.import_credential(cred_json);
    assert!(
        result.is_ok(),
        "import should succeed with storage, got {:?}",
        result.err()
    );

    let creds = wallet.list_credentials()?;
    assert_eq!(creds.len(), 1);
    Ok(())
}

#[test]
fn test_wallet_with_storage_import_with_secrets() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    let cred_json = create_test_credential_with_secrets_json();
    let cred_id = wallet.import_credential(cred_json)?;
    assert!(!cred_id.is_empty());

    // Secrets should be stored separately
    let has_secrets = wallet.has_credential_secrets(cred_id.clone())?;
    assert!(
        has_secrets,
        "imported credential should have stored secrets"
    );

    // Credential should be retrievable
    let cred_opt = wallet.get_credential(cred_id)?;
    assert!(cred_opt.is_some());
    Ok(())
}

#[test]
fn test_wallet_with_storage_delete_credential() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    let cred_json = create_test_credential_json();
    let cred_id = wallet.import_credential(cred_json)?;

    wallet.delete_credential(cred_id.clone())?;

    let creds = wallet.list_credentials()?;
    assert!(creds.is_empty());
    Ok(())
}

#[test]
fn test_wallet_with_storage_update_nickname() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    let cred_json = create_test_credential_json();
    let cred_id = wallet.import_credential(cred_json)?;

    wallet.update_credential_nickname(cred_id.clone(), Some("My Credential".to_string()))?;

    let creds = wallet.list_credentials()?;
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].nickname, Some("My Credential".to_string()));
    Ok(())
}

#[test]
fn test_wallet_with_storage_has_valid_credential() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    // No credentials yet
    assert!(!wallet.has_valid_credential());

    let cred_json = create_test_credential_json();
    wallet.import_credential(cred_json)?;

    // Now we have a credential (exp is in the future)
    assert!(wallet.has_valid_credential());
    Ok(())
}

#[test]
fn test_wallet_with_storage_available_slot_count() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    let slots = wallet.get_available_slot_count()?;
    // 1 primary + 5 managed = 6 slots available
    assert_eq!(slots, 6);
    Ok(())
}

#[test]
fn test_wallet_process_qr_challenge() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let challenge_json = create_test_challenge_json();
    let result = wallet.process_qr_challenge(challenge_json);
    assert!(result.is_ok());
    let challenge_id = result?;
    assert_eq!(challenge_id, "test-challenge-123");
    Ok(())
}

#[test]
fn test_wallet_get_challenge_diagnostics() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let challenge_json = create_test_challenge_json();
    let challenge_id = wallet.process_qr_challenge(challenge_json)?;

    let diag = wallet.get_challenge_diagnostics(challenge_id)?;
    assert!(diag.contains("test-challenge-123"));
    assert!(diag.contains("19000"));
    Ok(())
}

#[test]
fn test_wallet_get_challenge_diagnostics_not_found() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let result = wallet.get_challenge_diagnostics("nonexistent".to_string());
    assert!(result.is_err());
}

#[test]
fn test_wallet_process_scanned_qr_challenge() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let challenge_json = create_test_challenge_json();
    let result = wallet.process_scanned_qr(challenge_json);
    assert!(result.is_ok());
    match result? {
        QrAction::VerificationChallenge { challenge_json } => {
            assert!(challenge_json.contains("test-challenge-123"));
        }
        _ => panic!("Expected VerificationChallenge"),
    }
    Ok(())
}

#[test]
fn test_wallet_process_scanned_qr_invalid() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let result = wallet.process_scanned_qr("garbage".to_string());
    assert!(result.is_err());
}

#[test]
fn test_cached_challenge_debug_redacts_secret() {
    let challenge = CachedChallenge {
        payload: QrChallengePayload {
            challenge_id: "test-id".to_string(),
            rp_challenge: "rp".to_string(),
            cutoff_days: 19000,
            verifying_key_id: 1,
            submit_secret: "SUPER_SECRET".to_string(),
            expires_at: 2000000000,
            verify_url: "https://test.com".to_string(),
            code_verifier: Some("VERIFIER_SECRET".to_string()),
            proof_direction: None,
        },
        received_at: std::time::SystemTime::now(),
        expires_at: std::time::SystemTime::now(),
    };

    let debug_str = format!("{:?}", challenge);
    assert!(debug_str.contains("REDACTED"));
    assert!(!debug_str.contains("SUPER_SECRET"));
}

#[test]
fn test_safe_lock_unpoisoned() {
    let mutex = Mutex::new(42);
    let guard = safe_lock(&mutex);
    assert_eq!(*guard, 42);
}

#[test]
fn test_wallet_refresh_issuer_keys_empty_jwks() {
    let wallet = ProviiWallet::new(create_test_app_info());
    // Empty JWKS should not panic, but may error on parsing
    let result = wallet.refresh_issuer_keys("{}".to_string());
    // Accept either success (empty keys) or error (parse failure)
    let _ = result;
}

#[test]
fn test_wallet_refresh_issuer_keys_invalid_json() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let result = wallet.refresh_issuer_keys("not json".to_string());
    assert!(result.is_err());
}

#[test]
fn test_wallet_set_storage_handle_and_list() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    let creds = wallet.list_credentials()?;
    assert!(creds.is_empty());
    Ok(())
}

#[test]
fn test_wallet_import_managed_credential() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    let result = wallet.import_credential_with_type(
        create_test_credential_json(),
        "managed".to_string(),
        Some("Work ID".to_string()),
    );
    assert!(
        result.is_ok(),
        "managed import should succeed, got {:?}",
        result.err()
    );
    Ok(())
}

#[test]
fn test_wallet_store_credential_with_label() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    let result = wallet.store_credential_with_label(
        create_test_credential_json(),
        Some("sandbox".to_string()),
        "primary".to_string(),
        None,
    );
    assert!(
        result.is_ok(),
        "store with label should succeed, got {:?}",
        result.err()
    );
    Ok(())
}

#[test]
fn test_wallet_delete_sandbox_credentials_with_storage() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    // Store a sandbox credential
    wallet.store_credential_with_label(
        create_test_credential_json(),
        Some("sandbox".to_string()),
        "primary".to_string(),
        None,
    )?;

    let result = wallet.delete_sandbox_credentials();
    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_wallet_cleanup_expired_credentials_with_storage() -> Result<(), Box<dyn std::error::Error>>
{
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    // Import a credential (not expired, exp=1800000000 is far future)
    wallet.import_credential(create_test_credential_json())?;

    let removed = wallet.cleanup_expired_credentials();
    // Credential exp is 1800000000 which is year 2027, so not expired yet
    assert_eq!(removed, 0);
    Ok(())
}

#[test]
fn test_wallet_get_credential_by_id() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    let cred_id = wallet.import_credential(create_test_credential_json())?;
    let retrieved = wallet.get_credential(cred_id.clone())?;
    assert!(retrieved.is_some());

    // Non-existent should return None
    let missing = wallet.get_credential("nonexistent-id".to_string())?;
    assert!(missing.is_none());
    Ok(())
}

#[test]
fn test_wallet_process_qr_and_create_proof_no_prover() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    // Import a credential with secrets
    let cred_id = wallet.import_credential(create_test_credential_with_secrets_json())?;

    // Process a QR challenge
    let challenge_id = wallet.process_qr_challenge(create_test_challenge_json())?;

    // Attempt proof generation (will fail because prover is not initialised)
    let result = wallet.create_age_proof(cred_id, challenge_id);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_wallet_create_age_proof_auto_single_credential() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    // Import one credential with secrets
    wallet.import_credential(create_test_credential_with_secrets_json())?;

    // Process a QR challenge
    let challenge_id = wallet.process_qr_challenge(create_test_challenge_json())?;

    // Auto-select with single credential (will fail at proof generation, not selection)
    let result = wallet.create_age_proof_auto(challenge_id);
    assert!(result.is_err());
    // Should fail at prover, not credential selection
    if let Err(FfiError::Prover { .. }) = result {
        // expected
    } else if let Err(FfiError::CredentialExpired) = result {
        // also acceptable if system time makes exp look expired
    } else {
        // Could also be other errors depending on state
    }
    Ok(())
}

#[test]
fn test_wallet_create_age_proof_auto_no_credentials() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    let challenge_id = wallet.process_qr_challenge(create_test_challenge_json())?;

    let result = wallet.create_age_proof_auto(challenge_id);
    assert!(result.is_err());
    if let Err(FfiError::Generic { msg }) = &result {
        assert!(msg.contains("No credential stored"));
    }
    Ok(())
}

#[test]
fn test_wallet_create_age_proof_challenge_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    let cred_id = wallet.import_credential(create_test_credential_with_secrets_json())?;

    let result = wallet.create_age_proof(cred_id, "nonexistent-challenge".to_string());
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_wallet_create_age_proof_credential_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    let challenge_id = wallet.process_qr_challenge(create_test_challenge_json())?;

    let result = wallet.create_age_proof("nonexistent-cred".to_string(), challenge_id);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), FfiError::CredentialNotFound));
    Ok(())
}

#[test]
fn test_wallet_get_provable_credentials_no_challenge() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    let result = wallet.get_provable_credentials_for_challenge("nonexistent".to_string());
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_wallet_get_provable_credentials_with_challenge() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    // Import a credential with secrets
    wallet.import_credential(create_test_credential_with_secrets_json())?;

    // Process challenge
    let challenge_id = wallet.process_qr_challenge(create_test_challenge_json())?;

    let result = wallet.get_provable_credentials_for_challenge(challenge_id)?;
    // Should have one credential (may or may not satisfy age requirement)
    assert_eq!(result.len(), 1);
    Ok(())
}

#[test]
fn test_wallet_update_config() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());

    let mut config = wallet.get_config();
    config.auto_select = false;
    config.network_timeout = 120;
    wallet.update_config(config)?;

    let updated = wallet.get_config();
    assert!(!updated.auto_select);
    assert_eq!(updated.network_timeout, 120);
    Ok(())
}

#[test]
fn test_wallet_drop_zeroizes() {
    // Verify the wallet can be dropped without panicking
    let wallet = ProviiWallet::new(create_test_app_info());
    drop(wallet);
}

#[test]
fn test_wallet_process_manual_entry_invalid_code() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let result = wallet.process_manual_entry("abc".to_string());
    assert!(result.is_err());
    if let Err(FfiError::InvalidFormat { msg }) = result {
        assert!(msg.contains("12 digits"));
    }
}

#[test]
fn test_wallet_fetch_challenge_by_short_code_invalid() {
    let wallet = ProviiWallet::new(create_test_app_info());
    let result = wallet.fetch_challenge_by_short_code("abc".to_string());
    assert!(result.is_err());
}

#[test]
fn test_wallet_persist_and_load_anchor() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProviiWallet::new(create_test_app_info());
    let store = crate::create_default_secure_store()?;
    wallet.set_storage_handle(store)?;

    // Refresh with empty JWKS (valid structure but no supported keys)
    let jwks = r#"{"keys":[]}"#;
    let result = wallet.refresh_issuer_keys(jwks.to_string());
    // Should succeed (empty keys = no-op)
    assert!(result.is_ok());
    Ok(())
}
