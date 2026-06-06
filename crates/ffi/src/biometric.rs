// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Biometric authentication types and stub authenticator for the FFI layer.
//!
//! This module exposes [`BiometricResult`], [`BiometricConfig`], and
//! [`BiometricAuthenticator`] to Swift and Kotlin via UniFFI. The
//! authenticator is fail-closed by default: without a registered platform
//! callback it always returns [`BiometricResult::NotAvailable`].

use crate::errors::FfiResult;
use std::sync::Arc;

/// Outcome of a biometric authentication attempt.
///
/// Each variant maps directly to the platform-level result codes surfaced
/// by iOS LocalAuthentication and Android BiometricPrompt.
#[derive(uniffi::Enum, Debug, Clone)]
pub enum BiometricResult {
    /// Authentication succeeded; the user proved presence.
    Success,
    /// The user explicitly dismissed the prompt.
    Cancelled,
    /// The biometric check failed (wrong fingerprint, face mismatch, etc.).
    Failed,
    /// No biometric hardware exists on the device, or the platform callback
    /// has not been registered.
    NotAvailable,
    /// Biometric hardware is present but no fingerprints or faces are
    /// enrolled in device settings.
    NotEnrolled,
}

/// Configuration for a biometric authentication prompt.
///
/// Passed to [`BiometricAuthenticator::new`] to control timeout behaviour
/// and user-visible strings. The biometric policy is always fail-closed:
/// PIN/password fallback is never permitted.
#[derive(uniffi::Record, Debug, Clone)]
pub struct BiometricConfig {
    /// Maximum seconds to wait for the user to complete biometric auth.
    pub timeout_seconds: u32,
    /// Title text shown on the biometric prompt dialog.
    pub title: String,
    /// Optional subtitle displayed below the title.
    pub subtitle: Option<String>,
    /// Optional longer description shown in the prompt body.
    pub description: Option<String>,
}

impl Default for BiometricConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 30,
            title: "Authenticate".to_string(),
            subtitle: None,
            description: Some("Please authenticate to continue".to_string()),
        }
    }
}

/// Stub biometric authenticator exposed over UniFFI.
///
/// The real biometric flow is driven by the native host application (iOS
/// Keychain access-control flags, Android BiometricPrompt). This struct
/// exists so the FFI surface has a typed entry point for authentication
/// even before the native callback is wired up.
#[derive(uniffi::Object)]
pub struct BiometricAuthenticator {
    #[allow(dead_code)] // Accessed from Swift/Kotlin via UniFFI bindings
    config: BiometricConfig,
}

#[uniffi::export]
impl BiometricAuthenticator {
    /// Create a new authenticator with the given configuration.
    ///
    /// The `timeout_seconds` field is clamped to the range 1..=300. A value
    /// of 0 is rejected as invalid, and values above 300 are clamped to 300.
    #[uniffi::constructor]
    pub fn new(mut config: BiometricConfig) -> Arc<Self> {
        if config.timeout_seconds == 0 {
            config.timeout_seconds = 30;
            log::warn!("BiometricConfig timeout_seconds was 0; defaulting to 30s");
        } else if config.timeout_seconds > 300 {
            log::warn!(
                "BiometricConfig timeout_seconds {} clamped to 300s",
                config.timeout_seconds
            );
            config.timeout_seconds = 300;
        }
        Arc::new(Self { config })
    }

    /// Attempt biometric authentication.
    ///
    /// Returns [`BiometricResult::NotAvailable`] on all platforms until a
    /// native callback is registered by the host application. This is
    /// fail-closed: without a platform-specific biometric delegate,
    /// authentication never silently succeeds.
    pub fn authenticate(&self) -> FfiResult<BiometricResult> {
        // No platform callback mechanism is registered yet.
        // Fail-closed: return NotAvailable rather than silently succeeding.
        Ok(BiometricResult::NotAvailable)
    }

    /// Check whether biometric authentication is available on this device.
    ///
    /// Returns `false` on all platforms by default. Actual hardware
    /// availability is determined by the native `PlatformSecureStorage`
    /// implementations, not by this authenticator (which has no way to
    /// query hardware without a platform callback).
    pub fn is_available(&self) -> bool {
        false
    }
}

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

    // BiometricResult Tests
    #[test]
    fn test_biometric_result_all_variants() {
        // Verify all enum variants can be created
        let success = BiometricResult::Success;
        let cancelled = BiometricResult::Cancelled;
        let failed = BiometricResult::Failed;
        let not_available = BiometricResult::NotAvailable;
        let not_enrolled = BiometricResult::NotEnrolled;

        // Ensure they're distinct
        assert!(matches!(success, BiometricResult::Success));
        assert!(matches!(cancelled, BiometricResult::Cancelled));
        assert!(matches!(failed, BiometricResult::Failed));
        assert!(matches!(not_available, BiometricResult::NotAvailable));
        assert!(matches!(not_enrolled, BiometricResult::NotEnrolled));
    }

    #[test]
    fn test_biometric_result_debug_format() {
        let result = BiometricResult::Success;
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("Success"));
    }

    #[test]
    fn test_biometric_result_clone() {
        let original = BiometricResult::Failed;
        let cloned = original.clone();
        assert!(matches!(cloned, BiometricResult::Failed));
    }

    // BiometricConfig Tests
    #[test]
    fn test_biometric_config_default_values() {
        let config = BiometricConfig::default();

        assert_eq!(config.timeout_seconds, 30);
        assert_eq!(config.title, "Authenticate");
        assert_eq!(config.subtitle, None);
        assert_eq!(
            config.description,
            Some("Please authenticate to continue".to_string())
        );
    }

    #[test]
    fn test_biometric_config_custom_values() {
        let config = BiometricConfig {
            timeout_seconds: 60,
            title: "Verify Identity".to_string(),
            subtitle: Some("Wallet Access".to_string()),
            description: Some("Authenticate to access your wallet".to_string()),
        };

        assert_eq!(config.timeout_seconds, 60);
        assert_eq!(config.title, "Verify Identity");
        assert_eq!(config.subtitle, Some("Wallet Access".to_string()));
        assert_eq!(
            config.description,
            Some("Authenticate to access your wallet".to_string())
        );
    }

    #[test]
    fn test_biometric_config_optional_fields_none() {
        let config = BiometricConfig {
            timeout_seconds: 45,
            title: "Authenticate".to_string(),
            subtitle: None,
            description: None,
        };

        assert!(config.subtitle.is_none());
        assert!(config.description.is_none());
    }

    #[test]
    fn test_biometric_config_timeout_range() {
        // Test various timeout values
        let short = BiometricConfig {
            timeout_seconds: 10,
            ..Default::default()
        };
        assert_eq!(short.timeout_seconds, 10);

        let long = BiometricConfig {
            timeout_seconds: 120,
            ..Default::default()
        };
        assert_eq!(long.timeout_seconds, 120);
    }

    #[test]
    fn test_biometric_config_clone() {
        let original = BiometricConfig {
            timeout_seconds: 45,
            title: "Test".to_string(),
            subtitle: Some("Subtitle".to_string()),
            description: None,
        };

        let cloned = original.clone();
        assert_eq!(cloned.timeout_seconds, 45);
        assert_eq!(cloned.title, "Test");
        assert_eq!(cloned.subtitle, Some("Subtitle".to_string()));
        assert_eq!(cloned.description, None);
    }

    // BiometricAuthenticator Tests
    #[test]
    fn test_biometric_authenticator_constructor() {
        let config = BiometricConfig::default();
        let auth = BiometricAuthenticator::new(config);
        assert!(Arc::strong_count(&auth) == 1);
    }

    #[test]
    fn test_biometric_authenticator_is_available() {
        let config = BiometricConfig::default();
        let auth = BiometricAuthenticator::new(config);

        // Without a registered platform callback, availability is always false.
        assert!(!auth.is_available());
    }

    #[test]
    fn test_biometric_authenticator_authenticate() -> Result<(), Box<dyn std::error::Error>> {
        let config = BiometricConfig::default();
        let auth = BiometricAuthenticator::new(config);

        let result = auth.authenticate();
        assert!(result.is_ok());

        // Without a registered platform callback, authentication always
        // returns NotAvailable (fail-closed).
        let biometric_result = result?;
        assert!(matches!(biometric_result, BiometricResult::NotAvailable));
        Ok(())
    }

    #[test]
    fn test_biometric_authenticator_config_stored() {
        let config = BiometricConfig {
            timeout_seconds: 55,
            title: "Custom Auth".to_string(),
            subtitle: Some("Test".to_string()),
            description: None,
        };

        let auth = BiometricAuthenticator::new(config.clone());

        // Verify config was stored (access through internal field)
        assert_eq!(auth.config.timeout_seconds, 55);
        assert_eq!(auth.config.title, "Custom Auth");
    }

    #[test]
    fn test_biometric_authenticator_multiple_instances() {
        let config1 = BiometricConfig {
            timeout_seconds: 30,
            ..Default::default()
        };
        let config2 = BiometricConfig {
            timeout_seconds: 60,
            ..Default::default()
        };

        let auth1 = BiometricAuthenticator::new(config1);
        let auth2 = BiometricAuthenticator::new(config2);

        assert_eq!(auth1.config.timeout_seconds, 30);
        assert_eq!(auth2.config.timeout_seconds, 60);
    }

    #[test]
    fn test_biometric_authenticator_arc_ref_counting() {
        let config = BiometricConfig::default();
        let auth1 = BiometricAuthenticator::new(config);
        let auth2 = Arc::clone(&auth1);

        assert!(Arc::strong_count(&auth1) == 2);
        assert!(Arc::strong_count(&auth2) == 2);

        drop(auth2);
        assert!(Arc::strong_count(&auth1) == 1);
    }

    #[test]
    fn test_biometric_authenticator_platform_behavior() -> Result<(), Box<dyn std::error::Error>> {
        let config = BiometricConfig::default();
        let auth = BiometricAuthenticator::new(config);

        // Without a platform callback, both must indicate unavailability.
        assert!(!auth.is_available());
        let auth_result = auth.authenticate()?;
        assert!(matches!(auth_result, BiometricResult::NotAvailable));
        Ok(())
    }

    #[test]
    fn test_biometric_config_debug_format() {
        let config = BiometricConfig::default();
        let debug_str = format!("{:?}", config);

        assert!(debug_str.contains("BiometricConfig"));
        assert!(debug_str.contains("timeout_seconds"));
        assert!(debug_str.contains("30"));
    }

    // Edge Case Tests - BiometricConfig
    #[test]
    fn test_biometric_config_zero_timeout() {
        let config = BiometricConfig {
            timeout_seconds: 0,
            ..Default::default()
        };
        assert_eq!(config.timeout_seconds, 0);
    }

    #[test]
    fn test_biometric_config_max_timeout() {
        let config = BiometricConfig {
            timeout_seconds: u32::MAX,
            ..Default::default()
        };
        assert_eq!(config.timeout_seconds, u32::MAX);
    }

    #[test]
    fn test_biometric_config_empty_title() {
        let config = BiometricConfig {
            timeout_seconds: 30,
            title: "".to_string(),
            subtitle: None,
            description: None,
        };
        assert_eq!(config.title, "");
    }

    #[test]
    fn test_biometric_config_very_long_title() {
        let long_title = "A".repeat(10000);
        let config = BiometricConfig {
            timeout_seconds: 30,
            title: long_title.clone(),
            subtitle: None,
            description: None,
        };
        assert_eq!(config.title.len(), 10000);
        assert_eq!(config.title, long_title);
    }

    #[test]
    fn test_biometric_config_unicode_title() -> Result<(), Box<dyn std::error::Error>> {
        let config = BiometricConfig {
            timeout_seconds: 30,
            title: "認証してください 🔐".to_string(),
            subtitle: Some("生体認証".to_string()),
            description: Some("指紋または顔認証を使用してください".to_string()),
        };
        assert!(config.title.contains("認証"));
        assert!(config.title.contains("🔐"));
        assert!(config
            .subtitle
            .as_ref()
            .ok_or("expected Some")?
            .contains("生体認証"));
        Ok(())
    }

    #[test]
    fn test_biometric_config_newlines_in_description() -> Result<(), Box<dyn std::error::Error>> {
        let config = BiometricConfig {
            timeout_seconds: 30,
            title: "Authenticate".to_string(),
            subtitle: None,
            description: Some("Line 1\nLine 2\nLine 3".to_string()),
        };
        assert!(config
            .description
            .as_ref()
            .ok_or("expected Some")?
            .contains("\n"));
        assert_eq!(
            config
                .description
                .as_ref()
                .ok_or("expected Some")?
                .matches('\n')
                .count(),
            2
        );
        Ok(())
    }

    #[test]
    fn test_biometric_config_special_characters() -> Result<(), Box<dyn std::error::Error>> {
        let config = BiometricConfig {
            timeout_seconds: 30,
            title: "Auth: <Test> & \"Verify\"".to_string(),
            subtitle: Some("Sub's \"title\"".to_string()),
            description: Some("Desc with \t tabs \r and \n newlines".to_string()),
        };
        assert!(config.title.contains("<Test>"));
        assert!(config.title.contains("&"));
        assert!(config
            .subtitle
            .as_ref()
            .ok_or("expected Some")?
            .contains("'"));
        Ok(())
    }

    #[test]
    fn test_biometric_config_all_optional_fields_some() {
        let config = BiometricConfig {
            timeout_seconds: 30,
            title: "Title".to_string(),
            subtitle: Some("Subtitle".to_string()),
            description: Some("Description".to_string()),
        };
        assert!(config.subtitle.is_some());
        assert!(config.description.is_some());
    }

    #[test]
    fn test_biometric_config_all_optional_fields_empty_strings() {
        let config = BiometricConfig {
            timeout_seconds: 30,
            title: "Title".to_string(),
            subtitle: Some("".to_string()),
            description: Some("".to_string()),
        };
        assert_eq!(config.subtitle, Some("".to_string()));
        assert_eq!(config.description, Some("".to_string()));
    }

    #[test]
    fn test_biometric_config_emojis_in_all_fields() -> Result<(), Box<dyn std::error::Error>> {
        let config = BiometricConfig {
            timeout_seconds: 30,
            title: "🔒 Authenticate 🔒".to_string(),
            subtitle: Some("👤 User Auth 👤".to_string()),
            description: Some("🔐 Secure Access 🔐".to_string()),
        };
        assert!(config.title.contains("🔒"));
        assert!(config
            .subtitle
            .as_ref()
            .ok_or("expected Some")?
            .contains("👤"));
        assert!(config
            .description
            .as_ref()
            .ok_or("expected Some")?
            .contains("🔐"));
        Ok(())
    }

    // Edge Case Tests - BiometricResult
    #[test]
    fn test_biometric_result_equality() {
        let success1 = BiometricResult::Success;
        let success2 = BiometricResult::Success;
        let failed = BiometricResult::Failed;

        // Clone equality
        assert!(matches!(success1.clone(), BiometricResult::Success));
        assert!(matches!(success2, BiometricResult::Success));
        assert!(matches!(failed, BiometricResult::Failed));
    }

    #[test]
    fn test_biometric_result_match_all_variants() {
        let results = vec![
            BiometricResult::Success,
            BiometricResult::Cancelled,
            BiometricResult::Failed,
            BiometricResult::NotAvailable,
            BiometricResult::NotEnrolled,
        ];

        for result in results {
            let matched = match result {
                BiometricResult::Success => "success",
                BiometricResult::Cancelled => "cancelled",
                BiometricResult::Failed => "failed",
                BiometricResult::NotAvailable => "not_available",
                BiometricResult::NotEnrolled => "not_enrolled",
            };
            assert!(!matched.is_empty());
        }
    }

    #[test]
    fn test_biometric_result_vec_operations() {
        let results = [
            BiometricResult::Success,
            BiometricResult::Failed,
            BiometricResult::Cancelled,
        ];

        assert_eq!(results.len(), 3);
        assert!(matches!(results[0], BiometricResult::Success));
        assert!(matches!(results[1], BiometricResult::Failed));
        assert!(matches!(results[2], BiometricResult::Cancelled));
    }

    #[test]
    fn test_biometric_result_in_ffi_result() {
        let success: FfiResult<BiometricResult> = Ok(BiometricResult::Success);
        let failed: FfiResult<BiometricResult> = Ok(BiometricResult::Failed);

        assert!(matches!(success, Ok(BiometricResult::Success)));
        assert!(matches!(failed, Ok(BiometricResult::Failed)));
    }

    #[test]
    fn test_biometric_result_debug_all_variants() {
        assert!(format!("{:?}", BiometricResult::Success).contains("Success"));
        assert!(format!("{:?}", BiometricResult::Cancelled).contains("Cancelled"));
        assert!(format!("{:?}", BiometricResult::Failed).contains("Failed"));
        assert!(format!("{:?}", BiometricResult::NotAvailable).contains("NotAvailable"));
        assert!(format!("{:?}", BiometricResult::NotEnrolled).contains("NotEnrolled"));
    }

    // Edge Case Tests - BiometricAuthenticator
    #[test]
    fn test_biometric_authenticator_with_zero_timeout() {
        let config = BiometricConfig {
            timeout_seconds: 0,
            ..Default::default()
        };
        let auth = BiometricAuthenticator::new(config);
        // Zero is rejected and defaulted to 30s
        assert_eq!(auth.config.timeout_seconds, 30);

        let result = auth.authenticate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_biometric_authenticator_with_max_timeout() {
        let config = BiometricConfig {
            timeout_seconds: u32::MAX,
            ..Default::default()
        };
        let auth = BiometricAuthenticator::new(config);
        // Clamped to 300s maximum
        assert_eq!(auth.config.timeout_seconds, 300);

        let result = auth.authenticate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_biometric_authenticator_with_empty_title() {
        let config = BiometricConfig {
            timeout_seconds: 30,
            title: "".to_string(),
            subtitle: None,
            description: None,
        };
        let auth = BiometricAuthenticator::new(config);
        assert_eq!(auth.config.title, "");

        let result = auth.authenticate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_biometric_authenticator_with_unicode_config() {
        let config = BiometricConfig {
            timeout_seconds: 30,
            title: "認証 🔐".to_string(),
            subtitle: Some("生体認証".to_string()),
            description: Some("指紋認証".to_string()),
        };
        let auth = BiometricAuthenticator::new(config);
        assert!(auth.config.title.contains("認証"));

        let result = auth.authenticate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_biometric_authenticator_multiple_authenticate_calls() {
        let config = BiometricConfig::default();
        let auth = BiometricAuthenticator::new(config);

        // Multiple calls should all succeed
        let result1 = auth.authenticate();
        let result2 = auth.authenticate();
        let result3 = auth.authenticate();

        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert!(result3.is_ok());
    }

    #[test]
    fn test_biometric_authenticator_is_available_consistent() {
        let config = BiometricConfig::default();
        let auth = BiometricAuthenticator::new(config);

        // Multiple calls should return same result
        let available1 = auth.is_available();
        let available2 = auth.is_available();
        let available3 = auth.is_available();

        assert_eq!(available1, available2);
        assert_eq!(available2, available3);
    }

    #[test]
    fn test_biometric_authenticator_config_combinations() {
        let configs = vec![
            BiometricConfig {
                timeout_seconds: 0,
                title: "".to_string(),
                subtitle: None,
                description: None,
            },
            BiometricConfig {
                timeout_seconds: u32::MAX,
                title: "Test".to_string(),
                subtitle: Some("Sub".to_string()),
                description: Some("Desc".to_string()),
            },
            BiometricConfig {
                timeout_seconds: 60,
                title: "🔐".to_string(),
                subtitle: Some("".to_string()),
                description: None,
            },
        ];

        for config in configs {
            let auth = BiometricAuthenticator::new(config);
            let result = auth.authenticate();
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_biometric_authenticator_arc_clone_independent() {
        let config = BiometricConfig::default();
        let auth1 = BiometricAuthenticator::new(config);
        let auth2 = Arc::clone(&auth1);

        // Both should work independently
        let result1 = auth1.authenticate();
        let result2 = auth2.authenticate();

        assert!(result1.is_ok());
        assert!(result2.is_ok());
    }

    #[test]
    fn test_biometric_authenticator_with_very_long_strings() {
        let config = BiometricConfig {
            timeout_seconds: 30,
            title: "A".repeat(10000),
            subtitle: Some("B".repeat(10000)),
            description: Some("C".repeat(10000)),
        };
        let auth = BiometricAuthenticator::new(config);
        assert_eq!(auth.config.title.len(), 10000);

        let result = auth.authenticate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_biometric_authenticator_different_timeouts() {
        let short = BiometricConfig {
            timeout_seconds: 10,
            ..Default::default()
        };
        let long = BiometricConfig {
            timeout_seconds: 120,
            ..Default::default()
        };

        let auth1 = BiometricAuthenticator::new(short);
        let auth2 = BiometricAuthenticator::new(long);

        assert_eq!(auth1.config.timeout_seconds, 10);
        assert_eq!(auth2.config.timeout_seconds, 120);

        assert!(auth1.authenticate().is_ok());
        assert!(auth2.authenticate().is_ok());
    }

    #[test]
    fn test_biometric_config_partial_defaults() {
        let config1 = BiometricConfig {
            title: "Custom".to_string(),
            ..Default::default()
        };
        assert_eq!(config1.title, "Custom");
        assert_eq!(config1.timeout_seconds, 30);

        let config2 = BiometricConfig {
            timeout_seconds: 45,
            ..Default::default()
        };
        assert_eq!(config2.timeout_seconds, 45);
        assert_eq!(config2.title, "Authenticate");
    }

    #[test]
    fn test_biometric_result_from_authenticate_consistency(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config = BiometricConfig::default();
        let auth = BiometricAuthenticator::new(config);

        // Multiple authenticate calls should return consistent result types
        for _ in 0..5 {
            let result = auth.authenticate();
            assert!(result.is_ok());
            let biometric_result = result?;

            // Result should be one of the valid variants
            match biometric_result {
                BiometricResult::Success
                | BiometricResult::Cancelled
                | BiometricResult::Failed
                | BiometricResult::NotAvailable
                | BiometricResult::NotEnrolled => {
                    // Valid variant
                }
            }
        }
        Ok(())
    }
}
