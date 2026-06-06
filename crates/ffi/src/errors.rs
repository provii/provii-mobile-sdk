// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Error types surfaced across the FFI boundary.
//!
//! [`FfiError`] is the single error enum that UniFFI exposes to Swift and
//! Kotlin. Platform code pattern-matches on its variants to decide which
//! user-facing message or recovery flow to present.
//!
//! All conversions from internal error types (`anyhow::Error`,
//! [`WalletError`](provii_mobile_sdk_core::error::WalletError),
//! [`ProverError`](provii_mobile_sdk_core::ProverError), `serde_json::Error`) are
//! implemented here so that call-sites can use the `?` operator without
//! additional boilerplate.

/// Unified error type for the FFI surface.
///
/// Each variant maps to a distinct failure mode that mobile platforms can
/// handle independently. Variants that carry a `msg` field include a
/// human-readable description suitable for debug logging (but not for display
/// to end users without localisation).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// Input data could not be parsed or did not pass schema validation.
    #[error("Invalid format: {msg}")]
    InvalidFormat { msg: String },

    /// Platform secure storage read or write failed.
    #[error("Storage error: {msg}")]
    Storage { msg: String },

    /// HTTP request to provii-issuer or provii-verifier failed.
    #[error("Network error: {msg}")]
    Network { msg: String },

    /// Zero knowledge proof generation failed.
    #[error("Prover error: {msg}")]
    Prover { msg: String },

    /// A verification or issuance flow is already in progress.
    #[error("Operation in progress")]
    OperationInProgress,

    /// The in-flight operation was cancelled by the user or platform.
    #[error("Operation cancelled")]
    OperationCancelled,

    /// The SDK has not been initialised yet. Call `initialize()` first.
    #[error("Not initialised")]
    NotInitialized,

    /// The credential's date of birth does not satisfy the challenge's age cutoff.
    #[error("Your credential doesn't meet the age requirement for this verification")]
    AgeRequirementNotMet,

    /// A biometric prompt was required but the user did not authenticate.
    #[error("Biometric authentication required but not completed")]
    BiometricNotAuthenticated,

    /// The per-`vk_id` retry budget (5 attempts in 24 hours) has been exhausted.
    #[error("Retry budget exceeded for proving key download: {msg}")]
    RetryBudgetExceeded { msg: String },

    /// The HTTP request did not complete within the caller-specified deadline.
    #[error("Request timed out after {seconds}s")]
    RequestTimeout { seconds: u64 },

    /// The requested credential was not found in storage.
    #[error("Credential not found")]
    CredentialNotFound,

    /// The credential has passed its expiration timestamp.
    #[error("Credential expired")]
    CredentialExpired,

    /// A security-sensitive check failed (e.g. tampered data, trust anchor mismatch).
    #[error("Security violation: {msg}")]
    SecurityViolation { msg: String },

    /// Catch-all for errors that do not map to a more specific variant.
    #[error("{msg}")]
    Generic { msg: String },
}

impl From<anyhow::Error> for FfiError {
    fn from(err: anyhow::Error) -> Self {
        // Log the full error chain at debug level for internal diagnostics,
        // but only surface the root cause across the FFI boundary. The chain
        // may contain internal file paths, SQL queries, or other details
        // that should not cross to mobile code.
        log::debug!("anyhow error chain crossing FFI: {:?}", err);
        let msg = err.root_cause().to_string();
        FfiError::Generic { msg }
    }
}

impl From<provii_mobile_sdk_core::error::WalletError> for FfiError {
    fn from(err: provii_mobile_sdk_core::error::WalletError) -> Self {
        use provii_mobile_sdk_core::error::WalletError;
        match err {
            WalletError::StorageError(msg) => FfiError::Storage { msg },
            WalletError::StorageFull => FfiError::Storage {
                msg: "storage full".to_string(),
            },
            WalletError::NetworkError(msg) => FfiError::Network { msg },
            WalletError::RequestTimeout => FfiError::Network {
                msg: "request timeout".to_string(),
            },
            WalletError::ProverError(msg) => FfiError::Prover { msg },
            WalletError::ProverNotInitialized => FfiError::Prover {
                msg: "prover not initialised".to_string(),
            },
            WalletError::ProofGenerationFailed(msg) => FfiError::Prover { msg },
            WalletError::InvalidInput(msg) => FfiError::InvalidFormat { msg },
            WalletError::ValidationFailed(msg) => FfiError::InvalidFormat { msg },
            WalletError::SerializationError(msg) => FfiError::InvalidFormat { msg },
            WalletError::Base64Error(msg) => FfiError::InvalidFormat { msg },
            WalletError::InvalidCredentialFormat => FfiError::InvalidFormat {
                msg: "invalid credential format".to_string(),
            },
            WalletError::InvalidSignature => FfiError::InvalidFormat {
                msg: "invalid signature".to_string(),
            },
            WalletError::CredentialError(msg) => FfiError::InvalidFormat { msg },
            WalletError::CredentialNotFound => FfiError::CredentialNotFound,
            WalletError::CredentialExpired => FfiError::CredentialExpired,
            WalletError::UnderAge => FfiError::AgeRequirementNotMet,
            WalletError::SecurityError(msg) => FfiError::SecurityViolation { msg },
            WalletError::OperationFailed(msg) | WalletError::Unknown(msg) => {
                FfiError::Generic { msg }
            }
        }
    }
}

impl From<provii_mobile_sdk_core::ProverError> for FfiError {
    fn from(err: provii_mobile_sdk_core::ProverError) -> Self {
        use provii_mobile_sdk_core::ProverError;
        match err {
            ProverError::AgeRequirementNotMet => FfiError::AgeRequirementNotMet,
            ProverError::NotInitialized => FfiError::Prover {
                msg: "prover not initialised".to_string(),
            },
            ProverError::AlreadyInitialized => FfiError::Prover {
                msg: "prover already initialised".to_string(),
            },
            ProverError::InvalidProvingKey => FfiError::Prover {
                msg: "invalid proving key".to_string(),
            },
            ProverError::InvalidBase64(msg) => FfiError::InvalidFormat { msg },
            ProverError::InvalidInput(msg) => FfiError::InvalidFormat { msg },
            ProverError::MissingPrivateFields => FfiError::InvalidFormat {
                msg: "credential missing private fields required for proving".to_string(),
            },
            ProverError::ProofGenerationFailed(msg) => FfiError::Prover { msg },
            ProverError::VkIdMismatch { loaded, expected } => FfiError::Prover {
                msg: format!(
                    "verifying key mismatch: loaded {}, expected {}",
                    loaded, expected
                ),
            },
            ProverError::CredentialExpired => FfiError::CredentialExpired,
            ProverError::ChallengeExpired => FfiError::Prover {
                msg: "challenge has expired".to_string(),
            },
        }
    }
}

impl From<serde_json::Error> for FfiError {
    fn from(err: serde_json::Error) -> Self {
        log::debug!("serde_json error crossing FFI: {}", err);
        FfiError::InvalidFormat {
            msg: "JSON parsing failed".to_string(),
        }
    }
}

/// Convenience alias used throughout the FFI layer.
pub type FfiResult<T> = std::result::Result<T, FfiError>;

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

    #[test]
    fn test_ffi_error_invalid_format() {
        let error = FfiError::InvalidFormat {
            msg: "Bad JSON".to_string(),
        };

        assert_eq!(error.to_string(), "Invalid format: Bad JSON");
    }

    #[test]
    fn test_ffi_error_storage() {
        let error = FfiError::Storage {
            msg: "Database locked".to_string(),
        };

        assert_eq!(error.to_string(), "Storage error: Database locked");
    }

    #[test]
    fn test_ffi_error_network() {
        let error = FfiError::Network {
            msg: "Connection timeout".to_string(),
        };

        assert_eq!(error.to_string(), "Network error: Connection timeout");
    }

    #[test]
    fn test_ffi_error_prover() {
        let error = FfiError::Prover {
            msg: "Failed to generate proof".to_string(),
        };

        assert_eq!(error.to_string(), "Prover error: Failed to generate proof");
    }

    #[test]
    fn test_ffi_error_operation_in_progress() {
        let error = FfiError::OperationInProgress;
        assert_eq!(error.to_string(), "Operation in progress");
    }

    #[test]
    fn test_ffi_error_operation_cancelled() {
        let error = FfiError::OperationCancelled;
        assert_eq!(error.to_string(), "Operation cancelled");
    }

    #[test]
    fn test_ffi_error_not_initialized() {
        let error = FfiError::NotInitialized;
        assert_eq!(error.to_string(), "Not initialised");
    }

    #[test]
    fn test_ffi_error_age_requirement_not_met() {
        let error = FfiError::AgeRequirementNotMet;
        assert_eq!(
            error.to_string(),
            "Your credential doesn't meet the age requirement for this verification"
        );
    }

    #[test]
    fn test_from_prover_error_age_requirement_not_met() {
        use provii_mobile_sdk_core::ProverError;

        let prover_err = ProverError::AgeRequirementNotMet;
        let ffi_err: FfiError = prover_err.into();

        assert!(matches!(ffi_err, FfiError::AgeRequirementNotMet));
        assert_eq!(
            ffi_err.to_string(),
            "Your credential doesn't meet the age requirement for this verification"
        );
    }

    #[test]
    fn test_ffi_error_generic() {
        let error = FfiError::Generic {
            msg: "Something went wrong".to_string(),
        };

        assert_eq!(error.to_string(), "Something went wrong");
    }

    #[test]
    fn test_from_anyhow_error() {
        let anyhow_err = anyhow::anyhow!("test error");
        let ffi_err: FfiError = anyhow_err.into();

        match ffi_err {
            FfiError::Generic { msg } => {
                assert_eq!(msg, "test error");
            }
            _ => panic!("Expected Generic error"),
        }
    }

    #[test]
    fn test_from_wallet_error_credential_error() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::CredentialError("Invalid credential".to_string());
        let ffi_err: FfiError = wallet_err.into();

        match ffi_err {
            FfiError::InvalidFormat { msg } => {
                assert!(msg.contains("Invalid credential"));
            }
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_from_wallet_error_storage() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::StorageError("Key not found".to_string());
        let ffi_err: FfiError = wallet_err.into();

        match ffi_err {
            FfiError::Storage { msg } => {
                assert!(msg.contains("Key not found"));
            }
            _ => panic!("Expected Storage error"),
        }
    }

    #[test]
    fn test_from_wallet_error_network() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::NetworkError("connection refused".to_string());
        let ffi_err: FfiError = wallet_err.into();

        match ffi_err {
            FfiError::Network { msg } => {
                assert_eq!(msg, "connection refused");
            }
            _ => panic!("Expected Network error"),
        }
    }

    #[test]
    fn test_from_wallet_error_storage_full() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::StorageFull;
        let ffi_err: FfiError = wallet_err.into();

        match ffi_err {
            FfiError::Storage { msg } => {
                assert_eq!(msg, "storage full");
            }
            _ => panic!("Expected Storage error"),
        }
    }

    #[test]
    fn test_from_wallet_error_request_timeout() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::RequestTimeout;
        let ffi_err: FfiError = wallet_err.into();

        match ffi_err {
            FfiError::Network { msg } => {
                assert_eq!(msg, "request timeout");
            }
            _ => panic!("Expected Network error"),
        }
    }

    #[test]
    fn test_from_wallet_error_prover() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::ProverError("circuit constraint failed".to_string());
        let ffi_err: FfiError = wallet_err.into();

        match ffi_err {
            FfiError::Prover { msg } => {
                assert_eq!(msg, "circuit constraint failed");
            }
            _ => panic!("Expected Prover error"),
        }
    }

    #[test]
    fn test_from_wallet_error_prover_not_initialized() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::ProverNotInitialized;
        let ffi_err: FfiError = wallet_err.into();

        match ffi_err {
            FfiError::Prover { msg } => {
                assert_eq!(msg, "prover not initialised");
            }
            _ => panic!("Expected Prover error"),
        }
    }

    #[test]
    fn test_from_wallet_error_proof_generation_failed() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::ProofGenerationFailed("bad witness".to_string());
        let ffi_err: FfiError = wallet_err.into();

        match ffi_err {
            FfiError::Prover { msg } => {
                assert_eq!(msg, "bad witness");
            }
            _ => panic!("Expected Prover error"),
        }
    }

    #[test]
    fn test_from_wallet_error_under_age() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::UnderAge;
        let ffi_err: FfiError = wallet_err.into();

        assert!(matches!(ffi_err, FfiError::AgeRequirementNotMet));
    }

    #[test]
    fn test_from_wallet_error_unknown() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::Unknown("unexpected condition".to_string());
        let ffi_err: FfiError = wallet_err.into();

        match ffi_err {
            FfiError::Generic { msg } => {
                assert_eq!(msg, "unexpected condition");
            }
            _ => panic!("Expected Generic error"),
        }
    }

    #[test]
    fn test_from_wallet_error_operation_failed() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::OperationFailed("timed out".to_string());
        let ffi_err: FfiError = wallet_err.into();

        match ffi_err {
            FfiError::Generic { msg } => {
                assert_eq!(msg, "timed out");
            }
            _ => panic!("Expected Generic error"),
        }
    }

    #[test]
    fn test_from_wallet_error_invalid_input() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::InvalidInput("age must be positive".to_string());
        let ffi_err: FfiError = wallet_err.into();

        match ffi_err {
            FfiError::InvalidFormat { msg } => {
                assert_eq!(msg, "age must be positive");
            }
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_from_wallet_error_serialization() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::SerializationError("invalid JSON".to_string());
        let ffi_err: FfiError = wallet_err.into();

        match ffi_err {
            FfiError::InvalidFormat { msg } => {
                assert_eq!(msg, "invalid JSON");
            }
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_from_wallet_error_base64() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::Base64Error("invalid padding".to_string());
        let ffi_err: FfiError = wallet_err.into();

        match ffi_err {
            FfiError::InvalidFormat { msg } => {
                assert_eq!(msg, "invalid padding");
            }
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_from_wallet_error_security() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::SecurityError("tampered data".to_string());
        let ffi_err: FfiError = wallet_err.into();

        match ffi_err {
            FfiError::SecurityViolation { msg } => {
                assert_eq!(msg, "tampered data");
            }
            _ => panic!("Expected SecurityViolation error"),
        }
    }

    #[test]
    fn test_from_wallet_error_invalid_signature() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::InvalidSignature;
        let ffi_err: FfiError = wallet_err.into();

        match ffi_err {
            FfiError::InvalidFormat { msg } => {
                assert_eq!(msg, "invalid signature");
            }
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_from_wallet_error_credential_not_found() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::CredentialNotFound;
        let ffi_err: FfiError = wallet_err.into();

        assert!(
            matches!(ffi_err, FfiError::CredentialNotFound),
            "Expected CredentialNotFound error"
        );
    }

    #[test]
    fn test_from_wallet_error_credential_expired() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::CredentialExpired;
        let ffi_err: FfiError = wallet_err.into();

        assert!(
            matches!(ffi_err, FfiError::CredentialExpired),
            "Expected CredentialExpired error"
        );
    }

    #[test]
    fn test_from_wallet_error_invalid_credential_format() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::InvalidCredentialFormat;
        let ffi_err: FfiError = wallet_err.into();

        match ffi_err {
            FfiError::InvalidFormat { msg } => {
                assert_eq!(msg, "invalid credential format");
            }
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_from_wallet_error_validation_failed() {
        use provii_mobile_sdk_core::error::WalletError;

        let wallet_err = WalletError::ValidationFailed("checksum mismatch".to_string());
        let ffi_err: FfiError = wallet_err.into();

        match ffi_err {
            FfiError::InvalidFormat { msg } => {
                assert_eq!(msg, "checksum mismatch");
            }
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_from_serde_json_error() -> Result<(), Box<dyn std::error::Error>> {
        let Err(json_err) = serde_json::from_str::<serde_json::Value>("not json") else {
            panic!("expected error")
        };
        let ffi_err: FfiError = json_err.into();

        match ffi_err {
            FfiError::InvalidFormat { msg } => {
                assert_eq!(msg, "JSON parsing failed");
            }
            _ => panic!("Expected InvalidFormat error"),
        }
        Ok(())
    }

    #[test]
    fn test_ffi_result_ok() {
        let value = "success".to_string();
        let result: FfiResult<String> = Ok(value.clone());
        assert!(result.is_ok());
        // Verify the contained value through pattern matching.
        if let Ok(v) = result {
            assert_eq!(v, value);
        }
    }

    #[test]
    fn test_ffi_result_err() {
        let result: FfiResult<String> = Err(FfiError::NotInitialized);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.to_string(), "Not initialised");
        }
    }

    #[test]
    fn test_error_chain_conversion() -> Result<(), Box<dyn std::error::Error>> {
        // Test that errors can be converted through multiple layers
        let json_str = "{invalid json}";
        let parse_result = serde_json::from_str::<serde_json::Value>(json_str);

        let ffi_result: FfiResult<serde_json::Value> = parse_result.map_err(|e| e.into());

        assert!(ffi_result.is_err());
        let Err(err_val) = ffi_result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::InvalidFormat { .. } => {}
            _ => panic!("Expected InvalidFormat"),
        }
        Ok(())
    }

    #[test]
    fn test_error_display_variants() {
        let errors = vec![
            (
                FfiError::InvalidFormat {
                    msg: "test".to_string(),
                },
                "Invalid format: test",
            ),
            (
                FfiError::Storage {
                    msg: "test".to_string(),
                },
                "Storage error: test",
            ),
            (
                FfiError::Network {
                    msg: "test".to_string(),
                },
                "Network error: test",
            ),
            (
                FfiError::Prover {
                    msg: "test".to_string(),
                },
                "Prover error: test",
            ),
            (FfiError::OperationInProgress, "Operation in progress"),
            (FfiError::OperationCancelled, "Operation cancelled"),
            (FfiError::NotInitialized, "Not initialised"),
            (
                FfiError::BiometricNotAuthenticated,
                "Biometric authentication required but not completed",
            ),
            (
                FfiError::RequestTimeout { seconds: 10 },
                "Request timed out after 10s",
            ),
            (FfiError::CredentialNotFound, "Credential not found"),
            (FfiError::CredentialExpired, "Credential expired"),
            (
                FfiError::SecurityViolation {
                    msg: "test".to_string(),
                },
                "Security violation: test",
            ),
            (
                FfiError::Generic {
                    msg: "test".to_string(),
                },
                "test",
            ),
        ];

        for (error, expected) in errors {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn test_error_debug_format() {
        let error = FfiError::InvalidFormat {
            msg: "debug test".to_string(),
        };

        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("InvalidFormat"));
        assert!(debug_str.contains("debug test"));
    }

    // ========== Additional Edge Case Tests ==========

    #[test]
    fn test_error_empty_message() {
        let error = FfiError::InvalidFormat { msg: String::new() };
        assert_eq!(error.to_string(), "Invalid format: ");
    }

    #[test]
    fn test_error_very_long_message() {
        let long_msg = "A".repeat(10000);
        let error = FfiError::Network {
            msg: long_msg.clone(),
        };
        assert!(error.to_string().len() > 10000);
        assert!(error.to_string().contains(&long_msg));
    }

    #[test]
    fn test_error_unicode_message() {
        let unicode_msg = "エラー: ネットワーク接続に失敗しました 🔥";
        let error = FfiError::Network {
            msg: unicode_msg.to_string(),
        };
        assert!(error.to_string().contains(unicode_msg));
    }

    #[test]
    fn test_error_newline_in_message() {
        let multiline = "Line 1\nLine 2\nLine 3";
        let error = FfiError::Storage {
            msg: multiline.to_string(),
        };
        assert!(error.to_string().contains("\n"));
    }

    #[test]
    fn test_error_special_chars_in_message() {
        let special = "<>&\"'";
        let error = FfiError::InvalidFormat {
            msg: special.to_string(),
        };
        assert!(error.to_string().contains("<>&\"'"));
    }

    #[test]
    fn test_error_null_byte_in_message() {
        let with_null = "Error\0message";
        let error = FfiError::Generic {
            msg: with_null.to_string(),
        };
        assert!(error.to_string().contains("Error"));
    }

    #[test]
    fn test_from_anyhow_with_context() {
        let anyhow_err = anyhow::anyhow!("base error").context("additional context");
        let ffi_err: FfiError = anyhow_err.into();

        // Only the root cause should cross the FFI boundary, not the
        // full chain. This prevents leaking internal details to mobile.
        match ffi_err {
            FfiError::Generic { msg } => {
                assert!(msg.contains("base error"));
                assert!(
                    !msg.contains("additional context"),
                    "error chain should not cross FFI boundary"
                );
            }
            _ => panic!("Expected Generic error"),
        }
    }

    #[test]
    fn test_from_serde_json_eof_error() -> Result<(), Box<dyn std::error::Error>> {
        let Err(json_err) = serde_json::from_str::<serde_json::Value>("") else {
            panic!("expected error")
        };
        let ffi_err: FfiError = json_err.into();

        match ffi_err {
            FfiError::InvalidFormat { msg } => {
                assert_eq!(msg, "JSON parsing failed");
            }
            _ => panic!("Expected InvalidFormat error"),
        }
        Ok(())
    }

    #[test]
    fn test_from_serde_json_type_error() -> Result<(), Box<dyn std::error::Error>> {
        let Err(json_err) = serde_json::from_str::<i32>("\"string\"") else {
            panic!("expected error")
        };
        let ffi_err: FfiError = json_err.into();

        match ffi_err {
            FfiError::InvalidFormat { .. } => {}
            _ => panic!("Expected InvalidFormat error"),
        }
        Ok(())
    }

    #[test]
    fn test_ffi_result_map() -> Result<(), Box<dyn std::error::Error>> {
        let result: FfiResult<i32> = Ok(42);
        let mapped = result.map(|x| x * 2);
        assert_eq!(mapped?, 84);
        Ok(())
    }

    #[test]
    fn test_ffi_result_map_err() -> Result<(), Box<dyn std::error::Error>> {
        let result: FfiResult<i32> = Err(FfiError::NotInitialized);
        let mapped = result.map_err(|e| FfiError::Generic {
            msg: format!("Wrapped: {}", e),
        });

        let Err(err_val) = mapped else {
            panic!("expected error")
        };
        match err_val {
            FfiError::Generic { msg } => {
                assert!(msg.contains("Wrapped"));
                assert!(msg.contains("Not initialised"));
            }
            _ => panic!("Expected Generic error"),
        }
        Ok(())
    }

    #[test]
    fn test_ffi_result_and_then() -> Result<(), Box<dyn std::error::Error>> {
        let result: FfiResult<i32> = Ok(42);
        let chained = result.and_then(|x| {
            if x > 0 {
                Ok(x * 2)
            } else {
                Err(FfiError::InvalidFormat {
                    msg: "Negative".to_string(),
                })
            }
        });
        assert_eq!(chained?, 84);
        Ok(())
    }

    #[test]
    fn test_ffi_result_or_else() -> Result<(), Box<dyn std::error::Error>> {
        let result: FfiResult<i32> = Err(FfiError::NotInitialized);
        let recovered: FfiResult<i32> = result.or(Ok(42));
        assert_eq!(recovered?, 42);
        Ok(())
    }

    #[test]
    fn test_error_variants_are_distinct() {
        let errors = vec![
            FfiError::InvalidFormat {
                msg: "test".to_string(),
            },
            FfiError::Storage {
                msg: "test".to_string(),
            },
            FfiError::Network {
                msg: "test".to_string(),
            },
            FfiError::Prover {
                msg: "test".to_string(),
            },
            FfiError::OperationInProgress,
            FfiError::OperationCancelled,
            FfiError::NotInitialized,
            FfiError::AgeRequirementNotMet,
            FfiError::BiometricNotAuthenticated,
            FfiError::RetryBudgetExceeded {
                msg: "test".to_string(),
            },
            FfiError::RequestTimeout { seconds: 30 },
            FfiError::CredentialNotFound,
            FfiError::CredentialExpired,
            FfiError::SecurityViolation {
                msg: "test".to_string(),
            },
            FfiError::Generic {
                msg: "test".to_string(),
            },
        ];

        // Each error variant should have a distinct display string
        let mut displays: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
        displays.sort();
        displays.dedup();
        assert_eq!(displays.len(), 15);
    }

    #[test]
    fn test_error_message_with_quotes() {
        let msg_with_quotes = r#"Error: "value" is invalid"#;
        let error = FfiError::InvalidFormat {
            msg: msg_with_quotes.to_string(),
        };
        assert!(error.to_string().contains("\"value\""));
    }

    #[test]
    fn test_error_message_with_backslashes() {
        let msg = r"Path: C:\Users\test\file.txt";
        let error = FfiError::Storage {
            msg: msg.to_string(),
        };
        assert!(error.to_string().contains(r"C:\Users"));
    }

    #[test]
    fn test_error_concatenation() {
        let err1 = FfiError::Network {
            msg: "Connection failed".to_string(),
        };
        let err2 = FfiError::Storage {
            msg: "Disk full".to_string(),
        };

        let combined = FfiError::Generic {
            msg: format!("{} and {}", err1, err2),
        };

        assert!(combined.to_string().contains("Connection failed"));
        assert!(combined.to_string().contains("Disk full"));
    }

    #[test]
    fn test_error_from_multiple_sources() -> Result<(), Box<dyn std::error::Error>> {
        // Test converting from different error sources
        let Err(err_val) = serde_json::from_str::<i32>("bad") else {
            panic!("expected error")
        };
        let json_err: FfiError = err_val.into();
        let anyhow_err: FfiError = anyhow::anyhow!("test").into();

        assert!(matches!(json_err, FfiError::InvalidFormat { .. }));
        assert!(matches!(anyhow_err, FfiError::Generic { .. }));
        Ok(())
    }

    #[test]
    fn test_error_whitespace_handling() {
        let whitespace_msg = "  \t\n  Error with whitespace  \n\t  ";
        let error = FfiError::Network {
            msg: whitespace_msg.to_string(),
        };
        assert!(error.to_string().contains("\t"));
        assert!(error.to_string().contains("\n"));
    }

    #[test]
    fn test_error_emoji_in_message() {
        let emoji_msg = "❌ Error: Operation failed 🚫";
        let error = FfiError::Prover {
            msg: emoji_msg.to_string(),
        };
        assert!(error.to_string().contains("❌"));
        assert!(error.to_string().contains("🚫"));
    }

    #[test]
    fn test_ffi_result_question_mark_simulation() -> Result<(), Box<dyn std::error::Error>> {
        fn inner_function() -> FfiResult<i32> {
            let json_result = serde_json::from_str::<i32>("42");
            let value = json_result.map_err(FfiError::from)?;
            Ok(value)
        }

        let result = inner_function();
        assert_eq!(result?, 42);
        Ok(())
    }

    #[test]
    fn test_ffi_result_early_return() -> Result<(), Box<dyn std::error::Error>> {
        fn process() -> FfiResult<String> {
            let json: serde_json::Value =
                serde_json::from_str("invalid").map_err(FfiError::from)?;
            Ok(json.to_string())
        }

        let result = process();
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        assert!(matches!(err_val, FfiError::InvalidFormat { .. }));
        Ok(())
    }

    #[test]
    fn test_error_debug_vs_display() {
        let error = FfiError::Storage {
            msg: "test message".to_string(),
        };

        let display = format!("{}", error);
        let debug = format!("{:?}", error);

        assert_eq!(display, "Storage error: test message");
        assert!(debug.contains("Storage"));
        assert!(debug.contains("test message"));
        assert_ne!(display, debug); // Display and Debug should be different
    }

    #[test]
    fn test_error_message_with_json() -> Result<(), Box<dyn std::error::Error>> {
        let json_in_msg = r#"{"error": "Invalid JSON", "code": 400}"#;
        let error = FfiError::Network {
            msg: json_in_msg.to_string(),
        };
        assert!(error.to_string().contains("{\"error\""));
        Ok(())
    }

    #[test]
    fn test_error_message_with_url() {
        let url_in_msg = "Failed to fetch: https://example.com/api/v1/endpoint?token=abc123";
        let error = FfiError::Network {
            msg: url_in_msg.to_string(),
        };
        assert!(error.to_string().contains("https://"));
    }

    #[test]
    fn test_error_message_with_stacktrace_like_text() {
        let stacktrace =
            "at module::function (file.rs:123:45)\nat another::place (other.rs:456:78)";
        let error = FfiError::Prover {
            msg: stacktrace.to_string(),
        };
        assert!(error.to_string().contains("file.rs:123"));
    }

    #[test]
    fn test_error_variants_unit_types() {
        // Unit variants should not have any message
        let op_in_progress = FfiError::OperationInProgress;
        let op_cancelled = FfiError::OperationCancelled;
        let not_init = FfiError::NotInitialized;
        let age_not_met = FfiError::AgeRequirementNotMet;

        assert_eq!(op_in_progress.to_string(), "Operation in progress");
        assert_eq!(op_cancelled.to_string(), "Operation cancelled");
        assert_eq!(not_init.to_string(), "Not initialised");
        assert_eq!(
            age_not_met.to_string(),
            "Your credential doesn't meet the age requirement for this verification"
        );
    }

    #[test]
    fn test_ffi_result_collect() -> Result<(), Box<dyn std::error::Error>> {
        let results: Vec<FfiResult<i32>> = vec![Ok(1), Ok(2), Ok(3)];
        let collected: FfiResult<Vec<i32>> = results.into_iter().collect();
        assert_eq!(collected?, vec![1, 2, 3]);
        Ok(())
    }

    #[test]
    fn test_ffi_result_collect_with_error() {
        let results: Vec<FfiResult<i32>> = vec![Ok(1), Err(FfiError::NotInitialized), Ok(3)];
        let collected: FfiResult<Vec<i32>> = results.into_iter().collect();
        assert!(collected.is_err());
    }

    #[test]
    fn test_error_format_consistency() {
        // All message-based errors should follow the pattern "Type: message"
        let invalid = FfiError::InvalidFormat {
            msg: "test".to_string(),
        };
        let storage = FfiError::Storage {
            msg: "test".to_string(),
        };
        let network = FfiError::Network {
            msg: "test".to_string(),
        };
        let prover = FfiError::Prover {
            msg: "test".to_string(),
        };

        assert!(invalid.to_string().starts_with("Invalid format:"));
        assert!(storage.to_string().starts_with("Storage error:"));
        assert!(network.to_string().starts_with("Network error:"));
        assert!(prover.to_string().starts_with("Prover error:"));
    }

    #[test]
    fn test_error_case_sensitivity() {
        let lower = FfiError::InvalidFormat {
            msg: "error".to_string(),
        };
        let upper = FfiError::InvalidFormat {
            msg: "ERROR".to_string(),
        };

        assert_ne!(lower.to_string(), upper.to_string());
    }

    #[test]
    fn test_ffi_error_request_timeout() {
        let error = FfiError::RequestTimeout { seconds: 30 };
        assert_eq!(error.to_string(), "Request timed out after 30s");

        let error_1 = FfiError::RequestTimeout { seconds: 1 };
        assert_eq!(error_1.to_string(), "Request timed out after 1s");

        let error_0 = FfiError::RequestTimeout { seconds: 0 };
        assert_eq!(error_0.to_string(), "Request timed out after 0s");

        let error_large = FfiError::RequestTimeout { seconds: 3600 };
        assert_eq!(error_large.to_string(), "Request timed out after 3600s");
    }
}
