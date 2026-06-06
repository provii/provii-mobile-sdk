// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Error types for the wallet SDK core crate.
//!
//! Defines [`WalletError`], the top-level error enum that unifies errors from
//! credential management, proof generation, storage, networking, and input
//! validation. Conversion impls are provided for all internal error types
//! so callers can use the `?` operator throughout.

use std::fmt;
use thiserror::Error;

/// Top-level error enum for wallet SDK operations.
///
/// Each variant maps to a distinct failure domain. String payloads carry the
/// upstream error message; parameterless variants represent well-known
/// conditions that need no further detail.
///
/// All string payloads are derived from `.to_string()` on the source error,
/// so they contain display text only, never secret material.
#[derive(Debug, Error)]
pub enum WalletError {
    /// A credential operation failed with the given message.
    #[error("credential error: {0}")]
    CredentialError(String),

    /// The requested credential was not found in storage.
    #[error("credential not found")]
    CredentialNotFound,

    /// The credential's expiry timestamp has passed.
    #[error("credential expired")]
    CredentialExpired,

    /// The credential data could not be parsed or is structurally invalid.
    #[error("invalid credential format")]
    InvalidCredentialFormat,

    /// A prover subsystem error with detail message.
    #[error("prover error: {0}")]
    ProverError(String),

    /// The Groth16 proving key has not been loaded yet.
    #[error("prover not initialised")]
    ProverNotInitialized,

    /// Zero knowledge proof generation failed.
    #[error("proof generation failed: {0}")]
    ProofGenerationFailed(String),

    /// A platform storage operation failed.
    #[error("storage error: {0}")]
    StorageError(String),

    /// The credential store has reached its capacity limit.
    #[error("storage full")]
    StorageFull,

    /// An HTTP or QUIC network request failed.
    #[error("network error: {0}")]
    NetworkError(String),

    /// A network request exceeded the configured timeout.
    #[error("request timeout")]
    RequestTimeout,

    /// Caller-supplied input failed validation.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// A post-processing validation check did not pass.
    #[error("validation failed: {0}")]
    ValidationFailed(String),

    /// The credential holder does not meet the age threshold.
    #[error("age requirement not met")]
    UnderAge,

    /// JSON or postcard serialisation/deserialisation failed.
    #[error("serialisation error: {0}")]
    SerializationError(String),

    /// Base64 decoding failed.
    #[error("base64 decode error: {0}")]
    Base64Error(String),

    /// A security-sensitive operation was rejected.
    #[error("security error: {0}")]
    SecurityError(String),

    /// A cryptographic signature did not verify.
    #[error("invalid signature")]
    InvalidSignature,

    /// A compound operation failed; the message includes context from the
    /// [`ErrorContext`] trait.
    #[error("operation failed: {0}")]
    OperationFailed(String),

    /// An unexpected error from a dependency or internal logic. The message
    /// is the upstream error's display text.
    #[error("unknown error: {0}")]
    Unknown(String),
}

/// Convenience alias so callers can write `Result<T>` instead of
/// `std::result::Result<T, WalletError>`.
pub type Result<T> = std::result::Result<T, WalletError>;

impl From<serde_json::Error> for WalletError {
    fn from(err: serde_json::Error) -> Self {
        WalletError::SerializationError(err.to_string())
    }
}

impl From<base64::DecodeError> for WalletError {
    fn from(err: base64::DecodeError) -> Self {
        WalletError::Base64Error(err.to_string())
    }
}

impl From<crate::credential::CredentialError> for WalletError {
    fn from(err: crate::credential::CredentialError) -> Self {
        WalletError::CredentialError(err.to_string())
    }
}

impl From<crate::prover::ProverError> for WalletError {
    fn from(err: crate::prover::ProverError) -> Self {
        WalletError::ProverError(err.to_string())
    }
}

impl From<crate::storage::StorageError> for WalletError {
    fn from(err: crate::storage::StorageError) -> Self {
        WalletError::StorageError(err.to_string())
    }
}

// HTTP errors are handled in the FFI layer, not in this crate.

impl From<anyhow::Error> for WalletError {
    fn from(err: anyhow::Error) -> Self {
        WalletError::Unknown(err.to_string())
    }
}

/// Adds a human-readable context string to any error that converts into
/// [`WalletError`]. Modelled after `anyhow::Context` but stays within the
/// typed error world.
///
/// # Errors
///
/// Both methods return [`WalletError::OperationFailed`] wrapping the
/// original error message prefixed by the context string.
pub trait ErrorContext<T> {
    /// Wraps the error with a static context message.
    fn context<C>(self, context: C) -> Result<T>
    where
        C: fmt::Display + Send + Sync + 'static;

    /// Wraps the error with a lazily computed context message. The closure
    /// is only called when the result is `Err`.
    fn with_context<C, F>(self, f: F) -> Result<T>
    where
        C: fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C;
}

impl<T, E> ErrorContext<T> for std::result::Result<T, E>
where
    E: Into<WalletError>,
{
    fn context<C>(self, context: C) -> Result<T>
    where
        C: fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|e| {
            let base_error = e.into();
            WalletError::OperationFailed(format!("{}: {}", context, base_error))
        })
    }

    fn with_context<C, F>(self, f: F) -> Result<T>
    where
        C: fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.map_err(|e| {
            let base_error = e.into();
            WalletError::OperationFailed(format!("{}: {}", f(), base_error))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::CredentialError;
    use crate::prover::ProverError;
    use crate::storage::StorageError;

    #[test]
    fn test_wallet_error_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::CredentialNotFound;
        assert_eq!(err.to_string(), "credential not found");

        let err = WalletError::ProverNotInitialized;
        assert_eq!(err.to_string(), "prover not initialised");

        let err = WalletError::InvalidInput("test".to_string());
        assert_eq!(err.to_string(), "invalid input: test");
        Ok(())
    }

    #[test]
    fn test_from_serde_json_error() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let json_err = serde_json::from_str::<u32>("invalid")
            .err()
            .ok_or("expected error")?;
        let wallet_err: WalletError = json_err.into();

        match wallet_err {
            WalletError::SerializationError(_) => {}
            _ => return Err("Expected SerializationError".into()),
        }
        Ok(())
    }

    #[test]
    fn test_from_base64_error() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let base64_err = STANDARD.decode("!!!").err().ok_or("expected error")?;
        let wallet_err: WalletError = base64_err.into();

        match wallet_err {
            WalletError::Base64Error(_) => {}
            _ => return Err("Expected Base64Error".into()),
        }
        Ok(())
    }

    #[test]
    fn test_from_credential_error() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let cred_err = CredentialError::Expired;
        let wallet_err: WalletError = cred_err.into();

        match wallet_err {
            WalletError::CredentialError(msg) => {
                assert!(msg.contains("expired"));
            }
            _ => return Err("Expected CredentialError".into()),
        }
        Ok(())
    }

    #[test]
    fn test_from_prover_error() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let prover_err = ProverError::NotInitialized;
        let wallet_err: WalletError = prover_err.into();

        match wallet_err {
            WalletError::ProverError(msg) => {
                assert!(msg.contains("not initialised"));
            }
            _ => return Err("Expected ProverError".into()),
        }
        Ok(())
    }

    #[test]
    fn test_from_storage_error() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage_err = StorageError::NotFound;
        let wallet_err: WalletError = storage_err.into();

        match wallet_err {
            WalletError::StorageError(msg) => {
                assert!(msg.contains("not found"));
            }
            _ => return Err("Expected StorageError".into()),
        }
        Ok(())
    }

    #[test]
    fn test_from_anyhow_error() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let anyhow_err = anyhow::anyhow!("test error");
        let wallet_err: WalletError = anyhow_err.into();

        match wallet_err {
            WalletError::Unknown(msg) => {
                assert_eq!(msg, "test error");
            }
            _ => return Err("Expected Unknown error".into()),
        }
        Ok(())
    }

    #[test]
    fn test_error_context_trait() -> std::result::Result<(), Box<dyn std::error::Error>> {
        fn failing_operation() -> std::result::Result<(), StorageError> {
            Err(StorageError::NotFound)
        }

        let result = failing_operation().context("Failed to load credential");

        assert!(result.is_err());
        match result {
            Err(WalletError::OperationFailed(msg)) => {
                assert!(msg.contains("Failed to load credential"));
                assert!(msg.contains("not found"));
            }
            _ => return Err("Expected OperationFailed with context".into()),
        }
        Ok(())
    }

    #[test]
    fn test_error_with_context_trait() -> std::result::Result<(), Box<dyn std::error::Error>> {
        fn failing_operation() -> std::result::Result<(), StorageError> {
            Err(StorageError::NotFound)
        }

        let credential_id = "cred123";
        let result = failing_operation()
            .with_context(|| format!("Failed to load credential {}", credential_id));

        assert!(result.is_err());
        match result {
            Err(WalletError::OperationFailed(msg)) => {
                assert!(msg.contains("Failed to load credential cred123"));
                assert!(msg.contains("not found"));
            }
            _ => return Err("Expected OperationFailed with context".into()),
        }
        Ok(())
    }

    #[test]
    fn test_error_context_preserves_ok() -> std::result::Result<(), Box<dyn std::error::Error>> {
        fn successful_operation() -> std::result::Result<i32, StorageError> {
            Ok(42)
        }

        let result = successful_operation().context("This should not appear");

        assert!(result.is_ok());
        assert_eq!(result?, 42);
        Ok(())
    }

    #[test]
    fn test_result_type_alias() -> std::result::Result<(), Box<dyn std::error::Error>> {
        fn test_function() -> Result<String> {
            Ok("success".to_string())
        }

        let result = test_function();
        assert!(result.is_ok());
        assert_eq!(result?, "success");
        Ok(())
    }

    #[test]
    fn test_error_chain() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Test that errors can be chained through conversions
        let storage_err = StorageError::NotFound;
        let wallet_err: WalletError = storage_err.into();
        let result: Result<()> = Err(wallet_err);

        let chained = result.context("Outer operation failed");

        match chained {
            Err(WalletError::OperationFailed(msg)) => {
                assert!(msg.contains("Outer operation failed"));
                assert!(msg.contains("not found"));
            }
            _ => return Err("Expected chained error".into()),
        }
        Ok(())
    }

    #[test]
    fn test_all_error_variants() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Test that all error variants can be created
        let errors = vec![
            WalletError::CredentialError("test".to_string()),
            WalletError::CredentialNotFound,
            WalletError::CredentialExpired,
            WalletError::InvalidCredentialFormat,
            WalletError::ProverError("test".to_string()),
            WalletError::ProverNotInitialized,
            WalletError::ProofGenerationFailed("test".to_string()),
            WalletError::StorageError("test".to_string()),
            WalletError::StorageFull,
            WalletError::NetworkError("test".to_string()),
            WalletError::RequestTimeout,
            WalletError::InvalidInput("test".to_string()),
            WalletError::ValidationFailed("test".to_string()),
            WalletError::UnderAge,
            WalletError::SerializationError("test".to_string()),
            WalletError::Base64Error("test".to_string()),
            WalletError::SecurityError("test".to_string()),
            WalletError::InvalidSignature,
            WalletError::OperationFailed("test".to_string()),
            WalletError::Unknown("test".to_string()),
        ];

        // Verify they all implement Display
        for error in errors {
            let _ = error.to_string();
        }
        Ok(())
    }

    // ============================================================================
    // FULL COVERAGE ERROR VARIANT TESTS
    // ============================================================================

    #[test]
    fn test_credential_error_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::CredentialError("invalid format".to_string());
        assert_eq!(err.to_string(), "credential error: invalid format");

        let err = WalletError::CredentialError("".to_string());
        assert_eq!(err.to_string(), "credential error: ");

        let err = WalletError::CredentialError("日本語".to_string());
        assert!(err.to_string().contains("日本語"));
        Ok(())
    }

    #[test]
    fn test_credential_not_found_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::CredentialNotFound;
        assert_eq!(err.to_string(), "credential not found");
        Ok(())
    }

    #[test]
    fn test_credential_expired_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::CredentialExpired;
        assert_eq!(err.to_string(), "credential expired");
        Ok(())
    }

    #[test]
    fn test_invalid_credential_format_display(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::InvalidCredentialFormat;
        assert_eq!(err.to_string(), "invalid credential format");
        Ok(())
    }

    #[test]
    fn test_prover_error_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::ProverError("circuit failed".to_string());
        assert_eq!(err.to_string(), "prover error: circuit failed");
        Ok(())
    }

    #[test]
    fn test_prover_not_initialized_display() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let err = WalletError::ProverNotInitialized;
        assert_eq!(err.to_string(), "prover not initialised");
        Ok(())
    }

    #[test]
    fn test_proof_generation_failed_display() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let err = WalletError::ProofGenerationFailed("constraint not satisfied".to_string());
        assert_eq!(
            err.to_string(),
            "proof generation failed: constraint not satisfied"
        );
        Ok(())
    }

    #[test]
    fn test_storage_error_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::StorageError("disk full".to_string());
        assert_eq!(err.to_string(), "storage error: disk full");
        Ok(())
    }

    #[test]
    fn test_storage_full_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::StorageFull;
        assert_eq!(err.to_string(), "storage full");
        Ok(())
    }

    #[test]
    fn test_network_error_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::NetworkError("connection refused".to_string());
        assert_eq!(err.to_string(), "network error: connection refused");
        Ok(())
    }

    #[test]
    fn test_request_timeout_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::RequestTimeout;
        assert_eq!(err.to_string(), "request timeout");
        Ok(())
    }

    #[test]
    fn test_invalid_input_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::InvalidInput("age must be positive".to_string());
        assert_eq!(err.to_string(), "invalid input: age must be positive");
        Ok(())
    }

    #[test]
    fn test_validation_failed_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::ValidationFailed("signature mismatch".to_string());
        assert_eq!(err.to_string(), "validation failed: signature mismatch");
        Ok(())
    }

    #[test]
    fn test_under_age_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::UnderAge;
        assert_eq!(err.to_string(), "age requirement not met");
        Ok(())
    }

    #[test]
    fn test_serialization_error_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::SerializationError("invalid JSON".to_string());
        assert_eq!(err.to_string(), "serialisation error: invalid JSON");
        Ok(())
    }

    #[test]
    fn test_base64_error_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::Base64Error("invalid padding".to_string());
        assert_eq!(err.to_string(), "base64 decode error: invalid padding");
        Ok(())
    }

    #[test]
    fn test_security_error_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::SecurityError("tampered data".to_string());
        assert_eq!(err.to_string(), "security error: tampered data");
        Ok(())
    }

    #[test]
    fn test_invalid_signature_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::InvalidSignature;
        assert_eq!(err.to_string(), "invalid signature");
        Ok(())
    }

    #[test]
    fn test_operation_failed_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::OperationFailed("could not complete".to_string());
        assert_eq!(err.to_string(), "operation failed: could not complete");
        Ok(())
    }

    #[test]
    fn test_unknown_error_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::Unknown("unexpected condition".to_string());
        assert_eq!(err.to_string(), "unknown error: unexpected condition");
        Ok(())
    }

    // ============================================================================
    // FULL COVERAGE FROM CONVERSION TESTS
    // ============================================================================

    #[test]
    fn test_from_serde_json_error_variants() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        // Test various JSON parsing errors
        let err = serde_json::from_str::<u32>("{")
            .err()
            .ok_or("expected error")?;
        let wallet_err: WalletError = err.into();
        assert!(matches!(wallet_err, WalletError::SerializationError(_)));

        let err = serde_json::from_str::<u32>("null")
            .err()
            .ok_or("expected error")?;
        let wallet_err: WalletError = err.into();
        assert!(matches!(wallet_err, WalletError::SerializationError(_)));
        Ok(())
    }

    #[test]
    fn test_from_base64_error_variants() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        // Invalid characters
        let err = STANDARD.decode("!!!").err().ok_or("expected error")?;
        let wallet_err: WalletError = err.into();
        assert!(matches!(wallet_err, WalletError::Base64Error(_)));

        // Invalid length (with padding)
        let err = STANDARD.decode("A").err().ok_or("expected error")?;
        let wallet_err: WalletError = err.into();
        assert!(matches!(wallet_err, WalletError::Base64Error(_)));
        Ok(())
    }

    #[test]
    fn test_from_credential_error_multiple_variants(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let variants = vec![
            CredentialError::Expired,
            CredentialError::InvalidFormat,
            CredentialError::MissingPrivateFields,
            CredentialError::NotYetValid,
            CredentialError::InvalidTimestampOrder { iat: 200, exp: 100 },
        ];

        for cred_err in variants {
            let wallet_err: WalletError = cred_err.into();
            assert!(matches!(wallet_err, WalletError::CredentialError(_)));
        }
        Ok(())
    }

    #[test]
    fn test_from_prover_error_multiple_variants(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let variants = vec![
            ProverError::NotInitialized,
            ProverError::ProofGenerationFailed("test".to_string()),
            ProverError::AlreadyInitialized,
            ProverError::InvalidProvingKey,
            ProverError::InvalidBase64("test".to_string()),
            ProverError::InvalidInput("test".to_string()),
            ProverError::MissingPrivateFields,
        ];

        for prover_err in variants {
            let wallet_err: WalletError = prover_err.into();
            assert!(matches!(wallet_err, WalletError::ProverError(_)));
        }
        Ok(())
    }

    #[test]
    fn test_from_storage_error_multiple_variants(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let variants = vec![
            StorageError::NotFound,
            StorageError::SerializationError("test".to_string()),
            StorageError::StorageFull,
        ];

        for storage_err in variants {
            let wallet_err: WalletError = storage_err.into();
            assert!(matches!(wallet_err, WalletError::StorageError(_)));
        }
        Ok(())
    }

    #[test]
    fn test_from_anyhow_error_with_context() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let err = anyhow::anyhow!("base error").context("additional context");
        let wallet_err: WalletError = err.into();

        match wallet_err {
            WalletError::Unknown(msg) => {
                assert!(msg.contains("additional context"));
            }
            _ => return Err("Expected Unknown error".into()),
        }
        Ok(())
    }

    #[test]
    fn test_error_message_empty_string() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let errors = vec![
            WalletError::CredentialError("".to_string()),
            WalletError::ProverError("".to_string()),
            WalletError::StorageError("".to_string()),
            WalletError::NetworkError("".to_string()),
            WalletError::InvalidInput("".to_string()),
            WalletError::ValidationFailed("".to_string()),
        ];

        for err in errors {
            let display = err.to_string();
            assert!(!display.is_empty(), "Display should not be empty");
        }
        Ok(())
    }

    #[test]
    fn test_error_message_unicode() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let errors = vec![
            WalletError::CredentialError("エラー".to_string()),
            WalletError::InvalidInput("日本語入力🔑".to_string()),
            WalletError::NetworkError("连接失败".to_string()),
        ];

        for err in errors {
            let display = err.to_string();
            assert!(!display.is_empty());
        }
        Ok(())
    }

    #[test]
    fn test_error_message_very_long() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let long_msg = "x".repeat(10000);
        let err = WalletError::CredentialError(long_msg.clone());
        let display = err.to_string();
        assert!(display.contains(&long_msg));
        Ok(())
    }

    // ============================================================================
    // FULL COVERAGE ERROR CONTEXT TESTS
    // ============================================================================

    #[test]
    fn test_error_context_empty_string() -> std::result::Result<(), Box<dyn std::error::Error>> {
        fn failing_op() -> std::result::Result<(), StorageError> {
            Err(StorageError::NotFound)
        }

        let result = failing_op().context("");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_error_context_unicode() -> std::result::Result<(), Box<dyn std::error::Error>> {
        fn failing_op() -> std::result::Result<(), StorageError> {
            Err(StorageError::NotFound)
        }

        let result = failing_op().context("日本語のエラー");
        match result {
            Err(WalletError::OperationFailed(msg)) => {
                assert!(msg.contains("日本語のエラー"));
            }
            _ => return Err("Expected OperationFailed".into()),
        }
        Ok(())
    }

    #[test]
    fn test_error_context_very_long() -> std::result::Result<(), Box<dyn std::error::Error>> {
        fn failing_op() -> std::result::Result<(), StorageError> {
            Err(StorageError::NotFound)
        }

        let long_context = "context ".repeat(1000);
        let result = failing_op().context(long_context.clone());

        match result {
            Err(WalletError::OperationFailed(msg)) => {
                assert!(msg.contains(&long_context));
            }
            _ => return Err("Expected OperationFailed".into()),
        }
        Ok(())
    }

    #[test]
    fn test_error_with_context_computed_lazily(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        fn failing_op() -> std::result::Result<(), StorageError> {
            Err(StorageError::NotFound)
        }

        let mut call_count = 0;
        let result = failing_op().with_context(|| {
            call_count += 1;
            format!("computed context {}", call_count)
        });

        assert!(result.is_err());
        match result {
            Err(WalletError::OperationFailed(msg)) => {
                assert!(msg.contains("computed context"));
            }
            _ => return Err("Expected OperationFailed".into()),
        }
        Ok(())
    }

    #[test]
    fn test_error_with_context_not_called_on_ok(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        fn successful_op() -> std::result::Result<i32, StorageError> {
            Ok(42)
        }

        let mut was_called = false;
        let result = successful_op().with_context(|| {
            was_called = true;
            "should not be called"
        });

        assert!(result.is_ok());
        assert!(!was_called, "Context function should not be called for Ok");
        Ok(())
    }

    #[test]
    fn test_error_context_chain_multiple() -> std::result::Result<(), Box<dyn std::error::Error>> {
        fn inner_op() -> std::result::Result<(), StorageError> {
            Err(StorageError::NotFound)
        }

        fn middle_op() -> Result<()> {
            inner_op().context("middle layer")?;
            Ok(())
        }

        fn outer_op() -> Result<()> {
            middle_op().context("outer layer")?;
            Ok(())
        }

        let result = outer_op();
        match result {
            Err(WalletError::OperationFailed(msg)) => {
                assert!(msg.contains("outer layer"));
                assert!(msg.contains("middle layer"));
            }
            _ => return Err("Expected nested OperationFailed".into()),
        }
        Ok(())
    }

    // ============================================================================
    // ERROR TRAIT AND DEBUG TESTS
    // ============================================================================

    #[test]
    fn test_error_debug_format() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = WalletError::CredentialNotFound;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("CredentialNotFound"));

        let err = WalletError::InvalidInput("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("InvalidInput"));
        assert!(debug_str.contains("test"));
        Ok(())
    }

    #[test]
    fn test_error_is_send_sync() -> std::result::Result<(), Box<dyn std::error::Error>> {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<WalletError>();
        assert_sync::<WalletError>();
        Ok(())
    }

    // ============================================================================
    // RESULT TYPE ALIAS TESTS
    // ============================================================================

    #[test]
    fn test_result_alias_with_question_mark() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        fn inner() -> Result<i32> {
            Ok(42)
        }

        fn outer() -> Result<String> {
            let value = inner()?;
            Ok(format!("value: {}", value))
        }

        let result = outer();
        assert!(result.is_ok());
        assert_eq!(result?, "value: 42");
        Ok(())
    }

    #[test]
    fn test_result_alias_error_propagation() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        fn inner() -> Result<i32> {
            Err(WalletError::CredentialNotFound)
        }

        fn outer() -> Result<String> {
            let value = inner()?;
            Ok(format!("value: {}", value))
        }

        let result = outer();
        assert!(result.is_err());
        assert!(matches!(
            result.err().ok_or("expected error")?,
            WalletError::CredentialNotFound
        ));
        Ok(())
    }

    #[test]
    fn test_result_alias_multiple_conversions(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        fn uses_serde() -> Result<serde_json::Value> {
            let json: serde_json::Value = serde_json::from_str("{invalid}")?;
            Ok(json)
        }

        let result = uses_serde();
        assert!(result.is_err());
        assert!(matches!(
            result.err().ok_or("expected error")?,
            WalletError::SerializationError(_)
        ));
        Ok(())
    }

    // ============================================================================
    // CONVERSION CHAIN TESTS
    // ============================================================================

    #[test]
    fn test_nested_error_conversions() -> std::result::Result<(), Box<dyn std::error::Error>> {
        fn storage_operation() -> std::result::Result<(), StorageError> {
            Err(StorageError::NotFound)
        }

        fn wallet_operation() -> Result<()> {
            storage_operation()?;
            Ok(())
        }

        let result = wallet_operation();
        assert!(result.is_err());
        match result.err().ok_or("expected error")? {
            WalletError::StorageError(msg) => {
                assert!(msg.contains("not found"));
            }
            _ => return Err("Expected StorageError conversion".into()),
        }
        Ok(())
    }

    #[test]
    fn test_error_conversion_preserves_message(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let original_msg = "specific error details";
        let storage_err = StorageError::SerializationError(original_msg.to_string());
        let wallet_err: WalletError = storage_err.into();

        match wallet_err {
            WalletError::StorageError(msg) => {
                assert!(msg.contains(original_msg));
            }
            _ => return Err("Expected StorageError".into()),
        }
        Ok(())
    }

    // ============================================================================
    // EDGE CASE TESTS
    // ============================================================================

    #[test]
    fn test_error_equality_different_messages(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // WalletError doesn't implement PartialEq, so we test via display
        let err1 = WalletError::InvalidInput("message1".to_string());
        let err2 = WalletError::InvalidInput("message2".to_string());

        assert_ne!(err1.to_string(), err2.to_string());
        Ok(())
    }

    #[test]
    fn test_error_with_special_characters() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let special_chars = "error: \n\t\r\0";
        let err = WalletError::CredentialError(special_chars.to_string());
        let display = err.to_string();
        // Should not panic
        assert!(!display.is_empty());
        Ok(())
    }

    #[test]
    fn test_all_parameterless_variants_display(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let errors = vec![
            (WalletError::CredentialNotFound, "credential not found"),
            (WalletError::CredentialExpired, "credential expired"),
            (
                WalletError::InvalidCredentialFormat,
                "invalid credential format",
            ),
            (WalletError::ProverNotInitialized, "prover not initialised"),
            (WalletError::StorageFull, "storage full"),
            (WalletError::RequestTimeout, "request timeout"),
            (WalletError::UnderAge, "age requirement not met"),
            (WalletError::InvalidSignature, "invalid signature"),
        ];

        for (err, expected_msg) in errors {
            assert_eq!(err.to_string(), expected_msg);
        }
        Ok(())
    }

    #[test]
    fn test_all_parametered_variants_display() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let test_cases = vec![
            (
                WalletError::CredentialError("msg".into()),
                "credential error: msg",
            ),
            (WalletError::ProverError("msg".into()), "prover error: msg"),
            (
                WalletError::ProofGenerationFailed("msg".into()),
                "proof generation failed: msg",
            ),
            (
                WalletError::StorageError("msg".into()),
                "storage error: msg",
            ),
            (
                WalletError::NetworkError("msg".into()),
                "network error: msg",
            ),
            (
                WalletError::InvalidInput("msg".into()),
                "invalid input: msg",
            ),
            (
                WalletError::ValidationFailed("msg".into()),
                "validation failed: msg",
            ),
            (
                WalletError::SerializationError("msg".into()),
                "serialisation error: msg",
            ),
            (
                WalletError::Base64Error("msg".into()),
                "base64 decode error: msg",
            ),
            (
                WalletError::SecurityError("msg".into()),
                "security error: msg",
            ),
            (
                WalletError::OperationFailed("msg".into()),
                "operation failed: msg",
            ),
            (WalletError::Unknown("msg".into()), "unknown error: msg"),
        ];

        for (err, expected) in test_cases {
            assert_eq!(err.to_string(), expected);
        }
        Ok(())
    }
}
