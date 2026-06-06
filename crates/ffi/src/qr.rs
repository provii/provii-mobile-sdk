// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! QR code payload parsing and validation for the FFI boundary.
//!
//! Handles two QR payload families:
//!
//! * **Verification challenges** (v2) carry the full challenge data needed to
//!   generate a zero knowledge age proof. They arrive either as raw JSON, as a
//!   base64url-encoded body inside a deep link, or in a minimal form that only
//!   contains a `challenge_id` (which signals the caller to fetch the remaining
//!   fields from provii-verifier).
//! * **Attestation payloads** (v1) carry opaque base64url data produced during
//!   issuance.
//!
//! All incoming payloads are size-bounded by [`MAX_QR_PAYLOAD_SIZE`] before any
//! parsing begins. Individual string fields are further validated by
//! [`QrChallengePayload::validate_field_lengths`] to prevent memory exhaustion
//! from malformed input.
//!
//! # Security considerations
//!
//! `QrChallengePayload` derives [`Zeroize`] and [`ZeroizeOnDrop`] because it
//! contains the `submit_secret` and `code_verifier` fields. The manual
//! [`Debug`] impl on [`QrPayload`] redacts those fields so they cannot leak
//! into log output.

use crate::errors::{FfiError, FfiResult};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Hard upper bound (in bytes) on raw QR content accepted for parsing.
///
/// Applied before any base64 decoding or JSON deserialisation so that
/// oversized input is rejected at zero cost.
const MAX_QR_PAYLOAD_SIZE: usize = 500;

/// Expected deep link URL prefixes (exact match, not substring).
const CUSTOM_SCHEME_VERIFY_PREFIX: &str = "provii://verify?d=";

/// HTTPS variant of the deep link prefix used by Universal Links / App Links.
const HTTPS_VERIFY_PREFIX: &str = "https://provii.app/verify?d=";

/// Top-level discriminated union for all supported QR payload types.
///
/// The `type` field in the JSON selects the variant. Unknown types are
/// rejected by serde.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum QrPayload {
    /// Full or partial verification challenge, version 2.
    #[serde(rename = "verification_challenge/v2")]
    VerificationChallenge {
        /// The flattened challenge fields.
        #[serde(flatten)]
        data: QrChallengePayload,
    },

    /// Opaque attestation blob produced during issuance.
    #[serde(rename = "attestation/v1")]
    Attestation {
        /// Base64url-encoded attestation data.
        data: String,
    },
}

// Manual Debug impl to avoid leaking secret fields (submit_secret, code_verifier).
impl std::fmt::Debug for QrPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QrPayload::VerificationChallenge { data } => f
                .debug_struct("QrPayload::VerificationChallenge")
                .field("challenge_id", &data.challenge_id)
                .field("cutoff_days", &data.cutoff_days)
                .field("submit_secret", &"[REDACTED]")
                .field("code_verifier", &"[REDACTED]")
                .finish(),
            QrPayload::Attestation { .. } => f
                .debug_struct("QrPayload::Attestation")
                .field("data", &"[REDACTED]")
                .finish(),
        }
    }
}

/// Verification challenge payload as encoded in a QR code or deep link.
///
/// Fields marked `#[zeroize(skip)]` are non-secret identifiers or config
/// values. The remaining fields (`rp_challenge`, `submit_secret`,
/// `code_verifier`) are zeroised on drop because they carry per-session secret
/// material that must not persist in memory beyond their useful lifetime.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct QrChallengePayload {
    /// Opaque challenge identifier assigned by provii-verifier.
    #[zeroize(skip)]
    pub challenge_id: String,

    /// Relying party challenge string, used in proof generation.
    pub rp_challenge: String,

    /// Age cutoff in days since the Unix epoch.
    #[zeroize(skip)]
    pub cutoff_days: i32,

    /// Identifier for the verifying key that the verifier expects.
    #[zeroize(skip)]
    pub verifying_key_id: u32,

    /// One-time secret required when submitting the proof.
    pub submit_secret: String,

    /// UTC timestamp (seconds since epoch) after which this challenge expires.
    #[zeroize(skip)]
    pub expires_at: u64,

    /// Absolute URL to which the proof should be submitted.
    #[zeroize(skip)]
    pub verify_url: String,

    /// PKCE code verifier, present only for expert-mode integrations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,

    /// Direction of the age proof ("over_age" or "under_age").
    #[serde(default)]
    #[zeroize(skip)]
    pub proof_direction: Option<String>,
}

/// Maximum length for individual string fields in QR challenge payloads.
const MAX_PROTOCOL_FIELD_LEN: usize = 512;

impl QrChallengePayload {
    /// Validate per-field string length limits and proof_direction values.
    ///
    /// Must be called after every deserialisation of `QrChallengePayload` to
    /// enforce boundary constraints before the payload is used.
    fn validate_field_lengths(&self) -> FfiResult<()> {
        if self.challenge_id.is_empty() || self.challenge_id.len() > MAX_PROTOCOL_FIELD_LEN {
            return Err(FfiError::InvalidFormat {
                msg: format!(
                    "challenge_id must be 1-{} characters",
                    MAX_PROTOCOL_FIELD_LEN
                ),
            });
        }
        if self.rp_challenge.is_empty() || self.rp_challenge.len() > MAX_PROTOCOL_FIELD_LEN {
            return Err(FfiError::InvalidFormat {
                msg: format!(
                    "rp_challenge must be 1-{} characters",
                    MAX_PROTOCOL_FIELD_LEN
                ),
            });
        }
        if self.submit_secret.is_empty() || self.submit_secret.len() > MAX_PROTOCOL_FIELD_LEN {
            return Err(FfiError::InvalidFormat {
                msg: format!(
                    "submit_secret must be 1-{} characters",
                    MAX_PROTOCOL_FIELD_LEN
                ),
            });
        }
        if self.verify_url.is_empty() || self.verify_url.len() > MAX_PROTOCOL_FIELD_LEN {
            return Err(FfiError::InvalidFormat {
                msg: format!("verify_url must be 1-{} characters", MAX_PROTOCOL_FIELD_LEN),
            });
        }
        match url::Url::parse(&self.verify_url) {
            Ok(parsed) => {
                if parsed.scheme() != "https" {
                    return Err(FfiError::InvalidFormat {
                        msg: format!(
                            "verify_url must use HTTPS scheme, got '{}'",
                            parsed.scheme()
                        ),
                    });
                }
            }
            Err(e) => {
                return Err(FfiError::InvalidFormat {
                    msg: format!("verify_url is not a valid URL: {}", e),
                });
            }
        }
        if let Some(ref cv) = self.code_verifier {
            if cv.len() > MAX_PROTOCOL_FIELD_LEN {
                return Err(FfiError::InvalidFormat {
                    msg: format!(
                        "code_verifier must be at most {} characters",
                        MAX_PROTOCOL_FIELD_LEN
                    ),
                });
            }
        }
        if let Some(ref dir) = self.proof_direction {
            match dir.as_str() {
                "over_age" | "under_age" => {}
                other => {
                    return Err(FfiError::InvalidFormat {
                        msg: format!(
                            "invalid proof_direction '{}', expected 'over_age' or 'under_age'",
                            other
                        ),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Stateless decoder for QR code content strings.
///
/// Accepts raw JSON, deep link URLs (custom scheme and HTTPS), and tagged
/// envelope payloads. Returns a typed [`QrPayload`] or an error describing
/// what went wrong.
pub struct QrCodeHandler;

impl QrCodeHandler {
    /// Decode a raw QR string into a typed payload.
    ///
    /// The method tries the following strategies in order:
    ///
    /// 1. Strip a known deep link prefix and base64url-decode the remainder.
    /// 2. Parse as bare JSON containing a `challenge_id`.
    /// 3. Parse as a tagged [`QrPayload`] envelope.
    ///
    /// If the decoded JSON is a "minimal" challenge (no `rp_challenge`,
    /// `submit_secret`, or `cutoff_days`), an [`FfiError::InvalidFormat`] with
    /// the sentinel message `"MINIMAL_CHALLENGE"` is returned so that the
    /// caller can fetch the full challenge from provii-verifier.
    pub fn decode_payload(qr_content: &str) -> FfiResult<QrPayload> {
        if qr_content.len() > MAX_QR_PAYLOAD_SIZE {
            return Err(FfiError::InvalidFormat {
                msg: format!(
                    "QR payload too large ({} bytes, max {})",
                    qr_content.len(),
                    MAX_QR_PAYLOAD_SIZE
                ),
            });
        }

        let deep_link_encoded = if qr_content.starts_with(CUSTOM_SCHEME_VERIFY_PREFIX) {
            qr_content.strip_prefix(CUSTOM_SCHEME_VERIFY_PREFIX)
        } else if qr_content.starts_with(HTTPS_VERIFY_PREFIX) {
            qr_content.strip_prefix(HTTPS_VERIFY_PREFIX)
        } else {
            None
        };

        if let Some(encoded) = deep_link_encoded {
            let encoded = if encoded.is_empty() {
                return Err(FfiError::InvalidFormat {
                    msg: "Invalid deep link URL format".to_string(),
                });
            } else {
                encoded
            };

            // Decode base64url. Wrap in Zeroizing because the payload
            // contains secret fields (submit_secret, code_verifier).
            let json_bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded).map_err(|e| {
                FfiError::InvalidFormat {
                    msg: format!("Failed to decode base64url: {}", e),
                }
            })?);

            let json_str = Zeroizing::new(String::from_utf8(json_bytes.to_vec()).map_err(|e| {
                FfiError::InvalidFormat {
                    msg: format!("Invalid UTF-8: {}", e),
                }
            })?);

            // Check if it's minimal (only has challenge_id) before trying full parse
            if !json_str.contains("\"rp_challenge\"")
                && !json_str.contains("\"submit_secret\"")
                && !json_str.contains("\"cutoff_days\"")
            {
                return Err(FfiError::InvalidFormat {
                    msg: "MINIMAL_CHALLENGE".to_string(),
                });
            }

            let data: QrChallengePayload =
                serde_json::from_str(&json_str).map_err(|e| FfiError::InvalidFormat {
                    msg: format!("Failed to parse challenge: {}", e),
                })?;

            data.validate_field_lengths()?;

            return Ok(QrPayload::VerificationChallenge { data });
        }

        // Try to parse as direct JSON (for raw challenges).
        if qr_content.trim().starts_with("{") && qr_content.contains("challenge_id") {
            if !qr_content.contains("\"rp_challenge\"")
                && !qr_content.contains("\"submit_secret\"")
                && !qr_content.contains("\"cutoff_days\"")
            {
                return Err(FfiError::InvalidFormat {
                    msg: "MINIMAL_CHALLENGE".to_string(),
                });
            }

            let data: QrChallengePayload =
                serde_json::from_str(qr_content).map_err(|e| FfiError::InvalidFormat {
                    msg: format!("Failed to parse challenge JSON: {}", e),
                })?;

            data.validate_field_lengths()?;

            return Ok(QrPayload::VerificationChallenge { data });
        }

        // Try other formats (pickup tokens, etc.).
        let payload = serde_json::from_str::<QrPayload>(qr_content)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

        if let QrPayload::VerificationChallenge { ref data } = payload {
            data.validate_field_lengths()?;
        }

        Ok(payload)
    }
}

/// Parse a QR code string and return the payload as a JSON string.
///
/// For verification challenges the returned JSON is the raw
/// [`QrChallengePayload`]. For attestations it is a `{"type":"attestation","data":"..."}` object.
///
/// Minimal challenges propagate as an [`FfiError`] with the
/// `"MINIMAL_CHALLENGE"` sentinel so that the wallet layer can fetch the
/// full challenge using its configured environment URL.
#[uniffi::export]
pub fn parse_qr_code(qr_content: String) -> FfiResult<String> {
    match QrCodeHandler::decode_payload(&qr_content) {
        Ok(payload) => match payload {
            QrPayload::VerificationChallenge { data } => Ok(serde_json::to_string(&data)
                .map_err(|e| FfiError::Generic { msg: e.to_string() })?),
            QrPayload::Attestation { data } => Ok(serde_json::json!({
                "type": "attestation",
                "data": data
            })
            .to_string()),
        },
        Err(e) => Err(e),
    }
}

/// Validate a previously parsed QR payload JSON string.
///
/// Returns `true` if the payload looks structurally sound and, for
/// verification challenges, has not yet expired. Returns `false` for
/// unrecognised or expired payloads rather than returning an error.
#[uniffi::export]
pub fn validate_qr_payload(qr_json: String) -> FfiResult<bool> {
    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&qr_json) {
        // Check if it's an attestation.
        if data.get("type") == Some(&serde_json::json!("attestation")) {
            if let Some(attest_data) = data.get("data").and_then(|d| d.as_str()) {
                return Ok(!attest_data.is_empty()
                    && attest_data
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
            }
        }

        // Check if it's a verification challenge.
        if data.get("challenge_id").is_some() {
            if let Some(expires_at) = data.get("expires_at").and_then(|e| e.as_u64()) {
                #[allow(clippy::cast_sign_loss)]
                let now = chrono::Utc::now().timestamp().max(0) as u64;
                return Ok(now <= expires_at);
            }
            return Ok(true);
        }
    }

    Ok(false)
}

/// Returns `true` when the JSON payload represents an attestation QR code.
#[uniffi::export]
pub fn is_attestation_qr(qr_json: String) -> bool {
    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&qr_json) {
        return data.get("type") == Some(&serde_json::json!("attestation"));
    }
    false
}

/// Returns `true` when the JSON payload represents a verification challenge.
///
/// Detection is based on the presence of a `challenge_id` field.
#[uniffi::export]
pub fn is_verification_qr(qr_json: String) -> bool {
    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&qr_json) {
        return data.get("challenge_id").is_some();
    }
    false
}

/// Extract the base64url attestation data from a previously parsed QR JSON.
///
/// Returns an error if the JSON is not an attestation payload or is missing
/// the `data` field.
#[uniffi::export]
pub fn get_attestation_data(qr_json: String) -> FfiResult<String> {
    let data: serde_json::Value = serde_json::from_str(&qr_json)
        .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

    if data.get("type") != Some(&serde_json::json!("attestation")) {
        return Err(FfiError::InvalidFormat {
            msg: "Not an attestation QR".to_string(),
        });
    }

    data.get("data")
        .and_then(|d| d.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| FfiError::InvalidFormat {
            msg: "Missing attestation data".to_string(),
        })
}

/// Validate that a challenge ID is a well-formed UUID.
///
/// Delegates to [`provii_mobile_sdk_core::validate_uuid_format`] and maps the error
/// into [`FfiError::InvalidFormat`] so callers at the FFI boundary get a
/// consistent error type.
pub fn validate_challenge_id_format(id: &str) -> FfiResult<()> {
    provii_mobile_sdk_core::validate_uuid_format(id)
        .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })
}

/// Extract only the `challenge_id` from a previously parsed QR JSON.
///
/// Useful for fetching the full challenge from provii-verifier after receiving
/// a minimal QR payload.
#[uniffi::export]
pub fn parse_challenge_id(qr_json: String) -> FfiResult<String> {
    #[derive(serde::Deserialize)]
    struct MinimalChallenge {
        challenge_id: String,
    }

    let challenge: MinimalChallenge = serde_json::from_str(&qr_json)
        .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

    Ok(challenge.challenge_id)
}

/// Extract a `challenge_id` directly from a raw QR string.
///
/// Handles both deep link URLs (custom scheme and HTTPS) and bare JSON. Only
/// the `challenge_id` is extracted; other fields are ignored.
#[uniffi::export]
pub fn extract_challenge_id_from_qr(qr_content: String) -> FfiResult<String> {
    if qr_content.len() > MAX_QR_PAYLOAD_SIZE {
        return Err(FfiError::InvalidFormat {
            msg: format!(
                "QR payload too large ({} bytes, max {})",
                qr_content.len(),
                MAX_QR_PAYLOAD_SIZE
            ),
        });
    }

    #[derive(Deserialize)]
    struct MinimalChallenge {
        challenge_id: String,
    }

    let deep_link_encoded = if qr_content.starts_with(CUSTOM_SCHEME_VERIFY_PREFIX) {
        qr_content.strip_prefix(CUSTOM_SCHEME_VERIFY_PREFIX)
    } else if qr_content.starts_with(HTTPS_VERIFY_PREFIX) {
        qr_content.strip_prefix(HTTPS_VERIFY_PREFIX)
    } else {
        None
    };

    let json_str = if let Some(encoded) = deep_link_encoded {
        let encoded = if encoded.is_empty() {
            return Err(FfiError::InvalidFormat {
                msg: "Invalid URL".to_string(),
            });
        } else {
            encoded
        };
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;
        String::from_utf8(bytes).map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?
    } else {
        qr_content
    };

    let minimal: MinimalChallenge = serde_json::from_str(&json_str)
        .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

    Ok(minimal.challenge_id)
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

    #[test]
    fn test_parse_qr_code_verification_challenge() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "type":"verification_challenge/v2",
            "challenge_id":"test_challenge",
            "rp_challenge":"test_rp",
            "cutoff_days":19000,
            "verifying_key_id":1,
            "submit_secret":"secret",
            "expires_at":2000000000,
            "verify_url":"https://example.com/verify"
        }"#;

        let result = parse_qr_code(json.to_string());
        assert!(result.is_ok());
        let parsed = result?;
        assert!(parsed.contains("test_challenge"));
        Ok(())
    }

    #[test]
    fn test_validate_qr_payload_verification_not_expired() -> Result<(), Box<dyn std::error::Error>>
    {
        let far_future = chrono::Utc::now().timestamp() as u64 + 86400;
        let json = format!(r#"{{"challenge_id":"test","expires_at":{}}}"#, far_future);

        let result = validate_qr_payload(json);
        assert!(result.is_ok());
        assert!(result?);
        Ok(())
    }

    #[test]
    fn test_validate_qr_payload_verification_expired() -> Result<(), Box<dyn std::error::Error>> {
        let past = 1000000000u64;
        let json = format!(r#"{{"challenge_id":"test","expires_at":{}}}"#, past);

        let result = validate_qr_payload(json);
        assert!(result.is_ok());
        assert!(!result?);
        Ok(())
    }

    #[test]
    fn test_validate_qr_payload_invalid_json() -> Result<(), Box<dyn std::error::Error>> {
        let json = "not valid json";
        let result = validate_qr_payload(json.to_string());

        assert!(result.is_ok());
        assert!(!result?);
        Ok(())
    }

    #[test]
    fn test_is_verification_qr_true() {
        let json = r#"{"challenge_id":"test","cutoff_days":19000}"#;
        assert!(is_verification_qr(json.to_string()));
    }

    #[test]
    fn test_is_verification_qr_false() {
        let json = r#"{"type":"unknown","data":"test"}"#;
        assert!(!is_verification_qr(json.to_string()));
    }

    #[test]
    fn test_parse_challenge_id_success() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"challenge_id":"abc123xyz"}"#;
        let result = parse_challenge_id(json.to_string());

        assert!(result.is_ok());
        assert_eq!(result?, "abc123xyz");
        Ok(())
    }

    #[test]
    fn test_parse_challenge_id_missing() {
        let json = r#"{"other_field":"value"}"#;
        let result = parse_challenge_id(json.to_string());

        assert!(result.is_err());
    }

    #[test]
    fn test_extract_challenge_id_from_qr_plain_json() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"challenge_id":"test_id_123"}"#;
        let result = extract_challenge_id_from_qr(json.to_string());

        assert!(result.is_ok());
        assert_eq!(result?, "test_id_123");
        Ok(())
    }

    #[test]
    fn test_extract_challenge_id_from_qr_url_encoded() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let json = r#"{"challenge_id":"url_encoded_id"}"#;
        let encoded = URL_SAFE_NO_PAD.encode(json.as_bytes());
        let qr_url = format!("provii://verify?d={}", encoded);

        let result = extract_challenge_id_from_qr(qr_url);

        assert!(result.is_ok());
        assert_eq!(result?, "url_encoded_id");
        Ok(())
    }

    #[test]
    fn test_qr_code_handler_decode_verification_challenge() -> Result<(), Box<dyn std::error::Error>>
    {
        let json = r#"{
            "challenge_id":"test",
            "rp_challenge":"challenge_data",
            "cutoff_days":19000,
            "verifying_key_id":1,
            "submit_secret":"secret",
            "expires_at":2000000000,
            "verify_url":"https://test.com/verify"
        }"#;

        let result = QrCodeHandler::decode_payload(json);
        assert!(result.is_ok());

        match result? {
            QrPayload::VerificationChallenge { data } => {
                assert_eq!(data.challenge_id, "test");
                assert_eq!(data.cutoff_days, 19000);
                assert_eq!(data.verifying_key_id, 1);
            }
            _ => panic!("Expected VerificationChallenge"),
        }
        Ok(())
    }

    #[test]
    fn test_qr_code_handler_decode_provii_url() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let json = r#"{
            "challenge_id":"url_test",
            "rp_challenge":"rp_data",
            "cutoff_days":20000,
            "verifying_key_id":2,
            "submit_secret":"sec",
            "expires_at":2100000000,
            "verify_url":"https://verify.test"
        }"#;

        let encoded = URL_SAFE_NO_PAD.encode(json.as_bytes());
        let qr_url = format!("provii://verify?d={}", encoded);

        let result = QrCodeHandler::decode_payload(&qr_url);
        assert!(result.is_ok());

        match result? {
            QrPayload::VerificationChallenge { data } => {
                assert_eq!(data.challenge_id, "url_test");
            }
            _ => panic!("Expected VerificationChallenge"),
        }
        Ok(())
    }

    #[test]
    fn test_qr_code_handler_decode_minimal_challenge() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"challenge_id":"minimal_only"}"#;

        let result = QrCodeHandler::decode_payload(json);
        assert!(result.is_err());

        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::InvalidFormat { msg } => {
                assert_eq!(msg, "MINIMAL_CHALLENGE");
            }
            _ => panic!("Expected InvalidFormat with MINIMAL_CHALLENGE"),
        }
        Ok(())
    }

    #[test]
    fn test_qr_challenge_payload_with_code_verifier() -> Result<(), Box<dyn std::error::Error>> {
        let payload = QrChallengePayload {
            challenge_id: "test".to_string(),
            rp_challenge: "rp".to_string(),
            cutoff_days: 19000,
            verifying_key_id: 1,
            submit_secret: "secret".to_string(),
            expires_at: 2000000000,
            verify_url: "https://test.com".to_string(),
            code_verifier: Some("pkce_verifier".to_string()),
            proof_direction: None,
        };

        let json = serde_json::to_string(&payload)?;
        assert!(json.contains("pkce_verifier"));

        let decoded: QrChallengePayload = serde_json::from_str(&json)?;
        assert_eq!(decoded.code_verifier, Some("pkce_verifier".to_string()));
        Ok(())
    }

    #[test]
    fn test_qr_challenge_payload_without_code_verifier() -> Result<(), Box<dyn std::error::Error>> {
        let payload = QrChallengePayload {
            challenge_id: "test".to_string(),
            rp_challenge: "rp".to_string(),
            cutoff_days: 19000,
            verifying_key_id: 1,
            submit_secret: "secret".to_string(),
            expires_at: 2000000000,
            verify_url: "https://test.com".to_string(),
            code_verifier: None,
            proof_direction: None,
        };

        let json = serde_json::to_string(&payload)?;
        // Should not contain code_verifier when None (skip_serializing_if).
        assert!(!json.contains("code_verifier"));
        Ok(())
    }

    #[test]
    fn test_qr_code_handler_invalid_base64() {
        let qr_url = "provii://verify?d=not_valid_base64!!!";

        let result = QrCodeHandler::decode_payload(qr_url);
        assert!(result.is_err());
    }

    #[test]
    fn test_qr_code_handler_invalid_utf8_in_base64() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
        let encoded = URL_SAFE_NO_PAD.encode(&invalid_utf8);
        let qr_url = format!("provii://verify?d={}", encoded);

        let result = QrCodeHandler::decode_payload(&qr_url);
        assert!(result.is_err());
    }

    #[test]
    fn test_qr_code_handler_invalid_json_structure() {
        let json = r#"{"not":"a","valid":"structure"}"#;

        let result = QrCodeHandler::decode_payload(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_qr_code_handler_size_limit_enforced() -> Result<(), Box<dyn std::error::Error>> {
        let oversized = "x".repeat(MAX_QR_PAYLOAD_SIZE + 1);
        let result = QrCodeHandler::decode_payload(&oversized);
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::InvalidFormat { msg } => {
                assert!(msg.contains("too large"));
            }
            _ => panic!("Expected InvalidFormat error"),
        }
        Ok(())
    }

    #[test]
    fn test_qr_code_handler_ignores_extra_fields() {
        // Extra fields are silently ignored; field-level validation is handled
        // by validate_field_lengths().
        let json = r#"{
            "challenge_id":"test",
            "rp_challenge":"rp",
            "cutoff_days":19000,
            "verifying_key_id":1,
            "submit_secret":"sec",
            "expires_at":2000000000,
            "verify_url":"https://test.com",
            "unknown_field":"ignored"
        }"#;

        let result = QrCodeHandler::decode_payload(json);
        assert!(result.is_ok());
    }

    // --- validate_challenge_id_format() tests ---

    #[test]
    fn test_validate_challenge_id_format_valid_uuid() {
        let result = validate_challenge_id_format("550e8400-e29b-41d4-a716-446655440000");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_challenge_id_format_path_traversal() {
        let result = validate_challenge_id_format("../../etc/passwd/aaaaaaaaaaaa");
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        assert!(matches!(err_val, FfiError::InvalidFormat { .. }));
    }

    #[test]
    fn test_validate_challenge_id_format_query_injection() {
        let result = validate_challenge_id_format("550e8400-e29b-41d4-a716?admin=true");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_challenge_id_format_empty() {
        let result = validate_challenge_id_format("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_challenge_id_format_too_long() {
        let result = validate_challenge_id_format("550e8400-e29b-41d4-a716-4466554400000");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_challenge_id_from_qr_size_limit() {
        let oversized = "x".repeat(MAX_QR_PAYLOAD_SIZE + 1);
        let result = extract_challenge_id_from_qr(oversized);
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::InvalidFormat { msg } => {
                assert!(msg.contains("too large"));
            }
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_verify_url_rejects_http_scheme() {
        let json = r#"{
            "challenge_id":"test",
            "rp_challenge":"rp",
            "cutoff_days":19000,
            "verifying_key_id":1,
            "submit_secret":"sec",
            "expires_at":2000000000,
            "verify_url":"http://test.com/verify"
        }"#;

        let result = QrCodeHandler::decode_payload(json);
        assert!(result.is_err());
        if let Err(FfiError::InvalidFormat { msg }) = result {
            assert!(msg.contains("HTTPS"), "expected HTTPS error, got: {}", msg);
        } else {
            panic!("Expected InvalidFormat error");
        }
    }

    #[test]
    fn test_verify_url_rejects_ftp_scheme() {
        let json = r#"{
            "challenge_id":"test",
            "rp_challenge":"rp",
            "cutoff_days":19000,
            "verifying_key_id":1,
            "submit_secret":"sec",
            "expires_at":2000000000,
            "verify_url":"ftp://test.com/file"
        }"#;

        let result = QrCodeHandler::decode_payload(json);
        assert!(result.is_err());
        if let Err(FfiError::InvalidFormat { msg }) = result {
            assert!(msg.contains("HTTPS"), "expected HTTPS error, got: {}", msg);
        } else {
            panic!("Expected InvalidFormat error");
        }
    }

    #[test]
    fn test_verify_url_rejects_javascript_scheme() {
        let json = r#"{
            "challenge_id":"test",
            "rp_challenge":"rp",
            "cutoff_days":19000,
            "verifying_key_id":1,
            "submit_secret":"sec",
            "expires_at":2000000000,
            "verify_url":"javascript:alert(1)"
        }"#;

        let result = QrCodeHandler::decode_payload(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_url_accepts_https_scheme() {
        let json = r#"{
            "challenge_id":"test",
            "rp_challenge":"rp",
            "cutoff_days":19000,
            "verifying_key_id":1,
            "submit_secret":"sec",
            "expires_at":2000000000,
            "verify_url":"https://verify.example.com/v1/submit"
        }"#;

        let result = QrCodeHandler::decode_payload(json);
        assert!(result.is_ok());
    }

    // --- is_attestation_qr tests ---

    #[test]
    fn test_is_attestation_qr_true() {
        let json = r#"{"type":"attestation","data":"abc123"}"#;
        assert!(is_attestation_qr(json.to_string()));
    }

    #[test]
    fn test_is_attestation_qr_wrong_type() {
        let json = r#"{"type":"not_attestation","data":"abc123"}"#;
        assert!(!is_attestation_qr(json.to_string()));
    }

    #[test]
    fn test_is_attestation_qr_invalid_json() {
        assert!(!is_attestation_qr("garbage".to_string()));
    }

    // --- get_attestation_data tests ---

    #[test]
    fn test_get_attestation_data_valid() {
        let json = r#"{"type":"attestation","data":"abc123_valid"}"#;
        let result = get_attestation_data(json.to_string());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "abc123_valid");
    }

    #[test]
    fn test_get_attestation_data_not_attestation() {
        let json = r#"{"type":"challenge","data":"abc123"}"#;
        let result = get_attestation_data(json.to_string());
        assert!(result.is_err());
        if let Err(FfiError::InvalidFormat { msg }) = result {
            assert!(msg.contains("Not an attestation"));
        }
    }

    #[test]
    fn test_get_attestation_data_missing_data_field() {
        let json = r#"{"type":"attestation"}"#;
        let result = get_attestation_data(json.to_string());
        assert!(result.is_err());
        if let Err(FfiError::InvalidFormat { msg }) = result {
            assert!(msg.contains("Missing attestation data"));
        }
    }

    #[test]
    fn test_get_attestation_data_invalid_json() {
        let result = get_attestation_data("not json".to_string());
        assert!(result.is_err());
    }

    // --- validate_qr_payload attestation path ---

    #[test]
    fn test_validate_qr_payload_valid_attestation() {
        let json = r#"{"type":"attestation","data":"abc123_valid-data"}"#;
        let result = validate_qr_payload(json.to_string());
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_validate_qr_payload_attestation_empty_data() {
        let json = r#"{"type":"attestation","data":""}"#;
        let result = validate_qr_payload(json.to_string());
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_validate_qr_payload_attestation_invalid_chars() {
        let json = r#"{"type":"attestation","data":"abc 123!"}"#;
        let result = validate_qr_payload(json.to_string());
        assert!(result.is_ok());
        // Spaces and ! are not alphanumeric/dash/underscore
        assert!(!result.unwrap());
    }

    #[test]
    fn test_validate_qr_payload_challenge_no_expires() {
        let json = r#"{"challenge_id":"test"}"#;
        let result = validate_qr_payload(json.to_string());
        assert!(result.is_ok());
        // No expires_at, should still return true
        assert!(result.unwrap());
    }

    // --- QrPayload::Debug tests ---

    #[test]
    fn test_qr_payload_debug_redacts_verification_secret() {
        let payload = QrPayload::VerificationChallenge {
            data: QrChallengePayload {
                challenge_id: "debug-test".to_string(),
                rp_challenge: "rp".to_string(),
                cutoff_days: 19000,
                verifying_key_id: 1,
                submit_secret: "SUPER_SECRET_VALUE".to_string(),
                expires_at: 2000000000,
                verify_url: "https://test.com".to_string(),
                code_verifier: Some("CV_SECRET".to_string()),
                proof_direction: None,
            },
        };

        let debug_str = format!("{:?}", payload);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("SUPER_SECRET_VALUE"));
        assert!(debug_str.contains("debug-test"));
    }

    #[test]
    fn test_qr_payload_debug_redacts_attestation_data() {
        let payload = QrPayload::Attestation {
            data: "secret_attestation_bytes".to_string(),
        };

        let debug_str = format!("{:?}", payload);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("secret_attestation_bytes"));
    }

    // --- Field validation edge cases ---

    #[test]
    fn test_field_validation_empty_challenge_id() {
        let payload = QrChallengePayload {
            challenge_id: "".to_string(),
            rp_challenge: "rp".to_string(),
            cutoff_days: 19000,
            verifying_key_id: 1,
            submit_secret: "sec".to_string(),
            expires_at: 2000000000,
            verify_url: "https://test.com".to_string(),
            code_verifier: None,
            proof_direction: None,
        };
        let result = payload.validate_field_lengths();
        assert!(result.is_err());
    }

    #[test]
    fn test_field_validation_empty_rp_challenge() {
        let payload = QrChallengePayload {
            challenge_id: "test".to_string(),
            rp_challenge: "".to_string(),
            cutoff_days: 19000,
            verifying_key_id: 1,
            submit_secret: "sec".to_string(),
            expires_at: 2000000000,
            verify_url: "https://test.com".to_string(),
            code_verifier: None,
            proof_direction: None,
        };
        let result = payload.validate_field_lengths();
        assert!(result.is_err());
    }

    #[test]
    fn test_field_validation_empty_submit_secret() {
        let payload = QrChallengePayload {
            challenge_id: "test".to_string(),
            rp_challenge: "rp".to_string(),
            cutoff_days: 19000,
            verifying_key_id: 1,
            submit_secret: "".to_string(),
            expires_at: 2000000000,
            verify_url: "https://test.com".to_string(),
            code_verifier: None,
            proof_direction: None,
        };
        let result = payload.validate_field_lengths();
        assert!(result.is_err());
    }

    #[test]
    fn test_field_validation_empty_verify_url() {
        let payload = QrChallengePayload {
            challenge_id: "test".to_string(),
            rp_challenge: "rp".to_string(),
            cutoff_days: 19000,
            verifying_key_id: 1,
            submit_secret: "sec".to_string(),
            expires_at: 2000000000,
            verify_url: "".to_string(),
            code_verifier: None,
            proof_direction: None,
        };
        let result = payload.validate_field_lengths();
        assert!(result.is_err());
    }

    #[test]
    fn test_field_validation_invalid_verify_url() {
        let payload = QrChallengePayload {
            challenge_id: "test".to_string(),
            rp_challenge: "rp".to_string(),
            cutoff_days: 19000,
            verifying_key_id: 1,
            submit_secret: "sec".to_string(),
            expires_at: 2000000000,
            verify_url: "not a url at all".to_string(),
            code_verifier: None,
            proof_direction: None,
        };
        let result = payload.validate_field_lengths();
        assert!(result.is_err());
    }

    #[test]
    fn test_field_validation_invalid_proof_direction() {
        let payload = QrChallengePayload {
            challenge_id: "test".to_string(),
            rp_challenge: "rp".to_string(),
            cutoff_days: 19000,
            verifying_key_id: 1,
            submit_secret: "sec".to_string(),
            expires_at: 2000000000,
            verify_url: "https://test.com".to_string(),
            code_verifier: None,
            proof_direction: Some("sideways".to_string()),
        };
        let result = payload.validate_field_lengths();
        assert!(result.is_err());
        if let Err(FfiError::InvalidFormat { msg }) = result {
            assert!(msg.contains("sideways"));
        }
    }

    #[test]
    fn test_field_validation_valid_proof_directions() {
        for dir in &["over_age", "under_age"] {
            let payload = QrChallengePayload {
                challenge_id: "test".to_string(),
                rp_challenge: "rp".to_string(),
                cutoff_days: 19000,
                verifying_key_id: 1,
                submit_secret: "sec".to_string(),
                expires_at: 2000000000,
                verify_url: "https://test.com".to_string(),
                code_verifier: None,
                proof_direction: Some(dir.to_string()),
            };
            assert!(
                payload.validate_field_lengths().is_ok(),
                "direction '{}' should be valid",
                dir
            );
        }
    }

    #[test]
    fn test_field_validation_oversized_code_verifier() {
        let payload = QrChallengePayload {
            challenge_id: "test".to_string(),
            rp_challenge: "rp".to_string(),
            cutoff_days: 19000,
            verifying_key_id: 1,
            submit_secret: "sec".to_string(),
            expires_at: 2000000000,
            verify_url: "https://test.com".to_string(),
            code_verifier: Some("x".repeat(MAX_PROTOCOL_FIELD_LEN + 1)),
            proof_direction: None,
        };
        let result = payload.validate_field_lengths();
        assert!(result.is_err());
    }

    // --- HTTPS deep link prefix ---

    #[test]
    fn test_qr_code_handler_decode_https_deep_link() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let json = r#"{
            "challenge_id":"https_test",
            "rp_challenge":"rp_data",
            "cutoff_days":20000,
            "verifying_key_id":2,
            "submit_secret":"sec",
            "expires_at":2100000000,
            "verify_url":"https://verify.test"
        }"#;

        let encoded = URL_SAFE_NO_PAD.encode(json.as_bytes());
        let qr_url = format!("https://provii.app/verify?d={}", encoded);

        let result = QrCodeHandler::decode_payload(&qr_url);
        assert!(result.is_ok());

        match result? {
            QrPayload::VerificationChallenge { data } => {
                assert_eq!(data.challenge_id, "https_test");
            }
            _ => panic!("Expected VerificationChallenge"),
        }
        Ok(())
    }

    #[test]
    fn test_extract_challenge_id_from_https_deep_link() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let json = r#"{"challenge_id":"https_extracted_id"}"#;
        let encoded = URL_SAFE_NO_PAD.encode(json.as_bytes());
        let qr_url = format!("https://provii.app/verify?d={}", encoded);

        let result = extract_challenge_id_from_qr(qr_url);
        assert!(result.is_ok());
        assert_eq!(result?, "https_extracted_id");
        Ok(())
    }

    #[test]
    fn test_extract_challenge_id_empty_deep_link() {
        let result = extract_challenge_id_from_qr("provii://verify?d=".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_challenge_id_empty_https_deep_link() {
        let result = extract_challenge_id_from_qr("https://provii.app/verify?d=".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_minimal_challenge_from_deep_link() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let json = r#"{"challenge_id":"minimal_deep"}"#;
        let encoded = URL_SAFE_NO_PAD.encode(json.as_bytes());
        let qr_url = format!("provii://verify?d={}", encoded);

        let result = QrCodeHandler::decode_payload(&qr_url);
        assert!(result.is_err());
        if let Err(FfiError::InvalidFormat { msg }) = result {
            assert_eq!(msg, "MINIMAL_CHALLENGE");
        }
    }

    // --- parse_qr_code attestation path ---

    #[test]
    fn test_parse_qr_code_attestation() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"type":"attestation/v1","data":"abc123_attestation"}"#;
        let result = parse_qr_code(json.to_string());
        assert!(result.is_ok());
        let parsed = result?;
        assert!(parsed.contains("attestation"));
        assert!(parsed.contains("abc123_attestation"));
        Ok(())
    }

    #[test]
    fn test_is_verification_qr_invalid_json() {
        assert!(!is_verification_qr("not json".to_string()));
    }
}
