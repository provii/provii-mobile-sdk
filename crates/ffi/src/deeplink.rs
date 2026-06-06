// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Deep link parsing and construction for the Provii Wallet.
//!
//! The wallet receives two categories of deep link:
//!
//! * **Verify** (`/verify?d=...`) carries a base64url-encoded JSON challenge
//!   payload from a verifier. Parsing produces a
//!   [`DeeplinkAction::ScanChallenge`].
//! * **Attest** (`/attest?d=...`) carries base64url-encoded attestation data
//!   from an issuer officer. Parsing produces a [`DeeplinkAction::Attest`].
//!
//! Both the custom scheme (`proviiwallet://`) and the HTTPS universal link
//! scheme (`https://proviiwallet.app/`) are supported. Actions are matched
//! case-insensitively.
//!
//! # Size and field limits
//!
//! A hard 4 KiB cap on the raw URL ([`MAX_DEEPLINK_SIZE`]) is enforced
//! before any parsing to prevent denial-of-service via oversised inputs.
//! Verify payloads additionally enforce per-field string length limits
//! ([`MAX_FIELD_LEN`]) and reject unknown JSON keys via
//! `#[serde(deny_unknown_fields)]`.
//!
//! # Security
//!
//! Decoded verify payloads may contain secret fields (`submit_secret`,
//! `code_verifier`). The raw decoded bytes are wrapped in [`Zeroizing`] so
//! they are scrubbed from memory once parsing completes.

use crate::types::DeeplinkAction;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;

/// The domain used for HTTPS universal links.
///
/// Only URLs whose host matches this value are accepted when the scheme is
/// `https`. This prevents open-redirect attacks where a malicious site
/// crafts a link with a different host.
const UNIVERSAL_LINK_HOST: &str = "proviiwallet.app";

/// Hard upper bound on the raw deep link URL size in bytes.
///
/// Checked before URL parsing to guard against denial of service from
/// extremely long input strings.
const MAX_DEEPLINK_SIZE: usize = 4096;

/// Maximum byte length for any single string field inside a verify payload.
///
/// Applied to `challenge_id`, `rp_challenge`, `submit_secret`,
/// `code_verifier`, `verify_url`, and `proof_direction`.
const MAX_FIELD_LEN: usize = 512;

/// Typed verify deep link payload.
///
/// Uses `#[serde(deny_unknown_fields)]` so that unexpected keys cause a
/// parse error rather than being silently discarded. Optional fields use
/// `#[serde(default)]` so they may be omitted entirely.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // Fields populated by serde deserialization for validation
struct VerifyPayload {
    /// Unique identifier for this verification challenge.
    challenge_id: String,
    /// Relying party challenge nonce.
    rp_challenge: String,
    /// Age cutoff expressed as days since Unix epoch.
    cutoff_days: i32,
    /// Identifier of the verifying key to use for proof verification.
    verifying_key_id: u32,
    /// Secret token the wallet must include when submitting the proof.
    submit_secret: String,
    /// PKCE code verifier for expert-mode integrations.
    #[serde(default)]
    code_verifier: Option<String>,
    /// Unix timestamp (seconds) after which the challenge is invalid.
    #[serde(default)]
    expires_at: Option<u64>,
    /// URL to which the proof should be submitted.
    #[serde(default)]
    verify_url: Option<String>,
    /// Direction hint for the proof (reserved for future use).
    #[serde(default)]
    proof_direction: Option<String>,
}

/// Enforce [`MAX_FIELD_LEN`] on every string field in a parsed
/// [`VerifyPayload`].
///
/// Returns an error naming the first field that exceeds the limit. Called
/// after deserialisation so that the structural validity of the JSON has
/// already been confirmed.
fn validate_verify_field_lengths(payload: &VerifyPayload) -> Result<()> {
    if payload.challenge_id.len() > MAX_FIELD_LEN {
        return Err(anyhow!(
            "challenge_id too long (max {} bytes)",
            MAX_FIELD_LEN
        ));
    }
    if payload.rp_challenge.len() > MAX_FIELD_LEN {
        return Err(anyhow!(
            "rp_challenge too long (max {} bytes)",
            MAX_FIELD_LEN
        ));
    }
    if payload.submit_secret.len() > MAX_FIELD_LEN {
        return Err(anyhow!(
            "submit_secret too long (max {} bytes)",
            MAX_FIELD_LEN
        ));
    }
    if let Some(ref cv) = payload.code_verifier {
        if cv.len() > MAX_FIELD_LEN {
            return Err(anyhow!(
                "code_verifier too long (max {} bytes)",
                MAX_FIELD_LEN
            ));
        }
    }
    if let Some(ref verify_url) = payload.verify_url {
        if verify_url.len() > MAX_FIELD_LEN {
            return Err(anyhow!("verify_url too long (max {} bytes)", MAX_FIELD_LEN));
        }
        match url::Url::parse(verify_url) {
            Ok(parsed) => {
                if parsed.scheme() != "https" {
                    return Err(anyhow!(
                        "verify_url must use HTTPS scheme, got '{}'",
                        parsed.scheme()
                    ));
                }
            }
            Err(e) => {
                return Err(anyhow!("verify_url is not a valid URL: {}", e));
            }
        }
    }
    if let Some(ref dir) = payload.proof_direction {
        if dir.len() > MAX_FIELD_LEN {
            return Err(anyhow!(
                "proof_direction too long (max {} bytes)",
                MAX_FIELD_LEN
            ));
        }
    }
    Ok(())
}

/// Parse a deep link URL into a [`DeeplinkAction`].
///
/// Accepted URL formats:
///
/// | Scheme | Pattern | Action |
/// |--------|---------|--------|
/// | `proviiwallet://` | `proviiwallet://verify?d=<b64url>` | [`DeeplinkAction::ScanChallenge`] |
/// | `proviiwallet://` | `proviiwallet://attest?d=<b64url>` | [`DeeplinkAction::Attest`] |
/// | `https://` | `https://proviiwallet.app/verify?d=<b64url>` | [`DeeplinkAction::ScanChallenge`] |
/// | `https://` | `https://proviiwallet.app/attest?d=<b64url>` | [`DeeplinkAction::Attest`] |
///
/// The URL is rejected before parsing if it exceeds [`MAX_DEEPLINK_SIZE`]
/// bytes. HTTPS links must target the [`UNIVERSAL_LINK_HOST`] domain.
/// Verify payloads are deserialised into a typed struct with
/// `deny_unknown_fields` and per-field length limits.
///
/// # Errors
///
/// Returns an error if the scheme is unrecognised, the host is wrong, the
/// `d` query parameter is missing or invalid, base64url decoding fails,
/// UTF-8 conversion fails, or field-level validation fails.
pub fn parse(url: String) -> Result<DeeplinkAction> {
    // IV-701: Check size BEFORE parsing to prevent DoS via massive URL strings
    if url.len() > MAX_DEEPLINK_SIZE {
        return Err(anyhow!(
            "deeplink too large (max {} bytes)",
            MAX_DEEPLINK_SIZE
        ));
    }

    let u = Url::parse(&url).map_err(|e| anyhow!("bad url: {e}"))?;

    // Determine the action from either scheme
    let action = match u.scheme() {
        "proviiwallet" => {
            // Custom scheme: action is the host (e.g. proviiwallet://verify)
            u.host_str().unwrap_or_default().to_lowercase()
        }
        "https" => {
            // HTTPS universal link: action is the first path segment
            let host = u.host_str().unwrap_or_default();
            if host != UNIVERSAL_LINK_HOST {
                return Err(anyhow!(
                    "invalid host for HTTPS deep link - expected {}",
                    UNIVERSAL_LINK_HOST
                ));
            }
            u.path()
                .trim_start_matches('/')
                .split('/')
                .next()
                .unwrap_or_default()
                .to_lowercase()
        }
        other => {
            return Err(anyhow!(
                "invalid scheme '{}' - expected proviiwallet:// or https://",
                other
            ));
        }
    };

    let query = u.query_pairs().collect::<std::collections::HashMap<_, _>>();

    match action.as_str() {
        "verify" => {
            let d = query
                .get("d")
                .ok_or_else(|| anyhow!("missing d parameter"))?;

            // Decode base64url. Wrap in Zeroizing because the payload
            // may contain secret fields (submit_secret, code_verifier).
            let raw = Zeroizing::new(
                URL_SAFE_NO_PAD
                    .decode(d.as_ref()) // Use as_ref() to get &str from Cow<str>
                    .map_err(|e| anyhow!("bad b64url encoding: {}", e))?,
            );

            // Convert to UTF-8 string
            let payload_json = std::str::from_utf8(&raw)
                .map_err(|e| anyhow!("invalid UTF-8 in payload: {}", e))?
                .to_string();

            // Validate it's proper JSON and not empty
            if payload_json.trim().is_empty() {
                return Err(anyhow!("empty payload"));
            }

            // IV-702: Parse into typed struct with deny_unknown_fields
            // instead of serde_json::Value
            let parsed: VerifyPayload = serde_json::from_str(&payload_json)
                .map_err(|e| anyhow!("invalid verify payload: {}", e))?;

            // IV-703: Enforce per-field string length limits
            validate_verify_field_lengths(&parsed)?;

            Ok(DeeplinkAction::ScanChallenge { payload_json })
        }

        "attest" => {
            let d = query
                .get("d")
                .ok_or_else(|| anyhow!("missing d parameter"))?;

            // Validate base64url format
            if d.is_empty() {
                return Err(anyhow!("attestation data cannot be empty"));
            }

            if !d
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(anyhow!(
                    "invalid attestation data format (must be base64url)"
                ));
            }

            Ok(DeeplinkAction::Attest {
                attestation_data: d.to_string(),
            })
        }

        _ => Err(anyhow!("unsupported deeplink action: {}", action)),
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

    #[test]
    fn test_parse_verify_deeplink_custom_scheme() -> Result<(), Box<dyn std::error::Error>> {
        let payload = r#"{"challenge_id":"test123","rp_challenge":"abc","cutoff_days":4745,"verifying_key_id":12,"submit_secret":"xyz"}"#;
        let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());

        let url = format!("proviiwallet://verify?d={}", encoded);
        let result = parse(url)?;

        match result {
            DeeplinkAction::ScanChallenge { payload_json } => {
                assert_eq!(payload_json, payload);
            }
            _ => panic!("Expected ScanChallenge action"),
        }
        Ok(())
    }

    #[test]
    fn test_parse_verify_deeplink_https() -> Result<(), Box<dyn std::error::Error>> {
        let payload = r#"{"challenge_id":"test123","rp_challenge":"abc","cutoff_days":4745,"verifying_key_id":12,"submit_secret":"xyz"}"#;
        let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());

        let url = format!("https://proviiwallet.app/verify?d={}", encoded);
        let result = parse(url)?;

        match result {
            DeeplinkAction::ScanChallenge { payload_json } => {
                assert_eq!(payload_json, payload);
            }
            _ => panic!("Expected ScanChallenge action"),
        }
        Ok(())
    }

    #[test]
    fn test_parse_attest_deeplink_https() -> Result<(), Box<dyn std::error::Error>> {
        let url = "https://proviiwallet.app/attest?d=dGVzdERhdGE".to_string();
        let result = parse(url)?;

        match result {
            DeeplinkAction::Attest { attestation_data } => {
                assert_eq!(attestation_data, "dGVzdERhdGE");
            }
            _ => panic!("Expected Attest action"),
        }
        Ok(())
    }

    #[test]
    fn test_parse_https_wrong_host() {
        let payload = r#"{"challenge_id":"test123","rp_challenge":"abc","cutoff_days":4745,"verifying_key_id":12,"submit_secret":"xyz"}"#;
        let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let url = format!("https://evil.com/verify?d={}", encoded);
        assert!(parse(url).is_err());
    }

    #[test]
    fn test_invalid_schemes() {
        let invalid_urls = [
            "http://verify?d=test",
            "provii://verify?d=test",
            "wallet://verify?d=test",
        ];

        for url in &invalid_urls {
            assert!(parse(url.to_string()).is_err());
        }
    }

    // ============================================================================
    // COMPREHENSIVE DEEPLINK TESTS
    // ============================================================================

    #[test]
    fn test_parse_verify_empty_payload() {
        let encoded = URL_SAFE_NO_PAD.encode("   ".as_bytes());
        let url = format!("proviiwallet://verify?d={}", encoded);

        assert!(parse(url).is_err());
    }

    #[test]
    fn test_parse_verify_non_object_json() {
        let array_json = r#"["test"]"#;
        let encoded = URL_SAFE_NO_PAD.encode(array_json.as_bytes());
        let url = format!("proviiwallet://verify?d={}", encoded);

        let result = parse(url);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_verify_missing_required_fields() {
        let fields_to_test = [
            (
                "challenge_id",
                r#"{"rp_challenge":"abc","cutoff_days":4745,"verifying_key_id":12,"submit_secret":"xyz"}"#,
            ),
            (
                "rp_challenge",
                r#"{"challenge_id":"test","cutoff_days":4745,"verifying_key_id":12,"submit_secret":"xyz"}"#,
            ),
            (
                "cutoff_days",
                r#"{"challenge_id":"test","rp_challenge":"abc","verifying_key_id":12,"submit_secret":"xyz"}"#,
            ),
            (
                "verifying_key_id",
                r#"{"challenge_id":"test","rp_challenge":"abc","cutoff_days":4745,"submit_secret":"xyz"}"#,
            ),
            (
                "submit_secret",
                r#"{"challenge_id":"test","rp_challenge":"abc","cutoff_days":4745,"verifying_key_id":12}"#,
            ),
        ];

        for (field_name, payload) in &fields_to_test {
            let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());
            let url = format!("proviiwallet://verify?d={}", encoded);

            let result = parse(url);
            assert!(result.is_err(), "Should fail when missing {}", field_name);
        }
    }

    #[test]
    fn test_parse_verify_invalid_base64() {
        let url = "proviiwallet://verify?d=!!!invalid!!!";
        assert!(parse(url.to_string()).is_err());
    }

    #[test]
    fn test_parse_verify_non_utf8() {
        // Invalid UTF-8 sequence
        let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
        let encoded = URL_SAFE_NO_PAD.encode(&invalid_utf8);
        let url = format!("proviiwallet://verify?d={}", encoded);

        assert!(parse(url).is_err());
    }

    #[test]
    fn test_parse_verify_missing_d_parameter() {
        let url = "proviiwallet://verify?other=param";
        assert!(parse(url.to_string()).is_err());
    }

    #[test]
    fn test_parse_verify_extra_fields_rejected() {
        // IV-702: deny_unknown_fields means extra fields are now rejected
        let payload = r#"{"challenge_id":"test","rp_challenge":"abc","cutoff_days":4745,"verifying_key_id":12,"submit_secret":"xyz","extra":"field"}"#;
        let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let url = format!("proviiwallet://verify?d={}", encoded);

        let result = parse(url);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_unsupported_action() {
        let url = "proviiwallet://unknown?param=value";
        assert!(parse(url.to_string()).is_err());
    }

    #[test]
    fn test_parse_url_size_limit() -> Result<(), Box<dyn std::error::Error>> {
        // IV-701: Size check happens before URL parse
        let large_payload = "x".repeat(5000);
        let json = format!(
            r#"{{"challenge_id":"{}","rp_challenge":"abc","cutoff_days":4745,"verifying_key_id":12,"submit_secret":"xyz"}}"#,
            large_payload
        );
        let encoded = URL_SAFE_NO_PAD.encode(json.as_bytes());
        let url = format!("proviiwallet://verify?d={}", encoded);

        let Err(err) = parse(url) else {
            panic!("expected error")
        };
        assert!(err.to_string().contains("too large"));
        Ok(())
    }

    #[test]
    fn test_parse_empty_url() {
        assert!(parse("".to_string()).is_err());
    }

    #[test]
    fn test_parse_malformed_url() {
        let urls = ["not a url", "proviiwallet", "proviiwallet://", "://verify"];

        for url in &urls {
            assert!(parse(url.to_string()).is_err());
        }
    }

    #[test]
    fn test_parse_verify_field_length_limit() -> Result<(), Box<dyn std::error::Error>> {
        // IV-703: Per-field string length limits
        let long_id = "x".repeat(600);
        let payload = format!(
            r#"{{"challenge_id":"{}","rp_challenge":"abc","cutoff_days":4745,"verifying_key_id":12,"submit_secret":"xyz"}}"#,
            long_id
        );
        let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let url = format!("proviiwallet://verify?d={}", encoded);

        let Err(err) = parse(url) else {
            panic!("expected error")
        };
        assert!(err.to_string().contains("too long"));
        Ok(())
    }

    #[test]
    fn test_parse_case_insensitive_action() {
        // Action (host) should be case-insensitive
        let payload = r#"{"challenge_id":"test","rp_challenge":"abc","cutoff_days":4745,"verifying_key_id":12,"submit_secret":"xyz"}"#;
        let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());

        let urls = [
            format!("proviiwallet://verify?d={}", encoded),
            format!("proviiwallet://VERIFY?d={}", encoded),
            format!("proviiwallet://Verify?d={}", encoded),
        ];

        for url in &urls {
            let result = parse(url.clone());
            assert!(result.is_ok(), "Should parse: {}", url);
        }
    }

    #[test]
    fn test_parse_https_case_insensitive_action() {
        let payload = r#"{"challenge_id":"test","rp_challenge":"abc","cutoff_days":4745,"verifying_key_id":12,"submit_secret":"xyz"}"#;
        let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());

        // Path is case-sensitive in URLs but we lowercase it
        let url = format!("https://proviiwallet.app/Verify?d={}", encoded);
        let result = parse(url);
        assert!(result.is_ok());
    }

    #[test]
    fn test_both_schemes_produce_same_result() -> Result<(), Box<dyn std::error::Error>> {
        let payload = r#"{"challenge_id":"test","rp_challenge":"abc","cutoff_days":4745,"verifying_key_id":12,"submit_secret":"xyz"}"#;
        let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());

        let custom = parse(format!("proviiwallet://verify?d={}", encoded))?;
        let https = parse(format!("https://proviiwallet.app/verify?d={}", encoded))?;

        match (&custom, &https) {
            (
                DeeplinkAction::ScanChallenge {
                    payload_json: json1,
                },
                DeeplinkAction::ScanChallenge {
                    payload_json: json2,
                },
            ) => {
                assert_eq!(json1, json2);
            }
            _ => panic!("Both should produce ScanChallenge"),
        }
        Ok(())
    }

    #[test]
    fn test_verify_url_rejects_http_scheme() {
        let payload = r#"{"challenge_id":"test","rp_challenge":"abc","cutoff_days":4745,"verifying_key_id":12,"submit_secret":"xyz","verify_url":"http://evil.com/verify"}"#;
        let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let url = format!("proviiwallet://verify?d={}", encoded);

        let result = parse(url);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("HTTPS"),
            "expected HTTPS error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_verify_url_rejects_ftp_scheme() {
        let payload = r#"{"challenge_id":"test","rp_challenge":"abc","cutoff_days":4745,"verifying_key_id":12,"submit_secret":"xyz","verify_url":"ftp://files.com/data"}"#;
        let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let url = format!("proviiwallet://verify?d={}", encoded);

        let result = parse(url);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("HTTPS"),
            "expected HTTPS error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_verify_url_rejects_javascript_scheme() {
        let payload = r#"{"challenge_id":"test","rp_challenge":"abc","cutoff_days":4745,"verifying_key_id":12,"submit_secret":"xyz","verify_url":"javascript:alert(1)"}"#;
        let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let url = format!("proviiwallet://verify?d={}", encoded);

        let result = parse(url);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_url_accepts_https_scheme() {
        let payload = r#"{"challenge_id":"test","rp_challenge":"abc","cutoff_days":4745,"verifying_key_id":12,"submit_secret":"xyz","verify_url":"https://verify.example.com/submit"}"#;
        let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let url = format!("proviiwallet://verify?d={}", encoded);

        let result = parse(url);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_url_none_passes_validation() {
        // When verify_url is absent, the HTTPS check should not trigger.
        let payload = r#"{"challenge_id":"test","rp_challenge":"abc","cutoff_days":4745,"verifying_key_id":12,"submit_secret":"xyz"}"#;
        let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let url = format!("proviiwallet://verify?d={}", encoded);

        let result = parse(url);
        assert!(result.is_ok());
    }
}
