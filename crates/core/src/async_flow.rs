// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! End-to-end async flows for proof generation and submission.
//!
//! This module wires together proof building, network transport, and deep link
//! parsing into single-call convenience functions that mobile hosts can invoke
//! through UniFFI. All functions are gated behind the `async` feature and
//! require a Tokio runtime.
//!
//! ## Security considerations
//!
//! Intermediate JSON payloads that contain `submit_secret` or `code_verifier`
//! are wrapped in [`zeroize::Zeroizing`] so the plaintext is scrubbed from
//! memory when it falls out of scope.

#[cfg(feature = "async")]
use crate::{
    network::ApiClient,
    prover::build_verify_request,
    types::{CredentialV2, QrChallengePayload, SubmitProofRequest, VerifyResponse},
    Result, WalletError,
};
#[cfg(feature = "async")]
use zeroize::Zeroizing;

/// Build a zero knowledge proof from the given credential and submit it to the
/// verifier API in a single operation.
///
/// This is the primary happy-path entry point used by mobile wallets after a QR
/// code or deep link has been scanned. The function constructs the proof locally,
/// serialises the request (wrapping secrets in [`Zeroizing`]), and POSTs it to
/// `{api_base_url}/v1/verify`.
///
/// # Errors
///
/// Returns [`WalletError`] if proof generation fails, if the network request
/// cannot be completed, or if the verifier responds with a non-parseable body.
#[cfg(feature = "async")]
pub async fn generate_and_submit_proof(
    credential: &CredentialV2,
    qr_payload: &QrChallengePayload,
    api_base_url: &str,
) -> Result<VerifyResponse> {
    let request = build_verify_request(credential, qr_payload)?;

    let client = ApiClient::new(api_base_url);
    client.submit_proof(&request).await
}

/// Poll the verifier API until the verification reaches a terminal state or the
/// retry budget is exhausted.
///
/// The caller specifies `max_attempts` and `delay_ms` to control back-off. Each
/// iteration GETs `/v1/status/{challenge_id}` and returns as soon as the
/// response state is neither `"pending"` nor `"processing"`.
///
/// # Errors
///
/// Returns [`WalletError::RequestTimeout`] when all attempts are consumed
/// without reaching a terminal state. Network and deserialisation errors from
/// the underlying [`ApiClient`] are propagated immediately.
#[cfg(feature = "async")]
pub async fn poll_verification_status(
    challenge_id: &str,
    api_base_url: &str,
    max_attempts: usize,
    delay_ms: u64,
) -> Result<VerifyResponse> {
    crate::utils::validate_uuid_format(challenge_id)?;
    let client = ApiClient::new(api_base_url);
    let path = format!("/v1/status/{}", challenge_id);

    for attempt in 0..max_attempts {
        if attempt > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        }

        let response: VerifyResponse = client.get(&path).await?;

        if response.state != "pending" && response.state != "processing" {
            return Ok(response);
        }
    }

    Err(WalletError::RequestTimeout)
}

/// Parse an incoming deep link URL, extract the embedded QR challenge payload,
/// generate a proof, and submit it to the verifier API.
///
/// Deep links arrive in the form
/// `https://proviiwallet.app/verify?d=...&qr=<base64url_or_json>`. The `qr`
/// parameter may be raw JSON or base64url-encoded JSON. In both cases the
/// decoded string is wrapped in [`Zeroizing`] because it contains
/// `submit_secret` and `code_verifier`.
///
/// # Errors
///
/// Returns [`WalletError::InvalidInput`] if the URL cannot be parsed, if the
/// `qr` parameter is missing, or if field-length validation on the decoded
/// [`QrChallengePayload`] fails. Proof and network errors are propagated from
/// [`generate_and_submit_proof`].
#[cfg(feature = "async")]
pub async fn handle_deep_link(
    deep_link: &str,
    credential: &CredentialV2,
    api_base_url: &str,
) -> Result<VerifyResponse> {
    use crate::utils::parse_deep_link;

    let params = parse_deep_link(deep_link)?;

    let qr_json = params
        .get("qr")
        .ok_or_else(|| WalletError::InvalidInput("Missing QR data in deep link".to_string()))?;

    // Wrap in Zeroizing because the intermediate string contains submit_secret
    // and code_verifier.
    let qr_data = if qr_json.contains('{') {
        Zeroizing::new(qr_json.clone())
    } else {
        let decoded_bytes = Zeroizing::new(
            crate::utils::decode_base64url(qr_json)
                .map_err(|e| WalletError::Base64Error(e.to_string()))?,
        );
        Zeroizing::new(
            String::from_utf8(decoded_bytes.to_vec())
                .map_err(|e| WalletError::InvalidInput(format!("Invalid UTF-8: {}", e)))?,
        )
    };

    let qr_payload: QrChallengePayload = serde_json::from_str(&qr_data)?;
    qr_payload
        .validate_field_lengths()
        .map_err(|e| WalletError::InvalidInput(e))?;

    generate_and_submit_proof(credential, &qr_payload, api_base_url).await
}

#[cfg(test)]
#[cfg(all(feature = "async", feature = "http"))]
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

    fn dummy_credential() -> CredentialV2 {
        CredentialV2 {
            v: 2,
            kid: "provii:2026-05".to_string(),
            issuer_vk: [0u8; 32],
            sig_rj: [0u8; 64],
            c_bytes: [0u8; 32],
            iat: 1_700_000_000,
            exp: 1_900_000_000,
            schema: "provii.age/0".to_string(),
            dob_days: Some(10_000),
            r_bits: Some(vec![false; 128]),
        }
    }

    // ================================================================
    // poll_verification_status tests
    // ================================================================

    #[tokio::test]
    async fn poll_verification_status_rejects_invalid_uuid() {
        let result =
            poll_verification_status("not-a-valid-uuid", "https://example.com", 1, 100).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, WalletError::InvalidInput(_)),
            "expected InvalidInput for bad UUID, got: {:?}",
            err,
        );
    }

    #[tokio::test]
    async fn poll_verification_status_rejects_empty_challenge_id() {
        let result = poll_verification_status("", "https://example.com", 1, 100).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, WalletError::InvalidInput(_)),
            "expected InvalidInput for empty ID, got: {:?}",
            err,
        );
    }

    #[tokio::test]
    async fn poll_verification_status_rejects_path_traversal() {
        let result = poll_verification_status(
            "../../../etc/passwd/aaaaaaaaaaa",
            "https://example.com",
            1,
            100,
        )
        .await;
        assert!(result.is_err());
    }

    // ================================================================
    // handle_deep_link tests
    // ================================================================

    #[tokio::test]
    async fn handle_deep_link_rejects_invalid_url() {
        let result = handle_deep_link(
            "not a url at all",
            &dummy_credential(),
            "https://api.example.com",
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, WalletError::InvalidInput(_)),
            "expected InvalidInput for bad URL, got: {:?}",
            err,
        );
    }

    #[tokio::test]
    async fn handle_deep_link_rejects_missing_qr_param() {
        let result = handle_deep_link(
            "https://proviiwallet.app/verify?d=something",
            &dummy_credential(),
            "https://api.example.com",
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, WalletError::InvalidInput(_)),
            "expected InvalidInput for missing QR param, got: {:?}",
            err,
        );
    }

    #[tokio::test]
    async fn handle_deep_link_rejects_invalid_base64_qr() {
        let result = handle_deep_link(
            "https://proviiwallet.app/verify?qr=!!!invalid!!!",
            &dummy_credential(),
            "https://api.example.com",
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_deep_link_rejects_invalid_utf8_base64() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let bad_utf8 = URL_SAFE_NO_PAD.encode([0xFF, 0xFE, 0xFD, 0xFC]);
        let url = format!("https://proviiwallet.app/verify?qr={}", bad_utf8);

        let result = handle_deep_link(&url, &dummy_credential(), "https://api.example.com").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, WalletError::InvalidInput(_)),
            "expected InvalidInput for bad UTF-8, got: {:?}",
            err,
        );
    }

    #[tokio::test]
    async fn handle_deep_link_rejects_invalid_qr_json() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let not_json = URL_SAFE_NO_PAD.encode(b"this is not json");
        let url = format!("https://proviiwallet.app/verify?qr={}", not_json);

        let result = handle_deep_link(&url, &dummy_credential(), "https://api.example.com").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_deep_link_rejects_oversized_fields() {
        let oversized_id = "X".repeat(600);
        let qr_json = serde_json::json!({
            "challenge_id": oversized_id,
            "rp_challenge": "abc123def456",
            "cutoff_days": 19000,
            "verifying_key_id": 1243800079u32,
            "submit_secret": "submit_secret_base64url_32bytes",
            "expires_at": 1800000000u64,
            "verify_url": "https://verify.example.com/submit"
        })
        .to_string();
        let url = format!("https://proviiwallet.app/verify?qr={}", qr_json);

        let result = handle_deep_link(&url, &dummy_credential(), "https://api.example.com").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, WalletError::InvalidInput(_)),
            "expected InvalidInput for oversized fields, got: {:?}",
            err,
        );
    }

    // ================================================================
    // generate_and_submit_proof tests
    // ================================================================

    #[tokio::test]
    async fn generate_and_submit_proof_fails_without_prover() {
        let cred = dummy_credential();
        let qr = QrChallengePayload {
            challenge_id: "test-challenge-id".to_string(),
            rp_challenge: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xABu8; 32]),
            cutoff_days: 19_000,
            verifying_key_id: 0,
            submit_secret: "submit_secret_value".to_string(),
            expires_at: u64::MAX,
            verify_url: "https://verify.example.com/submit".to_string(),
            code_verifier: None,
            proof_direction: None,
        };

        let result = generate_and_submit_proof(&cred, &qr, "https://api.example.com").await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("prover"),
            "expected prover error, got: {}",
            err_msg,
        );
    }
}
