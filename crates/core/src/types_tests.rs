// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

// Test CredentialV2 serialization
#[test]
fn test_credential_v2_serialization() -> Result<(), Box<dyn std::error::Error>> {
    let cred = CredentialV2 {
        v: 2,
        kid: "test_issuer_001".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000000,
        exp: 2000000,
        schema: "provii.age/0".to_string(),
        dob_days: Some(18000),
        r_bits: Some(vec![true, false, true, false]),
    };

    // Test serialization
    let json = serde_json::to_string(&cred)?;

    // Test deserialization
    let deserialized: CredentialV2 = serde_json::from_str(&json)?;

    assert_eq!(deserialized.v, cred.v);
    assert_eq!(deserialized.kid, cred.kid);
    assert_eq!(deserialized.issuer_vk, cred.issuer_vk);
    assert_eq!(deserialized.sig_rj, cred.sig_rj);
    assert_eq!(deserialized.c_bytes, cred.c_bytes);
    assert_eq!(deserialized.iat, cred.iat);
    assert_eq!(deserialized.exp, cred.exp);
    assert_eq!(deserialized.schema, cred.schema);
    // SECURITY: Private fields are intentionally NOT serialized to prevent secret leakage
    assert_eq!(
        deserialized.dob_days, None,
        "dob_days should not be serialized"
    );
    assert_eq!(deserialized.r_bits, None, "r_bits should not be serialized");
    Ok(())
}

#[test]
fn test_credential_v2_without_private_fields() -> Result<(), Box<dyn std::error::Error>> {
    let cred = CredentialV2 {
        v: 2,
        kid: "test_issuer_001".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000000,
        exp: 2000000,
        schema: "provii.age/0".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;

    // Verify private fields are not in JSON when None
    assert!(!json.contains("dob_days"));
    assert!(!json.contains("r_bits"));

    let deserialized: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(deserialized.dob_days, None);
    assert_eq!(deserialized.r_bits, None);
    Ok(())
}

#[test]
fn test_signed_credential_header_base64_serialization() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 2,
        kid: "issuer_key_1".to_string(),
        issuer_vk: [5u8; 32],
        sig_rj: [6u8; 64],
        c_bytes: [7u8; 32],
        iat: 1500000,
        exp: 2500000,
        schema: "provii.age/0".to_string(),
    };

    let json = serde_json::to_string(&header)?;

    // Verify base64 encoding is used
    let expected_vk = URL_SAFE_NO_PAD.encode([5u8; 32]);
    assert!(json.contains(&expected_vk));

    let deserialized: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(deserialized.issuer_vk, header.issuer_vk);
    assert_eq!(deserialized.sig_rj, header.sig_rj);
    assert_eq!(deserialized.c_bytes, header.c_bytes);
    Ok(())
}

#[test]
fn test_qr_challenge_payload_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "challenge_123".to_string(),
        rp_challenge: URL_SAFE_NO_PAD.encode([10u8; 32]),
        cutoff_days: 19000,
        verifying_key_id: 1,
        submit_secret: URL_SAFE_NO_PAD.encode([11u8; 32]),
        expires_at: 3000000,
        verify_url: "https://verify.example.com/v1/verify".to_string(),
        code_verifier: Some("pkce_verifier_abc".to_string()),
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    let deserialized: QrChallengePayload = serde_json::from_str(&json)?;

    assert_eq!(deserialized.challenge_id, payload.challenge_id);
    assert_eq!(deserialized.rp_challenge, payload.rp_challenge);
    assert_eq!(deserialized.cutoff_days, payload.cutoff_days);
    assert_eq!(deserialized.verifying_key_id, payload.verifying_key_id);
    assert_eq!(deserialized.submit_secret, payload.submit_secret);
    assert_eq!(deserialized.expires_at, payload.expires_at);
    assert_eq!(deserialized.verify_url, payload.verify_url);
    assert_eq!(deserialized.code_verifier, payload.code_verifier);
    Ok(())
}

#[test]
fn test_authorizer_serialization() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "yubikey".to_string(),
        key_id: "officer_123".to_string(),
        challenge_id: Some("chal_456".to_string()),
        timestamp: 1234567890,
        hmac: "deadbeef".to_string(),
        nonce: "a".repeat(64),
    };

    let json = serde_json::to_string(&auth)?;

    // Check that keyId is used (not key_id)
    assert!(json.contains("keyId"));
    assert!(!json.contains("key_id"));

    let deserialized: Authorizer = serde_json::from_str(&json)?;
    assert_eq!(deserialized.key_id, auth.key_id);
    Ok(())
}

#[test]
fn test_age_proof_json_serialization() -> Result<(), Box<dyn std::error::Error>> {
    let proof = AgeProofJson {
        verifying_key_id: 1,
        public: AgePublicJson {
            cutoff_days: 19000,
            rp_challenge: URL_SAFE_NO_PAD.encode([15u8; 32]),
            issuer: IssuerKeyJson {
                value: URL_SAFE_NO_PAD.encode([16u8; 32]),
            },
            cred_nullifier: URL_SAFE_NO_PAD.encode([17u8; 32]),
        },
        proof: URL_SAFE_NO_PAD.encode(vec![18u8; 192]), // Mock Groth16 proof
    };

    let json = serde_json::to_string(&proof)?;
    let deserialized: AgeProofJson = serde_json::from_str(&json)?;

    assert_eq!(deserialized.verifying_key_id, proof.verifying_key_id);
    assert_eq!(deserialized.public.cutoff_days, proof.public.cutoff_days);
    assert_eq!(deserialized.public.rp_challenge, proof.public.rp_challenge);
    Ok(())
}

#[test]
fn test_submit_proof_request_serialization() -> Result<(), Box<dyn std::error::Error>> {
    let request = SubmitProofRequest {
        challenge_id: "chal_789".to_string(),
        submit_secret: URL_SAFE_NO_PAD.encode([20u8; 32]),
        code_verifier: Some("verifier_xyz".to_string()),
        proof: AgeProofJson {
            verifying_key_id: 1,
            public: AgePublicJson {
                cutoff_days: 19000,
                rp_challenge: URL_SAFE_NO_PAD.encode([21u8; 32]),
                issuer: IssuerKeyJson {
                    value: URL_SAFE_NO_PAD.encode([22u8; 32]),
                },
                cred_nullifier: URL_SAFE_NO_PAD.encode([23u8; 32]),
            },
            proof: URL_SAFE_NO_PAD.encode(vec![24u8; 192]),
        },
    };

    let json = serde_json::to_string(&request)?;
    let deserialized: SubmitProofRequest = serde_json::from_str(&json)?;

    assert_eq!(deserialized.challenge_id, request.challenge_id);
    assert_eq!(deserialized.submit_secret, request.submit_secret);
    assert_eq!(deserialized.code_verifier, request.code_verifier);
    Ok(())
}

#[test]
fn test_verify_response_parsing() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"result":"OK","state":"verified"}"#;
    let response: VerifyResponse = serde_json::from_str(json)?;

    assert_eq!(response.result, "OK");
    assert_eq!(response.state, "verified");
    Ok(())
}

#[test]
fn test_credential_metadata_serialization() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = CredentialMetadata {
        id: "cred_id_abc123".to_string(),
        label: Some("My Age Credential".to_string()),
        imported_at: 1600000000,
        issuer_name: Some("Provii Issuer".to_string()),
    };

    let json = serde_json::to_string(&metadata)?;
    let deserialized: CredentialMetadata = serde_json::from_str(&json)?;

    assert_eq!(deserialized.id, metadata.id);
    assert_eq!(deserialized.label, metadata.label);
    assert_eq!(deserialized.imported_at, metadata.imported_at);
    assert_eq!(deserialized.issuer_name, metadata.issuer_name);
    Ok(())
}

#[test]
fn test_wallet_config_serialization() -> Result<(), Box<dyn std::error::Error>> {
    let config = WalletConfig {
        auto_select: true,
        network_timeout: 30,
        cache_proving_keys: true,
    };

    let json = serde_json::to_string(&config)?;
    let deserialized: WalletConfig = serde_json::from_str(&json)?;

    assert_eq!(deserialized.auto_select, config.auto_select);
    assert_eq!(deserialized.network_timeout, config.network_timeout);
    assert_eq!(deserialized.cache_proving_keys, config.cache_proving_keys);
    Ok(())
}

// ============================================================================
// SECTION 1: sig_bytes module edge cases (20 tests)
// ============================================================================

#[test]
fn test_sig_bytes_exactly_64_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = [42u8; 64];
    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(parsed.sig_rj, bytes);
    assert_eq!(parsed.sig_rj.len(), 64);
    Ok(())
}

#[test]
fn test_sig_bytes_wrong_length_0() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"v":2,"kid":"test","issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":[],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<CredentialV2>(json);
    assert!(result.is_err());
    let err_msg = result.err().ok_or("expected error")?.to_string();
    assert!(err_msg.contains("expected 64 bytes") || err_msg.contains("got 0"));
    Ok(())
}

#[test]
fn test_sig_bytes_wrong_length_63() -> Result<(), Box<dyn std::error::Error>> {
    let bytes_vec = vec![2u8; 63];
    let json = format!(
        r#"{{"v":2,"kid":"test","issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":{:?},"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000,"exp":2000,"schema":"test"}}"#,
        bytes_vec
    );
    let result = serde_json::from_str::<CredentialV2>(&json);
    assert!(result.is_err());
    assert!(result
        .err()
        .ok_or("expected error")?
        .to_string()
        .contains("expected 64 bytes"));
    Ok(())
}

#[test]
fn test_sig_bytes_wrong_length_65() -> Result<(), Box<dyn std::error::Error>> {
    let bytes_vec = vec![2u8; 65];
    let json = format!(
        r#"{{"v":2,"kid":"test","issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":{:?},"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000,"exp":2000,"schema":"test"}}"#,
        bytes_vec
    );
    let result = serde_json::from_str::<CredentialV2>(&json);
    assert!(result.is_err());
    assert!(result
        .err()
        .ok_or("expected error")?
        .to_string()
        .contains("expected 64 bytes"));
    Ok(())
}

#[test]
fn test_sig_bytes_wrong_length_128() -> Result<(), Box<dyn std::error::Error>> {
    let bytes_vec = vec![2u8; 128];
    let json = format!(
        r#"{{"v":2,"kid":"test","issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":{:?},"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000,"exp":2000,"schema":"test"}}"#,
        bytes_vec
    );
    let result = serde_json::from_str::<CredentialV2>(&json);
    assert!(result.is_err());
    assert!(result
        .err()
        .ok_or("expected error")?
        .to_string()
        .contains("expected 64 bytes"));
    Ok(())
}

#[test]
fn test_sig_bytes_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = [0u8; 64];
    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(parsed.sig_rj, [0u8; 64]);
    Ok(())
}

#[test]
fn test_sig_bytes_all_255() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = [255u8; 64];
    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(parsed.sig_rj, [255u8; 64]);
    Ok(())
}

#[test]
fn test_sig_bytes_pattern_preservation() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = [0u8; 64];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(13);
    }

    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(parsed.sig_rj, bytes);
    Ok(())
}

#[test]
fn test_sig_bytes_serialization_format() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = [42u8; 64];
    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    // sig_rj should be serialized as array
    assert!(json.contains("sig_rj"));
    Ok(())
}

#[test]
fn test_sig_bytes_first_and_last_byte() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = [0u8; 64];
    bytes[0] = 123;
    bytes[63] = 231;

    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(parsed.sig_rj[0], 123);
    assert_eq!(parsed.sig_rj[63], 231);
    Ok(())
}

#[test]
fn test_sig_bytes_r_and_s_components() -> Result<(), Box<dyn std::error::Error>> {
    // RedJubjub sig is R||S format (32 + 32 bytes)
    let mut bytes = [0u8; 64];
    // R component (first 32 bytes)
    for (i, b) in bytes[..32].iter_mut().enumerate() {
        *b = 100 + i as u8;
    }
    // S component (last 32 bytes)
    for (i, b) in bytes[32..].iter_mut().enumerate() {
        *b = 200 + i as u8;
    }

    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    let parsed: CredentialV2 = serde_json::from_str(&json)?;

    // Verify R component
    for i in 0..32 {
        assert_eq!(parsed.sig_rj[i], 100 + i as u8);
    }
    // Verify S component
    for i in 32..64 {
        assert_eq!(parsed.sig_rj[i], 200 + (i - 32) as u8);
    }
    Ok(())
}

#[test]
fn test_sig_bytes_multiple_roundtrips() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = [7u8; 64];
    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    // First roundtrip
    let json1 = serde_json::to_string(&cred)?;
    let parsed1: CredentialV2 = serde_json::from_str(&json1)?;

    // Second roundtrip
    let json2 = serde_json::to_string(&parsed1)?;
    let parsed2: CredentialV2 = serde_json::from_str(&json2)?;

    assert_eq!(parsed2.sig_rj, bytes);
    Ok(())
}

#[test]
fn test_sig_bytes_alternating_pattern() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = [0u8; 64];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = if i % 2 == 0 { 0xFF } else { 0x00 };
    }

    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(parsed.sig_rj, bytes);
    Ok(())
}

#[test]
fn test_sig_bytes_error_message_format() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"v":2,"kid":"test","issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":[1,2,3],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<CredentialV2>(json);
    assert!(result.is_err());
    let err = result.err().ok_or("expected error")?.to_string();
    assert!(err.contains("64") || err.contains("expected"));
    Ok(())
}

#[test]
fn test_sig_bytes_boundary_values_per_byte() -> Result<(), Box<dyn std::error::Error>> {
    // Test with each byte at min and max values
    let mut bytes = [128u8; 64];
    bytes[0] = 0; // Min value
    bytes[1] = 255; // Max value
    bytes[63] = 255; // Last byte max

    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(parsed.sig_rj[0], 0);
    assert_eq!(parsed.sig_rj[1], 255);
    assert_eq!(parsed.sig_rj[63], 255);
    Ok(())
}

#[test]
fn test_sig_bytes_ascending_sequence() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = [0u8; 64];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i % 256) as u8;
    }

    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    let parsed: CredentialV2 = serde_json::from_str(&json)?;

    for i in 0..64 {
        assert_eq!(parsed.sig_rj[i], (i % 256) as u8);
    }
    Ok(())
}

#[test]
fn test_sig_bytes_wrong_type_string() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"v":2,"kid":"test","issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":"not_an_array","c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<CredentialV2>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_sig_bytes_wrong_type_null() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"v":2,"kid":"test","issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":null,"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<CredentialV2>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_sig_bytes_nested_arrays() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"v":2,"kid":"test","issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":[[1,2],[3,4]],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<CredentialV2>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_sig_bytes_with_negative_values() -> Result<(), Box<dyn std::error::Error>> {
    // JSON doesn't have negatives in byte arrays, but test parser handles it
    let json = r#"{"v":2,"kid":"test","issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":[-1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<CredentialV2>(json);
    assert!(result.is_err());
    Ok(())
}

// ============================================================================
// SECTION 2: base64_bytes module edge cases (20 tests)
// ============================================================================

#[test]
fn test_base64_bytes_exactly_32_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = [42u8; 32];
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: bytes,
        sig_rj: [1u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.issuer_vk, bytes);
    assert_eq!(parsed.issuer_vk.len(), 32);
    Ok(())
}

#[test]
fn test_base64_bytes_url_safe_no_padding() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = [255u8; 32];
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: bytes,
        sig_rj: [1u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;

    // Should use URL-safe alphabet (no + or /)
    // Should not have padding (no =)
    assert!(!json.contains("+"));
    assert!(!json.contains("/"));
    assert!(!json.contains("="));
    Ok(())
}

#[test]
fn test_base64_bytes_wrong_length_31() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = URL_SAFE_NO_PAD.encode([1u8; 31]);
    let json = format!(
        r#"{{"v":2,"kid":"test","issuer_vk":"{}","sig_rj":"{}","c_bytes":"{}","iat":1000,"exp":2000,"schema":"test"}}"#,
        encoded,
        URL_SAFE_NO_PAD.encode([1u8; 64]),
        URL_SAFE_NO_PAD.encode([3u8; 32])
    );
    let result = serde_json::from_str::<SignedCredentialHeader>(&json);
    assert!(result.is_err());
    assert!(result
        .err()
        .ok_or("expected error")?
        .to_string()
        .contains("expected 32 bytes"));
    Ok(())
}

#[test]
fn test_base64_bytes_wrong_length_33() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = URL_SAFE_NO_PAD.encode([1u8; 33]);
    let json = format!(
        r#"{{"v":2,"kid":"test","issuer_vk":"{}","sig_rj":"{}","c_bytes":"{}","iat":1000,"exp":2000,"schema":"test"}}"#,
        encoded,
        URL_SAFE_NO_PAD.encode([1u8; 64]),
        URL_SAFE_NO_PAD.encode([3u8; 32])
    );
    let result = serde_json::from_str::<SignedCredentialHeader>(&json);
    assert!(result.is_err());
    assert!(result
        .err()
        .ok_or("expected error")?
        .to_string()
        .contains("expected 32 bytes"));
    Ok(())
}

#[test]
fn test_base64_bytes_wrong_length_0() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = URL_SAFE_NO_PAD.encode([]);
    let json = format!(
        r#"{{"v":2,"kid":"test","issuer_vk":"{}","sig_rj":"{}","c_bytes":"{}","iat":1000,"exp":2000,"schema":"test"}}"#,
        encoded,
        URL_SAFE_NO_PAD.encode([1u8; 64]),
        URL_SAFE_NO_PAD.encode([3u8; 32])
    );
    let result = serde_json::from_str::<SignedCredentialHeader>(&json);
    assert!(result.is_err());
    assert!(result
        .err()
        .ok_or("expected error")?
        .to_string()
        .contains("expected 32 bytes"));
    Ok(())
}

#[test]
fn test_base64_bytes_wrong_length_64() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = URL_SAFE_NO_PAD.encode([1u8; 64]);
    let json = format!(
        r#"{{"v":2,"kid":"test","issuer_vk":"{}","sig_rj":"{}","c_bytes":"{}","iat":1000,"exp":2000,"schema":"test"}}"#,
        encoded,
        URL_SAFE_NO_PAD.encode([1u8; 64]),
        URL_SAFE_NO_PAD.encode([3u8; 32])
    );
    let result = serde_json::from_str::<SignedCredentialHeader>(&json);
    assert!(result.is_err());
    assert!(result
        .err()
        .ok_or("expected error")?
        .to_string()
        .contains("expected 32 bytes"));
    Ok(())
}

#[test]
fn test_base64_bytes_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = [0u8; 32];
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: bytes,
        sig_rj: [1u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.issuer_vk, [0u8; 32]);
    Ok(())
}

#[test]
fn test_base64_bytes_all_255() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = [255u8; 32];
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: bytes,
        sig_rj: [1u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.issuer_vk, [255u8; 32]);
    Ok(())
}

#[test]
fn test_base64_bytes_invalid_base64_chars() -> Result<(), Box<dyn std::error::Error>> {
    // Invalid base64 with special characters
    let json = r#"{"v":2,"kid":"test","issuer_vk":"!@#$%^&*()","sig_rj":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","c_bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<SignedCredentialHeader>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_base64_bytes_invalid_with_padding() -> Result<(), Box<dyn std::error::Error>> {
    // Base64 with standard padding (should fail because URL_SAFE_NO_PAD doesn't accept it)
    let json = r#"{"v":2,"kid":"test","issuer_vk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","sig_rj":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","c_bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<SignedCredentialHeader>(json);
    // URL_SAFE_NO_PAD decoder should reject standard padding characters
    assert!(
        result.is_err(),
        "padded base64 should be rejected by URL_SAFE_NO_PAD"
    );
    Ok(())
}

#[test]
fn test_base64_bytes_pattern_preservation() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(11);
    }

    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: bytes,
        sig_rj: [1u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.issuer_vk, bytes);
    Ok(())
}

#[test]
fn test_base64_bytes_roundtrip_multiple() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = [17u8; 32];
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: bytes,
        sig_rj: [1u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    // First roundtrip
    let json1 = serde_json::to_string(&header)?;
    let parsed1: SignedCredentialHeader = serde_json::from_str(&json1)?;

    // Second roundtrip
    let json2 = serde_json::to_string(&parsed1)?;
    let parsed2: SignedCredentialHeader = serde_json::from_str(&json2)?;

    assert_eq!(parsed2.issuer_vk, bytes);
    Ok(())
}

#[test]
fn test_base64_bytes_first_and_last() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = [128u8; 32];
    bytes[0] = 1;
    bytes[31] = 254;

    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: bytes,
        sig_rj: [1u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.issuer_vk[0], 1);
    assert_eq!(parsed.issuer_vk[31], 254);
    Ok(())
}

#[test]
fn test_base64_bytes_c_bytes_field() -> Result<(), Box<dyn std::error::Error>> {
    // Test the c_bytes field specifically
    let bytes = [99u8; 32];
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: bytes,
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.c_bytes, bytes);
    Ok(())
}

#[test]
fn test_base64_bytes_commitment_field() -> Result<(), Box<dyn std::error::Error>> {
    // Test SignCommitmentRequest which uses base64_bytes for commitment
    let commitment = [77u8; 32];
    let request = SignCommitmentRequest {
        session_id: "session123".to_string(),
        commitment,
        authorizer: Authorizer {
            format: "client".to_string(),
            key_id: "key1".to_string(),
            challenge_id: None,
            timestamp: 1000,
            hmac: "deadbeef".to_string(),
            nonce: "a".repeat(64),
        },
    };

    let json = serde_json::to_string(&request)?;
    let parsed: SignCommitmentRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.commitment, commitment);
    Ok(())
}

#[test]
fn test_base64_bytes_empty_string() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"v":2,"kid":"test","issuer_vk":"","sig_rj":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","c_bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<SignedCredentialHeader>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_base64_bytes_wrong_type_number() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"v":2,"kid":"test","issuer_vk":12345,"sig_rj":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","c_bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<SignedCredentialHeader>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_base64_bytes_wrong_type_null() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"v":2,"kid":"test","issuer_vk":null,"sig_rj":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","c_bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<SignedCredentialHeader>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_base64_bytes_alternating_bits() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = if i % 2 == 0 { 0xAA } else { 0x55 };
    }

    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: bytes,
        sig_rj: [1u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.issuer_vk, bytes);
    Ok(())
}

// ============================================================================
// SECTION 3: base64_bytes_64 module edge cases (20 tests)
// ============================================================================

#[test]
fn test_base64_bytes_64_exactly_64_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = [88u8; 64];
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.sig_rj, bytes);
    assert_eq!(parsed.sig_rj.len(), 64);
    Ok(())
}

#[test]
fn test_base64_bytes_64_url_safe_no_padding() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = [250u8; 64];
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;

    // Should use URL-safe alphabet and no padding
    assert!(!json.contains("+"));
    assert!(!json.contains("/"));
    Ok(())
}

#[test]
fn test_base64_bytes_64_wrong_length_63() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = URL_SAFE_NO_PAD.encode([1u8; 63]);
    let json = format!(
        r#"{{"v":2,"kid":"test","issuer_vk":"{}","sig_rj":"{}","c_bytes":"{}","iat":1000,"exp":2000,"schema":"test"}}"#,
        URL_SAFE_NO_PAD.encode([1u8; 32]),
        encoded,
        URL_SAFE_NO_PAD.encode([3u8; 32])
    );
    let result = serde_json::from_str::<SignedCredentialHeader>(&json);
    assert!(result.is_err());
    assert!(result
        .err()
        .ok_or("expected error")?
        .to_string()
        .contains("expected 64 bytes"));
    Ok(())
}

#[test]
fn test_base64_bytes_64_wrong_length_65() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = URL_SAFE_NO_PAD.encode([1u8; 65]);
    let json = format!(
        r#"{{"v":2,"kid":"test","issuer_vk":"{}","sig_rj":"{}","c_bytes":"{}","iat":1000,"exp":2000,"schema":"test"}}"#,
        URL_SAFE_NO_PAD.encode([1u8; 32]),
        encoded,
        URL_SAFE_NO_PAD.encode([3u8; 32])
    );
    let result = serde_json::from_str::<SignedCredentialHeader>(&json);
    assert!(result.is_err());
    assert!(result
        .err()
        .ok_or("expected error")?
        .to_string()
        .contains("expected 64 bytes"));
    Ok(())
}

#[test]
fn test_base64_bytes_64_wrong_length_0() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = URL_SAFE_NO_PAD.encode([]);
    let json = format!(
        r#"{{"v":2,"kid":"test","issuer_vk":"{}","sig_rj":"{}","c_bytes":"{}","iat":1000,"exp":2000,"schema":"test"}}"#,
        URL_SAFE_NO_PAD.encode([1u8; 32]),
        encoded,
        URL_SAFE_NO_PAD.encode([3u8; 32])
    );
    let result = serde_json::from_str::<SignedCredentialHeader>(&json);
    assert!(result.is_err());
    assert!(result
        .err()
        .ok_or("expected error")?
        .to_string()
        .contains("expected 64 bytes"));
    Ok(())
}

#[test]
fn test_base64_bytes_64_wrong_length_32() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = URL_SAFE_NO_PAD.encode([1u8; 32]);
    let json = format!(
        r#"{{"v":2,"kid":"test","issuer_vk":"{}","sig_rj":"{}","c_bytes":"{}","iat":1000,"exp":2000,"schema":"test"}}"#,
        URL_SAFE_NO_PAD.encode([1u8; 32]),
        encoded,
        URL_SAFE_NO_PAD.encode([3u8; 32])
    );
    let result = serde_json::from_str::<SignedCredentialHeader>(&json);
    assert!(result.is_err());
    assert!(result
        .err()
        .ok_or("expected error")?
        .to_string()
        .contains("expected 64 bytes"));
    Ok(())
}

#[test]
fn test_base64_bytes_64_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = [0u8; 64];
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.sig_rj, [0u8; 64]);
    Ok(())
}

#[test]
fn test_base64_bytes_64_all_255() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = [255u8; 64];
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.sig_rj, [255u8; 64]);
    Ok(())
}

#[test]
fn test_base64_bytes_64_pattern_preservation() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = [0u8; 64];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(3).wrapping_add(7);
    }

    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.sig_rj, bytes);
    Ok(())
}

#[test]
fn test_base64_bytes_64_first_and_last() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = [99u8; 64];
    bytes[0] = 5;
    bytes[63] = 250;

    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.sig_rj[0], 5);
    assert_eq!(parsed.sig_rj[63], 250);
    Ok(())
}

#[test]
fn test_base64_bytes_64_roundtrip_multiple() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = [33u8; 64];
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    // First roundtrip
    let json1 = serde_json::to_string(&header)?;
    let parsed1: SignedCredentialHeader = serde_json::from_str(&json1)?;

    // Second roundtrip
    let json2 = serde_json::to_string(&parsed1)?;
    let parsed2: SignedCredentialHeader = serde_json::from_str(&json2)?;

    assert_eq!(parsed2.sig_rj, bytes);
    Ok(())
}

#[test]
fn test_base64_bytes_64_r_and_s_halves() -> Result<(), Box<dyn std::error::Error>> {
    // sig_rj is R||S format (32 + 32)
    let mut bytes = [0u8; 64];
    // R half
    for (i, b) in bytes[..32].iter_mut().enumerate() {
        *b = i as u8;
    }
    // S half
    for (i, b) in bytes[32..].iter_mut().enumerate() {
        *b = 255 - i as u8;
    }

    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.sig_rj, bytes);
    Ok(())
}

#[test]
fn test_base64_bytes_64_invalid_base64() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"v":2,"kid":"test","issuer_vk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","sig_rj":"!invalid!base64!","c_bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<SignedCredentialHeader>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_base64_bytes_64_empty_string() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"v":2,"kid":"test","issuer_vk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","sig_rj":"","c_bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<SignedCredentialHeader>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_base64_bytes_64_wrong_type_number() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"v":2,"kid":"test","issuer_vk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","sig_rj":999999,"c_bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<SignedCredentialHeader>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_base64_bytes_64_wrong_type_null() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"v":2,"kid":"test","issuer_vk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","sig_rj":null,"c_bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<SignedCredentialHeader>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_base64_bytes_64_alternating_bits() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = [0u8; 64];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = if i % 2 == 0 { 0x0F } else { 0xF0 };
    }

    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.sig_rj, bytes);
    Ok(())
}

#[test]
fn test_base64_bytes_64_ascending_values() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = [0u8; 64];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i * 4) as u8;
    }

    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: bytes,
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;

    for i in 0..64 {
        assert_eq!(parsed.sig_rj[i], (i * 4) as u8);
    }
    Ok(())
}

#[test]
fn test_base64_bytes_64_with_wrong_padding() -> Result<(), Box<dyn std::error::Error>> {
    // Base64 with padding should be rejected by URL_SAFE_NO_PAD
    let json = r#"{"v":2,"kid":"test","issuer_vk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","sig_rj":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","c_bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<SignedCredentialHeader>(json);
    // URL_SAFE_NO_PAD decoder should reject standard padding characters
    assert!(
        result.is_err(),
        "padded base64 should be rejected by URL_SAFE_NO_PAD"
    );
    Ok(())
}

// ============================================================================
// SECTION 4: CredentialV2 comprehensive tests (25 tests)
// ============================================================================

#[test]
fn test_credentialv2_never_serializes_secrets() -> Result<(), Box<dyn std::error::Error>> {
    // SECURITY: dob_days and r_bits are NEVER serialized, even when present
    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: Some(18000),
        r_bits: Some(vec![true, false]),
    };

    let json = serde_json::to_string(&cred)?;
    // Neither field should ever be present in JSON - they are secrets
    assert!(
        !json.contains("dob_days"),
        "dob_days must never be serialized"
    );
    assert!(!json.contains("r_bits"), "r_bits must never be serialized");
    Ok(())
}

#[test]
fn test_credentialv2_secrets_can_be_deserialized() -> Result<(), Box<dyn std::error::Error>> {
    // Secrets CAN be deserialized - this is required for receiving credentials from the issuer.
    // The security property is that secrets are never SERIALIZED (no leakage).
    let json_with_secrets = r#"{
            "v": 2,
            "kid": "test",
            "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
            "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
            "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
            "iat": 1000,
            "exp": 2000,
            "schema": "test",
            "dob_days": 18000,
            "r_bits": [true, false]
        }"#;

    let parsed: CredentialV2 = serde_json::from_str(json_with_secrets)?;
    // Secrets SHOULD be deserialized (for receiving from issuer)
    assert_eq!(
        parsed.dob_days,
        Some(18000),
        "dob_days should be deserialized from issuer"
    );
    assert_eq!(
        parsed.r_bits,
        Some(vec![true, false]),
        "r_bits should be deserialized from issuer"
    );

    // But when we serialize, secrets should NOT be included (prevents leakage)
    let json = serde_json::to_string(&parsed)?;
    assert!(
        !json.contains("dob_days"),
        "dob_days must never be serialized"
    );
    assert!(!json.contains("r_bits"), "r_bits must never be serialized");
    Ok(())
}

#[test]
fn test_credentialv2_unicode_kid() -> Result<(), Box<dyn std::error::Error>> {
    let cred = CredentialV2 {
        v: 2,
        kid: "issuer_日本語_key_🔑".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(parsed.kid, "issuer_日本語_key_🔑");
    Ok(())
}

#[test]
fn test_credentialv2_unicode_schema() -> Result<(), Box<dyn std::error::Error>> {
    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "provii.age/0.测试".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(parsed.schema, "provii.age/0.测试");
    Ok(())
}

#[test]
fn test_credentialv2_empty_kid() -> Result<(), Box<dyn std::error::Error>> {
    let cred = CredentialV2 {
        v: 2,
        kid: "".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(parsed.kid, "");
    Ok(())
}

#[test]
fn test_credentialv2_very_long_kid() -> Result<(), Box<dyn std::error::Error>> {
    let long_kid = "a".repeat(1000);
    let cred = CredentialV2 {
        v: 2,
        kid: long_kid.clone(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(parsed.kid, long_kid);
    Ok(())
}

#[test]
fn test_credentialv2_timestamp_zero() -> Result<(), Box<dyn std::error::Error>> {
    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 0,
        exp: 0,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(parsed.iat, 0);
    assert_eq!(parsed.exp, 0);
    Ok(())
}

#[test]
fn test_credentialv2_timestamp_u64_max() -> Result<(), Box<dyn std::error::Error>> {
    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: u64::MAX,
        exp: u64::MAX,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(parsed.iat, u64::MAX);
    assert_eq!(parsed.exp, u64::MAX);
    Ok(())
}

#[test]
fn test_credentialv2_version_byte_variations() -> Result<(), Box<dyn std::error::Error>> {
    for version in [0, 1, 2, 3, 255] {
        let cred = CredentialV2 {
            v: version,
            kid: "test".to_string(),
            issuer_vk: [1u8; 32],
            sig_rj: [2u8; 64],
            c_bytes: [3u8; 32],
            iat: 1000,
            exp: 2000,
            schema: "test".to_string(),
            dob_days: None,
            r_bits: None,
        };

        let json = serde_json::to_string(&cred)?;
        let parsed: CredentialV2 = serde_json::from_str(&json)?;
        assert_eq!(parsed.v, version);
    }
    Ok(())
}

#[test]
fn test_credentialv2_dob_days_not_leaked_zero() -> Result<(), Box<dyn std::error::Error>> {
    // SECURITY: Verify dob_days=0 is NOT leaked through JSON
    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: Some(0),
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    assert!(
        !json.contains("dob_days"),
        "dob_days must not be serialized"
    );
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(
        parsed.dob_days, None,
        "dob_days must not survive JSON round-trip"
    );
    Ok(())
}

#[test]
fn test_credentialv2_dob_days_not_leaked_max() -> Result<(), Box<dyn std::error::Error>> {
    // SECURITY: Verify dob_days=MAX is NOT leaked through JSON
    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: Some(i32::MAX),
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    assert!(
        !json.contains("dob_days"),
        "dob_days must not be serialized"
    );
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(
        parsed.dob_days, None,
        "dob_days must not survive JSON round-trip"
    );
    Ok(())
}

#[test]
fn test_credentialv2_dob_days_not_leaked_negative() -> Result<(), Box<dyn std::error::Error>> {
    // SECURITY: Verify negative dob_days is NOT leaked through JSON
    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: Some(-1),
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    assert!(
        !json.contains("dob_days"),
        "dob_days must not be serialized"
    );
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(
        parsed.dob_days, None,
        "dob_days must not survive JSON round-trip"
    );
    Ok(())
}

#[test]
fn test_credentialv2_r_bits_not_leaked_empty() -> Result<(), Box<dyn std::error::Error>> {
    // SECURITY: Verify r_bits (even empty) is NOT leaked through JSON
    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: Some(vec![]),
    };

    let json = serde_json::to_string(&cred)?;
    assert!(!json.contains("r_bits"), "r_bits must not be serialized");
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(
        parsed.r_bits, None,
        "r_bits must not survive JSON round-trip"
    );
    Ok(())
}

#[test]
fn test_credentialv2_r_bits_not_leaked_long() -> Result<(), Box<dyn std::error::Error>> {
    // SECURITY: Verify long r_bits is NOT leaked through JSON
    let r_bits = vec![true; 512];
    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: Some(r_bits),
    };

    let json = serde_json::to_string(&cred)?;
    assert!(!json.contains("r_bits"), "r_bits must not be serialized");
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(
        parsed.r_bits, None,
        "r_bits must not survive JSON round-trip"
    );
    Ok(())
}

#[test]
fn test_credentialv2_r_bits_not_leaked_pattern() -> Result<(), Box<dyn std::error::Error>> {
    // SECURITY: Verify patterned r_bits is NOT leaked through JSON
    let r_bits: Vec<bool> = (0..256).map(|i| i % 3 == 0).collect();
    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: Some(r_bits),
    };

    let json = serde_json::to_string(&cred)?;
    assert!(!json.contains("r_bits"), "r_bits must not be serialized");
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(
        parsed.r_bits, None,
        "r_bits must not survive JSON round-trip"
    );
    Ok(())
}

#[test]
fn test_credentialv2_malformed_json_missing_field() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"v":2,"kid":"test","issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000,"exp":2000}"#;
    // Missing schema field
    let result = serde_json::from_str::<CredentialV2>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_credentialv2_malformed_json_wrong_type() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"v":"not_a_number","kid":"test","issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<CredentialV2>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_credentialv2_arrays_modified() -> Result<(), Box<dyn std::error::Error>> {
    let mut cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    // Modify specific bytes
    cred.issuer_vk[0] = 99;
    cred.sig_rj[0] = 88;
    cred.c_bytes[0] = 77;

    let json = serde_json::to_string(&cred)?;
    let parsed: CredentialV2 = serde_json::from_str(&json)?;

    assert_eq!(parsed.issuer_vk[0], 99);
    assert_eq!(parsed.sig_rj[0], 88);
    assert_eq!(parsed.c_bytes[0], 77);
    Ok(())
}

#[test]
fn test_credentialv2_special_chars_in_schema() -> Result<(), Box<dyn std::error::Error>> {
    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "provii.age/0-beta_test!@#".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(parsed.schema, "provii.age/0-beta_test!@#");
    Ok(())
}

#[test]
fn test_credentialv2_escaped_chars_in_kid() -> Result<(), Box<dyn std::error::Error>> {
    let cred = CredentialV2 {
        v: 2,
        kid: "test\"with\\quotes\nand\ttabs".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    // JSON should properly escape the special characters
    assert!(json.contains("\\\""));
    assert!(json.contains("\\n"));
    assert!(json.contains("\\t"));

    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(parsed.kid, "test\"with\\quotes\nand\ttabs");
    Ok(())
}

#[test]
fn test_credentialv2_exp_before_iat() -> Result<(), Box<dyn std::error::Error>> {
    // Allowed by type system, but semantically invalid
    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 2000,
        exp: 1000, // exp before iat
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(parsed.iat, 2000);
    assert_eq!(parsed.exp, 1000);
    Ok(())
}

#[test]
fn test_credentialv2_same_iat_and_exp() -> Result<(), Box<dyn std::error::Error>> {
    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1500,
        exp: 1500,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let json = serde_json::to_string(&cred)?;
    let parsed: CredentialV2 = serde_json::from_str(&json)?;
    assert_eq!(parsed.iat, parsed.exp);
    Ok(())
}

#[test]
fn test_credentialv2_clone_trait() -> Result<(), Box<dyn std::error::Error>> {
    let cred1 = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: Some(18000),
        r_bits: Some(vec![true, false]),
    };

    let cred2 = cred1.clone();

    assert_eq!(cred2.v, cred1.v);
    assert_eq!(cred2.kid, cred1.kid);
    assert_eq!(cred2.dob_days, cred1.dob_days);
    assert_eq!(cred2.r_bits, cred1.r_bits);
    Ok(())
}

#[test]
fn test_credentialv2_debug_trait() -> Result<(), Box<dyn std::error::Error>> {
    let cred = CredentialV2 {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
        dob_days: None,
        r_bits: None,
    };

    let debug_str = format!("{:?}", cred);
    assert!(debug_str.contains("CredentialV2"));
    assert!(debug_str.contains("kid"));
    Ok(())
}

// ============================================================================
// SECTION 5: SignedCredentialHeader comprehensive tests (25 tests)
// ============================================================================

#[test]
fn test_signed_credential_header_all_fields_valid() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 2,
        kid: "issuer_key_001".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1700000000,
        exp: 1800000000,
        schema: "provii.age/0".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;

    assert_eq!(parsed.v, 2);
    assert_eq!(parsed.kid, "issuer_key_001");
    assert_eq!(parsed.issuer_vk, [1u8; 32]);
    assert_eq!(parsed.sig_rj, [2u8; 64]);
    assert_eq!(parsed.c_bytes, [3u8; 32]);
    assert_eq!(parsed.iat, 1700000000);
    assert_eq!(parsed.exp, 1800000000);
    assert_eq!(parsed.schema, "provii.age/0");
    Ok(())
}

#[test]
fn test_signed_credential_header_version_byte_zero() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 0,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.v, 0);
    Ok(())
}

#[test]
fn test_signed_credential_header_version_byte_max() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 255,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.v, 255);
    Ok(())
}

#[test]
fn test_signed_credential_header_empty_kid() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 2,
        kid: "".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.kid, "");
    Ok(())
}

#[test]
fn test_signed_credential_header_unicode_kid() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 2,
        kid: "issuer_鍵_🔑_key".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.kid, "issuer_鍵_🔑_key");
    Ok(())
}

#[test]
fn test_signed_credential_header_very_long_kid() -> Result<(), Box<dyn std::error::Error>> {
    let long_kid = "k".repeat(5000);
    let header = SignedCredentialHeader {
        v: 2,
        kid: long_kid.clone(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.kid.len(), 5000);
    assert_eq!(parsed.kid, long_kid);
    Ok(())
}

#[test]
fn test_signed_credential_header_special_chars_kid() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 2,
        kid: "key-with_special.chars!@#$%".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.kid, "key-with_special.chars!@#$%");
    Ok(())
}

#[test]
fn test_signed_credential_header_escaped_chars_kid() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 2,
        kid: "key\"with\\quotes\nand\ttabs".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    assert!(json.contains("\\\""));
    assert!(json.contains("\\n"));
    assert!(json.contains("\\t"));

    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.kid, "key\"with\\quotes\nand\ttabs");
    Ok(())
}

#[test]
fn test_signed_credential_header_iat_zero() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 0,
        exp: 1000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.iat, 0);
    Ok(())
}

#[test]
fn test_signed_credential_header_iat_max() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: u64::MAX,
        exp: u64::MAX,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.iat, u64::MAX);
    Ok(())
}

#[test]
fn test_signed_credential_header_exp_before_iat() -> Result<(), Box<dyn std::error::Error>> {
    // Semantically invalid but type system allows
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 2000,
        exp: 1000,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.iat, 2000);
    assert_eq!(parsed.exp, 1000);
    assert!(parsed.exp < parsed.iat);
    Ok(())
}

#[test]
fn test_signed_credential_header_iat_equals_exp() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1500,
        exp: 1500,
        schema: "test".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.iat, parsed.exp);
    Ok(())
}

#[test]
fn test_signed_credential_header_empty_schema() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.schema, "");
    Ok(())
}

#[test]
fn test_signed_credential_header_unicode_schema() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "provii.年齢.v2".to_string(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.schema, "provii.年齢.v2");
    Ok(())
}

#[test]
fn test_signed_credential_header_long_schema() -> Result<(), Box<dyn std::error::Error>> {
    let long_schema = "a".repeat(1000);
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: long_schema.clone(),
    };

    let json = serde_json::to_string(&header)?;
    let parsed: SignedCredentialHeader = serde_json::from_str(&json)?;
    assert_eq!(parsed.schema, long_schema);
    Ok(())
}

#[test]
fn test_signed_credential_header_missing_field_v() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"kid":"test","issuer_vk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","sig_rj":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","c_bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<SignedCredentialHeader>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_signed_credential_header_missing_field_kid() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"v":2,"issuer_vk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","sig_rj":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","c_bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<SignedCredentialHeader>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_signed_credential_header_missing_field_schema() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"v":2,"kid":"test","issuer_vk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","sig_rj":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","c_bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","iat":1000,"exp":2000}"#;
    let result = serde_json::from_str::<SignedCredentialHeader>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_signed_credential_header_wrong_type_v() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"v":"not_a_number","kid":"test","issuer_vk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","sig_rj":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","c_bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","iat":1000,"exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<SignedCredentialHeader>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_signed_credential_header_wrong_type_iat() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"v":2,"kid":"test","issuer_vk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","sig_rj":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","c_bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","iat":"not_a_number","exp":2000,"schema":"test"}"#;
    let result = serde_json::from_str::<SignedCredentialHeader>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_signed_credential_header_wrong_type_schema() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"v":2,"kid":"test","issuer_vk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","sig_rj":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","c_bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","iat":1000,"exp":2000,"schema":12345}"#;
    let result = serde_json::from_str::<SignedCredentialHeader>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_signed_credential_header_clone_trait() -> Result<(), Box<dyn std::error::Error>> {
    let header1 = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let header2 = header1.clone();

    assert_eq!(header2.v, header1.v);
    assert_eq!(header2.kid, header1.kid);
    assert_eq!(header2.issuer_vk, header1.issuer_vk);
    assert_eq!(header2.sig_rj, header1.sig_rj);
    assert_eq!(header2.c_bytes, header1.c_bytes);
    Ok(())
}

#[test]
fn test_signed_credential_header_debug_trait() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [2u8; 64],
        c_bytes: [3u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    let debug_str = format!("{:?}", header);
    assert!(debug_str.contains("SignedCredentialHeader"));
    assert!(debug_str.contains("kid"));
    assert!(debug_str.contains("schema"));
    Ok(())
}

#[test]
fn test_signed_credential_header_multiple_roundtrips() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 2,
        kid: "test".to_string(),
        issuer_vk: [99u8; 32],
        sig_rj: [88u8; 64],
        c_bytes: [77u8; 32],
        iat: 1000,
        exp: 2000,
        schema: "test".to_string(),
    };

    // First roundtrip
    let json1 = serde_json::to_string(&header)?;
    let parsed1: SignedCredentialHeader = serde_json::from_str(&json1)?;

    // Second roundtrip
    let json2 = serde_json::to_string(&parsed1)?;
    let parsed2: SignedCredentialHeader = serde_json::from_str(&json2)?;

    // Third roundtrip
    let json3 = serde_json::to_string(&parsed2)?;
    let parsed3: SignedCredentialHeader = serde_json::from_str(&json3)?;

    assert_eq!(parsed3.issuer_vk, [99u8; 32]);
    assert_eq!(parsed3.sig_rj, [88u8; 64]);
    assert_eq!(parsed3.c_bytes, [77u8; 32]);
    Ok(())
}

// ============================================================================
// SECTION 6: Authorizer comprehensive tests (30 tests)
// ============================================================================

#[test]
fn test_authorizer_yubikey_with_challenge_id() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "yubikey".to_string(),
        key_id: "officer_001".to_string(),
        challenge_id: Some("chal_123".to_string()),
        timestamp: 1700000000,
        hmac: "abcdef0123456789".to_string(),
        nonce: "a".repeat(64),
    };

    let json = serde_json::to_string(&auth)?;
    // Should use keyId not key_id
    assert!(json.contains("keyId"));
    assert!(!json.contains("key_id"));

    let parsed: Authorizer = serde_json::from_str(&json)?;
    assert_eq!(parsed.format, "yubikey");
    assert_eq!(parsed.key_id, "officer_001");
    assert_eq!(parsed.challenge_id, Some("chal_123".to_string()));
    assert_eq!(parsed.timestamp, 1700000000);
    assert_eq!(parsed.hmac, "abcdef0123456789");
    Ok(())
}

#[test]
fn test_authorizer_client_without_challenge_id() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "client_api_key_001".to_string(),
        challenge_id: None,
        timestamp: 1700000000,
        hmac: "fedcba9876543210".to_string(),
        nonce: "a".repeat(64),
    };

    let json = serde_json::to_string(&auth)?;
    // challenge_id should not be present when None
    assert!(!json.contains("challenge_id"));

    let parsed: Authorizer = serde_json::from_str(&json)?;
    assert_eq!(parsed.format, "client");
    assert_eq!(parsed.key_id, "client_api_key_001");
    assert_eq!(parsed.challenge_id, None);
    Ok(())
}

#[test]
fn test_authorizer_key_id_field_rename() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "yubikey".to_string(),
        key_id: "test_key".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let json = serde_json::to_string(&auth)?;
    // Must serialize as keyId
    assert!(json.contains("\"keyId\""));
    // Must NOT serialize as key_id
    assert!(!json.contains("\"key_id\""));

    // Parse from keyId format
    let json_with_keyid = r#"{"format":"yubikey","keyId":"test_key","timestamp":1000,"hmac":"abc","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let parsed: Authorizer = serde_json::from_str(json_with_keyid)?;
    assert_eq!(parsed.key_id, "test_key");
    Ok(())
}

#[test]
fn test_authorizer_wrong_field_name_key_id() -> Result<(), Box<dyn std::error::Error>> {
    // Using key_id instead of keyId should fail
    let json = r#"{"format":"yubikey","key_id":"test_key","timestamp":1000,"hmac":"abc","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let result = serde_json::from_str::<Authorizer>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_authorizer_empty_format() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "".to_string(),
        key_id: "test".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let json = serde_json::to_string(&auth)?;
    let parsed: Authorizer = serde_json::from_str(&json)?;
    assert_eq!(parsed.format, "");
    Ok(())
}

#[test]
fn test_authorizer_empty_key_id() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let json = serde_json::to_string(&auth)?;
    let parsed: Authorizer = serde_json::from_str(&json)?;
    assert_eq!(parsed.key_id, "");
    Ok(())
}

#[test]
fn test_authorizer_empty_hmac() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "yubikey".to_string(),
        key_id: "test".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "".to_string(),
        nonce: "a".repeat(64),
    };

    let json = serde_json::to_string(&auth)?;
    let parsed: Authorizer = serde_json::from_str(&json)?;
    assert_eq!(parsed.hmac, "");
    Ok(())
}

#[test]
fn test_authorizer_unicode_format() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "yubikey_日本語".to_string(),
        key_id: "test".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let json = serde_json::to_string(&auth)?;
    let parsed: Authorizer = serde_json::from_str(&json)?;
    assert_eq!(parsed.format, "yubikey_日本語");
    Ok(())
}

#[test]
fn test_authorizer_unicode_key_id() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "キー🔑id".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let json = serde_json::to_string(&auth)?;
    let parsed: Authorizer = serde_json::from_str(&json)?;
    assert_eq!(parsed.key_id, "キー🔑id");
    Ok(())
}

#[test]
fn test_authorizer_long_key_id() -> Result<(), Box<dyn std::error::Error>> {
    let long_key = "k".repeat(10000);
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: long_key.clone(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let json = serde_json::to_string(&auth)?;
    let parsed: Authorizer = serde_json::from_str(&json)?;
    assert_eq!(parsed.key_id.len(), 10000);
    assert_eq!(parsed.key_id, long_key);
    Ok(())
}

#[test]
fn test_authorizer_timestamp_zero() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "yubikey".to_string(),
        key_id: "test".to_string(),
        challenge_id: None,
        timestamp: 0,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let json = serde_json::to_string(&auth)?;
    let parsed: Authorizer = serde_json::from_str(&json)?;
    assert_eq!(parsed.timestamp, 0);
    Ok(())
}

#[test]
fn test_authorizer_timestamp_max() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "yubikey".to_string(),
        key_id: "test".to_string(),
        challenge_id: None,
        timestamp: u64::MAX,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let json = serde_json::to_string(&auth)?;
    let parsed: Authorizer = serde_json::from_str(&json)?;
    assert_eq!(parsed.timestamp, u64::MAX);
    Ok(())
}

#[test]
fn test_authorizer_hmac_sha1_format() -> Result<(), Box<dyn std::error::Error>> {
    // SHA-1 HMAC is 40 hex chars (20 bytes)
    let auth = Authorizer {
        format: "yubikey".to_string(),
        key_id: "test".to_string(),
        challenge_id: Some("chal".to_string()),
        timestamp: 1000,
        hmac: "0123456789abcdef0123456789abcdef01234567".to_string(),
        nonce: "a".repeat(64),
    };

    let json = serde_json::to_string(&auth)?;
    let parsed: Authorizer = serde_json::from_str(&json)?;
    assert_eq!(parsed.hmac.len(), 40);
    Ok(())
}

#[test]
fn test_authorizer_hmac_sha256_format() -> Result<(), Box<dyn std::error::Error>> {
    // SHA-256 HMAC is 64 hex chars (32 bytes)
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "test".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        nonce: "a".repeat(64),
    };

    let json = serde_json::to_string(&auth)?;
    let parsed: Authorizer = serde_json::from_str(&json)?;
    assert_eq!(parsed.hmac.len(), 64);
    Ok(())
}

#[test]
fn test_authorizer_challenge_id_empty_string() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "yubikey".to_string(),
        key_id: "test".to_string(),
        challenge_id: Some("".to_string()),
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let json = serde_json::to_string(&auth)?;
    let parsed: Authorizer = serde_json::from_str(&json)?;
    assert_eq!(parsed.challenge_id, Some("".to_string()));
    Ok(())
}

#[test]
fn test_authorizer_challenge_id_unicode() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "yubikey".to_string(),
        key_id: "test".to_string(),
        challenge_id: Some("挑戦_🎯_challenge".to_string()),
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let json = serde_json::to_string(&auth)?;
    let parsed: Authorizer = serde_json::from_str(&json)?;
    assert_eq!(parsed.challenge_id, Some("挑戦_🎯_challenge".to_string()));
    Ok(())
}

#[test]
fn test_authorizer_missing_field_format() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"keyId":"test","timestamp":1000,"hmac":"abc","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let result = serde_json::from_str::<Authorizer>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_authorizer_missing_field_key_id() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"format":"yubikey","timestamp":1000,"hmac":"abc","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let result = serde_json::from_str::<Authorizer>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_authorizer_missing_field_timestamp() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"format":"yubikey","keyId":"test","hmac":"abc","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let result = serde_json::from_str::<Authorizer>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_authorizer_missing_field_hmac() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"format":"yubikey","keyId":"test","timestamp":1000,"nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let result = serde_json::from_str::<Authorizer>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_authorizer_missing_field_nonce() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"format":"yubikey","keyId":"test","timestamp":1000,"hmac":"abc"}"#;
    let result = serde_json::from_str::<Authorizer>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_authorizer_wrong_type_format() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"format":123,"keyId":"test","timestamp":1000,"hmac":"abc","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let result = serde_json::from_str::<Authorizer>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_authorizer_wrong_type_timestamp() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"format":"yubikey","keyId":"test","timestamp":"not_a_number","hmac":"abc","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let result = serde_json::from_str::<Authorizer>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_authorizer_wrong_type_hmac() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"format":"yubikey","keyId":"test","timestamp":1000,"hmac":999}"#;
    let result = serde_json::from_str::<Authorizer>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_authorizer_wrong_type_challenge_id() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"format":"yubikey","keyId":"test","timestamp":1000,"hmac":"abc","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","challenge_id":123}"#;
    let result = serde_json::from_str::<Authorizer>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_authorizer_clone_trait() -> Result<(), Box<dyn std::error::Error>> {
    let auth1 = Authorizer {
        format: "yubikey".to_string(),
        key_id: "test".to_string(),
        challenge_id: Some("chal".to_string()),
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let auth2 = auth1.clone();

    assert_eq!(auth2.format, auth1.format);
    assert_eq!(auth2.key_id, auth1.key_id);
    assert_eq!(auth2.challenge_id, auth1.challenge_id);
    assert_eq!(auth2.timestamp, auth1.timestamp);
    assert_eq!(auth2.hmac, auth1.hmac);
    Ok(())
}

#[test]
fn test_authorizer_debug_trait() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "yubikey".to_string(),
        key_id: "test".to_string(),
        challenge_id: Some("chal".to_string()),
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let debug_str = format!("{:?}", auth);
    assert!(debug_str.contains("Authorizer"));
    assert!(debug_str.contains("format"));
    assert!(debug_str.contains("yubikey"));
    Ok(())
}

#[test]
fn test_authorizer_multiple_roundtrips() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "api_key_123".to_string(),
        challenge_id: None,
        timestamp: 1700000000,
        hmac: "deadbeef".to_string(),
        nonce: "a".repeat(64),
    };

    // First roundtrip
    let json1 = serde_json::to_string(&auth)?;
    let parsed1: Authorizer = serde_json::from_str(&json1)?;

    // Second roundtrip
    let json2 = serde_json::to_string(&parsed1)?;
    let parsed2: Authorizer = serde_json::from_str(&json2)?;

    // Third roundtrip
    let json3 = serde_json::to_string(&parsed2)?;
    let parsed3: Authorizer = serde_json::from_str(&json3)?;

    assert_eq!(parsed3.format, "client");
    assert_eq!(parsed3.key_id, "api_key_123");
    assert_eq!(parsed3.challenge_id, None);
    Ok(())
}

#[test]
fn test_authorizer_special_chars_in_hmac() -> Result<(), Box<dyn std::error::Error>> {
    // HMAC should be hex, but test system doesn't validate format
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "test".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "GHIJKL!@#$%^&*()".to_string(),
        nonce: "a".repeat(64),
    };

    let json = serde_json::to_string(&auth)?;
    let parsed: Authorizer = serde_json::from_str(&json)?;
    assert_eq!(parsed.hmac, "GHIJKL!@#$%^&*()");
    Ok(())
}

#[test]
fn test_authorizer_escaped_chars_in_key_id() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "key\"with\\quotes\nand\ttabs".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let json = serde_json::to_string(&auth)?;
    assert!(json.contains("\\\""));
    assert!(json.contains("\\n"));
    assert!(json.contains("\\t"));

    let parsed: Authorizer = serde_json::from_str(&json)?;
    assert_eq!(parsed.key_id, "key\"with\\quotes\nand\ttabs");
    Ok(())
}

// ============================================================================
// SECTION 7: StartRequest comprehensive tests (30 tests)
// ============================================================================

#[test]
fn test_start_request_complete() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "client123".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "client".to_string(),
        authorizer: auth,
        schema: Some("provii.age/0".to_string()),
        validity_days: Some(365),
        kid: Some("key1".to_string()),
    };

    let json = serde_json::to_string(&req)?;
    let parsed: StartRequest = serde_json::from_str(&json)?;

    assert_eq!(parsed.actor, "client");
    assert_eq!(parsed.authorizer.format, "client");
    assert_eq!(parsed.schema, Some("provii.age/0".to_string()));
    assert_eq!(parsed.validity_days, Some(365));
    assert_eq!(parsed.kid, Some("key1".to_string()));
    Ok(())
}

#[test]
fn test_start_request_minimal() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "officer".to_string(),
        key_id: "off123".to_string(),
        challenge_id: Some("ch123".to_string()),
        timestamp: 1000,
        hmac: "xyz".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "officer".to_string(),
        authorizer: auth,
        schema: None,
        validity_days: None,
        kid: None,
    };

    let json = serde_json::to_string(&req)?;
    // Optional fields should be omitted
    assert!(!json.contains("\"schema\""));
    assert!(!json.contains("\"validity_days\""));
    assert!(!json.contains("\"kid\""));

    let parsed: StartRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.actor, "officer");
    assert_eq!(parsed.schema, None);
    assert_eq!(parsed.validity_days, None);
    assert_eq!(parsed.kid, None);
    Ok(())
}

#[test]
fn test_start_request_actor_empty() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "".to_string(),
        authorizer: auth,
        schema: None,
        validity_days: None,
        kid: None,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: StartRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.actor, "");
    Ok(())
}

#[test]
fn test_start_request_actor_unicode() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "オフィサー👮".to_string(),
        authorizer: auth,
        schema: None,
        validity_days: None,
        kid: None,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: StartRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.actor, "オフィサー👮");
    Ok(())
}

#[test]
fn test_start_request_actor_very_long() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let long_actor = "a".repeat(10000);
    let req = StartRequest {
        actor: long_actor.clone(),
        authorizer: auth,
        schema: None,
        validity_days: None,
        kid: None,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: StartRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.actor, long_actor);
    Ok(())
}

#[test]
fn test_start_request_missing_actor() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"authorizer":{"format":"client","keyId":"c1","timestamp":1000,"hmac":"abc","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#;
    let result = serde_json::from_str::<StartRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_start_request_wrong_type_actor() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"actor":123,"authorizer":{"format":"client","keyId":"c1","timestamp":1000,"hmac":"abc","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#;
    let result = serde_json::from_str::<StartRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_start_request_missing_authorizer() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"actor":"client"}"#;
    let result = serde_json::from_str::<StartRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_start_request_null_authorizer() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"actor":"client","authorizer":null}"#;
    let result = serde_json::from_str::<StartRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_start_request_wrong_type_authorizer() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"actor":"client","authorizer":"not an object"}"#;
    let result = serde_json::from_str::<StartRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_start_request_schema_present() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "client".to_string(),
        authorizer: auth,
        schema: Some("provii.age/0".to_string()),
        validity_days: None,
        kid: None,
    };

    let json = serde_json::to_string(&req)?;
    assert!(json.contains("\"schema\""));
    assert!(json.contains("provii.age/0"));
    Ok(())
}

#[test]
fn test_start_request_schema_absent() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "client".to_string(),
        authorizer: auth,
        schema: None,
        validity_days: None,
        kid: None,
    };

    let json = serde_json::to_string(&req)?;
    assert!(!json.contains("\"schema\""));
    Ok(())
}

#[test]
fn test_start_request_schema_empty_string() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "client".to_string(),
        authorizer: auth,
        schema: Some("".to_string()),
        validity_days: None,
        kid: None,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: StartRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.schema, Some("".to_string()));
    Ok(())
}

#[test]
fn test_start_request_schema_unicode() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "client".to_string(),
        authorizer: auth,
        schema: Some("スキーマ🔖.v2".to_string()),
        validity_days: None,
        kid: None,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: StartRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.schema, Some("スキーマ🔖.v2".to_string()));
    Ok(())
}

#[test]
fn test_start_request_validity_days_present() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "client".to_string(),
        authorizer: auth,
        schema: None,
        validity_days: Some(365),
        kid: None,
    };

    let json = serde_json::to_string(&req)?;
    assert!(json.contains("\"validity_days\""));
    assert!(json.contains("365"));
    Ok(())
}

#[test]
fn test_start_request_validity_days_absent() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "client".to_string(),
        authorizer: auth,
        schema: None,
        validity_days: None,
        kid: None,
    };

    let json = serde_json::to_string(&req)?;
    assert!(!json.contains("\"validity_days\""));
    Ok(())
}

#[test]
fn test_start_request_validity_days_zero() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "client".to_string(),
        authorizer: auth,
        schema: None,
        validity_days: Some(0),
        kid: None,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: StartRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.validity_days, Some(0));
    Ok(())
}

#[test]
fn test_start_request_validity_days_max() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "client".to_string(),
        authorizer: auth,
        schema: None,
        validity_days: Some(u32::MAX),
        kid: None,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: StartRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.validity_days, Some(u32::MAX));
    Ok(())
}

#[test]
fn test_start_request_kid_present() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "client".to_string(),
        authorizer: auth,
        schema: None,
        validity_days: None,
        kid: Some("key123".to_string()),
    };

    let json = serde_json::to_string(&req)?;
    assert!(json.contains("\"kid\""));
    assert!(json.contains("key123"));
    Ok(())
}

#[test]
fn test_start_request_kid_absent() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "client".to_string(),
        authorizer: auth,
        schema: None,
        validity_days: None,
        kid: None,
    };

    let json = serde_json::to_string(&req)?;
    assert!(!json.contains("\"kid\""));
    Ok(())
}

#[test]
fn test_start_request_kid_empty_string() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "client".to_string(),
        authorizer: auth,
        schema: None,
        validity_days: None,
        kid: Some("".to_string()),
    };

    let json = serde_json::to_string(&req)?;
    let parsed: StartRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.kid, Some("".to_string()));
    Ok(())
}

#[test]
fn test_start_request_kid_unicode() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "client".to_string(),
        authorizer: auth,
        schema: None,
        validity_days: None,
        kid: Some("キー🔑123".to_string()),
    };

    let json = serde_json::to_string(&req)?;
    let parsed: StartRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.kid, Some("キー🔑123".to_string()));
    Ok(())
}

#[test]
fn test_start_request_all_optional_present() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "client".to_string(),
        authorizer: auth,
        schema: Some("provii.age/0".to_string()),
        validity_days: Some(365),
        kid: Some("key1".to_string()),
    };

    let json = serde_json::to_string(&req)?;
    assert!(json.contains("\"schema\""));
    assert!(json.contains("\"validity_days\""));
    assert!(json.contains("\"kid\""));
    Ok(())
}

#[test]
fn test_start_request_all_optional_absent() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "client".to_string(),
        authorizer: auth,
        schema: None,
        validity_days: None,
        kid: None,
    };

    let json = serde_json::to_string(&req)?;
    assert!(!json.contains("\"schema\""));
    assert!(!json.contains("\"validity_days\""));
    assert!(!json.contains("\"kid\""));
    Ok(())
}

#[test]
fn test_start_request_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "officer".to_string(),
        key_id: "off123".to_string(),
        challenge_id: Some("ch456".to_string()),
        timestamp: 5000,
        hmac: "deadbeef".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "officer".to_string(),
        authorizer: auth,
        schema: Some("provii.age/0".to_string()),
        validity_days: Some(730),
        kid: Some("key2".to_string()),
    };

    let json = serde_json::to_string(&req)?;
    let parsed: StartRequest = serde_json::from_str(&json)?;
    let json2 = serde_json::to_string(&parsed)?;

    assert_eq!(json, json2);
    Ok(())
}

#[test]
fn test_start_request_multiple_roundtrips() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "client".to_string(),
        authorizer: auth,
        schema: Some("test".to_string()),
        validity_days: Some(365),
        kid: Some("k1".to_string()),
    };

    let json1 = serde_json::to_string(&req)?;
    let parsed1: StartRequest = serde_json::from_str(&json1)?;
    let json2 = serde_json::to_string(&parsed1)?;
    let parsed2: StartRequest = serde_json::from_str(&json2)?;
    let json3 = serde_json::to_string(&parsed2)?;

    assert_eq!(json1, json2);
    assert_eq!(json2, json3);
    Ok(())
}

#[test]
fn test_start_request_clone() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "client".to_string(),
        authorizer: auth,
        schema: Some("provii.age/0".to_string()),
        validity_days: Some(365),
        kid: Some("key1".to_string()),
    };

    let cloned = req.clone();
    assert_eq!(req.actor, cloned.actor);
    assert_eq!(req.authorizer.format, cloned.authorizer.format);
    assert_eq!(req.schema, cloned.schema);
    assert_eq!(req.validity_days, cloned.validity_days);
    assert_eq!(req.kid, cloned.kid);
    Ok(())
}

#[test]
fn test_start_request_debug() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = StartRequest {
        actor: "client".to_string(),
        authorizer: auth,
        schema: Some("provii.age/0".to_string()),
        validity_days: Some(365),
        kid: Some("key1".to_string()),
    };

    let debug = format!("{:?}", req);
    assert!(debug.contains("StartRequest"));
    assert!(debug.contains("client"));
    Ok(())
}

#[test]
fn test_start_request_wrong_type_validity_days() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"actor":"client","authorizer":{"format":"client","keyId":"c1","timestamp":1000,"hmac":"abc","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"validity_days":"not a number"}"#;
    let result = serde_json::from_str::<StartRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_start_request_wrong_type_kid() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"actor":"client","authorizer":{"format":"client","keyId":"c1","timestamp":1000,"hmac":"abc","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"kid":123}"#;
    let result = serde_json::from_str::<StartRequest>(json);
    assert!(result.is_err());
    Ok(())
}

// ============================================================================
// SECTION 8: StartResponse comprehensive tests (25 tests)
// ============================================================================

#[test]
fn test_start_response_complete() -> Result<(), Box<dyn std::error::Error>> {
    let resp = StartResponse {
        session_id: "sess123".to_string(),
        kid: "key1".to_string(),
        schema: "provii.age/0".to_string(),
        iat: 1700000000,
        exp: 1800000000,
        expires_at: 1800000000,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: StartResponse = serde_json::from_str(&json)?;

    assert_eq!(parsed.session_id, "sess123");
    assert_eq!(parsed.kid, "key1");
    assert_eq!(parsed.schema, "provii.age/0");
    assert_eq!(parsed.iat, 1700000000);
    assert_eq!(parsed.exp, 1800000000);
    assert_eq!(parsed.expires_at, 1800000000);
    Ok(())
}

#[test]
fn test_start_response_session_id_empty() -> Result<(), Box<dyn std::error::Error>> {
    let resp = StartResponse {
        session_id: "".to_string(),
        kid: "key1".to_string(),
        schema: "provii.age/0".to_string(),
        iat: 1000,
        exp: 2000,
        expires_at: 2000,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: StartResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.session_id, "");
    Ok(())
}

#[test]
fn test_start_response_session_id_unicode() -> Result<(), Box<dyn std::error::Error>> {
    let resp = StartResponse {
        session_id: "セッション🎫123".to_string(),
        kid: "key1".to_string(),
        schema: "provii.age/0".to_string(),
        iat: 1000,
        exp: 2000,
        expires_at: 2000,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: StartResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.session_id, "セッション🎫123");
    Ok(())
}

#[test]
fn test_start_response_session_id_very_long() -> Result<(), Box<dyn std::error::Error>> {
    let long_id = "s".repeat(10000);
    let resp = StartResponse {
        session_id: long_id.clone(),
        kid: "key1".to_string(),
        schema: "provii.age/0".to_string(),
        iat: 1000,
        exp: 2000,
        expires_at: 2000,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: StartResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.session_id, long_id);
    Ok(())
}

#[test]
fn test_start_response_kid_empty() -> Result<(), Box<dyn std::error::Error>> {
    let resp = StartResponse {
        session_id: "sess123".to_string(),
        kid: "".to_string(),
        schema: "provii.age/0".to_string(),
        iat: 1000,
        exp: 2000,
        expires_at: 2000,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: StartResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.kid, "");
    Ok(())
}

#[test]
fn test_start_response_kid_unicode() -> Result<(), Box<dyn std::error::Error>> {
    let resp = StartResponse {
        session_id: "sess123".to_string(),
        kid: "キー🔑id".to_string(),
        schema: "provii.age/0".to_string(),
        iat: 1000,
        exp: 2000,
        expires_at: 2000,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: StartResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.kid, "キー🔑id");
    Ok(())
}

#[test]
fn test_start_response_schema_empty() -> Result<(), Box<dyn std::error::Error>> {
    let resp = StartResponse {
        session_id: "sess123".to_string(),
        kid: "key1".to_string(),
        schema: "".to_string(),
        iat: 1000,
        exp: 2000,
        expires_at: 2000,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: StartResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.schema, "");
    Ok(())
}

#[test]
fn test_start_response_schema_unicode() -> Result<(), Box<dyn std::error::Error>> {
    let resp = StartResponse {
        session_id: "sess123".to_string(),
        kid: "key1".to_string(),
        schema: "スキーマ📋.v2".to_string(),
        iat: 1000,
        exp: 2000,
        expires_at: 2000,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: StartResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.schema, "スキーマ📋.v2");
    Ok(())
}

#[test]
fn test_start_response_missing_session_id() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"kid":"key1","schema":"provii.age/0","iat":1000,"exp":2000,"expires_at":2000}"#;
    let result = serde_json::from_str::<StartResponse>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_start_response_missing_kid() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"session_id":"sess123","schema":"provii.age/0","iat":1000,"exp":2000,"expires_at":2000}"#;
    let result = serde_json::from_str::<StartResponse>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_start_response_missing_schema() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"session_id":"sess123","kid":"key1","iat":1000,"exp":2000,"expires_at":2000}"#;
    let result = serde_json::from_str::<StartResponse>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_start_response_missing_iat() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"session_id":"sess123","kid":"key1","schema":"provii.age/0","exp":2000,"expires_at":2000}"#;
    let result = serde_json::from_str::<StartResponse>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_start_response_missing_exp() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"session_id":"sess123","kid":"key1","schema":"provii.age/0","iat":1000,"expires_at":2000}"#;
    let result = serde_json::from_str::<StartResponse>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_start_response_missing_expires_at() -> Result<(), Box<dyn std::error::Error>> {
    let json =
        r#"{"session_id":"sess123","kid":"key1","schema":"provii.age/0","iat":1000,"exp":2000}"#;
    let result = serde_json::from_str::<StartResponse>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_start_response_wrong_type_session_id() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"session_id":123,"kid":"key1","schema":"provii.age/0","iat":1000,"exp":2000,"expires_at":2000}"#;
    let result = serde_json::from_str::<StartResponse>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_start_response_wrong_type_iat() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"session_id":"sess123","kid":"key1","schema":"provii.age/0","iat":"not a number","exp":2000,"expires_at":2000}"#;
    let result = serde_json::from_str::<StartResponse>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_start_response_iat_zero() -> Result<(), Box<dyn std::error::Error>> {
    let resp = StartResponse {
        session_id: "sess123".to_string(),
        kid: "key1".to_string(),
        schema: "provii.age/0".to_string(),
        iat: 0,
        exp: 2000,
        expires_at: 2000,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: StartResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.iat, 0);
    Ok(())
}

#[test]
fn test_start_response_iat_max() -> Result<(), Box<dyn std::error::Error>> {
    let resp = StartResponse {
        session_id: "sess123".to_string(),
        kid: "key1".to_string(),
        schema: "provii.age/0".to_string(),
        iat: u64::MAX,
        exp: u64::MAX,
        expires_at: i64::MAX,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: StartResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.iat, u64::MAX);
    Ok(())
}

#[test]
fn test_start_response_expires_at_negative() -> Result<(), Box<dyn std::error::Error>> {
    let resp = StartResponse {
        session_id: "sess123".to_string(),
        kid: "key1".to_string(),
        schema: "provii.age/0".to_string(),
        iat: 1000,
        exp: 2000,
        expires_at: -1000,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: StartResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.expires_at, -1000);
    Ok(())
}

#[test]
fn test_start_response_expires_at_min() -> Result<(), Box<dyn std::error::Error>> {
    let resp = StartResponse {
        session_id: "sess123".to_string(),
        kid: "key1".to_string(),
        schema: "provii.age/0".to_string(),
        iat: 0,
        exp: 0,
        expires_at: i64::MIN,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: StartResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.expires_at, i64::MIN);
    Ok(())
}

#[test]
fn test_start_response_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let resp = StartResponse {
        session_id: "sess456".to_string(),
        kid: "key2".to_string(),
        schema: "provii.age.v3".to_string(),
        iat: 1700000000,
        exp: 1800000000,
        expires_at: 1800000000,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: StartResponse = serde_json::from_str(&json)?;
    let json2 = serde_json::to_string(&parsed)?;

    assert_eq!(json, json2);
    Ok(())
}

#[test]
fn test_start_response_multiple_roundtrips() -> Result<(), Box<dyn std::error::Error>> {
    let resp = StartResponse {
        session_id: "sess789".to_string(),
        kid: "key3".to_string(),
        schema: "test.schema".to_string(),
        iat: 1000,
        exp: 2000,
        expires_at: 2000,
    };

    let json1 = serde_json::to_string(&resp)?;
    let parsed1: StartResponse = serde_json::from_str(&json1)?;
    let json2 = serde_json::to_string(&parsed1)?;
    let parsed2: StartResponse = serde_json::from_str(&json2)?;
    let json3 = serde_json::to_string(&parsed2)?;

    assert_eq!(json1, json2);
    assert_eq!(json2, json3);
    Ok(())
}

#[test]
fn test_start_response_clone() -> Result<(), Box<dyn std::error::Error>> {
    let resp = StartResponse {
        session_id: "sess123".to_string(),
        kid: "key1".to_string(),
        schema: "provii.age/0".to_string(),
        iat: 1700000000,
        exp: 1800000000,
        expires_at: 1800000000,
    };

    let cloned = resp.clone();
    assert_eq!(resp.session_id, cloned.session_id);
    assert_eq!(resp.kid, cloned.kid);
    assert_eq!(resp.schema, cloned.schema);
    assert_eq!(resp.iat, cloned.iat);
    assert_eq!(resp.exp, cloned.exp);
    assert_eq!(resp.expires_at, cloned.expires_at);
    Ok(())
}

#[test]
fn test_start_response_debug() -> Result<(), Box<dyn std::error::Error>> {
    let resp = StartResponse {
        session_id: "sess123".to_string(),
        kid: "key1".to_string(),
        schema: "provii.age/0".to_string(),
        iat: 1700000000,
        exp: 1800000000,
        expires_at: 1800000000,
    };

    let debug = format!("{:?}", resp);
    assert!(debug.contains("StartResponse"));
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("sess123"));
    Ok(())
}

// ============================================================================
// SECTION 9: ChallengeRequest comprehensive tests (10 tests)
// ============================================================================

#[test]
fn test_challenge_request_complete() -> Result<(), Box<dyn std::error::Error>> {
    let req = ChallengeRequest {
        officer_id: "officer123".to_string(),
    };

    let json = serde_json::to_string(&req)?;
    let parsed: ChallengeRequest = serde_json::from_str(&json)?;

    assert_eq!(parsed.officer_id, "officer123");
    Ok(())
}

#[test]
fn test_challenge_request_officer_id_empty() -> Result<(), Box<dyn std::error::Error>> {
    let req = ChallengeRequest {
        officer_id: "".to_string(),
    };

    let json = serde_json::to_string(&req)?;
    let parsed: ChallengeRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.officer_id, "");
    Ok(())
}

#[test]
fn test_challenge_request_officer_id_unicode() -> Result<(), Box<dyn std::error::Error>> {
    let req = ChallengeRequest {
        officer_id: "オフィサー👮123".to_string(),
    };

    let json = serde_json::to_string(&req)?;
    let parsed: ChallengeRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.officer_id, "オフィサー👮123");
    Ok(())
}

#[test]
fn test_challenge_request_officer_id_very_long() -> Result<(), Box<dyn std::error::Error>> {
    let long_id = "o".repeat(10000);
    let req = ChallengeRequest {
        officer_id: long_id.clone(),
    };

    let json = serde_json::to_string(&req)?;
    let parsed: ChallengeRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.officer_id, long_id);
    Ok(())
}

#[test]
fn test_challenge_request_missing_officer_id() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{}"#;
    let result = serde_json::from_str::<ChallengeRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_challenge_request_wrong_type_officer_id() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"officer_id":123}"#;
    let result = serde_json::from_str::<ChallengeRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_challenge_request_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let req = ChallengeRequest {
        officer_id: "off456".to_string(),
    };

    let json = serde_json::to_string(&req)?;
    let parsed: ChallengeRequest = serde_json::from_str(&json)?;
    let json2 = serde_json::to_string(&parsed)?;

    assert_eq!(json, json2);
    Ok(())
}

#[test]
fn test_challenge_request_clone() -> Result<(), Box<dyn std::error::Error>> {
    let req = ChallengeRequest {
        officer_id: "officer123".to_string(),
    };

    let cloned = req.clone();
    assert_eq!(req.officer_id, cloned.officer_id);
    Ok(())
}

#[test]
fn test_challenge_request_debug() -> Result<(), Box<dyn std::error::Error>> {
    let req = ChallengeRequest {
        officer_id: "officer123".to_string(),
    };

    let debug = format!("{:?}", req);
    assert!(debug.contains("ChallengeRequest"));
    assert!(debug.contains("officer123"));
    Ok(())
}

#[test]
fn test_challenge_request_null_officer_id() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"officer_id":null}"#;
    let result = serde_json::from_str::<ChallengeRequest>(json);
    assert!(result.is_err());
    Ok(())
}

// ============================================================================
// SECTION 10: ChallengeResponse comprehensive tests (15 tests)
// ============================================================================

#[test]
fn test_challenge_response_complete() -> Result<(), Box<dyn std::error::Error>> {
    let resp = ChallengeResponse {
        challenge_id: "ch123".to_string(),
        challenge: "deadbeef".to_string(),
        expires_at: 1800000000,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: ChallengeResponse = serde_json::from_str(&json)?;

    assert_eq!(parsed.challenge_id, "ch123");
    assert_eq!(parsed.challenge, "deadbeef");
    assert_eq!(parsed.expires_at, 1800000000);
    Ok(())
}

#[test]
fn test_challenge_response_challenge_id_empty() -> Result<(), Box<dyn std::error::Error>> {
    let resp = ChallengeResponse {
        challenge_id: "".to_string(),
        challenge: "abc".to_string(),
        expires_at: 1000,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: ChallengeResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.challenge_id, "");
    Ok(())
}

#[test]
fn test_challenge_response_challenge_id_unicode() -> Result<(), Box<dyn std::error::Error>> {
    let resp = ChallengeResponse {
        challenge_id: "チャレンジ🎯123".to_string(),
        challenge: "abc".to_string(),
        expires_at: 1000,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: ChallengeResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.challenge_id, "チャレンジ🎯123");
    Ok(())
}

#[test]
fn test_challenge_response_challenge_hex_empty() -> Result<(), Box<dyn std::error::Error>> {
    let resp = ChallengeResponse {
        challenge_id: "ch123".to_string(),
        challenge: "".to_string(),
        expires_at: 1000,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: ChallengeResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.challenge, "");
    Ok(())
}

#[test]
fn test_challenge_response_challenge_hex_long() -> Result<(), Box<dyn std::error::Error>> {
    let long_hex = "abcdef0123456789".repeat(1000);
    let resp = ChallengeResponse {
        challenge_id: "ch123".to_string(),
        challenge: long_hex.clone(),
        expires_at: 1000,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: ChallengeResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.challenge, long_hex);
    Ok(())
}

#[test]
fn test_challenge_response_expires_at_zero() -> Result<(), Box<dyn std::error::Error>> {
    let resp = ChallengeResponse {
        challenge_id: "ch123".to_string(),
        challenge: "abc".to_string(),
        expires_at: 0,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: ChallengeResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.expires_at, 0);
    Ok(())
}

#[test]
fn test_challenge_response_expires_at_negative() -> Result<(), Box<dyn std::error::Error>> {
    let resp = ChallengeResponse {
        challenge_id: "ch123".to_string(),
        challenge: "abc".to_string(),
        expires_at: -1000,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: ChallengeResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.expires_at, -1000);
    Ok(())
}

#[test]
fn test_challenge_response_expires_at_max() -> Result<(), Box<dyn std::error::Error>> {
    let resp = ChallengeResponse {
        challenge_id: "ch123".to_string(),
        challenge: "abc".to_string(),
        expires_at: i64::MAX,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: ChallengeResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.expires_at, i64::MAX);
    Ok(())
}

#[test]
fn test_challenge_response_missing_challenge_id() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"challenge":"abc","expires_at":1000}"#;
    let result = serde_json::from_str::<ChallengeResponse>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_challenge_response_missing_challenge() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"challenge_id":"ch123","expires_at":1000}"#;
    let result = serde_json::from_str::<ChallengeResponse>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_challenge_response_missing_expires_at() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"challenge_id":"ch123","challenge":"abc"}"#;
    let result = serde_json::from_str::<ChallengeResponse>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_challenge_response_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let resp = ChallengeResponse {
        challenge_id: "ch456".to_string(),
        challenge: "0123456789abcdef".to_string(),
        expires_at: 1700000000,
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: ChallengeResponse = serde_json::from_str(&json)?;
    let json2 = serde_json::to_string(&parsed)?;

    assert_eq!(json, json2);
    Ok(())
}

#[test]
fn test_challenge_response_clone() -> Result<(), Box<dyn std::error::Error>> {
    let resp = ChallengeResponse {
        challenge_id: "ch123".to_string(),
        challenge: "deadbeef".to_string(),
        expires_at: 1800000000,
    };

    let cloned = resp.clone();
    assert_eq!(resp.challenge_id, cloned.challenge_id);
    assert_eq!(resp.challenge, cloned.challenge);
    assert_eq!(resp.expires_at, cloned.expires_at);
    Ok(())
}

#[test]
fn test_challenge_response_debug() -> Result<(), Box<dyn std::error::Error>> {
    let resp = ChallengeResponse {
        challenge_id: "ch123".to_string(),
        challenge: "deadbeef".to_string(),
        expires_at: 1800000000,
    };

    let debug = format!("{:?}", resp);
    assert!(debug.contains("ChallengeResponse"));
    assert!(debug.contains("ch123"));
    Ok(())
}

#[test]
fn test_challenge_response_wrong_type_expires_at() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"challenge_id":"ch123","challenge":"abc","expires_at":"not a number"}"#;
    let result = serde_json::from_str::<ChallengeResponse>(json);
    assert!(result.is_err());
    Ok(())
}

// ============================================================================
// SECTION 11: SignCommitmentRequest comprehensive tests (18 tests)
// ============================================================================

#[test]
fn test_sign_commitment_request_complete() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "yubikey".to_string(),
        key_id: "off123".to_string(),
        challenge_id: Some("ch456".to_string()),
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = SignCommitmentRequest {
        session_id: "sess123".to_string(),
        commitment: [42u8; 32],
        authorizer: auth,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: SignCommitmentRequest = serde_json::from_str(&json)?;

    assert_eq!(parsed.session_id, "sess123");
    assert_eq!(parsed.commitment, [42u8; 32]);
    assert_eq!(parsed.authorizer.format, "yubikey");
    Ok(())
}

#[test]
fn test_sign_commitment_request_session_id_empty() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = SignCommitmentRequest {
        session_id: "".to_string(),
        commitment: [0u8; 32],
        authorizer: auth,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: SignCommitmentRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.session_id, "");
    Ok(())
}

#[test]
fn test_sign_commitment_request_session_id_unicode() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = SignCommitmentRequest {
        session_id: "セッション📝123".to_string(),
        commitment: [1u8; 32],
        authorizer: auth,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: SignCommitmentRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.session_id, "セッション📝123");
    Ok(())
}

#[test]
fn test_sign_commitment_request_commitment_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = SignCommitmentRequest {
        session_id: "sess123".to_string(),
        commitment: [0u8; 32],
        authorizer: auth,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: SignCommitmentRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.commitment, [0u8; 32]);
    Ok(())
}

#[test]
fn test_sign_commitment_request_commitment_all_max() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = SignCommitmentRequest {
        session_id: "sess123".to_string(),
        commitment: [255u8; 32],
        authorizer: auth,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: SignCommitmentRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.commitment, [255u8; 32]);
    Ok(())
}

#[test]
fn test_sign_commitment_request_commitment_sequential() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let mut commitment = [0u8; 32];
    for (i, byte) in commitment.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }

    let req = SignCommitmentRequest {
        session_id: "sess123".to_string(),
        commitment,
        authorizer: auth,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: SignCommitmentRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.commitment, commitment);
    Ok(())
}

#[test]
fn test_sign_commitment_request_commitment_base64_encoding(
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = SignCommitmentRequest {
        session_id: "sess123".to_string(),
        commitment: [42u8; 32],
        authorizer: auth,
    };

    let json = serde_json::to_string(&req)?;
    // Should be base64url encoded
    assert!(json.contains("\"commitment\""));
    // Should not have padding
    assert!(!json.contains("="));
    Ok(())
}

#[test]
fn test_sign_commitment_request_missing_session_id() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"commitment":"KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKg","authorizer":{"format":"client","keyId":"c1","timestamp":1000,"hmac":"abc","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#;
    let result = serde_json::from_str::<SignCommitmentRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_sign_commitment_request_missing_commitment() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"session_id":"sess123","authorizer":{"format":"client","keyId":"c1","timestamp":1000,"hmac":"abc","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#;
    let result = serde_json::from_str::<SignCommitmentRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_sign_commitment_request_missing_authorizer() -> Result<(), Box<dyn std::error::Error>> {
    let json =
        r#"{"session_id":"sess123","commitment":"KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKg"}"#;
    let result = serde_json::from_str::<SignCommitmentRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_sign_commitment_request_wrong_type_session_id() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"session_id":123,"commitment":"KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKg","authorizer":{"format":"client","keyId":"c1","timestamp":1000,"hmac":"abc","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#;
    let result = serde_json::from_str::<SignCommitmentRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_sign_commitment_request_wrong_type_commitment() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"session_id":"sess123","commitment":123,"authorizer":{"format":"client","keyId":"c1","timestamp":1000,"hmac":"abc","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#;
    let result = serde_json::from_str::<SignCommitmentRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_sign_commitment_request_invalid_base64_commitment() -> Result<(), Box<dyn std::error::Error>>
{
    let json = r#"{"session_id":"sess123","commitment":"not valid base64!!!","authorizer":{"format":"client","keyId":"c1","timestamp":1000,"hmac":"abc","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#;
    let result = serde_json::from_str::<SignCommitmentRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_sign_commitment_request_wrong_length_commitment() -> Result<(), Box<dyn std::error::Error>>
{
    // Base64 for 16 bytes instead of 32
    let json = r#"{"session_id":"sess123","commitment":"KioqKioqKioqKioqKioqKg","authorizer":{"format":"client","keyId":"c1","timestamp":1000,"hmac":"abc","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#;
    let result = serde_json::from_str::<SignCommitmentRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_sign_commitment_request_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "yubikey".to_string(),
        key_id: "off456".to_string(),
        challenge_id: Some("ch789".to_string()),
        timestamp: 5000,
        hmac: "xyz".to_string(),
        nonce: "a".repeat(64),
    };

    let req = SignCommitmentRequest {
        session_id: "sess456".to_string(),
        commitment: [100u8; 32],
        authorizer: auth,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: SignCommitmentRequest = serde_json::from_str(&json)?;
    let json2 = serde_json::to_string(&parsed)?;

    assert_eq!(json, json2);
    Ok(())
}

#[test]
fn test_sign_commitment_request_clone() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = SignCommitmentRequest {
        session_id: "sess123".to_string(),
        commitment: [42u8; 32],
        authorizer: auth,
    };

    let cloned = req.clone();
    assert_eq!(req.session_id, cloned.session_id);
    assert_eq!(req.commitment, cloned.commitment);
    assert_eq!(req.authorizer.format, cloned.authorizer.format);
    Ok(())
}

#[test]
fn test_sign_commitment_request_debug() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Authorizer {
        format: "client".to_string(),
        key_id: "c1".to_string(),
        challenge_id: None,
        timestamp: 1000,
        hmac: "abc".to_string(),
        nonce: "a".repeat(64),
    };

    let req = SignCommitmentRequest {
        session_id: "sess123".to_string(),
        commitment: [42u8; 32],
        authorizer: auth,
    };

    let debug = format!("{:?}", req);
    assert!(debug.contains("SignCommitmentRequest"));
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("sess123"));
    Ok(())
}

#[test]
fn test_sign_commitment_request_null_authorizer() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"session_id":"sess123","commitment":"KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKg","authorizer":null}"#;
    let result = serde_json::from_str::<SignCommitmentRequest>(json);
    assert!(result.is_err());
    Ok(())
}

// ============================================================================
// SECTION 12: SignCommitmentResponse comprehensive tests (8 tests)
// ============================================================================

#[test]
fn test_sign_commitment_response_complete() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 2,
        kid: "key1".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [42u8; 64],
        c_bytes: [2u8; 32],
        iat: 1700000000,
        exp: 1800000000,
        schema: "provii.age/0".to_string(),
    };

    let resp = SignCommitmentResponse { credential: header };

    let json = serde_json::to_string(&resp)?;
    let parsed: SignCommitmentResponse = serde_json::from_str(&json)?;

    assert_eq!(parsed.credential.v, 2);
    assert_eq!(parsed.credential.kid, "key1");
    assert_eq!(parsed.credential.schema, "provii.age/0");
    Ok(())
}

#[test]
fn test_sign_commitment_response_missing_credential() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{}"#;
    let result = serde_json::from_str::<SignCommitmentResponse>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_sign_commitment_response_wrong_type_credential() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"credential":"not an object"}"#;
    let result = serde_json::from_str::<SignCommitmentResponse>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_sign_commitment_response_null_credential() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"credential":null}"#;
    let result = serde_json::from_str::<SignCommitmentResponse>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_sign_commitment_response_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 2,
        kid: "key2".to_string(),
        issuer_vk: [3u8; 32],
        sig_rj: [99u8; 64],
        c_bytes: [4u8; 32],
        iat: 1700000000,
        exp: 1800000000,
        schema: "provii.age/0".to_string(),
    };

    let resp = SignCommitmentResponse { credential: header };

    let json = serde_json::to_string(&resp)?;
    let parsed: SignCommitmentResponse = serde_json::from_str(&json)?;
    let json2 = serde_json::to_string(&parsed)?;

    assert_eq!(json, json2);
    Ok(())
}

#[test]
fn test_sign_commitment_response_clone() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 2,
        kid: "key1".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [42u8; 64],
        c_bytes: [2u8; 32],
        iat: 1700000000,
        exp: 1800000000,
        schema: "provii.age/0".to_string(),
    };

    let resp = SignCommitmentResponse { credential: header };

    let cloned = resp.clone();
    assert_eq!(resp.credential.v, cloned.credential.v);
    assert_eq!(resp.credential.kid, cloned.credential.kid);
    assert_eq!(resp.credential.sig_rj, cloned.credential.sig_rj);
    Ok(())
}

#[test]
fn test_sign_commitment_response_debug() -> Result<(), Box<dyn std::error::Error>> {
    let header = SignedCredentialHeader {
        v: 2,
        kid: "key1".to_string(),
        issuer_vk: [1u8; 32],
        sig_rj: [42u8; 64],
        c_bytes: [2u8; 32],
        iat: 1700000000,
        exp: 1800000000,
        schema: "provii.age/0".to_string(),
    };

    let resp = SignCommitmentResponse { credential: header };

    let debug = format!("{:?}", resp);
    assert!(debug.contains("SignCommitmentResponse"));
    Ok(())
}

#[test]
fn test_sign_commitment_response_malformed_credential() -> Result<(), Box<dyn std::error::Error>> {
    // Missing required field in nested credential
    let json = r#"{"credential":{"v":2,"kid":"test"}}"#;
    let result = serde_json::from_str::<SignCommitmentResponse>(json);
    assert!(result.is_err());
    Ok(())
}

// ============================================================================
// SECTION 13: QrChallengePayload comprehensive tests (30 tests)
// ============================================================================

#[test]
fn test_qr_challenge_payload_complete() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "ch123".to_string(),
        rp_challenge: "abc123xyz".to_string(),
        cutoff_days: 19000,
        verifying_key_id: 1,
        submit_secret: "secret123".to_string(),
        expires_at: 1800000000,
        verify_url: "https://verify.example.com".to_string(),
        code_verifier: Some("verifier123".to_string()),
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    let parsed: QrChallengePayload = serde_json::from_str(&json)?;

    assert_eq!(parsed.challenge_id, "ch123");
    assert_eq!(parsed.cutoff_days, 19000);
    assert_eq!(parsed.code_verifier, Some("verifier123".to_string()));
    Ok(())
}

#[test]
fn test_qr_challenge_payload_minimal() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "ch123".to_string(),
        rp_challenge: "abc".to_string(),
        cutoff_days: 6570,
        verifying_key_id: 1,
        submit_secret: "sec".to_string(),
        expires_at: 1800000000,
        verify_url: "https://verify.example.com".to_string(),
        code_verifier: None,
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    assert!(!json.contains("\"code_verifier\""));

    let parsed: QrChallengePayload = serde_json::from_str(&json)?;
    assert_eq!(parsed.code_verifier, None);
    Ok(())
}

#[test]
fn test_qr_challenge_payload_challenge_id_empty() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "".to_string(),
        rp_challenge: "abc".to_string(),
        cutoff_days: 6570,
        verifying_key_id: 1,
        submit_secret: "sec".to_string(),
        expires_at: 1800000000,
        verify_url: "https://verify.example.com".to_string(),
        code_verifier: None,
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    let parsed: QrChallengePayload = serde_json::from_str(&json)?;
    assert_eq!(parsed.challenge_id, "");
    Ok(())
}

#[test]
fn test_qr_challenge_payload_challenge_id_unicode() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "チャレンジ🎯123".to_string(),
        rp_challenge: "abc".to_string(),
        cutoff_days: 6570,
        verifying_key_id: 1,
        submit_secret: "sec".to_string(),
        expires_at: 1800000000,
        verify_url: "https://verify.example.com".to_string(),
        code_verifier: None,
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    let parsed: QrChallengePayload = serde_json::from_str(&json)?;
    assert_eq!(parsed.challenge_id, "チャレンジ🎯123");
    Ok(())
}

#[test]
fn test_qr_challenge_payload_rp_challenge_empty() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "ch123".to_string(),
        rp_challenge: "".to_string(),
        cutoff_days: 6570,
        verifying_key_id: 1,
        submit_secret: "sec".to_string(),
        expires_at: 1800000000,
        verify_url: "https://verify.example.com".to_string(),
        code_verifier: None,
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    let parsed: QrChallengePayload = serde_json::from_str(&json)?;
    assert_eq!(parsed.rp_challenge, "");
    Ok(())
}

#[test]
fn test_qr_challenge_payload_cutoff_days_zero() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "ch123".to_string(),
        rp_challenge: "abc".to_string(),
        cutoff_days: 0,
        verifying_key_id: 1,
        submit_secret: "sec".to_string(),
        expires_at: 1800000000,
        verify_url: "https://verify.example.com".to_string(),
        code_verifier: None,
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    let parsed: QrChallengePayload = serde_json::from_str(&json)?;
    assert_eq!(parsed.cutoff_days, 0);
    Ok(())
}

#[test]
fn test_qr_challenge_payload_cutoff_days_max() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "ch123".to_string(),
        rp_challenge: "abc".to_string(),
        cutoff_days: i32::MAX,
        verifying_key_id: 1,
        submit_secret: "sec".to_string(),
        expires_at: 1800000000,
        verify_url: "https://verify.example.com".to_string(),
        code_verifier: None,
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    let parsed: QrChallengePayload = serde_json::from_str(&json)?;
    assert_eq!(parsed.cutoff_days, i32::MAX);
    Ok(())
}

#[test]
fn test_qr_challenge_payload_verifying_key_id_zero() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "ch123".to_string(),
        rp_challenge: "abc".to_string(),
        cutoff_days: 6570,
        verifying_key_id: 0,
        submit_secret: "sec".to_string(),
        expires_at: 1800000000,
        verify_url: "https://verify.example.com".to_string(),
        code_verifier: None,
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    let parsed: QrChallengePayload = serde_json::from_str(&json)?;
    assert_eq!(parsed.verifying_key_id, 0);
    Ok(())
}

#[test]
fn test_qr_challenge_payload_verifying_key_id_max() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "ch123".to_string(),
        rp_challenge: "abc".to_string(),
        cutoff_days: 6570,
        verifying_key_id: u32::MAX,
        submit_secret: "sec".to_string(),
        expires_at: 1800000000,
        verify_url: "https://verify.example.com".to_string(),
        code_verifier: None,
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    let parsed: QrChallengePayload = serde_json::from_str(&json)?;
    assert_eq!(parsed.verifying_key_id, u32::MAX);
    Ok(())
}

#[test]
fn test_qr_challenge_payload_submit_secret_empty() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "ch123".to_string(),
        rp_challenge: "abc".to_string(),
        cutoff_days: 6570,
        verifying_key_id: 1,
        submit_secret: "".to_string(),
        expires_at: 1800000000,
        verify_url: "https://verify.example.com".to_string(),
        code_verifier: None,
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    let parsed: QrChallengePayload = serde_json::from_str(&json)?;
    assert_eq!(parsed.submit_secret, "");
    Ok(())
}

#[test]
fn test_qr_challenge_payload_expires_at_zero() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "ch123".to_string(),
        rp_challenge: "abc".to_string(),
        cutoff_days: 6570,
        verifying_key_id: 1,
        submit_secret: "sec".to_string(),
        expires_at: 0,
        verify_url: "https://verify.example.com".to_string(),
        code_verifier: None,
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    let parsed: QrChallengePayload = serde_json::from_str(&json)?;
    assert_eq!(parsed.expires_at, 0);
    Ok(())
}

#[test]
fn test_qr_challenge_payload_expires_at_max() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "ch123".to_string(),
        rp_challenge: "abc".to_string(),
        cutoff_days: 6570,
        verifying_key_id: 1,
        submit_secret: "sec".to_string(),
        expires_at: u64::MAX,
        verify_url: "https://verify.example.com".to_string(),
        code_verifier: None,
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    let parsed: QrChallengePayload = serde_json::from_str(&json)?;
    assert_eq!(parsed.expires_at, u64::MAX);
    Ok(())
}

#[test]
fn test_qr_challenge_payload_verify_url_empty() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "ch123".to_string(),
        rp_challenge: "abc".to_string(),
        cutoff_days: 6570,
        verifying_key_id: 1,
        submit_secret: "sec".to_string(),
        expires_at: 1800000000,
        verify_url: "".to_string(),
        code_verifier: None,
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    let parsed: QrChallengePayload = serde_json::from_str(&json)?;
    assert_eq!(parsed.verify_url, "");
    Ok(())
}

#[test]
fn test_qr_challenge_payload_verify_url_unicode() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "ch123".to_string(),
        rp_challenge: "abc".to_string(),
        cutoff_days: 6570,
        verifying_key_id: 1,
        submit_secret: "sec".to_string(),
        expires_at: 1800000000,
        verify_url: "https://検証.example.com/パス".to_string(),
        code_verifier: None,
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    let parsed: QrChallengePayload = serde_json::from_str(&json)?;
    assert_eq!(parsed.verify_url, "https://検証.example.com/パス");
    Ok(())
}

#[test]
fn test_qr_challenge_payload_code_verifier_present() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "ch123".to_string(),
        rp_challenge: "abc".to_string(),
        cutoff_days: 6570,
        verifying_key_id: 1,
        submit_secret: "sec".to_string(),
        expires_at: 1800000000,
        verify_url: "https://verify.example.com".to_string(),
        code_verifier: Some("pkce123".to_string()),
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    assert!(json.contains("\"code_verifier\""));
    assert!(json.contains("pkce123"));
    Ok(())
}

#[test]
fn test_qr_challenge_payload_code_verifier_absent() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "ch123".to_string(),
        rp_challenge: "abc".to_string(),
        cutoff_days: 6570,
        verifying_key_id: 1,
        submit_secret: "sec".to_string(),
        expires_at: 1800000000,
        verify_url: "https://verify.example.com".to_string(),
        code_verifier: None,
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    assert!(!json.contains("\"code_verifier\""));
    Ok(())
}

#[test]
fn test_qr_challenge_payload_code_verifier_empty_string() -> Result<(), Box<dyn std::error::Error>>
{
    let payload = QrChallengePayload {
        challenge_id: "ch123".to_string(),
        rp_challenge: "abc".to_string(),
        cutoff_days: 6570,
        verifying_key_id: 1,
        submit_secret: "sec".to_string(),
        expires_at: 1800000000,
        verify_url: "https://verify.example.com".to_string(),
        code_verifier: Some("".to_string()),
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    let parsed: QrChallengePayload = serde_json::from_str(&json)?;
    assert_eq!(parsed.code_verifier, Some("".to_string()));
    Ok(())
}

#[test]
fn test_qr_challenge_payload_missing_challenge_id() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"rp_challenge":"abc","cutoff_days":6570,"verifying_key_id":1,"submit_secret":"sec","expires_at":1800000000,"verify_url":"https://verify.example.com"}"#;
    let result = serde_json::from_str::<QrChallengePayload>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_qr_challenge_payload_missing_rp_challenge() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"challenge_id":"ch123","cutoff_days":6570,"verifying_key_id":1,"submit_secret":"sec","expires_at":1800000000,"verify_url":"https://verify.example.com"}"#;
    let result = serde_json::from_str::<QrChallengePayload>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_qr_challenge_payload_missing_cutoff_days() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"challenge_id":"ch123","rp_challenge":"abc","verifying_key_id":1,"submit_secret":"sec","expires_at":1800000000,"verify_url":"https://verify.example.com"}"#;
    let result = serde_json::from_str::<QrChallengePayload>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_qr_challenge_payload_missing_verifying_key_id() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"challenge_id":"ch123","rp_challenge":"abc","cutoff_days":6570,"submit_secret":"sec","expires_at":1800000000,"verify_url":"https://verify.example.com"}"#;
    let result = serde_json::from_str::<QrChallengePayload>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_qr_challenge_payload_wrong_type_cutoff_days() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"challenge_id":"ch123","rp_challenge":"abc","cutoff_days":"not a number","verifying_key_id":1,"submit_secret":"sec","expires_at":1800000000,"verify_url":"https://verify.example.com"}"#;
    let result = serde_json::from_str::<QrChallengePayload>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_qr_challenge_payload_wrong_type_verifying_key_id() -> Result<(), Box<dyn std::error::Error>>
{
    let json = r#"{"challenge_id":"ch123","rp_challenge":"abc","cutoff_days":6570,"verifying_key_id":"not a number","submit_secret":"sec","expires_at":1800000000,"verify_url":"https://verify.example.com"}"#;
    let result = serde_json::from_str::<QrChallengePayload>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_qr_challenge_payload_roundtrip_comprehensive() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "ch456".to_string(),
        rp_challenge: "xyz789".to_string(),
        cutoff_days: 7300,
        verifying_key_id: 2,
        submit_secret: "secret456".to_string(),
        expires_at: 1900000000,
        verify_url: "https://verify2.example.com".to_string(),
        code_verifier: Some("verifier456".to_string()),
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    let parsed: QrChallengePayload = serde_json::from_str(&json)?;
    let json2 = serde_json::to_string(&parsed)?;

    assert_eq!(json, json2);
    Ok(())
}

#[test]
fn test_qr_challenge_payload_clone() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "ch123".to_string(),
        rp_challenge: "abc123xyz".to_string(),
        cutoff_days: 19000,
        verifying_key_id: 1,
        submit_secret: "secret123".to_string(),
        expires_at: 1800000000,
        verify_url: "https://verify.example.com".to_string(),
        code_verifier: Some("verifier123".to_string()),
        proof_direction: None,
    };

    let cloned = payload.clone();
    assert_eq!(payload.challenge_id, cloned.challenge_id);
    assert_eq!(payload.cutoff_days, cloned.cutoff_days);
    assert_eq!(payload.code_verifier, cloned.code_verifier);
    Ok(())
}

#[test]
fn test_qr_challenge_payload_debug() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "ch123".to_string(),
        rp_challenge: "abc".to_string(),
        cutoff_days: 6570,
        verifying_key_id: 1,
        submit_secret: "sec".to_string(),
        expires_at: 1800000000,
        verify_url: "https://verify.example.com".to_string(),
        code_verifier: None,
        proof_direction: None,
    };

    let debug = format!("{:?}", payload);
    assert!(debug.contains("QrChallengePayload"));
    assert!(debug.contains("ch123"));
    Ok(())
}

#[test]
fn test_qr_challenge_payload_multiple_roundtrips() -> Result<(), Box<dyn std::error::Error>> {
    let payload = QrChallengePayload {
        challenge_id: "ch789".to_string(),
        rp_challenge: "test".to_string(),
        cutoff_days: 6570,
        verifying_key_id: 3,
        submit_secret: "sec789".to_string(),
        expires_at: 1700000000,
        verify_url: "https://verify3.example.com".to_string(),
        code_verifier: None,
        proof_direction: None,
    };

    let json1 = serde_json::to_string(&payload)?;
    let parsed1: QrChallengePayload = serde_json::from_str(&json1)?;
    let json2 = serde_json::to_string(&parsed1)?;
    let parsed2: QrChallengePayload = serde_json::from_str(&json2)?;
    let json3 = serde_json::to_string(&parsed2)?;

    assert_eq!(json1, json2);
    assert_eq!(json2, json3);
    Ok(())
}

#[test]
fn test_qr_challenge_payload_long_strings() -> Result<(), Box<dyn std::error::Error>> {
    let long_string = "x".repeat(10000);
    let payload = QrChallengePayload {
        challenge_id: long_string.clone(),
        rp_challenge: long_string.clone(),
        cutoff_days: 6570,
        verifying_key_id: 1,
        submit_secret: long_string.clone(),
        expires_at: 1800000000,
        verify_url: format!("https://verify.example.com/{}", long_string),
        code_verifier: Some(long_string.clone()),
        proof_direction: None,
    };

    let json = serde_json::to_string(&payload)?;
    let parsed: QrChallengePayload = serde_json::from_str(&json)?;
    assert_eq!(parsed.challenge_id, long_string);
    Ok(())
}

// ============================================================================
// SECTION 14: IssuerKeyJson comprehensive tests (10 tests)
// ============================================================================

#[test]
fn test_issuer_key_hash_json_complete() -> Result<(), Box<dyn std::error::Error>> {
    let hash = IssuerKeyJson {
        value: "abc123xyz".to_string(),
    };

    let json = serde_json::to_string(&hash)?;
    let parsed: IssuerKeyJson = serde_json::from_str(&json)?;
    assert_eq!(parsed.value, "abc123xyz");
    Ok(())
}

#[test]
fn test_issuer_key_hash_json_value_empty() -> Result<(), Box<dyn std::error::Error>> {
    let hash = IssuerKeyJson {
        value: "".to_string(),
    };

    let json = serde_json::to_string(&hash)?;
    let parsed: IssuerKeyJson = serde_json::from_str(&json)?;
    assert_eq!(parsed.value, "");
    Ok(())
}

#[test]
fn test_issuer_key_hash_json_value_unicode() -> Result<(), Box<dyn std::error::Error>> {
    let hash = IssuerKeyJson {
        value: "ハッシュ🔐123".to_string(),
    };

    let json = serde_json::to_string(&hash)?;
    let parsed: IssuerKeyJson = serde_json::from_str(&json)?;
    assert_eq!(parsed.value, "ハッシュ🔐123");
    Ok(())
}

#[test]
fn test_issuer_key_hash_json_value_very_long() -> Result<(), Box<dyn std::error::Error>> {
    let long_value = "h".repeat(10000);
    let hash = IssuerKeyJson {
        value: long_value.clone(),
    };

    let json = serde_json::to_string(&hash)?;
    let parsed: IssuerKeyJson = serde_json::from_str(&json)?;
    assert_eq!(parsed.value, long_value);
    Ok(())
}

#[test]
fn test_issuer_key_hash_json_missing_value() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{}"#;
    let result = serde_json::from_str::<IssuerKeyJson>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_issuer_key_hash_json_wrong_type_value() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"value":123}"#;
    let result = serde_json::from_str::<IssuerKeyJson>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_issuer_key_hash_json_null_value() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"value":null}"#;
    let result = serde_json::from_str::<IssuerKeyJson>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_issuer_key_hash_json_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let hash = IssuerKeyJson {
        value: "hash456".to_string(),
    };

    let json = serde_json::to_string(&hash)?;
    let parsed: IssuerKeyJson = serde_json::from_str(&json)?;
    let json2 = serde_json::to_string(&parsed)?;
    assert_eq!(json, json2);
    Ok(())
}

#[test]
fn test_issuer_key_hash_json_clone() -> Result<(), Box<dyn std::error::Error>> {
    let hash = IssuerKeyJson {
        value: "hash789".to_string(),
    };

    let cloned = hash.clone();
    assert_eq!(hash.value, cloned.value);
    Ok(())
}

#[test]
fn test_issuer_key_hash_json_debug() -> Result<(), Box<dyn std::error::Error>> {
    let hash = IssuerKeyJson {
        value: "hash_debug".to_string(),
    };

    let debug = format!("{:?}", hash);
    assert!(debug.contains("IssuerKeyJson"));
    assert!(debug.contains("hash_debug"));
    Ok(())
}

// ============================================================================
// SECTION 15: AgePublicJson comprehensive tests (16 tests)
// ============================================================================

#[test]
fn test_age_public_json_complete() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "issuer_hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "challenge123".to_string(),
        issuer,
        cred_nullifier: "nullifier456".to_string(),
    };

    let json = serde_json::to_string(&public)?;
    let parsed: AgePublicJson = serde_json::from_str(&json)?;

    assert_eq!(parsed.cutoff_days, 6570);
    assert_eq!(parsed.rp_challenge, "challenge123");
    assert_eq!(parsed.issuer.value, "issuer_hash");
    assert_eq!(parsed.cred_nullifier, "nullifier456");
    Ok(())
}

#[test]
fn test_age_public_json_cutoff_days_zero() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 0,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let json = serde_json::to_string(&public)?;
    let parsed: AgePublicJson = serde_json::from_str(&json)?;
    assert_eq!(parsed.cutoff_days, 0);
    Ok(())
}

#[test]
fn test_age_public_json_cutoff_days_max() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: i32::MAX,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let json = serde_json::to_string(&public)?;
    let parsed: AgePublicJson = serde_json::from_str(&json)?;
    assert_eq!(parsed.cutoff_days, i32::MAX);
    Ok(())
}

#[test]
fn test_age_public_json_rp_challenge_empty() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let json = serde_json::to_string(&public)?;
    let parsed: AgePublicJson = serde_json::from_str(&json)?;
    assert_eq!(parsed.rp_challenge, "");
    Ok(())
}

#[test]
fn test_age_public_json_cred_nullifier_empty() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "".to_string(),
    };

    let json = serde_json::to_string(&public)?;
    let parsed: AgePublicJson = serde_json::from_str(&json)?;
    assert_eq!(parsed.cred_nullifier, "");
    Ok(())
}

#[test]
fn test_age_public_json_unicode_strings() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "ハッシュ🔐".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "チャレンジ🎯".to_string(),
        issuer,
        cred_nullifier: "ヌリファイア🚫".to_string(),
    };

    let json = serde_json::to_string(&public)?;
    let parsed: AgePublicJson = serde_json::from_str(&json)?;
    assert_eq!(parsed.rp_challenge, "チャレンジ🎯");
    assert_eq!(parsed.issuer.value, "ハッシュ🔐");
    Ok(())
}

#[test]
fn test_age_public_json_missing_cutoff_days() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"rp_challenge":"ch","issuer":{"value":"hash"},"cred_nullifier":"null"}"#;
    let result = serde_json::from_str::<AgePublicJson>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_age_public_json_missing_rp_challenge() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"cutoff_days":6570,"issuer":{"value":"hash"},"cred_nullifier":"null"}"#;
    let result = serde_json::from_str::<AgePublicJson>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_age_public_json_missing_issuer() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"cutoff_days":6570,"rp_challenge":"ch","cred_nullifier":"null"}"#;
    let result = serde_json::from_str::<AgePublicJson>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_age_public_json_missing_cred_nullifier() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"cutoff_days":6570,"rp_challenge":"ch","issuer":{"value":"hash"}}"#;
    let result = serde_json::from_str::<AgePublicJson>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_age_public_json_wrong_type_cutoff_days() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"cutoff_days":"not a number","rp_challenge":"ch","issuer":{"value":"hash"},"cred_nullifier":"null"}"#;
    let result = serde_json::from_str::<AgePublicJson>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_age_public_json_wrong_type_issuer() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"cutoff_days":6570,"rp_challenge":"ch","issuer":"not an object","cred_nullifier":"null"}"#;
    let result = serde_json::from_str::<AgePublicJson>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_age_public_json_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash123".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 7300,
        rp_challenge: "ch456".to_string(),
        issuer,
        cred_nullifier: "null789".to_string(),
    };

    let json = serde_json::to_string(&public)?;
    let parsed: AgePublicJson = serde_json::from_str(&json)?;
    let json2 = serde_json::to_string(&parsed)?;
    assert_eq!(json, json2);
    Ok(())
}

#[test]
fn test_age_public_json_clone() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let cloned = public.clone();
    assert_eq!(public.cutoff_days, cloned.cutoff_days);
    assert_eq!(public.issuer.value, cloned.issuer.value);
    Ok(())
}

#[test]
fn test_age_public_json_debug() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash_debug".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch_debug".to_string(),
        issuer,
        cred_nullifier: "null_debug".to_string(),
    };

    let debug = format!("{:?}", public);
    assert!(debug.contains("AgePublicJson"));
    assert!(debug.contains("6570"));
    Ok(())
}

#[test]
fn test_age_public_json_malformed_issuer() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"cutoff_days":6570,"rp_challenge":"ch","issuer":{},"cred_nullifier":"null"}"#;
    let result = serde_json::from_str::<AgePublicJson>(json);
    assert!(result.is_err());
    Ok(())
}

// ============================================================================
// SECTION 16: AgeProofJson comprehensive tests (15 tests)
// ============================================================================

#[test]
fn test_age_proof_json_complete() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "issuer_hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "challenge123".to_string(),
        issuer,
        cred_nullifier: "nullifier456".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: 1,
        public,
        proof: "proof_base64".to_string(),
    };

    let json = serde_json::to_string(&proof)?;
    let parsed: AgeProofJson = serde_json::from_str(&json)?;

    assert_eq!(parsed.verifying_key_id, 1);
    assert_eq!(parsed.public.cutoff_days, 6570);
    assert_eq!(parsed.proof, "proof_base64");
    Ok(())
}

#[test]
fn test_age_proof_json_verifying_key_id_zero() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: 0,
        public,
        proof: "proof".to_string(),
    };

    let json = serde_json::to_string(&proof)?;
    let parsed: AgeProofJson = serde_json::from_str(&json)?;
    assert_eq!(parsed.verifying_key_id, 0);
    Ok(())
}

#[test]
fn test_age_proof_json_verifying_key_id_max() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: u32::MAX,
        public,
        proof: "proof".to_string(),
    };

    let json = serde_json::to_string(&proof)?;
    let parsed: AgeProofJson = serde_json::from_str(&json)?;
    assert_eq!(parsed.verifying_key_id, u32::MAX);
    Ok(())
}

#[test]
fn test_age_proof_json_proof_empty() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: 1,
        public,
        proof: "".to_string(),
    };

    let json = serde_json::to_string(&proof)?;
    let parsed: AgeProofJson = serde_json::from_str(&json)?;
    assert_eq!(parsed.proof, "");
    Ok(())
}

#[test]
fn test_age_proof_json_proof_unicode() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: 1,
        public,
        proof: "プルーフ🔒".to_string(),
    };

    let json = serde_json::to_string(&proof)?;
    let parsed: AgeProofJson = serde_json::from_str(&json)?;
    assert_eq!(parsed.proof, "プルーフ🔒");
    Ok(())
}

#[test]
fn test_age_proof_json_proof_very_long() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let long_proof = "p".repeat(10000);
    let proof = AgeProofJson {
        verifying_key_id: 1,
        public,
        proof: long_proof.clone(),
    };

    let json = serde_json::to_string(&proof)?;
    let parsed: AgeProofJson = serde_json::from_str(&json)?;
    assert_eq!(parsed.proof, long_proof);
    Ok(())
}

#[test]
fn test_age_proof_json_missing_verifying_key_id() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"public":{"cutoff_days":6570,"rp_challenge":"ch","issuer":{"value":"hash"},"cred_nullifier":"null"},"proof":"proof"}"#;
    let result = serde_json::from_str::<AgeProofJson>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_age_proof_json_missing_public() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"verifying_key_id":1,"proof":"proof"}"#;
    let result = serde_json::from_str::<AgeProofJson>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_age_proof_json_missing_proof() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"verifying_key_id":1,"public":{"cutoff_days":6570,"rp_challenge":"ch","issuer":{"value":"hash"},"cred_nullifier":"null"}}"#;
    let result = serde_json::from_str::<AgeProofJson>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_age_proof_json_wrong_type_verifying_key_id() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"verifying_key_id":"not a number","public":{"cutoff_days":6570,"rp_challenge":"ch","issuer":{"value":"hash"},"cred_nullifier":"null"},"proof":"proof"}"#;
    let result = serde_json::from_str::<AgeProofJson>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_age_proof_json_wrong_type_public() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"verifying_key_id":1,"public":"not an object","proof":"proof"}"#;
    let result = serde_json::from_str::<AgeProofJson>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_age_proof_json_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash456".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 7300,
        rp_challenge: "ch789".to_string(),
        issuer,
        cred_nullifier: "null012".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: 2,
        public,
        proof: "proof_abc".to_string(),
    };

    let json = serde_json::to_string(&proof)?;
    let parsed: AgeProofJson = serde_json::from_str(&json)?;
    let json2 = serde_json::to_string(&parsed)?;
    assert_eq!(json, json2);
    Ok(())
}

#[test]
fn test_age_proof_json_clone() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: 1,
        public,
        proof: "proof".to_string(),
    };

    let cloned = proof.clone();
    assert_eq!(proof.verifying_key_id, cloned.verifying_key_id);
    assert_eq!(proof.proof, cloned.proof);
    Ok(())
}

#[test]
fn test_age_proof_json_debug() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: 1,
        public,
        proof: "proof_debug".to_string(),
    };

    let debug = format!("{:?}", proof);
    assert!(debug.contains("AgeProofJson"));
    assert!(debug.contains("proof_debug"));
    Ok(())
}

#[test]
fn test_age_proof_json_malformed_public() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"verifying_key_id":1,"public":{},"proof":"proof"}"#;
    let result = serde_json::from_str::<AgeProofJson>(json);
    assert!(result.is_err());
    Ok(())
}

// ============================================================================
// SECTION 17: SubmitProofRequest comprehensive tests (20 tests)
// ============================================================================

#[test]
fn test_submit_proof_request_complete() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "issuer_hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "challenge123".to_string(),
        issuer,
        cred_nullifier: "nullifier456".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: 1,
        public,
        proof: "proof_base64".to_string(),
    };

    let req = SubmitProofRequest {
        challenge_id: "ch123".to_string(),
        submit_secret: "secret456".to_string(),
        code_verifier: Some("verifier789".to_string()),
        proof,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: SubmitProofRequest = serde_json::from_str(&json)?;

    assert_eq!(parsed.challenge_id, "ch123");
    assert_eq!(parsed.submit_secret, "secret456");
    assert_eq!(parsed.code_verifier, Some("verifier789".to_string()));
    assert_eq!(parsed.proof.verifying_key_id, 1);
    Ok(())
}

#[test]
fn test_submit_proof_request_minimal() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: 1,
        public,
        proof: "proof".to_string(),
    };

    let req = SubmitProofRequest {
        challenge_id: "ch123".to_string(),
        submit_secret: "secret".to_string(),
        code_verifier: None,
        proof,
    };

    let json = serde_json::to_string(&req)?;
    // code_verifier is omitted when None (skip_serializing_if)
    assert!(!json.contains("code_verifier"));

    let parsed: SubmitProofRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.code_verifier, None);
    Ok(())
}

#[test]
fn test_submit_proof_request_challenge_id_empty() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: 1,
        public,
        proof: "proof".to_string(),
    };

    let req = SubmitProofRequest {
        challenge_id: "".to_string(),
        submit_secret: "secret".to_string(),
        code_verifier: None,
        proof,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: SubmitProofRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.challenge_id, "");
    Ok(())
}

#[test]
fn test_submit_proof_request_submit_secret_empty() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: 1,
        public,
        proof: "proof".to_string(),
    };

    let req = SubmitProofRequest {
        challenge_id: "ch123".to_string(),
        submit_secret: "".to_string(),
        code_verifier: None,
        proof,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: SubmitProofRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.submit_secret, "");
    Ok(())
}

#[test]
fn test_submit_proof_request_code_verifier_present() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: 1,
        public,
        proof: "proof".to_string(),
    };

    let req = SubmitProofRequest {
        challenge_id: "ch123".to_string(),
        submit_secret: "secret".to_string(),
        code_verifier: Some("pkce123".to_string()),
        proof,
    };

    let json = serde_json::to_string(&req)?;
    assert!(json.contains("\"code_verifier\""));
    assert!(json.contains("pkce123"));
    Ok(())
}

#[test]
fn test_submit_proof_request_code_verifier_absent() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: 1,
        public,
        proof: "proof".to_string(),
    };

    let req = SubmitProofRequest {
        challenge_id: "ch123".to_string(),
        submit_secret: "secret".to_string(),
        code_verifier: None,
        proof,
    };

    let json = serde_json::to_string(&req)?;
    // code_verifier is omitted when None (skip_serializing_if)
    assert!(!json.contains("code_verifier"));
    Ok(())
}

#[test]
fn test_submit_proof_request_code_verifier_empty_string() -> Result<(), Box<dyn std::error::Error>>
{
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: 1,
        public,
        proof: "proof".to_string(),
    };

    let req = SubmitProofRequest {
        challenge_id: "ch123".to_string(),
        submit_secret: "secret".to_string(),
        code_verifier: Some("".to_string()),
        proof,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: SubmitProofRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.code_verifier, Some("".to_string()));
    Ok(())
}

#[test]
fn test_submit_proof_request_unicode_strings() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: 1,
        public,
        proof: "proof".to_string(),
    };

    let req = SubmitProofRequest {
        challenge_id: "チャレンジ🎯".to_string(),
        submit_secret: "シークレット🔑".to_string(),
        code_verifier: Some("検証🔐".to_string()),
        proof,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: SubmitProofRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.challenge_id, "チャレンジ🎯");
    assert_eq!(parsed.submit_secret, "シークレット🔑");
    Ok(())
}

#[test]
fn test_submit_proof_request_missing_challenge_id() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"submit_secret":"secret","proof":{"verifying_key_id":1,"public":{"cutoff_days":6570,"rp_challenge":"ch","issuer":{"value":"hash"},"cred_nullifier":"null"},"proof":"proof"}}"#;
    let result = serde_json::from_str::<SubmitProofRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_submit_proof_request_missing_submit_secret() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"challenge_id":"ch123","proof":{"verifying_key_id":1,"public":{"cutoff_days":6570,"rp_challenge":"ch","issuer":{"value":"hash"},"cred_nullifier":"null"},"proof":"proof"}}"#;
    let result = serde_json::from_str::<SubmitProofRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_submit_proof_request_missing_proof() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"challenge_id":"ch123","submit_secret":"secret"}"#;
    let result = serde_json::from_str::<SubmitProofRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_submit_proof_request_wrong_type_challenge_id() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"challenge_id":123,"submit_secret":"secret","proof":{"verifying_key_id":1,"public":{"cutoff_days":6570,"rp_challenge":"ch","issuer":{"value":"hash"},"cred_nullifier":"null"},"proof":"proof"}}"#;
    let result = serde_json::from_str::<SubmitProofRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_submit_proof_request_wrong_type_proof() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"challenge_id":"ch123","submit_secret":"secret","proof":"not an object"}"#;
    let result = serde_json::from_str::<SubmitProofRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_submit_proof_request_null_proof() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"challenge_id":"ch123","submit_secret":"secret","proof":null}"#;
    let result = serde_json::from_str::<SubmitProofRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_submit_proof_request_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash456".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 7300,
        rp_challenge: "ch789".to_string(),
        issuer,
        cred_nullifier: "null012".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: 2,
        public,
        proof: "proof_abc".to_string(),
    };

    let req = SubmitProofRequest {
        challenge_id: "ch456".to_string(),
        submit_secret: "secret789".to_string(),
        code_verifier: Some("verifier012".to_string()),
        proof,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: SubmitProofRequest = serde_json::from_str(&json)?;
    let json2 = serde_json::to_string(&parsed)?;
    assert_eq!(json, json2);
    Ok(())
}

#[test]
fn test_submit_proof_request_clone() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: 1,
        public,
        proof: "proof".to_string(),
    };

    let req = SubmitProofRequest {
        challenge_id: "ch123".to_string(),
        submit_secret: "secret".to_string(),
        code_verifier: Some("verifier".to_string()),
        proof,
    };

    let cloned = req.clone();
    assert_eq!(req.challenge_id, cloned.challenge_id);
    assert_eq!(req.submit_secret, cloned.submit_secret);
    assert_eq!(req.code_verifier, cloned.code_verifier);
    Ok(())
}

#[test]
fn test_submit_proof_request_debug() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: 1,
        public,
        proof: "proof_data".to_string(),
    };

    let req = SubmitProofRequest {
        challenge_id: "ch_test".to_string(),
        submit_secret: "secret_val_123".to_string(),
        code_verifier: Some("verifier_val_456".to_string()),
        proof,
    };

    let debug = format!("{:?}", req);
    assert!(debug.contains("SubmitProofRequest"));
    assert!(debug.contains("ch_test"));
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("secret_val_123"));
    assert!(!debug.contains("verifier_val_456"));
    Ok(())
}

#[test]
fn test_submit_proof_request_malformed_proof() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"challenge_id":"ch123","submit_secret":"secret","proof":{}}"#;
    let result = serde_json::from_str::<SubmitProofRequest>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_submit_proof_request_long_strings() -> Result<(), Box<dyn std::error::Error>> {
    let long_string = "x".repeat(5000);
    let issuer = IssuerKeyJson {
        value: "hash".to_string(),
    };

    let public = AgePublicJson {
        cutoff_days: 6570,
        rp_challenge: "ch".to_string(),
        issuer,
        cred_nullifier: "null".to_string(),
    };

    let proof = AgeProofJson {
        verifying_key_id: 1,
        public,
        proof: "proof".to_string(),
    };

    let req = SubmitProofRequest {
        challenge_id: long_string.clone(),
        submit_secret: long_string.clone(),
        code_verifier: Some(long_string.clone()),
        proof,
    };

    let json = serde_json::to_string(&req)?;
    let parsed: SubmitProofRequest = serde_json::from_str(&json)?;
    assert_eq!(parsed.challenge_id, long_string);
    Ok(())
}

// ============================================================================
// SECTION 18: VerifyResponse comprehensive tests (15 tests)
// ============================================================================

#[test]
fn test_verify_response_complete() -> Result<(), Box<dyn std::error::Error>> {
    let resp = VerifyResponse {
        result: "OK".to_string(),
        state: "approved".to_string(),
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: VerifyResponse = serde_json::from_str(&json)?;

    assert_eq!(parsed.result, "OK");
    assert_eq!(parsed.state, "approved");
    Ok(())
}

#[test]
fn test_verify_response_minimal() -> Result<(), Box<dyn std::error::Error>> {
    let resp = VerifyResponse {
        result: "INVALID_PROOF".to_string(),
        state: "pending".to_string(),
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: VerifyResponse = serde_json::from_str(&json)?;

    assert_ne!(parsed.result, "OK");
    assert_eq!(parsed.state, "pending");
    Ok(())
}

#[test]
fn test_verify_response_result_ok() -> Result<(), Box<dyn std::error::Error>> {
    let resp = VerifyResponse {
        result: "OK".to_string(),
        state: "approved".to_string(),
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: VerifyResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.result, "OK");
    Ok(())
}

#[test]
fn test_verify_response_result_invalid() -> Result<(), Box<dyn std::error::Error>> {
    let resp = VerifyResponse {
        result: "INVALID_PROOF".to_string(),
        state: "rejected".to_string(),
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: VerifyResponse = serde_json::from_str(&json)?;
    assert_ne!(parsed.result, "OK");
    Ok(())
}

#[test]
fn test_verify_response_state_empty() -> Result<(), Box<dyn std::error::Error>> {
    let resp = VerifyResponse {
        result: "OK".to_string(),
        state: "".to_string(),
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: VerifyResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.state, "");
    Ok(())
}

#[test]
fn test_verify_response_state_unicode() -> Result<(), Box<dyn std::error::Error>> {
    let resp = VerifyResponse {
        result: "OK".to_string(),
        state: "承認済み✅".to_string(),
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: VerifyResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.state, "承認済み✅");
    Ok(())
}

#[test]
fn test_verify_response_result_verifier_error() -> Result<(), Box<dyn std::error::Error>> {
    let resp = VerifyResponse {
        result: "VERIFIER_ERROR".to_string(),
        state: "failed".to_string(),
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: VerifyResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.result, "VERIFIER_ERROR");
    assert_eq!(parsed.state, "failed");
    Ok(())
}

#[test]
fn test_verify_response_result_policy_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let resp = VerifyResponse {
        result: "POLICY_REJECTED".to_string(),
        state: "rejected".to_string(),
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: VerifyResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.result, "POLICY_REJECTED");
    Ok(())
}

#[test]
fn test_verify_response_result_empty_string() -> Result<(), Box<dyn std::error::Error>> {
    let resp = VerifyResponse {
        result: "".to_string(),
        state: "approved".to_string(),
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: VerifyResponse = serde_json::from_str(&json)?;
    assert_eq!(parsed.result, "");
    Ok(())
}

#[test]
fn test_verify_response_missing_result() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"state":"approved"}"#;
    let result = serde_json::from_str::<VerifyResponse>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_verify_response_missing_state() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"result":"OK"}"#;
    let result = serde_json::from_str::<VerifyResponse>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_verify_response_wrong_type_result() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"result":42,"state":"approved"}"#;
    let result = serde_json::from_str::<VerifyResponse>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_verify_response_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let resp = VerifyResponse {
        result: "OK".to_string(),
        state: "approved".to_string(),
    };

    let json = serde_json::to_string(&resp)?;
    let parsed: VerifyResponse = serde_json::from_str(&json)?;
    let json2 = serde_json::to_string(&parsed)?;
    assert_eq!(json, json2);
    Ok(())
}

#[test]
fn test_verify_response_clone() -> Result<(), Box<dyn std::error::Error>> {
    let resp = VerifyResponse {
        result: "OK".to_string(),
        state: "approved".to_string(),
    };

    let cloned = resp.clone();
    assert_eq!(resp.result, cloned.result);
    assert_eq!(resp.state, cloned.state);
    Ok(())
}

#[test]
fn test_verify_response_debug() -> Result<(), Box<dyn std::error::Error>> {
    let resp = VerifyResponse {
        result: "INVALID_PROOF".to_string(),
        state: "rejected_debug".to_string(),
    };

    let debug = format!("{:?}", resp);
    assert!(debug.contains("VerifyResponse"));
    assert!(debug.contains("rejected_debug"));
    Ok(())
}

// ============================================================================
// SECTION 19: CredentialMetadata comprehensive tests (20 tests)
// ============================================================================

#[test]
fn test_credential_metadata_complete() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = CredentialMetadata {
        id: "id123".to_string(),
        label: Some("My ID".to_string()),
        imported_at: 1700000000,
        issuer_name: Some("Test Issuer".to_string()),
    };

    let json = serde_json::to_string(&metadata)?;
    let parsed: CredentialMetadata = serde_json::from_str(&json)?;

    assert_eq!(parsed.id, "id123");
    assert_eq!(parsed.label, Some("My ID".to_string()));
    assert_eq!(parsed.imported_at, 1700000000);
    assert_eq!(parsed.issuer_name, Some("Test Issuer".to_string()));
    Ok(())
}

#[test]
fn test_credential_metadata_minimal() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = CredentialMetadata {
        id: "id456".to_string(),
        label: None,
        imported_at: 1700000000,
        issuer_name: None,
    };

    let json = serde_json::to_string(&metadata)?;
    let parsed: CredentialMetadata = serde_json::from_str(&json)?;

    assert_eq!(parsed.id, "id456");
    assert_eq!(parsed.label, None);
    assert_eq!(parsed.issuer_name, None);
    Ok(())
}

#[test]
fn test_credential_metadata_id_empty() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = CredentialMetadata {
        id: "".to_string(),
        label: None,
        imported_at: 1700000000,
        issuer_name: None,
    };

    let json = serde_json::to_string(&metadata)?;
    let parsed: CredentialMetadata = serde_json::from_str(&json)?;
    assert_eq!(parsed.id, "");
    Ok(())
}

#[test]
fn test_credential_metadata_id_unicode() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = CredentialMetadata {
        id: "識別子🆔123".to_string(),
        label: None,
        imported_at: 1700000000,
        issuer_name: None,
    };

    let json = serde_json::to_string(&metadata)?;
    let parsed: CredentialMetadata = serde_json::from_str(&json)?;
    assert_eq!(parsed.id, "識別子🆔123");
    Ok(())
}

#[test]
fn test_credential_metadata_id_very_long() -> Result<(), Box<dyn std::error::Error>> {
    let long_id = "i".repeat(10000);
    let metadata = CredentialMetadata {
        id: long_id.clone(),
        label: None,
        imported_at: 1700000000,
        issuer_name: None,
    };

    let json = serde_json::to_string(&metadata)?;
    let parsed: CredentialMetadata = serde_json::from_str(&json)?;
    assert_eq!(parsed.id, long_id);
    Ok(())
}

#[test]
fn test_credential_metadata_label_present() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = CredentialMetadata {
        id: "id123".to_string(),
        label: Some("Driver's License".to_string()),
        imported_at: 1700000000,
        issuer_name: None,
    };

    let json = serde_json::to_string(&metadata)?;
    let parsed: CredentialMetadata = serde_json::from_str(&json)?;
    assert_eq!(parsed.label, Some("Driver's License".to_string()));
    Ok(())
}

#[test]
fn test_credential_metadata_label_absent() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = CredentialMetadata {
        id: "id123".to_string(),
        label: None,
        imported_at: 1700000000,
        issuer_name: None,
    };

    let json = serde_json::to_string(&metadata)?;
    let parsed: CredentialMetadata = serde_json::from_str(&json)?;
    assert_eq!(parsed.label, None);
    Ok(())
}

#[test]
fn test_credential_metadata_label_empty_string() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = CredentialMetadata {
        id: "id123".to_string(),
        label: Some("".to_string()),
        imported_at: 1700000000,
        issuer_name: None,
    };

    let json = serde_json::to_string(&metadata)?;
    let parsed: CredentialMetadata = serde_json::from_str(&json)?;
    assert_eq!(parsed.label, Some("".to_string()));
    Ok(())
}

#[test]
fn test_credential_metadata_imported_at_zero() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = CredentialMetadata {
        id: "id123".to_string(),
        label: None,
        imported_at: 0,
        issuer_name: None,
    };

    let json = serde_json::to_string(&metadata)?;
    let parsed: CredentialMetadata = serde_json::from_str(&json)?;
    assert_eq!(parsed.imported_at, 0);
    Ok(())
}

#[test]
fn test_credential_metadata_imported_at_max() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = CredentialMetadata {
        id: "id123".to_string(),
        label: None,
        imported_at: u64::MAX,
        issuer_name: None,
    };

    let json = serde_json::to_string(&metadata)?;
    let parsed: CredentialMetadata = serde_json::from_str(&json)?;
    assert_eq!(parsed.imported_at, u64::MAX);
    Ok(())
}

#[test]
fn test_credential_metadata_issuer_name_present() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = CredentialMetadata {
        id: "id123".to_string(),
        label: None,
        imported_at: 1700000000,
        issuer_name: Some("Government Agency".to_string()),
    };

    let json = serde_json::to_string(&metadata)?;
    let parsed: CredentialMetadata = serde_json::from_str(&json)?;
    assert_eq!(parsed.issuer_name, Some("Government Agency".to_string()));
    Ok(())
}

#[test]
fn test_credential_metadata_issuer_name_absent() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = CredentialMetadata {
        id: "id123".to_string(),
        label: None,
        imported_at: 1700000000,
        issuer_name: None,
    };

    let json = serde_json::to_string(&metadata)?;
    let parsed: CredentialMetadata = serde_json::from_str(&json)?;
    assert_eq!(parsed.issuer_name, None);
    Ok(())
}

#[test]
fn test_credential_metadata_issuer_name_unicode() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = CredentialMetadata {
        id: "id123".to_string(),
        label: None,
        imported_at: 1700000000,
        issuer_name: Some("発行者🏛️".to_string()),
    };

    let json = serde_json::to_string(&metadata)?;
    let parsed: CredentialMetadata = serde_json::from_str(&json)?;
    assert_eq!(parsed.issuer_name, Some("発行者🏛️".to_string()));
    Ok(())
}

#[test]
fn test_credential_metadata_missing_id() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"imported_at":1700000000}"#;
    let result = serde_json::from_str::<CredentialMetadata>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_credential_metadata_missing_imported_at() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"id":"id123"}"#;
    let result = serde_json::from_str::<CredentialMetadata>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_credential_metadata_wrong_type_imported_at() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"id":"id123","imported_at":"not a number"}"#;
    let result = serde_json::from_str::<CredentialMetadata>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_credential_metadata_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = CredentialMetadata {
        id: "id789".to_string(),
        label: Some("Passport".to_string()),
        imported_at: 1800000000,
        issuer_name: Some("Department of State".to_string()),
    };

    let json = serde_json::to_string(&metadata)?;
    let parsed: CredentialMetadata = serde_json::from_str(&json)?;
    let json2 = serde_json::to_string(&parsed)?;
    assert_eq!(json, json2);
    Ok(())
}

#[test]
fn test_credential_metadata_clone() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = CredentialMetadata {
        id: "id123".to_string(),
        label: Some("ID Card".to_string()),
        imported_at: 1700000000,
        issuer_name: Some("Issuer".to_string()),
    };

    let cloned = metadata.clone();
    assert_eq!(metadata.id, cloned.id);
    assert_eq!(metadata.label, cloned.label);
    assert_eq!(metadata.imported_at, cloned.imported_at);
    assert_eq!(metadata.issuer_name, cloned.issuer_name);
    Ok(())
}

#[test]
fn test_credential_metadata_debug() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = CredentialMetadata {
        id: "id_debug".to_string(),
        label: Some("debug_label".to_string()),
        imported_at: 1700000000,
        issuer_name: Some("debug_issuer".to_string()),
    };

    let debug = format!("{:?}", metadata);
    assert!(debug.contains("CredentialMetadata"));
    assert!(debug.contains("id_debug"));
    Ok(())
}

#[test]
fn test_credential_metadata_all_optional_present() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = CredentialMetadata {
        id: "id123".to_string(),
        label: Some("My Credential".to_string()),
        imported_at: 1700000000,
        issuer_name: Some("Official Issuer".to_string()),
    };

    let json = serde_json::to_string(&metadata)?;
    let parsed: CredentialMetadata = serde_json::from_str(&json)?;

    assert_eq!(parsed.label, Some("My Credential".to_string()));
    assert_eq!(parsed.issuer_name, Some("Official Issuer".to_string()));
    Ok(())
}

// ============================================================================
// SECTION 20: WalletConfig comprehensive tests (15 tests)
// ============================================================================

#[test]
fn test_wallet_config_complete() -> Result<(), Box<dyn std::error::Error>> {
    let config = WalletConfig {
        auto_select: true,
        network_timeout: 30,
        cache_proving_keys: true,
    };

    let json = serde_json::to_string(&config)?;
    let parsed: WalletConfig = serde_json::from_str(&json)?;

    assert!(parsed.auto_select);
    assert_eq!(parsed.network_timeout, 30);
    assert!(parsed.cache_proving_keys);
    Ok(())
}

#[test]
fn test_wallet_config_auto_select_true() -> Result<(), Box<dyn std::error::Error>> {
    let config = WalletConfig {
        auto_select: true,
        network_timeout: 30,
        cache_proving_keys: false,
    };

    let json = serde_json::to_string(&config)?;
    let parsed: WalletConfig = serde_json::from_str(&json)?;
    assert!(parsed.auto_select);
    Ok(())
}

#[test]
fn test_wallet_config_auto_select_false() -> Result<(), Box<dyn std::error::Error>> {
    let config = WalletConfig {
        auto_select: false,
        network_timeout: 30,
        cache_proving_keys: true,
    };

    let json = serde_json::to_string(&config)?;
    let parsed: WalletConfig = serde_json::from_str(&json)?;
    assert!(!parsed.auto_select);
    Ok(())
}

#[test]
fn test_wallet_config_network_timeout_zero() -> Result<(), Box<dyn std::error::Error>> {
    let config = WalletConfig {
        auto_select: true,
        network_timeout: 0,
        cache_proving_keys: true,
    };

    let json = serde_json::to_string(&config)?;
    let parsed: WalletConfig = serde_json::from_str(&json)?;
    assert_eq!(parsed.network_timeout, 0);
    Ok(())
}

#[test]
fn test_wallet_config_network_timeout_max() -> Result<(), Box<dyn std::error::Error>> {
    let config = WalletConfig {
        auto_select: true,
        network_timeout: u64::MAX,
        cache_proving_keys: true,
    };

    let json = serde_json::to_string(&config)?;
    let parsed: WalletConfig = serde_json::from_str(&json)?;
    assert_eq!(parsed.network_timeout, u64::MAX);
    Ok(())
}

#[test]
fn test_wallet_config_cache_proving_keys_true() -> Result<(), Box<dyn std::error::Error>> {
    let config = WalletConfig {
        auto_select: true,
        network_timeout: 30,
        cache_proving_keys: true,
    };

    let json = serde_json::to_string(&config)?;
    let parsed: WalletConfig = serde_json::from_str(&json)?;
    assert!(parsed.cache_proving_keys);
    Ok(())
}

#[test]
fn test_wallet_config_cache_proving_keys_false() -> Result<(), Box<dyn std::error::Error>> {
    let config = WalletConfig {
        auto_select: true,
        network_timeout: 30,
        cache_proving_keys: false,
    };

    let json = serde_json::to_string(&config)?;
    let parsed: WalletConfig = serde_json::from_str(&json)?;
    assert!(!parsed.cache_proving_keys);
    Ok(())
}

#[test]
fn test_wallet_config_missing_auto_select() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"network_timeout":30,"cache_proving_keys":true}"#;
    let result = serde_json::from_str::<WalletConfig>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_wallet_config_missing_network_timeout() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"auto_select":true,"cache_proving_keys":true}"#;
    let result = serde_json::from_str::<WalletConfig>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_wallet_config_missing_cache_proving_keys() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"auto_select":true,"network_timeout":30}"#;
    let result = serde_json::from_str::<WalletConfig>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_wallet_config_wrong_type_auto_select() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"auto_select":"not a boolean","network_timeout":30,"cache_proving_keys":true}"#;
    let result = serde_json::from_str::<WalletConfig>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_wallet_config_wrong_type_network_timeout() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{"auto_select":true,"network_timeout":"not a number","cache_proving_keys":true}"#;
    let result = serde_json::from_str::<WalletConfig>(json);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_wallet_config_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let config = WalletConfig {
        auto_select: false,
        network_timeout: 60,
        cache_proving_keys: false,
    };

    let json = serde_json::to_string(&config)?;
    let parsed: WalletConfig = serde_json::from_str(&json)?;
    let json2 = serde_json::to_string(&parsed)?;
    assert_eq!(json, json2);
    Ok(())
}

#[test]
fn test_wallet_config_clone() -> Result<(), Box<dyn std::error::Error>> {
    let config = WalletConfig {
        auto_select: true,
        network_timeout: 30,
        cache_proving_keys: true,
    };

    let cloned = config.clone();
    assert_eq!(config.auto_select, cloned.auto_select);
    assert_eq!(config.network_timeout, cloned.network_timeout);
    assert_eq!(config.cache_proving_keys, cloned.cache_proving_keys);
    Ok(())
}

#[test]
fn test_wallet_config_debug() -> Result<(), Box<dyn std::error::Error>> {
    let config = WalletConfig {
        auto_select: false,
        network_timeout: 45,
        cache_proving_keys: false,
    };

    let debug = format!("{:?}", config);
    assert!(debug.contains("WalletConfig"));
    assert!(debug.contains("45"));
    Ok(())
}

// Property-based tests
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::TestCaseError;

    proptest! {
        // Property: CredentialV2 JSON roundtrip
        #[test]
        fn prop_credentialv2_json_roundtrip(
            v in any::<u8>(),
            kid in "[a-z]{5,20}",
            iat in 1000u64..3000000u64,
            offset in 0u64..3000000u64,
            schema in "[a-z.]{5,30}",
        ) {
            let cred = CredentialV2 {
                v,
                kid: kid.clone(),
                issuer_vk: [1u8; 32],
                sig_rj: [2u8; 64],
                c_bytes: [3u8; 32],
                iat,
                exp: iat.saturating_add(offset),
                schema: schema.clone(),
                dob_days: Some(18000),
                r_bits: Some(vec![true, false]),
            };

            let json = serde_json::to_string(&cred).map_err(|e| TestCaseError::fail(format!("{e}")))?;
            let parsed: CredentialV2 = serde_json::from_str(&json).map_err(|e| TestCaseError::fail(format!("{e}")))?;

            prop_assert_eq!(parsed.v, cred.v);
            prop_assert_eq!(&parsed.kid, &cred.kid);
            prop_assert_eq!(parsed.iat, cred.iat);
            prop_assert_eq!(parsed.exp, cred.exp);
            prop_assert_eq!(&parsed.schema, &cred.schema);
        }

        // Property: QrChallengePayload roundtrip
        #[test]
        fn prop_qr_challenge_roundtrip(
            challenge_id in "[a-z0-9]{10,30}",
            cutoff_days in 10000i32..25000i32,
            verifying_key_id in 1u32..100u32,
            expires_at in 1000000u64..3000000u64,
        ) {
            let payload = QrChallengePayload {
                challenge_id: challenge_id.clone(),
                rp_challenge: URL_SAFE_NO_PAD.encode([10u8; 32]),
                cutoff_days,
                verifying_key_id,
                submit_secret: URL_SAFE_NO_PAD.encode([11u8; 32]),
                expires_at,
                verify_url: "https://verify.example.com/v1/verify".to_string(),
                code_verifier: Some("verifier".to_string()),
                proof_direction: None,
            };

            let json = serde_json::to_string(&payload).map_err(|e| TestCaseError::fail(format!("{e}")))?;
            let parsed: QrChallengePayload = serde_json::from_str(&json).map_err(|e| TestCaseError::fail(format!("{e}")))?;

            prop_assert_eq!(&parsed.challenge_id, &payload.challenge_id);
            prop_assert_eq!(parsed.cutoff_days, payload.cutoff_days);
            prop_assert_eq!(parsed.verifying_key_id, payload.verifying_key_id);
            prop_assert_eq!(parsed.expires_at, payload.expires_at);
        }

        // Property: CredentialMetadata roundtrip
        #[test]
        fn prop_metadata_roundtrip(
            id in "[a-z0-9]{10,50}",
            label: Option<String>,
            imported_at in 1000000u64..3000000u64,
            issuer_name: Option<String>,
        ) {
            let metadata = CredentialMetadata {
                id: id.clone(),
                label: label.clone(),
                imported_at,
                issuer_name: issuer_name.clone(),
            };

            let json = serde_json::to_string(&metadata).map_err(|e| TestCaseError::fail(format!("{e}")))?;
            let parsed: CredentialMetadata = serde_json::from_str(&json).map_err(|e| TestCaseError::fail(format!("{e}")))?;

            prop_assert_eq!(parsed.id, metadata.id);
            prop_assert_eq!(parsed.label, metadata.label);
            prop_assert_eq!(parsed.imported_at, metadata.imported_at);
            prop_assert_eq!(parsed.issuer_name, metadata.issuer_name);
        }

        // Property: WalletConfig roundtrip
        #[test]
        fn prop_wallet_config_roundtrip(
            auto_select: bool,
            network_timeout in 1u64..300u64,
            cache_proving_keys: bool,
        ) {
            let config = WalletConfig {
                auto_select,
                network_timeout,
                cache_proving_keys,
            };

            let json = serde_json::to_string(&config).map_err(|e| TestCaseError::fail(format!("{e}")))?;
            let parsed: WalletConfig = serde_json::from_str(&json).map_err(|e| TestCaseError::fail(format!("{e}")))?;

            prop_assert_eq!(parsed.auto_select, config.auto_select);
            prop_assert_eq!(parsed.network_timeout, config.network_timeout);
            prop_assert_eq!(parsed.cache_proving_keys, config.cache_proving_keys);
        }

        // Property: VerifyResponse parsing handles all result and state values
        #[test]
        fn prop_verify_response_parsing(
            result in "[A-Z_]{2,20}",
            state in "[a-z]{5,20}",
        ) {
            let response = VerifyResponse {
                result: result.clone(),
                state: state.clone(),
            };

            let json = serde_json::to_string(&response).map_err(|e| TestCaseError::fail(format!("{e}")))?;
            let parsed: VerifyResponse = serde_json::from_str(&json).map_err(|e| TestCaseError::fail(format!("{e}")))?;

            prop_assert_eq!(parsed.result, response.result);
            prop_assert_eq!(parsed.state, response.state);
        }

        // Property: Authorizer keyId field mapping
        #[test]
        fn prop_authorizer_key_id_mapping(
            format in "[a-z]{5,10}",
            key_id in "[a-z0-9]{5,20}",
            timestamp in 1000000u64..3000000u64,
            hmac in "[a-f0-9]{32,64}",
            nonce in "[a-f0-9]{64}",
        ) {
            let auth = Authorizer {
                format: format.clone(),
                key_id: key_id.clone(),
                challenge_id: Some("chal".to_string()),
                timestamp,
                hmac: hmac.clone(),
                nonce: nonce.clone(),
            };

            let json = serde_json::to_string(&auth).map_err(|e| TestCaseError::fail(format!("{e}")))?;

            // Should use keyId, not key_id
            prop_assert!(json.contains("keyId"));
            prop_assert!(!json.contains("key_id"));

            let parsed: Authorizer = serde_json::from_str(&json).map_err(|e| TestCaseError::fail(format!("{e}")))?;
            prop_assert_eq!(&parsed.key_id, &auth.key_id);
        }

        // Property: Base64 fields in SignedCredentialHeader
        #[test]
        fn prop_signed_header_base64_fields(
            v in any::<u8>(),
            kid in "[a-z]{5,20}",
            iat in 1000u64..3000000u64,
            offset in 0u64..3000000u64,
        ) {
            let header = SignedCredentialHeader {
                v,
                kid: kid.clone(),
                issuer_vk: [5u8; 32],
                sig_rj: [6u8; 64],
                c_bytes: [7u8; 32],
                iat,
                exp: iat.saturating_add(offset),
                schema: "test.schema".to_string(),
            };

            let json = serde_json::to_string(&header).map_err(|e| TestCaseError::fail(format!("{e}")))?;

            // Should contain base64 encoded values
            prop_assert!(json.contains(&URL_SAFE_NO_PAD.encode([5u8; 32])));

            let parsed: SignedCredentialHeader = serde_json::from_str(&json).map_err(|e| TestCaseError::fail(format!("{e}")))?;
            prop_assert_eq!(parsed.issuer_vk, header.issuer_vk);
            prop_assert_eq!(parsed.sig_rj, header.sig_rj);
            prop_assert_eq!(parsed.c_bytes, header.c_bytes);
        }

        // Property: Optional fields serialize correctly
        #[test]
        fn prop_optional_fields_serialize(
            has_code_verifier: bool,
        ) {
            let payload = QrChallengePayload {
                challenge_id: "test123".to_string(),
                rp_challenge: URL_SAFE_NO_PAD.encode([10u8; 32]),
                cutoff_days: 19000,
                verifying_key_id: 1,
                submit_secret: URL_SAFE_NO_PAD.encode([11u8; 32]),
                expires_at: 2000000,
                verify_url: "https://example.com".to_string(),
                code_verifier: if has_code_verifier { Some("verifier".to_string()) } else { None },
                proof_direction: None,
            };

            let json = serde_json::to_string(&payload).map_err(|e| TestCaseError::fail(format!("{e}")))?;
            let parsed: QrChallengePayload = serde_json::from_str(&json).map_err(|e| TestCaseError::fail(format!("{e}")))?;

            prop_assert_eq!(&parsed.code_verifier, &payload.code_verifier);
        }

        // Property: Arrays serialize to correct length
        #[test]
        fn prop_array_serialization_length(
            issuer_vk in prop::array::uniform32(any::<u8>()),
            sig_rj_vec in prop::collection::vec(any::<u8>(), 64..=64),
            c_bytes in prop::array::uniform32(any::<u8>()),
        ) {
            let mut sig_rj = [0u8; 64];
            sig_rj.copy_from_slice(&sig_rj_vec);

            let header = SignedCredentialHeader {
                v: 2,
                kid: "test".to_string(),
                issuer_vk,
                sig_rj,
                c_bytes,
                iat: 1000000,
                exp: 2000000,
                schema: "test".to_string(),
            };

            let json = serde_json::to_string(&header).map_err(|e| TestCaseError::fail(format!("{e}")))?;
            let parsed: SignedCredentialHeader = serde_json::from_str(&json).map_err(|e| TestCaseError::fail(format!("{e}")))?;

            prop_assert_eq!(parsed.issuer_vk.len(), 32);
            prop_assert_eq!(parsed.sig_rj.len(), 64);
            prop_assert_eq!(parsed.c_bytes.len(), 32);
        }
    }
}

fn valid_authorizer() -> Authorizer {
    Authorizer {
        format: "yubikey".to_string(),
        key_id: "officer-1".to_string(),
        challenge_id: None,
        timestamp: 1_700_000_000,
        hmac: "a".repeat(40),
        nonce: "a".repeat(64),
    }
}

#[test]
fn test_valid_yubikey_authorizer_passes() {
    let auth = valid_authorizer();
    assert!(auth.validate().is_ok());
}

#[test]
fn test_valid_client_authorizer_passes() {
    let mut auth = valid_authorizer();
    auth.format = "client".to_string();
    assert!(auth.validate().is_ok());
}

#[test]
fn test_invalid_format_fails() {
    let mut auth = valid_authorizer();
    auth.format = "bearer".to_string();
    let err = auth.validate().unwrap_err();
    assert!(err.contains("invalid authorizer format"));
}

#[test]
fn test_nonce_too_short_fails() {
    let mut auth = valid_authorizer();
    auth.nonce = "a".repeat(63);
    assert!(auth.validate().is_err());
}

#[test]
fn test_nonce_too_long_fails() {
    let mut auth = valid_authorizer();
    auth.nonce = "a".repeat(65);
    assert!(auth.validate().is_err());
}

#[test]
fn test_nonce_non_hex_fails() {
    let mut auth = valid_authorizer();
    auth.nonce = "g".repeat(64);
    assert!(auth.validate().is_err());
}

#[test]
fn test_empty_key_id_fails() {
    let mut auth = valid_authorizer();
    auth.key_id = String::new();
    assert!(auth.validate().is_err());
}

#[test]
fn test_key_id_at_max_passes() {
    let mut auth = valid_authorizer();
    auth.key_id = "x".repeat(super::MAX_PROTOCOL_FIELD_LEN);
    assert!(auth.validate().is_ok());
}

#[test]
fn test_key_id_over_max_fails() {
    let mut auth = valid_authorizer();
    auth.key_id = "x".repeat(super::MAX_PROTOCOL_FIELD_LEN + 1);
    assert!(auth.validate().is_err());
}

#[test]
fn test_empty_hmac_fails() {
    let mut auth = valid_authorizer();
    auth.hmac = String::new();
    assert!(auth.validate().is_err());
}

#[test]
fn test_hmac_at_max_passes() {
    let mut auth = valid_authorizer();
    auth.hmac = "a".repeat(128);
    assert!(auth.validate().is_ok());
}

#[test]
fn test_hmac_over_max_fails() {
    let mut auth = valid_authorizer();
    auth.hmac = "a".repeat(129);
    assert!(auth.validate().is_err());
}

fn valid_qr_payload() -> QrChallengePayload {
    QrChallengePayload {
        challenge_id: "chal-001".to_string(),
        rp_challenge: "dGVzdA".to_string(),
        cutoff_days: 18000,
        verifying_key_id: 1,
        submit_secret: "c2VjcmV0".to_string(),
        expires_at: 1_700_000_000,
        verify_url: "https://example.com/verify".to_string(),
        code_verifier: None,
        proof_direction: None,
    }
}

#[test]
fn test_valid_qr_payload_passes() {
    assert!(valid_qr_payload().validate_field_lengths().is_ok());
}

#[test]
fn test_empty_challenge_id_fails() {
    let mut p = valid_qr_payload();
    p.challenge_id = String::new();
    assert!(p.validate_field_lengths().is_err());
}

#[test]
fn test_challenge_id_at_max_passes() {
    let mut p = valid_qr_payload();
    p.challenge_id = "x".repeat(super::MAX_PROTOCOL_FIELD_LEN);
    assert!(p.validate_field_lengths().is_ok());
}

#[test]
fn test_challenge_id_over_max_fails() {
    let mut p = valid_qr_payload();
    p.challenge_id = "x".repeat(super::MAX_PROTOCOL_FIELD_LEN + 1);
    assert!(p.validate_field_lengths().is_err());
}

#[test]
fn test_empty_rp_challenge_fails() {
    let mut p = valid_qr_payload();
    p.rp_challenge = String::new();
    assert!(p.validate_field_lengths().is_err());
}

#[test]
fn test_rp_challenge_at_max_passes() {
    let mut p = valid_qr_payload();
    p.rp_challenge = "x".repeat(super::MAX_PROTOCOL_FIELD_LEN);
    assert!(p.validate_field_lengths().is_ok());
}

#[test]
fn test_rp_challenge_over_max_fails() {
    let mut p = valid_qr_payload();
    p.rp_challenge = "x".repeat(super::MAX_PROTOCOL_FIELD_LEN + 1);
    assert!(p.validate_field_lengths().is_err());
}

#[test]
fn test_empty_submit_secret_fails() {
    let mut p = valid_qr_payload();
    p.submit_secret = String::new();
    assert!(p.validate_field_lengths().is_err());
}

#[test]
fn test_submit_secret_at_max_passes() {
    let mut p = valid_qr_payload();
    p.submit_secret = "x".repeat(super::MAX_PROTOCOL_FIELD_LEN);
    assert!(p.validate_field_lengths().is_ok());
}

#[test]
fn test_submit_secret_over_max_fails() {
    let mut p = valid_qr_payload();
    p.submit_secret = "x".repeat(super::MAX_PROTOCOL_FIELD_LEN + 1);
    assert!(p.validate_field_lengths().is_err());
}

#[test]
fn test_empty_verify_url_fails() {
    let mut p = valid_qr_payload();
    p.verify_url = String::new();
    assert!(p.validate_field_lengths().is_err());
}

#[test]
fn test_verify_url_at_max_passes() {
    let mut p = valid_qr_payload();
    // Build a valid HTTPS URL that is exactly MAX_PROTOCOL_FIELD_LEN bytes.
    let prefix = "https://example.com/";
    let pad_len = super::MAX_PROTOCOL_FIELD_LEN - prefix.len();
    p.verify_url = format!("{}{}", prefix, "x".repeat(pad_len));
    assert!(p.validate_field_lengths().is_ok());
}

#[test]
fn test_verify_url_over_max_fails() {
    let mut p = valid_qr_payload();
    p.verify_url = "x".repeat(super::MAX_PROTOCOL_FIELD_LEN + 1);
    assert!(p.validate_field_lengths().is_err());
}

#[test]
fn test_verify_url_rejects_http() {
    let mut p = valid_qr_payload();
    p.verify_url = "http://example.com/verify".to_string();
    let err = p.validate_field_lengths().unwrap_err();
    assert!(err.contains("HTTPS"), "expected HTTPS error, got: {}", err);
}

#[test]
fn test_verify_url_rejects_ftp() {
    let mut p = valid_qr_payload();
    p.verify_url = "ftp://example.com/verify".to_string();
    let err = p.validate_field_lengths().unwrap_err();
    assert!(err.contains("HTTPS"), "expected HTTPS error, got: {}", err);
}

#[test]
fn test_verify_url_rejects_javascript() {
    let mut p = valid_qr_payload();
    p.verify_url = "javascript:alert(1)".to_string();
    let err = p.validate_field_lengths().unwrap_err();
    assert!(
        err.contains("HTTPS") || err.contains("not a valid URL"),
        "expected scheme error, got: {}",
        err
    );
}

#[test]
fn test_verify_url_accepts_https() {
    let mut p = valid_qr_payload();
    p.verify_url = "https://verify.example.com/v1/submit".to_string();
    assert!(p.validate_field_lengths().is_ok());
}

#[test]
fn test_verify_url_rejects_invalid_url() {
    let mut p = valid_qr_payload();
    p.verify_url = "not-a-url".to_string();
    let err = p.validate_field_lengths().unwrap_err();
    assert!(
        err.contains("not a valid URL"),
        "expected parse error, got: {}",
        err
    );
}

#[test]
fn test_code_verifier_none_passes() {
    let mut p = valid_qr_payload();
    p.code_verifier = None;
    assert!(p.validate_field_lengths().is_ok());
}

#[test]
fn test_code_verifier_at_max_passes() {
    let mut p = valid_qr_payload();
    p.code_verifier = Some("x".repeat(super::MAX_PROTOCOL_FIELD_LEN));
    assert!(p.validate_field_lengths().is_ok());
}

#[test]
fn test_code_verifier_over_max_fails() {
    let mut p = valid_qr_payload();
    p.code_verifier = Some("x".repeat(super::MAX_PROTOCOL_FIELD_LEN + 1));
    assert!(p.validate_field_lengths().is_err());
}

#[test]
fn test_valid_proof_direction_over_age() {
    let mut p = valid_qr_payload();
    p.proof_direction = Some("over_age".to_string());
    assert!(p.validate_field_lengths().is_ok());
}

#[test]
fn test_valid_proof_direction_under_age() {
    let mut p = valid_qr_payload();
    p.proof_direction = Some("under_age".to_string());
    assert!(p.validate_field_lengths().is_ok());
}

#[test]
fn test_invalid_proof_direction_fails() {
    let mut p = valid_qr_payload();
    p.proof_direction = Some("sideways".to_string());
    assert!(p.validate_field_lengths().is_err());
}

#[test]
fn test_proof_direction_none_passes() {
    let mut p = valid_qr_payload();
    p.proof_direction = None;
    assert!(p.validate_field_lengths().is_ok());
}

// ====================================================================
// Mutation-coverage tests: kill surviving mutants in types.rs
// ====================================================================

/// Kill: types.rs:726 replace || with && in validate_field_lengths
/// With the && mutant, an empty verify_url would bypass the length check
/// (is_empty && len>MAX is always false) and fall through to url::Url::parse
/// which would produce a DIFFERENT error message. We assert the specific
/// error message from the length check to kill this mutant.
#[test]
fn test_empty_verify_url_produces_length_error_message() {
    let mut p = valid_qr_payload();
    p.verify_url = String::new();
    let err = p.validate_field_lengths().unwrap_err();
    assert!(
        err.contains("verify_url must be 1-"),
        "empty verify_url should produce length error, got: {}",
        err
    );
}
