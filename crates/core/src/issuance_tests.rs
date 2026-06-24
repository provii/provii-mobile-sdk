// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

use super::*;

/// Create a signed test header for a given commitment.
///
/// Generates a fresh RedJubjub signing key, signs the credential message,
/// and returns both the header and the verification key bytes so callers
/// can perform additional checks.
fn create_signed_test_header(
    c_bytes: [u8; 32],
) -> std::result::Result<SignedCredentialHeader, Box<dyn std::error::Error>> {
    let sk = provii_crypto_sig_redjubjub::SigningKey::random();
    let vk = sk.verification_key().to_bytes();
    let sk_bytes = sk.to_bytes();

    let cred_msg = provii_crypto_commons::CredMsgV2 {
        v: 2,
        kid: "test-key".to_string(),
        c: c_bytes,
        iat: 1000000,
        exp: 2000000,
        schema: "provii.age/0".to_string(),
    };
    let sig_rj = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &sk_bytes)?;

    Ok(SignedCredentialHeader {
        v: 2,
        kid: "test-key".to_string(),
        issuer_vk: vk,
        sig_rj,
        c_bytes,
        iat: 1000000,
        exp: 2000000,
        schema: "provii.age/0".to_string(),
    })
}

#[test]
fn test_compute_commitment() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let dob_days = 10000; // ~27 years old
    let parts = compute_commitment(dob_days)?;

    assert_eq!(parts.dob_days, dob_days);
    assert_eq!(parts.r_bits.len(), R_BITS_LEN);
    assert_eq!(parts.c_bytes.len(), 32);

    // Verify commitment is correct
    let c_verify = pedersen_commit_dob_validated(parts.dob_days, &parts.r_bits).unwrap();
    assert_eq!(c_verify, parts.c_bytes);
    Ok(())
}

#[test]
fn test_deterministic_commitment() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let seed = [42u8; 32];
    let dob_days = 10000;

    let parts1 = compute_commitment_with_seed(dob_days, seed)?;
    let parts2 = compute_commitment_with_seed(dob_days, seed)?;

    assert_eq!(parts1.c_bytes, parts2.c_bytes);
    assert_eq!(parts1.r_bits, parts2.r_bits);
    Ok(())
}

#[test]
fn test_finalize_credential() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Create commitment
    let dob_days = 10000;
    let parts = compute_commitment(dob_days)?;

    // Signed header with valid RedJubjub signature
    let header = create_signed_test_header(parts.c_bytes)?;

    // Finalize
    let cred = finalize_credential(header.clone(), dob_days, parts.r_bits.clone())?;

    assert_eq!(cred.v, 2);
    assert_eq!(cred.kid, "test-key");
    assert_eq!(cred.c_bytes, parts.c_bytes);
    assert_eq!(cred.dob_days, Some(dob_days));
    assert_eq!(
        cred.r_bits.as_ref().ok_or("missing r_bits")?.len(),
        R_BITS_LEN
    );
    Ok(())
}

#[test]
fn test_commitment_mismatch() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let dob_days = 10000;
    let wrong_dob = 9999;
    let parts = compute_commitment(dob_days)?;

    // Header is signed for dob_days commitment; wrong_dob won't match.
    let header = create_signed_test_header(parts.c_bytes)?;

    // Try to finalize with wrong DOB. Must fail at commitment check before sig.
    let result = finalize_credential(header, wrong_dob, parts.r_bits.clone());
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_bits_packing() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let bits = vec![true, false, true, true, false, false, true, false];
    let packed = bits::pack_bits(&bits);
    assert_eq!(packed, vec![0b10110010]);

    let unpacked = bits::unpack_bits(&packed, bits.len());
    assert_eq!(unpacked, bits);
    Ok(())
}

#[test]
fn test_parse_dob() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let dob_iso = "1990-01-15";
    let days = parse_dob_iso(dob_iso)?;
    assert!(days > 0);

    let back_to_iso = days_to_iso(days)?;
    assert_eq!(back_to_iso, dob_iso);
    Ok(())
}
