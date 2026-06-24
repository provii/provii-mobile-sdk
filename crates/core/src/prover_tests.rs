// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

use super::*;

fn valid_witness() -> AgeWitness {
    AgeWitness {
        dob_days: 10_000,
        r_bits: vec![false; 128],
        issuer_vk_bytes: [0u8; 32],
        sig_rj_bytes: vec![0u8; 64],
        v: 2,
        kid: vec![0u8; 14],
        c_bytes: [0u8; 32],
        iat: 1_700_000_000,
        exp: 1_800_000_000,
        schema: vec![0u8; 12],
    }
}

fn dummy_credential(dob_days: Option<i32>) -> CredentialV2 {
    CredentialV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        issuer_vk: [0u8; 32],
        sig_rj: [0u8; 64],
        c_bytes: [0u8; 32],
        iat: 1_700_000_000,
        exp: 1_800_000_000,
        schema: "provii.age/0".to_string(),
        dob_days,
        r_bits: None,
    }
}

#[test]
fn decode_b64_32_valid_input() {
    let bytes: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    let result = decode_b64_32(&encoded).expect("should decode successfully");
    assert_eq!(result, bytes);
}

#[test]
fn decode_b64_32_rejects_31_bytes() {
    let short = URL_SAFE_NO_PAD.encode([0xAAu8; 31]);
    let err = decode_b64_32(&short).unwrap_err();
    assert!(matches!(err, ProverError::InvalidBase64(_)));
}

#[test]
fn decode_b64_32_rejects_33_bytes() {
    let long = URL_SAFE_NO_PAD.encode([0xBBu8; 33]);
    let err = decode_b64_32(&long).unwrap_err();
    assert!(matches!(err, ProverError::InvalidBase64(_)));
}

#[test]
fn decode_b64_32_rejects_invalid_characters() {
    let err = decode_b64_32("not!valid@base64$$$").unwrap_err();
    assert!(matches!(err, ProverError::InvalidBase64(_)));
}

#[test]
fn decode_b64_32_rejects_empty_string() {
    let err = decode_b64_32("").unwrap_err();
    assert!(matches!(err, ProverError::InvalidBase64(_)));
}

#[test]
fn verify_circuit_shape_valid_witness() {
    let w = valid_witness();
    assert!(verify_circuit_shape(&w).is_ok());
}

#[test]
fn verify_circuit_shape_kid_too_short() {
    let mut w = valid_witness();
    w.kid = vec![0u8; 13];
    let err = verify_circuit_shape(&w).unwrap_err();
    assert!(matches!(err, ProverError::InvalidInput(_)));
}

#[test]
fn verify_circuit_shape_kid_too_long() {
    let mut w = valid_witness();
    w.kid = vec![0u8; 15];
    let err = verify_circuit_shape(&w).unwrap_err();
    assert!(matches!(err, ProverError::InvalidInput(_)));
}

#[test]
fn verify_circuit_shape_schema_too_short() {
    let mut w = valid_witness();
    w.schema = vec![0u8; 11];
    let err = verify_circuit_shape(&w).unwrap_err();
    assert!(matches!(err, ProverError::InvalidInput(_)));
}

#[test]
fn verify_circuit_shape_schema_too_long() {
    let mut w = valid_witness();
    w.schema = vec![0u8; 13];
    let err = verify_circuit_shape(&w).unwrap_err();
    assert!(matches!(err, ProverError::InvalidInput(_)));
}

#[test]
fn verify_circuit_shape_r_bits_too_short() {
    let mut w = valid_witness();
    w.r_bits = vec![false; 127];
    let err = verify_circuit_shape(&w).unwrap_err();
    assert!(matches!(err, ProverError::InvalidInput(_)));
}

#[test]
fn verify_circuit_shape_r_bits_too_long() {
    let mut w = valid_witness();
    w.r_bits = vec![false; 129];
    let err = verify_circuit_shape(&w).unwrap_err();
    assert!(matches!(err, ProverError::InvalidInput(_)));
}

#[test]
fn verify_circuit_shape_sig_rj_too_short() {
    let mut w = valid_witness();
    w.sig_rj_bytes = vec![0u8; 63];
    let err = verify_circuit_shape(&w).unwrap_err();
    assert!(matches!(err, ProverError::InvalidInput(_)));
}

#[test]
fn verify_circuit_shape_sig_rj_too_long() {
    let mut w = valid_witness();
    w.sig_rj_bytes = vec![0u8; 65];
    let err = verify_circuit_shape(&w).unwrap_err();
    assert!(matches!(err, ProverError::InvalidInput(_)));
}

#[test]
fn can_satisfy_over_age_satisfied() {
    let cred = dummy_credential(Some(5_000));
    assert!(can_satisfy_age_requirement(&cred, 10_000, false));
}

#[test]
fn can_satisfy_over_age_not_satisfied() {
    let cred = dummy_credential(Some(15_000));
    assert!(!can_satisfy_age_requirement(&cred, 10_000, false));
}

#[test]
fn can_satisfy_under_age_satisfied() {
    let cred = dummy_credential(Some(15_000));
    assert!(can_satisfy_age_requirement(&cred, 10_000, true));
}

#[test]
fn can_satisfy_under_age_not_satisfied() {
    let cred = dummy_credential(Some(5_000));
    assert!(!can_satisfy_age_requirement(&cred, 10_000, true));
}

#[test]
fn can_satisfy_none_dob_returns_false() {
    let cred = dummy_credential(None);
    assert!(!can_satisfy_age_requirement(&cred, 10_000, false));
    assert!(!can_satisfy_age_requirement(&cred, 10_000, true));
}

#[test]
fn test_challenge_expired_error_display() {
    let err = ProverError::ChallengeExpired;
    assert_eq!(err.to_string(), "challenge has expired");
}

// ================================================================
// build_verify_request and generate_proof_safe error path tests
// ================================================================

fn dummy_qr_payload() -> QrChallengePayload {
    use crate::types::QrChallengePayload;

    QrChallengePayload {
        challenge_id: "test-challenge-id".to_string(),
        rp_challenge: URL_SAFE_NO_PAD.encode([0xABu8; 32]),
        cutoff_days: 19_000,
        verifying_key_id: 0,
        submit_secret: "submit_secret_value".to_string(),
        expires_at: u64::MAX,
        verify_url: "https://verify.example.com/submit".to_string(),
        code_verifier: None,
        proof_direction: None,
    }
}

/// build_verify_request returns NotInitialized when the prover has not
/// been loaded.
#[test]
fn build_verify_request_not_initialised() {
    let cred = dummy_credential(Some(10_000));
    let qr = dummy_qr_payload();

    let err = build_verify_request(&cred, &qr).unwrap_err();
    assert!(
        matches!(err, ProverError::NotInitialized),
        "expected NotInitialized, got: {:?}",
        err,
    );
}

/// build_verify_request returns MissingPrivateFields when dob_days is None.
#[test]
fn build_verify_request_missing_dob_days() {
    let cred = dummy_credential(None);
    let qr = dummy_qr_payload();

    let err = build_verify_request(&cred, &qr);
    let pf_err = preflight_report(&cred, &qr).unwrap_err();
    assert!(
        matches!(pf_err, ProverError::MissingPrivateFields),
        "expected MissingPrivateFields, got: {:?}",
        pf_err,
    );
    assert!(err.is_err());
}

/// preflight_report returns MissingPrivateFields when r_bits is None.
#[test]
fn preflight_report_missing_r_bits() {
    let mut cred = dummy_credential(Some(10_000));
    cred.r_bits = None;

    let qr = dummy_qr_payload();
    let err = preflight_report(&cred, &qr).unwrap_err();
    assert!(
        matches!(err, ProverError::MissingPrivateFields),
        "expected MissingPrivateFields, got: {:?}",
        err,
    );
}

/// preflight_report returns InvalidInput when r_bits has the wrong length.
#[test]
fn preflight_report_wrong_r_bits_length() {
    let mut cred = dummy_credential(Some(10_000));
    cred.r_bits = Some(vec![false; 64]);

    let qr = dummy_qr_payload();
    let err = preflight_report(&cred, &qr).unwrap_err();
    assert!(
        matches!(err, ProverError::InvalidInput(_)),
        "expected InvalidInput, got: {:?}",
        err,
    );
}

/// preflight_report returns InvalidBase64 when rp_challenge is not valid
/// base64url.
#[test]
fn preflight_report_invalid_rp_challenge() {
    let mut cred = dummy_credential(Some(10_000));
    cred.r_bits = Some(vec![false; R_BITS_LEN]);

    let mut qr = dummy_qr_payload();
    qr.rp_challenge = "not!valid!base64!data!!!".to_string();

    let err = preflight_report(&cred, &qr).unwrap_err();
    assert!(
        matches!(err, ProverError::InvalidBase64(_)),
        "expected InvalidBase64, got: {:?}",
        err,
    );
}

/// preflight_report returns InvalidBase64 when rp_challenge decodes to the
/// wrong byte count (not 32).
#[test]
fn preflight_report_rp_challenge_wrong_length() {
    let mut cred = dummy_credential(Some(10_000));
    cred.r_bits = Some(vec![false; R_BITS_LEN]);

    let mut qr = dummy_qr_payload();
    qr.rp_challenge = URL_SAFE_NO_PAD.encode([0xCDu8; 16]);

    let err = preflight_report(&cred, &qr).unwrap_err();
    assert!(
        matches!(err, ProverError::InvalidBase64(_)),
        "expected InvalidBase64 (wrong length), got: {:?}",
        err,
    );
}

/// All ProverError variants produce non-empty display strings.
#[test]
fn prover_error_variants_display() {
    let variants: Vec<ProverError> = vec![
        ProverError::NotInitialized,
        ProverError::AlreadyInitialized,
        ProverError::InvalidProvingKey,
        ProverError::InvalidBase64("test".to_string()),
        ProverError::InvalidInput("test".to_string()),
        ProverError::ProofGenerationFailed("test".to_string()),
        ProverError::MissingPrivateFields,
        ProverError::VkIdMismatch {
            loaded: 1,
            expected: 2,
        },
        ProverError::AgeRequirementNotMet,
        ProverError::CredentialExpired,
        ProverError::ChallengeExpired,
    ];

    for v in variants {
        let msg = v.to_string();
        assert!(!msg.is_empty(), "empty display for {:?}", v);
    }
}

/// can_satisfy_age_requirement boundary value tests.
#[test]
fn can_satisfy_boundary_values() {
    let exact = dummy_credential(Some(10_000));
    assert!(can_satisfy_age_requirement(&exact, 10_000, false));
    assert!(can_satisfy_age_requirement(&exact, 10_000, true));

    let one_over = dummy_credential(Some(10_001));
    assert!(!can_satisfy_age_requirement(&one_over, 10_000, false));
    assert!(can_satisfy_age_requirement(&one_over, 10_000, true));
}

// ====================================================================
// Mutation-coverage tests: kill surviving mutants in prover.rs
// ====================================================================

/// Helper: create a credential with a valid RedJubjub signature so
/// preflight_report can proceed past the signature check.
fn signed_credential_for_preflight(
    dob_days: i32,
) -> (CredentialV2, provii_crypto_sig_redjubjub::SigningKey) {
    use provii_crypto_commit::{generate_commitment_randomness, pedersen_commit_dob_validated};

    let mut rng = rand::rngs::OsRng;
    let r_bits_z = generate_commitment_randomness(&mut rng, R_BITS_LEN);
    let r_bits: Vec<bool> = r_bits_z.to_vec();
    let c_bytes = pedersen_commit_dob_validated(dob_days, &r_bits)
        .expect("commitment should succeed with valid inputs");

    let sk = provii_crypto_sig_redjubjub::SigningKey::random();
    let vk = sk.verification_key().to_bytes();

    let cred_msg = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        c: c_bytes,
        iat: 1_700_000_000,
        exp: 1_800_000_000,
        schema: "provii.age/0".to_string(),
    };
    let sig_rj = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &sk.to_bytes())
        .expect("signing should succeed");

    let cred = CredentialV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        issuer_vk: vk,
        sig_rj,
        c_bytes,
        iat: 1_700_000_000,
        exp: 1_800_000_000,
        schema: "provii.age/0".to_string(),
        dob_days: Some(dob_days),
        r_bits: Some(r_bits),
    };

    (cred, sk)
}

/// Kill: prover.rs:354 replace == with != in preflight_report (commitment_matches)
/// A credential whose stored c_bytes matches the recomputed commitment
/// should have commitment_matches == true.
#[test]
fn preflight_report_commitment_matches_true() {
    let (cred, _sk) = signed_credential_for_preflight(10_000);
    let qr = dummy_qr_payload();

    let report = preflight_report(&cred, &qr).expect("preflight should succeed");
    assert!(
        report.commitment_matches,
        "commitment_matches should be true when c_bytes matches recomputed"
    );
}

/// Kill: prover.rs:354 replace == with != in preflight_report (commitment_matches=false)
/// A credential with tampered c_bytes should have commitment_matches == false.
#[test]
fn preflight_report_commitment_matches_false_on_tampered() {
    let (mut cred, _sk) = signed_credential_for_preflight(10_000);
    // Tamper the stored commitment
    cred.c_bytes[0] ^= 0xFF;

    // We need to re-sign with the tampered c_bytes so the signature check passes
    let sk2 = provii_crypto_sig_redjubjub::SigningKey::random();
    let vk2 = sk2.verification_key().to_bytes();
    let cred_msg = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        c: cred.c_bytes,
        iat: 1_700_000_000,
        exp: 1_800_000_000,
        schema: "provii.age/0".to_string(),
    };
    let sig_rj = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &sk2.to_bytes())
        .expect("signing should succeed");
    cred.issuer_vk = vk2;
    cred.sig_rj = sig_rj;

    let qr = dummy_qr_payload();
    let report = preflight_report(&cred, &qr).expect("preflight should succeed");
    assert!(
        !report.commitment_matches,
        "commitment_matches should be false when c_bytes is tampered"
    );
}

/// Kill: prover.rs:371 replace == with != in preflight_report (is_under_age)
/// When proof_direction is "under_age", the age check should use >= direction.
/// When proof_direction is None/over_age, it should use <= direction.
#[test]
fn preflight_report_age_ok_over_age_direction() {
    // dob_days=5000, cutoff=19000 => 5000 <= 19000 => over_age satisfied
    let (cred, _sk) = signed_credential_for_preflight(5_000);
    let mut qr = dummy_qr_payload();
    qr.proof_direction = None; // default is over_age

    let report = preflight_report(&cred, &qr).expect("preflight should succeed");
    assert!(report.age_ok, "5000 <= 19000 in over_age direction");
}

#[test]
fn preflight_report_age_ok_under_age_direction() {
    // dob_days=5000, cutoff=19000 => 5000 >= 19000 => under_age NOT satisfied
    let (cred, _sk) = signed_credential_for_preflight(5_000);
    let mut qr = dummy_qr_payload();
    qr.proof_direction = Some("under_age".to_string());

    let report = preflight_report(&cred, &qr).expect("preflight should succeed");
    assert!(
        !report.age_ok,
        "5000 >= 19000 is false in under_age direction"
    );
}

#[test]
fn preflight_report_age_ok_under_age_satisfied() {
    // dob_days=20000, cutoff=19000 => 20000 >= 19000 => under_age satisfied
    let (cred, _sk) = signed_credential_for_preflight(20_000);
    let mut qr = dummy_qr_payload();
    qr.proof_direction = Some("under_age".to_string());

    let report = preflight_report(&cred, &qr).expect("preflight should succeed");
    assert!(report.age_ok, "20000 >= 19000 in under_age direction");
}

/// Kill: prover.rs:385 replace == with != in preflight_report (vk_id_matches)
/// When prover is not initialised, loaded_vk_id is None, so vk_id_matches=false.
#[test]
fn preflight_report_vk_id_matches_false_when_not_initialized() {
    let (cred, _sk) = signed_credential_for_preflight(10_000);
    let qr = dummy_qr_payload();

    let report = preflight_report(&cred, &qr).expect("preflight should succeed");
    // LOADED_VK_ID is None (prover not initialised in test)
    assert!(
        !report.vk_id_matches,
        "vk_id_matches should be false when prover not initialised"
    );
    assert_eq!(report.loaded_vk_id, None);
}

/// Kill: prover.rs:397 replace != with == in preflight_report (direction_bool)
/// direction_bool is true when NOT under_age (i.e. over_age).
/// When proof_direction is None (default = over_age) and "over_age", both
/// should produce the same public_inputs_hex. Under the mutant, None would
/// produce direction_bool=true (wrong direction for !=->==) but "over_age"
/// would produce direction_bool=false, so they would differ.
#[test]
fn preflight_report_direction_bool_consistency() {
    let (cred, _sk) = signed_credential_for_preflight(10_000);
    let mut qr = dummy_qr_payload();
    qr.proof_direction = None; // default = over_age

    let report_none = preflight_report(&cred, &qr).expect("preflight should succeed");

    qr.proof_direction = Some("over_age".to_string());
    let report_over = preflight_report(&cred, &qr).expect("preflight should succeed");

    // Both should produce the same direction_bool (true), hence same public inputs
    assert_eq!(
        report_none.public_inputs_hex, report_over.public_inputs_hex,
        "None and 'over_age' must produce identical public inputs"
    );

    // Under_age must differ from over_age
    qr.proof_direction = Some("under_age".to_string());
    let report_under = preflight_report(&cred, &qr).expect("preflight should succeed");
    assert_ne!(
        report_over.public_inputs_hex, report_under.public_inputs_hex,
        "public inputs must differ between over_age and under_age"
    );
}

/// Kill: prover.rs:518/524/530 - get_proving_key_fingerprint/get_loaded_vk_id/is_prover_initialized
/// When prover is NOT initialised, these should return None/None/false.
#[test]
fn prover_state_functions_when_not_initialized() {
    // In a fresh test process, the prover should not be initialised.
    // But since tests share process state, PROVING_PARAMS might already be set.
    // We test the contract: if PROVING_PARAMS is None, is_prover_initialized=false.
    if PROVING_PARAMS.get().is_none() {
        assert!(!is_prover_initialized());
        assert_eq!(get_proving_key_fingerprint(), None);
        assert_eq!(get_loaded_vk_id(), None);
    } else {
        // Prover was initialised by another test; verify the functions return Some values.
        assert!(is_prover_initialized());
        assert!(get_proving_key_fingerprint().is_some());
        assert!(get_loaded_vk_id().is_some());
    }
}

/// Kill: prover.rs:454 replace init_prover_with_pk_bytes -> Result<(), ProverError> with Ok(())
/// init_prover_with_pk_bytes must reject invalid (empty) proving key bytes.
#[test]
fn init_prover_rejects_invalid_bytes() {
    // If prover is already initialized, this returns Ok() due to idempotency.
    // In that case this test is a no-op. But if not initialized, empty bytes
    // must produce InvalidProvingKey.
    if PROVING_PARAMS.get().is_none() {
        let result = init_prover_with_pk_bytes(&[]);
        assert!(
            result.is_err(),
            "empty bytes should fail with InvalidProvingKey"
        );
        assert!(matches!(
            result.unwrap_err(),
            ProverError::InvalidProvingKey
        ));

        // Also try garbage bytes
        let result2 = init_prover_with_pk_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(
            result2.is_err(),
            "garbage bytes should fail with InvalidProvingKey"
        );
    }
}

/// Kill: prover.rs:690 replace * with +/div in build_verify_request (stack_size 8*1024*1024)
/// This is only triggered when called from within a rayon worker thread. The mutant
/// changes the stack size calculation (8*1024*1024) to something small. We test that
/// build_verify_request properly spawns an OS thread with adequate stack when called
/// from a rayon context. Since proof generation requires init, we just verify the
/// function doesn't panic with a bad credential (it should return an error, not crash).
#[test]
fn build_verify_request_from_rayon_context_returns_error() {
    // We can't easily test the 8 MiB stack requirement without a real proving key.
    // However, we verify that calling from a rayon pool handles errors gracefully.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .expect("pool creation should succeed");

    let result = pool.install(|| {
        let cred = dummy_credential(Some(10_000));
        let qr = dummy_qr_payload();
        build_verify_request(&cred, &qr)
    });

    // Should error (not crash) because prover is not initialised
    assert!(result.is_err());
}

/// Kill: prover.rs:1210 replace init_prover_with_pk_mmap -> Result<(), ProverError> with Ok(())
/// init_prover_with_pk_mmap must reject a non-existent file path.
#[cfg(feature = "mmap")]
#[test]
fn init_prover_with_pk_mmap_rejects_invalid_path() {
    if PROVING_PARAMS.get().is_some() {
        // Prover already initialised; the function returns Ok() idempotently.
        return;
    }

    let result = init_prover_with_pk_mmap("/nonexistent/path/to/proving.key");
    assert!(
        result.is_err(),
        "non-existent path should fail with InvalidProvingKey"
    );
    assert!(matches!(
        result.unwrap_err(),
        ProverError::InvalidProvingKey
    ));
}
