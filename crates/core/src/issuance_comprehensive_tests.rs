// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

    use super::*;

    /// Create a properly signed test header for a given commitment.
    ///
    /// Generates a fresh RedJubjub signing key, signs the credential fields,
    /// and returns a [`SignedCredentialHeader`] with a valid signature. Tests
    /// that call [`finalize_credential`] must use this helper. Stub bytes no
    /// longer pass signature verification.
    fn create_test_header(
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

    // ============================================================
    // Section 1: compute_commitment edge cases (15 tests)
    // ============================================================

    #[test]
    fn test_compute_commitment_zero_dob() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let parts = compute_commitment(0)?;
        assert_eq!(parts.dob_days, 0);
        assert_eq!(parts.r_bits.len(), R_BITS_LEN);
        assert_eq!(parts.c_bytes.len(), 32);

        // Verify commitment
        let c_verify = pedersen_commit_dob_validated(0, &parts.r_bits).unwrap();
        assert_eq!(c_verify, parts.c_bytes);
        Ok(())
    }

    #[test]
    fn test_compute_commitment_small_values() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        for dob in [1, 10, 100, 365, 1000] {
            let parts = compute_commitment(dob)?;
            assert_eq!(parts.dob_days, dob);
            assert_eq!(parts.r_bits.len(), R_BITS_LEN);

            // Verify commitment
            let c_verify = pedersen_commit_dob_validated(dob, &parts.r_bits).unwrap();
            assert_eq!(c_verify, parts.c_bytes);
        }
        Ok(())
    }

    #[test]
    fn test_compute_commitment_max_i32() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let parts = compute_commitment(i32::MAX)?;
        assert_eq!(parts.dob_days, i32::MAX);
        assert_eq!(parts.r_bits.len(), R_BITS_LEN);

        // Verify commitment
        let c_verify = pedersen_commit_dob_validated(i32::MAX, &parts.r_bits).unwrap();
        assert_eq!(c_verify, parts.c_bytes);
        Ok(())
    }

    #[test]
    fn test_compute_commitment_near_max() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = i32::MAX - 1;
        let parts = compute_commitment(dob)?;
        assert_eq!(parts.dob_days, dob);

        // Verify commitment
        let c_verify = pedersen_commit_dob_validated(dob, &parts.r_bits).unwrap();
        assert_eq!(c_verify, parts.c_bytes);
        Ok(())
    }

    #[test]
    fn test_compute_commitment_randomness_varies(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let parts1 = compute_commitment(dob)?;
        let parts2 = compute_commitment(dob)?;

        // Same DOB should produce different r_bits (randomness)
        assert_ne!(parts1.r_bits, parts2.r_bits);

        // Different r_bits should produce different commitments
        assert_ne!(parts1.c_bytes, parts2.c_bytes);
        Ok(())
    }

    #[test]
    fn test_compute_commitment_randomness_quality(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Test that r_bits are not trivial (not all same value)
        let parts = compute_commitment(10000)?;

        let all_true = parts.r_bits.iter().all(|&b| b);
        let all_false = parts.r_bits.iter().all(|&b| !b);

        assert!(!all_true, "r_bits should not be all true");
        assert!(!all_false, "r_bits should not be all false");
        Ok(())
    }

    #[test]
    fn test_compute_commitment_18_years_old() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        // Approximate days for 18 years old
        let days_18_years = 18 * 365 + 4; // Include leap years
        let parts = compute_commitment(days_18_years)?;

        assert_eq!(parts.dob_days, days_18_years);
        assert_eq!(parts.r_bits.len(), R_BITS_LEN);
        Ok(())
    }

    #[test]
    fn test_compute_commitment_c_bytes_always_32(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        for dob in [0, 1, 100, 10000, i32::MAX] {
            let parts = compute_commitment(dob)?;
            assert_eq!(parts.c_bytes.len(), 32);
        }
        Ok(())
    }

    #[test]
    fn test_compute_commitment_r_bits_always_128(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        for dob in [0, 1, 100, 10000, i32::MAX] {
            let parts = compute_commitment(dob)?;
            assert_eq!(parts.r_bits.len(), R_BITS_LEN);
            assert_eq!(parts.r_bits.len(), 128);
        }
        Ok(())
    }

    #[test]
    fn test_compute_commitment_multiple_calls_different(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let mut commitments = Vec::new();

        // Generate 10 commitments
        for _ in 0..10 {
            let parts = compute_commitment(dob)?;
            commitments.push(parts.c_bytes);
        }

        // All should be unique (with extremely high probability)
        for i in 0..commitments.len() {
            for j in (i + 1)..commitments.len() {
                assert_ne!(commitments[i], commitments[j]);
            }
        }
        Ok(())
    }

    #[test]
    fn test_compute_commitment_today_dob() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Test with "today" as DOB (0 years old)
        let today_days = (chrono::Utc::now().timestamp() / 86400) as i32;
        let parts = compute_commitment(today_days)?;

        assert_eq!(parts.dob_days, today_days);
        assert_eq!(parts.r_bits.len(), R_BITS_LEN);
        Ok(())
    }

    #[test]
    fn test_compute_commitment_very_old_person(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // 120 years old
        let days_120_years = 120 * 365 + 30; // Include leap years
        let parts = compute_commitment(days_120_years)?;

        assert_eq!(parts.dob_days, days_120_years);
        let c_verify = pedersen_commit_dob_validated(days_120_years, &parts.r_bits).unwrap();
        assert_eq!(c_verify, parts.c_bytes);
        Ok(())
    }

    #[test]
    fn test_compute_commitment_structure_fields(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let parts = compute_commitment(10000)?;

        // Verify CommitmentParts structure is complete
        assert!(parts.dob_days > 0);
        assert!(!parts.r_bits.is_empty());
        assert_ne!(parts.c_bytes, [0u8; 32]);
        Ok(())
    }

    #[test]
    fn test_compute_commitment_deterministic_verification(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Test that commitment can be verified deterministically
        let dob = 10000;
        let parts = compute_commitment(dob)?;

        // Multiple verifications should always succeed
        for _ in 0..5 {
            let c_verify = pedersen_commit_dob_validated(parts.dob_days, &parts.r_bits).unwrap();
            assert_eq!(c_verify, parts.c_bytes);
        }
        Ok(())
    }

    #[test]
    fn test_compute_commitment_year_boundaries(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Test dates at year boundaries
        let dates = [
            365,      // End of year 1
            365 * 2,  // End of year 2
            365 * 10, // End of year 10
            365 * 50, // End of year 50
        ];

        for days in dates {
            let parts = compute_commitment(days)?;
            assert_eq!(parts.dob_days, days);
            let c_verify = pedersen_commit_dob_validated(days, &parts.r_bits).unwrap();
            assert_eq!(c_verify, parts.c_bytes);
        }
        Ok(())
    }

    // ============================================================
    // Section 2: compute_commitment_with_seed tests (10 tests)
    // ============================================================

    #[test]
    fn test_deterministic_commitment_same_seed_same_output(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let seed = [42u8; 32];
        let dob = 10000;

        let parts1 = compute_commitment_with_seed(dob, seed)?;
        let parts2 = compute_commitment_with_seed(dob, seed)?;

        assert_eq!(parts1.dob_days, parts2.dob_days);
        assert_eq!(parts1.r_bits, parts2.r_bits);
        assert_eq!(parts1.c_bytes, parts2.c_bytes);
        Ok(())
    }

    #[test]
    fn test_deterministic_commitment_different_seeds(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];
        let dob = 10000;

        let parts1 = compute_commitment_with_seed(dob, seed1)?;
        let parts2 = compute_commitment_with_seed(dob, seed2)?;

        // Different seeds should produce different r_bits and c_bytes
        assert_ne!(parts1.r_bits, parts2.r_bits);
        assert_ne!(parts1.c_bytes, parts2.c_bytes);
        Ok(())
    }

    #[test]
    fn test_deterministic_commitment_zero_seed(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let seed = [0u8; 32];
        let dob = 10000;

        let parts = compute_commitment_with_seed(dob, seed)?;
        assert_eq!(parts.dob_days, dob);
        assert_eq!(parts.r_bits.len(), R_BITS_LEN);

        // Verify commitment
        let c_verify = pedersen_commit_dob_validated(dob, &parts.r_bits).unwrap();
        assert_eq!(c_verify, parts.c_bytes);
        Ok(())
    }

    #[test]
    fn test_deterministic_commitment_max_seed(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let seed = [0xFFu8; 32];
        let dob = 10000;

        let parts = compute_commitment_with_seed(dob, seed)?;
        assert_eq!(parts.dob_days, dob);
        assert_eq!(parts.r_bits.len(), R_BITS_LEN);

        // Verify commitment
        let c_verify = pedersen_commit_dob_validated(dob, &parts.r_bits).unwrap();
        assert_eq!(c_verify, parts.c_bytes);
        Ok(())
    }

    #[test]
    fn test_deterministic_commitment_sequential_seeds(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let mut commitments = Vec::new();

        for i in 0..10u8 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            let parts = compute_commitment_with_seed(dob, seed)?;
            commitments.push(parts.c_bytes);
        }

        // All should be unique
        for i in 0..commitments.len() {
            for j in (i + 1)..commitments.len() {
                assert_ne!(commitments[i], commitments[j]);
            }
        }
        Ok(())
    }

    #[test]
    fn test_deterministic_commitment_r_bits_length(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(10000, seed)?;

        assert_eq!(parts.r_bits.len(), R_BITS_LEN);
        assert_eq!(parts.r_bits.len(), 128);
        Ok(())
    }

    #[test]
    fn test_deterministic_commitment_different_dobs_same_seed(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let seed = [42u8; 32];

        let parts1 = compute_commitment_with_seed(10000, seed)?;
        let parts2 = compute_commitment_with_seed(20000, seed)?;

        // Same seed produces same r_bits
        assert_eq!(parts1.r_bits, parts2.r_bits);

        // But different DOBs produce different commitments
        assert_ne!(parts1.c_bytes, parts2.c_bytes);
        Ok(())
    }

    #[test]
    fn test_deterministic_commitment_multiple_runs(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let seed = [99u8; 32];
        let dob = 15000;

        // Run 100 times with same seed
        let first = compute_commitment_with_seed(dob, seed)?;

        for _ in 0..100 {
            let parts = compute_commitment_with_seed(dob, seed)?;
            assert_eq!(parts.c_bytes, first.c_bytes);
            assert_eq!(parts.r_bits, first.r_bits);
        }
        Ok(())
    }

    #[test]
    fn test_deterministic_commitment_edge_dobs(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let seed = [42u8; 32];

        for dob in [0, 1, i32::MAX - 1, i32::MAX] {
            let parts = compute_commitment_with_seed(dob, seed)?;
            assert_eq!(parts.dob_days, dob);

            let c_verify = pedersen_commit_dob_validated(dob, &parts.r_bits).unwrap();
            assert_eq!(c_verify, parts.c_bytes);
        }
        Ok(())
    }

    #[test]
    fn test_deterministic_commitment_verify_consistency(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let seed = [123u8; 32];
        let dob = 18000;

        let parts1 = compute_commitment_with_seed(dob, seed)?;

        // Manually verify the commitment
        let manual_c = pedersen_commit_dob_validated(parts1.dob_days, &parts1.r_bits).unwrap();
        assert_eq!(manual_c, parts1.c_bytes);

        // Generate again and verify it's the same
        let parts2 = compute_commitment_with_seed(dob, seed)?;
        assert_eq!(parts1.c_bytes, parts2.c_bytes);
        Ok(())
    }

    // ============================================================
    // Section 3: finalize_credential tests (20 tests)
    // ============================================================

    #[test]
    fn test_finalize_credential_valid() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        let cred = finalize_credential(header.clone(), dob, parts.r_bits.clone())?;

        assert_eq!(cred.v, header.v);
        assert_eq!(cred.kid, header.kid);
        assert_eq!(cred.issuer_vk, header.issuer_vk);
        assert_eq!(cred.sig_rj, header.sig_rj);
        assert_eq!(cred.c_bytes, header.c_bytes);
        assert_eq!(cred.iat, header.iat);
        assert_eq!(cred.exp, header.exp);
        assert_eq!(cred.schema, header.schema);
        assert_eq!(cred.dob_days, Some(dob));
        assert_eq!(cred.r_bits, Some(parts.r_bits.clone()));
        Ok(())
    }

    #[test]
    fn test_finalize_credential_r_bits_too_short(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        // Use only 127 bits
        let short_r_bits: Vec<bool> = parts.r_bits.iter().take(127).copied().collect();

        let result = finalize_credential(header, dob, short_r_bits);
        assert!(result.is_err());

        if let Err(WalletError::InvalidInput(msg)) = result {
            assert!(msg.contains("127"));
            assert!(msg.contains("128"));
        } else {
            return Err("Expected InvalidInput error".into());
        }
        Ok(())
    }

    #[test]
    fn test_finalize_credential_r_bits_too_long(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        // Use 129 bits
        let mut long_r_bits = parts.r_bits.clone();
        long_r_bits.push(true);

        let result = finalize_credential(header, dob, long_r_bits);
        assert!(result.is_err());

        if let Err(WalletError::InvalidInput(msg)) = result {
            assert!(msg.contains("129"));
        } else {
            return Err("Expected InvalidInput error".into());
        }
        Ok(())
    }

    #[test]
    fn test_finalize_credential_r_bits_exactly_128(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        assert_eq!(parts.r_bits.len(), 128);

        let result = finalize_credential(header, dob, parts.r_bits.clone());
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_finalize_credential_wrong_dob() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let wrong_dob = 9999;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        let result = finalize_credential(header, wrong_dob, parts.r_bits.clone());
        assert!(result.is_err());

        if let Err(WalletError::ValidationFailed(msg)) = result {
            assert!(msg.contains("Commitment mismatch"));
        } else {
            return Err("Expected ValidationFailed error".into());
        }
        Ok(())
    }

    #[test]
    fn test_finalize_credential_wrong_r_bits() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let dob = 10000;
        let seed1 = [42u8; 32];
        let seed2 = [99u8; 32];
        let parts1 = compute_commitment_with_seed(dob, seed1)?;
        let parts2 = compute_commitment_with_seed(dob, seed2)?;
        let header = create_test_header(parts1.c_bytes)?;

        // Use r_bits from parts2 (wrong)
        let result = finalize_credential(header, dob, parts2.r_bits.clone());
        assert!(result.is_err());

        if let Err(WalletError::ValidationFailed(msg)) = result {
            assert!(msg.contains("Commitment mismatch"));
        } else {
            return Err("Expected ValidationFailed error".into());
        }
        Ok(())
    }

    #[test]
    fn test_finalize_credential_dob_zero() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 0;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        let cred = finalize_credential(header, dob, parts.r_bits.clone())?;
        assert_eq!(cred.dob_days, Some(0));
        Ok(())
    }

    #[test]
    fn test_finalize_credential_dob_max() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = i32::MAX;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        let cred = finalize_credential(header, dob, parts.r_bits.clone())?;
        assert_eq!(cred.dob_days, Some(i32::MAX));
        Ok(())
    }

    #[test]
    fn test_finalize_credential_empty_r_bits() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let dob = 10000;
        let empty_r_bits: Vec<bool> = Vec::new();
        let header = create_test_header([0u8; 32])?;

        let result = finalize_credential(header, dob, empty_r_bits);
        assert!(result.is_err());

        if let Err(WalletError::InvalidInput(msg)) = result {
            assert!(msg.contains("0"));
        } else {
            return Err("Expected InvalidInput error".into());
        }
        Ok(())
    }

    #[test]
    fn test_finalize_credential_r_bits_all_false(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // All-false r_bits have zero entropy and are rejected by the validated API.
        let dob = 10000;
        let r_bits = vec![false; 128];
        let header = create_test_header([0u8; 32])?;

        let result = finalize_credential(header, dob, r_bits);
        assert!(result.is_err(), "Expected error for zero-entropy r_bits");
        Ok(())
    }

    #[test]
    fn test_finalize_credential_r_bits_all_true(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // All-true r_bits have zero entropy and are rejected by the validated API.
        let dob = 10000;
        let r_bits = vec![true; 128];
        let header = create_test_header([0xFFu8; 32])?;

        let result = finalize_credential(header, dob, r_bits);
        assert!(result.is_err(), "Expected error for zero-entropy r_bits");
        Ok(())
    }

    #[test]
    fn test_finalize_credential_rejects_zero_timestamps(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;

        // Build a signed header with iat=0, exp=0 embedded in the signature.
        let sk = provii_crypto_sig_redjubjub::SigningKey::random();
        let vk = sk.verification_key().to_bytes();
        let cred_msg = provii_crypto_commons::CredMsgV2 {
            v: 2,
            kid: "test-key".to_string(),
            c: parts.c_bytes,
            iat: 0,
            exp: 0,
            schema: "provii.age/0".to_string(),
        };
        let sig_rj = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &sk.to_bytes())?;
        let header = SignedCredentialHeader {
            v: 2,
            kid: "test-key".to_string(),
            issuer_vk: vk,
            sig_rj,
            c_bytes: parts.c_bytes,
            iat: 0,
            exp: 0,
            schema: "provii.age/0".to_string(),
        };

        let result = finalize_credential(header, dob, parts.r_bits.clone());
        assert!(result.is_err(), "zero timestamps must be rejected");
        if let Err(WalletError::ValidationFailed(msg)) = result {
            assert!(msg.contains("zero"));
        }
        Ok(())
    }

    #[test]
    fn test_finalize_credential_max_timestamps(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;

        // Build a signed header with iat=u64::MAX, exp=u64::MAX embedded.
        let sk = provii_crypto_sig_redjubjub::SigningKey::random();
        let vk = sk.verification_key().to_bytes();
        let cred_msg = provii_crypto_commons::CredMsgV2 {
            v: 2,
            kid: "test-key".to_string(),
            c: parts.c_bytes,
            iat: u64::MAX,
            exp: u64::MAX,
            schema: "provii.age/0".to_string(),
        };
        let sig_rj = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &sk.to_bytes())?;
        let header = SignedCredentialHeader {
            v: 2,
            kid: "test-key".to_string(),
            issuer_vk: vk,
            sig_rj,
            c_bytes: parts.c_bytes,
            iat: u64::MAX,
            exp: u64::MAX,
            schema: "provii.age/0".to_string(),
        };

        let cred = finalize_credential(header, dob, parts.r_bits.clone())?;
        assert_eq!(cred.iat, u64::MAX);
        assert_eq!(cred.exp, u64::MAX);
        Ok(())
    }

    #[test]
    fn test_finalize_credential_all_fields_transferred(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;

        // Build a signed header with custom field values.
        let sk = provii_crypto_sig_redjubjub::SigningKey::random();
        let vk = sk.verification_key().to_bytes();
        let cred_msg = provii_crypto_commons::CredMsgV2 {
            v: 2,
            kid: "unique-kid-123".to_string(),
            c: parts.c_bytes,
            iat: 123456789,
            exp: 987654321,
            schema: "custom.schema.v3".to_string(),
        };
        let sig_rj = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &sk.to_bytes())?;
        let header = SignedCredentialHeader {
            v: 2,
            kid: "unique-kid-123".to_string(),
            issuer_vk: vk,
            sig_rj,
            c_bytes: parts.c_bytes,
            iat: 123456789,
            exp: 987654321,
            schema: "custom.schema.v3".to_string(),
        };

        let cred = finalize_credential(header.clone(), dob, parts.r_bits.clone())?;

        assert_eq!(cred.v, 2);
        assert_eq!(cred.kid, "unique-kid-123");
        assert_eq!(cred.issuer_vk, vk);
        assert_eq!(cred.sig_rj, sig_rj);
        assert_eq!(cred.c_bytes, parts.c_bytes);
        assert_eq!(cred.iat, 123456789);
        assert_eq!(cred.exp, 987654321);
        assert_eq!(cred.schema, "custom.schema.v3");
        assert_eq!(cred.dob_days, Some(dob));
        assert_eq!(cred.r_bits, Some(parts.r_bits.clone()));
        Ok(())
    }

    #[test]
    fn test_finalize_credential_error_message_format(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        // Too short
        let result = finalize_credential(header, dob, vec![true; 100]);
        if let Err(WalletError::InvalidInput(msg)) = result {
            assert!(msg.contains("r_bits must be"));
            assert!(msg.contains("128"));
            assert!(msg.contains("100"));
        } else {
            return Err("Expected InvalidInput error".into());
        }
        Ok(())
    }

    #[test]
    fn test_finalize_credential_validation_failed_message(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let wrong_dob = 5000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        let result = finalize_credential(header, wrong_dob, parts.r_bits.clone());
        if let Err(WalletError::ValidationFailed(msg)) = result {
            assert!(msg.contains("Commitment mismatch"));
            assert!(msg.contains("private fields"));
        } else {
            return Err("Expected ValidationFailed error".into());
        }
        Ok(())
    }

    #[test]
    fn test_finalize_credential_unicode_in_header(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;

        // Sign a header whose kid and schema contain Unicode characters.
        let kid = "test-🔑-日本語";
        let schema = "provii.年齢.v2";
        let sk = provii_crypto_sig_redjubjub::SigningKey::random();
        let vk = sk.verification_key().to_bytes();
        let cred_msg = provii_crypto_commons::CredMsgV2 {
            v: 2,
            kid: kid.to_string(),
            c: parts.c_bytes,
            iat: 1000000,
            exp: 2000000,
            schema: schema.to_string(),
        };
        let sig_rj = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &sk.to_bytes())?;
        let header = SignedCredentialHeader {
            v: 2,
            kid: kid.to_string(),
            issuer_vk: vk,
            sig_rj,
            c_bytes: parts.c_bytes,
            iat: 1000000,
            exp: 2000000,
            schema: schema.to_string(),
        };

        let cred = finalize_credential(header.clone(), dob, parts.r_bits.clone())?;
        assert_eq!(cred.kid, kid);
        assert_eq!(cred.schema, schema);
        Ok(())
    }

    #[test]
    fn test_finalize_credential_preserves_all_bytes(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;

        let header = create_test_header(parts.c_bytes)?;
        let cred = finalize_credential(header.clone(), dob, parts.r_bits.clone())?;

        // Verify every byte is preserved
        for i in 0..32 {
            assert_eq!(cred.issuer_vk[i], header.issuer_vk[i]);
            assert_eq!(cred.c_bytes[i], header.c_bytes[i]);
        }

        for i in 0..64 {
            assert_eq!(cred.sig_rj[i], header.sig_rj[i]);
        }
        Ok(())
    }

    #[test]
    fn test_finalize_credential_multiple_finalizations(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        // Finalize multiple times with same inputs
        let cred1 = finalize_credential(header.clone(), dob, parts.r_bits.clone())?;
        let cred2 = finalize_credential(header.clone(), dob, parts.r_bits.clone())?;

        assert_eq!(cred1.credential_id(), cred2.credential_id());
        assert_eq!(cred1.dob_days, cred2.dob_days);
        assert_eq!(cred1.r_bits, cred2.r_bits);
        Ok(())
    }

    // ============================================================
    // Section 4: assemble_credential tests (8 tests)
    // ============================================================

    #[test]
    fn test_assemble_credential_valid() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        let cred = assemble_credential(&header, dob, &parts.r_bits)?;

        assert_eq!(cred.v, header.v);
        assert_eq!(cred.dob_days, Some(dob));
        assert_eq!(cred.r_bits, Some(parts.r_bits.clone()));
        Ok(())
    }

    #[test]
    fn test_assemble_credential_equivalent_to_finalize(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        let cred1 = assemble_credential(&header, dob, &parts.r_bits)?;
        let cred2 = finalize_credential(header.clone(), dob, parts.r_bits.clone())?;

        assert_eq!(cred1.credential_id(), cred2.credential_id());
        assert_eq!(cred1.dob_days, cred2.dob_days);
        assert_eq!(cred1.r_bits, cred2.r_bits);
        Ok(())
    }

    #[test]
    fn test_assemble_credential_borrowed_header(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        // Borrow header
        let cred = assemble_credential(&header, dob, &parts.r_bits)?;

        // Header should still be usable
        assert_eq!(header.v, 2);
        assert_eq!(cred.v, header.v);
        Ok(())
    }

    #[test]
    fn test_assemble_credential_borrowed_r_bits(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        // Borrow r_bits
        let cred = assemble_credential(&header, dob, &parts.r_bits)?;

        // r_bits should still be usable
        assert_eq!(parts.r_bits.len(), 128);
        assert_eq!(cred.r_bits.as_ref().ok_or("missing r_bits")?.len(), 128);
        Ok(())
    }

    #[test]
    fn test_assemble_credential_error_propagation(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let wrong_dob = 9999;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        // Should error with wrong DOB
        let result = assemble_credential(&header, wrong_dob, &parts.r_bits);
        assert!(result.is_err());

        if let Err(WalletError::ValidationFailed(_)) = result {
            // Correct error type
        } else {
            return Err("Expected ValidationFailed error".into());
        }
        Ok(())
    }

    #[test]
    fn test_assemble_credential_slice_conversion(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        // Pass as slice
        let r_bits_slice: &[bool] = &parts.r_bits;
        let cred = assemble_credential(&header, dob, r_bits_slice)?;

        assert_eq!(cred.r_bits.as_ref().ok_or("missing r_bits")?.len(), 128);
        Ok(())
    }

    #[test]
    fn test_assemble_credential_multiple_assemblies(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        // Assemble multiple times
        let cred1 = assemble_credential(&header, dob, &parts.r_bits)?;
        let cred2 = assemble_credential(&header, dob, &parts.r_bits)?;

        assert_eq!(cred1.credential_id(), cred2.credential_id());
        Ok(())
    }

    #[test]
    fn test_assemble_credential_edge_case_dobs(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let seed = [42u8; 32];

        for dob in [0, 1, i32::MAX] {
            let parts = compute_commitment_with_seed(dob, seed)?;
            let header = create_test_header(parts.c_bytes)?;

            let cred = assemble_credential(&header, dob, &parts.r_bits)?;
            assert_eq!(cred.dob_days, Some(dob));
        }
        Ok(())
    }

    // ============================================================
    // Section 5: bits::pack_bits tests (20 tests)
    // ============================================================

    #[test]
    fn test_pack_bits_empty() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bits: Vec<bool> = vec![];
        let packed = bits::pack_bits(&bits);
        assert_eq!(packed.len(), 0);
        Ok(())
    }

    #[test]
    fn test_pack_bits_single_bit_true() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bits = vec![true];
        let packed = bits::pack_bits(&bits);
        assert_eq!(packed.len(), 1);
        assert_eq!(packed[0], 0b10000000);
        Ok(())
    }

    #[test]
    fn test_pack_bits_single_bit_false() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bits = vec![false];
        let packed = bits::pack_bits(&bits);
        assert_eq!(packed.len(), 1);
        assert_eq!(packed[0], 0b00000000);
        Ok(())
    }

    #[test]
    fn test_pack_bits_eight_bits_exactly() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bits = vec![true, false, true, true, false, false, true, false];
        let packed = bits::pack_bits(&bits);
        assert_eq!(packed.len(), 1);
        assert_eq!(packed[0], 0b10110010);
        Ok(())
    }

    #[test]
    fn test_pack_bits_seven_bits() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bits = vec![true, false, true, true, false, false, true];
        let packed = bits::pack_bits(&bits);
        assert_eq!(packed.len(), 1);
        // 7 bits: 1011001 + padding 0
        assert_eq!(packed[0], 0b10110010);
        Ok(())
    }

    #[test]
    fn test_pack_bits_nine_bits() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bits = vec![true, false, true, true, false, false, true, false, true];
        let packed = bits::pack_bits(&bits);
        assert_eq!(packed.len(), 2);
        assert_eq!(packed[0], 0b10110010);
        assert_eq!(packed[1], 0b10000000);
        Ok(())
    }

    #[test]
    fn test_pack_bits_128_bits() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bits = vec![true; 128];
        let packed = bits::pack_bits(&bits);
        assert_eq!(packed.len(), 16);
        for byte in packed {
            assert_eq!(byte, 0xFF);
        }
        Ok(())
    }

    #[test]
    fn test_pack_bits_all_true() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bits = vec![true; 16];
        let packed = bits::pack_bits(&bits);
        assert_eq!(packed.len(), 2);
        assert_eq!(packed[0], 0xFF);
        assert_eq!(packed[1], 0xFF);
        Ok(())
    }

    #[test]
    fn test_pack_bits_all_false() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bits = vec![false; 16];
        let packed = bits::pack_bits(&bits);
        assert_eq!(packed.len(), 2);
        assert_eq!(packed[0], 0x00);
        assert_eq!(packed[1], 0x00);
        Ok(())
    }

    #[test]
    fn test_pack_bits_alternating_pattern() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bits = vec![true, false, true, false, true, false, true, false];
        let packed = bits::pack_bits(&bits);
        assert_eq!(packed.len(), 1);
        assert_eq!(packed[0], 0b10101010);
        Ok(())
    }

    #[test]
    fn test_pack_bits_msb_first() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Test that MSB comes first
        let bits = vec![true, false, false, false, false, false, false, false];
        let packed = bits::pack_bits(&bits);
        assert_eq!(packed[0], 0b10000000);
        Ok(())
    }

    #[test]
    fn test_pack_bits_large_vector() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bits = vec![true; 1024];
        let packed = bits::pack_bits(&bits);
        assert_eq!(packed.len(), 128);
        for byte in packed {
            assert_eq!(byte, 0xFF);
        }
        Ok(())
    }

    #[test]
    fn test_pack_bits_single_true_at_start() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let bits = vec![true, false, false, false, false, false, false, false];
        let packed = bits::pack_bits(&bits);
        assert_eq!(packed[0], 0b10000000);
        Ok(())
    }

    #[test]
    fn test_pack_bits_single_true_at_end() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bits = vec![false, false, false, false, false, false, false, true];
        let packed = bits::pack_bits(&bits);
        assert_eq!(packed[0], 0b00000001);
        Ok(())
    }

    #[test]
    fn test_pack_bits_byte_boundary_handling() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        // Test exactly 16 bits (2 bytes)
        let bits = vec![
            true, false, true, false, true, false, true, false, // Byte 1: 0xAA
            false, true, false, true, false, true, false, true, // Byte 2: 0x55
        ];
        let packed = bits::pack_bits(&bits);
        assert_eq!(packed.len(), 2);
        assert_eq!(packed[0], 0b10101010);
        assert_eq!(packed[1], 0b01010101);
        Ok(())
    }

    #[test]
    fn test_pack_bits_partial_last_byte() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // 10 bits = 1 full byte + 2 bits in second byte
        let bits = vec![true, true, true, true, true, true, true, true, false, false];
        let packed = bits::pack_bits(&bits);
        assert_eq!(packed.len(), 2);
        assert_eq!(packed[0], 0xFF);
        assert_eq!(packed[1], 0b00000000);
        Ok(())
    }

    #[test]
    fn test_pack_bits_known_pattern_1() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bits = vec![false, false, true, true, false, false, true, true];
        let packed = bits::pack_bits(&bits);
        assert_eq!(packed[0], 0b00110011);
        Ok(())
    }

    #[test]
    fn test_pack_bits_known_pattern_2() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bits = vec![true, true, false, false, true, true, false, false];
        let packed = bits::pack_bits(&bits);
        assert_eq!(packed[0], 0b11001100);
        Ok(())
    }

    #[test]
    fn test_pack_bits_128_mixed_pattern() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Create a mixed pattern for R_BITS_LEN
        let mut bits = Vec::with_capacity(128);
        for i in 0..128 {
            bits.push(i % 3 == 0); // Every 3rd bit is true
        }
        let packed = bits::pack_bits(&bits);
        assert_eq!(packed.len(), 16);

        // Verify roundtrip
        let unpacked = bits::unpack_bits(&packed, 128);
        assert_eq!(unpacked, bits);
        Ok(())
    }

    #[test]
    fn test_pack_bits_capacity_allocation() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bits = vec![true; 100];
        let packed = bits::pack_bits(&bits);
        // 100 bits = 13 bytes (12 full + 1 partial)
        assert_eq!(packed.len(), 13);
        Ok(())
    }

    // ============================================================
    // Section 6: bits::unpack_bits tests (20 tests)
    // ============================================================

    #[test]
    fn test_unpack_bits_empty() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes: Vec<u8> = vec![];
        let bits = bits::unpack_bits(&bytes, 0);
        assert_eq!(bits.len(), 0);
        Ok(())
    }

    #[test]
    fn test_unpack_bits_single_byte_to_8_bits(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = vec![0b10110010];
        let bits = bits::unpack_bits(&bytes, 8);
        assert_eq!(bits.len(), 8);
        assert_eq!(
            bits,
            vec![true, false, true, true, false, false, true, false]
        );
        Ok(())
    }

    #[test]
    fn test_unpack_bits_single_byte_to_fewer_bits(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = vec![0b10110010];
        let bits = bits::unpack_bits(&bytes, 5);
        assert_eq!(bits.len(), 5);
        assert_eq!(bits, vec![true, false, true, true, false]);
        Ok(())
    }

    #[test]
    fn test_unpack_bits_two_bytes_to_16_bits() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let bytes = vec![0b10101010, 0b01010101];
        let bits = bits::unpack_bits(&bytes, 16);
        assert_eq!(bits.len(), 16);

        let expected = vec![
            true, false, true, false, true, false, true, false, // 0xAA
            false, true, false, true, false, true, false, true, // 0x55
        ];
        assert_eq!(bits, expected);
        Ok(())
    }

    #[test]
    fn test_unpack_bits_two_bytes_to_10_bits() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let bytes = vec![0xFF, 0x00];
        let bits = bits::unpack_bits(&bytes, 10);
        assert_eq!(bits.len(), 10);

        let expected = vec![true, true, true, true, true, true, true, true, false, false];
        assert_eq!(bits, expected);
        Ok(())
    }

    #[test]
    fn test_unpack_bits_zero_count() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = vec![0xFF];
        let bits = bits::unpack_bits(&bytes, 0);
        assert_eq!(bits.len(), 0);
        Ok(())
    }

    #[test]
    fn test_unpack_bits_all_0xff() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = vec![0xFF, 0xFF];
        let bits = bits::unpack_bits(&bytes, 16);
        assert_eq!(bits.len(), 16);
        assert!(bits.iter().all(|&b| b));
        Ok(())
    }

    #[test]
    fn test_unpack_bits_all_0x00() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = vec![0x00, 0x00];
        let bits = bits::unpack_bits(&bytes, 16);
        assert_eq!(bits.len(), 16);
        assert!(bits.iter().all(|&b| !b));
        Ok(())
    }

    #[test]
    fn test_unpack_bits_msb_first() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = vec![0b10000000];
        let bits = bits::unpack_bits(&bytes, 8);
        assert!(bits[0]);
        assert!(!bits[1]);
        Ok(())
    }

    #[test]
    fn test_unpack_bits_lsb_last() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = vec![0b00000001];
        let bits = bits::unpack_bits(&bytes, 8);
        assert!(bits[7]);
        assert!(!bits[0]);
        Ok(())
    }

    #[test]
    fn test_unpack_bits_roundtrip_128() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let original_bits = vec![true, false, true, true, false, false, true, false];
        let packed = bits::pack_bits(&original_bits);
        let unpacked = bits::unpack_bits(&packed, original_bits.len());
        assert_eq!(unpacked, original_bits);
        Ok(())
    }

    #[test]
    fn test_unpack_bits_roundtrip_r_bits_len() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        // Test with R_BITS_LEN = 128
        let mut original = Vec::with_capacity(128);
        for i in 0..128 {
            original.push(i % 2 == 0);
        }

        let packed = bits::pack_bits(&original);
        let unpacked = bits::unpack_bits(&packed, 128);
        assert_eq!(unpacked, original);
        Ok(())
    }

    #[test]
    fn test_unpack_bits_count_exceeds_available(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = vec![0xFF];
        // Ask for 16 bits but only 8 available
        let bits = bits::unpack_bits(&bytes, 16);
        // Should only return 8 bits
        assert_eq!(bits.len(), 8);
        Ok(())
    }

    #[test]
    fn test_unpack_bits_known_pattern_1() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = vec![0b00110011];
        let bits = bits::unpack_bits(&bytes, 8);
        assert_eq!(
            bits,
            vec![false, false, true, true, false, false, true, true]
        );
        Ok(())
    }

    #[test]
    fn test_unpack_bits_known_pattern_2() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = vec![0b11001100];
        let bits = bits::unpack_bits(&bytes, 8);
        assert_eq!(
            bits,
            vec![true, true, false, false, true, true, false, false]
        );
        Ok(())
    }

    #[test]
    fn test_unpack_bits_partial_byte() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = vec![0b10110000];
        let bits = bits::unpack_bits(&bytes, 4);
        assert_eq!(bits, vec![true, false, true, true]);
        Ok(())
    }

    #[test]
    fn test_unpack_bits_128_bits_16_bytes() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = vec![0xAA; 16]; // 16 bytes = 128 bits
        let bits = bits::unpack_bits(&bytes, 128);
        assert_eq!(bits.len(), 128);

        // 0xAA = 10101010 pattern
        for (i, &bit) in bits.iter().enumerate() {
            assert_eq!(bit, i % 2 == 0);
        }
        Ok(())
    }

    #[test]
    fn test_unpack_bits_truncate_behavior() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = vec![0xFF, 0xFF, 0xFF];
        let bits = bits::unpack_bits(&bytes, 10);
        // Should truncate to exactly 10 bits
        assert_eq!(bits.len(), 10);
        assert!(bits.iter().all(|&b| b));
        Ok(())
    }

    #[test]
    fn test_unpack_bits_single_bit() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = vec![0b10000000];
        let bits = bits::unpack_bits(&bytes, 1);
        assert_eq!(bits.len(), 1);
        assert!(bits[0]);
        Ok(())
    }

    #[test]
    fn test_unpack_bits_large_count() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bytes = vec![0xFF; 128];
        let bits = bits::unpack_bits(&bytes, 1024);
        assert_eq!(bits.len(), 1024);
        assert!(bits.iter().all(|&b| b));
        Ok(())
    }

    // ============================================================
    // Section 7: parse_dob_iso tests (25 tests)
    // ============================================================

    #[test]
    fn test_parse_dob_iso_valid_date() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let days = parse_dob_iso("1990-01-15")?;
        assert!(days > 0);

        // 1990-01-15 is approximately 7319 days after epoch
        assert!(days > 7000 && days < 8000);
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_epoch_date() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let days = parse_dob_iso("1970-01-01")?;
        assert_eq!(days, 0);
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_before_epoch() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Pre-epoch dates are now valid and return negative days
        let result = parse_dob_iso("1969-12-31");
        assert!(result.is_ok());
        assert_eq!(result?, -1);
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_leap_year_feb_29() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        // 2000 was a leap year
        let result = parse_dob_iso("2000-02-29");
        assert!(result.is_ok());

        let days = result?;
        assert!(days > 0);
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_non_leap_year_feb_29(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // 2001 was not a leap year
        let result = parse_dob_iso("2001-02-29");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_invalid_format_american(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let result = parse_dob_iso("01/15/1990");
        assert!(result.is_err());

        if let Err(WalletError::InvalidInput(msg)) = result {
            assert!(msg.contains("Invalid date format"));
        } else {
            return Err("Expected InvalidInput error".into());
        }
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_invalid_format_no_padding(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Note: chrono actually accepts this format even without padding
        // So we test that it parses correctly instead
        let result = parse_dob_iso("1990-1-15");
        // Chrono's parser is lenient and accepts this
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_invalid_format_reversed(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let result = parse_dob_iso("15-01-1990");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_invalid_month() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let result = parse_dob_iso("1990-13-01");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_invalid_day() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let result = parse_dob_iso("1990-01-32");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_february_30() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let result = parse_dob_iso("1990-02-30");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_april_31() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // April has only 30 days
        let result = parse_dob_iso("1990-04-31");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_empty_string() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let result = parse_dob_iso("");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_unicode() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let result = parse_dob_iso("1990-01-1五");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_leading_whitespace() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        // Note: chrono's parser is lenient and accepts leading whitespace
        let result = parse_dob_iso(" 1990-01-15");
        // Chrono accepts this
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_trailing_whitespace(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let result = parse_dob_iso("1990-01-15 ");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_future_date() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let result = parse_dob_iso("2100-06-15");
        assert!(result.is_ok());

        let days = result?;
        assert!(days > 18000); // Way in the future
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_year_2400_leap_year(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // 2400 is a leap year (divisible by 400)
        let result = parse_dob_iso("2400-02-29");
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_recent_date() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Someone born 18 years ago
        let today = chrono::Utc::now().naive_utc().date();
        let eighteen_years_ago = today - chrono::Duration::days(18 * 365);
        let iso = eighteen_years_ago.format("%Y-%m-%d").to_string();

        let result = parse_dob_iso(&iso);
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_roundtrip() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dates = ["1990-01-15", "2000-02-29", "1985-12-25", "1970-01-01"];

        for date_str in dates {
            let days = parse_dob_iso(date_str)?;
            let back_to_iso = days_to_iso(days)?;
            assert_eq!(back_to_iso, date_str);
        }
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_boundary_dates() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Test first and last day of various months
        let dates = [
            "1990-01-01",
            "1990-01-31",
            "1990-02-01",
            "1990-02-28",
            "1990-12-01",
            "1990-12-31",
        ];

        for date_str in dates {
            let result = parse_dob_iso(date_str);
            assert!(result.is_ok(), "Failed to parse {}", date_str);
        }
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_zero_year() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Year 0 in proleptic Gregorian calendar (1 BC) - returns a large negative value
        let result = parse_dob_iso("0000-01-01");
        assert!(result.is_ok());
        assert!(result? < 0);
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_error_message_quality(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let result = parse_dob_iso("not-a-date");
        if let Err(WalletError::InvalidInput(msg)) = result {
            assert!(msg.contains("Invalid date format"));
            assert!(msg.contains("YYYY-MM-DD"));
        } else {
            return Err("Expected InvalidInput error".into());
        }
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_century_boundaries() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let dates = ["1900-01-01", "2000-01-01", "2100-01-01"];

        for date_str in dates {
            let result = parse_dob_iso(date_str);
            assert!(result.is_ok(), "Failed to parse {}", date_str);
            // 1900 is before 1970, should return negative days
            if date_str == "1900-01-01" {
                assert!(result? < 0);
            }
        }
        Ok(())
    }

    #[test]
    fn test_parse_dob_iso_common_ages() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Test common ages (18, 21, 50, 65) - pre-epoch dates now return negative i32
        let today = chrono::Utc::now().naive_utc().date();

        for age in [18, 21, 50, 65] {
            // Account for leap years: approximately 1 leap year every 4 years
            let approx_days = age * 365 + age / 4;
            let dob = today - chrono::Duration::days(approx_days as i64);
            let iso = dob.format("%Y-%m-%d").to_string();

            let result = parse_dob_iso(&iso);
            assert!(
                result.is_ok(),
                "Failed to parse age {} with date {}",
                age,
                iso
            );
        }
        Ok(())
    }

    // ============================================================
    // Section 8: days_to_iso tests (15 tests)
    // ============================================================

    #[test]
    fn test_days_to_iso_zero() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let iso = days_to_iso(0)?;
        assert_eq!(iso, "1970-01-01");
        Ok(())
    }

    #[test]
    fn test_days_to_iso_one_day() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let iso = days_to_iso(1)?;
        assert_eq!(iso, "1970-01-02");
        Ok(())
    }

    #[test]
    fn test_days_to_iso_365_days() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let iso = days_to_iso(365)?;
        assert_eq!(iso, "1971-01-01");
        Ok(())
    }

    #[test]
    fn test_days_to_iso_leap_year_handling() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        // Days for 1972-02-29 (first leap year after epoch)
        // 1970: 365 days, 1971: 365 days, Jan 1972: 31 days, Feb 1972: 29 days = 790 days
        // But we count from day 0, so Feb 29, 1972 is day 789
        let iso = days_to_iso(789)?;
        assert_eq!(iso, "1972-02-29");
        Ok(())
    }

    #[test]
    fn test_days_to_iso_large_value() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Test a large but reasonable value
        let days = 20000; // About 54 years
        let iso = days_to_iso(days)?;

        // Should be in YYYY-MM-DD format
        assert_eq!(iso.len(), 10);
        assert_eq!(&iso[4..5], "-");
        assert_eq!(&iso[7..8], "-");
        Ok(())
    }

    #[test]
    fn test_days_to_iso_roundtrip() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let days_values = [0, 1, 365, 1000, 10000, 18000];

        for days in days_values {
            let iso = days_to_iso(days)?;
            let back_to_days = parse_dob_iso(&iso)?;
            assert_eq!(back_to_days, days);
        }
        Ok(())
    }

    #[test]
    fn test_days_to_iso_known_dates() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Test some known conversions
        let known = [
            (0, "1970-01-01"),
            (365, "1971-01-01"),
            (730, "1972-01-01"), // 1972 is a leap year
        ];

        for (days, expected) in known {
            let iso = days_to_iso(days)?;
            assert_eq!(iso, expected);
        }
        Ok(())
    }

    #[test]
    fn test_days_to_iso_year_2000() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Days from 1970-01-01 to 2000-01-01
        let days = 10957;
        let iso = days_to_iso(days)?;
        assert_eq!(iso, "2000-01-01");
        Ok(())
    }

    #[test]
    fn test_days_to_iso_leap_day_2000() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Days from 1970-01-01 to 2000-02-29
        let days = 11016;
        let iso = days_to_iso(days)?;
        assert_eq!(iso, "2000-02-29");
        Ok(())
    }

    #[test]
    fn test_days_to_iso_format_validation() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let iso = days_to_iso(10000)?;

        // Verify format
        assert_eq!(iso.len(), 10);
        assert!(iso.chars().nth(4).ok_or("missing char")? == '-');
        assert!(iso.chars().nth(7).ok_or("missing char")? == '-');

        // Year should be 4 digits
        let year: u32 = iso[0..4].parse()?;
        assert!(year >= 1970);

        // Month should be 01-12
        let month: u32 = iso[5..7].parse()?;
        assert!((1..=12).contains(&month));

        // Day should be 01-31
        let day: u32 = iso[8..10].parse()?;
        assert!((1..=31).contains(&day));
        Ok(())
    }

    #[test]
    fn test_days_to_iso_leading_zeros() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let iso = days_to_iso(10)?;
        // Month and day should have leading zeros
        assert!(iso.contains("-01-"));
        Ok(())
    }

    #[test]
    fn test_days_to_iso_no_trailing_whitespace(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let iso = days_to_iso(5000)?;
        assert_eq!(iso.trim(), iso);
        Ok(())
    }

    #[test]
    fn test_days_to_iso_century_boundaries() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        // Test dates at century boundaries
        let dates = [(10957, "2000-01-01"), (47482, "2100-01-01")];

        for (days, expected) in dates {
            let iso = days_to_iso(days)?;
            assert_eq!(iso, expected);
        }
        Ok(())
    }

    #[test]
    fn test_days_to_iso_common_ages_roundtrip(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Test common ages: 18, 21, 65 years in days
        let ages_in_days = [
            18 * 365 + 4,  // ~18 years (with leap years)
            21 * 365 + 5,  // ~21 years
            65 * 365 + 16, // ~65 years
        ];

        for days in ages_in_days {
            let iso = days_to_iso(days)?;
            let back = parse_dob_iso(&iso)?;
            assert_eq!(back, days);
        }
        Ok(())
    }

    #[test]
    fn test_days_to_iso_consistency() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Test that consecutive days produce consecutive dates
        let base_days = 10000;
        let iso1 = days_to_iso(base_days)?;
        let iso2 = days_to_iso(base_days.checked_add(1).ok_or("overflow")?)?;

        // Parse both and verify they're 1 day apart
        let days1 = parse_dob_iso(&iso1)?;
        let days2 = parse_dob_iso(&iso2)?;
        assert_eq!(days2 - days1, 1);
        Ok(())
    }

    // ============================================================
    // Section 9: RedJubjub signature verification tests (6 tests)
    // ============================================================

    #[test]
    fn test_finalize_rejects_invalid_signature(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A zeroed sig_rj is not a valid RedJubjub signature; finalise must reject it.
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;

        let sk = provii_crypto_sig_redjubjub::SigningKey::random();
        let vk = sk.verification_key().to_bytes();

        let header = SignedCredentialHeader {
            v: 2,
            kid: "test-key".to_string(),
            issuer_vk: vk,
            sig_rj: [0u8; 64], // invalid: all-zero bytes cannot be a valid signature
            c_bytes: parts.c_bytes,
            iat: 1000000,
            exp: 2000000,
            schema: "provii.age/0".to_string(),
        };

        let result = finalize_credential(header, dob, parts.r_bits.clone());
        assert!(result.is_err(), "all-zero signature must be rejected");
        if let Err(WalletError::ValidationFailed(msg)) = result {
            assert!(
                msg.contains("RedJubjub"),
                "error message must mention RedJubjub"
            );
        } else {
            return Err("Expected ValidationFailed error for invalid signature".into());
        }
        Ok(())
    }

    #[test]
    fn test_finalize_rejects_tampered_signature(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A valid signature with one byte flipped must be rejected.
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        // Flip the first byte of sig_rj.
        let mut tampered = header.clone();
        tampered.sig_rj[0] ^= 0xFF;

        let result = finalize_credential(tampered, dob, parts.r_bits.clone());
        assert!(result.is_err(), "tampered signature must be rejected");
        Ok(())
    }

    #[test]
    fn test_finalize_accepts_valid_signature() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        // A properly signed header must be accepted.
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        let result = finalize_credential(header, dob, parts.r_bits.clone());
        assert!(
            result.is_ok(),
            "valid signature must be accepted: {:?}",
            result
        );
        Ok(())
    }

    #[test]
    fn test_finalize_rejects_wrong_key() -> std::result::Result<(), Box<dyn std::error::Error>> {
        // A signature from one key paired with a different key's vk must be rejected.
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;

        let sk_a = provii_crypto_sig_redjubjub::SigningKey::random();
        let sk_b = provii_crypto_sig_redjubjub::SigningKey::random();
        let vk_b = sk_b.verification_key().to_bytes();

        let cred_msg = provii_crypto_commons::CredMsgV2 {
            v: 2,
            kid: "test-key".to_string(),
            c: parts.c_bytes,
            iat: 1000000,
            exp: 2000000,
            schema: "provii.age/0".to_string(),
        };
        // Sign with key A but advertise key B's vk.
        let sig_rj = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &sk_a.to_bytes())?;
        let header = SignedCredentialHeader {
            v: 2,
            kid: "test-key".to_string(),
            issuer_vk: vk_b,
            sig_rj,
            c_bytes: parts.c_bytes,
            iat: 1000000,
            exp: 2000000,
            schema: "provii.age/0".to_string(),
        };

        let result = finalize_credential(header, dob, parts.r_bits.clone());
        assert!(result.is_err(), "mismatched key pair must be rejected");
        Ok(())
    }

    #[test]
    fn test_finalize_signature_over_all_header_fields(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Mutating any signed field after signing must invalidate the signature.
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;
        let header = create_test_header(parts.c_bytes)?;

        // Flip exp to a different value; the signature covers exp so this breaks it.
        let mut mutated = header.clone();
        mutated.exp = mutated.exp.wrapping_add(1);

        let result = finalize_credential(mutated, dob, parts.r_bits.clone());
        assert!(
            result.is_err(),
            "mutation of exp field must invalidate signature"
        );
        Ok(())
    }

    #[test]
    fn test_finalize_signature_check_before_storage(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Verify that the error from an invalid signature is a ValidationFailed,
        // confirming the check happens inside finalize_credential.
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;

        let sk = provii_crypto_sig_redjubjub::SigningKey::random();
        let vk = sk.verification_key().to_bytes();
        // Sign a different iat than the one stored in the header.
        let cred_msg = provii_crypto_commons::CredMsgV2 {
            v: 2,
            kid: "test-key".to_string(),
            c: parts.c_bytes,
            iat: 9999,
            exp: 2000000,
            schema: "provii.age/0".to_string(),
        };
        let sig_rj = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &sk.to_bytes())?;
        let header = SignedCredentialHeader {
            v: 2,
            kid: "test-key".to_string(),
            issuer_vk: vk,
            sig_rj,
            c_bytes: parts.c_bytes,
            iat: 1000000, // differs from what was signed
            exp: 2000000,
            schema: "provii.age/0".to_string(),
        };

        let result = finalize_credential(header, dob, parts.r_bits.clone());
        assert!(result.is_err());
        if let Err(WalletError::ValidationFailed(msg)) = result {
            assert!(
                msg.contains("RedJubjub"),
                "error must be RedJubjub-related, got: {}",
                msg
            );
        } else {
            return Err("Expected ValidationFailed error".into());
        }
        Ok(())
    }

    // ====================================================================
    // Mutation-coverage tests: kill surviving mutants in issuance.rs
    // ====================================================================

    /// Kill: issuance.rs:105 replace || with && in finalize_credential
    /// When only iat==0 (but exp!=0), finalize_credential must reject.
    /// The && mutant requires BOTH to be zero to trigger the error.
    #[test]
    fn test_finalize_credential_rejects_zero_iat_only(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;

        let sk = provii_crypto_sig_redjubjub::SigningKey::random();
        let vk = sk.verification_key().to_bytes();
        let cred_msg = provii_crypto_commons::CredMsgV2 {
            v: 2,
            kid: "test-key".to_string(),
            c: parts.c_bytes,
            iat: 0,
            exp: 2000000,
            schema: "provii.age/0".to_string(),
        };
        let sig_rj = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &sk.to_bytes())?;
        let header = SignedCredentialHeader {
            v: 2,
            kid: "test-key".to_string(),
            issuer_vk: vk,
            sig_rj,
            c_bytes: parts.c_bytes,
            iat: 0,
            exp: 2000000,
            schema: "provii.age/0".to_string(),
        };

        let result = finalize_credential(header, dob, parts.r_bits.clone());
        assert!(result.is_err(), "zero iat alone must be rejected");
        if let Err(WalletError::ValidationFailed(msg)) = result {
            assert!(
                msg.contains("zero"),
                "error should mention zero, got: {}",
                msg
            );
        } else {
            return Err("Expected ValidationFailed for zero iat".into());
        }
        Ok(())
    }

    /// Kill: issuance.rs:105 replace || with && (second case: only exp==0)
    #[test]
    fn test_finalize_credential_rejects_zero_exp_only(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let dob = 10000;
        let seed = [42u8; 32];
        let parts = compute_commitment_with_seed(dob, seed)?;

        let sk = provii_crypto_sig_redjubjub::SigningKey::random();
        let vk = sk.verification_key().to_bytes();
        let cred_msg = provii_crypto_commons::CredMsgV2 {
            v: 2,
            kid: "test-key".to_string(),
            c: parts.c_bytes,
            iat: 1000000,
            exp: 0,
            schema: "provii.age/0".to_string(),
        };
        let sig_rj = provii_crypto_sig_redjubjub::sign_cred_v2(&cred_msg, &sk.to_bytes())?;
        let header = SignedCredentialHeader {
            v: 2,
            kid: "test-key".to_string(),
            issuer_vk: vk,
            sig_rj,
            c_bytes: parts.c_bytes,
            iat: 1000000,
            exp: 0,
            schema: "provii.age/0".to_string(),
        };

        let result = finalize_credential(header, dob, parts.r_bits.clone());
        assert!(result.is_err(), "zero exp alone must be rejected");
        if let Err(WalletError::ValidationFailed(msg)) = result {
            assert!(
                msg.contains("zero"),
                "error should mention zero, got: {}",
                msg
            );
        } else {
            return Err("Expected ValidationFailed for zero exp".into());
        }
        Ok(())
    }
