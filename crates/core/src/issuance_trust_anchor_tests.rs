// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

    use super::*;
    use crate::types::{IssuerTrustAnchor, TrustedIssuerKey};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    // ============================================================
    // parse_jwks_into_keys tests
    // ============================================================

    fn make_jwks(entries: &[serde_json::Value]) -> String {
        serde_json::json!({ "keys": entries }).to_string()
    }

    fn okp_jubjub_entry(kid: &str, vk: &[u8; 32]) -> serde_json::Value {
        serde_json::json!({
            "kty": "OKP",
            "crv": "JUBJUB",
            "kid": kid,
            "x": URL_SAFE_NO_PAD.encode(vk),
        })
    }

    #[test]
    fn test_parse_jwks_empty_keys() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let jwks = make_jwks(&[]);
        let keys = parse_jwks_into_keys(&jwks)?;
        assert!(keys.is_empty());
        Ok(())
    }

    #[test]
    fn test_parse_jwks_single_okp_jubjub() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let vk = [1u8; 32];
        let jwks = make_jwks(&[okp_jubjub_entry("key-1", &vk)]);
        let keys = parse_jwks_into_keys(&jwks)?;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid, "key-1");
        assert_eq!(keys[0].vk, vk);
        Ok(())
    }

    #[test]
    fn test_parse_jwks_multiple_keys() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let vk1 = [1u8; 32];
        let vk2 = [2u8; 32];
        let jwks = make_jwks(&[
            okp_jubjub_entry("key-1", &vk1),
            okp_jubjub_entry("key-2", &vk2),
        ]);
        let keys = parse_jwks_into_keys(&jwks)?;
        assert_eq!(keys.len(), 2);
        Ok(())
    }

    #[test]
    fn test_parse_jwks_filters_non_jubjub() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let vk = [3u8; 32];
        let ec_entry = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "kid": "ec-key",
            "x": URL_SAFE_NO_PAD.encode(vk),
        });
        let jwks = make_jwks(&[ec_entry, okp_jubjub_entry("jubjub-key", &vk)]);
        let keys = parse_jwks_into_keys(&jwks)?;
        // Only the JUBJUB entry should be returned.
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid, "jubjub-key");
        Ok(())
    }

    #[test]
    fn test_parse_jwks_skips_missing_kid() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let vk = [4u8; 32];
        let no_kid = serde_json::json!({
            "kty": "OKP",
            "crv": "JUBJUB",
            "x": URL_SAFE_NO_PAD.encode(vk),
        });
        let jwks = make_jwks(&[no_kid]);
        let keys = parse_jwks_into_keys(&jwks)?;
        assert!(keys.is_empty());
        Ok(())
    }

    #[test]
    fn test_parse_jwks_skips_bad_base64() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let bad_entry = serde_json::json!({
            "kty": "OKP",
            "crv": "JUBJUB",
            "kid": "bad-key",
            "x": "not-valid-base64!!!",
        });
        let jwks = make_jwks(&[bad_entry]);
        let keys = parse_jwks_into_keys(&jwks)?;
        assert!(keys.is_empty());
        Ok(())
    }

    #[test]
    fn test_parse_jwks_skips_wrong_length_x() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        // 16 bytes instead of 32
        let short_x = URL_SAFE_NO_PAD.encode([0u8; 16]);
        let entry = serde_json::json!({
            "kty": "OKP",
            "crv": "JUBJUB",
            "kid": "short-key",
            "x": short_x,
        });
        let jwks = make_jwks(&[entry]);
        let keys = parse_jwks_into_keys(&jwks)?;
        assert!(keys.is_empty());
        Ok(())
    }

    #[test]
    fn test_parse_jwks_filters_okp_wrong_crv() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let vk = [9u8; 32];
        let okp_ed25519 = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "ed-key",
            "x": URL_SAFE_NO_PAD.encode(vk),
        });
        let jwks = make_jwks(&[okp_ed25519]);
        let keys = parse_jwks_into_keys(&jwks)?;
        assert!(keys.is_empty());
        Ok(())
    }

    #[test]
    fn test_parse_jwks_filters_wrong_kty_jubjub_crv(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let vk = [10u8; 32];
        let ec_jubjub = serde_json::json!({
            "kty": "EC",
            "crv": "JUBJUB",
            "kid": "ec-jubjub-key",
            "x": URL_SAFE_NO_PAD.encode(vk),
        });
        let jwks = make_jwks(&[ec_jubjub]);
        let keys = parse_jwks_into_keys(&jwks)?;
        assert!(keys.is_empty());
        Ok(())
    }

    #[test]
    fn test_parse_jwks_invalid_json() {
        let result = parse_jwks_into_keys("not json at all");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_jwks_missing_keys_array() {
        let result = parse_jwks_into_keys("{\"other\": []}");
        assert!(result.is_err());
    }

    // ============================================================
    // validate_issuer_vk tests
    // ============================================================

    fn make_header(vk: [u8; 32]) -> SignedCredentialHeader {
        SignedCredentialHeader {
            v: 2,
            kid: "test-key".to_string(),
            issuer_vk: vk,
            sig_rj: [0u8; 64],
            c_bytes: [0u8; 32],
            iat: 1000000,
            exp: 2000000,
            schema: "provii.age/0".to_string(),
        }
    }

    fn make_anchor(keys: Vec<TrustedIssuerKey>) -> IssuerTrustAnchor {
        IssuerTrustAnchor {
            keys,
            fetched_at: 0,
        }
    }

    #[test]
    fn test_validate_vk_exact_match() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let vk = [7u8; 32];
        let header = make_header(vk);
        let anchor = make_anchor(vec![TrustedIssuerKey {
            kid: "k1".to_string(),
            vk,
        }]);
        validate_issuer_vk(&header, &anchor)?;
        Ok(())
    }

    #[test]
    fn test_validate_vk_no_match() {
        let header = make_header([1u8; 32]);
        let anchor = make_anchor(vec![TrustedIssuerKey {
            kid: "k1".to_string(),
            vk: [2u8; 32],
        }]);
        let result = validate_issuer_vk(&header, &anchor);
        assert!(result.is_err());
        if let Err(WalletError::SecurityError(msg)) = result {
            assert!(msg.contains("not in trust anchor"));
        } else {
            panic!("expected SecurityError");
        }
    }

    #[test]
    fn test_validate_vk_empty_anchor() {
        let header = make_header([1u8; 32]);
        let anchor = make_anchor(vec![]);
        let result = validate_issuer_vk(&header, &anchor);
        assert!(result.is_err());
        if let Err(WalletError::SecurityError(msg)) = result {
            assert!(msg.contains("no keys"));
        } else {
            panic!("expected SecurityError");
        }
    }

    #[test]
    fn test_validate_vk_match_among_multiple() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let vk_target = [99u8; 32];
        let anchor = make_anchor(vec![
            TrustedIssuerKey {
                kid: "old".to_string(),
                vk: [11u8; 32],
            },
            TrustedIssuerKey {
                kid: "current".to_string(),
                vk: vk_target,
            },
            TrustedIssuerKey {
                kid: "future".to_string(),
                vk: [33u8; 32],
            },
        ]);
        let header = make_header(vk_target);
        validate_issuer_vk(&header, &anchor)?;
        Ok(())
    }

    // ============================================================
    // IssuerTrustAnchor::union_merge tests
    // ============================================================

    #[test]
    fn test_union_merge_new_kid() {
        let mut anchor = make_anchor(vec![TrustedIssuerKey {
            kid: "k1".to_string(),
            vk: [1u8; 32],
        }]);
        anchor.union_merge(vec![TrustedIssuerKey {
            kid: "k2".to_string(),
            vk: [2u8; 32],
        }]);
        assert_eq!(anchor.keys.len(), 2);
    }

    #[test]
    fn test_union_merge_same_kid_same_vk() {
        let vk = [5u8; 32];
        let mut anchor = make_anchor(vec![TrustedIssuerKey {
            kid: "k1".to_string(),
            vk,
        }]);
        anchor.union_merge(vec![TrustedIssuerKey {
            kid: "k1".to_string(),
            vk,
        }]);
        // No-op: still one key.
        assert_eq!(anchor.keys.len(), 1);
        assert_eq!(anchor.keys[0].vk, vk);
    }

    #[test]
    fn test_union_merge_rotation() {
        let old_vk = [5u8; 32];
        let new_vk = [6u8; 32];
        let mut anchor = make_anchor(vec![TrustedIssuerKey {
            kid: "k1".to_string(),
            vk: old_vk,
        }]);
        anchor.union_merge(vec![TrustedIssuerKey {
            kid: "k1".to_string(),
            vk: new_vk,
        }]);
        // Still one key but vk updated.
        assert_eq!(anchor.keys.len(), 1);
        assert_eq!(anchor.keys[0].vk, new_vk);
    }

    /// ADV-WS-06-04: Verify CommitmentParts zeroises dob_days on drop.
    #[test]
    fn test_commitment_parts_zeroize_on_drop() {
        let parts = Box::new(compute_commitment(10_000).expect("commitment should succeed"));

        // Sanity: the field holds a non-trivial value pre-drop.
        assert_eq!(parts.dob_days, 10_000);
        assert_eq!(parts.r_bits.len(), R_BITS_LEN);

        // Convert to raw pointer so we can control when drop runs.
        let raw = Box::into_raw(parts);

        // Capture the address of `dob_days` before dropping.
        #[allow(unsafe_code)]
        let dob_ptr: *const i32 = unsafe { &(*raw).dob_days as *const i32 };

        // Drop the CommitmentParts (runs ZeroizeOnDrop), then free the heap
        // allocation.
        #[allow(unsafe_code)]
        unsafe {
            // SAFETY: `raw` was obtained from `Box::into_raw` and has not
            // been freed or aliased. Reconstructing the Box and letting it
            // drop is the correct way to run the destructor chain
            // (ZeroizeOnDrop then dealloc).
            drop(Box::from_raw(raw));
        }

        // SAFETY: `dob_ptr` pointed into the heap allocation that was just
        // freed. Under debug allocators the page is not immediately returned
        // to the OS, so the volatile read is valid in practice. If ZeroizeOnDrop
        // worked correctly, the i32 at that address will be zero.
        #[allow(unsafe_code)]
        let dob_after = unsafe { core::ptr::read_volatile(dob_ptr) };
        assert_eq!(
            dob_after, 0,
            "dob_days was not zeroed after drop (got {})",
            dob_after
        );
    }
