// Copyright (c) 2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust (ABN 61 633 823 792)
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_mobile_sdk_core::utils::parse_qr_json;
use provii_mobile_sdk_core::types::QrChallengePayload;

fuzz_target!(|data: &[u8]| {
    // Test 1: Fuzz raw JSON deserialization
    if let Ok(json_str) = std::str::from_utf8(data) {
        let _ = parse_qr_json::<QrChallengePayload>(json_str);
        let _ = parse_qr_json::<serde_json::Value>(json_str);
    }

    // Test 2: Malformed JSON patterns
    let malformed = vec![
        b"{}".as_slice(),
        b"[]",
        b"null",
        b"true",
        b"false",
        b"123",
        b"\"string\"",
        b"{{{",
        b"}}}",
        b"[[[",
        b"]]]",
        b"",
    ];

    for pattern in malformed {
        if let Ok(s) = std::str::from_utf8(pattern) {
            let _ = parse_qr_json::<QrChallengePayload>(s);
        }
    }

    // Test 3: Valid QrChallengePayload structure with fuzzer data
    if data.len() >= 64 {
        // Extract fields from fuzzer data
        let challenge_id_len = (data[0] as usize % 20).min(30);
        let rp_challenge_len = (data[1] as usize % 50).min(60);

        if data.len() >= 4 + challenge_id_len + rp_challenge_len {
            if let (Ok(challenge_id), Ok(rp_challenge)) = (
                std::str::from_utf8(&data[4..4 + challenge_id_len]),
                std::str::from_utf8(&data[4 + challenge_id_len..4 + challenge_id_len + rp_challenge_len]),
            ) {
                let cutoff_days = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                let verifying_key_id = data[10] as u32;
                let expires_at = u64::from_le_bytes([
                    data[20], data[21], data[22], data[23],
                    data[24], data[25], data[26], data[27],
                ]);

                let json = format!(
                    r#"{{
                        "challenge_id": "{}",
                        "rp_challenge": "{}",
                        "cutoff_days": {},
                        "verifying_key_id": {},
                        "submit_secret": "test_secret",
                        "expires_at": {},
                        "verify_url": "https://example.com/verify"
                    }}"#,
                    challenge_id,
                    rp_challenge,
                    cutoff_days,
                    verifying_key_id,
                    expires_at
                );

                let _ = parse_qr_json::<QrChallengePayload>(&json);
            }
        }
    }

    // Test 4: Missing required fields
    let missing_fields = vec![
        r#"{}"#,
        r#"{"challenge_id":"test"}"#,
        r#"{"challenge_id":"test","rp_challenge":"ch"}"#,
        r#"{"challenge_id":"test","rp_challenge":"ch","cutoff_days":19000}"#,
    ];

    for json in missing_fields {
        let _ = parse_qr_json::<QrChallengePayload>(json);
    }

    // Test 5: Wrong types for fields
    let wrong_types = vec![
        r#"{"challenge_id":123,"rp_challenge":"ch","cutoff_days":19000,"verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com"}"#,
        r#"{"challenge_id":"test","rp_challenge":123,"cutoff_days":19000,"verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com"}"#,
        r#"{"challenge_id":"test","rp_challenge":"ch","cutoff_days":"not_a_number","verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com"}"#,
        r#"{"challenge_id":"test","rp_challenge":"ch","cutoff_days":19000,"verifying_key_id":"not_a_number","submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com"}"#,
    ];

    for json in wrong_types {
        let _ = parse_qr_json::<QrChallengePayload>(json);
    }

    // Test 6: Null values
    let null_tests = vec![
        r#"{"challenge_id":null,"rp_challenge":"ch","cutoff_days":19000,"verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com"}"#,
        r#"{"challenge_id":"test","rp_challenge":null,"cutoff_days":19000,"verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com"}"#,
        r#"{"challenge_id":"test","rp_challenge":"ch","cutoff_days":null,"verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com"}"#,
    ];

    for json in null_tests {
        let _ = parse_qr_json::<QrChallengePayload>(json);
    }

    // Test 7: Extra fields (rejected by deny_unknown_fields)
    let extra_fields = r#"{"challenge_id":"test","rp_challenge":"ch","cutoff_days":19000,"verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com","extra1":"ignored","extra2":123,"nested":{"deep":"value"}}"#;
    let _ = parse_qr_json::<QrChallengePayload>(extra_fields);

    // Test 8: Optional code_verifier field
    let with_code_verifier = r#"{"challenge_id":"test","rp_challenge":"ch","cutoff_days":19000,"verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com","code_verifier":"optional_pkce_code"}"#;
    let _ = parse_qr_json::<QrChallengePayload>(with_code_verifier);

    let with_null_code_verifier = r#"{"challenge_id":"test","rp_challenge":"ch","cutoff_days":19000,"verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com","code_verifier":null}"#;
    let _ = parse_qr_json::<QrChallengePayload>(with_null_code_verifier);

    // Test 9: Very long strings
    if data.len() >= 200 {
        let long_challenge_id = String::from_utf8_lossy(&data[0..100]).to_string();
        let long_rp_challenge = String::from_utf8_lossy(&data[100..200]).to_string();

        let json = format!(
            r#"{{
                "challenge_id": "{}",
                "rp_challenge": "{}",
                "cutoff_days": 19000,
                "verifying_key_id": 1,
                "submit_secret": "sec",
                "expires_at": 2000000,
                "verify_url": "https://example.com/verify"
            }}"#,
            long_challenge_id,
            long_rp_challenge
        );

        let _ = parse_qr_json::<QrChallengePayload>(&json);
    }

    // Test 10: Unicode and special characters
    if let Ok(utf8_str) = std::str::from_utf8(data) {
        let json_unicode = format!(
            r#"{{
                "challenge_id": "test-🔐-{}",
                "rp_challenge": "ch-{}",
                "cutoff_days": 19000,
                "verifying_key_id": 1,
                "submit_secret": "sec",
                "expires_at": 2000000,
                "verify_url": "https://example.com/verify"
            }}"#,
            utf8_str.chars().take(5).collect::<String>(),
            utf8_str.chars().take(10).collect::<String>()
        );

        let _ = parse_qr_json::<QrChallengePayload>(&json_unicode);
    }

    // Test 11: Deeply nested JSON (should fail for QrChallengePayload)
    let deep_nested = r#"{"outer":{"middle":{"inner":{"challenge_id":"test"}}}}"#;
    let _ = parse_qr_json::<QrChallengePayload>(deep_nested);

    // Test 12: Arrays instead of objects
    let array_json = r#"["challenge_id","rp_challenge"]"#;
    let _ = parse_qr_json::<QrChallengePayload>(array_json);

    // Test 13: Numbers at edge cases
    let edge_numbers = vec![
        format!(r#"{{"challenge_id":"test","rp_challenge":"ch","cutoff_days":{},"verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com"}}"#, i32::MAX),
        format!(r#"{{"challenge_id":"test","rp_challenge":"ch","cutoff_days":0,"verifying_key_id":{},"submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com"}}"#, u32::MAX),
        format!(r#"{{"challenge_id":"test","rp_challenge":"ch","cutoff_days":19000,"verifying_key_id":1,"submit_secret":"sec","expires_at":{},"verify_url":"https://example.com"}}"#, u64::MAX),
        r#"{"challenge_id":"test","rp_challenge":"ch","cutoff_days":0,"verifying_key_id":0,"submit_secret":"sec","expires_at":0,"verify_url":"https://example.com"}"#.to_string(),
    ];

    for json in edge_numbers {
        let _ = parse_qr_json::<QrChallengePayload>(&json);
    }

    // Test 14: Truncated JSON at various points
    if let Ok(json_str) = std::str::from_utf8(data) {
        for i in 0..json_str.len().min(100) {
            // Only slice at valid character boundaries to avoid panics
            if json_str.is_char_boundary(i) {
                let truncated = &json_str[..i];
                let _ = parse_qr_json::<QrChallengePayload>(truncated);
            }
        }
    }

    // Test 15: Whitespace variations
    let whitespace_tests = vec![
        r#"{"challenge_id":"test","rp_challenge":"ch","cutoff_days":19000,"verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com"}"#,
        r#"{ "challenge_id" : "test" , "rp_challenge" : "ch" , "cutoff_days" : 19000 , "verifying_key_id" : 1 , "submit_secret" : "sec" , "expires_at" : 2000000 , "verify_url" : "https://example.com" }"#,
        r#"{
            "challenge_id": "test",
            "rp_challenge": "ch",
            "cutoff_days": 19000,
            "verifying_key_id": 1,
            "submit_secret": "sec",
            "expires_at": 2000000,
            "verify_url": "https://example.com"
        }"#,
    ];

    for json in whitespace_tests {
        let _ = parse_qr_json::<QrChallengePayload>(json);
    }

    // Test 16: Invalid URL formats in verify_url
    let invalid_urls = vec![
        r#"{"challenge_id":"test","rp_challenge":"ch","cutoff_days":19000,"verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":"not_a_url"}"#,
        r#"{"challenge_id":"test","rp_challenge":"ch","cutoff_days":19000,"verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":""}"#,
        r#"{"challenge_id":"test","rp_challenge":"ch","cutoff_days":19000,"verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":"ftp://example.com"}"#,
    ];

    for json in invalid_urls {
        let _ = parse_qr_json::<QrChallengePayload>(json);
    }

    // Test 17: Empty strings
    let empty_strings = vec![
        r#"{"challenge_id":"","rp_challenge":"ch","cutoff_days":19000,"verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com"}"#,
        r#"{"challenge_id":"test","rp_challenge":"","cutoff_days":19000,"verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com"}"#,
        r#"{"challenge_id":"test","rp_challenge":"ch","cutoff_days":19000,"verifying_key_id":1,"submit_secret":"","expires_at":2000000,"verify_url":"https://example.com"}"#,
    ];

    for json in empty_strings {
        let _ = parse_qr_json::<QrChallengePayload>(json);
    }

    // Test 18: Control characters in strings
    let with_control = r#"{"challenge_id":"test\x00\x01","rp_challenge":"ch\n\r\t","cutoff_days":19000,"verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com"}"#;
    let _ = parse_qr_json::<QrChallengePayload>(with_control);

    // Test 19: Escaped characters
    let escaped = r#"{"challenge_id":"test\"quoted\"","rp_challenge":"ch\\backslash","cutoff_days":19000,"verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com"}"#;
    let _ = parse_qr_json::<QrChallengePayload>(escaped);

    // Test 20: Valid QR payload that should parse successfully
    let valid = r#"{"challenge_id":"chal_abc123","rp_challenge":"dGVzdF9jaGFsbGVuZ2U","cutoff_days":6575,"verifying_key_id":1,"submit_secret":"c2VjcmV0X3Rva2Vu","expires_at":1700000000,"verify_url":"https://verify.proviiwallet.app/v1/verify","code_verifier":"pkce_verifier_xyz"}"#;
    if let Ok(payload) = parse_qr_json::<QrChallengePayload>(valid) {
        // Verify parsed values
        assert_eq!(payload.challenge_id, "chal_abc123");
        assert_eq!(payload.cutoff_days, 6575);
        assert_eq!(payload.verifying_key_id, 1);
        assert_eq!(payload.code_verifier, Some("pkce_verifier_xyz".to_string()));
    }

    // Test 21: Large numbers (potential overflow)
    if data.len() >= 8 {
        let large_cutoff = u64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]);

        let json = format!(
            r#"{{
                "challenge_id": "test",
                "rp_challenge": "ch",
                "cutoff_days": {},
                "verifying_key_id": 1,
                "submit_secret": "sec",
                "expires_at": {},
                "verify_url": "https://example.com"
            }}"#,
            large_cutoff % (u32::MAX as u64),
            large_cutoff
        );

        let _ = parse_qr_json::<QrChallengePayload>(&json);
    }

    // Test 22: Repeated keys in JSON
    let repeated_keys = r#"{"challenge_id":"first","challenge_id":"second","challenge_id":"third","rp_challenge":"ch","cutoff_days":19000,"verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com"}"#;
    let _ = parse_qr_json::<QrChallengePayload>(repeated_keys);

    // Test 23: Mixed case field names (should fail - serde is case-sensitive)
    let mixed_case = r#"{"Challenge_ID":"test","rp_challenge":"ch","cutoff_days":19000,"verifying_key_id":1,"submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com"}"#;
    let _ = parse_qr_json::<QrChallengePayload>(mixed_case);

    // Test 24: Scientific notation for numbers
    let scientific = r#"{"challenge_id":"test","rp_challenge":"ch","cutoff_days":1.9e4,"verifying_key_id":1,"submit_secret":"sec","expires_at":2.0e6,"verify_url":"https://example.com"}"#;
    let _ = parse_qr_json::<QrChallengePayload>(scientific);

    // Test 25: Boolean values in place of numbers
    let bool_values = r#"{"challenge_id":"test","rp_challenge":"ch","cutoff_days":true,"verifying_key_id":false,"submit_secret":"sec","expires_at":2000000,"verify_url":"https://example.com"}"#;
    let _ = parse_qr_json::<QrChallengePayload>(bool_values);
});
