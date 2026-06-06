// Copyright (c) 2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust (ABN 61 633 823 792)
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_mobile_sdk_core::types::CredentialV2;

fuzz_target!(|data: &[u8]| {
    // Test 1: Fuzz raw JSON deserialization of CredentialV2
    if let Ok(json_str) = std::str::from_utf8(data) {
        let _ = CredentialV2::from_json(json_str);
    }

    // Test 2: Try to parse malformed JSON patterns
    let malformed_patterns: Vec<&[u8]> = vec![
        b"{}",
        b"{\"v\":2}",
        b"{\"v\":2,\"kid\":\"test\"}",
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
    ];

    for pattern in malformed_patterns {
        if let Ok(s) = std::str::from_utf8(pattern) {
            let _ = CredentialV2::from_json(s);
        }
    }

    // Test 3: Construct JSON-like strings from fuzzer data
    if data.len() >= 32 {
        // Try to build a CredentialV2 JSON with fuzzer data
        let kid_len = (data[0] as usize % 20).min(data.len() - 32);
        if let Ok(kid) = std::str::from_utf8(&data[1..1 + kid_len]) {
            let schema_len = (data[kid_len + 1] as usize % 20).min(data.len() - kid_len - 32);
            if let Ok(schema) = std::str::from_utf8(&data[kid_len + 2..kid_len + 2 + schema_len]) {
                // Parse timestamps
                let iat = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3],
                    data[4], data[5], data[6], data[7],
                ]);
                let exp = u64::from_le_bytes([
                    data[8], data[9], data[10], data[11],
                    data[12], data[13], data[14], data[15],
                ]);

                // Build JSON with valid structure but fuzzer-controlled values
                let json = format!(
                    r#"{{
                        "v": {},
                        "kid": "{}",
                        "issuer_vk": [{}],
                        "sig_rj": [{}],
                        "c_bytes": [{}],
                        "iat": {},
                        "exp": {},
                        "schema": "{}"
                    }}"#,
                    data[16],
                    kid,
                    (0..32).map(|i| data[i % data.len()].to_string()).collect::<Vec<_>>().join(","),
                    (0..64).map(|i| data[i % data.len()].to_string()).collect::<Vec<_>>().join(","),
                    (0..32).map(|i| data[i % data.len()].to_string()).collect::<Vec<_>>().join(","),
                    iat,
                    exp,
                    schema
                );

                let _ = CredentialV2::from_json(&json);
            }
        }
    }

    // Test 4: JSON with extra/missing fields
    if data.len() >= 10 {
        let extra_fields = format!(
            r#"{{
                "v": 2,
                "kid": "test",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": {},
                "exp": {},
                "schema": "test.schema",
                "extra_field": "{}",
                "another_field": {}
            }}"#,
            data[0] as u64,
            data[1] as u64,
            String::from_utf8_lossy(&data[2..data.len().min(10)]),
            data[data.len() - 1]
        );

        let _ = CredentialV2::from_json(&extra_fields);
    }

    // Test 5: JSON with wrong array lengths
    let wrong_lengths = vec![
        // issuer_vk wrong length
        r#"{"v":2,"kid":"test","issuer_vk":[1,2,3],"sig_rj":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000000,"exp":2000000,"schema":"test"}"#,
        // sig_rj wrong length
        r#"{"v":2,"kid":"test","issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":[2,2,2],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000000,"exp":2000000,"schema":"test"}"#,
        // c_bytes wrong length
        r#"{"v":2,"kid":"test","issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"c_bytes":[3,3,3],"iat":1000000,"exp":2000000,"schema":"test"}"#,
        // Empty arrays
        r#"{"v":2,"kid":"test","issuer_vk":[],"sig_rj":[],"c_bytes":[],"iat":1000000,"exp":2000000,"schema":"test"}"#,
    ];

    for wrong_json in wrong_lengths {
        let _ = CredentialV2::from_json(wrong_json);
    }

    // Test 6: JSON with wrong types for fields
    let wrong_types = vec![
        r#"{"v":"not_a_number","kid":"test","issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000000,"exp":2000000,"schema":"test"}"#,
        r#"{"v":2,"kid":123,"issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000000,"exp":2000000,"schema":"test"}"#,
        r#"{"v":2,"kid":"test","issuer_vk":"not_an_array","sig_rj":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000000,"exp":2000000,"schema":"test"}"#,
        r#"{"v":2,"kid":"test","issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":"not_a_number","exp":2000000,"schema":"test"}"#,
        r#"{"v":2,"kid":"test","issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000000,"exp":"not_a_number","schema":"test"}"#,
    ];

    for wrong_json in wrong_types {
        let _ = CredentialV2::from_json(wrong_json);
    }

    // Test 7: JSON with null values
    let null_tests = vec![
        r#"{"v":null,"kid":"test","issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000000,"exp":2000000,"schema":"test"}"#,
        r#"{"v":2,"kid":null,"issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000000,"exp":2000000,"schema":"test"}"#,
        r#"{"v":2,"kid":"test","issuer_vk":null,"sig_rj":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000000,"exp":2000000,"schema":"test"}"#,
    ];

    for null_json in null_tests {
        let _ = CredentialV2::from_json(null_json);
    }

    // Test 8: JSON with optional private fields (dob_days, r_bits)
    if data.len() >= 4 {
        let dob_days = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        let json_with_private = format!(
            r#"{{
                "v": 2,
                "kid": "test",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 1000000,
                "exp": 2000000,
                "schema": "test",
                "dob_days": {},
                "r_bits": [true, false, true]
            }}"#,
            dob_days
        );

        let _ = CredentialV2::from_json(&json_with_private);
    }

    // Test 9: Deeply nested JSON
    let deep_nested = r#"{"outer":{"middle":{"inner":{"v":2}}}}"#;
    let _ = CredentialV2::from_json(deep_nested);

    // Test 10: Very long strings
    if data.len() >= 100 {
        let long_kid = String::from_utf8_lossy(&data[0..100]).to_string();
        let json_long = format!(
            r#"{{
                "v": 2,
                "kid": "{}",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 1000000,
                "exp": 2000000,
                "schema": "test"
            }}"#,
            long_kid
        );

        let _ = CredentialV2::from_json(&json_long);
    }

    // Test 11: JSON with Unicode and special characters
    if let Ok(utf8_str) = std::str::from_utf8(data) {
        let json_unicode = format!(
            r#"{{
                "v": 2,
                "kid": "{}",
                "issuer_vk": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                "sig_rj": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                "c_bytes": [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],
                "iat": 1000000,
                "exp": 2000000,
                "schema": "🔐-test-{}""
            }}"#,
            utf8_str.chars().take(10).collect::<String>(),
            utf8_str.chars().take(5).collect::<String>()
        );

        let _ = CredentialV2::from_json(&json_unicode);
    }

    // Test 12: Truncated JSON at various points
    if let Ok(json_str) = std::str::from_utf8(data) {
        for i in 0..json_str.len().min(200) {
            // Only slice at valid character boundaries to avoid panics
            if json_str.is_char_boundary(i) {
                let truncated = &json_str[..i];
                let _ = CredentialV2::from_json(truncated);
            }
        }
    }

    // Test 13: Valid credential followed by parsing it
    let valid_json = r#"{"v":2,"kid":"test_issuer","issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000000,"exp":2000000,"schema":"provii.age/0"}"#;
    if let Ok(cred) = CredentialV2::from_json(valid_json) {
        // Test serialization round-trip
        if let Ok(json_out) = cred.to_json() {
            let _ = CredentialV2::from_json(&json_out);
        }

        // Test pretty-print round-trip
        if let Ok(json_pretty) = cred.to_json_pretty() {
            let _ = CredentialV2::from_json(&json_pretty);
        }
    }

    // Test 14: Array elements out of range
    let out_of_range = r#"{"v":2,"kid":"test","issuer_vk":[256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256,256],"sig_rj":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000000,"exp":2000000,"schema":"test"}"#;
    let _ = CredentialV2::from_json(out_of_range);

    let negative_values = r#"{"v":2,"kid":"test","issuer_vk":[-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1],"sig_rj":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000000,"exp":2000000,"schema":"test"}"#;
    let _ = CredentialV2::from_json(negative_values);

    // Test 15: JSON with whitespace variations
    let whitespace_variations = vec![
        r#"{"v":2,"kid":"test","issuer_vk":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sig_rj":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"c_bytes":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"iat":1000000,"exp":2000000,"schema":"test"}"#,
        r#"{ "v" : 2 , "kid" : "test" , "issuer_vk" : [ 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 ] , "sig_rj" : [ 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 ] , "c_bytes" : [ 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 ] , "iat" : 1000000 , "exp" : 2000000 , "schema" : "test" }"#,
    ];

    for ws_json in whitespace_variations {
        let _ = CredentialV2::from_json(ws_json);
    }
});
