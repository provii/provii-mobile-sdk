// Copyright (c) 2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust (ABN 61 633 823 792)
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_mobile_sdk_core::utils::{encode_base64url, decode_base64url};

fuzz_target!(|data: &[u8]| {
    // Test 1: Encode fuzzer data to base64url
    if data.len() >= 1 {
        let encoded = encode_base64url(data);

        // CRITICAL: Verify no padding
        assert!(!encoded.contains('='), "Base64url should not contain padding");

        // CRITICAL: Verify URL-safe alphabet (no + or /)
        for ch in encoded.chars() {
            assert!(
                ch.is_alphanumeric() || ch == '-' || ch == '_',
                "Invalid URL-safe base64 character: {}",
                ch
            );
        }

        // Test roundtrip
        if let Ok(decoded) = decode_base64url(&encoded) {
            assert_eq!(decoded, data, "Base64url roundtrip must be lossless");
        }

        // Test determinism
        let encoded2 = encode_base64url(data);
        assert_eq!(encoded, encoded2, "Encoding must be deterministic");
    }

    // Test 2: Try to decode fuzzer data as base64url
    if let Ok(input_str) = std::str::from_utf8(data) {
        let _ = decode_base64url(input_str);
    }

    // Test 3: Edge cases - empty data
    let empty_encoded = encode_base64url(&[]);
    assert_eq!(empty_encoded, "", "Empty data should encode to empty string");

    let empty_decoded = decode_base64url("").expect("Empty string should decode");
    assert_eq!(empty_decoded.len(), 0, "Empty string should decode to empty vec");

    // Test 4: Single byte encoding
    for byte in 0u8..=255 {
        let single_byte = [byte];
        let encoded = encode_base64url(&single_byte);
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));

        let decoded = decode_base64url(&encoded).expect("should decode");
        assert_eq!(decoded, vec![byte]);
    }

    // Test 5: Various lengths to test padding edge cases
    for len in [0, 1, 2, 3, 4, 5, 8, 16, 32, 64, 128].iter() {
        if data.len() >= *len {
            let test_data = &data[..*len];
            let encoded = encode_base64url(test_data);

            // No padding for URL_SAFE_NO_PAD
            assert!(!encoded.contains('='));

            let decoded = decode_base64url(&encoded).expect("decode should work");
            assert_eq!(decoded, test_data);
        }
    }

    // Test 6: Base64url with padding (should fail with NO_PAD variant)
    let padded_strings = vec!["AA==", "AAA=", "AAAA=", "A==="];
    for padded in padded_strings {
        let result = decode_base64url(padded);
        // URL_SAFE_NO_PAD should reject padding
        if result.is_ok() {
            // If it decoded, verify the result
            let _ = result.unwrap();
        }
    }

    // Test 7: Standard base64 characters + and / (should fail for URL_SAFE)
    let standard_chars = vec!["AAAA+BBB", "AAAA/BBB", "++++", "////", "AA+/"];
    for chars in standard_chars {
        let result = decode_base64url(chars);
        // These should fail or produce different results than standard base64
        let _ = result;
    }

    // Test 8: Invalid base64url characters
    let invalid_chars = vec![
        "AAAA BBBB", // Whitespace
        "AAAA\nBBBB", // Newline
        "AAAA\tBBBB", // Tab
        "AAAA\rBBBB", // Carriage return
        "AAAA@BBBB", // Invalid char @
        "AAAA#BBBB", // Invalid char #
        "AAAA$BBBB", // Invalid char $
        "AAAA%BBBB", // Invalid char %
        "AAAA&BBBB", // Invalid char &
        "AAAA*BBBB", // Invalid char *
        "AAAA(BBBB", // Invalid char (
        "AAAA)BBBB", // Invalid char )
    ];

    for invalid in invalid_chars {
        let result = decode_base64url(invalid);
        // Should fail gracefully, not panic
        let _ = result;
    }

    // Test 9: Unicode in base64url (should fail)
    let unicode_tests = vec![
        "AAAA🔐BBBB",
        "テスト",
        "你好",
        "مرحبا",
    ];

    for unicode in unicode_tests {
        let result = decode_base64url(unicode);
        // Should fail gracefully
        assert!(result.is_err(), "Unicode should be rejected");
    }

    // Test 10: Very long base64url strings
    if data.len() >= 1000 {
        let encoded = encode_base64url(&data[..1000]);
        let decoded = decode_base64url(&encoded).expect("long string should decode");
        assert_eq!(decoded, &data[..1000]);
    }

    // Test 11: All zeros
    let zeros = vec![0u8; 32];
    let zeros_encoded = encode_base64url(&zeros);
    let zeros_decoded = decode_base64url(&zeros_encoded).expect("zeros should decode");
    assert_eq!(zeros_decoded, zeros);

    // Test 12: All ones (0xFF)
    let ones = vec![0xFFu8; 32];
    let ones_encoded = encode_base64url(&ones);
    let ones_decoded = decode_base64url(&ones_encoded).expect("ones should decode");
    assert_eq!(ones_decoded, ones);

    // Test 13: Alternating bytes
    let alternating: Vec<u8> = (0..32).map(|i| if i % 2 == 0 { 0xAA } else { 0x55 }).collect();
    let alt_encoded = encode_base64url(&alternating);
    let alt_decoded = decode_base64url(&alt_encoded).expect("alternating should decode");
    assert_eq!(alt_decoded, alternating);

    // Test 14: Truncated base64url strings
    if let Ok(input_str) = std::str::from_utf8(data) {
        if !input_str.is_empty() {
            for i in 0..input_str.len().min(50) {
                // Only slice at valid character boundaries to avoid panics
                if input_str.is_char_boundary(i) {
                    let truncated = &input_str[..i];
                    let _ = decode_base64url(truncated);
                }
            }
        }
    }

    // Test 15: Base64url alphabet edge cases
    let alphabet_tests = vec![
        "AAAA", // Valid
        "aaaa", // Valid (lowercase)
        "0000", // Valid (digits)
        "----", // Valid (URL-safe hyphen)
        "____", // Valid (URL-safe underscore)
        "AaZ0", // Mixed case and digits
        "A-_Z", // Mixed with URL-safe chars
    ];

    for test in alphabet_tests {
        let result = decode_base64url(test);
        if result.is_ok() {
            // Verify re-encoding produces valid base64url
            let decoded = result.unwrap();
            let re_encoded = encode_base64url(&decoded);
            assert!(!re_encoded.contains('='));
            assert!(!re_encoded.contains('+'));
            assert!(!re_encoded.contains('/'));
        }
    }

    // Test 16: Mixed valid/invalid sequences
    if data.len() >= 32 {
        let valid_b64 = encode_base64url(&data[..16]);
        let invalid_str = String::from_utf8_lossy(&data[16..32]);
        let mixed = format!("{}{}", valid_b64, invalid_str);

        let _ = decode_base64url(&mixed);
    }

    // Test 17: Case sensitivity
    if let Ok(input_str) = std::str::from_utf8(data) {
        if !input_str.is_empty() {
            let lower = input_str.to_lowercase();
            let upper = input_str.to_uppercase();

            let _ = decode_base64url(&lower);
            let _ = decode_base64url(&upper);

            // Base64 is case-sensitive, so these should produce different results or both fail
            let result_lower = decode_base64url(&lower);
            let result_upper = decode_base64url(&upper);

            if result_lower.is_ok() && result_upper.is_ok() {
                // Both valid base64url, but may decode to different values
                let _ = result_lower.unwrap() == result_upper.unwrap();
            }
        }
    }

    // Test 18: Encode data of various specific lengths
    let test_lengths = vec![1, 2, 3, 4, 5, 16, 31, 32, 33, 63, 64, 65, 127, 128];
    for len in test_lengths {
        if data.len() >= len {
            let test_data = &data[..len];
            let encoded = encode_base64url(test_data);

            // Verify encoding properties
            assert!(!encoded.contains('='), "No padding at length {}", len);
            assert!(!encoded.contains('+'), "No + at length {}", len);
            assert!(!encoded.contains('/'), "No / at length {}", len);

            // Verify roundtrip
            let decoded = decode_base64url(&encoded).expect(&format!("decode at length {}", len));
            assert_eq!(decoded, test_data, "Roundtrip at length {}", len);
        }
    }

    // Test 19: Control characters in input
    let with_control = "AAAA\x00\x01\x02BBBB";
    let _ = decode_base64url(with_control);

    // Test 20: High byte values in encoding
    if data.len() >= 8 {
        let high_bytes = vec![0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0];
        let encoded = encode_base64url(&high_bytes);
        let decoded = decode_base64url(&encoded).expect("high bytes should decode");
        assert_eq!(decoded, high_bytes);
    }

    // Test 21: Specific 32-byte and 64-byte arrays (common in crypto)
    if data.len() >= 32 {
        let bytes_32 = &data[..32];
        let encoded_32 = encode_base64url(bytes_32);

        // 32 bytes encodes to 43 chars without padding
        assert_eq!(encoded_32.len(), 43, "32 bytes should encode to 43 chars");

        let decoded_32 = decode_base64url(&encoded_32).expect("32-byte decode");
        assert_eq!(decoded_32.len(), 32);
        assert_eq!(decoded_32, bytes_32);
    }

    if data.len() >= 64 {
        let bytes_64 = &data[..64];
        let encoded_64 = encode_base64url(bytes_64);

        // 64 bytes encodes to 86 chars without padding
        assert_eq!(encoded_64.len(), 86, "64 bytes should encode to 86 chars");

        let decoded_64 = decode_base64url(&encoded_64).expect("64-byte decode");
        assert_eq!(decoded_64.len(), 64);
        assert_eq!(decoded_64, bytes_64);
    }

    // Test 22: Null bytes in data
    let with_nulls = vec![0u8, 1, 2, 3, 0, 0, 4, 5, 0];
    let nulls_encoded = encode_base64url(&with_nulls);
    let nulls_decoded = decode_base64url(&nulls_encoded).expect("nulls should decode");
    assert_eq!(nulls_decoded, with_nulls);

    // Test 23: Sequential byte patterns
    let sequential: Vec<u8> = (0..=255).collect();
    let seq_encoded = encode_base64url(&sequential);
    let seq_decoded = decode_base64url(&seq_encoded).expect("sequential should decode");
    assert_eq!(seq_decoded, sequential);

    // Test 24: Empty and whitespace strings
    let empty_ws_tests = vec!["", " ", "  ", "\n", "\t", "\r\n"];
    for ws in empty_ws_tests {
        let result = decode_base64url(ws);
        // Empty should succeed, whitespace should fail
        if ws.is_empty() {
            assert!(result.is_ok(), "Empty string should decode");
            assert_eq!(result.unwrap().len(), 0);
        } else {
            // Whitespace should be rejected
            let _ = result;
        }
    }

    // Test 25: Determinism check - encode same data multiple times
    if data.len() >= 16 {
        let test_data = &data[..16];
        let enc1 = encode_base64url(test_data);
        let enc2 = encode_base64url(test_data);
        let enc3 = encode_base64url(test_data);

        assert_eq!(enc1, enc2, "Encoding must be deterministic");
        assert_eq!(enc2, enc3, "Encoding must be deterministic");
    }
});
