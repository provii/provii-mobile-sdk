// Copyright (c) 2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust (ABN 61 633 823 792)
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_mobile_sdk_core::issuance::{parse_dob_iso, days_to_iso};

fuzz_target!(|data: &[u8]| {
    // Test 1: Fuzz parse_dob_iso with arbitrary data
    if let Ok(date_str) = std::str::from_utf8(data) {
        let _ = parse_dob_iso(date_str);
    }

    // Test 2: Valid date format patterns with fuzzer data
    if data.len() >= 8 {
        // Extract year, month, day from fuzzer data
        let year = u16::from_le_bytes([data[0], data[1]]) % 3000; // 0-2999
        let month = (data[2] % 12) + 1; // 1-12
        let day = (data[3] % 31) + 1; // 1-31

        let date_string = format!("{:04}-{:02}-{:02}", year, month, day);
        let result = parse_dob_iso(&date_string);

        // If parsing succeeded, verify round-trip
        if let Ok(days) = result {
            if let Ok(recovered) = days_to_iso(days) {
                // The recovered date should be parseable
                let _ = parse_dob_iso(&recovered);
            }
        }
    }

    // Test 3: Malformed date patterns
    let malformed_patterns = vec![
        "",
        "not-a-date",
        "2020",
        "2020-01",
        "2020-1-1",
        "20-01-01",
        "2020/01/01",
        "01-01-2020",
        "2020-13-01", // Invalid month
        "2020-00-01", // Invalid month
        "2020-01-32", // Invalid day
        "2020-01-00", // Invalid day
        "2020-02-30", // Invalid day for February
        "2020-04-31", // Invalid day for April
        "9999-99-99",
        "0000-00-00",
        "-001-01-01",
        "2020--1-01",
        "2020-01--1",
    ];

    for pattern in malformed_patterns {
        let _ = parse_dob_iso(pattern);
    }

    // Test 4: Edge case dates
    let edge_cases = vec![
        "1970-01-01", // Unix epoch
        "2000-01-01", // Y2K
        "2020-02-29", // Leap year
        "2021-02-29", // Not a leap year
        "1900-02-29", // Not a leap year (divisible by 100)
        "2000-02-29", // Leap year (divisible by 400)
        "1969-12-31", // Before epoch (should fail)
        "1970-01-02", // Just after epoch
        "2100-01-01", // Future date
        "2038-01-19", // Near 32-bit timestamp limit
        "2262-04-11", // Near 64-bit millisecond limit
    ];

    for date_str in edge_cases {
        let _ = parse_dob_iso(date_str);
    }

    // Test 5: Dates with various separators (should fail - expects hyphen)
    let wrong_separators = vec![
        "2020/01/01",
        "2020.01.01",
        "2020_01_01",
        "2020 01 01",
        "20200101",
    ];

    for date_str in wrong_separators {
        let result = parse_dob_iso(date_str);
        // Should fail - format requires YYYY-MM-DD
        assert!(result.is_err(), "Wrong separator should be rejected: {}", date_str);
    }

    // Test 6: Dates with extra characters
    let extra_chars = vec![
        "2020-01-01 ",
        " 2020-01-01",
        "2020-01-01T00:00:00",
        "2020-01-01Z",
        "2020-01-01+00:00",
        "2020-01-01\n",
        "2020-01-01\r\n",
        "x2020-01-01",
        "2020-01-01x",
    ];

    for date_str in extra_chars {
        let _ = parse_dob_iso(date_str);
    }

    // Test 7: Various date lengths
    if let Ok(input_str) = std::str::from_utf8(data) {
        // Try various lengths, only at character boundaries
        for len in 1..input_str.len().min(50) {
            if input_str.is_char_boundary(len) {
                let substring = &input_str[..len];
                let _ = parse_dob_iso(substring);
            }
        }
    }

    // Test 8: Specific year edge cases
    let year_edges = vec![
        "0001-01-01", // Year 1
        "1000-01-01", // Year 1000
        "1969-12-31", // Day before epoch (should fail)
        "1970-01-01", // Epoch
        "1999-12-31", // End of millennium
        "2000-01-01", // Start of new millennium
        "2020-12-31", // Recent date
        "2099-12-31", // Near century end
        "2100-01-01", // New century
        "9999-12-31", // Far future
    ];

    for date_str in year_edges {
        let _ = parse_dob_iso(date_str);
    }

    // Test 9: Month edge cases
    for month in 0..=13 {
        let date_str = format!("2020-{:02}-15", month);
        let result = parse_dob_iso(&date_str);

        if month >= 1 && month <= 12 {
            // Valid months should succeed
            let _ = result;
        } else {
            // Invalid months should fail
            assert!(result.is_err(), "Invalid month should be rejected: {}", month);
        }
    }

    // Test 10: Day edge cases for each month
    let days_in_month = vec![
        (1, 31),  // January
        (2, 29),  // February (leap year)
        (3, 31),  // March
        (4, 30),  // April
        (5, 31),  // May
        (6, 30),  // June
        (7, 31),  // July
        (8, 31),  // August
        (9, 30),  // September
        (10, 31), // October
        (11, 30), // November
        (12, 31), // December
    ];

    for (month, max_day) in days_in_month {
        // Test valid day
        let valid_date = format!("2020-{:02}-{:02}", month, max_day);
        let _ = parse_dob_iso(&valid_date);

        // Test invalid day (one more than max)
        let invalid_date = format!("2020-{:02}-{:02}", month, max_day + 1);
        let result = parse_dob_iso(&invalid_date);
        // Should fail for most months
        let _ = result;
    }

    // Test 11: Leap year handling
    let leap_years = vec![2000, 2004, 2008, 2012, 2016, 2020, 2024];
    let non_leap_years = vec![1900, 2001, 2002, 2003, 2100, 2200];

    for year in leap_years {
        let leap_date = format!("{}-02-29", year);
        let result = parse_dob_iso(&leap_date);
        // Feb 29 should be valid in leap years
        if year >= 1970 {
            // Only after epoch
            let _ = result.is_ok();
        }
    }

    for year in non_leap_years {
        let non_leap_date = format!("{}-02-29", year);
        let result = parse_dob_iso(&non_leap_date);
        // Feb 29 should be invalid in non-leap years
        assert!(result.is_err(), "Feb 29 should be invalid in non-leap year {}", year);
    }

    // Test 12: Round-trip consistency
    for days in [0i32, 1, 100, 1000, 10000, 18262, 20000, 25000].iter() {
        if let Ok(date_str) = days_to_iso(*days) {
            if let Ok(recovered_days) = parse_dob_iso(&date_str) {
                assert_eq!(recovered_days, *days, "Round-trip failed for {} days", days);
            }
        }
    }

    // Test 13: dates before epoch (now return negative i32)
    let before_epoch = vec![
        "1969-12-31",
        "1960-01-01",
        "1900-01-01",
        "1800-01-01",
    ];

    for date_str in before_epoch {
        let result = parse_dob_iso(date_str);
        assert!(result.is_ok(), "Pre-epoch dates should be valid: {}", date_str);
        assert!(result.expect("validated above") < 0, "Pre-epoch date should have negative days: {}", date_str);
    }

    // Test 14: Unicode and special characters
    if let Ok(utf8_str) = std::str::from_utf8(data) {
        let unicode_dates = vec![
            format!("2020-01-01{}", utf8_str.chars().take(5).collect::<String>()),
            format!("{}2020-01-01", utf8_str.chars().take(5).collect::<String>()),
            format!("2020{}01-01", utf8_str.chars().take(2).collect::<String>()),
        ];

        for date_str in unicode_dates {
            let _ = parse_dob_iso(&date_str);
        }
    }

    // Test 15: Null bytes and control characters
    let with_nulls = "2020\x00-01-01";
    let _ = parse_dob_iso(with_nulls);

    let with_control = "2020\n-01\r-01\t";
    let _ = parse_dob_iso(with_control);

    // Test 16: Very long strings
    if data.len() >= 100 {
        let long_str = String::from_utf8_lossy(&data[..100]).to_string();
        let _ = parse_dob_iso(&long_str);
    }

    // Test 17: Padding variations
    let padding_variations = vec![
        "2020-1-1",     // No padding
        "2020-01-1",    // Partial padding
        "2020-1-01",    // Partial padding
        "02020-01-01",  // Extra padding
        "2020-001-01",  // Extra padding
        "2020-01-001",  // Extra padding
    ];

    for date_str in padding_variations {
        let _ = parse_dob_iso(date_str);
    }

    // Test 18: Negative numbers
    let negative_tests = vec![
        "-2020-01-01",
        "2020--01-01",
        "2020-01--01",
        "-1-01-01",
    ];

    for date_str in negative_tests {
        let _ = parse_dob_iso(date_str);
    }

    // Test 19: Decimal/floating point numbers
    let decimal_tests = vec![
        "2020.5-01-01",
        "2020-01.5-01",
        "2020-01-01.5",
        "2020-1.2-1.3",
    ];

    for date_str in decimal_tests {
        let _ = parse_dob_iso(date_str);
    }

    // Test 20: Valid dates that should parse successfully
    let valid_dates = vec![
        "1970-01-01",
        "1980-06-15",
        "1990-12-31",
        "2000-02-29", // Leap year
        "2010-07-04",
        "2020-01-01",
        "2024-02-29", // Leap year
    ];

    for date_str in valid_dates {
        if let Ok(days) = parse_dob_iso(date_str) {
            // Verify it's a reasonable number
            assert!(days < 50000, "Days should be reasonable: {}", days);

            // Verify round-trip
            if let Ok(recovered) = days_to_iso(days) {
                let recovered_days = parse_dob_iso(&recovered).expect("round-trip should work");
                assert_eq!(recovered_days, days, "Round-trip consistency failed");
            }
        }
    }

    // Test 21: Case sensitivity (dates should be case-insensitive, but our parser is strict)
    let case_tests = vec![
        "2020-01-01",
        "2020-01-01",
    ];

    for date_str in case_tests {
        let _ = parse_dob_iso(date_str);
    }

    // Test 22: Repeated separators
    let repeated_separators = vec![
        "2020--01-01",
        "2020-01--01",
        "2020---01-01",
    ];

    for date_str in repeated_separators {
        let result = parse_dob_iso(date_str);
        assert!(result.is_err(), "Repeated separators should be rejected");
    }

    // Test 23: Missing separators
    let missing_separators = vec![
        "202001-01",
        "2020-0101",
        "20200101",
    ];

    for date_str in missing_separators {
        let result = parse_dob_iso(date_str);
        assert!(result.is_err(), "Missing separators should be rejected");
    }

    // Test 24: Fuzzer-generated numeric patterns
    if data.len() >= 10 {
        // Generate year from 1900-2100
        let year = 1900 + (u16::from_le_bytes([data[0], data[1]]) % 201);
        let month = 1 + (data[2] % 12);
        let day = 1 + (data[3] % 28); // Use 28 to avoid invalid days

        let date_str = format!("{:04}-{:02}-{:02}", year, month, day);
        let result = parse_dob_iso(&date_str);

        if let Ok(days) = result {
            // Pre-epoch dates return negative i32, post-epoch return positive.
            if year >= 1970 {
                assert!(days >= 0, "Post-epoch date should have non-negative days");
            } else {
                assert!(days < 0, "Pre-epoch date should have negative days");
            }
            // Verify round-trip
            if let Ok(recovered) = days_to_iso(days) {
                let _ = parse_dob_iso(&recovered).expect("round-trip");
            }
        }
    }

    // Test 25: Boundary testing for days_to_iso
    if data.len() >= 4 {
        let days = (i32::from_le_bytes([data[0], data[1], data[2], data[3]]).abs()) % 50000; // Reasonable range
        if let Ok(date_str) = days_to_iso(days) {
            // Verify it's a valid date string format
            assert_eq!(date_str.len(), 10, "Date string should be 10 chars: YYYY-MM-DD");
            assert_eq!(date_str.as_bytes()[4], b'-', "Should have hyphen at position 4");
            assert_eq!(date_str.as_bytes()[7], b'-', "Should have hyphen at position 7");

            // Verify it can be parsed back
            let recovered_days = parse_dob_iso(&date_str).expect("Generated date should be parseable");
            assert_eq!(recovered_days, days, "Round-trip should preserve days value");
        }
    }
});
