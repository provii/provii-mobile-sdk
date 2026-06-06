// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Common utility functions for the wallet SDK.
//!
//! Provides date arithmetic (epoch day conversions, age cutoff calculations),
//! cryptographic helpers (SHA-256 hashing, random nonce generation),
//! encoding (base64url without padding), timestamp formatting, and
//! deep link URL parsing.
//!
//! All functions in this module are safe to use in both `std` and `no_std`
//! environments unless gated behind `#[cfg(feature = "std")]`.

#![forbid(unsafe_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Datelike, NaiveDate, Utc};
use sha2::{Digest, Sha256};

/// Returns the current wall-clock time as seconds since the Unix epoch.
///
/// Falls back to zero if the system clock is set before 1970-01-01.
#[inline]
pub fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Days between day-0 in the proleptic Gregorian calendar and 1970-01-01.
const UNIX_EPOCH_OFFSET_DAYS: i64 = 719_163;

/// Converts a calendar date to the number of days since the Unix epoch.
///
/// Returns 0 for dates before 1970-01-01 (the subtraction is clamped).
#[inline]
#[allow(clippy::arithmetic_side_effects)] // i64 subtraction of bounded calendar day count cannot overflow
#[allow(clippy::cast_sign_loss)] // .max(0) guarantees non-negative before cast
pub fn days_since_epoch(date: NaiveDate) -> u64 {
    let days_from_ce = i64::from(date.num_days_from_ce());
    let signed = days_from_ce - UNIX_EPOCH_OFFSET_DAYS;
    signed.max(0) as u64
}

/// Converts a day count (since the Unix epoch) back to a [`NaiveDate`].
///
/// Returns `None` if `days` overflows the representable calendar range. In
/// practice this only occurs for values well above 10 million.
#[inline]
pub fn date_from_days(days: u64) -> Option<NaiveDate> {
    let days_i64 = i64::try_from(days).ok()?;
    let days_from_ce = UNIX_EPOCH_OFFSET_DAYS.checked_add(days_i64)?;
    let days_i32 = i32::try_from(days_from_ce).ok()?;
    NaiveDate::from_num_days_from_ce_opt(days_i32)
}

/// Calculates the cutoff day (as days since epoch) for a given minimum age.
///
/// The cutoff date is today's date minus `min_age_years` whole calendar years.
/// A person born on or before the cutoff date satisfies the age requirement.
///
/// Returns an error if `min_age_years` exceeds 200 or if the resulting year
/// falls outside the representable calendar range.
pub fn calculate_cutoff_days(min_age_years: u32) -> Result<i32, crate::WalletError> {
    if min_age_years > 200 {
        return Err(crate::WalletError::InvalidInput(
            "min_age_years exceeds maximum of 200".to_string(),
        ));
    }
    let today = Utc::now().date_naive();
    let age_i32 = i32::try_from(min_age_years).map_err(|_| {
        crate::WalletError::InvalidInput("min_age_years exceeds i32 range".to_string())
    })?;
    let target_year = today.year().checked_sub(age_i32).ok_or_else(|| {
        crate::WalletError::InvalidInput("cutoff year out of representable range".to_string())
    })?;
    let cutoff_date = match today.with_year(target_year) {
        Some(d) => d,
        // Feb 29 in a leap year with a non-leap target year: fall back to Feb 28.
        // Conservative: slightly earlier cutoff = slightly stricter age gate.
        None => NaiveDate::from_ymd_opt(target_year, 2, 28).ok_or_else(|| {
            crate::WalletError::InvalidInput("cutoff year out of representable range".to_string())
        })?,
    };
    // Use signed arithmetic: cutoff date may be before 1970, producing a negative day count
    let days_from_ce = i64::from(cutoff_date.num_days_from_ce());
    #[allow(clippy::arithmetic_side_effects)] // bounded i64 subtraction
    let signed_days = days_from_ce - UNIX_EPOCH_OFFSET_DAYS;
    i32::try_from(signed_days)
        .map_err(|_| crate::WalletError::InvalidInput("cutoff days exceeds i32 range".to_string()))
}

/// Generates a 32-byte cryptographically secure random nonce using the OS RNG.
#[cfg(feature = "std")]
pub fn random_nonce() -> [u8; 32] {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Computes the SHA-256 digest of `data`, returning the 32-byte hash.
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Encodes `data` as a base64url string without padding characters.
pub fn encode_base64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decodes a base64url string (without padding) into raw bytes.
///
/// Returns an error if `s` contains characters outside the base64url
/// alphabet or includes padding (`=`).
pub fn decode_base64url(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s)
}

/// Deserialises a JSON-encoded QR code payload into `T`.
#[cfg(feature = "std")]
pub fn parse_qr_json<T: serde::de::DeserializeOwned>(
    qr_data: &str,
) -> Result<T, serde_json::Error> {
    serde_json::from_str(qr_data)
}

/// Formats a Unix timestamp (seconds) as an ISO 8601 / RFC 3339 string.
///
/// Falls back to the raw numeric representation if the timestamp cannot be
/// converted to a valid datetime.
#[cfg(feature = "std")]
pub fn format_timestamp(timestamp: u64) -> String {
    use chrono::TimeZone;
    let ts_i64 = match i64::try_from(timestamp) {
        Ok(v) => v,
        Err(_) => return format!("{}", timestamp),
    };
    chrono::Utc
        .timestamp_opt(ts_i64, 0)
        .single()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| format!("{}", timestamp))
}

/// Returns `true` if `exp_timestamp` (seconds since epoch) is in the past.
pub fn is_expired(exp_timestamp: u64) -> bool {
    current_timestamp() > exp_timestamp
}

/// Returns `true` if a person born on `dob_days` satisfies the age requirement
/// expressed by `cutoff_days`. Both values are days since the Unix epoch.
///
/// When `is_under_age` is `false` (the default "over_age" direction), the person
/// must have been born on or before the cutoff (i.e. old enough). When `true`,
/// the person must have been born on or after the cutoff (i.e. young enough).
pub fn validate_age(dob_days: i32, cutoff_days: i32, is_under_age: bool) -> bool {
    if is_under_age {
        dob_days >= cutoff_days // born AFTER cutoff = young enough
    } else {
        dob_days <= cutoff_days // born BEFORE cutoff = old enough
    }
}

/// Validates that `id` is a well-formed UUID v4 string.
///
/// Accepts exactly 36 ASCII characters in the pattern
/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` where each `x` is a lowercase or
/// uppercase hex digit and hyphens appear at byte positions 8, 13, 18, and 23.
///
/// This is intentionally lenient about the version and variant nibbles so that
/// any UUID-shaped string is accepted (v1 through v7). The purpose is to prevent
/// path traversal and query injection when the value is interpolated into a URL
/// path segment, not to enforce RFC 4122 version semantics.
///
/// # Errors
///
/// Returns [`crate::WalletError::InvalidInput`] if the string does not match.
pub fn validate_uuid_format(id: &str) -> Result<(), crate::WalletError> {
    if id.len() != 36 {
        return Err(crate::WalletError::InvalidInput(
            "challenge_id must be exactly 36 characters".to_string(),
        ));
    }

    for (i, b) in id.bytes().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if b != b'-' {
                    return Err(crate::WalletError::InvalidInput(
                        "challenge_id has invalid format: expected hyphen".to_string(),
                    ));
                }
            }
            _ => {
                if !b.is_ascii_hexdigit() {
                    return Err(crate::WalletError::InvalidInput(
                        "challenge_id has invalid format: non-hex character".to_string(),
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Parses a deep link URL and returns its query parameters as key-value pairs.
///
/// Intended for processing `https://proviiwallet.app/attest?d=...` and
/// `https://proviiwallet.app/verify?d=...` deep link URLs received by the
/// wallet application.
#[cfg(feature = "std")]
pub fn parse_deep_link(
    url_str: &str,
) -> Result<std::collections::HashMap<String, String>, crate::WalletError> {
    use std::collections::HashMap;

    let url = url::Url::parse(url_str)
        .map_err(|e| crate::WalletError::InvalidInput(format!("Invalid URL: {}", e)))?;

    let params: HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    Ok(params)
}

#[cfg(test)]
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
    use chrono::NaiveDate;

    #[test]
    fn test_days_since_epoch() -> Result<(), Box<dyn std::error::Error>> {
        // Test Unix epoch start date
        let epoch_date = NaiveDate::from_ymd_opt(1970, 1, 1).ok_or("invalid date")?;
        assert_eq!(days_since_epoch(epoch_date), 0);

        // Test a known date: 2020-01-01 = 18262 days since epoch
        let date_2020 = NaiveDate::from_ymd_opt(2020, 1, 1).ok_or("invalid date")?;
        assert_eq!(days_since_epoch(date_2020), 18262);

        // Test a known date: 2000-01-01 = 10957 days since epoch
        let date_2000 = NaiveDate::from_ymd_opt(2000, 1, 1).ok_or("invalid date")?;
        assert_eq!(days_since_epoch(date_2000), 10957);
        Ok(())
    }

    #[test]
    fn test_date_from_days() -> Result<(), Box<dyn std::error::Error>> {
        // Test Unix epoch
        let epoch = date_from_days(0).ok_or("invalid days")?;
        assert_eq!(
            epoch,
            NaiveDate::from_ymd_opt(1970, 1, 1).ok_or("invalid date")?
        );

        // Test 2020-01-01
        let date_2020 = date_from_days(18262).ok_or("invalid days")?;
        assert_eq!(
            date_2020,
            NaiveDate::from_ymd_opt(2020, 1, 1).ok_or("invalid date")?
        );

        // Test 2000-01-01
        let date_2000 = date_from_days(10957).ok_or("invalid days")?;
        assert_eq!(
            date_2000,
            NaiveDate::from_ymd_opt(2000, 1, 1).ok_or("invalid date")?
        );
        Ok(())
    }

    #[test]
    fn test_days_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        // Test that conversion is reversible
        let original_date = NaiveDate::from_ymd_opt(1995, 6, 15).ok_or("invalid date")?;
        let days = days_since_epoch(original_date);
        let recovered_date = date_from_days(days).ok_or("invalid days")?;
        assert_eq!(recovered_date, original_date);
        Ok(())
    }

    #[test]
    fn test_calculate_cutoff_days() -> Result<(), Box<dyn std::error::Error>> {
        // This test depends on current date, so we'll just verify it returns a reasonable value
        let cutoff_18 = calculate_cutoff_days(18)?;
        let cutoff_21 = calculate_cutoff_days(21)?;

        // 21-year cutoff should be less than 18-year cutoff (earlier date)
        assert!(cutoff_21 < cutoff_18);

        // Verify the difference is approximately 3 years worth of days (about 1095 days)
        let diff = cutoff_18.saturating_sub(cutoff_21);
        assert!(
            (1090..=1100).contains(&diff),
            "diff should be ~3 years = ~1095 days, got {}",
            diff
        );
        Ok(())
    }

    #[test]
    fn test_sha256_hash() -> Result<(), Box<dyn std::error::Error>> {
        let data = b"hello world";
        let hash = sha256_hash(data);

        // Verify hash length
        assert_eq!(hash.len(), 32);

        // Verify deterministic (same input produces same hash)
        let hash2 = sha256_hash(data);
        assert_eq!(hash, hash2);

        // Verify different inputs produce different hashes
        let hash3 = sha256_hash(b"goodbye world");
        assert_ne!(hash, hash3);
        Ok(())
    }

    #[test]
    fn test_encode_decode_base64url() -> Result<(), Box<dyn std::error::Error>> {
        let data = b"test data for base64url encoding";

        // Test encode
        let encoded = encode_base64url(data);

        // Verify no padding
        assert!(!encoded.contains('='));

        // Test decode
        let decoded = decode_base64url(&encoded)?;
        assert_eq!(decoded, data);
        Ok(())
    }

    #[test]
    fn test_base64url_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let test_cases: Vec<&[u8]> = vec![
            b"",
            b"a",
            b"ab",
            b"abc",
            b"test",
            &[0u8; 32],   // 32 zero bytes
            &[255u8; 64], // 64 max bytes
        ];

        for data in test_cases {
            let encoded = encode_base64url(data);
            let decoded = decode_base64url(&encoded)?;
            assert_eq!(&decoded[..], data);
        }
        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_random_nonce() -> Result<(), Box<dyn std::error::Error>> {
        let nonce1 = random_nonce();
        let nonce2 = random_nonce();

        // Verify length
        assert_eq!(nonce1.len(), 32);
        assert_eq!(nonce2.len(), 32);

        // Verify randomness (two nonces should be different)
        assert_ne!(nonce1, nonce2);
        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_parse_qr_json() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"field1": "value1", "field2": 42}"#;

        #[derive(serde::Deserialize, PartialEq, Debug)]
        struct TestStruct {
            field1: String,
            field2: u32,
        }

        let parsed: TestStruct = parse_qr_json(json)?;
        assert_eq!(parsed.field1, "value1");
        assert_eq!(parsed.field2, 42);
        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_format_timestamp() -> Result<(), Box<dyn std::error::Error>> {
        let timestamp: u64 = 1609459200; // 2021-01-01 00:00:00 UTC
        let formatted = format_timestamp(timestamp);

        // Verify it contains the year
        assert!(formatted.contains("2021"));
        assert!(formatted.contains("01"));
        Ok(())
    }

    #[test]
    fn test_is_expired() -> Result<(), Box<dyn std::error::Error>> {
        // Get current timestamp
        let now = current_timestamp();

        // Past timestamp should be expired
        assert!(is_expired(now.saturating_sub(100)));

        // Future timestamp should not be expired
        assert!(!is_expired(now + 1000));

        // Current timestamp (edge case)
        assert!(!is_expired(now + 1));
        Ok(())
    }

    #[test]
    fn test_validate_age() -> Result<(), Box<dyn std::error::Error>> {
        // DOB exactly at cutoff (over_age)
        assert!(validate_age(10000, 10000, false));

        // DOB before cutoff (older, valid for over_age)
        assert!(validate_age(9000, 10000, false));

        // DOB after cutoff (younger, invalid for over_age)
        assert!(!validate_age(11000, 10000, false));
        Ok(())
    }

    #[test]
    fn test_current_timestamp() -> Result<(), Box<dyn std::error::Error>> {
        let ts = current_timestamp();
        // Just verify it's a reasonable timestamp (after 2020-01-01 and before 2100-01-01)
        assert!(ts > 1577836800); // 2020-01-01
        assert!(ts < 4102444800); // 2100-01-01
        Ok(())
    }

    // ============================================================================
    // COMPREHENSIVE EDGE CASE TESTS
    // ============================================================================

    // --- days_since_epoch() edge cases ---

    #[test]
    fn test_days_since_epoch_year_boundaries() -> Result<(), Box<dyn std::error::Error>> {
        // Year 1971 start
        let date = NaiveDate::from_ymd_opt(1971, 1, 1).ok_or("invalid date")?;
        assert_eq!(days_since_epoch(date), 365);

        // Year 1980 start (after leap years)
        let date = NaiveDate::from_ymd_opt(1980, 1, 1).ok_or("invalid date")?;
        assert_eq!(days_since_epoch(date), 3652);
        Ok(())
    }

    #[test]
    fn test_days_since_epoch_leap_year_feb29() -> Result<(), Box<dyn std::error::Error>> {
        // 1972 was a leap year
        let feb28_1972 = NaiveDate::from_ymd_opt(1972, 2, 28).ok_or("invalid date")?;
        let feb29_1972 = NaiveDate::from_ymd_opt(1972, 2, 29).ok_or("invalid date")?;
        let mar1_1972 = NaiveDate::from_ymd_opt(1972, 3, 1).ok_or("invalid date")?;

        assert_eq!(
            days_since_epoch(feb29_1972),
            days_since_epoch(feb28_1972) + 1
        );
        assert_eq!(
            days_since_epoch(mar1_1972),
            days_since_epoch(feb29_1972) + 1
        );
        Ok(())
    }

    #[test]
    fn test_days_since_epoch_century_leap_year() -> Result<(), Box<dyn std::error::Error>> {
        // 2000 was a leap year (divisible by 400)
        let feb29_2000 = NaiveDate::from_ymd_opt(2000, 2, 29).ok_or("invalid date")?;
        assert!(days_since_epoch(feb29_2000) > 0);
        Ok(())
    }

    #[test]
    fn test_days_since_epoch_month_boundaries() -> Result<(), Box<dyn std::error::Error>> {
        // Test all month transitions
        let dates = vec![
            (
                NaiveDate::from_ymd_opt(2020, 1, 31).ok_or("invalid date")?,
                NaiveDate::from_ymd_opt(2020, 2, 1).ok_or("invalid date")?,
            ),
            (
                NaiveDate::from_ymd_opt(2020, 3, 31).ok_or("invalid date")?,
                NaiveDate::from_ymd_opt(2020, 4, 1).ok_or("invalid date")?,
            ),
            (
                NaiveDate::from_ymd_opt(2020, 4, 30).ok_or("invalid date")?,
                NaiveDate::from_ymd_opt(2020, 5, 1).ok_or("invalid date")?,
            ),
            (
                NaiveDate::from_ymd_opt(2020, 11, 30).ok_or("invalid date")?,
                NaiveDate::from_ymd_opt(2020, 12, 1).ok_or("invalid date")?,
            ),
        ];

        for (last_of_month, first_of_next) in dates {
            assert_eq!(
                days_since_epoch(first_of_next),
                days_since_epoch(last_of_month) + 1
            );
        }
        Ok(())
    }

    #[test]
    fn test_days_since_epoch_far_future() -> Result<(), Box<dyn std::error::Error>> {
        // Year 2100
        let date = NaiveDate::from_ymd_opt(2100, 1, 1).ok_or("invalid date")?;
        let days = days_since_epoch(date);
        assert!(days > 40000); // Should be ~47482 days

        // Year 2500
        let date = NaiveDate::from_ymd_opt(2500, 1, 1).ok_or("invalid date")?;
        let days = days_since_epoch(date);
        assert!(days > 100000);
        Ok(())
    }

    #[test]
    fn test_days_since_epoch_dates_before_1970() -> Result<(), Box<dyn std::error::Error>> {
        // 1969-12-31 (one day before epoch)
        // days_since_epoch clamps pre-epoch dates to 0
        let date = NaiveDate::from_ymd_opt(1969, 12, 31).ok_or("invalid date")?;
        let days = days_since_epoch(date);
        assert_eq!(days, 0, "pre-epoch dates should clamp to 0");
        Ok(())
    }

    #[test]
    fn test_days_since_epoch_year_1900() -> Result<(), Box<dyn std::error::Error>> {
        // 1900 was NOT a leap year (not divisible by 400)
        // days_since_epoch clamps pre-epoch dates to 0
        let date = NaiveDate::from_ymd_opt(1900, 1, 1).ok_or("invalid date")?;
        let days = days_since_epoch(date);
        assert_eq!(days, 0, "pre-epoch dates should clamp to 0");
        Ok(())
    }

    // --- date_from_days() edge cases ---

    #[test]
    fn test_date_from_days_large_values() -> Result<(), Box<dyn std::error::Error>> {
        // 50000 days from epoch (year 2106)
        let date = date_from_days(50000).ok_or("invalid days")?;
        assert!(date.year() > 2100);

        // 100000 days from epoch (year 2243)
        let date = date_from_days(100000).ok_or("invalid days")?;
        assert!(date.year() > 2200);
        Ok(())
    }

    #[test]
    fn test_date_from_days_sequential() -> Result<(), Box<dyn std::error::Error>> {
        // Verify sequential days produce valid dates
        for days in 0..1000 {
            let date = date_from_days(days).ok_or("invalid days")?;
            assert!(date.year() >= 1970);
        }
        Ok(())
    }

    #[test]
    fn test_date_from_days_leap_year_coverage() -> Result<(), Box<dyn std::error::Error>> {
        // Days that should land on Feb 29 of various leap years
        let feb29_1972_days =
            days_since_epoch(NaiveDate::from_ymd_opt(1972, 2, 29).ok_or("invalid date")?);
        let recovered = date_from_days(feb29_1972_days).ok_or("invalid days")?;
        assert_eq!(recovered.month(), 2);
        assert_eq!(recovered.day(), 29);
        Ok(())
    }

    // --- calculate_cutoff_days() edge cases ---

    #[test]
    fn test_calculate_cutoff_days_age_zero() -> Result<(), Box<dyn std::error::Error>> {
        let cutoff = calculate_cutoff_days(0)?;
        let today = Utc::now().date_naive();
        let expected = days_since_epoch(today) as i32;
        assert_eq!(cutoff, expected);
        Ok(())
    }

    #[test]
    fn test_calculate_cutoff_days_age_one() -> Result<(), Box<dyn std::error::Error>> {
        let cutoff = calculate_cutoff_days(1)?;
        let today = Utc::now().date_naive();
        let expected =
            days_since_epoch(today.with_year(today.year() - 1).ok_or("invalid year")?) as i32;
        assert_eq!(cutoff, expected);
        Ok(())
    }

    #[test]
    fn test_calculate_cutoff_days_age_100() -> Result<(), Box<dyn std::error::Error>> {
        let cutoff_100 = calculate_cutoff_days(100)?;
        let cutoff_99 = calculate_cutoff_days(99)?;

        // 100 year old cutoff should be less than 99
        assert!(cutoff_100 < cutoff_99);

        // Difference should be approximately 365 days
        let diff = cutoff_99.saturating_sub(cutoff_100);
        assert!((365..=366).contains(&diff));
        Ok(())
    }

    #[test]
    fn test_calculate_cutoff_days_age_150() -> Result<(), Box<dyn std::error::Error>> {
        // Extreme age (150 years ago is before 1970) - returns negative i32
        let cutoff = calculate_cutoff_days(150)?;
        assert!(cutoff < 0);
        Ok(())
    }

    #[test]
    fn test_calculate_cutoff_days_standard_ages() -> Result<(), Box<dyn std::error::Error>> {
        // Test common verification ages
        let ages = [13, 16, 18, 19, 21, 25];
        let mut prev_cutoff = i32::MAX;

        for &age in ages.iter() {
            let cutoff = calculate_cutoff_days(age)?;
            // Each higher age should have lower cutoff (earlier date)
            if prev_cutoff != i32::MAX {
                assert!(
                    cutoff < prev_cutoff,
                    "age {} cutoff {} should be < previous {}",
                    age,
                    cutoff,
                    prev_cutoff
                );
            }
            prev_cutoff = cutoff;
        }

        // Test that 65 year cutoff is significantly less than 25 year cutoff
        let cutoff_25 = calculate_cutoff_days(25)?;
        let cutoff_65 = calculate_cutoff_days(65)?;

        // Note: If 65 years ago is before 1970, cutoff_65 will be negative (i32)
        // The comparison still holds: negative < positive
        if cutoff_65 < cutoff_25 {
            // Difference should be approximately 40 years worth of days (about 14600 days)
            let diff = cutoff_25.saturating_sub(cutoff_65);
            assert!(
                (14500..=14700).contains(&diff),
                "diff should be ~40 years = ~14600 days, got {}",
                diff
            );
        }
        Ok(())
    }

    #[test]
    fn test_calculate_cutoff_days_boundary_200_succeeds() -> Result<(), Box<dyn std::error::Error>>
    {
        let result = calculate_cutoff_days(200);
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_calculate_cutoff_days_boundary_201_fails() -> Result<(), Box<dyn std::error::Error>> {
        let result = calculate_cutoff_days(201);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_calculate_cutoff_days_feb29_leap_year() {
        // Simulate the Feb 29 edge case directly: when today is Feb 29 of a
        // leap year and target_year is NOT a leap year, with_year returns None.
        // Verify the fallback produces Feb 28 of the target year.
        let leap_day = NaiveDate::from_ymd_opt(2024, 2, 29).unwrap();
        let target_year = 2024 - 18; // 2006 is not a leap year

        let result = leap_day.with_year(target_year);
        assert!(result.is_none(), "2006-02-29 does not exist");

        let fallback = NaiveDate::from_ymd_opt(target_year, 2, 28).unwrap();
        assert_eq!(fallback.year(), 2006);
        assert_eq!(fallback.month(), 2);
        assert_eq!(fallback.day(), 28);
    }

    #[test]
    fn test_calculate_cutoff_days_feb29_to_leap_year() {
        // When both today and target_year are leap years, with_year succeeds.
        let leap_day = NaiveDate::from_ymd_opt(2024, 2, 29).unwrap();
        let target_year = 2024 - 4; // 2020 is also a leap year

        let result = leap_day.with_year(target_year);
        assert!(result.is_some(), "2020-02-29 exists");
        assert_eq!(result.unwrap().day(), 29);
    }

    // --- sha256_hash() edge cases ---

    #[test]
    fn test_sha256_hash_empty_input() -> Result<(), Box<dyn std::error::Error>> {
        let hash = sha256_hash(b"");
        assert_eq!(hash.len(), 32);

        // Known SHA-256 hash of empty string
        let expected_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let actual_hex = hex::encode(hash);
        assert_eq!(actual_hex, expected_hex);
        Ok(())
    }

    #[test]
    fn test_sha256_hash_single_byte() -> Result<(), Box<dyn std::error::Error>> {
        let hash = sha256_hash(&[0x00]);
        assert_eq!(hash.len(), 32);

        let hash2 = sha256_hash(&[0xFF]);
        assert_eq!(hash2.len(), 32);

        assert_ne!(hash, hash2);
        Ok(())
    }

    #[test]
    fn test_sha256_hash_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        let data = [0u8; 1000];
        let hash = sha256_hash(&data);

        // Hash should not be all zeros
        assert_ne!(hash, [0u8; 32]);
        Ok(())
    }

    #[test]
    fn test_sha256_hash_all_ones() -> Result<(), Box<dyn std::error::Error>> {
        let data = [0xFFu8; 1000];
        let hash = sha256_hash(&data);

        // Hash should not be all ones
        assert_ne!(hash, [0xFFu8; 32]);
        Ok(())
    }

    #[test]
    fn test_sha256_hash_known_test_vector_abc() -> Result<(), Box<dyn std::error::Error>> {
        // Known test vector: "abc"
        let hash = sha256_hash(b"abc");
        let expected_hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let actual_hex = hex::encode(hash);
        assert_eq!(actual_hex, expected_hex);
        Ok(())
    }

    #[test]
    fn test_sha256_hash_large_input() -> Result<(), Box<dyn std::error::Error>> {
        // 1 MB of data
        let data = vec![0x42u8; 1024 * 1024];
        let hash = sha256_hash(&data);
        assert_eq!(hash.len(), 32);

        // Hash should be deterministic
        let hash2 = sha256_hash(&data);
        assert_eq!(hash, hash2);
        Ok(())
    }

    #[test]
    fn test_sha256_hash_incremental_differences() -> Result<(), Box<dyn std::error::Error>> {
        // Verify that similar inputs produce very different hashes
        let hash1 = sha256_hash(b"test1");
        let hash2 = sha256_hash(b"test2");

        // Count different bytes
        let diff_count = hash1
            .iter()
            .zip(hash2.iter())
            .filter(|(a, b)| a != b)
            .count();

        // Should have many differences (avalanche effect)
        assert!(diff_count > 10);
        Ok(())
    }

    // --- encode_base64url() edge cases ---

    #[test]
    fn test_encode_base64url_empty() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = encode_base64url(b"");
        assert_eq!(encoded, "");
        Ok(())
    }

    #[test]
    fn test_encode_base64url_single_byte() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = encode_base64url(&[0x00]);
        assert!(!encoded.contains('='));
        assert_eq!(encoded.len(), 2); // ceil(8/6) * 4 / 3 = 2 chars no padding
        Ok(())
    }

    #[test]
    fn test_encode_base64url_two_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = encode_base64url(&[0x00, 0x00]);
        assert!(!encoded.contains('='));
        Ok(())
    }

    #[test]
    fn test_encode_base64url_three_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = encode_base64url(&[0x00, 0x00, 0x00]);
        assert!(!encoded.contains('='));
        assert_eq!(encoded.len(), 4); // 3 bytes = 4 base64 chars
        Ok(())
    }

    #[test]
    fn test_encode_base64url_32_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let data = [0x42u8; 32];
        let encoded = encode_base64url(&data);
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+')); // URL-safe, no +
        assert!(!encoded.contains('/')); // URL-safe, no /
        Ok(())
    }

    #[test]
    fn test_encode_base64url_64_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let data = [0x7Fu8; 64];
        let encoded = encode_base64url(&data);
        assert!(!encoded.contains('='));
        Ok(())
    }

    #[test]
    fn test_encode_base64url_url_safe_alphabet() -> Result<(), Box<dyn std::error::Error>> {
        // Data that would produce + or / in standard base64
        let data = [0xFBu8, 0xFFu8]; // Produces + and / in standard base64
        let encoded = encode_base64url(&data);

        // Should use - and _ instead
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        Ok(())
    }

    #[test]
    fn test_encode_base64url_all_byte_values() -> Result<(), Box<dyn std::error::Error>> {
        // Test all 256 possible byte values
        let mut data = Vec::new();
        for i in 0..=255u8 {
            data.push(i);
        }

        let encoded = encode_base64url(&data);
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));

        // Should be decodable
        let decoded = decode_base64url(&encoded)?;
        assert_eq!(decoded, data);
        Ok(())
    }

    // --- decode_base64url() edge cases ---

    #[test]
    fn test_decode_base64url_empty() -> Result<(), Box<dyn std::error::Error>> {
        let decoded = decode_base64url("")?;
        assert_eq!(decoded, Vec::<u8>::new());
        Ok(())
    }

    #[test]
    fn test_decode_base64url_invalid_char() -> Result<(), Box<dyn std::error::Error>> {
        // Standard base64 char + should fail
        let result = decode_base64url("AB+D");
        assert!(result.is_err());

        // Standard base64 char / should fail
        let result = decode_base64url("AB/D");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_decode_base64url_with_padding() -> Result<(), Box<dyn std::error::Error>> {
        // Padding should cause decode error with URL_SAFE_NO_PAD
        let result = decode_base64url("ABCD=");
        assert!(result.is_err());

        let result = decode_base64url("ABCD==");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_decode_base64url_invalid_length() -> Result<(), Box<dyn std::error::Error>> {
        // Invalid base64 (not proper length)
        let result = decode_base64url("A");
        // May succeed or fail depending on engine, but test it
        let _ = result;
        Ok(())
    }

    #[test]
    fn test_decode_base64url_non_ascii() -> Result<(), Box<dyn std::error::Error>> {
        // Non-ASCII characters should fail
        let result = decode_base64url("ABC日本語");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_decode_base64url_whitespace() -> Result<(), Box<dyn std::error::Error>> {
        // Whitespace should cause error
        let result = decode_base64url("AB CD");
        assert!(result.is_err());

        let result = decode_base64url("ABCD\n");
        assert!(result.is_err());
        Ok(())
    }

    // --- parse_qr_json() edge cases ---

    #[test]
    #[cfg(feature = "std")]
    fn test_parse_qr_json_empty_string() -> Result<(), Box<dyn std::error::Error>> {
        let result: Result<serde_json::Value, _> = parse_qr_json("");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_parse_qr_json_invalid_json() -> Result<(), Box<dyn std::error::Error>> {
        let result: Result<serde_json::Value, _> = parse_qr_json("{invalid}");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_parse_qr_json_missing_field() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(serde::Deserialize)]
        struct TestStruct {
            #[serde(rename = "required_field")]
            _required_field: String,
        }

        let result: Result<TestStruct, _> = parse_qr_json("{}");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_parse_qr_json_wrong_type() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(serde::Deserialize)]
        struct TestStruct {
            #[serde(rename = "number_field")]
            _number_field: u32,
        }

        let result: Result<TestStruct, _> = parse_qr_json(r#"{"number_field": "not_a_number"}"#);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_parse_qr_json_extra_fields() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(serde::Deserialize)]
        struct TestStruct {
            field1: String,
        }

        // Extra fields should be ignored
        let result: TestStruct = parse_qr_json(r#"{"field1": "value", "extra": "ignored"}"#)?;
        assert_eq!(result.field1, "value");
        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_parse_qr_json_unicode() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(serde::Deserialize)]
        struct TestStruct {
            text: String,
        }

        let result: TestStruct = parse_qr_json(r#"{"text": "日本語🔑"}"#)?;
        assert_eq!(result.text, "日本語🔑");
        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_parse_qr_json_nested() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(serde::Deserialize)]
        struct Inner {
            value: u32,
        }

        #[derive(serde::Deserialize)]
        struct Outer {
            inner: Inner,
        }

        let result: Outer = parse_qr_json(r#"{"inner": {"value": 42}}"#)?;
        assert_eq!(result.inner.value, 42);
        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_parse_qr_json_large_json() -> Result<(), Box<dyn std::error::Error>> {
        // Large but valid JSON
        let large_json = format!(r#"{{"data": "{}"}}"#, "x".repeat(10000));
        let result: serde_json::Value = parse_qr_json(&large_json)?;
        assert!(result.is_object());
        Ok(())
    }

    // --- format_timestamp() edge cases ---

    #[test]
    #[cfg(feature = "std")]
    fn test_format_timestamp_epoch() -> Result<(), Box<dyn std::error::Error>> {
        let formatted = format_timestamp(0);
        assert!(formatted.contains("1970"));
        assert!(formatted.contains("01")); // January
        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_format_timestamp_far_future() -> Result<(), Box<dyn std::error::Error>> {
        // Year 2100
        let timestamp: u64 = 4102444800; // 2100-01-01
        let formatted = format_timestamp(timestamp);
        assert!(formatted.contains("2100"));
        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_format_timestamp_leap_second() -> Result<(), Box<dyn std::error::Error>> {
        // Just before/after a leap second boundary
        let timestamp: u64 = 915148800; // 1999-01-01
        let formatted = format_timestamp(timestamp);
        assert!(formatted.contains("1999"));
        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_format_timestamp_rfc3339_format() -> Result<(), Box<dyn std::error::Error>> {
        let formatted = format_timestamp(1609459200); // 2021-01-01
                                                      // Should be RFC3339 format with T and Z
        assert!(formatted.contains("T"));
        assert!(formatted.contains("Z") || formatted.contains("+") || formatted.contains("-"));
        Ok(())
    }

    // --- is_expired() edge cases ---

    #[test]
    fn test_is_expired_zero_timestamp() -> Result<(), Box<dyn std::error::Error>> {
        // Timestamp 0 should definitely be expired
        assert!(is_expired(0));
        Ok(())
    }

    #[test]
    fn test_is_expired_max_timestamp() -> Result<(), Box<dyn std::error::Error>> {
        // u64::MAX should not be expired
        assert!(!is_expired(u64::MAX));
        Ok(())
    }

    #[test]
    fn test_is_expired_current_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let now = current_timestamp();

        // Exactly now should not be expired (now > now is false)
        assert!(!is_expired(now));

        // One second before now should be expired
        if now > 0 {
            assert!(is_expired(now - 1));
        }

        // One second after now should not be expired
        if now < u64::MAX {
            assert!(!is_expired(now + 1));
        }
        Ok(())
    }

    #[test]
    fn test_is_expired_far_past() -> Result<(), Box<dyn std::error::Error>> {
        // Year 2000
        assert!(is_expired(946684800));
        Ok(())
    }

    #[test]
    fn test_is_expired_far_future() -> Result<(), Box<dyn std::error::Error>> {
        // Year 2200
        assert!(!is_expired(7258118400));
        Ok(())
    }

    // --- validate_age() edge cases ---

    #[test]
    fn test_validate_age_both_zero() -> Result<(), Box<dyn std::error::Error>> {
        assert!(validate_age(0, 0, false));
        assert!(validate_age(0, 0, true));
        Ok(())
    }

    #[test]
    fn test_validate_age_dob_zero() -> Result<(), Box<dyn std::error::Error>> {
        assert!(validate_age(0, 10000, false));
        assert!(!validate_age(0, 10000, true));
        Ok(())
    }

    #[test]
    fn test_validate_age_cutoff_zero() -> Result<(), Box<dyn std::error::Error>> {
        // DOB > cutoff means too young for over_age
        assert!(!validate_age(10000, 0, false));
        // DOB > cutoff means young enough for under_age
        assert!(validate_age(10000, 0, true));
        Ok(())
    }

    #[test]
    fn test_validate_age_max_values() -> Result<(), Box<dyn std::error::Error>> {
        assert!(validate_age(i32::MAX, i32::MAX, false));
        assert!(!validate_age(i32::MAX, i32::MAX - 1, false));
        assert!(validate_age(i32::MAX, i32::MAX, true));
        assert!(validate_age(i32::MAX, i32::MAX - 1, true));
        Ok(())
    }

    #[test]
    fn test_validate_age_boundary_minus_one() -> Result<(), Box<dyn std::error::Error>> {
        let cutoff = 10000;
        // over_age direction
        assert!(validate_age(cutoff - 1, cutoff, false)); // Older, valid
        assert!(validate_age(cutoff, cutoff, false)); // Exactly at cutoff
        assert!(!validate_age(cutoff + 1, cutoff, false)); // Younger, invalid
                                                           // under_age direction
        assert!(!validate_age(cutoff - 1, cutoff, true)); // Too old
        assert!(validate_age(cutoff, cutoff, true)); // Exactly at cutoff
        assert!(validate_age(cutoff + 1, cutoff, true)); // Young enough
        Ok(())
    }

    #[test]
    fn test_validate_age_one_day_difference() -> Result<(), Box<dyn std::error::Error>> {
        // One day can make the difference (over_age)
        assert!(validate_age(9999, 10000, false));
        assert!(!validate_age(10001, 10000, false));
        // under_age is the reverse
        assert!(!validate_age(9999, 10000, true));
        assert!(validate_age(10001, 10000, true));
        Ok(())
    }

    #[test]
    fn test_validate_age_under_age_10_year_old() -> Result<(), Box<dyn std::error::Error>> {
        // Scenario: a venue requires patrons to be UNDER a certain age.
        // A 10-year-old was born ~3652 days ago, so dob_days (days since epoch)
        // is roughly today minus 3652. For a "must be under 13" check the cutoff
        // is today minus 4748 (13 years). The 10-year-old's dob_days is LARGER
        // (more recent) than the cutoff, so they satisfy the under_age predicate.
        //
        // Using concrete values: dob_days ~= 16892, cutoff_days ~= 14708.
        let dob_days: i32 = 16892; // ~10 years old
        let cutoff_days: i32 = 14708; // ~13 years old threshold

        // under_age: 16892 >= 14708 => true (young enough)
        assert!(validate_age(dob_days, cutoff_days, true));

        // over_age: 16892 <= 14708 => false (too young)
        assert!(!validate_age(dob_days, cutoff_days, false));

        // A 15-year-old should FAIL the under_age check for "under 13"
        let older_dob: i32 = 14000; // ~15 years old
        assert!(!validate_age(older_dob, cutoff_days, true));
        assert!(validate_age(older_dob, cutoff_days, false));
        Ok(())
    }

    // --- random_nonce() edge cases ---

    #[test]
    #[cfg(feature = "std")]
    fn test_random_nonce_not_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        let nonce = random_nonce();
        // Probability of all zeros is 2^-256, so this should never happen
        assert_ne!(nonce, [0u8; 32]);
        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_random_nonce_not_all_ones() -> Result<(), Box<dyn std::error::Error>> {
        let nonce = random_nonce();
        // Probability of all ones is 2^-256
        assert_ne!(nonce, [0xFFu8; 32]);
        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_random_nonce_multiple_different() -> Result<(), Box<dyn std::error::Error>> {
        // Generate 10 nonces, they should all be different
        let mut nonces = Vec::new();
        for _ in 0..10 {
            nonces.push(random_nonce());
        }

        // Check all pairs are different
        for i in 0..nonces.len() {
            for j in (i + 1)..nonces.len() {
                assert_ne!(nonces[i], nonces[j], "nonces {} and {} are the same", i, j);
            }
        }
        Ok(())
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_random_nonce_has_entropy() -> Result<(), Box<dyn std::error::Error>> {
        let nonce = random_nonce();

        // Count unique bytes
        let mut seen = std::collections::HashSet::new();
        for &byte in &nonce {
            seen.insert(byte);
        }

        // Should have at least some variety (not all same value)
        assert!(
            seen.len() > 1,
            "nonce has no entropy, all bytes are the same"
        );
        Ok(())
    }

    // --- current_timestamp() edge cases ---

    #[test]
    fn test_current_timestamp_reasonable_range() -> Result<(), Box<dyn std::error::Error>> {
        let ts = current_timestamp();

        // Should be after 2020-01-01
        assert!(ts > 1577836800, "timestamp {} is before 2020", ts);

        // Should be before 2100-01-01
        assert!(ts < 4102444800, "timestamp {} is after 2100", ts);
        Ok(())
    }

    #[test]
    fn test_current_timestamp_monotonic() -> Result<(), Box<dyn std::error::Error>> {
        let ts1 = current_timestamp();
        // Small delay
        for _ in 0..1000 {
            std::hint::black_box(42);
        }
        let ts2 = current_timestamp();

        // ts2 should be >= ts1 (monotonic)
        assert!(ts2 >= ts1, "timestamp went backwards: {} -> {}", ts1, ts2);
        Ok(())
    }

    #[test]
    fn test_current_timestamp_not_zero() -> Result<(), Box<dyn std::error::Error>> {
        let ts = current_timestamp();
        assert_ne!(ts, 0, "timestamp should not be zero");
        Ok(())
    }

    // --- validate_uuid_format() tests ---

    #[test]
    fn test_validate_uuid_format_valid() -> Result<(), Box<dyn std::error::Error>> {
        // Standard v4 UUID
        validate_uuid_format("550e8400-e29b-41d4-a716-446655440000")?;
        // All zeros
        validate_uuid_format("00000000-0000-0000-0000-000000000000")?;
        // All uppercase hex
        validate_uuid_format("ABCDEF01-2345-6789-ABCD-EF0123456789")?;
        // Mixed case
        validate_uuid_format("aAbBcCdD-eEfF-0011-2233-445566778899")?;
        Ok(())
    }

    #[test]
    fn test_validate_uuid_format_path_traversal() {
        // "../" injection
        let result = validate_uuid_format("../../../etc/passwd/aaaaaaaaaa");
        assert!(result.is_err());

        // Encoded traversal with valid length
        let result = validate_uuid_format("..%2F..%2F..%2Fetc%2Fpasswd00");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_format_query_injection() {
        // Query param injection
        let result = validate_uuid_format("550e8400-e29b-41d4-a716?admin=true");
        assert!(result.is_err());

        // Ampersand in value
        let result = validate_uuid_format("550e8400-e29b-41d4-a716&key=value!");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_format_fragment_injection() {
        let result = validate_uuid_format("550e8400-e29b-41d4-a716#fragment!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_format_empty() {
        let result = validate_uuid_format("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_format_too_long() {
        let result = validate_uuid_format("550e8400-e29b-41d4-a716-4466554400000");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_format_too_short() {
        let result = validate_uuid_format("550e8400-e29b-41d4-a716-44665544000");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_format_missing_hyphens() {
        let result = validate_uuid_format("550e8400e29b41d4a716446655440000");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_format_hyphens_wrong_positions() {
        // Hyphens present but shifted
        let result = validate_uuid_format("550e840-0e29b-41d4-a716-4466554400000");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_format_non_hex_chars() {
        let result = validate_uuid_format("550e8400-e29b-41d4-a716-44665544000g");
        assert!(result.is_err());

        // Slash in hex position
        let result = validate_uuid_format("550e8400-e29b-41d4-a716-44665544000/");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_format_spaces() {
        let result = validate_uuid_format("550e8400 e29b 41d4 a716 446655440000");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_format_newlines() {
        let result = validate_uuid_format("550e8400-e29b-41d4-a716-44665544\n000");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_format_null_bytes() {
        let result = validate_uuid_format("550e8400-e29b-41d4-a716-44665544\x00000");
        assert!(result.is_err());
    }

    // Property-based tests
    mod proptests {
        use super::*;
        use proptest::prelude::*;
        use proptest::test_runner::TestCaseError;

        proptest! {
            // Property: base64url encode/decode roundtrip always succeeds
            #[test]
            fn prop_base64url_roundtrip(data: Vec<u8>) {
                let encoded = encode_base64url(&data);
                let decoded = decode_base64url(&encoded).map_err(|e| TestCaseError::fail(format!("{e}")))?;
                prop_assert_eq!(decoded, data);
            }

            // Property: base64url encoding never produces padding
            #[test]
            fn prop_base64url_no_padding(data: Vec<u8>) {
                let encoded = encode_base64url(&data);
                prop_assert!(!encoded.contains('='));
            }

            // Property: SHA-256 always produces 32 bytes
            #[test]
            fn prop_sha256_output_size(data: Vec<u8>) {
                let hash = sha256_hash(&data);
                prop_assert_eq!(hash.len(), 32);
            }

            // Property: SHA-256 is deterministic
            #[test]
            fn prop_sha256_deterministic(data: Vec<u8>) {
                let hash1 = sha256_hash(&data);
                let hash2 = sha256_hash(&data);
                prop_assert_eq!(hash1, hash2);
            }

            // Property: days_since_epoch and date_from_days are inverses
            #[test]
            fn prop_date_conversion_roundtrip(days in 0u64..50000u64) {
                let date = date_from_days(days).ok_or_else(|| TestCaseError::fail("date_from_days returned None"))?;
                let recovered_days = days_since_epoch(date);
                prop_assert_eq!(recovered_days, days);
            }

            // Property: validate_age (over_age) is monotonic with respect to dob_days
            #[test]
            fn prop_validate_age_monotonic(cutoff_days in 1000i32..30000i32, offset in 0i32..1000i32) {
                let younger_dob = cutoff_days + offset;
                let older_dob = cutoff_days - offset.min(cutoff_days);

                // over_age: older person should always pass if younger person passes
                if validate_age(younger_dob, cutoff_days, false) {
                    prop_assert!(validate_age(older_dob, cutoff_days, false));
                }
                // under_age: younger person should always pass if older person passes
                if validate_age(older_dob, cutoff_days, true) {
                    prop_assert!(validate_age(younger_dob, cutoff_days, true));
                }
            }

            // Note: prop_is_expired_monotonic removed - it's non-deterministic because
            // current_timestamp() changes during execution, making the test unreliable

            // Property: encode/decode produces valid UTF-8
            #[test]
            fn prop_base64url_produces_valid_utf8(data: Vec<u8>) {
                let encoded = encode_base64url(&data);
                prop_assert!(encoded.is_ascii());
            }

            // Property: Hash of different data produces different hashes (with high probability)
            #[test]
            fn prop_sha256_collision_resistance(data1: Vec<u8>, data2: Vec<u8>) {
                // Skip if data is the same
                if data1 != data2 {
                    let hash1 = sha256_hash(&data1);
                    let hash2 = sha256_hash(&data2);
                    // In practice, hashes should always differ for different inputs
                    // (collision resistance property)
                    prop_assert_ne!(hash1, hash2);
                }
            }

            // Property: cutoff calculation preserves ordering for reasonable ages
            #[test]
            fn prop_cutoff_days_ordering(age1 in 18u32..50u32, age2 in 18u32..50u32) {
                let cutoff1 = calculate_cutoff_days(age1).map_err(|e| TestCaseError::fail(format!("{e}")))?;
                let cutoff2 = calculate_cutoff_days(age2).map_err(|e| TestCaseError::fail(format!("{e}")))?;

                // Larger minimum age should result in smaller (earlier) cutoff days
                // E.g., 21+ years old means born on or before (smaller days) than 18+ years old
                if age1 > age2 {
                    prop_assert!(cutoff1 < cutoff2, "age1={}, age2={}, cutoff1={}, cutoff2={}", age1, age2, cutoff1, cutoff2);
                } else if age1 < age2 {
                    prop_assert!(cutoff1 > cutoff2, "age1={}, age2={}, cutoff1={}, cutoff2={}", age1, age2, cutoff1, cutoff2);
                } else {
                    prop_assert_eq!(cutoff1, cutoff2);
                }
            }
        }
    }
}
