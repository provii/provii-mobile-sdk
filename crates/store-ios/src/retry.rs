// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Retry policy for transient Keychain failures.

use super::*;
use log::debug;

impl IOSKeychainStorage {
    pub(crate) fn with_retry<T, F>(&self, max_retries: u32, mut op: F) -> Result<T>
    where
        F: FnMut() -> Result<T>,
    {
        let mut last_error = None;

        for attempt in 0..=max_retries {
            match op() {
                Ok(v) => return Ok(v),
                Err(e) => {
                    // SECURITY: Never retry authentication failures or user
                    // cancellations. Retrying these would circumvent the
                    // system's biometric lockout counter and re-prompt the
                    // user unexpectedly.
                    if Self::is_non_retryable_error(&e) {
                        return Err(e);
                    }

                    last_error = Some(e);
                    if attempt < max_retries {
                        debug!(
                            "Keychain operation failed (attempt {}/{}), retrying...",
                            attempt + 1,
                            max_retries + 1
                        );
                        thread::sleep(Duration::from_millis(100 * (attempt as u64 + 1)));
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| WalletError::Storage {
            msg: "retry loop completed with no error recorded".to_string(),
        }))
    }

    /// Returns `true` for errors that must never be retried: authentication
    /// failures and user cancellations. These are definitive outcomes, not
    /// transient faults, and retrying them would bypass iOS biometric lockout
    /// counting.
    fn is_non_retryable_error(err: &WalletError) -> bool {
        match err {
            WalletError::BiometricFailed { .. } => true,
            WalletError::Storage { msg } => {
                // errSecAuthFailed (-25293) or errSecUserCanceled (-128)
                msg.contains("Authentication failed")
                    || msg.contains("User cancelled")
                    || msg.contains(&format!("OSStatus: {}", errSecAuthFailed))
                    || msg.contains(&format!("OSStatus: {}", ERRSEC_USER_CANCELED))
            }
            _ => false,
        }
    }
}
