// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Progress reporting, expiry cleanup, and emergency zeroisation for
//! [`ProviiWallet`].

use super::*;
use crate::progress::{ProgressStage, ProgressTracker};

#[uniffi::export]
impl ProviiWallet {
    /// Create a new progress tracker for reporting proof generation stages.
    pub fn create_progress_tracker(&self) -> Arc<ProgressTracker> {
        ProgressTracker::new()
    }

    /// Report a progress stage with a human-readable message.
    pub fn report_progress(
        &self,
        tracker: Arc<ProgressTracker>,
        stage: ProgressStage,
        message: String,
    ) {
        tracker.report_progress(stage, message);
    }

    /// Remove expired credentials from storage. Returns the count removed.
    pub fn cleanup_expired_credentials(&self) -> u32 {
        match self.storage.list_credentials() {
            Ok(creds) => {
                let mut removed: u32 = 0;
                for cred_info in &creds {
                    if cred_info.is_expired {
                        if let Err(e) = self.storage.delete_credential(&cred_info.id) {
                            log::warn!(
                                "Failed to delete expired credential {}: {}",
                                cred_info.id,
                                e
                            );
                        } else {
                            log::info!("Cleaned up expired credential: {}", cred_info.id);
                            removed = removed.saturating_add(1);
                        }
                    }
                }
                removed
            }
            Err(e) => {
                log::warn!("Could not list credentials for cleanup: {}", e);
                0
            }
        }
    }

    /// Evict expired challenges from the in-memory cache. Returns the count removed.
    pub fn cleanup_expired_challenges(&self) -> u32 {
        let mut cached = safe_lock(&self.cached_challenges);
        let now = std::time::SystemTime::now();

        let expired: Vec<String> = cached
            .iter()
            .filter(|(_, c)| now > c.expires_at)
            .map(|(k, _)| k.clone())
            .collect();

        for key in &expired {
            cached.remove(key);
        }

        u32::try_from(expired.len()).unwrap_or(u32::MAX)
    }

    /// Zeroise all in-memory secret material immediately.
    ///
    /// Intended for emergency termination paths (integrity violation, debugger
    /// detection) where the process is about to be killed. Uses `try_lock`
    /// instead of blocking `lock` to avoid deadlock if the calling thread
    /// already holds one of the mutexes.
    ///
    /// If a mutex cannot be acquired, those secrets will persist for the
    /// remaining microseconds until the process exits. This is an acceptable
    /// trade-off: deadlocking the termination path is worse than briefly
    /// leaving secrets in memory that the OS will reclaim.
    pub fn emergency_zeroize(&self) {
        log::warn!("emergency_zeroize called: clearing all in-memory secrets");

        // Clear cached challenges (each CachedChallenge has ZeroizeOnDrop)
        if let Ok(mut cached) = self.cached_challenges.try_lock() {
            cached.clear();
        } else {
            log::warn!("emergency_zeroize: cached_challenges mutex held, skipping");
        }

        // Zeroize secret fields in config (verifier_api_key)
        if let Ok(mut config) = self.config.try_lock() {
            config.zeroize_secrets();
        } else {
            log::warn!("emergency_zeroize: config mutex held, skipping");
        }

        // Reset state manager (clears active verifications, failure counters)
        self.state_manager.reset();
    }
}
