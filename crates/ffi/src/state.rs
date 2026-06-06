// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! In-memory state tracking for the wallet SDK FFI layer.
//!
//! [`StateManager`] holds the current verification status, active challenge
//! set, failure counters, and biometric authentication state. It is shared
//! across the FFI boundary via `Arc` and protected by internal `Mutex`es so
//! that concurrent calls from platform dispatch queues are safe.
//!
//! All mutexes recover from poisoning rather than propagating the panic,
//! because a crash on one thread must not permanently wedge the wallet.

use anyhow::Result;
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

/// Acquire the mutex, recovering transparently from poisoning.
///
/// If a previous holder panicked, the inner data may be in a partially updated
/// state, but we accept that over a permanent deadlock. The warning is logged
/// so that diagnostics can surface the incident.
fn safe_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::warn!("Recovering from poisoned mutex in StateManager");
            poisoned.into_inner()
        }
    }
}

/// Tracks biometric authentication state for the current session.
///
/// Platform code (Swift/Kotlin) should call into the FFI layer to update
/// availability and enrollment whenever the app foregrounds. The SDK uses
/// `is_recently_authenticated` to avoid redundant biometric prompts within
/// a short window (default 5 seconds, matching MASVS AUTH-2).
#[derive(Debug, Clone)]
#[allow(dead_code)] // Internal state read by StateManager methods; fields set by platform callbacks
pub struct BiometricState {
    /// Whether biometric hardware is available (set by platform).
    pub is_available: bool,
    /// Whether biometrics are enrolled (set by platform).
    pub is_enrolled: bool,
    /// Timestamp of last successful authentication.
    pub last_auth_time: Option<Instant>,
    /// Maximum age of a biometric auth before re-authentication required (seconds).
    pub max_auth_age_seconds: u64,
}

impl Default for BiometricState {
    fn default() -> Self {
        Self {
            is_available: false,
            is_enrolled: false,
            last_auth_time: None,
            max_auth_age_seconds: 5, // 5 seconds, matching MASVS AUTH-2
        }
    }
}

#[allow(dead_code)] // Internal biometric state API; called by StateManager methods
impl BiometricState {
    /// Check if a recent biometric auth is still valid.
    pub fn is_recently_authenticated(&self) -> bool {
        match self.last_auth_time {
            Some(t) => t.elapsed().as_secs() < self.max_auth_age_seconds,
            None => false,
        }
    }

    /// Record a successful authentication.
    pub fn record_authentication(&mut self) {
        self.last_auth_time = Some(Instant::now());
    }
}

/// Progress of a single verification flow, reported to the platform UI.
///
/// The status advances linearly from [`NotStarted`](Self::NotStarted) through
/// [`Verified`](Self::Verified) on the happy path. Any step may transition to
/// [`Failed`](Self::Failed) if an error occurs.
#[derive(uniffi::Enum, Debug, Clone)]
pub enum VerificationStatus {
    /// No verification is in progress.
    NotStarted,
    /// A challenge has been received from the verifier.
    ChallengeReceived,
    /// The zero knowledge proof has been generated locally.
    ProofGenerated,
    /// The proof is being submitted to provii-verifier.
    Submitting,
    /// The verifier accepted the proof.
    Verified,
    /// The verification failed for the given reason.
    Failed { reason: String },
}

/// Thread-safe container for all mutable SDK session state.
///
/// Created once during SDK initialisation and shared via `Arc`. Platform code
/// reads the verification status to drive UI updates; the SDK core writes it
/// as the flow progresses.
pub struct StateManager {
    verification_status: Mutex<VerificationStatus>,
    active_verifications: Mutex<Vec<String>>,
    failed_attempts: Mutex<u32>,
    last_error: Mutex<Option<String>>,
    #[allow(dead_code)] // Biometric state managed via dedicated methods below
    biometric_state: Mutex<BiometricState>,
}

impl StateManager {
    /// Create a new state manager with all fields at their initial values.
    pub fn new() -> Self {
        Self {
            verification_status: Mutex::new(VerificationStatus::NotStarted),
            active_verifications: Mutex::new(Vec::new()),
            failed_attempts: Mutex::new(0),
            last_error: Mutex::new(None),
            biometric_state: Mutex::new(BiometricState::default()),
        }
    }

    /// Begin tracking a new verification for `challenge_id`.
    ///
    /// Resets the failure counter and last-error state, then sets the status to
    /// [`VerificationStatus::ChallengeReceived`]. Duplicate challenge IDs are
    /// silently deduplicated.
    ///
    /// # Locking order
    ///
    /// This method acquires four mutexes sequentially: `verification_status`,
    /// `active_verifications`, `failed_attempts`, and `last_error`. The four
    /// locks are not held simultaneously, so there is a brief observation
    /// window where a concurrent reader could see partially updated state
    /// (e.g. status already set to `ChallengeReceived` while
    /// `failed_attempts` still holds the previous value). This is accepted
    /// for single-user mobile apps where the primary reader is the UI thread
    /// and the SDK core is the sole writer. A composite lock or transactional
    /// wrapper is not warranted given the single-writer usage pattern.
    pub fn start_verification(&self, challenge_id: &str) -> Result<()> {
        log::debug!("Starting verification for challenge: {}", challenge_id);

        *safe_lock(&self.verification_status) = VerificationStatus::ChallengeReceived;

        let mut verifications = safe_lock(&self.active_verifications);
        if !verifications.contains(&challenge_id.to_string()) {
            verifications.push(challenge_id.to_string());
        }

        *safe_lock(&self.failed_attempts) = 0;
        *safe_lock(&self.last_error) = None;

        Ok(())
    }

    /// Advance the verification status for the given challenge.
    ///
    /// When the new status is [`VerificationStatus::Failed`], the failure
    /// counter is incremented and the reason is stored in `last_error`.
    pub fn update_verification_status(
        &self,
        challenge_id: &str,
        status: VerificationStatus,
    ) -> Result<()> {
        log::debug!(
            "Updating verification status for {}: {:?}",
            challenge_id,
            status
        );

        if let VerificationStatus::Failed { ref reason } = status {
            let mut attempts = safe_lock(&self.failed_attempts);
            *attempts = attempts.saturating_add(1);
            *safe_lock(&self.last_error) = Some(reason.clone());

            log::warn!("Verification failed (attempt {}): {}", *attempts, reason);
        }

        *safe_lock(&self.verification_status) = status;
        Ok(())
    }

    /// Mark a verification as finished.
    ///
    /// On success the status moves to [`VerificationStatus::Verified`] and
    /// failure counters are cleared. On failure a synthetic reason is built
    /// from the cumulative attempt count.
    pub fn complete_verification(&self, challenge_id: &str, success: bool) -> Result<()> {
        log::info!(
            "Completing verification for {}: success={}",
            challenge_id,
            success
        );

        let status = if success {
            VerificationStatus::Verified
        } else {
            let attempts = *safe_lock(&self.failed_attempts);
            VerificationStatus::Failed {
                reason: format!(
                    "Verification failed after {} attempts",
                    attempts.saturating_add(1)
                ),
            }
        };

        *safe_lock(&self.verification_status) = status;
        self.remove_verification(challenge_id);

        if success {
            *safe_lock(&self.failed_attempts) = 0;
            *safe_lock(&self.last_error) = None;
        }

        Ok(())
    }

    /// Return a clone of the current verification status.
    pub fn get_verification_status(&self) -> VerificationStatus {
        safe_lock(&self.verification_status).clone()
    }

    /// Cancel an in-flight verification and reset the status to `NotStarted`.
    pub fn cancel_verification(&self, challenge_id: &str) -> Result<()> {
        log::debug!("Cancelling verification for {}", challenge_id);

        self.remove_verification(challenge_id);
        *safe_lock(&self.verification_status) = VerificationStatus::NotStarted;

        Ok(())
    }

    /// Log that a credential was imported. Currently informational only.
    pub fn record_credential_imported(&self, credential_id: &str) {
        log::info!("Credential imported: {}", credential_id);
    }

    /// Log that a credential was deleted. Currently informational only.
    pub fn record_credential_deleted(&self, credential_id: &str) {
        log::info!("Credential deleted: {}", credential_id);
    }

    /// Return the set of challenge IDs that are currently in-flight.
    #[allow(dead_code)] // Public API for platform state queries
    pub fn get_active_verifications(&self) -> Vec<String> {
        safe_lock(&self.active_verifications).clone()
    }

    /// Return the number of consecutive failed verification attempts.
    #[allow(dead_code)] // Public API for platform state queries
    pub fn get_failed_attempts(&self) -> u32 {
        *safe_lock(&self.failed_attempts)
    }

    /// Return the reason string from the most recent failure, if any.
    #[allow(dead_code)] // Public API for platform state queries
    pub fn get_last_error(&self) -> Option<String> {
        safe_lock(&self.last_error).clone()
    }

    /// Return `true` if at least one verification is currently in-flight.
    #[allow(dead_code)] // Public API for platform state queries
    pub fn is_verification_active(&self) -> bool {
        !safe_lock(&self.active_verifications).is_empty()
    }

    // -----------------------------------------------------------------------
    // Biometric state
    // -----------------------------------------------------------------------

    /// Return a snapshot of the current biometric state.
    #[allow(dead_code)] // Public API for platform biometric state queries
    pub fn get_biometric_state(&self) -> BiometricState {
        safe_lock(&self.biometric_state).clone()
    }

    /// Update platform-reported biometric availability and enrollment.
    #[allow(dead_code)] // Public API for platform biometric state updates
    pub fn update_biometric_capabilities(&self, is_available: bool, is_enrolled: bool) {
        let mut state = safe_lock(&self.biometric_state);
        state.is_available = is_available;
        state.is_enrolled = is_enrolled;
    }

    /// Record a successful biometric authentication.
    #[allow(dead_code)] // Public API for platform biometric state updates
    pub fn record_biometric_auth(&self) {
        safe_lock(&self.biometric_state).record_authentication();
    }

    /// Check whether a recent biometric auth is still valid.
    #[allow(dead_code)] // Public API for platform biometric state queries
    pub fn is_biometric_recently_authenticated(&self) -> bool {
        safe_lock(&self.biometric_state).is_recently_authenticated()
    }

    /// Reset all state to initial values.
    ///
    /// Biometric hardware flags (`is_available`, `is_enrolled`) are preserved
    /// because they reflect the physical device, but the authentication
    /// timestamp is cleared.
    #[allow(dead_code)] // Public API for platform state management
    pub fn reset(&self) {
        log::debug!("Resetting state manager");

        *safe_lock(&self.verification_status) = VerificationStatus::NotStarted;
        safe_lock(&self.active_verifications).clear();
        *safe_lock(&self.failed_attempts) = 0;
        *safe_lock(&self.last_error) = None;
        safe_lock(&self.biometric_state).last_auth_time = None;
    }

    /// Remove a challenge ID from the active set.
    fn remove_verification(&self, challenge_id: &str) {
        let mut verifications = safe_lock(&self.active_verifications);
        verifications.retain(|id| id != challenge_id);
    }
}

impl Default for StateManager {
    fn default() -> Self {
        Self::new()
    }
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

    #[test]
    fn test_verification_flow() {
        let manager = StateManager::new();

        // Start verification
        assert!(manager.start_verification("test-123").is_ok());
        assert!(matches!(
            manager.get_verification_status(),
            VerificationStatus::ChallengeReceived
        ));

        // Update to proof generated
        assert!(manager
            .update_verification_status("test-123", VerificationStatus::ProofGenerated)
            .is_ok());

        // Complete successfully
        assert!(manager.complete_verification("test-123", true).is_ok());
        assert!(matches!(
            manager.get_verification_status(),
            VerificationStatus::Verified
        ));
    }

    #[test]
    fn test_failed_attempts_tracking() -> Result<(), Box<dyn std::error::Error>> {
        let manager = StateManager::new();

        manager.start_verification("test-456")?;

        // Simulate failures
        for i in 1..=3 {
            manager.update_verification_status(
                "test-456",
                VerificationStatus::Failed {
                    reason: format!("Attempt {}", i),
                },
            )?;
            assert_eq!(manager.get_failed_attempts(), i);
        }

        // Start new verification should reset
        manager.start_verification("test-789")?;
        assert_eq!(manager.get_failed_attempts(), 0);
        Ok(())
    }

    #[test]
    fn test_concurrent_verifications() -> Result<(), Box<dyn std::error::Error>> {
        let manager = StateManager::new();

        manager.start_verification("verify-1")?;
        manager.start_verification("verify-2")?;

        let active = manager.get_active_verifications();
        assert_eq!(active.len(), 2);
        assert!(active.contains(&"verify-1".to_string()));
        assert!(active.contains(&"verify-2".to_string()));

        manager.cancel_verification("verify-1")?;
        let active = manager.get_active_verifications();
        assert_eq!(active.len(), 1);
        assert!(!active.contains(&"verify-1".to_string()));
        Ok(())
    }

    // ============================================================================
    // COMPREHENSIVE STATE MANAGER TESTS
    // ============================================================================

    #[test]
    fn test_state_manager_new() {
        let manager = StateManager::new();

        assert!(matches!(
            manager.get_verification_status(),
            VerificationStatus::NotStarted
        ));
        assert_eq!(manager.get_active_verifications().len(), 0);
        assert_eq!(manager.get_failed_attempts(), 0);
        assert!(manager.get_last_error().is_none());
        assert!(!manager.is_verification_active());
    }

    #[test]
    fn test_state_manager_default() {
        let manager = StateManager::default();

        assert!(matches!(
            manager.get_verification_status(),
            VerificationStatus::NotStarted
        ));
        assert!(!manager.is_verification_active());
    }

    #[test]
    fn test_start_verification_empty_challenge_id() {
        let manager = StateManager::new();

        assert!(manager.start_verification("").is_ok());
        assert!(matches!(
            manager.get_verification_status(),
            VerificationStatus::ChallengeReceived
        ));
        assert_eq!(manager.get_active_verifications().len(), 1);
    }

    #[test]
    fn test_start_verification_unicode_challenge_id() {
        let manager = StateManager::new();

        let challenge_id = "test-日本語-123";
        assert!(manager.start_verification(challenge_id).is_ok());

        let active = manager.get_active_verifications();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0], challenge_id);
    }

    #[test]
    fn test_start_verification_very_long_challenge_id() {
        let manager = StateManager::new();

        let long_id = "x".repeat(10000);
        assert!(manager.start_verification(&long_id).is_ok());

        let active = manager.get_active_verifications();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].len(), 10000);
    }

    #[test]
    fn test_start_verification_duplicate_challenge_id() -> Result<(), Box<dyn std::error::Error>> {
        let manager = StateManager::new();

        let challenge_id = "test-duplicate";
        manager.start_verification(challenge_id)?;
        manager.start_verification(challenge_id)?;

        // Should not create duplicate entries
        let active = manager.get_active_verifications();
        assert_eq!(active.len(), 1);
        Ok(())
    }

    #[test]
    fn test_start_verification_resets_failed_attempts() -> Result<(), Box<dyn std::error::Error>> {
        let manager = StateManager::new();

        manager.start_verification("test-1")?;
        manager.update_verification_status(
            "test-1",
            VerificationStatus::Failed {
                reason: "Error".to_string(),
            },
        )?;

        assert_eq!(manager.get_failed_attempts(), 1);
        assert!(manager.get_last_error().is_some());

        // Start new verification should reset
        manager.start_verification("test-2")?;
        assert_eq!(manager.get_failed_attempts(), 0);
        assert!(manager.get_last_error().is_none());
        Ok(())
    }

    #[test]
    fn test_update_verification_status_all_variants() -> Result<(), Box<dyn std::error::Error>> {
        let manager = StateManager::new();
        let challenge_id = "test-status";

        manager.start_verification(challenge_id)?;

        // Test ChallengeReceived
        manager.update_verification_status(challenge_id, VerificationStatus::ChallengeReceived)?;
        assert!(matches!(
            manager.get_verification_status(),
            VerificationStatus::ChallengeReceived
        ));

        // Test ProofGenerated
        manager.update_verification_status(challenge_id, VerificationStatus::ProofGenerated)?;
        assert!(matches!(
            manager.get_verification_status(),
            VerificationStatus::ProofGenerated
        ));

        // Test Submitting
        manager.update_verification_status(challenge_id, VerificationStatus::Submitting)?;
        assert!(matches!(
            manager.get_verification_status(),
            VerificationStatus::Submitting
        ));

        // Test Verified
        manager.update_verification_status(challenge_id, VerificationStatus::Verified)?;
        assert!(matches!(
            manager.get_verification_status(),
            VerificationStatus::Verified
        ));
        Ok(())
    }

    #[test]
    fn test_update_verification_status_failed_increments_attempts(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let manager = StateManager::new();

        manager.start_verification("test")?;

        for i in 1..=5 {
            manager.update_verification_status(
                "test",
                VerificationStatus::Failed {
                    reason: format!("Error {}", i),
                },
            )?;

            assert_eq!(manager.get_failed_attempts(), i);
            assert_eq!(manager.get_last_error(), Some(format!("Error {}", i)));
        }
        Ok(())
    }

    #[test]
    fn test_update_verification_status_failed_empty_reason(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let manager = StateManager::new();

        manager.start_verification("test")?;
        manager.update_verification_status(
            "test",
            VerificationStatus::Failed {
                reason: "".to_string(),
            },
        )?;

        assert_eq!(manager.get_failed_attempts(), 1);
        assert_eq!(manager.get_last_error(), Some("".to_string()));
        Ok(())
    }

    #[test]
    fn test_complete_verification_success() -> Result<(), Box<dyn std::error::Error>> {
        let manager = StateManager::new();

        manager.start_verification("test-success")?;
        manager.complete_verification("test-success", true)?;

        assert!(matches!(
            manager.get_verification_status(),
            VerificationStatus::Verified
        ));
        assert_eq!(manager.get_active_verifications().len(), 0);
        assert_eq!(manager.get_failed_attempts(), 0);
        assert!(manager.get_last_error().is_none());
        Ok(())
    }

    #[test]
    fn test_complete_verification_failure() -> Result<(), Box<dyn std::error::Error>> {
        let manager = StateManager::new();

        manager.start_verification("test-fail")?;
        manager.complete_verification("test-fail", false)?;

        match manager.get_verification_status() {
            VerificationStatus::Failed { reason } => {
                assert!(reason.contains("Verification failed"));
                assert!(reason.contains("1 attempts"));
            }
            _ => panic!("Expected Failed status"),
        }
        assert_eq!(manager.get_active_verifications().len(), 0);
        Ok(())
    }

    #[test]
    fn test_complete_verification_with_previous_failures() -> Result<(), Box<dyn std::error::Error>>
    {
        let manager = StateManager::new();

        manager.start_verification("test")?;

        // Simulate 3 failures
        for _ in 0..3 {
            manager.update_verification_status(
                "test",
                VerificationStatus::Failed {
                    reason: "Error".to_string(),
                },
            )?;
        }

        assert_eq!(manager.get_failed_attempts(), 3);

        // Complete with failure
        manager.complete_verification("test", false)?;

        match manager.get_verification_status() {
            VerificationStatus::Failed { reason } => {
                assert!(reason.contains("4 attempts"));
            }
            _ => panic!("Expected Failed status"),
        }
        Ok(())
    }

    #[test]
    fn test_cancel_verification() -> Result<(), Box<dyn std::error::Error>> {
        let manager = StateManager::new();

        manager.start_verification("test-cancel")?;
        manager.update_verification_status("test-cancel", VerificationStatus::ProofGenerated)?;

        manager.cancel_verification("test-cancel")?;

        assert!(matches!(
            manager.get_verification_status(),
            VerificationStatus::NotStarted
        ));
        assert_eq!(manager.get_active_verifications().len(), 0);
        Ok(())
    }

    #[test]
    fn test_cancel_nonexistent_verification() {
        let manager = StateManager::new();

        // Should not panic or error
        assert!(manager.cancel_verification("nonexistent").is_ok());
    }

    #[test]
    fn test_record_credential_imported() {
        let manager = StateManager::new();

        // Should not panic
        manager.record_credential_imported("cred-123");
        manager.record_credential_imported("");
        manager.record_credential_imported("日本語");
    }

    #[test]
    fn test_record_credential_deleted() {
        let manager = StateManager::new();

        // Should not panic
        manager.record_credential_deleted("cred-456");
        manager.record_credential_deleted("");
        manager.record_credential_deleted("x".repeat(1000).as_str());
    }

    #[test]
    fn test_get_active_verifications_multiple() -> Result<(), Box<dyn std::error::Error>> {
        let manager = StateManager::new();

        for i in 0..10 {
            manager.start_verification(&format!("test-{}", i))?;
        }

        let active = manager.get_active_verifications();
        assert_eq!(active.len(), 10);
        Ok(())
    }

    #[test]
    fn test_get_active_verifications_empty() {
        let manager = StateManager::new();

        let active = manager.get_active_verifications();
        assert!(active.is_empty());
    }

    #[test]
    fn test_is_verification_active() -> Result<(), Box<dyn std::error::Error>> {
        let manager = StateManager::new();

        assert!(!manager.is_verification_active());

        manager.start_verification("test")?;
        assert!(manager.is_verification_active());

        manager.cancel_verification("test")?;
        assert!(!manager.is_verification_active());
        Ok(())
    }

    #[test]
    fn test_reset() -> Result<(), Box<dyn std::error::Error>> {
        let manager = StateManager::new();

        // Set up some state
        manager.start_verification("test-1")?;
        manager.start_verification("test-2")?;
        manager.update_verification_status(
            "test-1",
            VerificationStatus::Failed {
                reason: "Error".to_string(),
            },
        )?;

        assert!(manager.is_verification_active());
        assert_eq!(manager.get_failed_attempts(), 1);
        assert!(manager.get_last_error().is_some());

        // Reset
        manager.reset();

        // Verify everything is cleared
        assert!(matches!(
            manager.get_verification_status(),
            VerificationStatus::NotStarted
        ));
        assert_eq!(manager.get_active_verifications().len(), 0);
        assert_eq!(manager.get_failed_attempts(), 0);
        assert!(manager.get_last_error().is_none());
        assert!(!manager.is_verification_active());
        Ok(())
    }

    #[test]
    fn test_concurrent_access() -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::Arc;
        use std::thread;

        let manager = Arc::new(StateManager::new());

        let mut handles = vec![];

        for i in 0..10 {
            let manager_clone = Arc::clone(&manager);
            let handle = thread::spawn(move || -> anyhow::Result<()> {
                let challenge_id = format!("test-{}", i);
                manager_clone.start_verification(&challenge_id)?;
                manager_clone.update_verification_status(
                    &challenge_id,
                    VerificationStatus::ProofGenerated,
                )?;
                Ok(())
            });
            handles.push(handle);
        }

        for handle in handles {
            handle
                .join()
                .map_err(|_| "thread panicked")?
                .map_err(|e| e.to_string())?;
        }

        // Should have 10 active verifications
        assert_eq!(manager.get_active_verifications().len(), 10);
        Ok(())
    }

    #[test]
    fn test_status_enum_clone() {
        let status1 = VerificationStatus::NotStarted;
        let status2 = status1.clone();

        assert!(matches!(status1, VerificationStatus::NotStarted));
        assert!(matches!(status2, VerificationStatus::NotStarted));
    }

    #[test]
    fn test_status_enum_failed_clone() {
        let status1 = VerificationStatus::Failed {
            reason: "Test error".to_string(),
        };
        let status2 = status1.clone();

        match status2 {
            VerificationStatus::Failed { reason } => {
                assert_eq!(reason, "Test error");
            }
            _ => panic!("Expected Failed status"),
        }
    }

    #[test]
    fn test_verification_flow_complete_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
        let manager = StateManager::new();
        let challenge_id = "lifecycle-test";

        // Start
        manager.start_verification(challenge_id)?;
        assert!(matches!(
            manager.get_verification_status(),
            VerificationStatus::ChallengeReceived
        ));

        // Generate proof
        manager.update_verification_status(challenge_id, VerificationStatus::ProofGenerated)?;

        // Start submitting
        manager.update_verification_status(challenge_id, VerificationStatus::Submitting)?;

        // Complete successfully
        manager.complete_verification(challenge_id, true)?;
        assert!(matches!(
            manager.get_verification_status(),
            VerificationStatus::Verified
        ));
        assert!(!manager.is_verification_active());
        Ok(())
    }

    #[test]
    fn test_multiple_verifications_different_states() -> Result<(), Box<dyn std::error::Error>> {
        let manager = StateManager::new();

        manager.start_verification("verify-1")?;
        manager.start_verification("verify-2")?;
        manager.start_verification("verify-3")?;

        // Complete one
        manager.complete_verification("verify-1", true)?;

        // Cancel another
        manager.cancel_verification("verify-2")?;

        // verify-3 should still be active
        let active = manager.get_active_verifications();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0], "verify-3");
        Ok(())
    }
}
