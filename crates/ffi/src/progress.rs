// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Progress tracking for long-running issuance and verification operations.
//!
//! Mobile platforms use [`ProgressTracker`] to drive UI progress indicators
//! during proof generation, network submission, and issuance workflows. The
//! tracker maintains an ordered history of stage transitions and broadcasts
//! each update to every registered [`ProgressListener`].
//!
//! # Thread safety
//!
//! All internal state is behind `Arc<Mutex<_>>`, so the tracker is `Send +
//! Sync` and can be shared across the Tokio runtime and UniFFI callback
//! threads. Poisoned mutexes are recovered from rather than propagated,
//! because a panic in one listener must not tear down the entire progress
//! pipeline.
//!
//! # Listener panic isolation
//!
//! Listener callbacks are invoked inside `catch_unwind` so that a panicking
//! implementation cannot abort the operation being tracked.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

/// Recover from a poisoned mutex rather than panicking.
///
/// Poisoning indicates that a thread panicked while holding the lock. Since
/// the progress tracker is advisory (never guards safety-critical state),
/// recovering and logging a warning is the correct trade-off.
fn safe_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::warn!("Recovering from poisoned mutex in ProgressTracker");
            poisoned.into_inner()
        }
    }
}

/// Discrete stages of an issuance or verification workflow.
///
/// Each stage maps to a deterministic progress percentage via
/// `ProgressTracker::calculate_progress`.
#[derive(uniffi::Enum, Debug, Clone, Copy)]
pub enum ProgressStage {
    /// The operation has been initiated but no protocol messages have been
    /// sent yet.
    Started,

    // -- Issuance stages --
    /// The issuance request has been created and sent to provii-issuer.
    IssuanceRequestCreated,

    /// Waiting for an officer to verify the user's identity document.
    IssuanceWaitingForOfficer,

    /// The officer has verified the document; commitment is being finalised.
    IssuanceDocumentVerified,

    /// Issuance completed successfully. The credential is now stored.
    IssuanceCompleted,

    // -- Verification stages --
    /// A verification challenge has been received and parsed.
    VerificationChallengeReceived,

    /// The zero knowledge proof has been generated.
    VerificationProofGenerated,

    /// The proof is being submitted to provii-verifier.
    VerificationSubmitting,

    /// Verification completed successfully.
    VerificationCompleted,

    /// The operation failed. See the accompanying message for details.
    Failed,

    /// The operation was cancelled by the user.
    Cancelled,
}

/// Snapshot of a progress update, delivered to listeners.
#[derive(uniffi::Record, Debug, Clone)]
pub struct ProgressUpdate {
    /// The stage that was just entered.
    pub stage: ProgressStage,

    /// Human-readable description of what happened.
    pub message: String,

    /// Percentage complete (0..=100), if calculable for this stage.
    pub progress_percent: Option<u8>,

    /// Estimated seconds remaining, if calculable for this stage.
    pub estimated_time_remaining_secs: Option<u32>,

    /// Milliseconds since the Unix epoch when this update was created.
    pub timestamp: u64,
}

/// Callback interface for receiving progress updates on the mobile side.
///
/// Implementations must be `Send + Sync` because the tracker may invoke
/// `on_progress` from any thread.
#[uniffi::export(callback_interface)]
pub trait ProgressListener: Send + Sync {
    /// Called each time the tracked operation transitions to a new stage.
    fn on_progress(&self, update: ProgressUpdate);
}

/// Tracks the progress of a single issuance or verification operation.
///
/// Create via [`ProgressTracker::new`], register one or more listeners, then
/// call [`report_progress`](ProgressTracker::report_progress) as the
/// operation advances. When the operation finishes, call
/// [`mark_completed`](ProgressTracker::mark_completed) or
/// [`mark_failed`](ProgressTracker::mark_failed).
#[derive(uniffi::Object)]
pub struct ProgressTracker {
    /// Registered listeners, notified on each stage transition.
    listeners: Arc<Mutex<Vec<Box<dyn ProgressListener>>>>,

    /// Most recent stage.
    current_stage: Arc<Mutex<ProgressStage>>,

    /// Ordered history of (stage, timestamp_ms) pairs.
    /// SEC-09: VecDeque for O(1) front eviction when history exceeds 100 entries.
    stage_history: Arc<Mutex<VecDeque<(ProgressStage, u64)>>>,

    /// Start timestamp in milliseconds, or `None` if timing has stopped.
    start_time: Arc<Mutex<Option<u64>>>,

    /// Timestamp of the most recent update.
    last_update_time: Arc<Mutex<u64>>,
}

#[uniffi::export]
impl ProgressTracker {
    /// Create a new tracker with the clock started.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        let now = current_timestamp();
        Arc::new(Self {
            listeners: Arc::new(Mutex::new(Vec::new())),
            current_stage: Arc::new(Mutex::new(ProgressStage::Started)),
            stage_history: Arc::new(Mutex::new(VecDeque::new())),
            start_time: Arc::new(Mutex::new(Some(now))),
            last_update_time: Arc::new(Mutex::new(now)),
        })
    }

    /// Register a listener to receive subsequent progress updates.
    pub fn add_listener(&self, listener: Box<dyn ProgressListener>) {
        let mut listeners = safe_lock(&self.listeners);
        listeners.push(listener);
        log::debug!(
            "Progress listener added, total listeners: {}",
            listeners.len()
        );
    }

    /// Remove all registered listeners.
    pub fn remove_all_listeners(&self) {
        let mut listeners = safe_lock(&self.listeners);
        let count = listeners.len();
        listeners.clear();
        log::debug!("Removed {} progress listeners", count);
    }

    /// Record a stage transition, update internal state, and notify listeners.
    pub fn report_progress(&self, stage: ProgressStage, message: String) {
        let now = current_timestamp();

        *safe_lock(&self.current_stage) = stage;
        *safe_lock(&self.last_update_time) = now;

        {
            let mut history = safe_lock(&self.stage_history);
            history.push_back((stage, now));

            // SEC-09: O(1) front eviction instead of O(n) Vec::remove(0).
            if history.len() > 100 {
                history.pop_front();
            }
        }

        let elapsed_secs = {
            let start = safe_lock(&self.start_time);
            if let Some(start_time) = *start {
                u32::try_from(now.saturating_sub(start_time) / 1000).unwrap_or(u32::MAX)
            } else {
                0
            }
        };

        let update = ProgressUpdate {
            stage,
            message: message.clone(),
            progress_percent: self.calculate_progress(stage),
            estimated_time_remaining_secs: self.estimate_time(stage, elapsed_secs),
            timestamp: now,
        };

        log::debug!("Progress update: {:?} - {}", stage, message);

        let listeners = safe_lock(&self.listeners);
        for listener in listeners.iter() {
            let update_clone = update.clone();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                listener.on_progress(update_clone);
            }));

            if result.is_err() {
                log::error!("Progress listener panicked during callback");
            }
        }
    }

    /// Return the most recently reported stage.
    pub fn get_current_stage(&self) -> ProgressStage {
        *safe_lock(&self.current_stage)
    }

    /// Wall-clock seconds elapsed since the tracker was created or last reset.
    pub fn get_elapsed_time_secs(&self) -> u32 {
        let start = safe_lock(&self.start_time);
        if let Some(start_time) = *start {
            let now = current_timestamp();
            u32::try_from(now.saturating_sub(start_time) / 1000).unwrap_or(u32::MAX)
        } else {
            0
        }
    }

    /// Number of listeners currently registered.
    pub fn get_listener_count(&self) -> u32 {
        u32::try_from(safe_lock(&self.listeners).len()).unwrap_or(u32::MAX)
    }

    /// Reset the tracker to the `Started` stage and restart the clock.
    ///
    /// Listeners are preserved; only stage, history, and timing are cleared.
    pub fn reset(&self) {
        let now = current_timestamp();
        *safe_lock(&self.current_stage) = ProgressStage::Started;
        *safe_lock(&self.start_time) = Some(now);
        *safe_lock(&self.last_update_time) = now;
        safe_lock(&self.stage_history).clear();
        log::debug!("Progress tracker reset");
    }

    /// Transition to the `Failed` stage and stop the clock.
    pub fn mark_failed(&self, reason: String) {
        self.report_progress(ProgressStage::Failed, reason);
        *safe_lock(&self.start_time) = None;
    }

    /// Transition to the appropriate completion stage and stop the clock.
    ///
    /// The tracker infers the correct `*Completed` variant from the current
    /// stage. If the current stage is not a recognised pre-completion stage,
    /// a generic "Operation completed" update is emitted at the current stage.
    pub fn mark_completed(&self) {
        let stage = *safe_lock(&self.current_stage);
        match stage {
            ProgressStage::IssuanceWaitingForOfficer | ProgressStage::IssuanceDocumentVerified => {
                self.report_progress(
                    ProgressStage::IssuanceCompleted,
                    "Issuance completed successfully".to_string(),
                );
            }
            ProgressStage::VerificationProofGenerated | ProgressStage::VerificationSubmitting => {
                self.report_progress(
                    ProgressStage::VerificationCompleted,
                    "Verification completed successfully".to_string(),
                );
            }
            _ => {
                self.report_progress(stage, "Operation completed".to_string());
            }
        }
        *safe_lock(&self.start_time) = None;
    }

    /// Map a stage to a deterministic progress percentage.
    fn calculate_progress(&self, stage: ProgressStage) -> Option<u8> {
        match stage {
            ProgressStage::Started => Some(0),
            ProgressStage::IssuanceRequestCreated => Some(25),
            ProgressStage::IssuanceWaitingForOfficer => Some(50),
            ProgressStage::IssuanceDocumentVerified => Some(75),
            ProgressStage::IssuanceCompleted => Some(100),
            ProgressStage::VerificationChallengeReceived => Some(33),
            ProgressStage::VerificationProofGenerated => Some(66),
            ProgressStage::VerificationSubmitting => Some(90),
            ProgressStage::VerificationCompleted => Some(100),
            ProgressStage::Failed | ProgressStage::Cancelled => Some(100),
        }
    }

    /// Rough time-remaining estimate based on typical mobile timings.
    fn estimate_time(&self, stage: ProgressStage, elapsed_secs: u32) -> Option<u32> {
        match stage {
            ProgressStage::IssuanceWaitingForOfficer => None, // user action required
            ProgressStage::VerificationProofGenerated => {
                if elapsed_secs < 3 {
                    Some(5)
                } else {
                    Some(2)
                }
            }
            ProgressStage::VerificationSubmitting => Some(2),
            ProgressStage::IssuanceCompleted | ProgressStage::VerificationCompleted => Some(0),
            _ => None,
        }
    }
}

impl Default for ProgressTracker {
    fn default() -> Self {
        Self {
            listeners: Arc::new(Mutex::new(Vec::new())),
            current_stage: Arc::new(Mutex::new(ProgressStage::Started)),
            stage_history: Arc::new(Mutex::new(VecDeque::new())),
            start_time: Arc::new(Mutex::new(Some(current_timestamp()))),
            last_update_time: Arc::new(Mutex::new(current_timestamp())),
        }
    }
}

/// Current wall-clock time in milliseconds since the Unix epoch.
///
/// Uses `as_millis()` which returns `u128`, then truncates to `u64`. This is
/// safe because `u64::MAX` millis is ~584 million years from the epoch.
fn current_timestamp() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestListener {
        call_count: Arc<AtomicUsize>,
    }

    impl ProgressListener for TestListener {
        fn on_progress(&self, _update: ProgressUpdate) {
            self.call_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn test_progress_tracking() {
        let tracker = ProgressTracker::new();

        let call_count = Arc::new(AtomicUsize::new(0));
        let listener = Box::new(TestListener {
            call_count: call_count.clone(),
        });
        tracker.add_listener(listener);

        tracker.report_progress(
            ProgressStage::VerificationChallengeReceived,
            "Challenge received".to_string(),
        );
        tracker.report_progress(
            ProgressStage::VerificationProofGenerated,
            "Proof generated".to_string(),
        );
        tracker.report_progress(ProgressStage::VerificationCompleted, "Done".to_string());

        assert_eq!(call_count.load(Ordering::Relaxed), 3);

        assert!(matches!(
            tracker.get_current_stage(),
            ProgressStage::VerificationCompleted
        ));
    }

    #[test]
    fn test_elapsed_time() {
        let tracker = ProgressTracker::new();

        let elapsed = tracker.get_elapsed_time_secs();
        assert!(elapsed < 2);

        tracker.reset();
        let elapsed_after = tracker.get_elapsed_time_secs();
        assert!(elapsed_after < 2);
    }

    #[test]
    fn test_listener_management() {
        let tracker = ProgressTracker::new();

        assert_eq!(tracker.get_listener_count(), 0);

        for _ in 0..3 {
            let listener = Box::new(TestListener {
                call_count: Arc::new(AtomicUsize::new(0)),
            });
            tracker.add_listener(listener);
        }

        assert_eq!(tracker.get_listener_count(), 3);

        tracker.remove_all_listeners();
        assert_eq!(tracker.get_listener_count(), 0);
    }

    #[test]
    fn test_progress_tracker_new() {
        let tracker = ProgressTracker::new();

        assert!(matches!(
            tracker.get_current_stage(),
            ProgressStage::Started
        ));
        assert_eq!(tracker.get_listener_count(), 0);
        assert!(tracker.get_elapsed_time_secs() < 2);
    }

    #[test]
    fn test_progress_tracker_default() {
        let tracker = ProgressTracker::default();

        assert!(matches!(
            tracker.get_current_stage(),
            ProgressStage::Started
        ));
    }

    #[test]
    fn test_all_progress_stages() {
        let tracker = ProgressTracker::new();

        let stages = [
            ProgressStage::Started,
            ProgressStage::IssuanceRequestCreated,
            ProgressStage::IssuanceWaitingForOfficer,
            ProgressStage::IssuanceDocumentVerified,
            ProgressStage::IssuanceCompleted,
            ProgressStage::VerificationChallengeReceived,
            ProgressStage::VerificationProofGenerated,
            ProgressStage::VerificationSubmitting,
            ProgressStage::VerificationCompleted,
            ProgressStage::Failed,
            ProgressStage::Cancelled,
        ];

        for stage in &stages {
            tracker.report_progress(*stage, format!("Testing {:?}", stage));
            assert!(matches!(tracker.get_current_stage(), s if s as u8 == *stage as u8));
        }
    }

    #[test]
    fn test_calculate_progress_percentages() {
        let tracker = ProgressTracker::new();

        let test_cases = [
            (ProgressStage::Started, Some(0)),
            (ProgressStage::IssuanceRequestCreated, Some(25)),
            (ProgressStage::IssuanceWaitingForOfficer, Some(50)),
            (ProgressStage::IssuanceDocumentVerified, Some(75)),
            (ProgressStage::IssuanceCompleted, Some(100)),
            (ProgressStage::VerificationChallengeReceived, Some(33)),
            (ProgressStage::VerificationProofGenerated, Some(66)),
            (ProgressStage::VerificationSubmitting, Some(90)),
            (ProgressStage::VerificationCompleted, Some(100)),
            (ProgressStage::Failed, Some(100)),
            (ProgressStage::Cancelled, Some(100)),
        ];

        for (stage, expected_percent) in &test_cases {
            let percent = tracker.calculate_progress(*stage);
            assert_eq!(
                percent, *expected_percent,
                "Stage {:?} should have progress {:?}",
                stage, expected_percent
            );
        }
    }

    #[test]
    fn test_mark_failed() {
        let tracker = ProgressTracker::new();
        let call_count = Arc::new(AtomicUsize::new(0));
        let listener = Box::new(TestListener {
            call_count: call_count.clone(),
        });
        tracker.add_listener(listener);

        tracker.mark_failed("Test failure".to_string());

        assert!(matches!(tracker.get_current_stage(), ProgressStage::Failed));
        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_mark_completed_from_issuance() {
        let tracker = ProgressTracker::new();

        tracker.report_progress(
            ProgressStage::IssuanceWaitingForOfficer,
            "Waiting".to_string(),
        );
        tracker.mark_completed();

        assert!(matches!(
            tracker.get_current_stage(),
            ProgressStage::IssuanceCompleted
        ));
    }

    #[test]
    fn test_mark_completed_from_verification() {
        let tracker = ProgressTracker::new();

        tracker.report_progress(
            ProgressStage::VerificationProofGenerated,
            "Proof ready".to_string(),
        );
        tracker.mark_completed();

        assert!(matches!(
            tracker.get_current_stage(),
            ProgressStage::VerificationCompleted
        ));
    }

    #[test]
    fn test_mark_completed_from_arbitrary_stage() {
        let tracker = ProgressTracker::new();

        tracker.report_progress(ProgressStage::Started, "Starting".to_string());
        tracker.mark_completed();

        assert!(matches!(
            tracker.get_current_stage(),
            ProgressStage::Started
        ));
    }

    #[test]
    fn test_reset() {
        let tracker = ProgressTracker::new();

        tracker.report_progress(
            ProgressStage::VerificationProofGenerated,
            "Test".to_string(),
        );

        tracker.reset();

        assert!(matches!(
            tracker.get_current_stage(),
            ProgressStage::Started
        ));
        assert!(tracker.get_elapsed_time_secs() < 2);
    }

    #[test]
    fn test_multiple_listeners() {
        let tracker = ProgressTracker::new();

        let count1 = Arc::new(AtomicUsize::new(0));
        let count2 = Arc::new(AtomicUsize::new(0));
        let count3 = Arc::new(AtomicUsize::new(0));

        tracker.add_listener(Box::new(TestListener {
            call_count: count1.clone(),
        }));
        tracker.add_listener(Box::new(TestListener {
            call_count: count2.clone(),
        }));
        tracker.add_listener(Box::new(TestListener {
            call_count: count3.clone(),
        }));

        tracker.report_progress(ProgressStage::Started, "Test".to_string());

        assert_eq!(count1.load(Ordering::Relaxed), 1);
        assert_eq!(count2.load(Ordering::Relaxed), 1);
        assert_eq!(count3.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_report_progress_empty_message() {
        let tracker = ProgressTracker::new();

        tracker.report_progress(ProgressStage::Started, "".to_string());
        assert!(matches!(
            tracker.get_current_stage(),
            ProgressStage::Started
        ));
    }

    #[test]
    fn test_report_progress_unicode_message() {
        let tracker = ProgressTracker::new();

        tracker.report_progress(ProgressStage::Started, "Test message".to_string());
        assert!(matches!(
            tracker.get_current_stage(),
            ProgressStage::Started
        ));
    }

    #[test]
    fn test_report_progress_very_long_message() {
        let tracker = ProgressTracker::new();

        let long_message = "x".repeat(10000);
        tracker.report_progress(ProgressStage::Started, long_message);
        assert!(matches!(
            tracker.get_current_stage(),
            ProgressStage::Started
        ));
    }

    #[test]
    fn test_progress_update_timestamp() -> Result<(), Box<dyn std::error::Error>> {
        let tracker = ProgressTracker::new();

        struct TimestampListener {
            last_timestamp: Arc<Mutex<Option<u64>>>,
        }

        impl ProgressListener for TimestampListener {
            fn on_progress(&self, update: ProgressUpdate) {
                if let Ok(mut guard) = self.last_timestamp.lock() {
                    *guard = Some(update.timestamp);
                }
            }
        }

        let last_timestamp = Arc::new(Mutex::new(None));
        let listener = Box::new(TimestampListener {
            last_timestamp: last_timestamp.clone(),
        });
        tracker.add_listener(listener);

        tracker.report_progress(ProgressStage::Started, "Test".to_string());

        let timestamp = last_timestamp.lock().map_err(|_| "mutex poisoned")?;
        assert!(timestamp.is_some());
        assert!(timestamp.unwrap_or(0) > 0);
        Ok(())
    }

    #[test]
    fn test_progress_update_contains_progress_percent() -> Result<(), Box<dyn std::error::Error>> {
        let tracker = ProgressTracker::new();

        struct PercentListener {
            last_percent: Arc<Mutex<Option<u8>>>,
        }

        impl ProgressListener for PercentListener {
            fn on_progress(&self, update: ProgressUpdate) {
                if let Ok(mut guard) = self.last_percent.lock() {
                    *guard = update.progress_percent;
                }
            }
        }

        let last_percent = Arc::new(Mutex::new(None));
        let listener = Box::new(PercentListener {
            last_percent: last_percent.clone(),
        });
        tracker.add_listener(listener);

        tracker.report_progress(
            ProgressStage::VerificationChallengeReceived,
            "Test".to_string(),
        );

        let percent = last_percent.lock().map_err(|_| "mutex poisoned")?;
        assert_eq!(*percent, Some(33));
        Ok(())
    }

    #[test]
    fn test_estimate_time_verification_proof() {
        let tracker = ProgressTracker::new();

        let estimate1 = tracker.estimate_time(ProgressStage::VerificationProofGenerated, 1);
        assert_eq!(estimate1, Some(5));

        let estimate2 = tracker.estimate_time(ProgressStage::VerificationProofGenerated, 5);
        assert_eq!(estimate2, Some(2));
    }

    #[test]
    fn test_estimate_time_waiting_for_user() {
        let tracker = ProgressTracker::new();

        let estimate = tracker.estimate_time(ProgressStage::IssuanceWaitingForOfficer, 10);
        assert_eq!(estimate, None);
    }

    #[test]
    fn test_estimate_time_completed() {
        let tracker = ProgressTracker::new();

        let estimate1 = tracker.estimate_time(ProgressStage::IssuanceCompleted, 10);
        assert_eq!(estimate1, Some(0));

        let estimate2 = tracker.estimate_time(ProgressStage::VerificationCompleted, 10);
        assert_eq!(estimate2, Some(0));
    }

    #[test]
    fn test_concurrent_progress_updates() -> Result<(), Box<dyn std::error::Error>> {
        use std::thread;

        let tracker = Arc::new(ProgressTracker::new());

        let mut handles = vec![];

        for i in 0..10 {
            let tracker_clone = Arc::clone(&tracker);
            let handle = thread::spawn(move || {
                tracker_clone.report_progress(ProgressStage::Started, format!("Thread {}", i));
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().map_err(|_| "thread panicked")?;
        }

        assert!(matches!(
            tracker.get_current_stage(),
            ProgressStage::Started
        ));
        Ok(())
    }

    #[test]
    fn test_progress_stage_enum_copy() {
        let stage1 = ProgressStage::Started;
        let stage2 = stage1;

        assert!(matches!(stage1, ProgressStage::Started));
        assert!(matches!(stage2, ProgressStage::Started));
    }

    #[test]
    fn test_progress_stage_enum_debug() {
        let stage = ProgressStage::VerificationProofGenerated;
        let debug_str = format!("{:?}", stage);

        assert!(debug_str.contains("VerificationProofGenerated"));
    }

    #[test]
    fn test_progress_update_clone() {
        let update1 = ProgressUpdate {
            stage: ProgressStage::Started,
            message: "Test".to_string(),
            progress_percent: Some(50),
            estimated_time_remaining_secs: Some(10),
            timestamp: 123456789,
        };

        let update2 = update1.clone();

        assert!(matches!(update2.stage, ProgressStage::Started));
        assert_eq!(update2.message, "Test");
        assert_eq!(update2.progress_percent, Some(50));
    }
}
