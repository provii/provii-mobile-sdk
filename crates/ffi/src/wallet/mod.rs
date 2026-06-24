// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Primary [`ProviiWallet`] UniFFI object exposed to Swift and Kotlin.
//!
//! This module contains the full wallet lifecycle: prover initialisation,
//! credential import and storage, QR code processing, zero knowledge proof
//! generation, verification submission, and diagnostic reporting. All public
//! methods are exported through UniFFI unless otherwise noted.
//!
//! Secrets (dob_days, r_bits) are stored separately from the credential body
//! and wrapped in [`Zeroizing`] or types that derive [`ZeroizeOnDrop`] to
//! ensure deterministic memory erasure.
//!
//! The implementation is split across concern submodules ([`setup`],
//! [`credentials`], [`qr`], [`proof`], [`lifecycle`]) as multiple
//! `impl ProviiWallet` blocks. The split is purely organisational: because
//! UniFFI generates bindings in library mode from the whole crate, moving
//! `#[uniffi::export]` items between modules within this crate has no effect on
//! the generated Swift/Kotlin surface as long as method names, parameters,
//! types, and receivers are unchanged.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::storage::Storage;
use provii_mobile_sdk_core::types::{IssuerTrustAnchor, QrChallengePayload};

// Re-exported so the concern submodules (and the test module) can pull the
// shared FFI types into scope with `use super::*`. `pub(crate)` keeps them
// crate-internal and avoids unused-import warnings in this module.
pub(crate) use crate::errors::*;
#[cfg(test)]
pub(crate) use crate::progress::{ProgressStage, ProgressTracker};
pub(crate) use crate::state::*;
pub(crate) use crate::types::*;

mod credentials;
mod lifecycle;
mod proof;
mod qr;
mod setup;

/// Storage key for the persisted issuer trust anchor JSON blob.
pub(super) const TRUST_ANCHOR_STORAGE_KEY: &str = "provii.issuer.trust_anchor";

/// Acquire a [`MutexGuard`], recovering from a poisoned mutex by returning
/// the inner value. This prevents a panic in one thread from permanently
/// locking the wallet.
pub(super) fn safe_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::warn!("Recovering from poisoned mutex");
            poisoned.into_inner()
        }
    }
}

/// Thread-safe wallet object exposed to mobile platforms via UniFFI.
///
/// Manages credential storage, zero knowledge proof generation, QR code
/// processing, and verification state. All methods that touch secret
/// material (dob_days, r_bits) ensure secrets are zeroised before returning.
#[derive(uniffi::Object)]
pub struct ProviiWallet {
    /// Mutable runtime configuration (API URLs, timeouts, feature flags).
    config: Arc<Mutex<WalletConfig>>,
    /// Platform-backed secure storage abstraction.
    storage: Arc<Storage>,
    /// Tracks the current verification lifecycle state.
    state_manager: Arc<StateManager>,
    /// Immutable application metadata supplied by the host at construction.
    app_info: Arc<AppInfo>,
    /// In-memory cache of recently processed QR challenges, keyed by challenge ID.
    cached_challenges: Arc<Mutex<HashMap<String, CachedChallenge>>>,
    /// Trust anchor for issuer key validation. Persisted to secure storage so it
    /// survives restarts. `None` until the first successful JWKS fetch.
    issuer_trust_anchor: Arc<Mutex<Option<IssuerTrustAnchor>>>,
}

/// Check whether a string is a valid 12-digit short code.
///
/// Short codes are displayed as `XXXX XXXX XXXX` but stored and transmitted
/// without spaces. Whitespace in the input is stripped before validation.
#[uniffi::export]
pub fn is_short_code(input: String) -> bool {
    // Remove any whitespace for validation
    let normalized: String = input.chars().filter(|c| !c.is_whitespace()).collect();

    // Must be exactly 12 digits
    normalized.len() == 12 && normalized.chars().all(|c| c.is_ascii_digit())
}

/// A cached QR challenge with its receive and expiry timestamps.
///
/// The `payload` field contains the submit secret and is zeroised on drop.
/// Timestamps are skipped by `Zeroize` because they are not secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(super) struct CachedChallenge {
    pub(super) payload: QrChallengePayload,
    #[zeroize(skip)]
    pub(super) received_at: std::time::SystemTime,
    #[zeroize(skip)]
    pub(super) expires_at: std::time::SystemTime,
}

/// Manual [`Debug`] implementation that redacts the submit secret.
impl std::fmt::Debug for CachedChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedChallenge")
            .field("challenge_id", &self.payload.challenge_id)
            .field("cutoff_days", &self.payload.cutoff_days)
            .field("submit_secret", &"[REDACTED]")
            .field("received_at", &self.received_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Zeroize in-memory secrets when the wallet is dropped.
///
/// Uses `try_lock` (not `lock`) to avoid panicking if a mutex is poisoned or
/// held by another thread at teardown time. If a lock cannot be acquired the
/// secrets remain in freed heap memory until the OS reclaims the page; this is
/// an acceptable trade-off versus deadlocking the destructor.
impl Drop for ProviiWallet {
    fn drop(&mut self) {
        if let Ok(mut config) = self.config.try_lock() {
            config.zeroize_secrets();
        }
        if let Ok(mut cached) = self.cached_challenges.try_lock() {
            cached.clear();
        }
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
#[path = "wallet_tests.rs"]
mod tests;
