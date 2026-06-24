// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Android Keystore-backed secure storage for Provii Wallet SDK.
//!
//! Implements `PlatformSecureStorage` for Android using the hardware-backed
//! Keystore with optional StrongBox HSM integration. Supports biometric
//! authentication, audit logging, thread-safe operations, memory zeroisation,
//! and key rotation. Attestation-free design ensures GrapheneOS compatibility.

#![cfg(target_os = "android")]
#![deny(unsafe_code)]
#![allow(non_snake_case)] // Allow JNI_OnLoad

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, Once, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use jni::{
    objects::{GlobalRef, JByteArray, JObject, JObjectArray, JString, JValue},
    JNIEnv, JavaVM,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use jni::AttachGuard;

use once_cell::sync::OnceCell;
use provii_mobile_sdk_platform_storage::{
    BiometricRequirement, PlatformSecureStorage, Result, UsageStats, WalletError,
};
use rayon;

/* =======================================================================
Constants and Configuration
=================================================================== */

/// Keystore alias prefix for wallet identity storage
const IDENTITY_KEY_PREFIX: &str = "provii_identity";

/// Keystore alias prefix for credential storage
const CREDENTIAL_KEY_PREFIX: &str = "provii_credential";

/// Keystore alias prefix for configuration storage
const CONFIG_KEY_PREFIX: &str = "provii_config";

/// Maximum retry attempts for keystore operations
const MAX_KEYSTORE_RETRIES: u32 = 3;

/// Timeout for biometric authentication (milliseconds)
const BIOMETRIC_TIMEOUT_MS: i32 = 30000;

/// Maximum size for individual keystore items (2MB)
const MAX_ITEM_SIZE: usize = 2 * 1024 * 1024;

/// Cache TTL for hardware feature checks (1 hour)
const HARDWARE_CACHE_TTL: u64 = 3600;

/* =======================================================================
Global State Management
=================================================================== */

static JVM: OnceCell<JavaVM> = OnceCell::new();
static INIT: Once = Once::new();
static OPERATION_STATS: Mutex<OperationStatistics> = Mutex::new(OperationStatistics::new());

// ---------------------------------------------------------------------------
//  Global Android Context (set once from Kotlin via FFI)
// ---------------------------------------------------------------------------
static APP_CONTEXT: OnceCell<GlobalRef> = OnceCell::new();

use thiserror::Error;

/// Errors returned by [`init_android_context`].
#[derive(Debug, Error)]
pub enum Error {
    #[error("Android context already initialised")]
    AlreadyInitialised,
    #[error(transparent)]
    Jni(#[from] jni::errors::Error),
}

// Helper function to convert JNI errors to WalletError
fn jni_to_wallet_error(err: jni::errors::Error) -> WalletError {
    WalletError::Storage {
        msg: format!("JNI error: {}", err),
    }
}

/// Store the Application `Context` as a global [`GlobalRef`].
/// Safe to call more than once – the second call returns
/// `Error::AlreadyInitialised` so the caller can ignore it.
pub fn init_android_context<'a>(
    env: &JNIEnv<'a>,
    ctx: JObject<'a>,
) -> core::result::Result<(), Error> {
    let global = env.new_global_ref(ctx)?;
    APP_CONTEXT
        .set(global)
        .map_err(|_| Error::AlreadyInitialised)
}

/// Retrieve the saved context if it exists (clone = new global ref).
pub fn android_context() -> Option<GlobalRef> {
    APP_CONTEXT.get().cloned()
}

/* =======================================================================
JVM Initialization
=================================================================== */

// SAFETY: JNI_OnLoad is called by the Android JVM class loader during native library loading.
// `vm` is a valid JavaVM handle provided by the JVM. `_reserved` is always null per the
// JNI specification. This function is an FFI boundary callable from non-Rust code.
/// Initialize JVM reference - called automatically by Android runtime
#[no_mangle]
#[allow(non_snake_case)]
#[allow(unsafe_code)]
pub extern "system" fn JNI_OnLoad(vm: JavaVM, _reserved: *mut std::ffi::c_void) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Initialize Android logging FIRST
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Trace)
                .with_tag("ProviiRust"),
        );

        // Calculate optimal thread count using n-2 strategy
        let hw_threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);

        let proof_threads = match hw_threads {
            1..=2 => 1,                      // Dual core or less: single thread
            n => n.saturating_sub(2).max(1), // n-2 for everything else
        };

        log::info!("========================================");
        log::info!("JNI_OnLoad: Initializing Provii Wallet");
        log::info!("Device hardware cores: {}", hw_threads);
        log::info!(
            "Configuring {} threads for proof generation (n-2 strategy)",
            proof_threads
        );
        log::info!("========================================");

        // CRITICAL: Build the global Rayon thread pool with our configuration
        // This MUST be done before any Rayon/Bellman operations
        match rayon::ThreadPoolBuilder::new()
            .num_threads(proof_threads)
            .thread_name(|idx| format!("proof-{}", idx))
            .stack_size(4 * 1024 * 1024) // 4MB stack for proof generation
            .build_global()
        {
            Ok(()) => {
                log::info!(
                    "✓ Rayon global thread pool initialized with {} threads",
                    proof_threads
                );

                // Verify the pool was created correctly
                let actual_threads = rayon::current_num_threads();
                if actual_threads != proof_threads {
                    log::warn!(
                        "Warning: Requested {} threads but got {}",
                        proof_threads,
                        actual_threads
                    );
                } else {
                    log::info!("✓ Thread pool verified: {} threads active", actual_threads);
                }
            }
            Err(e) => {
                log::error!("✗ Failed to initialize Rayon thread pool: {:?}", e);
                log::error!("Rayon will use default configuration (may be single-threaded!)");
            }
        }

        // Log expected performance
        let expected_speedup = if proof_threads == 1 {
            1.0
        } else {
            proof_threads as f32 * 0.7
        };
        log::info!(
            "Expected proof generation speedup: ~{:.1}x",
            expected_speedup
        );
        log::info!(
            "Expected time: ~{} seconds",
            (40.0 / expected_speedup) as u32
        );

        // Install panic hook with diagnostics for native crash debugging
        std::panic::set_hook(Box::new(|panic_info| {
            let payload = panic_info.payload();

            let msg = if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = payload.downcast_ref::<&str>() {
                s.to_string()
            } else {
                format!(
                    "Non-string panic payload: {:?}",
                    std::any::type_name_of_val(&payload)
                )
            };

            log::error!("PANIC: {}", msg);

            if let Some(location) = panic_info.location() {
                log::error!(
                    "  at {}:{}:{}",
                    location.file(),
                    location.line(),
                    location.column()
                );
            }

            // Try to get a backtrace
            let backtrace = std::backtrace::Backtrace::capture();
            if backtrace.status() == std::backtrace::BacktraceStatus::Captured {
                log::error!("Backtrace:\n{}", backtrace);
            }
        }));

        // Store JVM reference
        if JVM.set(vm).is_err() {
            log::warn!("JVM already initialized");
            return jni::sys::JNI_VERSION_1_6;
        }

        log::info!("JNI_OnLoad completed successfully");
        log::info!("========================================");

        jni::sys::JNI_VERSION_1_6
    })) {
        Ok(result) => result,
        Err(_) => {
            // Panic during JNI_OnLoad; return JNI_ERR to signal load failure to the JVM
            jni::sys::JNI_ERR
        }
    }
}

/* =======================================================================
Enhanced Android Secure Storage Implementation
=================================================================== */

/// Production-grade Android Keystore storage with StrongBox integration
pub struct AndroidSecureStorage {
    /// Configuration for this storage instance
    config: StorageConfig,
    /// Hardware security profile cache
    device_profile: Arc<RwLock<Option<DeviceSecurityProfile>>>,
    /// Keystore bridge instance cache
    keystore_bridge: Arc<Mutex<Option<GlobalRef>>>,
    /// Security event audit log (bounded ring buffer)
    audit_log: Arc<Mutex<VecDeque<SecurityEvent>>>,
    /// Metrics and monitoring
    metrics: Arc<Mutex<StorageMetrics>>,
    /// Operation cache for performance
    operation_cache: Arc<RwLock<HashMap<String, CachedOperation>>>,
}

/// Configuration for an [`AndroidSecureStorage`] instance.
///
/// Controls biometric policy, StrongBox usage, caching behaviour,
/// lockout thresholds, and audit logging.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Whether to require biometric authentication for all operations
    pub require_biometrics: bool,
    /// Whether to use StrongBox when available
    pub use_strongbox: bool,
    /// Whether to enable audit logging
    pub enable_audit_logging: bool,
    /// Maximum number of failed attempts before lockout.
    /// Reserved for future use: the Kotlin KeystoreBridge does not yet
    /// consume these values. They are retained so the config struct can
    /// drive a lockout policy once the bridge supports it.
    pub max_failed_attempts: u32,
    /// Lockout duration in seconds.
    /// Reserved for future use (see `max_failed_attempts`).
    pub lockout_duration: u32,
    /// Whether to enable operation caching
    pub enable_caching: bool,
    /// Cache TTL in seconds
    pub cache_ttl: u64,
    /// Whether to allow software keystore fallback (SECURITY: false by default)
    /// Set to true only for development/testing or non-sensitive data
    pub allow_software_keystore: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            require_biometrics: true,
            use_strongbox: true,
            enable_audit_logging: true,
            max_failed_attempts: 5,
            lockout_duration: 300,          // 5 minutes
            enable_caching: false,          // Disabled by default for security
            cache_ttl: 600,                 // 10 minutes
            allow_software_keystore: false, // SECURITY: Require hardware keystore by default
        }
    }
}

/// Legacy alias for [`AndroidSecureStorage`].
pub type AndroidKeystoreStorage = AndroidSecureStorage;

/* =======================================================================
Factory Functions for Different Use Cases
=================================================================== */

/// Create an AndroidSecureStorage instance configured for production use
pub fn create_production_storage() -> Result<Arc<dyn PlatformSecureStorage>> {
    let config = StorageConfig {
        require_biometrics: true,
        use_strongbox: true,
        enable_audit_logging: true,
        max_failed_attempts: 3,
        lockout_duration: 300,
        enable_caching: false, // Disabled for maximum security
        cache_ttl: 0,
        allow_software_keystore: false, // Production requires hardware-backed keystore
    };

    let storage = AndroidSecureStorage::new_with_config(config)?;
    Ok(storage as Arc<dyn PlatformSecureStorage>)
}

/// Create an AndroidSecureStorage instance configured for development/testing
pub fn create_development_storage() -> Result<Arc<dyn PlatformSecureStorage>> {
    let config = StorageConfig {
        require_biometrics: false,
        use_strongbox: false,
        enable_audit_logging: true,
        max_failed_attempts: 10,
        lockout_duration: 60,
        enable_caching: true,
        cache_ttl: 300,
        allow_software_keystore: true, // Development allows software fallback
    };

    let storage = AndroidSecureStorage::new_with_config(config)?;
    Ok(storage as Arc<dyn PlatformSecureStorage>)
}

/* =======================================================================
Module wiring
=================================================================== */

mod cache;
mod hardware;
mod keystore_ops;
mod lifecycle;
mod metrics;

use cache::CachedOperation;
use keystore_ops::{current_timestamp, safe_key_label};
use metrics::{
    DeviceSecurityProfile, OperationStatistics, RiskLevel, SecurityEvent, SecurityEventType,
    StorageMetrics,
};

/* =======================================================================
Tests
=================================================================== */

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
