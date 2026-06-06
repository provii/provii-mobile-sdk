// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! JNI bridge that forwards the Android `Context` to the secure storage
//! crate and performs one-time runtime initialisation.
//!
//! Compiled only when `target_os = "android"`. The three exported JNI
//! functions are called from `app.provii.wallet.sdk.WalletSdk` on the
//! Kotlin side.
//!
//! # Initialisation sequence
//!
//! 1. Android logcat logging (tag: `ProviiRust`, level: TRACE).
//! 2. Rayon global thread pool (n-2 cores, minimum 1, 4 MiB stack).
//! 3. Panic hook that routes to logcat instead of stderr.
//! 4. Android `Context` forwarded to `store-android`.
//!
//! All four steps run inside [`std::sync::Once`] so they are safe to call
//! from any thread and will execute at most once per process.

#![cfg(target_os = "android")]

use jni::{
    objects::{JClass, JObject},
    sys::jint,
    JNIEnv,
};
use rayon;
use std::sync::Once;

use provii_mobile_sdk_store_android::Error as StoreError;

/// JNI return code: initialisation succeeded.
const RESULT_OK: jint = 0;
/// JNI return code: context was already set by a prior call.
const RESULT_ALREADY_INITIALISED: jint = 1;
/// JNI return code: an unrecoverable error occurred.
const RESULT_ERROR: jint = -1;

/// Guard that ensures [`initialize_android_runtime`] runs at most once.
static INIT_ONCE: Once = Once::new();

/// Perform all one-time Android runtime setup.
///
/// Configures logging, the Rayon thread pool, and a panic hook that routes
/// to logcat. Idempotent: subsequent calls are no-ops.
fn initialize_android_runtime() {
    INIT_ONCE.call_once(|| {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Trace)
                .with_tag("ProviiRust"),
        );

        // Reserve 2 cores for system/UI work; use the remainder for proofs.
        let hw_threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);

        let proof_threads = match hw_threads {
            1..=2 => 1,
            n => n.saturating_sub(2).max(1),
        };

        match rayon::ThreadPoolBuilder::new()
            .num_threads(proof_threads)
            .thread_name(|i| format!("proof-{}", i))
            .stack_size(4 * 1024 * 1024)
            .build_global()
        {
            Ok(()) => {
                log::info!(
                    "Rayon global pool: {} threads (hw={}, n-2 strategy)",
                    rayon::current_num_threads(),
                    hw_threads
                );
            }
            Err(e) => {
                log::warn!("Rayon global pool already exists or failed: {:?}", e);
                log::warn!("Current Rayon threads = {}", rayon::current_num_threads());
            }
        }

        std::panic::set_hook(Box::new(|panic_info| {
            let payload = panic_info.payload();
            let msg = if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = payload.downcast_ref::<&str>() {
                s.to_string()
            } else {
                "Unknown panic payload".to_string()
            };

            log::error!("=== PANIC DETECTED ===");
            log::error!("PANIC: {}", msg);

            if let Some(location) = panic_info.location() {
                log::error!(
                    "Panic location: {}:{}:{}",
                    location.file(),
                    location.line(),
                    location.column()
                );
            }

            if let Some(name) = std::thread::current().name() {
                log::error!("Thread: {}", name);
            } else {
                log::error!("Thread: unnamed (id: {:?})", std::thread::current().id());
            }
        }));

        log::info!("Android runtime initialised");
        log::info!(
            "Device cores: {}, proof threads: {}",
            hw_threads,
            proof_threads
        );
        log::info!("Architecture: {}", std::env::consts::ARCH);
    });
}

/// Initialise the Android `Context` and runtime environment.
///
/// Called from `WalletSdk.initAndroidContext(context)` on the Kotlin side.
/// Sets up logging, the Rayon pool, and forwards the Android `Context` to
/// the secure storage backend.
///
/// # Return codes
///
/// * `0` on success.
/// * `1` if already initialised (harmless, context is unchanged).
/// * `-1` on any other failure.
///
/// # Safety
///
/// This function is called by the Android JVM via JNI. The JVM guarantees
/// the validity of all pointer arguments (`JNIEnv`, `JClass`, `JObject`)
/// per the JNI specification. It is `unsafe extern "C"` because it is an
/// FFI boundary callable from non-Rust code.
#[no_mangle]
#[allow(non_snake_case)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn Java_app_provii_wallet_sdk_WalletSdk_initAndroidContext(
    env: JNIEnv,
    _class: JClass,
    context: JObject,
) -> jint {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        initialize_android_runtime();

        log::debug!("initAndroidContext called from JNI");

        match provii_mobile_sdk_store_android::init_android_context(&env, context) {
            Ok(()) => {
                log::info!("Android context initialised successfully");
                RESULT_OK
            }
            Err(StoreError::AlreadyInitialised) => {
                log::debug!("Android context already initialised");
                RESULT_ALREADY_INITIALISED
            }
            Err(e) => {
                log::error!("init_android_context failed: {e}");
                RESULT_ERROR
            }
        }
    })) {
        Ok(result) => result,
        Err(_) => {
            // Panic crossed the FFI boundary; return error rather than aborting.
            RESULT_ERROR
        }
    }
}

#[cfg(debug_assertions)]
/// Emit test log messages at every level to verify logcat integration.
///
/// Called from `WalletSdk.testLogging()` on the Kotlin side. Useful during
/// development to confirm that log output from Rust reaches Android logcat
/// at the expected filter levels.
///
/// # Return codes
///
/// * `0` on success.
/// * `-1` if a panic occurred.
///
/// # Safety
///
/// This function is called by the Android JVM via JNI. The JVM guarantees
/// the validity of all pointer arguments (`JNIEnv`, `JClass`) per the JNI
/// specification. It is `unsafe extern "C"` because it is an FFI boundary
/// callable from non-Rust code.
#[no_mangle]
#[allow(non_snake_case)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn Java_app_provii_wallet_sdk_WalletSdk_testLogging(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        log::error!("[TEST] Error level message");
        log::warn!("[TEST] Warn level message");
        log::info!("[TEST] Info level message");
        log::debug!("[TEST] Debug level message");
        log::trace!("[TEST] Trace level message");

        log::info!("[prover] Test message as if from crypto-prover");
        log::debug!("[prover] Debug message as if from crypto-prover");
        log::trace!("[prover] Trace message as if from crypto-prover");

        let hw_threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let proof_threads = match hw_threads {
            1..=2 => 1,
            n => n.saturating_sub(2).max(1),
        };
        log::info!(
            "[TEST] Thread config: {} cores, {} proof threads",
            hw_threads,
            proof_threads
        );

        log::info!("[TEST] Rayon pool size: {}", rayon::current_num_threads());
        if let Some(idx) = rayon::current_thread_index() {
            log::info!("[TEST] Currently in Rayon worker thread #{}", idx);
        } else {
            log::info!("[TEST] Not currently in a Rayon worker thread");
        }

        RESULT_OK
    })) {
        Ok(result) => result,
        Err(_) => RESULT_ERROR,
    }
}

#[cfg(debug_assertions)]
/// Run a small parallel computation to verify that the Rayon pool is
/// functioning correctly on this device.
///
/// Called from `WalletSdk.verifyRayonPool()` on the Kotlin side. Logs
/// timing results and thread counts to logcat so developers can confirm
/// multi-threaded proof generation will work.
///
/// # Return codes
///
/// * `0` on success.
/// * `-1` if a panic occurred.
///
/// # Safety
///
/// This function is called by the Android JVM via JNI. The JVM guarantees
/// the validity of all pointer arguments (`JNIEnv`, `JClass`) per the JNI
/// specification. It is `unsafe extern "C"` because it is an FFI boundary
/// callable from non-Rust code.
#[no_mangle]
#[allow(non_snake_case)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn Java_app_provii_wallet_sdk_WalletSdk_verifyRayonPool(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        initialize_android_runtime();

        use rayon::prelude::*;
        let start = std::time::Instant::now();

        let sum: u64 = (0..1_000_000u64).into_par_iter().map(|x| x * x).sum();

        let elapsed = start.elapsed();

        log::info!("=== RAYON POOL VERIFICATION ===");
        log::info!("Rayon pool threads: {}", rayon::current_num_threads());
        log::info!("Parallel computation completed in {:?}", elapsed);
        log::info!("Result: {}", sum);

        if elapsed.as_millis() < 100 {
            log::info!("Multi-threading appears to be working");
        } else {
            log::warn!("Computation seems slow; might be single-threaded");
        }

        RESULT_OK
    })) {
        Ok(result) => result,
        Err(_) => RESULT_ERROR,
    }
}
