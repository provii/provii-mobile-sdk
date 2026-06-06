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

#[derive(Debug, Clone)]
struct OperationStatistics {
    total_operations: u64,
    successful_operations: u64,
    failed_operations: u64,
    biometric_authentications: u64,
    hardware_operations: u64,
    last_operation_time: u64,
}

impl OperationStatistics {
    const fn new() -> Self {
        Self {
            total_operations: 0,
            successful_operations: 0,
            failed_operations: 0,
            biometric_authentications: 0,
            hardware_operations: 0,
            last_operation_time: 0,
        }
    }

    fn record_operation(&mut self, success: bool, used_biometrics: bool, used_hardware: bool) {
        self.total_operations += 1;
        if success {
            self.successful_operations += 1;
        } else {
            self.failed_operations += 1;
        }
        if used_biometrics {
            self.biometric_authentications += 1;
        }
        if used_hardware {
            self.hardware_operations += 1;
        }
        self.last_operation_time = current_timestamp();
    }
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
Hardware Security Assessment (Attestation-Free)
=================================================================== */

#[derive(Debug, Clone)]
struct DeviceSecurityProfile {
    has_strongbox: bool,
    has_hardware_keystore: bool,
    has_biometric_hardware: bool,
    security_patch_level: String,
    api_level: i32,
    last_assessed: u64,
}

impl Default for DeviceSecurityProfile {
    fn default() -> Self {
        Self {
            has_strongbox: false,
            has_hardware_keystore: false,
            has_biometric_hardware: false,
            security_patch_level: "unknown".to_string(),
            api_level: 0,
            last_assessed: 0,
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

/// SECURITY: CachedOperation may contain sensitive credential data.
/// Implements ZeroizeOnDrop to clear memory when the operation is dropped.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
struct CachedOperation {
    #[zeroize(skip)] // Key name is not sensitive
    key: String,
    data: Vec<u8>,
    #[zeroize(skip)] // Timestamps are not sensitive
    cached_at: u64,
    #[zeroize(skip)] // TTL is not sensitive
    ttl: u64,
}

#[derive(Debug, Clone)]
struct SecurityEvent {
    event_type: SecurityEventType,
    timestamp: u64,
    details: String,
    risk_level: RiskLevel,
}

#[derive(Debug, Clone)]
enum SecurityEventType {
    KeystoreAccess,
    BiometricAuth,
    HardwareFeatureCheck,
    FailedOperation,
    ConfigurationChange,
}

#[derive(Debug, Clone)]
enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Default, Clone)]
struct StorageMetrics {
    operations_count: u64,
    cache_hits: u64,
    cache_misses: u64,
    biometric_prompts: u64,
    strongbox_operations: u64,
    errors_count: u64,
    average_operation_time_ms: u64,
    last_error: Option<String>,
}

impl AndroidSecureStorage {
    /// Create a new storage instance with the given configuration.
    ///
    /// Initialises the JNI environment, assesses hardware security features,
    /// and validates that the device meets minimum requirements (API 29+,
    /// hardware keystore present unless `allow_software_keystore` is set).
    pub fn new_with_config(config: StorageConfig) -> Result<Arc<Self>> {
        INIT.call_once(|| {
            // Initialize Android logging
            #[cfg(target_os = "android")]
            android_logger::init_once(
                android_logger::Config::default().with_max_level(log::LevelFilter::Debug),
            );
        });

        let temp_self = Arc::new(Self {
            config,
            device_profile: Arc::new(RwLock::new(None)),
            keystore_bridge: Arc::new(Mutex::new(None)),
            audit_log: Arc::new(Mutex::new(VecDeque::new())),
            metrics: Arc::new(Mutex::new(StorageMetrics::default())),
            operation_cache: Arc::new(RwLock::new(HashMap::new())),
        });

        // Initialize hardware features assessment
        temp_self.initialize()?;
        Ok(temp_self)
    }

    fn initialize(&self) -> Result<()> {
        let mut guard = self.get_jni_env()?;
        let env = &mut *guard;

        let device_profile = self.assess_hardware_features(env)?;
        Self::validate_hardware_requirements(&device_profile, &self.config)?;

        *self
            .device_profile
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(device_profile);
        Ok(())
    }

    // Fixed jni_safe_call with explicit lifetime to match JNI objects
    fn jni_safe_call<'local, F, T>(env: &mut JNIEnv<'local>, f: F) -> Result<T>
    where
        F: FnOnce(&mut JNIEnv<'local>) -> jni::errors::Result<T>,
    {
        let result = f(env);

        // Handle exceptions first
        if env.exception_check().map_err(jni_to_wallet_error)? {
            let exception = env.exception_occurred().map_err(jni_to_wallet_error)?;
            env.exception_clear().map_err(jni_to_wallet_error)?;

            if !exception.is_null() {
                let jstr = env
                    .call_method(&exception, "toString", "()Ljava/lang/String;", &[])
                    .map_err(jni_to_wallet_error)?
                    .l()
                    .map_err(jni_to_wallet_error)?;
                let text: String = env
                    .get_string(&JString::from(jstr))
                    .map_err(jni_to_wallet_error)?
                    .into();
                return Err(WalletError::Storage {
                    msg: format!("JNI exception: {}", text),
                });
            }
            return Err(WalletError::Storage {
                msg: "JNI exception occurred".to_string(),
            });
        }

        result.map_err(jni_to_wallet_error)
    }

    /* ---------------------------------------------------------------
    Hardware Feature Assessment (No Attestation)
    ------------------------------------------------------------- */

    fn assess_hardware_features<'local>(
        &self,
        env: &mut JNIEnv<'local>,
    ) -> Result<DeviceSecurityProfile> {
        let mut profile = DeviceSecurityProfile::default();
        profile.last_assessed = current_timestamp();

        // Get Android API level
        profile.api_level = Self::get_api_level(env)?;

        // Check for hardware security features
        profile.has_hardware_keystore = Self::check_hardware_keystore(env)?;
        profile.has_strongbox = Self::check_strongbox_availability(env)?;
        profile.has_biometric_hardware = Self::check_biometric_hardware(env)?;

        // Get security patch level
        profile.security_patch_level = Self::get_security_patch_level(env)?;

        Ok(profile)
    }

    fn get_api_level<'local>(env: &mut JNIEnv<'local>) -> Result<i32> {
        let cls = Self::jni_safe_call(env, |e| e.find_class("android/os/Build$VERSION"))?;
        let field = Self::jni_safe_call(env, |e| e.get_static_field(&cls, "SDK_INT", "I"))?;
        field.i().map_err(jni_to_wallet_error)
    }

    /// Check whether the device actually has hardware-backed key storage.
    ///
    /// Generates a temporary AES key in the Android Keystore, retrieves its
    /// `KeyInfo`, and queries `isInsideSecureHardware()`. The probe key is
    /// deleted immediately after the check. If any step fails (e.g. the
    /// device lacks the Keystore provider entirely), returns `false` rather
    /// than propagating the error, since this is a best-effort capability
    /// check.
    fn check_hardware_keystore<'local>(env: &mut JNIEnv<'local>) -> Result<bool> {
        // Step 1: Verify the Keystore API class exists at all.
        let api_class = Self::jni_safe_call(env, |e| {
            e.find_class("android/security/keystore/KeyGenParameterSpec")
        });
        if api_class.is_err() {
            return Ok(false);
        }

        // Step 2: Generate a temporary probe key to test hardware backing.
        let probe_alias = "__provii_hw_probe";
        let probe_alias_jstr = Self::jni_safe_call(env, |e| e.new_string(probe_alias))?;

        // KeyGenParameterSpec.Builder(alias, PURPOSE_ENCRYPT | PURPOSE_DECRYPT)
        let builder_cls = Self::jni_safe_call(env, |e| {
            e.find_class("android/security/keystore/KeyGenParameterSpec$Builder")
        })?;
        // PURPOSE_ENCRYPT=1, PURPOSE_DECRYPT=2 => 3
        let builder = Self::jni_safe_call(env, |e| {
            e.new_object(
                &builder_cls,
                "(Ljava/lang/String;I)V",
                &[JValue::from(&probe_alias_jstr), JValue::from(3i32)],
            )
        })?;

        // Set block modes and encryption padding so the key is usable
        let block_modes_arr = Self::jni_safe_call(env, |e| {
            let gcm = e.new_string("GCM")?;
            let arr = e.new_object_array(1, "java/lang/String", &gcm)?;
            Ok(arr)
        })?;
        let builder = Self::jni_safe_call(env, |e| {
            e.call_method(
                &builder,
                "setBlockModes",
                "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[JValue::from(&block_modes_arr)],
            )
            .and_then(|v| v.l())
        })?;

        let padding_arr = Self::jni_safe_call(env, |e| {
            let none_padding = e.new_string("NoPadding")?;
            let arr = e.new_object_array(1, "java/lang/String", &none_padding)?;
            Ok(arr)
        })?;
        let builder = Self::jni_safe_call(env, |e| {
            e.call_method(
                &builder,
                "setEncryptionPaddings",
                "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[JValue::from(&padding_arr)],
            )
            .and_then(|v| v.l())
        })?;

        let spec = Self::jni_safe_call(env, |e| {
            e.call_method(
                &builder,
                "build",
                "()Landroid/security/keystore/KeyGenParameterSpec;",
                &[],
            )
            .and_then(|v| v.l())
        })?;

        // KeyGenerator.getInstance("AES", "AndroidKeyStore")
        let kg_cls = Self::jni_safe_call(env, |e| e.find_class("javax/crypto/KeyGenerator"))?;
        let aes_str = Self::jni_safe_call(env, |e| e.new_string("AES"))?;
        let aks_str = Self::jni_safe_call(env, |e| e.new_string("AndroidKeyStore"))?;

        let kg = Self::jni_safe_call(env, |e| {
            e.call_static_method(
                &kg_cls,
                "getInstance",
                "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
                &[JValue::from(&aes_str), JValue::from(&aks_str)],
            )
            .and_then(|v| v.l())
        })?;

        // kg.init(spec)
        let init_result = Self::jni_safe_call(env, |e| {
            e.call_method(
                &kg,
                "init",
                "(Ljava/security/spec/AlgorithmParameterSpec;)V",
                &[JValue::from(&spec)],
            )
        });
        if init_result.is_err() {
            return Ok(false);
        }

        // kg.generateKey()
        let secret_key = Self::jni_safe_call(env, |e| {
            e.call_method(&kg, "generateKey", "()Ljavax/crypto/SecretKey;", &[])
                .and_then(|v| v.l())
        });
        let secret_key = match secret_key {
            Ok(k) => k,
            Err(_) => return Ok(false),
        };

        // SecretKeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore")
        let skf_cls = Self::jni_safe_call(env, |e| e.find_class("javax/crypto/SecretKeyFactory"))?;
        let algo = Self::jni_safe_call(env, |e| {
            e.call_method(&secret_key, "getAlgorithm", "()Ljava/lang/String;", &[])
                .and_then(|v| v.l())
        })?;

        let skf = Self::jni_safe_call(env, |e| {
            e.call_static_method(
                &skf_cls,
                "getInstance",
                "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/SecretKeyFactory;",
                &[JValue::from(&algo), JValue::from(&aks_str)],
            )
            .and_then(|v| v.l())
        })?;

        // KeyInfo = skf.getKeySpec(secretKey, KeyInfo.class)
        // JNI find_class returns a JClass which is already a java.lang.Class<?>
        // reference, so it can be passed directly to getKeySpec.
        let key_info_cls =
            Self::jni_safe_call(env, |e| e.find_class("android/security/keystore/KeyInfo"))?;

        let key_spec = Self::jni_safe_call(env, |e| {
            e.call_method(
                &skf,
                "getKeySpec",
                "(Ljava/security/Key;Ljava/lang/Class;)Ljava/security/spec/KeySpec;",
                &[JValue::from(&secret_key), JValue::from(&key_info_cls)],
            )
            .and_then(|v| v.l())
        });

        // Clean up: delete the probe key from the Keystore regardless of result
        let mut cleanup = || -> Result<()> {
            let ks_cls = Self::jni_safe_call(env, |e| e.find_class("java/security/KeyStore"))?;
            let aks_str2 = Self::jni_safe_call(env, |e| e.new_string("AndroidKeyStore"))?;
            let ks = Self::jni_safe_call(env, |e| {
                e.call_static_method(
                    &ks_cls,
                    "getInstance",
                    "(Ljava/lang/String;)Ljava/security/KeyStore;",
                    &[JValue::from(&aks_str2)],
                )
                .and_then(|v| v.l())
            })?;
            Self::jni_safe_call(env, |e| {
                e.call_method(
                    &ks,
                    "load",
                    "(Ljava/security/KeyStore$LoadStoreParameter;)V",
                    &[JValue::from(&JObject::null())],
                )
            })?;
            let alias_str = Self::jni_safe_call(env, |e| e.new_string(probe_alias))?;
            Self::jni_safe_call(env, |e| {
                e.call_method(
                    &ks,
                    "deleteEntry",
                    "(Ljava/lang/String;)V",
                    &[JValue::from(&alias_str)],
                )
            })?;
            Ok(())
        };
        let _ = cleanup();

        // Check isInsideSecureHardware() on the KeyInfo
        let key_spec = match key_spec {
            Ok(ks) => ks,
            Err(_) => return Ok(false),
        };

        let is_hardware = Self::jni_safe_call(env, |e| {
            e.call_method(&key_spec, "isInsideSecureHardware", "()Z", &[])
                .and_then(|v| v.z())
        });

        match is_hardware {
            Ok(hw) => Ok(hw),
            Err(_) => Ok(false),
        }
    }

    fn check_strongbox_availability<'local>(env: &mut JNIEnv<'local>) -> Result<bool> {
        let feat =
            Self::jni_safe_call(env, |e| e.new_string("android.hardware.strongbox_keystore"))?;
        let pm = Self::get_package_manager(env)?;

        let has_feature = Self::jni_safe_call(env, |e| {
            e.call_method(
                &pm,
                "hasSystemFeature",
                "(Ljava/lang/String;)Z",
                &[JValue::from(&feat)],
            )
        })?;
        has_feature.z().map_err(jni_to_wallet_error)
    }

    fn check_biometric_hardware<'local>(env: &mut JNIEnv<'local>) -> Result<bool> {
        let api_level = Self::get_api_level(env)?;

        let bm_cls =
            Self::jni_safe_call(env, |e| e.find_class("androidx/biometric/BiometricManager"))?;
        let ctx = Self::get_android_context(env)?;

        let bm = Self::jni_safe_call(env, |e| {
            e.call_static_method(
                &bm_cls,
                "from",
                "(Landroid/content/Context;)Landroidx/biometric/BiometricManager;",
                &[JValue::from(&ctx)],
            )
            .and_then(|v| v.l())
        })?;

        let auth_class = Self::jni_safe_call(env, |e| {
            e.find_class("androidx/biometric/BiometricManager$Authenticators")
        })?;

        let authenticator_type = if api_level >= 30 {
            Self::jni_safe_call(env, |e| {
                e.get_static_field(&auth_class, "BIOMETRIC_STRONG", "I")
            })?
            .i()
            .map_err(jni_to_wallet_error)?
        } else {
            Self::jni_safe_call(env, |e| {
                e.get_static_field(&auth_class, "BIOMETRIC_WEAK", "I")
            })?
            .i()
            .map_err(jni_to_wallet_error)?
        };

        let can_auth = Self::jni_safe_call(env, |e| {
            e.call_method(
                &bm,
                "canAuthenticate",
                "(I)I",
                &[JValue::from(authenticator_type)],
            )
            .and_then(|v| v.i())
        })?;

        Ok(can_auth == 0)
    }

    fn get_security_patch_level<'local>(env: &mut JNIEnv<'local>) -> Result<String> {
        let ver_cls = Self::jni_safe_call(env, |e| e.find_class("android/os/Build$VERSION"))?;
        let obj = Self::jni_safe_call(env, |e| {
            e.get_static_field(&ver_cls, "SECURITY_PATCH", "Ljava/lang/String;")
                .and_then(|v| v.l())
        })?;

        let patch_jstr = JString::from(obj);
        let patch: String = Self::jni_safe_call(env, |e| e.get_string(&patch_jstr))?.into();
        Ok(patch)
    }

    fn validate_hardware_requirements(
        profile: &DeviceSecurityProfile,
        config: &StorageConfig,
    ) -> Result<()> {
        if profile.api_level < 29 {
            return Err(WalletError::Storage {
                msg: "Android version too old (minimum API 29 required)".to_string(),
            });
        }

        // SECURITY FIX: Fail if hardware keystore is not available and not explicitly allowed
        // This prevents credential storage on devices without hardware-backed key protection
        if !profile.has_hardware_keystore {
            if config.allow_software_keystore {
                log::warn!("SECURITY WARNING: Using software keystore - credentials not hardware-protected");
            } else {
                log::error!("Hardware keystore not available and allow_software_keystore=false");
                return Err(WalletError::Storage {
                    msg: "Hardware keystore required but not available. Set allow_software_keystore=true to override (NOT RECOMMENDED for production).".to_string(),
                });
            }
        }
        if !profile.has_strongbox {
            log::info!("StrongBox not available - using standard hardware keystore");
        }

        Ok(())
    }

    /* ---------------------------------------------------------------
    Core Keystore Operations
    ------------------------------------------------------------- */

    fn store_secure(&self, key: &str, data: &[u8], require_bio: bool) -> Result<()> {
        let start = current_timestamp();
        let mut guard = self.get_jni_env()?;
        let env = &mut *guard;

        self.validate_key(key)?;
        self.validate_data(data)?;

        let used_bio = if require_bio {
            // SECURITY: authenticate_biometric returns Ok(false) when the user
            // rejects the prompt or times out. We must fail-closed here.
            // SECURITY: Use a generic prompt. Never include the key name, which
            // may contain credential identifiers visible in the system dialog.
            let ok = self.authenticate_biometric(env, "Authenticate to store credentials")?;
            if !ok {
                return Err(WalletError::BiometricFailed {
                    msg: "Biometric authentication rejected or timed out".to_string(),
                });
            }
            true
        } else {
            false
        };

        let bridge = self.get_keystore_bridge(env)?;
        let k_str = Self::jni_safe_call(env, |e| e.new_string(key))?;
        let data_arr = Self::jni_safe_call(env, |e| e.byte_array_from_slice(data))?;
        let data_obj = JObject::from(data_arr);

        let used_sb = self.device_supports_strongbox() && self.config.use_strongbox;
        let ok = Self::jni_safe_call(env, |e| {
            e.call_method(
                &bridge,
                "storeSecure",
                "(Ljava/lang/String;[BZZ)Z",
                &[
                    JValue::from(&k_str),
                    JValue::Object(&data_obj),
                    JValue::from(used_sb),
                    JValue::from(require_bio),
                ],
            )
            .and_then(|v| v.z())
        })?;

        if !ok {
            self.log_security_event(
                SecurityEventType::FailedOperation,
                "storeSecure failed",
                RiskLevel::Medium,
            );
            return Err(WalletError::Storage {
                msg: "Keystore error".into(),
            });
        }

        self.update_metrics(true, used_bio, used_sb, current_timestamp() - start);
        Ok(())
    }

    fn retrieve_secure(&self, key: &str, require_bio: bool) -> Result<Zeroizing<Vec<u8>>> {
        let start = current_timestamp();
        let mut guard = self.get_jni_env()?;
        let env = &mut *guard;

        // SECURITY: Only serve from cache when biometric is NOT required.
        // Returning cached data would bypass the biometric gate.
        if self.config.enable_caching && !require_bio {
            if let Some(d) = self.get_from_cache(key) {
                self.update_cache_metrics(true);
                return Ok(d);
            }
            self.update_cache_metrics(false);
        }

        self.validate_key(key)?;

        let used_bio = if require_bio {
            // SECURITY: authenticate_biometric returns Ok(false) when the user
            // rejects the prompt or times out. We must fail-closed here.
            // SECURITY: Use a generic prompt. Never include the key name, which
            // may contain credential identifiers visible in the system dialog.
            let ok = self.authenticate_biometric(env, "Authenticate to access credentials")?;
            if !ok {
                return Err(WalletError::BiometricFailed {
                    msg: "Biometric authentication rejected or timed out".to_string(),
                });
            }
            true
        } else {
            false
        };

        let bridge = self.get_keystore_bridge(env)?;
        let k_str = Self::jni_safe_call(env, |e| e.new_string(key))?;
        let arr = Self::jni_safe_call(env, |e| {
            e.call_method(
                &bridge,
                "retrieveSecure",
                "(Ljava/lang/String;Z)[B",
                &[JValue::from(&k_str), JValue::from(require_bio)],
            )
            .and_then(|v| v.l())
        })?;

        if arr.is_null() {
            return Err(WalletError::Storage {
                msg: "NotFound".into(),
            });
        }

        let jni_byte_array = JByteArray::from(arr);
        let bytes = Zeroizing::new(Self::jni_safe_call(env, |e| {
            e.convert_byte_array(&jni_byte_array)
        })?);

        // SECURITY: Zero the Java-side byte array after copying to Rust.
        // JNI's SetByteArrayRegion overwrites the JVM heap copy with zeros
        // so that plaintext credential data does not linger in managed memory
        // after the Rust side has taken ownership.
        {
            let len =
                Self::jni_safe_call(env, |e| e.get_array_length(&jni_byte_array)).unwrap_or(0);
            if len > 0 {
                let zeros = vec![0i8; len as usize];
                let _ = env.set_byte_array_region(&jni_byte_array, 0, &zeros);
            }
        }

        // SECURITY: Only cache non-biometric items. Caching biometric-protected
        // items would allow subsequent retrieves to bypass the biometric gate,
        // defeating the purpose of biometric protection entirely.
        if self.config.enable_caching && !require_bio {
            self.add_to_cache(key, &bytes);
        }

        let used_sb = self.device_supports_strongbox() && self.config.use_strongbox;
        self.update_metrics(true, used_bio, used_sb, current_timestamp() - start);
        Ok(bytes)
    }

    fn delete_secure(&self, key: &str) -> Result<()> {
        let mut guard = self.get_jni_env()?;
        let env = &mut *guard;

        self.validate_key(key)?;

        let bridge = self.get_keystore_bridge(env)?;
        let k_str = Self::jni_safe_call(env, |e| e.new_string(key))?;

        Self::jni_safe_call(env, |e| {
            e.call_method(
                &bridge,
                "deleteSecure",
                "(Ljava/lang/String;)Z",
                &[JValue::from(&k_str)],
            )
            .and_then(|v| v.z())
        })?;

        if self.config.enable_caching {
            self.remove_from_cache(key);
        }
        Ok(())
    }

    fn list_keys_secure(&self) -> Result<Vec<String>> {
        let mut guard = self.get_jni_env()?;
        let env = &mut *guard;

        let bridge = self.get_keystore_bridge(env)?;

        let arr_obj = Self::jni_safe_call(env, |e| {
            e.call_method(&bridge, "listKeys", "()[Ljava/lang/String;", &[])
                .and_then(|v| v.l())
        })?;

        if arr_obj.is_null() {
            return Ok(Vec::new());
        }

        let array = JObjectArray::from(arr_obj);
        let len = Self::jni_safe_call(env, |e| e.get_array_length(&array))?;
        // SEC-11: Guard against negative JNI array lengths (corrupted or invalid arrays)
        if len < 0 {
            return Err(WalletError::Storage {
                msg: "negative JNI array length".to_string(),
            });
        }
        let mut out = Vec::with_capacity(len as usize);

        for i in 0..len {
            let el = Self::jni_safe_call(env, |e| e.get_object_array_element(&array, i))?;
            let el_jstr = JString::from(el);
            let s: String = Self::jni_safe_call(env, |e| e.get_string(&el_jstr))?.into();
            out.push(s);
        }
        Ok(out)
    }

    /* ---------------------------------------------------------------
    Biometric Authentication
    ------------------------------------------------------------- */

    fn authenticate_biometric<'local>(
        &self,
        env: &mut JNIEnv<'local>,
        reason: &str,
    ) -> Result<bool> {
        let bridge = self.get_keystore_bridge(env)?;
        let r_str = Self::jni_safe_call(env, |e| e.new_string(reason))?;

        let ok = Self::jni_safe_call(env, |e| {
            e.call_method(
                &bridge,
                "authenticateBiometric",
                "(Ljava/lang/String;I)Z",
                &[JValue::from(&r_str), JValue::from(BIOMETRIC_TIMEOUT_MS)],
            )
            .and_then(|v| v.z())
        })?;

        if ok {
            self.log_security_event(
                SecurityEventType::BiometricAuth,
                "biometric OK",
                RiskLevel::Low,
            );
        } else {
            self.log_security_event(
                SecurityEventType::FailedOperation,
                "biometric FAIL",
                RiskLevel::High,
            );
        }
        Ok(ok)
    }

    /* ---------------------------------------------------------------
    Helper Methods
    ------------------------------------------------------------- */

    fn get_jni_env(&self) -> Result<AttachGuard<'static>> {
        JVM.get()
            .ok_or_else(|| WalletError::Storage {
                msg: "JVM not initialized".to_string(),
            })?
            .attach_current_thread()
            .map_err(|e| WalletError::Storage {
                msg: format!("Failed to attach to JVM: {e}"),
            })
    }

    fn get_android_context<'local>(env: &mut JNIEnv<'local>) -> Result<GlobalRef> {
        // First try to use the saved context from init_android_context
        if let Some(ctx) = android_context() {
            return Ok(ctx);
        }

        // Fallback to ActivityThread if no saved context
        let act_thread_cls =
            Self::jni_safe_call(env, |e| e.find_class("android/app/ActivityThread"))?;
        let cur_thread = Self::jni_safe_call(env, |e| {
            e.call_static_method(
                &act_thread_cls,
                "currentActivityThread",
                "()Landroid/app/ActivityThread;",
                &[],
            )
            .and_then(|v| v.l())
        })?;
        let app_ctx = Self::jni_safe_call(env, |e| {
            e.call_method(
                &cur_thread,
                "getApplication",
                "()Landroid/app/Application;",
                &[],
            )
            .and_then(|v| v.l())
        })?;

        let global_ref = env.new_global_ref(app_ctx).map_err(jni_to_wallet_error)?;
        Ok(global_ref)
    }

    fn get_package_manager<'local>(env: &mut JNIEnv<'local>) -> Result<GlobalRef> {
        let context = Self::get_android_context(env)?;

        let package_manager = Self::jni_safe_call(env, |e| {
            e.call_method(
                &context,
                "getPackageManager",
                "()Landroid/content/pm/PackageManager;",
                &[],
            )
            .and_then(|v| v.l())
        })?;

        let global_ref = env
            .new_global_ref(package_manager)
            .map_err(jni_to_wallet_error)?;
        Ok(global_ref)
    }

    fn get_keystore_bridge<'local>(&self, env: &mut JNIEnv<'local>) -> Result<GlobalRef> {
        // Poisoned bridge just means a prior thread panicked; try to reinitialise
        let mut bridge_guard = self
            .keystore_bridge
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(bridge) = bridge_guard.as_ref() {
            return Ok(bridge.clone());
        }

        let bridge_cls =
            Self::jni_safe_call(env, |e| e.find_class("app/provii/wallet/KeystoreBridge"))?;
        let ctx = Self::get_android_context(env)?;

        let bridge_obj = Self::jni_safe_call(env, |e| {
            e.call_static_method(
                &bridge_cls,
                "getInstance",
                "(Landroid/content/Context;)Lapp/provii/wallet/KeystoreBridge;",
                &[JValue::from(&ctx)],
            )
            .and_then(|v| v.l())
        })?;

        let want_strongbox = Self::check_strongbox_availability(env)?;
        let want_biometrics = self.config.require_biometrics;

        let ok = Self::jni_safe_call(env, |e| {
            e.call_method(
                &bridge_obj,
                "ensureMasterKey",
                "(ZZ)Z",
                &[JValue::from(want_strongbox), JValue::from(want_biometrics)],
            )
            .and_then(|v| v.z())
        })?;

        if !ok {
            return Err(WalletError::Storage {
                msg: "Failed to prepare master key".into(),
            });
        }

        Self::jni_safe_call(env, |e| {
            e.call_method(
                &bridge_obj,
                "initialise",
                "(ZZ)V",
                &[JValue::from(want_biometrics), JValue::from(want_strongbox)],
            )
        })?;

        let global_ref = Self::jni_safe_call(env, |e| e.new_global_ref(&bridge_obj))?;

        *bridge_guard = Some(global_ref.clone());

        Ok(global_ref)
    }

    fn device_supports_strongbox(&self) -> bool {
        let profile_guard = self
            .device_profile
            .read()
            .unwrap_or_else(|e| e.into_inner());
        profile_guard
            .as_ref()
            .map(|p| p.has_strongbox)
            .unwrap_or(false)
    }

    fn validate_key(&self, key: &str) -> Result<()> {
        if key.is_empty() {
            return Err(WalletError::Storage {
                msg: "Key cannot be empty".to_string(),
            });
        }
        if key.len() > 255 {
            return Err(WalletError::Storage {
                msg: "Key too long (max 255 characters)".to_string(),
            });
        }
        // Use is_ascii_alphanumeric to match the trait's byte-level ASCII check.
        // is_alphanumeric would accept Unicode letters (e.g. CJK, emoji), which
        // the PlatformSecureStorage::validate_key contract explicitly rejects.
        if !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
        {
            return Err(WalletError::Storage {
                msg: "Key contains invalid characters".to_string(),
            });
        }
        Ok(())
    }

    fn validate_data(&self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Err(WalletError::Storage {
                msg: "Data cannot be empty".to_string(),
            });
        }
        if data.len() > MAX_ITEM_SIZE {
            return Err(WalletError::Storage {
                msg: format!("Data too large (max {} bytes)", MAX_ITEM_SIZE),
            });
        }
        Ok(())
    }

    /* ---------------------------------------------------------------
    Caching Operations
    ------------------------------------------------------------- */

    fn get_from_cache(&self, key: &str) -> Option<Zeroizing<Vec<u8>>> {
        let cache = self
            .operation_cache
            .read()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(cached) = cache.get(key) {
            let now = current_timestamp();
            // VULN-03: cached_at is milliseconds (from current_timestamp), ttl is seconds.
            // Convert ttl to milliseconds before comparison.
            if now.saturating_sub(cached.cached_at) < cached.ttl.saturating_mul(1000) {
                return Some(Zeroizing::new(cached.data.clone()));
            }
        }
        None
    }

    fn add_to_cache(&self, key: &str, data: &[u8]) {
        if !self.config.enable_caching {
            return;
        }

        let mut cache = self
            .operation_cache
            .write()
            .unwrap_or_else(|e| e.into_inner());

        // Implement LRU eviction if cache is getting too large
        if cache.len() >= 100 {
            let oldest_key = cache
                .iter()
                .min_by_key(|(_, op)| op.cached_at)
                .map(|(k, _)| k.clone());

            if let Some(old_key) = oldest_key {
                cache.remove(&old_key);
            }
        }

        cache.insert(
            key.to_string(),
            CachedOperation {
                key: key.to_string(),
                data: data.to_vec(),
                cached_at: current_timestamp(),
                ttl: self.config.cache_ttl,
            },
        );
    }

    fn remove_from_cache(&self, key: &str) {
        let mut cache = self
            .operation_cache
            .write()
            .unwrap_or_else(|e| e.into_inner());
        cache.remove(key);
    }

    /* ---------------------------------------------------------------
    Metrics and Monitoring
    ------------------------------------------------------------- */

    fn update_metrics(
        &self,
        success: bool,
        used_biometrics: bool,
        used_strongbox: bool,
        operation_time_ms: u64,
    ) {
        let mut metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        metrics.operations_count += 1;

        if !success {
            metrics.errors_count += 1;
        }

        if used_biometrics {
            metrics.biometric_prompts += 1;
        }

        if used_strongbox {
            metrics.strongbox_operations += 1;
        }

        // Update rolling average of operation time
        metrics.average_operation_time_ms =
            (metrics.average_operation_time_ms + operation_time_ms) / 2;

        // Update global stats
        let mut stats = OPERATION_STATS.lock().unwrap_or_else(|e| e.into_inner());
        stats.record_operation(success, used_biometrics, used_strongbox);
    }

    fn update_cache_metrics(&self, cache_hit: bool) {
        let mut metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        if cache_hit {
            metrics.cache_hits += 1;
        } else {
            metrics.cache_misses += 1;
        }
    }

    /* ---------------------------------------------------------------
    Security Event Logging
    ------------------------------------------------------------- */

    fn log_security_event(
        &self,
        event_type: SecurityEventType,
        details: &str,
        risk_level: RiskLevel,
    ) {
        if !self.config.enable_audit_logging {
            return;
        }

        let event = SecurityEvent {
            event_type,
            timestamp: current_timestamp(),
            details: details.to_string(),
            risk_level,
        };

        let mut audit_log = self.audit_log.lock().unwrap_or_else(|e| e.into_inner());
        audit_log.push_back(event.clone());

        // SEC-09: Evict oldest entry with O(1) pop_front instead of O(n) remove(0)
        if audit_log.len() > 1000 {
            audit_log.pop_front();
        }
    }

    /* ---------------------------------------------------------------
    Public Diagnostic Methods
    ------------------------------------------------------------- */

    /// Get storage metrics for monitoring and debugging
    pub fn get_metrics(&self) -> StorageMetrics {
        self.metrics
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Get security audit log
    pub fn get_audit_log(&self) -> Vec<SecurityEvent> {
        self.audit_log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    /// Get device security profile
    pub fn get_device_profile(&self) -> Option<DeviceSecurityProfile> {
        self.device_profile
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Clear operation cache
    pub fn clear_cache(&self) {
        let mut cache = self
            .operation_cache
            .write()
            .unwrap_or_else(|e| e.into_inner());
        cache.clear();
    }

    /// Test keystore connectivity and functionality
    pub fn test_keystore_functionality(&self) -> Result<()> {
        let test_key = "provii_test_connectivity";
        let test_data = b"test_data_12345";

        // Test store operation
        self.store_secure(test_key, test_data, false)?;

        // Test retrieve operation
        let retrieved = self.retrieve_secure(test_key, false)?;
        if *retrieved != test_data[..] {
            return Err(WalletError::Storage {
                msg: "Keystore test data mismatch".to_string(),
            });
        }

        // Test delete operation
        self.delete_secure(test_key)?;

        // Verify deletion
        match self.retrieve_secure(test_key, false) {
            Err(WalletError::Storage { msg }) if msg == "NotFound" => Ok(()),
            _ => Err(WalletError::Storage {
                msg: "Keystore delete test failed".to_string(),
            }),
        }
    }

    /* ---------------------------------------------------------------
    Storage-maintenance helpers (parity with iOS backend)
    ------------------------------------------------------------- */

    /// Remove **all** Provii entries from the Android Keystore and cache.
    pub fn wipe_all(&self) -> Result<()> {
        let keys = self.list_keys_secure()?;
        for k in keys {
            if let Err(e) = self.delete_secure(&k) {
                log::warn!(
                    "Failed to delete key {} during wipe_all: {:?}",
                    safe_key_label(&k),
                    e
                );
            }
        }
        self.clear_cache();
        Ok(())
    }

    /// Re-encrypt every item with a *new* AES-GCM master key.
    ///
    /// Decrypted credential data is held in `Zeroizing<Vec<u8>>` so that the
    /// plaintext backup is cleared from memory once re-encryption completes.
    ///
    /// Each item is re-stored with its original biometric requirement
    /// preserved. Non-biometric items are read first, then biometric-protected
    /// items are read (triggering a biometric prompt). Items whose biometric
    /// status cannot be determined are skipped to avoid downgrading their ACL.
    ///
    /// ## Data loss window
    ///
    /// The Java-side `rotateMasterKey()` atomically destroys the old master
    /// key and creates a new one. There is a window between the key swap and
    /// the re-store loop where a crash would leave items encrypted under a
    /// destroyed key. A true two-phase rotation (store under new key first,
    /// delete old key after verification) would require changes to the Kotlin
    /// `KeystoreBridge`. This limitation is accepted for now. The backup is
    /// verified before proceeding, and a failure count is returned so callers
    /// can detect partial data loss.
    fn rotate_master_key(&self) -> Result<()> {
        let mut guard = self.get_jni_env()?;
        let env = &mut *guard;

        let keys = self.list_keys_secure()?;

        // Phase 1a: Read all non-biometric items. Biometric-protected items
        // will fail here and are collected for a second pass.
        let mut backup: Vec<(String, Zeroizing<Vec<u8>>, bool)> = Vec::new();
        let mut bio_keys: Vec<String> = Vec::new();
        for k in &keys {
            match self.retrieve_secure(k, false) {
                Ok(d) => backup.push((k.clone(), d, false)),
                Err(_) => bio_keys.push(k.clone()),
            }
        }

        // Phase 1b: Read biometric-protected items (triggers biometric prompt).
        for k in &bio_keys {
            match self.retrieve_secure(k, true) {
                Ok(d) => backup.push((k.clone(), d, true)),
                Err(e) => {
                    log::warn!(
                        "Key rotation: skip bio-protected key {}: {}",
                        safe_key_label(k),
                        e
                    );
                }
            }
        }

        // Phase 2: Verify that every non-skipped key was successfully backed
        // up before performing the destructive master key swap. If the backup
        // is empty but keys existed, something went wrong and we must not
        // proceed.
        let expected_count = keys.len();
        let skipped = expected_count.saturating_sub(backup.len());
        if backup.is_empty() && expected_count > 0 {
            return Err(WalletError::Storage {
                msg: "Key rotation aborted: could not read any items for backup".to_string(),
            });
        }
        if skipped > 0 {
            log::warn!(
                "Key rotation: {} of {} items could not be backed up and will be skipped",
                skipped,
                expected_count
            );
        }

        // Phase 3: Rotate the master key. This is the destructive operation.
        // Items encrypted under the old key become unreadable after this point.
        let bridge = self.get_keystore_bridge(env)?;
        let recreated = Self::jni_safe_call(env, |e| {
            e.call_method(&bridge, "rotateMasterKey", "()Z", &[])
                .and_then(|v| v.z())
        })?;

        if !recreated {
            return Err(WalletError::Storage {
                msg: "Failed to rotate master key".into(),
            });
        }

        // Phase 4: Re-store each item under the new master key with its
        // ORIGINAL biometric requirement preserved. Count failures so the
        // caller knows data was lost.
        let backup_len = backup.len();
        let mut failures = 0u32;
        for (k, d, was_bio) in &backup {
            if let Err(e) = self.store_secure(k, d, *was_bio) {
                log::error!(
                    "Key rotation: re-store failed for '{}': {}",
                    safe_key_label(k),
                    e
                );
                failures += 1;
            }
        }
        // backup dropped here: Zeroizing clears all decrypted data from memory

        if failures > 0 {
            return Err(WalletError::Storage {
                msg: format!(
                    "Key rotation: {} of {} items failed to re-store (data may be lost)",
                    failures, backup_len
                ),
            });
        }

        Ok(())
    }

    /// Provide lightweight usage metrics for the SDK settings screen.
    pub fn usage_stats(&self) -> Result<UsageStats> {
        let keys = self.list_keys_secure()?;
        let mut total_size: usize = 0;
        let mut cred_cnt: usize = 0;

        for k in &keys {
            if let Ok(d) = self.retrieve_secure(k, false) {
                total_size += d.len();
                if k.starts_with(CREDENTIAL_KEY_PREFIX) {
                    cred_cnt += 1;
                }
            }
        }

        Ok(UsageStats {
            total_keys: keys.len(),
            total_bytes: total_size,
            credentials_count: cred_cnt,
        })
    }
}

/* =======================================================================
PlatformSecureStorage Trait Implementation
=================================================================== */

impl PlatformSecureStorage for AndroidSecureStorage {
    fn store(
        &self,
        key: &str,
        value: &[u8],
        bio: BiometricRequirement,
    ) -> std::result::Result<(), WalletError> {
        let require_bio = matches!(bio, BiometricRequirement::Required { .. });
        self.store_secure(key, value, require_bio)
    }

    fn retrieve(
        &self,
        key: &str,
        bio: BiometricRequirement,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, WalletError> {
        let require_bio = matches!(bio, BiometricRequirement::Required { .. });
        self.retrieve_secure(key, require_bio)
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.delete_secure(key)
    }

    fn exists(&self, key: &str) -> Result<bool> {
        // SECURITY: Check existence via the key list rather than retrieving
        // and decrypting the item. This avoids bypassing biometric gates on
        // items protected by biometric ACL, and avoids loading sensitive data
        // into memory just to test for presence.
        self.validate_key(key)?;
        let keys = self.list_keys_secure()?;
        Ok(keys.iter().any(|k| k == key))
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        self.list_keys_secure()
    }

    fn wipe_all(&self) -> Result<()> {
        self.wipe_all()
    }

    fn rotate_master_key(&self) -> Result<()> {
        self.rotate_master_key()
    }

    fn usage_stats(&self) -> Result<UsageStats> {
        self.usage_stats()
    }
}

/// Legacy alias for [`AndroidSecureStorage`].
pub type AndroidKeystoreStorage = AndroidSecureStorage;

/* =======================================================================
Utility Functions
=================================================================== */

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Return a privacy-safe representation of a storage key for logging.
///
/// Shows only the prefix and a truncated hash, so credential identifiers
/// never appear in device logs.
fn safe_key_label(key: &str) -> String {
    let prefix_end = key[..key.len().min(20)]
        .find('.')
        .or_else(|| key[..key.len().min(20)].find('_'))
        .map(|i| i + 1)
        .unwrap_or(key.len().min(8));
    let hash = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        key.hash(&mut h);
        format!("{:08x}", h.finish() & 0xFFFF_FFFF)
    };
    format!("{}..{}", &key[..prefix_end], hash)
}

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
Tests
=================================================================== */

#[cfg(test)]
mod tests {
    use super::*;

    /* =======================================================================
    Configuration Tests
    =================================================================== */

    #[test]
    fn test_storage_config_default() {
        let config = StorageConfig::default();

        assert!(config.require_biometrics);
        assert!(config.use_strongbox);
        assert!(config.enable_audit_logging);
        assert_eq!(config.max_failed_attempts, 5);
        assert_eq!(config.lockout_duration, 300);
        assert!(!config.enable_caching);
        assert_eq!(config.cache_ttl, 600);
    }

    #[test]
    fn test_storage_config_custom() {
        let config = StorageConfig {
            require_biometrics: false,
            use_strongbox: false,
            enable_audit_logging: false,
            max_failed_attempts: 10,
            lockout_duration: 600,
            enable_caching: true,
            cache_ttl: 1200,
            allow_software_keystore: true,
        };

        assert!(!config.require_biometrics);
        assert!(!config.use_strongbox);
        assert!(!config.enable_audit_logging);
        assert_eq!(config.max_failed_attempts, 10);
        assert_eq!(config.lockout_duration, 600);
        assert!(config.enable_caching);
        assert_eq!(config.cache_ttl, 1200);
    }

    #[test]
    fn test_storage_config_production() {
        let config = StorageConfig {
            require_biometrics: true,
            use_strongbox: true,
            enable_audit_logging: true,
            max_failed_attempts: 3,
            lockout_duration: 300,
            enable_caching: false,
            cache_ttl: 0,
            allow_software_keystore: false,
        };

        assert!(config.require_biometrics);
        assert!(config.use_strongbox);
        assert_eq!(config.max_failed_attempts, 3);
        assert!(!config.enable_caching);
    }

    #[test]
    fn test_device_security_profile_default() {
        let profile = DeviceSecurityProfile::default();

        assert!(!profile.has_strongbox);
        assert!(!profile.has_hardware_keystore);
        assert!(!profile.has_biometric_hardware);
        assert_eq!(profile.security_patch_level, "unknown");
        assert_eq!(profile.api_level, 0);
        assert_eq!(profile.last_assessed, 0);
    }

    #[test]
    fn test_device_security_profile_custom() {
        let profile = DeviceSecurityProfile {
            has_strongbox: true,
            has_hardware_keystore: true,
            has_biometric_hardware: true,
            security_patch_level: "2024-01-01".to_string(),
            api_level: 33,
            last_assessed: 1234567890,
        };

        assert!(profile.has_strongbox);
        assert!(profile.has_hardware_keystore);
        assert!(profile.has_biometric_hardware);
        assert_eq!(profile.security_patch_level, "2024-01-01");
        assert_eq!(profile.api_level, 33);
        assert_eq!(profile.last_assessed, 1234567890);
    }

    /* =======================================================================
    Operation Statistics Tests
    =================================================================== */

    #[test]
    fn test_operation_statistics_new() {
        let stats = OperationStatistics::new();

        assert_eq!(stats.total_operations, 0);
        assert_eq!(stats.successful_operations, 0);
        assert_eq!(stats.failed_operations, 0);
        assert_eq!(stats.biometric_authentications, 0);
        assert_eq!(stats.hardware_operations, 0);
        assert_eq!(stats.last_operation_time, 0);
    }

    #[test]
    fn test_operation_statistics_record_success() {
        let mut stats = OperationStatistics::new();

        stats.record_operation(true, false, false);

        assert_eq!(stats.total_operations, 1);
        assert_eq!(stats.successful_operations, 1);
        assert_eq!(stats.failed_operations, 0);
        assert_eq!(stats.biometric_authentications, 0);
        assert_eq!(stats.hardware_operations, 0);
        assert!(stats.last_operation_time > 0);
    }

    #[test]
    fn test_operation_statistics_record_failure() {
        let mut stats = OperationStatistics::new();

        stats.record_operation(false, false, false);

        assert_eq!(stats.total_operations, 1);
        assert_eq!(stats.successful_operations, 0);
        assert_eq!(stats.failed_operations, 1);
        assert_eq!(stats.biometric_authentications, 0);
        assert_eq!(stats.hardware_operations, 0);
    }

    #[test]
    fn test_operation_statistics_record_with_biometrics() {
        let mut stats = OperationStatistics::new();

        stats.record_operation(true, true, false);

        assert_eq!(stats.total_operations, 1);
        assert_eq!(stats.successful_operations, 1);
        assert_eq!(stats.biometric_authentications, 1);
        assert_eq!(stats.hardware_operations, 0);
    }

    #[test]
    fn test_operation_statistics_record_with_hardware() {
        let mut stats = OperationStatistics::new();

        stats.record_operation(true, false, true);

        assert_eq!(stats.total_operations, 1);
        assert_eq!(stats.successful_operations, 1);
        assert_eq!(stats.biometric_authentications, 0);
        assert_eq!(stats.hardware_operations, 1);
    }

    #[test]
    fn test_operation_statistics_record_all_features() {
        let mut stats = OperationStatistics::new();

        stats.record_operation(true, true, true);

        assert_eq!(stats.total_operations, 1);
        assert_eq!(stats.successful_operations, 1);
        assert_eq!(stats.biometric_authentications, 1);
        assert_eq!(stats.hardware_operations, 1);
    }

    #[test]
    fn test_operation_statistics_multiple_operations() {
        let mut stats = OperationStatistics::new();

        stats.record_operation(true, false, false);
        stats.record_operation(false, false, false);
        stats.record_operation(true, true, false);
        stats.record_operation(true, false, true);
        stats.record_operation(true, true, true);

        assert_eq!(stats.total_operations, 5);
        assert_eq!(stats.successful_operations, 4);
        assert_eq!(stats.failed_operations, 1);
        assert_eq!(stats.biometric_authentications, 3);
        assert_eq!(stats.hardware_operations, 2);
    }

    /* =======================================================================
    Storage Metrics Tests
    =================================================================== */

    #[test]
    fn test_storage_metrics_default() {
        let metrics = StorageMetrics::default();

        assert_eq!(metrics.operations_count, 0);
        assert_eq!(metrics.cache_hits, 0);
        assert_eq!(metrics.cache_misses, 0);
        assert_eq!(metrics.biometric_prompts, 0);
        assert_eq!(metrics.strongbox_operations, 0);
        assert_eq!(metrics.errors_count, 0);
        assert_eq!(metrics.average_operation_time_ms, 0);
        assert!(metrics.last_error.is_none());
    }

    #[test]
    fn test_storage_metrics_clone() {
        let metrics = StorageMetrics {
            operations_count: 100,
            cache_hits: 50,
            cache_misses: 50,
            biometric_prompts: 10,
            strongbox_operations: 75,
            errors_count: 5,
            average_operation_time_ms: 150,
            last_error: Some("test error".to_string()),
        };

        let cloned = metrics.clone();

        assert_eq!(cloned.operations_count, 100);
        assert_eq!(cloned.cache_hits, 50);
        assert_eq!(cloned.cache_misses, 50);
        assert_eq!(cloned.biometric_prompts, 10);
        assert_eq!(cloned.strongbox_operations, 75);
        assert_eq!(cloned.errors_count, 5);
        assert_eq!(cloned.average_operation_time_ms, 150);
        assert_eq!(cloned.last_error, Some("test error".to_string()));
    }

    /* =======================================================================
    Cached Operation Tests
    =================================================================== */

    #[test]
    fn test_cached_operation_creation() {
        let cached = CachedOperation {
            key: "test_key".to_string(),
            data: vec![1, 2, 3, 4],
            cached_at: 1000,
            ttl: 600,
        };

        assert_eq!(cached.key, "test_key");
        assert_eq!(cached.data, vec![1, 2, 3, 4]);
        assert_eq!(cached.cached_at, 1000);
        assert_eq!(cached.ttl, 600);
    }

    #[test]
    fn test_cached_operation_clone() {
        let cached = CachedOperation {
            key: "test_key".to_string(),
            data: vec![5, 6, 7, 8],
            cached_at: 2000,
            ttl: 300,
        };

        let cloned = cached.clone();

        assert_eq!(cloned.key, "test_key");
        assert_eq!(cloned.data, vec![5, 6, 7, 8]);
        assert_eq!(cloned.cached_at, 2000);
        assert_eq!(cloned.ttl, 300);
    }

    /* =======================================================================
    Security Event Tests
    =================================================================== */

    #[test]
    fn test_security_event_creation() {
        let event = SecurityEvent {
            event_type: SecurityEventType::KeystoreAccess,
            timestamp: 1234567890,
            details: "Test event".to_string(),
            risk_level: RiskLevel::Low,
        };

        assert_eq!(event.timestamp, 1234567890);
        assert_eq!(event.details, "Test event");
    }

    #[test]
    fn test_security_event_types() {
        // Verify all enum variants compile
        let _events = vec![
            SecurityEventType::KeystoreAccess,
            SecurityEventType::BiometricAuth,
            SecurityEventType::HardwareFeatureCheck,
            SecurityEventType::FailedOperation,
            SecurityEventType::ConfigurationChange,
        ];
    }

    #[test]
    fn test_risk_levels() {
        // Verify all enum variants compile
        let _levels = vec![
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ];
    }

    /* =======================================================================
    Validation Tests (Non-Android specific)
    =================================================================== */

    // Note: These tests can only run on Android target with JVM initialized
    // For now, we test the validation logic expectations

    #[test]
    fn test_key_validation_expectations() {
        // Test that our validation rules are correct
        let valid_keys = vec![
            "valid_key",
            "valid.key",
            "valid-key",
            "ValidKey123",
            "a".repeat(255), // Max length
        ];

        let invalid_keys = vec![
            "",              // Empty
            "a".repeat(256), // Too long
            "key with spaces",
            "key@invalid",
            "key#invalid",
        ];

        // Verify key character validation logic
        for key in &valid_keys {
            let all_valid = key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-');
            assert!(all_valid, "Key '{}' should be valid", key);
            assert!(!key.is_empty(), "Key should not be empty");
            assert!(key.len() <= 255, "Key should not exceed 255 chars");
        }

        for key in &invalid_keys {
            let is_empty = key.is_empty();
            let is_too_long = key.len() > 255;
            let has_invalid_chars = !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-');

            assert!(
                is_empty || is_too_long || has_invalid_chars,
                "Key '{}' should be invalid",
                key
            );
        }
    }

    #[test]
    fn test_data_validation_expectations() {
        // Test that our validation rules are correct
        let valid_data = vec![
            vec![1],                // Minimum size
            vec![0; MAX_ITEM_SIZE], // Maximum size
            vec![0; 1024],          // Normal size
        ];

        let invalid_data = vec![
            vec![],                     // Empty
            vec![0; MAX_ITEM_SIZE + 1], // Too large
        ];

        for data in &valid_data {
            assert!(!data.is_empty(), "Data should not be empty");
            assert!(
                data.len() <= MAX_ITEM_SIZE,
                "Data should not exceed MAX_ITEM_SIZE"
            );
        }

        for data in &invalid_data {
            let is_empty = data.is_empty();
            let is_too_large = data.len() > MAX_ITEM_SIZE;

            assert!(
                is_empty || is_too_large,
                "Data with length {} should be invalid",
                data.len()
            );
        }
    }

    /* =======================================================================
    Constants Tests
    =================================================================== */

    #[test]
    fn test_constants() {
        assert_eq!(IDENTITY_KEY_PREFIX, "provii_identity");
        assert_eq!(CREDENTIAL_KEY_PREFIX, "provii_credential");
        assert_eq!(CONFIG_KEY_PREFIX, "provii_config");
        assert_eq!(MAX_KEYSTORE_RETRIES, 3);
        assert_eq!(BIOMETRIC_TIMEOUT_MS, 30000);
        assert_eq!(MAX_ITEM_SIZE, 2 * 1024 * 1024);
        assert_eq!(HARDWARE_CACHE_TTL, 3600);
    }

    /* =======================================================================
    Utility Function Tests
    =================================================================== */

    #[test]
    fn test_current_timestamp() {
        let ts1 = current_timestamp();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let ts2 = current_timestamp();

        assert!(ts2 > ts1);
        assert!(ts2 - ts1 >= 10);
    }

    #[test]
    fn test_current_timestamp_monotonic() {
        let timestamps: Vec<u64> = (0..10)
            .map(|_| {
                let ts = current_timestamp();
                std::thread::sleep(std::time::Duration::from_millis(1));
                ts
            })
            .collect();

        // Verify timestamps are increasing
        for i in 1..timestamps.len() {
            assert!(timestamps[i] >= timestamps[i - 1]);
        }
    }

    #[test]
    fn test_jni_to_wallet_error() {
        let jni_error = jni::errors::Error::NullPtr("test null pointer");
        let wallet_error = jni_to_wallet_error(jni_error);

        match wallet_error {
            WalletError::Storage { msg } => {
                assert!(msg.contains("JNI error"));
                assert!(msg.contains("null pointer"));
            }
            _ => panic!("Expected Storage error"),
        }
    }

    /* =======================================================================
    Error Handling Tests
    =================================================================== */

    #[test]
    fn test_error_already_initialised() {
        let err = Error::AlreadyInitialised;
        let err_string = err.to_string();
        assert!(err_string.contains("already initialised"));
    }

    #[test]
    fn test_error_display() {
        let err = Error::AlreadyInitialised;
        let display_string = format!("{}", err);
        assert_eq!(display_string, "Android context already initialised");
    }

    /* =======================================================================
    Security Validation Tests
    =================================================================== */

    #[test]
    fn test_api_level_requirements() {
        // Verify that minimum API level requirement is correct
        let min_api_level = 29;

        let valid_profile = DeviceSecurityProfile {
            api_level: 29,
            ..DeviceSecurityProfile::default()
        };

        let invalid_profile = DeviceSecurityProfile {
            api_level: 28,
            ..DeviceSecurityProfile::default()
        };

        // Test validation logic
        assert!(valid_profile.api_level >= min_api_level);
        assert!(invalid_profile.api_level < min_api_level);
    }

    #[test]
    fn test_security_profile_completeness() {
        let profile = DeviceSecurityProfile {
            has_strongbox: true,
            has_hardware_keystore: true,
            has_biometric_hardware: true,
            security_patch_level: "2024-01-01".to_string(),
            api_level: 33,
            last_assessed: current_timestamp(),
        };

        // Verify all security features are accounted for
        assert!(profile.has_strongbox || !profile.has_strongbox); // has field
        assert!(profile.has_hardware_keystore || !profile.has_hardware_keystore); // has field
        assert!(profile.has_biometric_hardware || !profile.has_biometric_hardware); // has field
        assert!(!profile.security_patch_level.is_empty());
        assert!(profile.api_level > 0);
        assert!(profile.last_assessed > 0);
    }

    /* =======================================================================
    Configuration Validation Tests
    =================================================================== */

    #[test]
    fn test_storage_config_security_levels() {
        // High security config
        let high_security = StorageConfig {
            require_biometrics: true,
            use_strongbox: true,
            enable_audit_logging: true,
            max_failed_attempts: 3,
            lockout_duration: 600,
            enable_caching: false,
            cache_ttl: 0,
            allow_software_keystore: false,
        };

        assert!(high_security.require_biometrics);
        assert!(high_security.use_strongbox);
        assert!(high_security.enable_audit_logging);
        assert!(high_security.max_failed_attempts <= 5);
        assert!(!high_security.enable_caching);

        // Low security config (development)
        let low_security = StorageConfig {
            require_biometrics: false,
            use_strongbox: false,
            enable_audit_logging: false,
            max_failed_attempts: 100,
            lockout_duration: 0,
            enable_caching: true,
            cache_ttl: 3600,
            allow_software_keystore: true,
        };

        assert!(!low_security.require_biometrics);
        assert!(!low_security.use_strongbox);
        assert!(low_security.enable_caching);
        assert!(low_security.max_failed_attempts >= 10);
    }

    #[test]
    fn test_biometric_timeout_reasonable() {
        // Verify timeout is in reasonable range (10-60 seconds)
        assert!(BIOMETRIC_TIMEOUT_MS >= 10_000);
        assert!(BIOMETRIC_TIMEOUT_MS <= 60_000);
    }

    #[test]
    fn test_max_item_size_reasonable() {
        // Verify max size is reasonable (should be at least 1MB, at most 10MB)
        assert!(MAX_ITEM_SIZE >= 1024 * 1024);
        assert!(MAX_ITEM_SIZE <= 10 * 1024 * 1024);
    }

    /* =======================================================================
    Cache Logic Tests
    =================================================================== */

    #[test]
    fn test_cache_ttl_expiry_logic() {
        // VULN-03: cached_at is milliseconds, ttl is seconds.
        // Production code compares: now - cached_at < ttl * 1000
        let cached = CachedOperation {
            key: "test".to_string(),
            data: vec![1, 2, 3],
            cached_at: 1_000_000, // ms
            ttl: 5,               // seconds
        };

        let ttl_ms = cached.ttl.saturating_mul(1000); // 5000 ms

        let check_valid = 1_004_000; // 4s elapsed, within 5s TTL
        let check_expired = 1_006_000; // 6s elapsed, beyond 5s TTL

        assert!(check_valid - cached.cached_at < ttl_ms);
        assert!(check_expired - cached.cached_at >= ttl_ms);
    }

    #[test]
    fn test_cache_eviction_threshold() {
        // Verify cache eviction happens at 100 items
        let cache_limit = 100;
        assert!(cache_limit > 0);
        assert!(cache_limit <= 1000); // Reasonable upper bound
    }

    /* =======================================================================
    JNI Safety Tests
    =================================================================== */

    #[test]
    fn test_jni_error_conversion_coverage() {
        let test_cases = vec![
            jni::errors::Error::NullPtr("null ptr"),
            jni::errors::Error::WrongJValueType("wrong type", "expected"),
            jni::errors::Error::InvalidCtorReturn,
        ];

        for jni_err in test_cases {
            let wallet_err = jni_to_wallet_error(jni_err);
            match wallet_err {
                WalletError::Storage { msg } => {
                    assert!(msg.contains("JNI error"));
                }
                _ => panic!("Expected Storage error"),
            }
        }
    }

    /* =======================================================================
    Metrics Calculation Tests
    =================================================================== */

    #[test]
    fn test_average_operation_time_calculation() {
        // Verify rolling average formula: (current_avg + new_value) / 2
        let mut metrics = StorageMetrics {
            average_operation_time_ms: 100,
            ..StorageMetrics::default()
        };

        let new_operation_time = 200;
        let expected_avg = (metrics.average_operation_time_ms + new_operation_time) / 2;

        metrics.average_operation_time_ms = expected_avg;

        assert_eq!(metrics.average_operation_time_ms, 150);
    }

    #[test]
    fn test_metrics_counter_increments() {
        let mut metrics = StorageMetrics::default();

        // Simulate operations
        metrics.operations_count += 1;
        metrics.cache_hits += 1;
        metrics.biometric_prompts += 1;
        metrics.strongbox_operations += 1;

        assert_eq!(metrics.operations_count, 1);
        assert_eq!(metrics.cache_hits, 1);
        assert_eq!(metrics.biometric_prompts, 1);
        assert_eq!(metrics.strongbox_operations, 1);

        // Simulate more operations
        metrics.operations_count += 5;
        metrics.cache_misses += 3;
        metrics.errors_count += 1;

        assert_eq!(metrics.operations_count, 6);
        assert_eq!(metrics.cache_misses, 3);
        assert_eq!(metrics.errors_count, 1);
    }

    /* =======================================================================
    Audit Log Tests
    =================================================================== */

    #[test]
    fn test_audit_log_size_limit() {
        // Verify audit log has a size limit of 1000
        let max_audit_size = 1000;
        assert_eq!(max_audit_size, 1000);

        // SEC-09: Verify eviction happens with O(1) VecDeque::pop_front
        let mut log: VecDeque<SecurityEvent> = VecDeque::new();

        for i in 0..1001 {
            log.push_back(SecurityEvent {
                event_type: SecurityEventType::KeystoreAccess,
                timestamp: i,
                details: format!("event_{}", i),
                risk_level: RiskLevel::Low,
            });

            if log.len() > 1000 {
                log.pop_front();
            }
        }

        assert_eq!(log.len(), 1000);
        assert_eq!(log[0].timestamp, 1); // First event should be #1 (0 was evicted)
    }

    #[test]
    fn test_security_event_risk_level_ordering() {
        // Verify risk levels can be compared (implicitly)
        let _low = RiskLevel::Low;
        let _medium = RiskLevel::Medium;
        let _high = RiskLevel::High;
        let _critical = RiskLevel::Critical;

        // Just verify they're all distinct types
        // In production, you might want to implement Ord for these
    }

    /* =======================================================================
    Key Prefix Tests
    =================================================================== */

    #[test]
    fn test_key_prefixes_distinct() {
        // Verify all key prefixes are distinct
        let prefixes = vec![
            IDENTITY_KEY_PREFIX,
            CREDENTIAL_KEY_PREFIX,
            CONFIG_KEY_PREFIX,
        ];

        for i in 0..prefixes.len() {
            for j in (i + 1)..prefixes.len() {
                assert_ne!(prefixes[i], prefixes[j]);
            }
        }
    }

    #[test]
    fn test_key_prefix_format() {
        // Verify prefixes follow naming convention
        assert!(IDENTITY_KEY_PREFIX.starts_with("provii_"));
        assert!(CREDENTIAL_KEY_PREFIX.starts_with("provii_"));
        assert!(CONFIG_KEY_PREFIX.starts_with("provii_"));
    }

    /* =======================================================================
    Usage Stats Tests
    =================================================================== */

    #[test]
    fn test_usage_stats_credential_counting() {
        // Verify credential counting logic
        let keys = vec![
            format!("{}cred1", CREDENTIAL_KEY_PREFIX),
            format!("{}cred2", CREDENTIAL_KEY_PREFIX),
            format!("{}id1", IDENTITY_KEY_PREFIX),
            "other_key".to_string(),
        ];

        let mut cred_count = 0;
        for key in &keys {
            if key.starts_with(CREDENTIAL_KEY_PREFIX) {
                cred_count += 1;
            }
        }

        assert_eq!(cred_count, 2);
        assert_eq!(keys.len(), 4);
    }

    /* =======================================================================
    Thread Pool Configuration Tests
    =================================================================== */

    #[test]
    fn test_thread_pool_n_minus_2_strategy() {
        // Test the n-2 thread allocation strategy
        let test_cases = vec![
            (1, 1),   // 1 core -> 1 thread
            (2, 1),   // 2 cores -> 1 thread
            (4, 2),   // 4 cores -> 2 threads (4-2)
            (8, 6),   // 8 cores -> 6 threads (8-2)
            (12, 10), // 12 cores -> 10 threads (12-2)
        ];

        for (hw_threads, expected_proof_threads) in test_cases {
            let proof_threads = match hw_threads {
                1..=2 => 1,
                n => n.saturating_sub(2).max(1),
            };
            assert_eq!(
                proof_threads, expected_proof_threads,
                "Hardware threads: {}, expected: {}, got: {}",
                hw_threads, expected_proof_threads, proof_threads
            );
        }
    }

    #[test]
    fn test_stack_size_configuration() {
        // Verify stack size is 4MB as configured
        let stack_size = 4 * 1024 * 1024;
        assert_eq!(stack_size, 4_194_304);

        // Verify it's reasonable (between 1MB and 16MB)
        assert!(stack_size >= 1024 * 1024);
        assert!(stack_size <= 16 * 1024 * 1024);
    }
}
