// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Core Keystore operations, JNI plumbing, biometric authentication, and the
//! PlatformSecureStorage trait implementation for the Android backend.

use super::*;

impl AndroidSecureStorage {
    // Fixed jni_safe_call with explicit lifetime to match JNI objects
    pub(crate) fn jni_safe_call<'local, F, T>(env: &mut JNIEnv<'local>, f: F) -> Result<T>
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
    Core Keystore Operations
    ------------------------------------------------------------- */

    pub(crate) fn store_secure(&self, key: &str, data: &[u8], require_bio: bool) -> Result<()> {
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

    pub(crate) fn retrieve_secure(
        &self,
        key: &str,
        require_bio: bool,
    ) -> Result<Zeroizing<Vec<u8>>> {
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

    pub(crate) fn delete_secure(&self, key: &str) -> Result<()> {
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

    pub(crate) fn list_keys_secure(&self) -> Result<Vec<String>> {
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

    pub(crate) fn get_jni_env(&self) -> Result<AttachGuard<'static>> {
        JVM.get()
            .ok_or_else(|| WalletError::Storage {
                msg: "JVM not initialized".to_string(),
            })?
            .attach_current_thread()
            .map_err(|e| WalletError::Storage {
                msg: format!("Failed to attach to JVM: {e}"),
            })
    }

    pub(crate) fn get_android_context<'local>(env: &mut JNIEnv<'local>) -> Result<GlobalRef> {
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

    pub(crate) fn get_package_manager<'local>(env: &mut JNIEnv<'local>) -> Result<GlobalRef> {
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

    pub(crate) fn get_keystore_bridge<'local>(
        &self,
        env: &mut JNIEnv<'local>,
    ) -> Result<GlobalRef> {
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

/* =======================================================================
Utility Functions
=================================================================== */

pub(crate) fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Return a privacy-safe representation of a storage key for logging.
///
/// Shows only the prefix and a truncated hash, so credential identifiers
/// never appear in device logs.
pub(crate) fn safe_key_label(key: &str) -> String {
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
