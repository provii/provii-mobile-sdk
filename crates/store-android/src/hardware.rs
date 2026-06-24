// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Attestation-free hardware security feature assessment for the Android
//! Keystore backend.

use super::*;

impl AndroidSecureStorage {
    /* ---------------------------------------------------------------
    Hardware Feature Assessment (No Attestation)
    ------------------------------------------------------------- */

    pub(crate) fn assess_hardware_features<'local>(
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

    pub(crate) fn check_strongbox_availability<'local>(env: &mut JNIEnv<'local>) -> Result<bool> {
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

    pub(crate) fn validate_hardware_requirements(
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

    pub(crate) fn device_supports_strongbox(&self) -> bool {
        let profile_guard = self
            .device_profile
            .read()
            .unwrap_or_else(|e| e.into_inner());
        profile_guard
            .as_ref()
            .map(|p| p.has_strongbox)
            .unwrap_or(false)
    }
}
