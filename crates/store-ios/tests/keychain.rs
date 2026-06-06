// Copyright (c) 2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust (ABN 61 633 823 792)
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the iOS Keychain storage backend.
//!
//! We verify that:
//! 1. A secret can be stored and fetched via the trait API.
//! 2. The value persists after the storage wrapper is rebuilt (simulated
//!    process restart where the in-memory cache is gone).
//! 3. Retrieval without biometric context fails when the item was stored
//!    with a biometric access-control policy.
//!
//! These tests run only on the iOS simulator or device.

#![cfg(target_os = "ios")]

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use provii_mobile_sdk_platform_storage::{
    BiometricRequirement, PlatformSecureStorage, WalletError,
};
use provii_mobile_sdk_store_ios::{IOSKeychainStorage, StorageConfig};

// -------- additional low-level FFI imports (biometric guard test) ----------
use core_foundation::{
    base::{CFType, CFTypeRef, TCFType},
    boolean::CFBoolean,
    dictionary::CFMutableDictionary,
    string::CFString,
};
use core_foundation_sys::base::CFRelease;
use objc::runtime::{Class, Object};
use objc::{msg_send, sel, sel_impl};
use security_framework_sys::{
    base::{errSecAuthFailed, errSecInteractionNotAllowed, errSecSuccess},
    item::{
        kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecMatchLimit,
        kSecMatchLimitOne, kSecReturnData, kSecUseAuthenticationContext, kSecUseOperationPrompt,
        SecItemCopyMatching,
    },
};

// Re-usable helpers --------------------------------------------------------

fn random_secret() -> ([u8; 64], String) {
    let rng = OsRng;
    let kp = SigningKey::generate(&mut rng);
    let sec = kp.to_bytes(); // 32 bytes (ed25519 seed)
    let mut full = [0u8; 64];
    full[..32].copy_from_slice(&sec);
    let name = format!("provii.test.{}", hex::encode(&sec[..4]));
    (full, name)
}

fn fresh_storage(_require_biometrics: bool) -> Arc<IOSKeychainStorage> {
    let cfg = StorageConfig {
        require_biometrics: _require_biometrics,
        use_secure_enclave: false, // CI / simulator may lack Secure Enclave
        enable_caching: true,
        service_name: "com.provii.wallet.test".into(),
        max_cache_size: 16,
        cache_ttl_seconds: 60,
        enable_audit_logging: true,
    };
    IOSKeychainStorage::new_with_config(cfg)
}

/// Shorthand for no-biometric operations.
fn bio_none() -> BiometricRequirement {
    BiometricRequirement::None
}

// --------------------------------------------------------------------------

/// Round-trip + persistence + delete.
#[test]
fn keychain_roundtrip_persists() {
    let (secret, key_name) = random_secret();

    // 1) Store
    let kc = fresh_storage(false);
    kc.store(&key_name, &secret, bio_none()).expect("store");

    // 2) Retrieve in the same process
    let fetched = kc.retrieve(&key_name, bio_none()).expect("retrieve-1");
    assert_eq!(*fetched, secret);

    // 3) Simulate a new process (drop cache / new instance)
    drop(kc);
    let fresh = fresh_storage(false);
    let fetched2 = fresh.retrieve(&key_name, bio_none()).expect("retrieve-2");
    assert_eq!(*fetched2, secret);

    // 4) Delete and verify non-existence
    fresh.delete(&key_name).expect("delete");
    assert!(!fresh.exists(&key_name).unwrap());
}

/// Biometric-guard behaviour.
///
/// Store with biometric access control. Attempt retrieval without a biometric
/// context, which should fail. A direct SecItemCopyMatching call with a mock
/// LAContext proves the item is protected by `kSecAccessControlBiometryCurrentSet`
/// (yields `errSecInteractionNotAllowed` or `errSecAuthFailed` on the simulator
/// where no face/Touch ID can be presented).
#[test]
fn keychain_biometric_guard() {
    let (secret, key_name) = random_secret();

    // Store the secret with biometric policy enabled.
    let bio_store = fresh_storage(true);
    bio_store
        .store(
            &key_name,
            &secret,
            BiometricRequirement::for_credential_secrets(),
        )
        .expect("store-bio");

    // Attempt to read with a store that does not present biometric credentials;
    // this should fail with an authentication-related error.
    let no_bio_store = fresh_storage(false);
    match no_bio_store.retrieve(&key_name, bio_none()) {
        Err(WalletError::Storage { msg }) => {
            assert!(
                msg.contains("Authentication failed")
                    || msg.contains("User cancelled")
                    || msg.contains("NotFound"),
                "unexpected error: {msg}"
            );
        }
        Ok(_) => panic!("retrieval succeeded without biometrics - policy not enforced"),
        Err(e) => panic!("unexpected error: {e:?}"),
    }

    // Extra: raw SecItemCopyMatching with mock LAContext + prompt -----------
    unsafe {
        // SAFETY: Class::get("LAContext") returns the Objective-C class object for
        // LAContext, a valid runtime class on iOS. msg_send![cls, new] allocates and
        // initialises an LAContext instance. msg_send![ctx, setInteractionNotAllowed:]
        // sets a BOOL property. Standard Objective-C message sends with correct
        // selector signatures.
        let cls = Class::get("LAContext").expect("LAContext");
        let ctx: *mut Object = msg_send![cls, new];
        let _: () = msg_send![ctx, setInteractionNotAllowed: true];

        // Build CFDictionary query
        let mut q = CFMutableDictionary::new();
        // SAFETY: All kSec* constants below are framework-owned global CFStringRefs.
        // wrap_under_get_rule is correct because we do not own these references
        // (the Security framework does).
        q.set(
            CFString::wrap_under_get_rule(kSecClass).as_CFType(),
            CFString::wrap_under_get_rule(kSecClassGenericPassword).as_CFType(),
        );
        q.set(
            CFString::wrap_under_get_rule(kSecAttrService).as_CFType(),
            CFString::new("app.provii.wallet.test").as_CFType(),
        );
        q.set(
            CFString::wrap_under_get_rule(kSecAttrAccount).as_CFType(),
            CFString::new(&key_name).as_CFType(),
        );
        q.set(
            CFString::wrap_under_get_rule(kSecReturnData).as_CFType(),
            CFBoolean::true_value().as_CFType(),
        );
        q.set(
            CFString::wrap_under_get_rule(kSecMatchLimit).as_CFType(),
            CFString::wrap_under_get_rule(kSecMatchLimitOne).as_CFType(),
        );
        // Supply the mock context and a custom prompt
        // SAFETY: ctx is a live Objective-C object (LAContext *) cast to CFTypeRef.
        // wrap_under_get_rule is correct because we manage the lifetime of ctx
        // manually (released via CFRelease below).
        q.set(
            CFString::wrap_under_get_rule(kSecUseAuthenticationContext).as_CFType(),
            CFType::wrap_under_get_rule(ctx as CFTypeRef),
        );
        q.set(
            CFString::wrap_under_get_rule(kSecUseOperationPrompt).as_CFType(),
            CFString::new("Unit-test biometric prompt").as_CFType(),
        );

        // SAFETY: q is a valid CFDictionary on the stack. result is initialised to
        // null. SecItemCopyMatching reads the query and writes a +1 retained result
        // on success. In this test we expect failure, so result remains null.
        let mut result: CFTypeRef = std::ptr::null_mut();
        let status = SecItemCopyMatching(q.as_concrete_TypeRef(), &mut result);

        // SAFETY: ctx is the +1 retained LAContext created by msg_send![cls, new]
        // above. We must release it to avoid a leak.
        CFRelease(ctx as CFTypeRef);

        // On simulator we expect "interaction not allowed"; on device without
        // user biometrics enrolled we get "auth failed". Either proves the
        // access-control policy is active.
        assert!(
            status == errSecInteractionNotAllowed || status == errSecAuthFailed,
            "unexpected OSStatus: {status}"
        );
        assert_ne!(status, errSecSuccess, "biometric gate was bypassed");
    }
}
