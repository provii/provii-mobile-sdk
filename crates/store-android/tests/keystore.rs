// Copyright (c) 2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust (ABN 61 633 823 792)
// SPDX-License-Identifier: Apache-2.0

//! Android-side integration tests for the hardware-backed secure store.
//!
//! Executed by the GitHub Actions Android Runner matrix (API 29, 33, 34).
//! We validate two scenarios:
//!
//! 1. **Development mode**: no biometrics, software keystore allowed.
//!    Should always succeed on every emulator API level.
//! 2. **Production mode**: biometrics required, StrongBox if present.
//!    Gracefully skipped when the emulator cannot satisfy these requirements.
//!
//! A third test verifies the biometric gate: store with biometric access
//! control, then attempt retrieval without biometric credentials. The
//! retrieval must fail.

#![cfg(target_os = "android")]

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use jni::JavaVM;
use provii_mobile_sdk_platform_storage::{
    BiometricRequirement, PlatformSecureStorage, WalletError,
};

use provii_mobile_sdk_store_android::{create_development_storage, create_production_storage};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Produce a random secret and a unique key name so concurrent jobs do not
/// collide in the global Android Keystore.
fn random_secret() -> ([u8; 64], String) {
    let rng = OsRng;
    let kp = SigningKey::generate(&mut rng);
    let sec = kp.to_bytes();
    let mut full = [0u8; 64];
    full[..32].copy_from_slice(&sec);
    let name = format!("provii.test.{}", hex::encode(&sec[..4]));
    (full, name)
}

/// Shorthand for no-biometric operations.
fn bio_none() -> BiometricRequirement {
    BiometricRequirement::None
}

// ---------------------------------------------------------------------------
// 1. Development-mode round-trip (no biometrics / no StrongBox)
// ---------------------------------------------------------------------------
#[test]
fn keystore_roundtrip_development() {
    let store = create_development_storage().expect("dev storage creation failed");

    let (secret, key_name) = random_secret();

    // Store -> retrieve -> restart -> retrieve -> delete
    store.store(&key_name, &secret, bio_none()).expect("store");
    assert_eq!(*store.retrieve(&key_name, bio_none()).unwrap(), secret);

    drop(store); // simulate process death

    let store2 = create_development_storage().unwrap();
    assert_eq!(*store2.retrieve(&key_name, bio_none()).unwrap(), secret);

    store2.delete(&key_name).unwrap();
    assert!(!store2.exists(&key_name).unwrap());
}

// ---------------------------------------------------------------------------
// 2. Production-mode round-trip (biometrics + StrongBox if present)
//    Skipped automatically when not supported on the runner.
// ---------------------------------------------------------------------------
#[test]
fn keystore_roundtrip_production() {
    let store = match create_production_storage() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("skipping production test - env unsupported: {e:?}");
            return; // gracefully skip on CI emulators without biometrics
        }
    };

    let (secret, key_name) = random_secret();

    if let Err(e) = store.store(
        &key_name,
        &secret,
        BiometricRequirement::for_credential_secrets(),
    ) {
        eprintln!("skipping production test - store() failed: {e:?}");
        return;
    }

    // Retrieval should succeed with biometrics available.
    assert_eq!(
        *store
            .retrieve(&key_name, BiometricRequirement::for_credential_secrets())
            .unwrap(),
        secret
    );
    store.delete(&key_name).unwrap();
}

// ---------------------------------------------------------------------------
// 3. Biometric-gate validation
// ---------------------------------------------------------------------------
#[test]
fn keystore_biometric_guard() {
    // Try to build a biometric-protected store; skip if unsupported.
    let bio_store = match create_production_storage() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("skipping biometric-guard test - no biometric env");
            return;
        }
    };

    let (secret, key_name) = random_secret();
    if let Err(e) = bio_store.store(
        &key_name,
        &secret,
        BiometricRequirement::for_credential_secrets(),
    ) {
        eprintln!("skipping biometric-guard test - store() failed: {e:?}");
        return;
    }

    // Attempt to read the item without biometrics: use dev store.
    let dev_store = create_development_storage().unwrap();
    match dev_store.retrieve(&key_name, bio_none()) {
        Err(WalletError::Storage { msg })
            if msg == "Authentication failed"
                || msg == "Keystore operation failed"
                || msg == "User cancelled authentication" =>
        {
            // Expected: biometric gate enforced.
        }
        Ok(_) => panic!("biometric-protected item retrieved without auth!"),
        Err(e) => panic!("unexpected error: {e:?}"),
    }

    // Clean-up (delete with biometric credentials)
    bio_store.delete(&key_name).ok();
}
