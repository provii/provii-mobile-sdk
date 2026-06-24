// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Operation statistics and device capability detection for the iOS Keychain
//! storage backend.

use super::*;

#[derive(Debug, Clone, Default)]
pub(crate) struct OperationStatistics {
    total_operations: u64,
    successful_operations: u64,
    failed_operations: u64,
    biometric_authentications: u64,
    cache_hits: u64,
    last_operation_time: u64,
}

impl OperationStatistics {
    pub(crate) const fn new() -> Self {
        Self {
            total_operations: 0,
            successful_operations: 0,
            failed_operations: 0,
            biometric_authentications: 0,
            cache_hits: 0,
            last_operation_time: 0,
        }
    }

    pub(crate) fn record_operation(&mut self, success: bool, used_biometrics: bool) {
        self.total_operations += 1;
        if success {
            self.successful_operations += 1;
        } else {
            self.failed_operations += 1;
        }
        if used_biometrics {
            self.biometric_authentications += 1;
        }
        self.last_operation_time = current_timestamp();
    }
}

/* =======================================================================
Device Capabilities Detection
=================================================================== */

#[derive(Debug, Clone)]
pub(crate) struct DeviceCapabilities {
    has_secure_enclave: Option<bool>,
    biometric_type: BiometricType,
    ios_version: Option<String>,
}

impl Default for DeviceCapabilities {
    fn default() -> Self {
        Self {
            has_secure_enclave: Self::detect_secure_enclave(),
            biometric_type: Self::detect_biometric_type(),
            ios_version: Self::get_ios_version(),
        }
    }
}

impl DeviceCapabilities {
    fn detect_secure_enclave() -> Option<bool> {
        // NOTE: Runtime Secure Enclave detection requires calling
        // SecKeyCreateRandomKey with kSecAttrTokenIDSecureEnclave via
        // Objective-C FFI, which is not available from pure Rust. This
        // returns None to express that the detection was not performed.
        // The Keychain ACL enforces Secure Enclave usage regardless of
        // what we report here; callers should not branch on this value
        // for security decisions.
        None
    }

    fn detect_biometric_type() -> BiometricType {
        // NOTE: Runtime biometric type detection requires LAContext
        // Objective-C FFI to LocalAuthentication.framework, which is not
        // available from pure Rust. Returns Unknown rather than a false
        // positive. The Keychain ACL enforces the actual biometric policy
        // regardless of what we report here.
        BiometricType::Unknown
    }

    fn get_ios_version() -> Option<String> {
        // NOTE: Runtime version query requires UIDevice.current.systemVersion
        // via Objective-C FFI to UIKit, which is not available from pure
        // Rust. Returns None. The deployment target is iOS 17.6+ but we
        // cannot confirm the actual running version from this layer.
        None
    }
}

#[derive(Debug, Clone)]
pub(crate) enum BiometricType {
    None,
    TouchID,
    FaceID,
    Available, // Generic - biometrics available but type unknown
    Unknown,   // Runtime detection unavailable (no LAContext FFI)
}
