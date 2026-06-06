// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! FFI-safe types exposed to Swift and Kotlin via UniFFI.
//!
//! Every public struct and enum in this module carries a `uniffi::Record` or
//! `uniffi::Enum` attribute so that UniFFI can generate idiomatic platform
//! bindings. Types that hold secret material (`verifier_api_key`, `dob_days`,
//! `r_bits`) implement [`Zeroize`] and redact their [`Debug`] output to
//! prevent accidental leakage through logging.
//!
//! Where `ZeroizeOnDrop` cannot be derived (because UniFFI moves fields out of
//! the struct at the FFI boundary), callers are responsible for calling
//! `.zeroize()` once they are done with the value. This trade-off is
//! documented on each affected type.

use provii_mobile_sdk_core::types::CredentialV2;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Action parsed from a deeplink.
///
/// All variants contain only public protocol data (challenge payloads, attestation
/// data). No secret material is stored in this enum. `ZeroizeOnDrop` cannot be
/// derived because `uniffi::Enum` moves fields out at the FFI boundary, which is
/// incompatible with a custom `Drop` impl. This is acceptable because no variant
/// holds secrets.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, uniffi::Enum)]
pub enum DeeplinkAction {
    /// Scan challenge for age verification
    ScanChallenge {
        #[zeroize(skip)] // Challenge payload is public
        payload_json: String,
    },

    /// Receive attestation for blind credential issuance
    Attest {
        #[zeroize(skip)] // Attestation is public
        attestation_data: String,
    },
}

/// Action from QR code scanning.
///
/// All variants contain only public protocol data (challenge JSON, attestation
/// data). No secret material is stored in this enum. `ZeroizeOnDrop` cannot be
/// derived because `uniffi::Enum` moves fields out at the FFI boundary, which is
/// incompatible with a custom `Drop` impl. This is acceptable because no variant
/// holds secrets.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, uniffi::Enum)]
pub enum QrAction {
    /// Verification challenge
    VerificationChallenge {
        #[zeroize(skip)] // Challenge is public data
        challenge_json: String,
    },

    /// Attestation for blind credential issuance
    Attestation {
        #[zeroize(skip)] // Attestation data is public
        attestation_data: String,
    },
}

/// Wallet configuration exposed to Swift and Kotlin via UniFFI.
///
/// NOTE: This type intentionally diverges from the core crate's
/// `WalletConfig` (`crates/core/src/types.rs`). Core's version holds only
/// the subset of preferences (`auto_select`, `network_timeout`,
/// `cache_proving_keys`) that core business logic references directly.
/// This FFI version adds runtime configuration fields (`issuer_api_url`,
/// `verifier_api_url`, `verifier_api_key`, `verifier_origin`,
/// `environment`, `enable_parallel_prover`, `max_prover_threads`) needed
/// by the platform layer. No automatic conversion exists between them.
///
/// SECURITY: `verifier_api_key` is secret material. Implements `Zeroize` for
/// manual clearing. Cannot use `ZeroizeOnDrop` because `uniffi::Record` moves
/// fields out of the struct, which is incompatible with `Drop`. Callers must
/// call `.zeroize()` when done with the config. The `Debug` impl redacts the
/// key to prevent accidental logging.
#[derive(Clone, Serialize, Deserialize, Zeroize, uniffi::Record)]
pub struct WalletConfig {
    #[zeroize(skip)]
    pub auto_select: bool,
    #[zeroize(skip)]
    pub network_timeout: u64,
    #[zeroize(skip)]
    pub cache_proving_keys: bool,
    #[zeroize(skip)]
    pub issuer_api_url: String,
    #[zeroize(skip)]
    pub verifier_api_url: String,
    #[serde(skip_serializing)]
    pub verifier_api_key: Option<String>,
    #[zeroize(skip)]
    pub verifier_origin: Option<String>,
    #[zeroize(skip)]
    pub environment: String,
    /// Enable/disable parallel proving at runtime
    #[zeroize(skip)]
    pub enable_parallel_prover: bool,
    /// Maximum number of prover threads (0 = auto-detect)
    /// Mobile defaults to 2, desktop defaults to 4
    #[zeroize(skip)]
    pub max_prover_threads: u8,
}

impl std::fmt::Debug for WalletConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletConfig")
            .field("auto_select", &self.auto_select)
            .field("network_timeout", &self.network_timeout)
            .field("cache_proving_keys", &self.cache_proving_keys)
            .field("issuer_api_url", &self.issuer_api_url)
            .field("verifier_api_url", &self.verifier_api_url)
            .field(
                "verifier_api_key",
                &self.verifier_api_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("verifier_origin", &self.verifier_origin)
            .field("environment", &self.environment)
            .field("enable_parallel_prover", &self.enable_parallel_prover)
            .field("max_prover_threads", &self.max_prover_threads)
            .finish()
    }
}

impl WalletConfig {
    /// Zeroize secret fields (`verifier_api_key`).
    ///
    /// UniFFI's `Record` attribute moves fields out of the struct at the FFI
    /// boundary, making `Drop` and `ZeroizeOnDrop` incompatible.
    /// The `Drop` impl on `ProviiWallet` calls this automatically when the wallet is
    /// deallocated. It is also called on transient clones at construction,
    /// config update, and challenge fetch sites.
    pub fn zeroize_secrets(&mut self) {
        self.verifier_api_key.zeroize();
    }
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            auto_select: true,
            network_timeout: 30,
            cache_proving_keys: true,
            issuer_api_url: "https://api.issuer.example".to_string(),
            verifier_api_url: "https://verify.proviiwallet.app".to_string(),
            verifier_api_key: None,
            verifier_origin: None,
            environment: "production".to_string(),
            enable_parallel_prover: true,
            max_prover_threads: 0, // 0 = auto-detect based on platform
        }
    }
}

impl WalletConfig {
    /// IV-707: Validate that URL fields are non-empty and use HTTPS.
    /// Returns `Err` with a description of the first invalid field.
    pub fn validate(&self) -> Result<(), String> {
        Self::validate_https_url(&self.issuer_api_url, "issuer_api_url")?;
        Self::validate_https_url(&self.verifier_api_url, "verifier_api_url")?;

        if self.environment.trim().is_empty() {
            return Err("environment must not be empty".to_string());
        }

        Ok(())
    }

    fn validate_https_url(url: &str, field_name: &str) -> Result<(), String> {
        if url.trim().is_empty() {
            return Err(format!("{} must not be empty", field_name));
        }
        if !url.starts_with("https://") {
            return Err(format!("{} must use https:// scheme", field_name));
        }
        Ok(())
    }
}

/// Application metadata reported by the mobile host.
///
/// Platform code populates this struct at startup and passes it through FFI so
/// the SDK can include device context in diagnostic payloads and HTTP headers.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct AppInfo {
    /// Semantic version of the host application (e.g. "2.1.0").
    pub version: String,
    /// Platform-specific build identifier (e.g. CFBundleVersion on iOS).
    pub build_number: String,
    /// Operating system family: "iOS" or "Android".
    pub platform: String,
    /// Hardware model string when available (e.g. "iPhone14,2").
    pub device_model: Option<String>,
    /// OS version string when available (e.g. "17.4.1").
    pub os_version: Option<String>,
}

/// Connectivity snapshot provided by the platform layer.
///
/// The SDK consults this before making HTTP requests so it can fail fast with a
/// meaningful error rather than blocking on a socket timeout.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct NetworkStatus {
    /// `true` when the device has a usable network path (Wi-Fi or cellular).
    pub connected: bool,
}

/// Maximum number of managed credential slots per namespace.
#[allow(dead_code)]
pub const MAX_MANAGED_SLOTS: u8 = 15;

/// Storage slot that determines where a credential lives on-device.
///
/// A device can hold one primary credential and up to 15 managed (child)
/// credentials per namespace (Primary / Sandbox), supporting up to 32
/// credentials total. Managed indices run from 0 to 14 inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
pub enum CredentialSlot {
    /// The user's own credential.
    Primary,
    /// A managed (child) credential at a given index (0..14, up to 15 slots).
    Managed { index: u8 },
}

impl CredentialSlot {
    /// Return the storage key suffix used to namespace credential persistence.
    pub fn storage_key_suffix(&self) -> String {
        match self {
            CredentialSlot::Primary => "primary".to_string(),
            CredentialSlot::Managed { index } => format!("managed.{}", index),
        }
    }
}

/// Read-only view of a stored credential, suitable for display in the wallet UI.
///
/// This is a projection: it contains only the fields the UI needs and never
/// exposes cryptographic secrets. Build one via the credential storage layer
/// rather than constructing it directly.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct CredentialInfo {
    pub id: String,
    pub issuer_name: String,
    pub issuer_kid: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub is_expired: bool,
    pub can_prove: bool,
    pub schema: String,
    pub status: CredentialStatus,
    /// Credential type: "primary" or "managed"
    pub credential_type: String,
    /// User-assigned nickname (required for managed credentials)
    pub nickname: Option<String>,
    /// Managed credential index (0..14, up to 15 slots), None for primary.
    pub managed_index: Option<u8>,
}

/// Result of evaluating whether a credential can satisfy a given challenge.
///
/// The wallet UI uses this to grey-out credentials that are ineligible (for
/// example, an expired credential or one whose age does not meet the cutoff).
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct CredentialSuitability {
    pub id: String,
    pub nickname: Option<String>,
    pub credential_type: String,
    pub can_satisfy: bool,
    pub failure_reason: Option<String>,
}

/// Lifecycle status of a stored credential.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Enum)]
pub enum CredentialStatus {
    /// Credential is within its validity period and can generate proofs.
    Valid,
    /// Credential has passed its `expires_at` timestamp.
    Expired,
    /// Credential failed integrity checks or was revoked.
    Invalid,
}

/// Runtime diagnostic snapshot returned by the SDK's health-check API.
///
/// Contains no secret material. Safe to serialise and transmit for support
/// triage.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct DiagnosticInfo {
    /// Version of the provii-mobile-sdk crate.
    pub sdk_version: String,
    /// Version of the host application (mirrors [`AppInfo::version`]).
    pub app_version: String,
    /// Platform identifier ("iOS" or "Android").
    pub platform: String,
    /// Whether the Groth16 prover has been initialised with proving keys.
    pub prover_initialized: bool,
    /// Total number of credentials currently in storage.
    pub credential_count: u32,
    /// Whether the platform storage backend is reachable.
    pub storage_available: bool,
    /// Active environment name from [`WalletConfig::environment`].
    pub config_environment: String,
    /// Unix timestamp (seconds) of the most recent proof generation, if any.
    pub last_proof_generated: Option<u64>,
}

/// A credential together with its associated metadata, as persisted on-device.
///
/// Not exposed through UniFFI directly; used internally by the storage layer.
///
/// Custom `Serialize`/`Deserialize` implementations handle the fact that
/// [`CredentialV2`] uses `#[serde(skip_serializing, default)]` on its secret
/// fields (`dob_days`, `r_bits`). That annotation works correctly with
/// named-field formats like JSON (missing keys get defaults), but breaks
/// positional binary formats like postcard where every field in the
/// `deserialize_struct` field list is expected in the byte stream. The
/// manual impls route through [`PostcardCredential`], which uses
/// `#[serde(skip)]` (both directions) so the field count matches on read
/// and write.
#[derive(Debug, Clone)]
pub struct StoredCredential {
    /// The cryptographic credential (commitments, signatures, public inputs).
    pub credential: CredentialV2,
    /// Bookkeeping fields (import time, usage count, label, slot info).
    pub metadata: CredentialMetadata,
}

/// Postcard-safe mirror of [`CredentialV2`] that uses `#[serde(skip)]` on
/// secret fields instead of `skip_serializing` + `default`.
///
/// In positional binary formats the field list passed to `deserialize_struct`
/// determines how many elements the deserialiser reads. `skip_serializing`
/// alone omits the bytes on write but still expects them on read, causing an
/// "Option discriminant" error when the next struct's bytes are misread as an
/// `Option<i32>` discriminant. `#[serde(skip)]` removes the field from both
/// the serialise and deserialise paths, so the byte count stays consistent.
#[derive(Clone, Serialize, Deserialize)]
#[allow(dead_code)] // Structural mirror of CredentialV2 for serde round-trip parity
struct PostcardCredential {
    v: u8,
    kid: String,
    issuer_vk: [u8; 32],
    #[serde(with = "postcard_sig_bytes")]
    sig_rj: [u8; 64],
    c_bytes: [u8; 32],
    iat: u64,
    exp: u64,
    schema: String,
    // Secret fields excluded from the postcard byte stream entirely.
    #[serde(skip)]
    dob_days: Option<i32>,
    #[serde(skip)]
    r_bits: Option<Vec<bool>>,
}

/// Postcard-compatible serde helpers for `[u8; 64]` signature arrays.
///
/// Mirrors the `sig_bytes` module in `provii_mobile_sdk_core::types` but lives here
/// so this crate does not depend on the module being `pub`.
mod postcard_sig_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes for sig_rj, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

impl From<&CredentialV2> for PostcardCredential {
    fn from(c: &CredentialV2) -> Self {
        Self {
            v: c.v,
            kid: c.kid.clone(),
            issuer_vk: c.issuer_vk,
            sig_rj: c.sig_rj,
            c_bytes: c.c_bytes,
            iat: c.iat,
            exp: c.exp,
            schema: c.schema.clone(),
            dob_days: None,
            r_bits: None,
        }
    }
}

impl From<PostcardCredential> for CredentialV2 {
    fn from(p: PostcardCredential) -> Self {
        Self {
            v: p.v,
            kid: p.kid,
            issuer_vk: p.issuer_vk,
            sig_rj: p.sig_rj,
            c_bytes: p.c_bytes,
            iat: p.iat,
            exp: p.exp,
            schema: p.schema,
            dob_days: None,
            r_bits: None,
        }
    }
}

/// Wire format for [`StoredCredential`] that postcard can round-trip without
/// the `skip_serializing` / `default` mismatch.
#[derive(Serialize, Deserialize)]
struct StoredCredentialWire {
    credential: PostcardCredential,
    metadata: CredentialMetadata,
}

impl Serialize for StoredCredential {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let wire = StoredCredentialWire {
            credential: PostcardCredential::from(&self.credential),
            metadata: self.metadata.clone(),
        };
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StoredCredential {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = StoredCredentialWire::deserialize(deserializer)?;
        Ok(StoredCredential {
            credential: CredentialV2::from(wire.credential),
            metadata: wire.metadata,
        })
    }
}

/// Bookkeeping metadata for a stored credential.
///
/// Serialised alongside the credential itself in platform secure storage. The
/// `credential_type` field defaults to `"primary"` when deserialising records
/// that were written before managed credentials existed.
///
/// NOTE: This type intentionally diverges from the core crate's
/// `CredentialMetadata` (`crates/core/src/types.rs`). Core's version is a
/// minimal read-only projection (`id`, `label`, `imported_at`,
/// `issuer_name`) used by the storage trait. This FFI version adds runtime
/// bookkeeping fields (`last_used`, `use_count`, `credential_type`,
/// `nickname`, `managed_index`) that only the platform storage layer
/// tracks. No field-level conversion exists between them because they
/// serve different purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMetadata {
    /// Unix timestamp (seconds) of the import event.
    pub imported_at: u64,
    /// Unix timestamp (seconds) of the most recent proof using this credential.
    pub last_used: Option<u64>,
    /// Cumulative number of proofs generated with this credential.
    pub use_count: u32,
    /// Optional user-visible label for the credential.
    pub label: Option<String>,
    /// Credential type: "primary" or "managed"
    #[serde(default = "default_credential_type")]
    pub credential_type: String,
    /// User-assigned nickname (required for managed credentials)
    pub nickname: Option<String>,
    /// Managed credential index (0..14, up to 15 slots), None for primary
    pub managed_index: Option<u8>,
}

fn default_credential_type() -> String {
    "primary".to_string()
}

/// Parsed response body from a provii-verifier `/v1/verify` POST.
///
/// The verifier returns a JSON object with at least `result` and `state`.
/// `result` is `"OK"` on a successful verification and any other string
/// (e.g. `"INVALID_PROOF"`, `"EXPIRED"`) on failure.
#[derive(Debug, Clone, Deserialize)]
pub struct VerifyResponse {
    /// Verification outcome. `"OK"` indicates the proof was accepted.
    pub result: String,
    /// Verifier state string associated with the outcome.
    pub state: String,
}

/// Secret witness data needed to generate a zero knowledge proof.
///
/// Stored separately from the public credential in platform secure storage.
/// Implements `ZeroizeOnDrop` so the memory is scrubbed when the value goes
/// out of scope.
///
/// SECURITY: The `Debug` impl redacts both fields. Do not log or serialise
/// this struct except when persisting to secure storage.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CredentialSecrets {
    /// Date of birth encoded as days since the Unix epoch.
    pub dob_days: i32,
    /// Blinding factor bits used in the Pedersen commitment (matches [`CredentialV2`] layout).
    pub r_bits: Vec<bool>,
}

impl std::fmt::Debug for CredentialSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialSecrets")
            .field("dob_days", &"[REDACTED]")
            .field("r_bits", &format!("[REDACTED; {} bits]", self.r_bits.len()))
            .finish()
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::string_slice,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used
)]
mod tests {
    use super::*;

    #[test]
    fn test_deeplink_action_serialize_scan_challenge() -> Result<(), Box<dyn std::error::Error>> {
        let action = DeeplinkAction::ScanChallenge {
            payload_json: r#"{"challenge_id":"abc123"}"#.to_string(),
        };

        let json = serde_json::to_string(&action)?;
        assert!(json.contains("ScanChallenge"));
        assert!(json.contains("payload_json"));

        // Test roundtrip
        let decoded: DeeplinkAction = serde_json::from_str(&json)?;
        match decoded {
            DeeplinkAction::ScanChallenge { payload_json } => {
                assert_eq!(payload_json, r#"{"challenge_id":"abc123"}"#);
            }
            _ => panic!("Wrong variant"),
        }
        Ok(())
    }

    #[test]
    fn test_qr_action_verification_challenge() -> Result<(), Box<dyn std::error::Error>> {
        let challenge_json = r#"{"challenge_id":"test","cutoff_days":19000}"#;
        let action = QrAction::VerificationChallenge {
            challenge_json: challenge_json.to_string(),
        };

        let json = serde_json::to_string(&action)?;
        assert!(json.contains("VerificationChallenge"));
        assert!(json.contains("challenge_id"));
        Ok(())
    }

    #[test]
    fn test_wallet_config_default() {
        let config = WalletConfig::default();

        assert!(config.auto_select);
        assert_eq!(config.network_timeout, 30);
        assert!(config.cache_proving_keys);
        assert_eq!(config.environment, "production");
        assert!(config.enable_parallel_prover);
        assert_eq!(config.max_prover_threads, 0);
        assert!(config.issuer_api_url.starts_with("https://"));
        assert!(config.verifier_api_url.starts_with("https://"));
    }

    #[test]
    fn test_wallet_config_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let config = WalletConfig {
            auto_select: false,
            network_timeout: 60,
            cache_proving_keys: false,
            issuer_api_url: "https://test.com".to_string(),
            verifier_api_url: "https://verify.test.com".to_string(),
            verifier_api_key: None,
            verifier_origin: None,
            environment: "development".to_string(),
            enable_parallel_prover: false,
            max_prover_threads: 4,
        };

        let json = serde_json::to_string(&config)?;
        let decoded: WalletConfig = serde_json::from_str(&json)?;

        assert!(!decoded.auto_select);
        assert_eq!(decoded.network_timeout, 60);
        assert_eq!(decoded.max_prover_threads, 4);
        assert_eq!(decoded.environment, "development");
        Ok(())
    }

    #[test]
    fn test_app_info_full() -> Result<(), Box<dyn std::error::Error>> {
        let info = AppInfo {
            version: "2.0.0".to_string(),
            build_number: "42".to_string(),
            platform: "iOS".to_string(),
            device_model: Some("iPhone14,2".to_string()),
            os_version: Some("17.1".to_string()),
        };

        let json = serde_json::to_string(&info)?;
        let decoded: AppInfo = serde_json::from_str(&json)?;

        assert_eq!(decoded.version, "2.0.0");
        assert_eq!(decoded.build_number, "42");
        assert_eq!(decoded.platform, "iOS");
        assert_eq!(decoded.device_model, Some("iPhone14,2".to_string()));
        assert_eq!(decoded.os_version, Some("17.1".to_string()));
        Ok(())
    }

    #[test]
    fn test_app_info_minimal() -> Result<(), Box<dyn std::error::Error>> {
        let info = AppInfo {
            version: "1.0.0".to_string(),
            build_number: "1".to_string(),
            platform: "Android".to_string(),
            device_model: None,
            os_version: None,
        };

        let json = serde_json::to_string(&info)?;
        let decoded: AppInfo = serde_json::from_str(&json)?;

        assert_eq!(decoded.device_model, None);
        assert_eq!(decoded.os_version, None);
        Ok(())
    }

    #[test]
    fn test_network_status() -> Result<(), Box<dyn std::error::Error>> {
        let status = NetworkStatus { connected: true };

        let json = serde_json::to_string(&status)?;
        let decoded: NetworkStatus = serde_json::from_str(&json)?;

        assert!(decoded.connected);
        Ok(())
    }

    #[test]
    fn test_credential_status_variants() -> Result<(), Box<dyn std::error::Error>> {
        let statuses = vec![
            CredentialStatus::Valid,
            CredentialStatus::Expired,
            CredentialStatus::Invalid,
        ];

        for status in statuses {
            let json = serde_json::to_string(&status)?;
            let decoded: CredentialStatus = serde_json::from_str(&json)?;
            // Verify roundtrip works
            let json2 = serde_json::to_string(&decoded)?;
            assert_eq!(json, json2);
        }
        Ok(())
    }

    #[test]
    fn test_credential_info_complete() -> Result<(), Box<dyn std::error::Error>> {
        let info = CredentialInfo {
            id: "cred123".to_string(),
            issuer_name: "Test Issuer".to_string(),
            issuer_kid: "key1".to_string(),
            issued_at: 1700000000,
            expires_at: 1800000000,
            is_expired: false,
            can_prove: true,
            schema: "provii.age/0".to_string(),
            status: CredentialStatus::Valid,
            credential_type: "primary".to_string(),
            nickname: None,
            managed_index: None,
        };

        let json = serde_json::to_string(&info)?;
        let decoded: CredentialInfo = serde_json::from_str(&json)?;

        assert_eq!(decoded.id, "cred123");
        assert_eq!(decoded.issuer_name, "Test Issuer");
        assert!(!decoded.is_expired);
        assert!(decoded.can_prove);
        assert!(matches!(decoded.status, CredentialStatus::Valid));
        assert_eq!(decoded.credential_type, "primary");
        Ok(())
    }

    #[test]
    fn test_credential_info_expired() {
        let info = CredentialInfo {
            id: "cred_old".to_string(),
            issuer_name: "Expired Issuer".to_string(),
            issuer_kid: "key2".to_string(),
            issued_at: 1000000000,
            expires_at: 1100000000,
            is_expired: true,
            can_prove: false,
            schema: "provii.age.v1".to_string(),
            status: CredentialStatus::Expired,
            credential_type: "primary".to_string(),
            nickname: None,
            managed_index: None,
        };

        assert!(info.is_expired);
        assert!(!info.can_prove);
        assert!(matches!(info.status, CredentialStatus::Expired));
    }

    #[test]
    fn test_diagnostic_info() -> Result<(), Box<dyn std::error::Error>> {
        let diag = DiagnosticInfo {
            sdk_version: "2.0.0".to_string(),
            app_version: "1.0.0".to_string(),
            platform: "iOS".to_string(),
            prover_initialized: true,
            credential_count: 5,
            storage_available: true,
            config_environment: "production".to_string(),
            last_proof_generated: Some(1700000000),
        };

        let json = serde_json::to_string(&diag)?;
        let decoded: DiagnosticInfo = serde_json::from_str(&json)?;

        assert_eq!(decoded.sdk_version, "2.0.0");
        assert_eq!(decoded.credential_count, 5);
        assert_eq!(decoded.last_proof_generated, Some(1700000000));
        Ok(())
    }

    #[test]
    fn test_diagnostic_info_no_proofs() {
        let diag = DiagnosticInfo {
            sdk_version: "2.0.0".to_string(),
            app_version: "1.0.0".to_string(),
            platform: "Android".to_string(),
            prover_initialized: false,
            credential_count: 0,
            storage_available: true,
            config_environment: "development".to_string(),
            last_proof_generated: None,
        };

        assert_eq!(diag.last_proof_generated, None);
        assert!(!diag.prover_initialized);
        assert_eq!(diag.credential_count, 0);
    }

    #[test]
    fn test_credential_metadata_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let metadata = CredentialMetadata {
            imported_at: 1700000000,
            last_used: Some(1700001000),
            use_count: 42,
            label: Some("My ID".to_string()),
            credential_type: "primary".to_string(),
            nickname: None,
            managed_index: None,
        };

        let json = serde_json::to_string(&metadata)?;
        let decoded: CredentialMetadata = serde_json::from_str(&json)?;

        assert_eq!(decoded.imported_at, 1700000000);
        assert_eq!(decoded.last_used, Some(1700001000));
        assert_eq!(decoded.use_count, 42);
        assert_eq!(decoded.label, Some("My ID".to_string()));
        Ok(())
    }

    #[test]
    fn test_credential_metadata_never_used() {
        let metadata = CredentialMetadata {
            imported_at: 1700000000,
            last_used: None,
            use_count: 0,
            label: None,
            credential_type: "primary".to_string(),
            nickname: None,
            managed_index: None,
        };

        assert_eq!(metadata.last_used, None);
        assert_eq!(metadata.use_count, 0);
        assert_eq!(metadata.label, None);
    }

    #[test]
    fn test_credential_secrets() -> Result<(), Box<dyn std::error::Error>> {
        let secrets = CredentialSecrets {
            dob_days: 19000,
            r_bits: vec![true, false, true, true, false],
        };

        let json = serde_json::to_string(&secrets)?;
        let decoded: CredentialSecrets = serde_json::from_str(&json)?;

        assert_eq!(decoded.dob_days, 19000);
        assert_eq!(decoded.r_bits.len(), 5);
        assert!(decoded.r_bits[0]);
        assert!(!decoded.r_bits[1]);
        Ok(())
    }

    #[test]
    fn test_wallet_config_parallel_prover_enabled() {
        let mut config = WalletConfig::default();
        assert!(config.enable_parallel_prover);

        config.enable_parallel_prover = false;
        assert!(!config.enable_parallel_prover);
    }

    #[test]
    fn test_wallet_config_max_prover_threads() {
        let mut config = WalletConfig::default();
        assert_eq!(config.max_prover_threads, 0); // auto-detect

        config.max_prover_threads = 4;
        assert_eq!(config.max_prover_threads, 4);

        config.max_prover_threads = 1;
        assert_eq!(config.max_prover_threads, 1);
    }

    // Edge Case Tests - DeeplinkAction
    #[test]
    fn test_deeplink_action_empty_payload_json() -> Result<(), Box<dyn std::error::Error>> {
        let action = DeeplinkAction::ScanChallenge {
            payload_json: "".to_string(),
        };

        let json = serde_json::to_string(&action)?;
        let decoded: DeeplinkAction = serde_json::from_str(&json)?;

        match decoded {
            DeeplinkAction::ScanChallenge { payload_json } => {
                assert_eq!(payload_json, "");
            }
            _ => panic!("Wrong variant"),
        }
        Ok(())
    }

    #[test]
    fn test_deeplink_action_very_long_payload() -> Result<(), Box<dyn std::error::Error>> {
        let long_payload = "x".repeat(100000);
        let action = DeeplinkAction::ScanChallenge {
            payload_json: long_payload.clone(),
        };

        let json = serde_json::to_string(&action)?;
        let decoded: DeeplinkAction = serde_json::from_str(&json)?;

        match decoded {
            DeeplinkAction::ScanChallenge { payload_json } => {
                assert_eq!(payload_json.len(), 100000);
            }
            _ => panic!("Wrong variant"),
        }
        Ok(())
    }

    #[test]
    fn test_deeplink_action_unicode_payload() -> Result<(), Box<dyn std::error::Error>> {
        let action = DeeplinkAction::ScanChallenge {
            payload_json: r#"{"challenge":"チャレンジ🔐"}"#.to_string(),
        };

        let json = serde_json::to_string(&action)?;
        let decoded: DeeplinkAction = serde_json::from_str(&json)?;

        match decoded {
            DeeplinkAction::ScanChallenge { payload_json } => {
                assert!(payload_json.contains("チャレンジ"));
                assert!(payload_json.contains("🔐"));
            }
            _ => panic!("Wrong variant"),
        }
        Ok(())
    }

    // Edge Case Tests - QrAction
    #[test]
    fn test_qr_action_very_long_challenge_json() -> Result<(), Box<dyn std::error::Error>> {
        let long_challenge = format!(r#"{{"challenge_id":"{}"}}"#, "x".repeat(100000));
        let action = QrAction::VerificationChallenge {
            challenge_json: long_challenge.clone(),
        };

        let json = serde_json::to_string(&action)?;
        let decoded: QrAction = serde_json::from_str(&json)?;

        match decoded {
            QrAction::VerificationChallenge { challenge_json } => {
                assert!(challenge_json.len() > 100000);
            }
            _ => panic!("Wrong variant"),
        }
        Ok(())
    }

    #[test]
    fn test_qr_action_unicode_challenge() -> Result<(), Box<dyn std::error::Error>> {
        let action = QrAction::VerificationChallenge {
            challenge_json: r#"{"id":"チャレンジ🔐"}"#.to_string(),
        };

        let json = serde_json::to_string(&action)?;
        let decoded: QrAction = serde_json::from_str(&json)?;

        match decoded {
            QrAction::VerificationChallenge { challenge_json } => {
                assert!(challenge_json.contains("チャレンジ"));
            }
            _ => panic!("Wrong variant"),
        }
        Ok(())
    }

    // Edge Case Tests - WalletConfig
    #[test]
    fn test_wallet_config_zero_timeout() -> Result<(), Box<dyn std::error::Error>> {
        let config = WalletConfig {
            network_timeout: 0,
            ..Default::default()
        };

        let json = serde_json::to_string(&config)?;
        let decoded: WalletConfig = serde_json::from_str(&json)?;
        assert_eq!(decoded.network_timeout, 0);
        Ok(())
    }

    #[test]
    fn test_wallet_config_max_timeout() -> Result<(), Box<dyn std::error::Error>> {
        let config = WalletConfig {
            network_timeout: u64::MAX,
            ..Default::default()
        };

        let json = serde_json::to_string(&config)?;
        let decoded: WalletConfig = serde_json::from_str(&json)?;
        assert_eq!(decoded.network_timeout, u64::MAX);
        Ok(())
    }

    // IV-707: Empty URLs and non-HTTPS URLs are now rejected by validate()
    #[test]
    fn test_wallet_config_empty_urls_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let config = WalletConfig {
            issuer_api_url: "".to_string(),
            verifier_api_url: "".to_string(),
            environment: "".to_string(),
            ..Default::default()
        };

        let Err(err) = config.validate() else {
            panic!("expected error")
        };
        assert!(err.contains("must not be empty"));
        Ok(())
    }

    #[test]
    fn test_wallet_config_http_urls_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let config = WalletConfig {
            issuer_api_url: "http://insecure.example.com".to_string(),
            ..Default::default()
        };

        let Err(err) = config.validate() else {
            panic!("expected error")
        };
        assert!(err.contains("https://"));
        Ok(())
    }

    #[test]
    fn test_wallet_config_validate_default_ok() {
        let config = WalletConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_wallet_config_very_long_urls() {
        let long_url = format!("https://example.com/{}", "x".repeat(10000));
        let config = WalletConfig {
            issuer_api_url: long_url.clone(),
            verifier_api_url: long_url.clone(),
            environment: "e".repeat(10000),
            ..Default::default()
        };

        // Long HTTPS URLs are valid (length is bounded by the transport layer)
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_wallet_config_unicode_environment() {
        let config = WalletConfig {
            environment: "sandbox".to_string(),
            ..Default::default()
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_wallet_config_max_threads() -> Result<(), Box<dyn std::error::Error>> {
        let config = WalletConfig {
            max_prover_threads: u8::MAX,
            ..Default::default()
        };

        let json = serde_json::to_string(&config)?;
        let decoded: WalletConfig = serde_json::from_str(&json)?;
        assert_eq!(decoded.max_prover_threads, 255);
        Ok(())
    }

    // Edge Case Tests - AppInfo
    #[test]
    fn test_app_info_empty_strings() -> Result<(), Box<dyn std::error::Error>> {
        let info = AppInfo {
            version: "".to_string(),
            build_number: "".to_string(),
            platform: "".to_string(),
            device_model: Some("".to_string()),
            os_version: Some("".to_string()),
        };

        let json = serde_json::to_string(&info)?;
        let decoded: AppInfo = serde_json::from_str(&json)?;
        assert_eq!(decoded.version, "");
        Ok(())
    }

    #[test]
    fn test_app_info_very_long_strings() -> Result<(), Box<dyn std::error::Error>> {
        let long_str = "x".repeat(10000);
        let info = AppInfo {
            version: long_str.clone(),
            build_number: long_str.clone(),
            platform: long_str.clone(),
            device_model: Some(long_str.clone()),
            os_version: Some(long_str.clone()),
        };

        let json = serde_json::to_string(&info)?;
        let decoded: AppInfo = serde_json::from_str(&json)?;
        assert_eq!(decoded.version.len(), 10000);
        Ok(())
    }

    #[test]
    fn test_app_info_unicode() -> Result<(), Box<dyn std::error::Error>> {
        let info = AppInfo {
            version: "2.0.0-日本語".to_string(),
            build_number: "42-β".to_string(),
            platform: "iOS 🍎".to_string(),
            device_model: Some("iPhone 📱".to_string()),
            os_version: Some("17.1-अ".to_string()),
        };

        let json = serde_json::to_string(&info)?;
        let decoded: AppInfo = serde_json::from_str(&json)?;
        assert!(decoded.version.contains("日本語"));
        assert!(decoded.platform.contains("🍎"));
        Ok(())
    }

    // Edge Case Tests - CredentialInfo
    #[test]
    fn test_credential_info_empty_strings() -> Result<(), Box<dyn std::error::Error>> {
        let info = CredentialInfo {
            id: "".to_string(),
            issuer_name: "".to_string(),
            issuer_kid: "".to_string(),
            issued_at: 0,
            expires_at: 0,
            is_expired: false,
            can_prove: true,
            schema: "".to_string(),
            status: CredentialStatus::Valid,
            credential_type: "primary".to_string(),
            nickname: None,
            managed_index: None,
        };

        let json = serde_json::to_string(&info)?;
        let decoded: CredentialInfo = serde_json::from_str(&json)?;
        assert_eq!(decoded.id, "");
        assert_eq!(decoded.issuer_name, "");
        Ok(())
    }

    #[test]
    fn test_credential_info_very_long_strings() -> Result<(), Box<dyn std::error::Error>> {
        let long_str = "x".repeat(10000);
        let info = CredentialInfo {
            id: long_str.clone(),
            issuer_name: long_str.clone(),
            issuer_kid: long_str.clone(),
            issued_at: 1000,
            expires_at: 2000,
            is_expired: false,
            can_prove: true,
            schema: long_str.clone(),
            status: CredentialStatus::Valid,
            credential_type: "primary".to_string(),
            nickname: None,
            managed_index: None,
        };

        let json = serde_json::to_string(&info)?;
        let decoded: CredentialInfo = serde_json::from_str(&json)?;
        assert_eq!(decoded.id.len(), 10000);
        Ok(())
    }

    #[test]
    fn test_credential_info_unicode() -> Result<(), Box<dyn std::error::Error>> {
        let info = CredentialInfo {
            id: "認証情報-123-🔐".to_string(),
            issuer_name: "発行者名 🏢".to_string(),
            issuer_kid: "キー-456".to_string(),
            issued_at: 1000,
            expires_at: 2000,
            is_expired: false,
            can_prove: true,
            schema: "スキーマ.v2".to_string(),
            status: CredentialStatus::Valid,
            credential_type: "managed".to_string(),
            nickname: Some("Child".to_string()),
            managed_index: Some(0),
        };

        let json = serde_json::to_string(&info)?;
        let decoded: CredentialInfo = serde_json::from_str(&json)?;
        assert!(decoded.id.contains("認証情報"));
        assert!(decoded.issuer_name.contains("発行者名"));
        Ok(())
    }

    #[test]
    fn test_credential_info_max_timestamps() -> Result<(), Box<dyn std::error::Error>> {
        let info = CredentialInfo {
            id: "test".to_string(),
            issuer_name: "Test".to_string(),
            issuer_kid: "key1".to_string(),
            issued_at: u64::MAX,
            expires_at: u64::MAX,
            is_expired: false,
            can_prove: true,
            schema: "test.v1".to_string(),
            status: CredentialStatus::Valid,
            credential_type: "primary".to_string(),
            nickname: None,
            managed_index: None,
        };

        let json = serde_json::to_string(&info)?;
        let decoded: CredentialInfo = serde_json::from_str(&json)?;
        assert_eq!(decoded.issued_at, u64::MAX);
        assert_eq!(decoded.expires_at, u64::MAX);
        Ok(())
    }

    #[test]
    fn test_credential_info_issued_after_expiry() {
        let info = CredentialInfo {
            id: "invalid".to_string(),
            issuer_name: "Test".to_string(),
            issuer_kid: "key1".to_string(),
            issued_at: 2000,
            expires_at: 1000,
            is_expired: true,
            can_prove: false,
            schema: "test.v1".to_string(),
            status: CredentialStatus::Invalid,
            credential_type: "primary".to_string(),
            nickname: None,
            managed_index: None,
        };

        assert!(info.issued_at > info.expires_at);
        assert!(matches!(info.status, CredentialStatus::Invalid));
    }

    // Edge Case Tests - DiagnosticInfo
    #[test]
    fn test_diagnostic_info_empty_strings() -> Result<(), Box<dyn std::error::Error>> {
        let diag = DiagnosticInfo {
            sdk_version: "".to_string(),
            app_version: "".to_string(),
            platform: "".to_string(),
            prover_initialized: false,
            credential_count: 0,
            storage_available: false,
            config_environment: "".to_string(),
            last_proof_generated: None,
        };

        let json = serde_json::to_string(&diag)?;
        let decoded: DiagnosticInfo = serde_json::from_str(&json)?;
        assert_eq!(decoded.sdk_version, "");
        Ok(())
    }

    #[test]
    fn test_diagnostic_info_max_values() -> Result<(), Box<dyn std::error::Error>> {
        let diag = DiagnosticInfo {
            sdk_version: "v".repeat(10000),
            app_version: "v".repeat(10000),
            platform: "p".repeat(10000),
            prover_initialized: true,
            credential_count: u32::MAX,
            storage_available: true,
            config_environment: "e".repeat(10000),
            last_proof_generated: Some(u64::MAX),
        };

        let json = serde_json::to_string(&diag)?;
        let decoded: DiagnosticInfo = serde_json::from_str(&json)?;
        assert_eq!(decoded.credential_count, u32::MAX);
        Ok(())
    }

    #[test]
    fn test_diagnostic_info_unicode() -> Result<(), Box<dyn std::error::Error>> {
        let diag = DiagnosticInfo {
            sdk_version: "2.0.0-日本語".to_string(),
            app_version: "1.0.0-β".to_string(),
            platform: "iOS 🍎".to_string(),
            prover_initialized: true,
            credential_count: 5,
            storage_available: true,
            config_environment: "本番 🌍".to_string(),
            last_proof_generated: Some(1700000000),
        };

        let json = serde_json::to_string(&diag)?;
        let decoded: DiagnosticInfo = serde_json::from_str(&json)?;
        assert!(decoded.sdk_version.contains("日本語"));
        assert!(decoded.platform.contains("🍎"));
        Ok(())
    }

    // Edge Case Tests - CredentialMetadata
    #[test]
    fn test_credential_metadata_zero_values() -> Result<(), Box<dyn std::error::Error>> {
        let metadata = CredentialMetadata {
            imported_at: 0,
            last_used: Some(0),
            use_count: 0,
            label: Some("".to_string()),
            credential_type: "primary".to_string(),
            nickname: None,
            managed_index: None,
        };

        let json = serde_json::to_string(&metadata)?;
        let decoded: CredentialMetadata = serde_json::from_str(&json)?;
        assert_eq!(decoded.imported_at, 0);
        assert_eq!(decoded.use_count, 0);
        Ok(())
    }

    #[test]
    fn test_credential_metadata_max_values() -> Result<(), Box<dyn std::error::Error>> {
        let metadata = CredentialMetadata {
            imported_at: u64::MAX,
            last_used: Some(u64::MAX),
            use_count: u32::MAX,
            label: Some("l".repeat(10000)),
            credential_type: "primary".to_string(),
            nickname: None,
            managed_index: None,
        };

        let json = serde_json::to_string(&metadata)?;
        let decoded: CredentialMetadata = serde_json::from_str(&json)?;
        assert_eq!(decoded.imported_at, u64::MAX);
        assert_eq!(decoded.use_count, u32::MAX);
        Ok(())
    }

    #[test]
    fn test_credential_metadata_unicode_label() -> Result<(), Box<dyn std::error::Error>> {
        let metadata = CredentialMetadata {
            imported_at: 1700000000,
            last_used: Some(1700001000),
            use_count: 5,
            label: Some("私のID 🆔".to_string()),
            credential_type: "managed".to_string(),
            nickname: Some("Child".to_string()),
            managed_index: Some(0),
        };

        let json = serde_json::to_string(&metadata)?;
        let decoded: CredentialMetadata = serde_json::from_str(&json)?;
        assert!(decoded.label.ok_or("expected label")?.contains("私のID"));
        Ok(())
    }

    // Edge Case Tests - CredentialSecrets
    #[test]
    fn test_credential_secrets_zero_dob_days() -> Result<(), Box<dyn std::error::Error>> {
        let secrets = CredentialSecrets {
            dob_days: 0,
            r_bits: vec![true, false],
        };

        let json = serde_json::to_string(&secrets)?;
        let decoded: CredentialSecrets = serde_json::from_str(&json)?;
        assert_eq!(decoded.dob_days, 0);
        Ok(())
    }

    #[test]
    fn test_credential_secrets_max_dob_days() -> Result<(), Box<dyn std::error::Error>> {
        let secrets = CredentialSecrets {
            dob_days: i32::MAX,
            r_bits: vec![false; 100],
        };

        let json = serde_json::to_string(&secrets)?;
        let decoded: CredentialSecrets = serde_json::from_str(&json)?;
        assert_eq!(decoded.dob_days, i32::MAX);
        Ok(())
    }

    #[test]
    fn test_credential_secrets_empty_r_bits() -> Result<(), Box<dyn std::error::Error>> {
        let secrets = CredentialSecrets {
            dob_days: 19000,
            r_bits: vec![],
        };

        let json = serde_json::to_string(&secrets)?;
        let decoded: CredentialSecrets = serde_json::from_str(&json)?;
        assert_eq!(decoded.r_bits.len(), 0);
        Ok(())
    }

    #[test]
    fn test_credential_secrets_very_large_r_bits() -> Result<(), Box<dyn std::error::Error>> {
        let secrets = CredentialSecrets {
            dob_days: 19000,
            r_bits: vec![true; 100000],
        };

        let json = serde_json::to_string(&secrets)?;
        let decoded: CredentialSecrets = serde_json::from_str(&json)?;
        assert_eq!(decoded.r_bits.len(), 100000);
        Ok(())
    }

    #[test]
    fn test_credential_secrets_all_false_r_bits() -> Result<(), Box<dyn std::error::Error>> {
        let secrets = CredentialSecrets {
            dob_days: 19000,
            r_bits: vec![false; 1000],
        };

        let json = serde_json::to_string(&secrets)?;
        let decoded: CredentialSecrets = serde_json::from_str(&json)?;
        assert!(decoded.r_bits.iter().all(|&b| !b));
        Ok(())
    }

    #[test]
    fn test_credential_secrets_all_true_r_bits() -> Result<(), Box<dyn std::error::Error>> {
        let secrets = CredentialSecrets {
            dob_days: 19000,
            r_bits: vec![true; 1000],
        };

        let json = serde_json::to_string(&secrets)?;
        let decoded: CredentialSecrets = serde_json::from_str(&json)?;
        assert!(decoded.r_bits.iter().all(|&b| b));
        Ok(())
    }

    // Edge Case Tests - CredentialStatus
    #[test]
    fn test_credential_status_debug_format() {
        assert!(format!("{:?}", CredentialStatus::Valid).contains("Valid"));
        assert!(format!("{:?}", CredentialStatus::Expired).contains("Expired"));
        assert!(format!("{:?}", CredentialStatus::Invalid).contains("Invalid"));
    }

    #[test]
    fn test_credential_status_clone() {
        let status = CredentialStatus::Valid;
        let cloned = status.clone();
        assert!(matches!(cloned, CredentialStatus::Valid));
    }

    #[test]
    fn test_wallet_config_zeroize_secrets_clears_api_key() {
        let mut config = WalletConfig {
            verifier_api_key: Some("sk_live_secret_key_1234".to_string()),
            ..Default::default()
        };

        // Precondition: key is set
        assert!(config.verifier_api_key.is_some());
        assert!(!config.verifier_api_key.as_ref().unwrap().is_empty());

        config.zeroize_secrets();

        // After zeroize_secrets, the Option becomes None (zeroize on Option<String>
        // sets it to None, scrubbing the heap allocation)
        assert_eq!(config.verifier_api_key, None);
    }

    #[test]
    fn test_wallet_config_zeroize_secrets_noop_when_none() {
        let mut config = WalletConfig {
            verifier_api_key: None,
            ..Default::default()
        };

        // Should not panic when already None
        config.zeroize_secrets();
        assert_eq!(config.verifier_api_key, None);
    }
}
