// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Core type definitions for the Provii wallet SDK.
//!
//! This module defines the canonical data structures shared across all wallet
//! operations: credential storage, issuance protocol messages, QR challenge
//! payloads, zero knowledge proof submission types, and wallet configuration.
//!
//! Types here are the single source of truth consumed by the FFI layer, the
//! platform storage backends, and the proof generation pipeline. Sensitive
//! fields (`dob_days`, `r_bits`, HMAC values, challenge secrets) are annotated
//! with [`Zeroize`] and [`ZeroizeOnDrop`], and their [`Debug`] implementations
//! emit `[REDACTED]` instead of real values.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Custom serde helpers for `[u8; 64]` signature arrays, serialised as raw bytes.
mod sig_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialise a 64-byte array as raw serde bytes.
    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    /// Deserialise raw serde bytes into a `[u8; 64]`, returning an error if
    /// the length is not exactly 64.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Base64url (no padding) serde helpers for `[u8; 32]` arrays.
mod base64_bytes {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Encode a 32-byte array as a base64url string (no padding).
    pub fn serialize<S>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        encoded.serialize(s)
    }

    /// Decode a base64url string (no padding) into a `[u8; 32]`, returning
    /// an error if the decoded length is not exactly 32.
    pub fn deserialize<'de, D>(d: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Base64url (no padding) serde helpers for `[u8; 64]` arrays.
mod base64_bytes_64 {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Encode a 64-byte array as a base64url string (no padding).
    pub fn serialize<S>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        encoded.serialize(s)
    }

    /// Decode a base64url string (no padding) into a `[u8; 64]`, returning
    /// an error if the decoded length is not exactly 64.
    pub fn deserialize<'de, D>(d: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// A RedJubjub-signed Pedersen commitment credential stored by the wallet.
///
/// The credential binds a date-of-birth value (as days since Unix epoch) to a
/// Pedersen commitment `c_bytes` with randomness `r_bits`. The issuer signs
/// the commitment using RedJubjub over the JubJub curve, producing `sig_rj`.
/// During verification the wallet uses `dob_days` and `r_bits` as private
/// witnesses to generate a Groth16 age proof without revealing the DOB itself.
///
/// # Security
///
/// This struct holds secret witness material (`dob_days`, `r_bits`) required
/// for proof generation. Both fields derive [`Zeroize`] and [`ZeroizeOnDrop`],
/// and are excluded from serde serialisation by default so they cannot leak
/// through accidental JSON output or logging.
///
/// The manual [`Debug`] implementation replaces secret fields with
/// `[REDACTED]`.
///
/// For persistent storage that must retain secrets, use
/// `CredentialStorageData` with postcard, encrypted by the platform keychain.
/// For safe export or logging, call `to_json()` or `redacted()`.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CredentialV2 {
    /// Format version byte. Always `2` for this credential layout.
    pub v: u8,

    /// Issuer key identifier, matching the `kid` field in the issuer's
    /// published key set.
    pub kid: String,

    /// RedJubjub verification (public) key of the issuer, 32 bytes.
    pub issuer_vk: [u8; 32],

    /// RedJubjub signature over the credential payload, stored in R||S
    /// format (32 bytes R followed by 32 bytes S).
    #[serde(with = "sig_bytes")]
    pub sig_rj: [u8; 64],

    /// Pedersen commitment to `dob_days` with randomness `r_bits`, 32 bytes.
    pub c_bytes: [u8; 32],

    /// Issuance timestamp in seconds since the Unix epoch.
    pub iat: u64,

    /// Expiration timestamp in seconds since the Unix epoch. The credential
    /// is considered invalid after this point.
    pub exp: u64,

    /// Schema identifier (ASCII/UTF-8). Determines which circuit and public
    /// input layout apply when generating proofs with this credential.
    pub schema: String,

    /// Date of birth expressed as days since the Unix epoch.
    ///
    /// This is a **secret witness** used during Groth16 proof generation.
    /// It is `Some` when the credential is fully populated (immediately after
    /// issuance) and `None` in redacted or public views.
    ///
    /// # Security
    ///
    /// Skipped during serde serialisation to prevent accidental leakage.
    /// Deserialisation is permitted so the wallet can receive credentials
    /// from the issuer. Use `CredentialStorageData` for postcard storage
    /// that needs to preserve this value.
    #[serde(skip_serializing, default)]
    pub dob_days: Option<i32>,

    /// Randomness bits used in the Pedersen commitment.
    ///
    /// This is a **secret witness** used during Groth16 proof generation.
    /// It is `Some` when the credential is fully populated and `None` in
    /// redacted or public views.
    ///
    /// # Security
    ///
    /// Skipped during serde serialisation to prevent accidental leakage.
    /// Deserialisation is permitted so the wallet can receive credentials
    /// from the issuer. Use `CredentialStorageData` for postcard storage
    /// that needs to preserve this value.
    #[serde(skip_serializing, default)]
    pub r_bits: Option<Vec<bool>>,
}

impl core::fmt::Debug for CredentialV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CredentialV2")
            .field("v", &self.v)
            .field("kid", &self.kid)
            .field("issuer_vk", &self.issuer_vk)
            .field("sig_rj", &self.sig_rj)
            .field("c_bytes", &self.c_bytes)
            .field("iat", &self.iat)
            .field("exp", &self.exp)
            .field("schema", &self.schema)
            .field("dob_days", &"[REDACTED]")
            .field("r_bits", &"[REDACTED]")
            .finish()
    }
}

/// Public-only view of a signed credential, returned by the issuer API
/// after the commitment signing step.
///
/// All byte arrays are base64url-encoded in JSON. This struct intentionally
/// excludes `dob_days` and `r_bits` so it is safe to log, cache, or transmit
/// without risk of leaking secret witness data.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCredentialHeader {
    /// Format version byte.
    pub v: u8,

    /// Issuer key identifier.
    pub kid: String,

    /// RedJubjub verification key of the issuer, base64url-encoded 32 bytes.
    #[serde(with = "base64_bytes")]
    pub issuer_vk: [u8; 32],

    /// RedJubjub signature in R||S format, base64url-encoded 64 bytes.
    #[serde(with = "base64_bytes_64")]
    pub sig_rj: [u8; 64],

    /// Pedersen commitment bytes, base64url-encoded 32 bytes.
    #[serde(with = "base64_bytes")]
    pub c_bytes: [u8; 32],

    /// Issuance timestamp in seconds since the Unix epoch.
    pub iat: u64,

    /// Expiration timestamp in seconds since the Unix epoch.
    pub exp: u64,

    /// Schema identifier.
    pub schema: String,
}

/// A single trusted issuer key entry, identified by a key ID and its raw
/// 32-byte verification key.
///
/// The `kid` field is a public identifier and is compared using ordinary string
/// equality. The `vk` field is the RedJubjub verification key and is compared
/// using constant-time equality when validating credential headers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustedIssuerKey {
    /// Key identifier, matching the `kid` field published in the issuer's JWKS.
    pub kid: String,

    /// 32-byte RedJubjub verification key corresponding to this `kid`.
    #[serde(with = "base64_bytes")]
    pub vk: [u8; 32],
}

/// A set of trusted issuer keys, fetched from the issuer's JWKS endpoint.
///
/// The `keys` vector holds every key that the wallet will accept as a valid
/// signing key. Keys are never discarded during a union-merge refresh: if a
/// `kid` is seen with the same `vk` it is a no-op; if the `vk` changes the
/// entry is updated; new `kid` values are appended.
///
/// `fetched_at` is a Unix timestamp (seconds) recording when the anchor was
/// last refreshed. Callers may use it to decide when to trigger a refresh.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuerTrustAnchor {
    /// All currently trusted issuer keys.
    pub keys: Vec<TrustedIssuerKey>,

    /// Unix timestamp (seconds since epoch) when this anchor was last fetched.
    pub fetched_at: u64,
}

impl IssuerTrustAnchor {
    /// Merge `new_keys` into this anchor using the union-merge strategy.
    ///
    /// Rules applied in order for each incoming key:
    ///
    /// * Same `kid`, identical `vk`: no-op.
    /// * Same `kid`, different `vk` (key rotation): replace the existing entry.
    /// * New `kid` not yet in the anchor: append.
    pub fn union_merge(&mut self, new_keys: Vec<TrustedIssuerKey>) {
        for new_key in new_keys {
            if let Some(existing) = self.keys.iter_mut().find(|k| k.kid == new_key.kid) {
                // kid comparison is public; no constant-time needed here.
                if existing.vk != new_key.vk {
                    // Key rotation: replace vk for existing kid.
                    existing.vk = new_key.vk;
                }
                // Same kid + same vk: no-op (fall through).
            } else {
                self.keys.push(new_key);
            }
        }
    }
}

/// Request body for `POST /v1/start`, initiating an issuance session.
///
/// The caller must supply an [`Authorizer`] proving they are permitted to
/// issue credentials (either a YubiKey officer or an API client). Optional
/// fields let the caller override the default schema, validity period, and
/// issuer key.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct StartRequest {
    /// Actor role: `"officer"` (in-person YubiKey flow) or `"client"`
    /// (API key flow).
    #[zeroize(skip)]
    pub actor: String,

    /// Authentication payload proving the caller is authorised.
    pub authorizer: Authorizer,

    /// Optional schema identifier override. When absent the issuer uses its
    /// default schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub schema: Option<String>,

    /// Optional credential validity period in days. When absent the issuer
    /// applies its configured default.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub validity_days: Option<u32>,

    /// Optional issuer key ID override. When absent the issuer selects its
    /// current active key.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub kid: Option<String>,
}

/// Response from `POST /v1/start`, confirming that an issuance session has
/// been created.
///
/// The `session_id` is required for the subsequent `POST /v1/sign` call.
/// Timestamps use seconds since the Unix epoch except `expires_at`, which
/// is a signed value to accommodate server-side clock representation.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct StartResponse {
    /// Opaque session identifier, passed to the sign endpoint.
    ///
    /// # Security
    ///
    /// Sensitive. Zeroised on drop and redacted in debug output.
    pub session_id: String,

    /// Issuer key identifier selected for this session.
    #[zeroize(skip)]
    pub kid: String,

    /// Schema identifier for the credential being issued.
    #[zeroize(skip)]
    pub schema: String,

    /// Issuance timestamp (seconds since the Unix epoch).
    #[zeroize(skip)]
    pub iat: u64,

    /// Credential expiration timestamp (seconds since the Unix epoch).
    #[zeroize(skip)]
    pub exp: u64,

    /// Session expiry as a signed Unix timestamp. The session becomes invalid
    /// after this point and the caller must start a new one.
    #[zeroize(skip)]
    pub expires_at: i64,
}

impl core::fmt::Debug for StartResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StartResponse")
            .field("session_id", &"[REDACTED]")
            .field("kid", &self.kid)
            .field("schema", &self.schema)
            .field("iat", &self.iat)
            .field("exp", &self.exp)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Authentication payload attached to issuance requests.
///
/// Two flows are supported:
///
/// | `format`   | Auth mechanism                          |
/// |------------|-----------------------------------------|
/// | `"yubikey"`| HMAC-SHA-1 challenge/response via YubiKey hardware |
/// | `"client"` | HMAC-SHA-256 over a shared API secret   |
///
/// The HMAC value is hex-encoded and treated as sensitive. The manual
/// [`Debug`] implementation replaces it with `[REDACTED]`.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Authorizer {
    /// Authentication format: `"yubikey"` or `"client"`.
    #[zeroize(skip)]
    pub format: String,

    /// Officer ID (YubiKey flow) or client ID (API key flow). Serialised as
    /// `keyId` in JSON.
    #[serde(rename = "keyId")]
    #[zeroize(skip)]
    pub key_id: String,

    /// Server-issued challenge identifier. Present for YubiKey flows, absent
    /// for client flows. Serialised as `challengeId` in JSON.
    #[serde(rename = "challengeId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub challenge_id: Option<String>,

    /// Request timestamp in seconds since the Unix epoch.
    #[zeroize(skip)]
    pub timestamp: u64,

    /// Hex-encoded HMAC value. SHA-1 for YubiKey, SHA-256 for clients.
    ///
    /// # Security
    ///
    /// This field is sensitive. It is zeroised on drop and redacted in
    /// [`Debug`] output.
    pub hmac: String,

    /// Replay-prevention nonce: exactly 64 hex characters (256 bits).
    #[zeroize(skip)]
    pub nonce: String,
}

impl core::fmt::Debug for Authorizer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Authorizer")
            .field("format", &self.format)
            .field("key_id", &self.key_id)
            .field("challenge_id", &self.challenge_id)
            .field("timestamp", &self.timestamp)
            .field("hmac", &"[REDACTED]")
            .field("nonce", &self.nonce)
            .finish()
    }
}

/// Upper bound on individual string fields in protocol types. Applied during
/// input validation to reject oversized payloads before further processing.
const MAX_PROTOCOL_FIELD_LEN: usize = 512;

impl Authorizer {
    /// Validate structural invariants on the authoriser fields.
    ///
    /// Checks that `format` is a recognised value, `nonce` is exactly 64 hex
    /// characters (256 bits), `key_id` is within length bounds, and `hmac` is
    /// non-empty and not excessively long.
    ///
    /// Returns `Err` with a human-readable message on the first violation.
    pub fn validate(&self) -> core::result::Result<(), String> {
        match self.format.as_str() {
            "yubikey" | "client" => {}
            other => {
                return Err(format!(
                    "invalid authorizer format '{}', expected 'yubikey' or 'client'",
                    other
                ));
            }
        }

        // nonce must be exactly 64 hex characters (256 bits)
        if self.nonce.len() != 64 {
            return Err(format!(
                "nonce must be exactly 64 hex characters, got {}",
                self.nonce.len()
            ));
        }
        if !self.nonce.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("nonce must contain only hex characters".to_string());
        }

        // key_id length check
        if self.key_id.is_empty() || self.key_id.len() > MAX_PROTOCOL_FIELD_LEN {
            return Err(format!(
                "key_id must be 1-{} characters",
                MAX_PROTOCOL_FIELD_LEN
            ));
        }

        // hmac length check (hex-encoded SHA-1 is 40 chars, SHA-256 is 64 chars)
        if self.hmac.is_empty() || self.hmac.len() > 128 {
            return Err("hmac must be 1-128 characters".to_string());
        }

        Ok(())
    }
}

/// Request body for `POST /v1/challenge`, initiating the YubiKey HMAC
/// challenge/response flow for officer authentication.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    /// Identifier of the officer requesting a challenge.
    pub officer_id: String,
}

/// Response from `POST /v1/challenge`, containing the server-generated
/// challenge that the officer's YubiKey must HMAC-SHA-1 sign.
///
/// The `challenge` field is hex-encoded and treated as sensitive. The manual
/// [`Debug`] implementation replaces it with `[REDACTED]`.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct ChallengeResponse {
    /// Opaque challenge identifier, passed back in the [`Authorizer`].
    #[zeroize(skip)]
    pub challenge_id: String,

    /// Hex-encoded random challenge bytes. The YubiKey computes
    /// `HMAC-SHA-1(slot_secret, challenge)` and the result is sent as the
    /// `hmac` field in [`Authorizer`].
    ///
    /// # Security
    ///
    /// Sensitive. Zeroised on drop and redacted in debug output.
    pub challenge: String,

    /// Signed Unix timestamp after which this challenge is expired and the
    /// server will reject it.
    #[zeroize(skip)]
    pub expires_at: i64,
}

impl core::fmt::Debug for ChallengeResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChallengeResponse")
            .field("challenge_id", &self.challenge_id)
            .field("challenge", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Request body for `POST /v1/sign`, asking the issuer to RedJubjub-sign a
/// Pedersen commitment within an existing issuance session.
///
/// The wallet computes the commitment locally from the user's DOB and
/// randomness, then sends only the commitment (not the DOB) to the issuer.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct SignCommitmentRequest {
    /// Session identifier returned by the prior `POST /v1/start` call.
    ///
    /// # Security
    ///
    /// Sensitive. Zeroised on drop and redacted in debug output.
    #[zeroize(skip)]
    pub session_id: String,

    /// Pedersen commitment to sign, base64url-encoded 32 bytes.
    #[serde(with = "base64_bytes")]
    #[zeroize(skip)]
    pub commitment: [u8; 32],

    /// Re-authentication payload for this step.
    pub authorizer: Authorizer,
}

impl core::fmt::Debug for SignCommitmentRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignCommitmentRequest")
            .field("session_id", &"[REDACTED]")
            .field("commitment", &self.commitment)
            .field("authorizer", &self.authorizer)
            .finish()
    }
}

/// Response from `POST /v1/sign`, returning the issuer-signed credential
/// header that the wallet combines with its local secrets to form a
/// complete [`CredentialV2`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignCommitmentResponse {
    /// The signed credential header containing the issuer's RedJubjub
    /// signature, commitment, timestamps, and schema.
    pub credential: SignedCredentialHeader,
}

/// Payload extracted from a verification QR code (or deep link) presented by
/// the relying party (RP).
///
/// The wallet scans this payload, generates a Groth16 age proof against
/// `rp_challenge` and `cutoff_days`, then POSTs the result to `verify_url`
/// along with the `submit_secret`.
///
/// Several fields are sensitive (`rp_challenge`, `submit_secret`,
/// `code_verifier`). The manual [`Debug`] implementation replaces them with
/// `[REDACTED]`, and the struct derives [`Zeroize`] and [`ZeroizeOnDrop`].
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
// INTENTIONAL: deny_unknown_fields is NOT applied here.
//
// The verifier server may add new fields to the QR challenge payload in
// future protocol versions (e.g. short_code, short_code_formatted,
// display hints). The wallet MUST tolerate unknown fields for forward
// compatibility so that older wallet builds continue to work with newer
// server payloads. Adding deny_unknown_fields would cause deserialisation
// failures when the server sends any field the wallet does not know about.
pub struct QrChallengePayload {
    /// Server-assigned identifier for this challenge session.
    #[zeroize(skip)]
    pub challenge_id: String,

    /// Random challenge from the RP, base64url-encoded 32 bytes.
    ///
    /// # Security
    ///
    /// Sensitive. Bound into the Groth16 public inputs so the proof is
    /// tied to this specific challenge.
    pub rp_challenge: String,

    /// Age cutoff expressed as days since the Unix epoch. The proof
    /// demonstrates that the credential holder's DOB is on or before this
    /// value (for `over_age`) or strictly after it (for `under_age`).
    #[zeroize(skip)]
    pub cutoff_days: i32,

    /// Identifier of the Groth16 verifying key the server will use to
    /// check the proof.
    #[zeroize(skip)]
    pub verifying_key_id: u32,

    /// Shared secret the wallet must include when submitting the proof,
    /// base64url-encoded 32 bytes.
    ///
    /// # Security
    ///
    /// Sensitive. Prevents third parties from submitting proofs on behalf
    /// of the wallet.
    pub submit_secret: String,

    /// Challenge expiry as a Unix timestamp (seconds). The server rejects
    /// proof submissions after this point.
    #[zeroize(skip)]
    pub expires_at: u64,

    /// Absolute URL to which the wallet POSTs the completed proof.
    #[zeroize(skip)]
    pub verify_url: String,

    /// Optional PKCE code verifier for OAuth integration flows.
    ///
    /// # Security
    ///
    /// Sensitive. Zeroised on drop and redacted in debug output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,

    /// Proof direction: `"over_age"` (default) or `"under_age"`.
    #[serde(default)]
    #[zeroize(skip)]
    pub proof_direction: Option<String>,
}

impl core::fmt::Debug for QrChallengePayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QrChallengePayload")
            .field("challenge_id", &self.challenge_id)
            .field("rp_challenge", &"[REDACTED]")
            .field("cutoff_days", &self.cutoff_days)
            .field("verifying_key_id", &self.verifying_key_id)
            .field("submit_secret", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("verify_url", &self.verify_url)
            .field("code_verifier", &"[REDACTED]")
            .field("proof_direction", &self.proof_direction)
            .finish()
    }
}

impl QrChallengePayload {
    /// Validate that all string fields are within acceptable length bounds.
    ///
    /// Each field must be non-empty and at most `MAX_PROTOCOL_FIELD_LEN`
    /// characters. `proof_direction`, when present, must be one of the two
    /// recognised values.
    ///
    /// Returns `Err` with a human-readable message on the first violation.
    pub fn validate_field_lengths(&self) -> core::result::Result<(), String> {
        if self.challenge_id.is_empty() || self.challenge_id.len() > MAX_PROTOCOL_FIELD_LEN {
            return Err(format!(
                "challenge_id must be 1-{} characters",
                MAX_PROTOCOL_FIELD_LEN
            ));
        }
        if self.rp_challenge.is_empty() || self.rp_challenge.len() > MAX_PROTOCOL_FIELD_LEN {
            return Err(format!(
                "rp_challenge must be 1-{} characters",
                MAX_PROTOCOL_FIELD_LEN
            ));
        }
        if self.submit_secret.is_empty() || self.submit_secret.len() > MAX_PROTOCOL_FIELD_LEN {
            return Err(format!(
                "submit_secret must be 1-{} characters",
                MAX_PROTOCOL_FIELD_LEN
            ));
        }
        if self.verify_url.is_empty() || self.verify_url.len() > MAX_PROTOCOL_FIELD_LEN {
            return Err(format!(
                "verify_url must be 1-{} characters",
                MAX_PROTOCOL_FIELD_LEN
            ));
        }
        match url::Url::parse(&self.verify_url) {
            Ok(parsed) => {
                if parsed.scheme() != "https" {
                    return Err(format!(
                        "verify_url must use HTTPS scheme, got '{}'",
                        parsed.scheme()
                    ));
                }
            }
            Err(e) => {
                return Err(format!("verify_url is not a valid URL: {}", e));
            }
        }
        if let Some(ref cv) = self.code_verifier {
            if cv.len() > MAX_PROTOCOL_FIELD_LEN {
                return Err(format!(
                    "code_verifier must be at most {} characters",
                    MAX_PROTOCOL_FIELD_LEN
                ));
            }
        }
        if let Some(ref dir) = self.proof_direction {
            match dir.as_str() {
                "over_age" | "under_age" => {}
                other => {
                    return Err(format!(
                        "invalid proof_direction '{}', expected 'over_age' or 'under_age'",
                        other
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Public inputs for a Groth16 age proof, serialised as JSON for API
/// submission.
///
/// These values are public by design (they appear in the proof verification
/// equation). [`Zeroize`] and [`ZeroizeOnDrop`] are derived for
/// defence-in-depth when this struct is embedded alongside secret data.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct AgePublicJson {
    /// Age cutoff in days since the Unix epoch. Matches the value from the
    /// QR challenge payload.
    pub cutoff_days: i32,

    /// RP challenge, base64url-encoded 32 bytes.
    pub rp_challenge: String,

    /// Issuer's RedJubjub verification key, used to bind the proof to a
    /// specific issuer. The field name `issuer` wraps a dedicated struct so
    /// the on-wire JSON shape is `{ "issuer": { "value": "..." } }`.
    pub issuer: IssuerKeyJson,

    /// Credential nullifier, base64url-encoded 32 bytes. Allows the verifier
    /// to detect proof replay without learning which credential was used.
    pub cred_nullifier: String,
}

/// Wrapper carrying the base64url-encoded 32-byte raw RedJubjub verification
/// key.
///
/// Field name is `value` to match the on-wire JSON schema expected by the
/// verifier API: `{ "issuer": { "value": "..." } }`.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct IssuerKeyJson {
    /// Base64url-encoded 32 bytes of the raw RedJubjub verification key
    /// (compressed Jubjub subgroup point encoding).
    pub value: String,
}

/// Complete Groth16 age proof in JSON format, ready for submission to the
/// verifier API.
///
/// Contains the proof bytes and public inputs alongside a verifying key
/// identifier so the server can select the correct verification key.
/// All values are public ZK outputs. [`Zeroize`] is derived for
/// defence-in-depth.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct AgeProofJson {
    /// Identifier of the Groth16 verifying key that corresponds to the
    /// proving key used to generate this proof.
    pub verifying_key_id: u32,

    /// Public inputs bound into the proof.
    pub public: AgePublicJson,

    /// Groth16 proof bytes (A, B, C curve points), base64url-encoded.
    pub proof: String,
}

/// Request body for `POST /v1/verify`, submitting a completed age proof to
/// the verifier API.
///
/// The wallet populates this from the [`QrChallengePayload`] (for fields
/// like `challenge_id`, `submit_secret`, `code_verifier`, `proof_direction`)
/// and from the proof generation pipeline (for `proof`).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct SubmitProofRequest {
    /// Challenge identifier from the QR payload, linking this submission to
    /// the original verification session.
    #[zeroize(skip)]
    pub challenge_id: String,

    /// Shared secret from the QR payload, proving the submitter is the
    /// intended wallet.
    pub submit_secret: String,

    /// Optional PKCE code verifier for OAuth integration flows.
    /// Omitted from serialisation when absent, since the provii-verifier's
    /// proof submission endpoint does not accept this field (PKCE is
    /// validated on the separate /redeem endpoint).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,

    /// The Groth16 age proof with its public inputs.
    pub proof: AgeProofJson,
}

impl core::fmt::Debug for SubmitProofRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SubmitProofRequest")
            .field("challenge_id", &self.challenge_id)
            .field("submit_secret", &"[REDACTED]")
            .field("code_verifier", &"[REDACTED]")
            .field("proof", &self.proof)
            .finish()
    }
}

/// Response from the verifier API after a proof submission.
///
/// Server response from the `/v1/verify` submit-proof endpoint or the
/// `/v1/status/{id}` polling endpoint.
///
/// `result` carries one of: `"OK"`, `"INVALID_PROOF"`, `"INVALID_PROOF_FORMAT"`,
/// `"VERIFIER_ERROR"`, or `"POLICY_REJECTED"`. The wallet uses `state` to decide
/// whether to keep polling (`"pending"`, `"processing"`) or treat the flow as
/// terminal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// Verification outcome. `"OK"` indicates the proof was accepted.
    pub result: String,

    /// Current state of the verification session, for example `"verified"`,
    /// `"failed"`, `"pending"`, or `"processing"`.
    pub state: String,
}

/// Non-secret metadata stored alongside a credential in the wallet's
/// persistent store.
///
/// This struct carries display and bookkeeping information. It does not
/// contain any cryptographic material, so it does not derive [`Zeroize`].
///
/// NOTE: The FFI layer (`crates/ffi/src/types.rs`) defines its own
/// `CredentialMetadata` with additional fields (`last_used`, `use_count`,
/// `credential_type`, `nickname`, `managed_index`) needed for on-device
/// storage bookkeeping and multi-credential slot management. That type is
/// not a mirror of this one. This core type is a minimal read-only
/// projection produced by [`CredentialV2::to_metadata`], used internally
/// by the storage trait and credential management layer. The FFI type
/// extends it with runtime state that only the platform layer tracks.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialMetadata {
    /// Stable identifier for storage lookups, typically a BLAKE3 hash of
    /// the credential's commitment bytes.
    pub id: String,

    /// Optional human-readable label assigned by the user.
    pub label: Option<String>,

    /// Timestamp (seconds since the Unix epoch) when the credential was
    /// imported into this wallet.
    pub imported_at: u64,

    /// Optional display name of the issuing organisation.
    pub issuer_name: Option<String>,
}

/// User-facing wallet configuration, persisted in platform-specific
/// preferences storage.
///
/// NOTE: The FFI layer (`crates/ffi/src/types.rs`) defines its own
/// `WalletConfig` with additional fields (`issuer_api_url`,
/// `verifier_api_url`, `verifier_api_key`, `verifier_origin`,
/// `environment`, `enable_parallel_prover`, `max_prover_threads`) needed
/// by the platform runtime. This core type holds only the subset of
/// preferences that the core business logic references directly. The FFI
/// type is the superset exposed to Swift and Kotlin via UniFFI and is not
/// a mirror of this struct.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletConfig {
    /// When `true`, the wallet automatically selects the most suitable
    /// credential for a verification request instead of prompting the user.
    pub auto_select: bool,

    /// Default timeout for network requests in seconds. Applied to proof
    /// submission, challenge fetches, issuance API calls, and key downloads.
    pub network_timeout: u64,

    /// When `true`, Groth16 proving keys are cached on disk after first
    /// download, avoiding repeated fetches at the cost of local storage.
    pub cache_proving_keys: bool,
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
#[path = "types_tests.rs"]
mod tests;
