// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Core crate for the Provii wallet SDK.
//!
//! Provides Groth16-based age proof generation and credential management,
//! built on the `provii-crypto` library suite. This is the primary Rust
//! entry point consumed by the UniFFI bindings layer (`provii-mobile-sdk-ffi`).

// deny rather than forbid: prover.rs contains one feature-gated unsafe block
// for mmap. See `init_prover_with_pk_mmap` for the SAFETY justification.
#![deny(unsafe_code)]
#![allow(unexpected_cfgs)] // `http` feature is defined externally by consumers

pub mod blind_issuance;
pub mod credential;
pub mod error;
pub mod issuance;
pub mod prover;
pub mod storage;
pub mod types;
pub mod utils;

// The `network` module is behind `http` because HTTP transport is provided by
// platform-specific code (OkHttp on Android, URLSession on iOS). Consumers
// enable this feature and supply the transport implementation.
#[cfg(feature = "http")]
pub mod network;

// Depends on the `network` module, so requires both feature gates.
#[cfg(all(feature = "async", feature = "http"))]
pub mod async_flow;

#[cfg(feature = "parallel")]
pub mod parallel;

pub use types::{
    CredentialMetadata, CredentialV2, IssuerTrustAnchor, QrChallengePayload, SubmitProofRequest,
    TrustedIssuerKey, WalletConfig,
};

pub use prover::{
    build_verify_request, get_proving_key_fingerprint, init_prover_with_pk_bytes,
    is_prover_initialized, ProverError,
};

pub use issuance::R_BITS_LEN;

pub use error::{Result, WalletError};

pub use utils::{validate_age, validate_uuid_format};
