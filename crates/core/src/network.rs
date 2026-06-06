// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! HTTP transport layer for wallet-to-verifier communication.
//!
//! Provides [`ApiClient`], a thin wrapper around the low-level `crate::net`
//! transport that adds JSON serialisation, timeouts, and automatic
//! [`zeroize::Zeroizing`] wrapping of request bodies that may contain secret
//! material (`submit_secret`, `code_verifier`).
//!
//! All methods on [`ApiClient`] are gated behind the `async` feature and
//! require a Tokio runtime. The underlying transport uses HTTP/3 (QUIC) via
//! the Quinn stack when the platform supports it.
//!
//! Deep link URL parsing is provided by [`crate::utils::parse_deep_link`].

use crate::types::{SubmitProofRequest, VerifyResponse};
use crate::{Result, WalletError};
use serde::{Deserialize, Serialize};
#[cfg(feature = "async")]
use zeroize::Zeroizing;

/// HTTP/3 client for communicating with Provii verifier and status endpoints.
///
/// Construct an instance with [`ApiClient::new`], optionally override the
/// default 30-second timeout with [`ApiClient::with_timeout`], then call
/// [`ApiClient::submit_proof`], [`ApiClient::post`], or [`ApiClient::get`].
///
/// # Security
///
/// Request bodies are serialised into a [`Zeroizing<String>`] so that
/// secret fields (e.g. `submit_secret`) are scrubbed from heap memory once
/// the request has been sent.
#[cfg(feature = "async")]
pub struct ApiClient {
    base_url: String,
    timeout: std::time::Duration,
}

#[cfg(feature = "async")]
impl ApiClient {
    /// Create a new client pointing at the given base URL.
    ///
    /// The URL must use `https://` (or `http://localhost` for local development)
    /// and must not exceed 2048 characters. A trailing slash is stripped
    /// automatically.
    ///
    /// # Errors
    ///
    /// Returns [`WalletError::InvalidInput`] if the URL is empty, too long,
    /// or uses an unsupported scheme.
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let mut url = base_url.into();
        if url.is_empty() {
            return Err(WalletError::InvalidInput(
                "base URL must not be empty".to_string(),
            ));
        }
        if url.len() > 2048 {
            return Err(WalletError::InvalidInput(
                "base URL exceeds 2048 characters".to_string(),
            ));
        }
        let is_https = url.starts_with("https://");
        let is_localhost =
            url.starts_with("http://localhost") || url.starts_with("http://127.0.0.1");
        if !is_https && !is_localhost {
            return Err(WalletError::InvalidInput(
                "base URL must use https:// (or http://localhost for development)".to_string(),
            ));
        }
        // Strip trailing slash for consistent path joining
        while url.ends_with('/') {
            url.pop();
        }
        Ok(Self {
            base_url: url,
            timeout: std::time::Duration::from_secs(30),
        })
    }

    /// Return a new client with the given request timeout in seconds.
    pub fn with_timeout(mut self, seconds: u64) -> Self {
        self.timeout = std::time::Duration::from_secs(seconds);
        self
    }

    /// Serialise a [`SubmitProofRequest`] and POST it to `/v1/verify`.
    ///
    /// The serialised JSON is wrapped in [`Zeroizing`] because it contains
    /// `submit_secret`.
    ///
    /// # Errors
    ///
    /// Returns [`WalletError::SerializationError`] if the request cannot be
    /// serialised, [`WalletError::NetworkError`] on transport failure, or
    /// [`WalletError::SerializationError`] if the response body is not valid
    /// [`VerifyResponse`] JSON.
    pub async fn submit_proof(&self, request: &SubmitProofRequest) -> Result<VerifyResponse> {
        let url = format!("{}/v1/verify", self.base_url);

        let request_json = Zeroizing::new(
            serde_json::to_string(request)
                .map_err(|e| WalletError::SerializationError(e.to_string()))?,
        );

        let response = crate::net::post_json(&url, &request_json)
            .await
            .map_err(|e| WalletError::NetworkError(e.to_string()))?;

        serde_json::from_str(&response).map_err(|e| WalletError::SerializationError(e.to_string()))
    }

    /// Serialise `body` as JSON and POST it to `{base_url}{path}`.
    ///
    /// The serialised JSON is wrapped in [`Zeroizing`] as a precaution
    /// because the caller's type may contain secret fields.
    ///
    /// # Errors
    ///
    /// Propagates serialisation and network errors as [`WalletError`].
    pub async fn post<T, R>(&self, path: &str, body: &T) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let url = format!("{}{}", self.base_url, path);

        let request_json = Zeroizing::new(
            serde_json::to_string(body)
                .map_err(|e| WalletError::SerializationError(e.to_string()))?,
        );

        let response = crate::net::post_json(&url, &request_json)
            .await
            .map_err(|e| WalletError::NetworkError(e.to_string()))?;

        serde_json::from_str(&response).map_err(|e| WalletError::SerializationError(e.to_string()))
    }

    /// Issue a GET request to `{base_url}{path}` and deserialise the response.
    ///
    /// Uses the client's configured timeout.
    ///
    /// # Errors
    ///
    /// Returns [`WalletError::NetworkError`] on transport failure or
    /// [`WalletError::SerializationError`] if the response is not valid JSON
    /// for type `R`.
    pub async fn get<R>(&self, path: &str) -> Result<R>
    where
        R: for<'de> Deserialize<'de>,
    {
        let url = format!("{}{}", self.base_url, path);

        let response = crate::net::get_with_timeout(&url, self.timeout.as_secs())
            .await
            .map_err(|e| WalletError::NetworkError(e.to_string()))?;

        serde_json::from_str(&response).map_err(|e| WalletError::SerializationError(e.to_string()))
    }
}
