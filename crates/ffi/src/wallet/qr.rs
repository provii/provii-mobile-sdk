// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! QR code, deep link, and manual short-code entry handling for
//! [`ProviiWallet`].

use super::*;
use crate::qr::{
    extract_challenge_id_from_qr, parse_qr_code, validate_challenge_id_format, validate_qr_payload,
};
use crate::tokio_rt;
#[cfg(feature = "http")]
use zeroize::Zeroize;

#[uniffi::export]
impl ProviiWallet {
    /// Classify a scanned QR code as either an attestation or a verification
    /// challenge and return the appropriate [`QrAction`].
    pub fn process_scanned_qr(&self, qr_content: String) -> FfiResult<QrAction> {
        // Parse the QR code using wallet instance method to respect environment configuration
        let payload = self.parse_qr_payload_internal(&qr_content)?;
        let parsed = serde_json::to_string(&payload)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;
        let data: serde_json::Value = serde_json::from_str(&parsed)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

        // Determine action based on type
        if data.get("type") == Some(&serde_json::json!("attestation")) {
            let attest_data = data.get("data").and_then(|d| d.as_str()).ok_or_else(|| {
                FfiError::InvalidFormat {
                    msg: "Missing attestation data".to_string(),
                }
            })?;

            Ok(QrAction::Attestation {
                attestation_data: attest_data.to_string(),
            })
        } else if data.get("challenge_id").is_some() {
            // It's a verification challenge
            Ok(QrAction::VerificationChallenge {
                challenge_json: parsed,
            })
        } else {
            Err(FfiError::InvalidFormat {
                msg: "Unknown QR code type".to_string(),
            })
        }
    }

    /// Parse a QR challenge, cache it, and start a verification session.
    ///
    /// Returns the challenge ID on success. The cached challenge expires
    /// after 300 seconds.
    pub fn process_qr_challenge(&self, qr_content: String) -> FfiResult<String> {
        log::info!("process_qr_challenge called");

        let challenge: QrChallengePayload = self.parse_qr_payload_internal(&qr_content)?;

        let challenge_id = challenge.challenge_id.clone();
        log::info!("Processing challenge ID: {}", challenge_id);
        log::debug!(
            "Challenge details: cutoff_days={}, vk_id={}",
            challenge.cutoff_days,
            challenge.verifying_key_id
        );

        let now = std::time::SystemTime::now();
        let expires_at = now
            .checked_add(std::time::Duration::from_secs(300))
            .unwrap_or(now);

        let mut cached = safe_lock(&self.cached_challenges);

        // Evict expired entries before inserting to prevent unbounded growth.
        if cached.len() >= 64 {
            let now_for_evict = std::time::SystemTime::now();
            cached.retain(|_, v| v.expires_at > now_for_evict);
        }
        // Hard cap: reject if still too many after eviction.
        if cached.len() >= 64 {
            return Err(FfiError::InvalidFormat {
                msg: "challenge cache full; try again shortly".to_string(),
            });
        }

        cached.insert(
            challenge_id.clone(),
            CachedChallenge {
                payload: challenge.clone(),
                received_at: now,
                expires_at,
            },
        );

        self.state_manager.start_verification(&challenge_id)?;

        log::info!("Challenge cached and verification started");
        Ok(challenge_id)
    }

    /// Parse a `proviiwallet.app` deep link into a [`DeeplinkAction`].
    pub fn handle_deeplink(&self, url: String) -> FfiResult<DeeplinkAction> {
        crate::deeplink::parse(url).map_err(Into::into)
    }

    /// Parse a raw QR string into its JSON payload, respecting the current
    /// environment configuration for verifier URL resolution.
    pub fn parse_qr_payload(&self, qr_content: String) -> FfiResult<String> {
        // Use internal method that respects environment configuration
        let payload = self.parse_qr_payload_internal(&qr_content)?;
        serde_json::to_string(&payload).map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })
    }

    /// Parse a QR code string. Convenience wrapper around [`parse_qr_payload`](Self::parse_qr_payload).
    pub fn parse_qr(&self, qr_content: String) -> FfiResult<String> {
        // Use internal method that respects environment configuration
        let payload = self.parse_qr_payload_internal(&qr_content)?;
        serde_json::to_string(&payload).map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })
    }

    /// Validate a QR code string and return whether it represents a well-formed payload.
    pub fn validate_qr(&self, qr_content: String) -> FfiResult<bool> {
        // Use internal method that respects environment configuration
        let payload = self.parse_qr_payload_internal(&qr_content)?;
        let payload_json = serde_json::to_string(&payload)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;
        validate_qr_payload(payload_json)
    }

    /// Fetch challenge details from the configured verifier endpoint
    /// This respects the environment configuration (production/sandbox/etc)
    pub fn fetch_challenge_details(&self, challenge_id: String) -> FfiResult<String> {
        validate_challenge_id_format(&challenge_id)?;

        #[cfg(feature = "http")]
        {
            let (url, mut api_key, origin) = {
                let config = safe_lock(&self.config);
                let url = format!(
                    "{}/v1/challenge/{}/details",
                    config.verifier_api_url.trim_end_matches('/'),
                    challenge_id
                );
                let api_key = config.verifier_api_key.clone();
                let origin = config.verifier_origin.clone();
                (url, api_key, origin)
            };

            log::info!(
                "Fetching challenge details from configured verifier: {}",
                url
            );

            let rt = tokio_rt()?;

            let result = rt.block_on(async {
                crate::net::get_with_headers(&url, 10, api_key.as_deref(), origin.as_deref()).await
            });

            // Zeroize the cloned api_key after the HTTP call completes
            api_key.zeroize();

            result
        }

        #[cfg(not(feature = "http"))]
        {
            Err(FfiError::Generic {
                msg: "HTTP support not compiled in".to_string(),
            })
        }
    }

    /// Fetch challenge details using a 12-digit short code
    /// This respects the environment configuration (production/sandbox/etc)
    pub fn fetch_challenge_by_short_code(&self, short_code: String) -> FfiResult<String> {
        #[cfg(feature = "http")]
        {
            // Remove any spaces from the short code
            let normalized: String = short_code.chars().filter(|c| !c.is_whitespace()).collect();

            // Validate short code format
            if !is_short_code(normalized.clone()) {
                return Err(FfiError::InvalidFormat {
                    msg: "Invalid short code format (must be 12 digits)".to_string(),
                });
            }

            let url = {
                let config = safe_lock(&self.config);
                format!(
                    "{}/v1/challenge/by-code/{}",
                    config.verifier_api_url.trim_end_matches('/'),
                    normalized
                )
            };

            log::info!(
                "Fetching challenge by short code from configured verifier: {}",
                url
            );

            let rt = tokio_rt()?;

            rt.block_on(async { crate::net::get_with_timeout(&url, 10).await })
        }

        #[cfg(not(feature = "http"))]
        {
            Err(FfiError::Generic {
                msg: "HTTP support not compiled in".to_string(),
            })
        }
    }

    /// Process manual entry of a 12-digit short code
    /// and fetch the challenge details
    pub fn process_manual_entry(&self, input: String) -> FfiResult<String> {
        log::info!(
            "process_manual_entry called with input length: {}",
            input.len()
        );

        // Remove whitespace (user may enter "1234 5678 9012")
        let normalized: String = input.chars().filter(|c| !c.is_whitespace()).collect();

        // Validate it's a 12-digit short code
        if !is_short_code(normalized.clone()) {
            return Err(FfiError::InvalidFormat {
                msg: "Invalid short code format. Expected 12 digits.".to_string(),
            });
        }

        log::info!("Processing short code, fetching challenge");
        let challenge_json = self.fetch_challenge_by_short_code(normalized)?;

        // Parse the response to extract challenge details
        let challenge: QrChallengePayload =
            serde_json::from_str(&challenge_json).map_err(|e| FfiError::InvalidFormat {
                msg: format!("Failed to parse challenge response: {}", e),
            })?;
        challenge
            .validate_field_lengths()
            .map_err(|e| FfiError::InvalidFormat { msg: e })?;

        let challenge_id = challenge.challenge_id.clone();
        log::info!("Short code resolved to challenge ID: {}", challenge_id);

        // Cache the challenge
        let now = std::time::SystemTime::now();
        let expires_at = now
            .checked_add(std::time::Duration::from_secs(300))
            .unwrap_or(now);

        let mut cached = safe_lock(&self.cached_challenges);

        // Evict expired entries before inserting to prevent unbounded growth.
        if cached.len() >= 64 {
            let now_for_evict = std::time::SystemTime::now();
            cached.retain(|_, v| v.expires_at > now_for_evict);
        }
        if cached.len() >= 64 {
            return Err(FfiError::InvalidFormat {
                msg: "challenge cache full; try again shortly".to_string(),
            });
        }

        cached.insert(
            challenge_id.clone(),
            CachedChallenge {
                payload: challenge.clone(),
                received_at: now,
                expires_at,
            },
        );

        self.state_manager.start_verification(&challenge_id)?;

        log::info!("Challenge cached and verification started");
        Ok(challenge_id)
    }
}

impl ProviiWallet {
    /// Parse a QR string, resolving minimal challenges via HTTP if necessary.
    fn parse_qr_payload_internal(&self, qr_content: &str) -> FfiResult<QrChallengePayload> {
        // Try to parse with the standalone function first
        match parse_qr_code(qr_content.to_string()) {
            Ok(parsed) => serde_json::from_str(&parsed)
                .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() }),
            Err(e) if e.to_string().contains("MINIMAL_CHALLENGE") => {
                // Handle minimal challenge - fetch details using configured verifier URL
                log::info!("Detected minimal challenge, fetching details from configured verifier");
                let challenge_id = extract_challenge_id_from_qr(qr_content.to_string())?;
                validate_challenge_id_format(&challenge_id)?;

                // Get verifier URL from config
                let verifier_url = {
                    let config = safe_lock(&self.config);
                    config.verifier_api_url.clone()
                };

                let url = format!("{}/v1/challenge/{}/details", verifier_url, challenge_id);
                log::info!("Fetching challenge details from: {}", url);

                // Fetch challenge details using configured URL
                #[cfg(feature = "http")]
                {
                    use crate::net::get_with_timeout;
                    let rt = tokio_rt()?;

                    rt.block_on(async { get_with_timeout(&url, 10).await })
                        .and_then(|json| {
                            let payload: QrChallengePayload = serde_json::from_str(&json)
                                .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;
                            payload
                                .validate_field_lengths()
                                .map_err(|e| FfiError::InvalidFormat { msg: e })?;
                            Ok(payload)
                        })
                }

                #[cfg(not(feature = "http"))]
                {
                    Err(FfiError::Generic {
                        msg: "HTTP support not compiled in, cannot fetch challenge details"
                            .to_string(),
                    })
                }
            }
            Err(e) => Err(e),
        }
    }
}
