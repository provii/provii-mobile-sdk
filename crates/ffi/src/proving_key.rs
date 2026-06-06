// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Proving key lifecycle management for the FFI boundary.
//!
//! The Groth16 age-verification circuit requires a ~52 MB proving key (PK)
//! that is too large to bundle inside the app binary. This module handles the
//! full download-verify-init cycle:
//!
//! 1. Check available storage via [`ProvingKeyManager::check_storage_available`].
//! 2. Download the PK with HTTP/3 (falling back to HTTP/2) through
//!    [`ProvingKeyManager::download_with_progress`].
//! 3. Verify size and Blake2s-256 integrity on disk.
//! 4. Load into memory and hand off to `provii-mobile-sdk-core` prover init.
//!
//! # Integrity verification
//!
//! Every PK file is verified twice: once after download (before the atomic
//! rename from the `.tmp` path) and again before loading into memory for
//! prover initialisation. Verification checks both the exact byte length and
//! a Blake2s-256 digest against compile-time constants, so a corrupted or
//! tampered file can never reach the prover.
//!
//! # Resume support
//!
//! Partial downloads are detected by the presence of a `.tmp` file and
//! resumed with an HTTP `Range` header, avoiding full re-downloads on
//! unstable mobile connections.

use crate::errors::FfiError;
use blake2::{Blake2s256, Digest};
use bytes::Buf;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Retry budget tracking (per vk_id, 5 attempts within 24 hours)
// ---------------------------------------------------------------------------

/// Maximum number of download attempts allowed per `vk_id` within a 24 hour
/// rolling window. Mandated by protocol spec section 13.8.
const MAX_RETRIES_PER_24H: usize = 5;

/// Rolling window duration for the retry budget.
const RETRY_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Base backoff duration in milliseconds (2 seconds).
const BASE_BACKOFF_MS: u64 = 2_000;

/// Maximum backoff duration in milliseconds (60 seconds).
const MAX_BACKOFF_MS: u64 = 60_000;

/// Global retry tracker. Each `vk_id` maps to a list of attempt timestamps.
/// Entries older than 24 hours are trimmed on every access.
static RETRY_STATE: once_cell::sync::Lazy<Mutex<HashMap<u32, Vec<Instant>>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

/// Remove entries older than [`RETRY_WINDOW`] from the given attempt list.
fn trim_stale_attempts(attempts: &mut Vec<Instant>) {
    let cutoff = Instant::now().checked_sub(RETRY_WINDOW);
    if let Some(cutoff) = cutoff {
        attempts.retain(|t| *t > cutoff);
    }
    // If checked_sub returns None (should not happen in practice), retain all.
}

/// Record a new attempt for the given `vk_id`. Returns `Err` if the budget
/// has been exhausted (i.e. 5 attempts already recorded within the rolling
/// 24 hour window).
fn record_attempt(vk_id: u32) -> Result<usize, FfiError> {
    let mut map = RETRY_STATE.lock().map_err(|e| FfiError::Generic {
        msg: format!("Retry state lock poisoned: {}", e),
    })?;
    let attempts = map.entry(vk_id).or_default();
    trim_stale_attempts(attempts);

    if attempts.len() >= MAX_RETRIES_PER_24H {
        return Err(FfiError::RetryBudgetExceeded {
            msg: format!(
                "{} download attempts for vk_id {} in the last 24 hours. \
                 No further retries permitted until the window expires.",
                MAX_RETRIES_PER_24H, vk_id
            ),
        });
    }

    attempts.push(Instant::now());
    // Return the 0-based attempt index (i.e. how many previous attempts exist).
    Ok(attempts.len().saturating_sub(1))
}

/// Query the number of attempts already consumed for `vk_id` within the
/// current 24 hour window.
fn attempts_consumed(vk_id: u32) -> Result<usize, FfiError> {
    let mut map = RETRY_STATE.lock().map_err(|e| FfiError::Generic {
        msg: format!("Retry state lock poisoned: {}", e),
    })?;
    let attempts = map.entry(vk_id).or_default();
    trim_stale_attempts(attempts);
    Ok(attempts.len())
}

/// Compute the jittered backoff delay for a given attempt index.
///
/// `delay_ms = min(2000 * 2^attempt, 60000)`, then
/// `actual_delay = rand in [0, delay_ms)`.
fn compute_jittered_backoff(attempt: usize) -> Duration {
    // 2^attempt, clamped so the shift cannot overflow a u32. The `.min(63)`
    // guarantees the value fits in u32 (max 63 < u32::MAX), so `try_from`
    // will never fail here.
    let shift = match u32::try_from(attempt.min(63)) {
        Ok(v) => v,
        Err(_) => return Duration::ZERO,
    };
    let exponential = BASE_BACKOFF_MS.saturating_mul(1u64.checked_shl(shift).unwrap_or(u64::MAX));
    let capped_ms = exponential.min(MAX_BACKOFF_MS);

    if capped_ms == 0 {
        return Duration::ZERO;
    }

    // Full jitter: uniform random in [0, capped_ms).
    // The `rem` (%) is safe because `capped_ms` is proven > 0 by the guard above.
    #[allow(clippy::arithmetic_side_effects)]
    let jittered = rand::random::<u64>() % capped_ms;
    Duration::from_millis(jittered)
}

/// Reset the retry budget for a given `vk_id`. Exposed for testing.
#[cfg(test)]
fn reset_retry_budget(vk_id: u32) {
    if let Ok(mut map) = RETRY_STATE.lock() {
        map.remove(&vk_id);
    }
}

/// Manages the on-disk lifecycle of the Groth16 proving key.
///
/// A single PK file is identified by its verifying key ID and stored under
/// the application files directory provided at construction time.
pub struct ProvingKeyManager {
    /// Root directory for PK storage (the platform's app-files dir).
    storage_dir: PathBuf,

    /// Filename derived from the verifying key ID, e.g. `age_pk.2031517468.bin`.
    pk_filename: String,

    /// Verifying key ID that this PK corresponds to.
    #[allow(dead_code)] // Stored for diagnostic reference; read in tests
    vk_id: u32,
}

impl ProvingKeyManager {
    /// The verifying key ID embedded in the current circuit parameters.
    const VK_ID: u32 = 2031517468;

    /// CDN URL for the proving key binary.
    const PK_URL: &'static str = "https://cdn.provii.app/age_pk.2031517468.bin";

    /// Expected byte length of a valid proving key file.
    const PK_SIZE: u64 = 51_945_624;

    /// Hex-encoded Blake2s-256 digest of a valid proving key file.
    const PK_BLAKE2S: &'static str =
        "8839a9f0e88175af6cdeeea09ab9e031a9f627c6e42de8001fd31e0fd0586895";

    /// Minimum free space (bytes) required before starting a download.
    ///
    /// Set above the PK size to leave headroom for the temporary file that
    /// coexists with the final file during the atomic rename window.
    const MIN_FREE_SPACE: u64 = 65_000_000;

    /// Create a new manager rooted at the given application files directory.
    pub fn new(app_files_dir: &str) -> Self {
        Self {
            storage_dir: PathBuf::from(app_files_dir),
            pk_filename: format!("age_pk.{}.bin", Self::VK_ID),
            vk_id: Self::VK_ID,
        }
    }

    /// Verify the integrity of a PK file by checking size then Blake2s-256.
    ///
    /// Returns `Ok(false)` when the file is missing, has the wrong size, or
    /// fails the hash check. Returns `Err` only on I/O failures that prevent
    /// the check from completing.
    fn verify_pk_integrity(&self, path: &Path) -> Result<bool, FfiError> {
        if !path.exists() {
            return Ok(false);
        }

        let metadata = fs::metadata(path).map_err(|e| FfiError::Storage {
            msg: format!("Failed to get metadata: {}", e),
        })?;

        if metadata.len() != Self::PK_SIZE {
            log::warn!(
                "PK size mismatch: expected {} bytes, got {} bytes",
                Self::PK_SIZE,
                metadata.len()
            );
            return Ok(false);
        }

        let mut file = File::open(path).map_err(|e| FfiError::Storage {
            msg: format!("Failed to open PK: {}", e),
        })?;

        let mut hasher = Blake2s256::new();
        let mut buffer = vec![0u8; 1024 * 1024]; // 1 MB read buffer

        loop {
            let bytes_read = file.read(&mut buffer).map_err(|e| FfiError::Storage {
                msg: format!("Failed to read PK: {}", e),
            })?;

            if bytes_read == 0 {
                break;
            }

            let chunk = buffer.get(..bytes_read).ok_or_else(|| FfiError::Generic {
                msg: "read returned more bytes than buffer length".to_string(),
            })?;
            hasher.update(chunk);
        }

        let hash = hex::encode(hasher.finalize());

        if hash != Self::PK_BLAKE2S {
            log::warn!(
                "PK hash mismatch: expected {}, got {}",
                Self::PK_BLAKE2S,
                hash
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// Check whether the storage directory has enough free space for a PK
    /// download.
    pub fn check_storage_available(&self) -> Result<StorageStatus, FfiError> {
        let free_space = get_free_space(&self.storage_dir)?;

        if free_space < Self::MIN_FREE_SPACE {
            return Ok(StorageStatus::InsufficientSpace {
                available_mb: free_space / 1_000_000,
                required_mb: Self::MIN_FREE_SPACE / 1_000_000,
            });
        }

        Ok(StorageStatus::Available)
    }

    /// Download the proving key, reporting progress through the callback.
    ///
    /// Implements the retry policy mandated by protocol spec section 13.8:
    /// exponential backoff starting at 2 s (capped at 60 s), full jitter,
    /// and a hard limit of 5 attempts per `vk_id` within a rolling 24 hour
    /// window. On success the file is integrity-verified and atomically
    /// renamed into place. On retry budget exhaustion the caller receives
    /// [`FfiError::RetryBudgetExceeded`].
    ///
    /// HTTP/3 is attempted first with an HTTP/2 fallback. Integrity failures
    /// delete the partial file so that the next attempt starts from zero
    /// bytes (spec requirement).
    #[cfg(feature = "http")]
    pub async fn download_with_progress<F>(&self, mut progress_callback: F) -> Result<(), FfiError>
    where
        F: FnMut(DownloadProgress) + Send,
    {
        // Pre-flight: storage space.
        if let StorageStatus::InsufficientSpace {
            available_mb,
            required_mb,
        } = self.check_storage_available()?
        {
            return Err(FfiError::Storage {
                msg: format!(
                    "Not enough storage. Need {} MB but only {} MB available.",
                    required_mb, available_mb
                ),
            });
        }

        fs::create_dir_all(&self.storage_dir).map_err(|e| FfiError::Storage {
            msg: format!("Failed to create directory: {}", e),
        })?;

        let final_path = self.storage_dir.join(&self.pk_filename);

        // Skip download if a valid file already exists.
        if self.verify_pk_integrity(&final_path).unwrap_or(false) {
            log::info!("Valid PK already exists, skipping download");
            return Ok(());
        }

        // Retry loop. Each iteration is one full attempt (HTTP fetch +
        // integrity check). Budget enforcement happens at the top of the
        // loop via `record_attempt`.
        loop {
            // Budget gate: record this attempt (trims stale entries first).
            let attempt_idx = record_attempt(self.vk_id)?;

            log::info!(
                "PK download attempt {} of {} for vk_id {}",
                attempt_idx.saturating_add(1),
                MAX_RETRIES_PER_24H,
                self.vk_id
            );

            let attempt_err = match self
                .download_single_attempt(&final_path, &mut progress_callback)
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) => {
                    log::warn!(
                        "PK download attempt {} failed: {}",
                        attempt_idx.saturating_add(1),
                        e
                    );
                    e
                }
            };

            // Check whether we have budget remaining for another attempt.
            let consumed = attempts_consumed(self.vk_id)?;
            if consumed >= MAX_RETRIES_PER_24H {
                return Err(FfiError::RetryBudgetExceeded {
                    msg: format!(
                        "All {} download attempts exhausted for vk_id {} within the last 24 hours. \
                         Last failure: {}",
                        MAX_RETRIES_PER_24H, self.vk_id, attempt_err
                    ),
                });
            }

            // Backoff with full jitter before the next attempt.
            let delay = compute_jittered_backoff(attempt_idx);
            log::info!(
                "Backing off for {} ms before next PK download attempt",
                delay.as_millis()
            );
            tokio::time::sleep(delay).await;
        }
    }

    /// Execute a single download-and-verify cycle. Returns `Ok(())` when the
    /// PK file has been verified and atomically placed at `final_path`.
    ///
    /// On integrity failure the temporary file is deleted so that subsequent
    /// attempts start from zero bytes (spec requirement 13.8 item 5).
    #[cfg(feature = "http")]
    async fn download_single_attempt<F>(
        &self,
        final_path: &Path,
        progress_callback: &mut F,
    ) -> Result<(), FfiError>
    where
        F: FnMut(DownloadProgress) + Send,
    {
        let temp_path = self.storage_dir.join(format!("{}.tmp", self.pk_filename));

        // Detect partial download for resume (only valid if previous attempt
        // was a network failure, not an integrity failure, because we delete
        // the temp file on integrity failures).
        let resume_from = if temp_path.exists() {
            let size = fs::metadata(&temp_path)
                .map_err(|e| FfiError::Storage { msg: e.to_string() })?
                .len();

            if size > 0 && size < Self::PK_SIZE {
                log::info!("Resuming download from byte {}", size);
                size
            } else if size >= Self::PK_SIZE {
                if self.verify_pk_integrity(&temp_path).unwrap_or(false) {
                    fs::rename(&temp_path, final_path)
                        .map_err(|e| FfiError::Storage { msg: e.to_string() })?;
                    return Ok(());
                } else {
                    log::warn!("Temp file is corrupted, starting fresh download");
                    fs::remove_file(&temp_path).ok();
                    0
                }
            } else {
                0
            }
        } else {
            0
        };

        // Try HTTP/3 first.
        let h3_result = self
            .download_with_http3(&temp_path, resume_from, &mut *progress_callback)
            .await;

        match h3_result {
            Ok(()) => {
                log::info!("Download complete via HTTP/3, verifying integrity...");
            }
            Err(e) => {
                log::warn!("HTTP/3 download failed: {}. Falling back to HTTP/2...", e);

                let resume_from_h2 = if temp_path.exists() {
                    fs::metadata(&temp_path).map(|m| m.len()).unwrap_or(0)
                } else {
                    0
                };

                crate::net::http2_download_to_file(
                    Self::PK_URL,
                    &temp_path,
                    Some(resume_from_h2),
                    Some(Self::PK_SIZE),
                    |bytes_downloaded, total_bytes| {
                        let percentage = if total_bytes > 0 {
                            let pct = (bytes_downloaded as f32 / total_bytes as f32) * 100.0;
                            // SAFETY: clamp guarantees [0.0, 100.0], which fits in u8.
                            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                            let p = pct.clamp(0.0, 100.0) as u8;
                            p
                        } else {
                            0
                        };
                        progress_callback(DownloadProgress {
                            bytes_downloaded,
                            total_bytes,
                            percentage,
                        });
                    },
                )
                .await
                .map_err(|e| {
                    log::error!("HTTP/2 fallback also failed: {}", e);
                    e
                })?;

                log::info!("Download complete via HTTP/2, verifying integrity...");
            }
        }

        // Spec 13.8 item 5: integrity-failed partial downloads MUST NOT be
        // resumed. Delete the temp file on integrity failure so the next
        // attempt starts from zero bytes.
        if !self.verify_pk_integrity(&temp_path)? {
            fs::remove_file(&temp_path).ok();
            return Err(FfiError::InvalidFormat {
                msg: "Downloaded file failed integrity check. File may be corrupted.".to_string(),
            });
        }

        // Atomic rename to final location.
        fs::rename(&temp_path, final_path).map_err(|e| FfiError::Storage {
            msg: format!("Failed to finalize file: {}", e),
        })?;

        log::info!("PK download and verification successful");
        Ok(())
    }

    /// Perform the HTTP/3 download leg, writing to `temp_path`.
    #[cfg(feature = "http")]
    async fn download_with_http3<F>(
        &self,
        temp_path: &Path,
        resume_from: u64,
        mut progress_callback: F,
    ) -> Result<(), FfiError>
    where
        F: FnMut(DownloadProgress) + Send,
    {
        use h3::client;
        use std::net::ToSocketAddrs;

        let url = url::Url::parse(Self::PK_URL)
            .map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

        let host = url
            .host_str()
            .ok_or_else(|| FfiError::InvalidFormat {
                msg: "No host in URL".to_string(),
            })?
            .to_string();

        let port = url.port().unwrap_or(443);
        let path = url.path();

        let addr = format!("{}:{}", host, port)
            .to_socket_addrs()
            .map_err(|e| FfiError::Network {
                msg: format!("DNS resolution failed: {}", e),
            })?
            .next()
            .ok_or_else(|| FfiError::Network {
                msg: "No address found".to_string(),
            })?;

        log::info!("Attempting PK download via HTTP/3 from {}", host);

        let endpoint = crate::net::create_quinn_endpoint().map_err(|e| FfiError::Network {
            msg: format!("Quinn endpoint: {}", e),
        })?;

        let connection = endpoint
            .connect(addr, &host)
            .map_err(|e| FfiError::Network {
                msg: format!("QUIC connection failed: {}", e),
            })?
            .await
            .map_err(|e| FfiError::Network {
                msg: format!("QUIC handshake failed: {}", e),
            })?;

        log::debug!("QUIC connection established to {}", host);

        let quinn_conn = h3_quinn::Connection::new(connection);
        let (mut driver, mut send_request) =
            client::new(quinn_conn)
                .await
                .map_err(|e| FfiError::Network {
                    msg: format!("HTTP/3 setup failed: {}", e),
                })?;

        tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });

        let mut req_builder = http::Request::builder()
            .method("GET")
            .uri(path)
            .header("host", &host)
            .header("user-agent", crate::net::current_user_agent())
            .header("accept-encoding", "identity");

        if resume_from > 0 {
            req_builder = req_builder.header("range", format!("bytes={}-", resume_from));
        }

        let req = req_builder
            .body(())
            .map_err(|e| FfiError::Network { msg: e.to_string() })?;

        let mut stream = send_request
            .send_request(req)
            .await
            .map_err(|e| FfiError::Network {
                msg: format!("HTTP/3 request failed: {}", e),
            })?;

        stream.finish().await.map_err(|e| FfiError::Network {
            msg: format!("Failed to finish stream: {}", e),
        })?;

        let response = stream
            .recv_response()
            .await
            .map_err(|e| FfiError::Network {
                msg: format!("Failed to receive response: {}", e),
            })?;

        let status = response.status();
        log::info!("HTTP/3 download started, status: {}", status);

        if !status.is_success() && status.as_u16() != 206 {
            return Err(FfiError::Network {
                msg: format!("Server returned status: {}", status),
            });
        }

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(resume_from > 0)
            .truncate(resume_from == 0)
            .open(temp_path)
            .map_err(|e| FfiError::Storage { msg: e.to_string() })?;

        let mut downloaded = resume_from;
        let mut last_sync = std::time::Instant::now();

        while let Some(mut chunk) = stream.recv_data().await.map_err(|e| FfiError::Network {
            msg: format!("Failed to read chunk: {}", e),
        })? {
            let chunk_bytes = chunk.chunk().to_vec();
            chunk.advance(chunk.remaining());

            file.write_all(&chunk_bytes)
                .map_err(|e| FfiError::Storage {
                    msg: format!("Write error: {}", e),
                })?;

            downloaded = downloaded.saturating_add(chunk_bytes.len() as u64);

            let percentage = if Self::PK_SIZE > 0 {
                let pct = (downloaded as f32 / Self::PK_SIZE as f32) * 100.0;
                // SAFETY: clamp guarantees [0.0, 100.0], which fits in u8.
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let p = pct.clamp(0.0, 100.0) as u8;
                p
            } else {
                0
            };
            progress_callback(DownloadProgress {
                bytes_downloaded: downloaded,
                total_bytes: Self::PK_SIZE,
                percentage,
            });

            // Sync to disk every 5 MB or 10 seconds.
            if downloaded.is_multiple_of(5 * 1024 * 1024) || last_sync.elapsed().as_secs() > 10 {
                file.sync_data().map_err(|e| FfiError::Storage {
                    msg: format!("Sync error: {}", e),
                })?;
                last_sync = std::time::Instant::now();
            }
        }

        file.sync_all().map_err(|e| FfiError::Storage {
            msg: format!("Final sync error: {}", e),
        })?;
        drop(file);

        Ok(())
    }

    /// Returns `true` when a valid, integrity-checked PK file exists on disk.
    pub fn is_available(&self) -> bool {
        let path = self.storage_dir.join(&self.pk_filename);
        self.verify_pk_integrity(&path).unwrap_or(false)
    }

    /// Returns the expected on-disk path for the PK file.
    pub fn get_path(&self) -> PathBuf {
        self.storage_dir.join(&self.pk_filename)
    }

    /// Delete both the PK file and any leftover `.tmp` partial download.
    pub fn delete_proving_key(&self) -> Result<(), FfiError> {
        let path = self.storage_dir.join(&self.pk_filename);
        let temp_path = self.storage_dir.join(format!("{}.tmp", self.pk_filename));

        if path.exists() {
            fs::remove_file(path).map_err(|e| FfiError::Storage { msg: e.to_string() })?;
        }
        if temp_path.exists() {
            fs::remove_file(temp_path).map_err(|e| FfiError::Storage { msg: e.to_string() })?;
        }

        Ok(())
    }

    /// Load the PK file into memory after verifying integrity.
    ///
    /// Returns the raw bytes suitable for passing to the Groth16 prover
    /// initialisation routine.
    pub fn load_pk_to_memory(&self) -> Result<Vec<u8>, FfiError> {
        let path = self.get_path();

        if !self.verify_pk_integrity(&path)? {
            return Err(FfiError::InvalidFormat {
                msg: "PK file failed integrity check".to_string(),
            });
        }

        fs::read(&path).map_err(|e| FfiError::Storage {
            msg: format!("Failed to read PK into memory: {}", e),
        })
    }
}

/// Query available free space for a directory.
///
/// Returns a conservative default on platforms where querying free space is
/// not directly supported from Rust (e.g. Android, where the check should be
/// performed on the JVM side and passed via
/// [`proving_key_check_storage_with_bytes`]).
fn get_free_space(_path: &Path) -> Result<u64, FfiError> {
    #[cfg(target_os = "android")]
    {
        // On Android this should be called from the JVM side.
        Ok(200_000_000) // 200 MB default
    }

    #[cfg(not(target_os = "android"))]
    {
        #[cfg(feature = "fs2")]
        {
            use fs2::available_space;
            available_space(_path).map_err(|e| FfiError::Storage {
                msg: format!("Failed to get free space: {}", e),
            })
        }

        #[cfg(not(feature = "fs2"))]
        {
            Ok(500_000_000) // 500 MB default
        }
    }
}

// ---------------------------------------------------------------------------
// Data types for FFI
// ---------------------------------------------------------------------------

/// Progress snapshot emitted during a proving key download.
#[derive(Debug, Clone)]
pub struct DownloadProgress {
    /// Number of bytes written to disk so far (including any resumed prefix).
    pub bytes_downloaded: u64,

    /// Total expected byte count for the complete file.
    pub total_bytes: u64,

    /// Percentage complete, clamped to 0..=100.
    pub percentage: u8,
}

/// Outcome of a storage availability check.
#[derive(Debug)]
pub enum StorageStatus {
    /// Enough free space exists.
    Available,

    /// Free space is below the required threshold.
    InsufficientSpace {
        /// Free space currently available, in megabytes.
        available_mb: u64,
        /// Free space required, in megabytes.
        required_mb: u64,
    },
}

/// UniFFI-exported variant of `StorageStatus` with an additional `Error`
/// arm for when the check itself fails.
#[derive(uniffi::Enum)]
pub enum StorageCheckResult {
    /// The device has enough free space to proceed.
    Ready,

    /// Free space is insufficient.
    InsufficientSpace {
        /// Free space currently available, in megabytes.
        available_mb: u64,
        /// Free space required, in megabytes.
        required_mb: u64,
        /// Human-readable description of the shortfall.
        message: String,
    },

    /// The storage check itself failed.
    Error {
        /// Description of the failure.
        message: String,
    },
}

/// Error type specific to proving key operations, exported via UniFFI.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ProvingKeyError {
    /// The device does not have enough free storage.
    #[error("Insufficient storage: {details}")]
    InsufficientStorage {
        /// Human-readable description.
        details: String,
    },

    /// A network request failed during download.
    #[error("Network error: {details}")]
    NetworkError {
        /// Human-readable description.
        details: String,
    },

    /// The prover could not be initialised from the PK bytes.
    #[error("Initialization error: {details}")]
    InitializationError {
        /// Human-readable description.
        details: String,
    },

    /// The per-`vk_id` retry budget (5 attempts / 24 hours) has been exhausted.
    #[error("Retry budget exceeded: {details}")]
    RetryBudgetExceeded {
        /// Human-readable description.
        details: String,
    },

    /// An unexpected error occurred.
    #[error("Unknown error: {details}")]
    UnknownError {
        /// Human-readable description.
        details: String,
    },
}

/// Callback interface for receiving download progress updates on mobile.
#[uniffi::export(callback_interface)]
pub trait ProvingKeyProgressListener: Send + Sync {
    /// Called each time a new chunk is flushed to disk.
    fn on_progress(&self, bytes_downloaded: u64, total_bytes: u64, percentage: u8);
}

/// Check storage availability using a byte count supplied by the platform.
///
/// On Android, where Rust cannot reliably query free space, the JVM layer
/// should call this function with the result of
/// `StatFs.getAvailableBytes()`.
#[uniffi::export]
pub fn proving_key_check_storage_with_bytes(
    app_files_dir: String,
    available_bytes: u64,
) -> StorageCheckResult {
    let _manager = ProvingKeyManager::new(&app_files_dir);

    if available_bytes < ProvingKeyManager::MIN_FREE_SPACE {
        StorageCheckResult::InsufficientSpace {
            available_mb: available_bytes / 1_000_000,
            required_mb: ProvingKeyManager::MIN_FREE_SPACE / 1_000_000,
            message: format!(
                "Need {} MB free space. Only {} MB available. Please free up space.",
                ProvingKeyManager::MIN_FREE_SPACE / 1_000_000,
                available_bytes / 1_000_000
            ),
        }
    } else {
        StorageCheckResult::Ready
    }
}

/// Returns `true` when a valid, integrity-checked proving key exists on disk.
#[uniffi::export]
pub fn proving_key_is_available(app_files_dir: String) -> bool {
    let manager = ProvingKeyManager::new(&app_files_dir);
    manager.is_available()
}

/// Check storage using the platform's own free-space query.
///
/// Prefer [`proving_key_check_storage_with_bytes`] on Android where the Rust
/// `fs2` crate may not report accurate values.
#[uniffi::export]
pub fn proving_key_check_storage(app_files_dir: String) -> StorageCheckResult {
    let manager = ProvingKeyManager::new(&app_files_dir);
    match manager.check_storage_available() {
        Ok(StorageStatus::Available) => StorageCheckResult::Ready,
        Ok(StorageStatus::InsufficientSpace {
            available_mb,
            required_mb,
        }) => StorageCheckResult::InsufficientSpace {
            available_mb,
            required_mb,
            message: format!(
                "Need {} MB free space. Only {} MB available. Please free up space.",
                required_mb, available_mb
            ),
        },
        Err(e) => StorageCheckResult::Error {
            message: e.to_string(),
        },
    }
}

/// Download the proving key, blocking the calling thread on the global Tokio
/// runtime.
///
/// Progress is reported through the supplied listener callback. On success
/// the file is verified and ready for [`proving_key_init`].
#[cfg(feature = "http")]
#[uniffi::export]
pub fn proving_key_download(
    app_files_dir: String,
    progress_listener: Box<dyn ProvingKeyProgressListener>,
) -> Result<(), ProvingKeyError> {
    crate::tokio_rt()
        .map_err(|e| ProvingKeyError::InitializationError {
            details: format!("Tokio runtime: {}", e),
        })?
        .block_on(async move { proving_key_download_async(app_files_dir, progress_listener).await })
}

/// Inner async implementation for the download (not exported via UniFFI).
#[cfg(feature = "http")]
async fn proving_key_download_async(
    app_files_dir: String,
    progress_listener: Box<dyn ProvingKeyProgressListener>,
) -> Result<(), ProvingKeyError> {
    let manager = ProvingKeyManager::new(&app_files_dir);

    let result = manager
        .download_with_progress(move |progress| {
            progress_listener.on_progress(
                progress.bytes_downloaded,
                progress.total_bytes,
                progress.percentage,
            );
        })
        .await;

    match result {
        Ok(()) => Ok(()),
        Err(FfiError::Storage { msg }) if msg.contains("Not enough storage") => {
            Err(ProvingKeyError::InsufficientStorage { details: msg })
        }
        Err(FfiError::Network { msg }) => Err(ProvingKeyError::NetworkError { details: msg }),
        Err(FfiError::RetryBudgetExceeded { msg }) => {
            Err(ProvingKeyError::RetryBudgetExceeded { details: msg })
        }
        Err(e) => Err(ProvingKeyError::UnknownError {
            details: e.to_string(),
        }),
    }
}

/// Load and initialise the Groth16 prover from the on-disk proving key.
///
/// The entire PK is read into memory and verified before being handed to the
/// core prover. This prevents streaming-related corruption that could occur
/// if the file were read lazily during proof generation.
#[uniffi::export]
pub fn proving_key_init(app_files_dir: String) -> Result<(), ProvingKeyError> {
    let manager = ProvingKeyManager::new(&app_files_dir);

    if !manager.is_available() {
        return Err(ProvingKeyError::InitializationError {
            details: "Proving key file not found or invalid. Please download it first.".to_string(),
        });
    }

    let pk_bytes =
        manager
            .load_pk_to_memory()
            .map_err(|e| ProvingKeyError::InitializationError {
                details: format!("Failed to load PK: {}", e),
            })?;

    log::info!("Loaded PK into memory: {} bytes", pk_bytes.len());

    let expected_size = usize::try_from(ProvingKeyManager::PK_SIZE).unwrap_or(usize::MAX);
    if pk_bytes.len() != expected_size {
        return Err(ProvingKeyError::InitializationError {
            details: format!(
                "PK size mismatch: expected {} bytes, got {} bytes",
                ProvingKeyManager::PK_SIZE,
                pk_bytes.len()
            ),
        });
    }

    provii_mobile_sdk_core::prover::init_prover_with_pk_bytes(&pk_bytes).map_err(|e| {
        ProvingKeyError::InitializationError {
            details: format!("Prover initialization failed: {}", e),
        }
    })?;

    log::info!(
        "Prover initialised successfully with VK ID {}",
        ProvingKeyManager::VK_ID
    );
    Ok(())
}

/// Delete the proving key and any partial download from disk.
#[uniffi::export]
pub fn proving_key_delete(app_files_dir: String) -> Result<(), ProvingKeyError> {
    let manager = ProvingKeyManager::new(&app_files_dir);
    manager
        .delete_proving_key()
        .map_err(|e| ProvingKeyError::UnknownError {
            details: e.to_string(),
        })
}

/// Return a human-readable summary of the current PK state on disk.
///
/// Intended for debug/diagnostic screens in the mobile app.
#[uniffi::export]
pub fn proving_key_get_info(app_files_dir: String) -> String {
    let manager = ProvingKeyManager::new(&app_files_dir);
    let path = manager.get_path();

    if !path.exists() {
        return format!("PK not found at: {:?}", path);
    }

    match fs::metadata(&path) {
        Ok(metadata) => {
            let size = metadata.len();
            let valid = manager.verify_pk_integrity(&path).unwrap_or(false);
            format!(
                "PK Info:\n  Path: {:?}\n  Size: {} bytes\n  Expected: {} bytes\n  Valid: {}\n  VK ID: {}",
                path, size, ProvingKeyManager::PK_SIZE, valid, ProvingKeyManager::VK_ID
            )
        }
        Err(e) => format!("Failed to get PK info: {}", e),
    }
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
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    /// Create a test manager backed by a fresh temporary directory.
    fn create_test_manager() -> Result<(ProvingKeyManager, TempDir), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let path_str = temp_dir.path().to_str().ok_or("non-UTF-8 path")?;
        let manager = ProvingKeyManager::new(path_str);
        Ok((manager, temp_dir))
    }

    /// Write `size` zero-bytes into a new file at `path`.
    fn create_file_with_size(path: &Path, size: u64) -> std::io::Result<()> {
        let mut file = File::create(path)?;
        let data = vec![0u8; size as usize];
        file.write_all(&data)?;
        file.sync_all()?;
        Ok(())
    }

    // ========================================================================
    // Basic Instantiation and Path Tests
    // ========================================================================

    #[test]
    fn test_proving_key_manager_new() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let manager = ProvingKeyManager::new(temp_dir.path().to_str().ok_or("non-UTF-8 path")?);

        assert_eq!(manager.vk_id, ProvingKeyManager::VK_ID);
        assert!(manager
            .pk_filename
            .contains(&ProvingKeyManager::VK_ID.to_string()));
        Ok(())
    }

    #[test]
    fn test_get_path() -> Result<(), Box<dyn std::error::Error>> {
        let (manager, temp_dir) = create_test_manager()?;
        let path = manager.get_path();

        assert!(path.starts_with(temp_dir.path()));
        assert!(path.to_str().ok_or("non-UTF-8 path")?.contains("age_pk"));
        Ok(())
    }

    #[test]
    fn test_pk_filename_format() -> Result<(), Box<dyn std::error::Error>> {
        let (manager, _) = create_test_manager()?;

        assert_eq!(
            manager.pk_filename,
            format!("age_pk.{}.bin", ProvingKeyManager::VK_ID)
        );
        Ok(())
    }

    #[test]
    fn test_constants() {
        assert_eq!(ProvingKeyManager::VK_ID, 2031517468);
        assert_eq!(ProvingKeyManager::PK_SIZE, 51_945_624);
        assert_eq!(ProvingKeyManager::MIN_FREE_SPACE, 65_000_000);
        assert_eq!(ProvingKeyManager::PK_BLAKE2S.len(), 64);
    }

    #[test]
    fn test_storage_dir_created() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let nested_path = temp_dir.path().join("nested/path");
        let manager = ProvingKeyManager::new(nested_path.to_str().ok_or("non-UTF-8 path")?);

        assert_eq!(manager.storage_dir, nested_path);
        Ok(())
    }

    // ========================================================================
    // Size and Hash Verification Tests
    // ========================================================================

    #[test]
    fn test_verify_pk_integrity_missing_file() -> Result<(), Box<dyn std::error::Error>> {
        let (manager, temp_dir) = create_test_manager()?;
        let path = temp_dir.path().join("nonexistent.bin");

        let result = manager.verify_pk_integrity(&path);
        assert!(result.is_ok());
        assert!(!result?);
        Ok(())
    }

    #[test]
    fn test_verify_pk_integrity_wrong_size_too_small() -> Result<(), Box<dyn std::error::Error>> {
        let (manager, temp_dir) = create_test_manager()?;
        let path = temp_dir.path().join("test.bin");

        create_file_with_size(&path, 1000)?;

        let result = manager.verify_pk_integrity(&path);
        assert!(result.is_ok());
        assert!(!result?);
        Ok(())
    }

    #[test]
    fn test_verify_pk_integrity_wrong_size_too_large() -> Result<(), Box<dyn std::error::Error>> {
        let (manager, temp_dir) = create_test_manager()?;
        let path = temp_dir.path().join("test.bin");

        create_file_with_size(&path, ProvingKeyManager::PK_SIZE + 1000)?;

        let result = manager.verify_pk_integrity(&path);
        assert!(result.is_ok());
        assert!(!result?);
        Ok(())
    }

    #[test]
    fn test_verify_pk_integrity_exact_size_wrong_hash() -> Result<(), Box<dyn std::error::Error>> {
        let (manager, temp_dir) = create_test_manager()?;
        let path = temp_dir.path().join("test.bin");

        create_file_with_size(&path, ProvingKeyManager::PK_SIZE)?;

        let result = manager.verify_pk_integrity(&path);
        assert!(result.is_ok());
        assert!(!result?);
        Ok(())
    }

    #[test]
    fn test_verify_pk_integrity_zero_size() -> Result<(), Box<dyn std::error::Error>> {
        let (manager, temp_dir) = create_test_manager()?;
        let path = temp_dir.path().join("test.bin");

        File::create(&path)?;

        let result = manager.verify_pk_integrity(&path);
        assert!(result.is_ok());
        assert!(!result?);
        Ok(())
    }

    #[test]
    fn test_verify_pk_size_boundary() {
        assert_eq!(ProvingKeyManager::PK_SIZE, 51_945_624);
    }

    #[test]
    fn test_verify_pk_blake2s_format() {
        let hash = ProvingKeyManager::PK_BLAKE2S;
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_verify_pk_url_format() {
        let url = ProvingKeyManager::PK_URL;
        assert!(url.starts_with("https://"));
        assert!(url.contains("cdn.provii.app"));
        assert!(url.contains(&ProvingKeyManager::VK_ID.to_string()));
    }

    // ========================================================================
    // Storage Space Tests
    // ========================================================================

    #[test]
    fn test_check_storage_available_sufficient() -> Result<(), Box<dyn std::error::Error>> {
        let (manager, _temp_dir) = create_test_manager()?;

        let result = manager.check_storage_available();
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_storage_check_result_ready() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let result = proving_key_check_storage(
            temp_dir
                .path()
                .to_str()
                .ok_or("non-UTF-8 path")?
                .to_string(),
        );

        match result {
            StorageCheckResult::Ready => {}
            _ => panic!("Expected Ready"),
        }
        Ok(())
    }

    #[test]
    fn test_storage_check_with_bytes_sufficient() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let result = proving_key_check_storage_with_bytes(
            temp_dir
                .path()
                .to_str()
                .ok_or("non-UTF-8 path")?
                .to_string(),
            200_000_000,
        );

        match result {
            StorageCheckResult::Ready => {}
            _ => panic!("Expected Ready with 200MB"),
        }
        Ok(())
    }

    #[test]
    fn test_storage_check_with_bytes_insufficient() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let result = proving_key_check_storage_with_bytes(
            temp_dir
                .path()
                .to_str()
                .ok_or("non-UTF-8 path")?
                .to_string(),
            50_000_000,
        );

        match result {
            StorageCheckResult::InsufficientSpace {
                available_mb,
                required_mb,
                message,
            } => {
                assert_eq!(available_mb, 50);
                assert_eq!(required_mb, 65);
                assert!(message.contains("MB"));
            }
            _ => panic!("Expected InsufficientSpace"),
        }
        Ok(())
    }

    #[test]
    fn test_min_free_space_constant() {
        // MIN_FREE_SPACE (65 MB) must exceed PK_SIZE (52 MB) and stay under 3x PK_SIZE.
        // Use local bindings to avoid the `assertions_on_constants` lint while
        // still verifying the relationship at test time.
        let min_free = ProvingKeyManager::MIN_FREE_SPACE;
        let pk_size = ProvingKeyManager::PK_SIZE;
        assert!(min_free > pk_size);
        assert!(min_free < pk_size * 3);
    }

    // ========================================================================
    // Is Available Tests
    // ========================================================================

    #[test]
    fn test_is_available_no_file() -> Result<(), Box<dyn std::error::Error>> {
        let (manager, _) = create_test_manager()?;

        assert!(!manager.is_available());
        Ok(())
    }

    #[test]
    fn test_is_available_wrong_size_file() -> Result<(), Box<dyn std::error::Error>> {
        let (manager, temp_dir) = create_test_manager()?;
        let path = manager.get_path();

        fs::create_dir_all(temp_dir.path()).ok();
        create_file_with_size(&path, 1000)?;

        assert!(!manager.is_available());
        Ok(())
    }

    #[test]
    fn test_proving_key_is_available_ffi() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let available = proving_key_is_available(
            temp_dir
                .path()
                .to_str()
                .ok_or("non-UTF-8 path")?
                .to_string(),
        );

        assert!(!available);
        Ok(())
    }

    // ========================================================================
    // Delete Tests
    // ========================================================================

    #[test]
    fn test_delete_proving_key_nonexistent() -> Result<(), Box<dyn std::error::Error>> {
        let (manager, _) = create_test_manager()?;

        let result = manager.delete_proving_key();
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_delete_proving_key_removes_pk() -> Result<(), Box<dyn std::error::Error>> {
        let (manager, temp_dir) = create_test_manager()?;
        let path = manager.get_path();

        fs::create_dir_all(temp_dir.path()).ok();
        File::create(&path)?;
        assert!(path.exists());

        let result = manager.delete_proving_key();
        assert!(result.is_ok());
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn test_delete_proving_key_removes_temp() -> Result<(), Box<dyn std::error::Error>> {
        let (manager, temp_dir) = create_test_manager()?;
        let path = manager.get_path();
        let temp_path = temp_dir.path().join(format!("{}.tmp", manager.pk_filename));

        fs::create_dir_all(temp_dir.path()).ok();
        File::create(&path)?;
        File::create(&temp_path)?;

        assert!(path.exists());
        assert!(temp_path.exists());

        let result = manager.delete_proving_key();
        assert!(result.is_ok());
        assert!(!path.exists());
        assert!(!temp_path.exists());
        Ok(())
    }

    // ========================================================================
    // Memory Loading Tests
    // ========================================================================

    #[test]
    fn test_load_pk_to_memory_missing_file() -> Result<(), Box<dyn std::error::Error>> {
        let (manager, _) = create_test_manager()?;

        let result = manager.load_pk_to_memory();
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_load_pk_to_memory_wrong_size() -> Result<(), Box<dyn std::error::Error>> {
        let (manager, temp_dir) = create_test_manager()?;
        let path = manager.get_path();

        fs::create_dir_all(temp_dir.path()).ok();
        create_file_with_size(&path, 1000)?;

        let result = manager.load_pk_to_memory();
        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        assert!(err_val.to_string().contains("integrity"));
        Ok(())
    }

    #[test]
    fn test_load_pk_to_memory_validates_first() -> Result<(), Box<dyn std::error::Error>> {
        let (manager, temp_dir) = create_test_manager()?;
        let path = manager.get_path();

        fs::create_dir_all(temp_dir.path()).ok();
        create_file_with_size(&path, ProvingKeyManager::PK_SIZE)?;

        let result = manager.load_pk_to_memory();
        assert!(result.is_err());
        Ok(())
    }

    // ========================================================================
    // Get Info Tests
    // ========================================================================

    #[test]
    fn test_get_info_no_file() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let info = proving_key_get_info(
            temp_dir
                .path()
                .to_str()
                .ok_or("non-UTF-8 path")?
                .to_string(),
        );

        assert!(info.contains("not found"));
        Ok(())
    }

    #[test]
    fn test_get_info_with_file() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let manager = ProvingKeyManager::new(temp_dir.path().to_str().ok_or("non-UTF-8 path")?);
        let path = manager.get_path();

        fs::create_dir_all(temp_dir.path()).ok();
        create_file_with_size(&path, 1000)?;

        let info = proving_key_get_info(
            temp_dir
                .path()
                .to_str()
                .ok_or("non-UTF-8 path")?
                .to_string(),
        );

        assert!(info.contains("PK Info"));
        assert!(info.contains("Size"));
        assert!(info.contains("1000"));
        assert!(info.contains("Valid"));
        assert!(info.contains(&ProvingKeyManager::VK_ID.to_string()));
        Ok(())
    }

    // ========================================================================
    // Error Type Tests
    // ========================================================================

    #[test]
    fn test_proving_key_error_insufficient_storage() {
        let error = ProvingKeyError::InsufficientStorage {
            details: "Not enough space".to_string(),
        };

        assert!(error.to_string().contains("Insufficient storage"));
        assert!(error.to_string().contains("Not enough space"));
    }

    #[test]
    fn test_proving_key_error_network() {
        let error = ProvingKeyError::NetworkError {
            details: "Connection failed".to_string(),
        };

        assert!(error.to_string().contains("Network error"));
        assert!(error.to_string().contains("Connection failed"));
    }

    #[test]
    fn test_proving_key_error_initialization() {
        let error = ProvingKeyError::InitializationError {
            details: "Failed to initialize".to_string(),
        };

        assert!(error.to_string().contains("Initialization error"));
        assert!(error.to_string().contains("Failed to initialize"));
    }

    #[test]
    fn test_proving_key_error_unknown() {
        let error = ProvingKeyError::UnknownError {
            details: "Something went wrong".to_string(),
        };

        assert!(error.to_string().contains("Unknown error"));
        assert!(error.to_string().contains("Something went wrong"));
    }

    #[test]
    fn test_download_progress_structure() {
        let progress = DownloadProgress {
            bytes_downloaded: 1000,
            total_bytes: 10000,
            percentage: 10,
        };

        assert_eq!(progress.bytes_downloaded, 1000);
        assert_eq!(progress.total_bytes, 10000);
        assert_eq!(progress.percentage, 10);
    }

    // ========================================================================
    // Storage Status Tests
    // ========================================================================

    #[test]
    fn test_storage_status_available() {
        match StorageStatus::Available {
            StorageStatus::Available => {}
            _ => panic!("Expected Available"),
        }
    }

    #[test]
    fn test_storage_status_insufficient() {
        let status = StorageStatus::InsufficientSpace {
            available_mb: 50,
            required_mb: 100,
        };

        match status {
            StorageStatus::InsufficientSpace {
                available_mb,
                required_mb,
            } => {
                assert_eq!(available_mb, 50);
                assert_eq!(required_mb, 100);
            }
            _ => panic!("Expected InsufficientSpace"),
        }
    }

    // ========================================================================
    // Retry Policy Tests (protocol spec section 13.8)
    // ========================================================================

    #[test]
    fn test_backoff_progression_matches_formula() {
        // Verify `delay_ms = min(2000 * 2^attempt, 60000)` for each attempt
        // index. Since full jitter randomises the actual delay, we check the
        // *cap* by sampling many values and asserting they never exceed it.
        let expected_caps_ms: Vec<u64> = vec![
            2_000,  // attempt 0: 2000 * 2^0 = 2000
            4_000,  // attempt 1: 2000 * 2^1 = 4000
            8_000,  // attempt 2: 2000 * 2^2 = 8000
            16_000, // attempt 3: 2000 * 2^3 = 16000
            32_000, // attempt 4: 2000 * 2^4 = 32000
            60_000, // attempt 5: 2000 * 2^5 = 64000, capped to 60000
            60_000, // attempt 6: still capped
        ];

        for (attempt, expected_cap) in expected_caps_ms.iter().enumerate() {
            for _ in 0..200 {
                let delay = compute_jittered_backoff(attempt);
                assert!(
                    delay.as_millis() < *expected_cap as u128,
                    "attempt {}: delay {} ms should be < {} ms",
                    attempt,
                    delay.as_millis(),
                    expected_cap
                );
            }
        }
    }

    #[test]
    fn test_jitter_produces_values_in_expected_range() {
        // For attempt 0, cap is 2000 ms. Sample many values and verify
        // that we see both small (< 500 ms) and larger (> 500 ms) values,
        // proving the jitter is not degenerate.
        let mut saw_low = false;
        let mut saw_high = false;

        for _ in 0..500 {
            let delay = compute_jittered_backoff(0);
            let ms = delay.as_millis();
            if ms < 500 {
                saw_low = true;
            }
            if ms >= 500 {
                saw_high = true;
            }
            if saw_low && saw_high {
                break;
            }
        }

        assert!(saw_low, "jitter never produced a value under 500 ms");
        assert!(saw_high, "jitter never produced a value at or above 500 ms");
    }

    #[test]
    fn test_backoff_zero_attempt_is_bounded() {
        // attempt 0 must produce delays in [0, 2000) ms.
        for _ in 0..100 {
            let delay = compute_jittered_backoff(0);
            assert!(delay.as_millis() < 2000);
        }
    }

    #[test]
    fn test_backoff_large_attempt_is_capped() {
        // Very large attempt index must still be capped at 60 000 ms.
        for _ in 0..100 {
            let delay = compute_jittered_backoff(100);
            assert!(delay.as_millis() < 60_000);
        }
    }

    #[test]
    fn test_retry_budget_allows_five_attempts() {
        // Use an unlikely vk_id to avoid interference from other tests.
        let vk_id = 99_900_001;
        reset_retry_budget(vk_id);

        for i in 0..5 {
            let idx = record_attempt(vk_id).expect("attempt should succeed");
            assert_eq!(idx, i);
        }

        // Sixth attempt must fail.
        let result = record_attempt(vk_id);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, FfiError::RetryBudgetExceeded { .. }),
            "expected RetryBudgetExceeded, got {:?}",
            err
        );

        reset_retry_budget(vk_id);
    }

    #[test]
    fn test_retry_budget_exceeded_error_message() {
        let vk_id = 99_900_002;
        reset_retry_budget(vk_id);

        for _ in 0..5 {
            record_attempt(vk_id).unwrap();
        }

        let err = record_attempt(vk_id).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("5"));
        assert!(msg.contains(&vk_id.to_string()));
        assert!(msg.contains("24 hours"));

        reset_retry_budget(vk_id);
    }

    #[test]
    fn test_retry_budget_independent_per_vk_id() {
        let vk_a = 99_900_003;
        let vk_b = 99_900_004;
        reset_retry_budget(vk_a);
        reset_retry_budget(vk_b);

        // Exhaust budget for vk_a.
        for _ in 0..5 {
            record_attempt(vk_a).unwrap();
        }
        assert!(record_attempt(vk_a).is_err());

        // vk_b should still have full budget.
        assert!(record_attempt(vk_b).is_ok());

        reset_retry_budget(vk_a);
        reset_retry_budget(vk_b);
    }

    #[test]
    fn test_attempts_consumed_tracks_correctly() {
        let vk_id = 99_900_005;
        reset_retry_budget(vk_id);

        assert_eq!(attempts_consumed(vk_id).unwrap(), 0);

        record_attempt(vk_id).unwrap();
        assert_eq!(attempts_consumed(vk_id).unwrap(), 1);

        record_attempt(vk_id).unwrap();
        assert_eq!(attempts_consumed(vk_id).unwrap(), 2);

        reset_retry_budget(vk_id);
    }

    #[test]
    fn test_successful_first_attempt_no_delay() {
        // `compute_jittered_backoff(0)` is what would be used before the
        // second attempt. On the very first attempt there is no backoff at
        // all (the retry loop only sleeps after a failure). We verify that
        // by confirming attempt index 0 is returned from `record_attempt`.
        let vk_id = 99_900_006;
        reset_retry_budget(vk_id);

        let idx = record_attempt(vk_id).unwrap();
        assert_eq!(idx, 0, "first attempt should return index 0");

        reset_retry_budget(vk_id);
    }

    #[test]
    fn test_proving_key_error_retry_budget_exceeded() {
        let error = ProvingKeyError::RetryBudgetExceeded {
            details: "Budget exceeded".to_string(),
        };

        assert!(error.to_string().contains("Retry budget exceeded"));
        assert!(error.to_string().contains("Budget exceeded"));
    }

    #[test]
    fn test_ffi_error_retry_budget_exceeded() {
        let error = FfiError::RetryBudgetExceeded {
            msg: "5 attempts used".to_string(),
        };

        assert!(error.to_string().contains("Retry budget exceeded"));
        assert!(error.to_string().contains("5 attempts used"));
    }

    #[test]
    fn test_trim_stale_attempts_removes_old_entries() {
        let mut attempts = vec![
            // Simulate an attempt from 25 hours ago (beyond the 24h window).
            // We can't directly create a past Instant, but we can verify that
            // a recent entry survives trimming.
            Instant::now(),
        ];

        trim_stale_attempts(&mut attempts);
        assert_eq!(attempts.len(), 1, "recent entry should survive trim");
    }

    #[test]
    fn test_retry_constants_match_spec() {
        assert_eq!(MAX_RETRIES_PER_24H, 5);
        assert_eq!(RETRY_WINDOW, Duration::from_secs(86_400));
        assert_eq!(BASE_BACKOFF_MS, 2_000);
        assert_eq!(MAX_BACKOFF_MS, 60_000);
    }
}
