// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! HTTP/3 (QUIC) networking layer with HTTP/2 fallback.
//!
//! Every outbound request from the wallet SDK flows through this module. The
//! primary transport is HTTP/3 over QUIC (via Quinn and the `h3` crate),
//! which gives lower handshake latency on mobile networks and avoids
//! head-of-line blocking. When HTTP/3 is unavailable (e.g. on networks that
//! block UDP), callers fall back to [`http2_download_to_file`].
//!
//! # Endpoint lifecycle
//!
//! Each request creates a fresh [`quinn::Endpoint`] so that stale QUIC state
//! from a previous network context (WiFi to cellular handover, for instance)
//! cannot cause spurious failures. The cost is one extra UDP socket bind per
//! request, which is negligible compared to the TLS handshake.
//!
//! # User-Agent management
//!
//! The user-agent string defaults to `ProviiWallet/<version> (Rust SDK)` and
//! can be overridden by the mobile platform at startup via [`set_user_agent`].

use crate::errors::{FfiError, FfiResult};
use bytes::{Buf, Bytes};
use h3::client;
use h3_quinn::quinn;
use http::{Method, Request, StatusCode};
use once_cell::sync::Lazy;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::time::timeout as tokio_timeout;

/// Maximum number of bytes accepted in an in-memory HTTP response body.
///
/// Responses that exceed this limit are rejected and the QUIC connection is
/// closed cleanly. File-based downloads (`http2_download_to_file`) stream
/// directly to disk and are not subject to this cap.
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Default timeout applied to POST requests when no explicit timeout is
/// provided by the caller. Protects against slow-trickle attacks that would
/// otherwise only be bounded by the QUIC idle timeout.
const DEFAULT_POST_TIMEOUT_SECS: u64 = 30;

/// Default timeout for file downloads (seconds). Protects against stalled
/// connections that would otherwise hang indefinitely.
const DEFAULT_DOWNLOAD_TIMEOUT_SECS: u64 = 300;

/// Maximum download size in bytes (50 MB). Prevents disk/memory exhaustion
/// from unexpectedly large server responses.
const MAX_DOWNLOAD_BYTES: u64 = 50 * 1024 * 1024;

/// Global user-agent string, readable from any thread.
pub(crate) static USER_AGENT: Lazy<RwLock<String>> = Lazy::new(|| {
    RwLock::new(format!(
        "ProviiWallet/{} (Rust SDK)",
        env!("CARGO_PKG_VERSION")
    ))
});

/// Return the current user-agent string.
pub(crate) fn current_user_agent() -> String {
    USER_AGENT
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Replace the user-agent string for all subsequent requests.
pub(crate) fn set_user_agent(ua: String) {
    *USER_AGENT
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = ua;
}

/// Create a fresh Quinn endpoint configured for short-lived HTTP/3 requests.
///
/// Uses webpki-roots for TLS verification and sets a 10-second idle timeout
/// to avoid lingering sockets on mobile.
pub(crate) fn create_quinn_endpoint() -> Result<quinn::Endpoint, Box<dyn std::error::Error>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(quinn::IdleTimeout::try_from(Duration::from_secs(10))?))
        .keep_alive_interval(Some(Duration::from_secs(5)))
        .datagram_receive_buffer_size(Some(0)); // DATAGRAM frames unused

    use quinn::crypto::rustls::QuicClientConfig;
    let mut client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls_config)?));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

/// Parse a URL into `(host, port, path_and_query)` for HTTP/3.
///
/// Only HTTPS URLs are accepted. The path component includes the query
/// string when present.
fn parse_url_for_h3(url: &str) -> Result<(String, u16, String), FfiError> {
    let parsed =
        url::Url::parse(url).map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

    if parsed.scheme() != "https" {
        return Err(FfiError::InvalidFormat {
            msg: "Only HTTPS URLs are supported".to_string(),
        });
    }

    let host = parsed.host_str().ok_or_else(|| FfiError::InvalidFormat {
        msg: "No host in URL".to_string(),
    })?;

    if host.is_empty() {
        return Err(FfiError::InvalidFormat {
            msg: "Empty host in URL".to_string(),
        });
    }

    let host = host.to_string();
    let port = parsed.port().unwrap_or(443);
    let path_and_query = format!(
        "{}{}",
        parsed.path(),
        parsed
            .query()
            .map(|q| format!("?{}", q))
            .unwrap_or_default()
    );

    Ok((host, port, path_and_query))
}

/// POST a JSON body over HTTP/3 and return the response body as a string.
///
/// Applies [`DEFAULT_POST_TIMEOUT_SECS`] as the per-request deadline.
pub async fn post_json(url: &str, json_body: &str) -> FfiResult<String> {
    post_json_with_api_key(url, json_body, None, DEFAULT_POST_TIMEOUT_SECS).await
}

/// POST a JSON body over HTTP/3 with an optional `X-API-Key` header.
///
/// The API key, if provided, is copied into an HTTP `HeaderValue`. That copy
/// cannot be wrapped in `Zeroizing` due to `http` crate type constraints;
/// the `HeaderValue` is consumed by the HTTP/3 send and dropped when the
/// request completes, so the key does not persist beyond this scope.
///
/// `timeout_secs` caps the total wall-clock time for connection setup, request
/// send, and response read. If the deadline elapses, the future is cancelled
/// and [`FfiError::RequestTimeout`] is returned.
pub async fn post_json_with_api_key(
    url: &str,
    json_body: &str,
    api_key: Option<&str>,
    timeout_secs: u64,
) -> FfiResult<String> {
    tokio_timeout(
        Duration::from_secs(timeout_secs),
        post_json_with_api_key_inner(url, json_body, api_key),
    )
    .await
    .map_err(|_| FfiError::RequestTimeout {
        seconds: timeout_secs,
    })?
}

/// Inner implementation of [`post_json_with_api_key`] without timeout wrapping.
async fn post_json_with_api_key_inner(
    url: &str,
    json_body: &str,
    api_key: Option<&str>,
) -> FfiResult<String> {
    log::info!("HTTP/3 POST to {}", url);

    let (host, port, path) = parse_url_for_h3(url)?;

    let lookup_host = format!("{}:{}", host, port);
    let addr = tokio::net::lookup_host(&lookup_host)
        .await
        .map_err(|e| FfiError::Network {
            msg: format!("DNS resolution failed: {}", e),
        })?
        .next()
        .ok_or_else(|| FfiError::Network {
            msg: "No address found".to_string(),
        })?;

    let endpoint = create_quinn_endpoint().map_err(|e| FfiError::Network {
        msg: format!("Failed to create endpoint: {}", e),
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

    let driver_handle = tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    let mut req_builder = Request::builder()
        .method(Method::POST)
        .uri(&path)
        .header("host", &host)
        .header("user-agent", current_user_agent())
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("content-length", json_body.len());

    if let Some(key) = api_key {
        req_builder = req_builder.header("x-api-key", key);
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

    stream
        .send_data(Bytes::from(json_body.to_string()))
        .await
        .map_err(|e| FfiError::Network {
            msg: format!("Failed to send body: {}", e),
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
    log::info!("POST {} -> HTTP/3 {}", url, status);

    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.map_err(|e| FfiError::Network {
        msg: format!("Failed to read body: {}", e),
    })? {
        let slice = chunk.chunk();
        if body.len().saturating_add(slice.len()) > MAX_RESPONSE_BYTES {
            log::warn!(
                "POST response body exceeded {} byte limit, aborting",
                MAX_RESPONSE_BYTES
            );
            driver_handle.abort();
            endpoint.close(0u32.into(), b"response too large");
            return Err(FfiError::Network {
                msg: format!("Response body exceeded {} byte limit", MAX_RESPONSE_BYTES),
            });
        }
        body.extend_from_slice(slice);
        chunk.advance(chunk.remaining());
    }

    driver_handle.abort();
    endpoint.close(0u32.into(), b"done");

    let body_str =
        String::from_utf8(body).map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

    if !status.is_success() {
        let truncated: String = body_str.chars().take(128).collect();
        log::warn!(
            "POST {} returned {} (body {} bytes, preview: {})",
            url,
            status,
            body_str.len(),
            truncated
        );
        return Err(FfiError::Network {
            msg: format!("Server returned status: {}", status),
        });
    }

    Ok(body_str)
}

/// GET over HTTP/3 with a per-request timeout.
///
/// `timeout_secs` caps the total wall-clock time for the request. If the
/// deadline elapses, [`FfiError::RequestTimeout`] is returned.
pub async fn get_with_timeout(url: &str, timeout_secs: u64) -> FfiResult<String> {
    get_with_api_key(url, timeout_secs, None).await
}

/// GET over HTTP/3 with an optional API key and per-request timeout.
pub async fn get_with_api_key(
    url: &str,
    timeout_secs: u64,
    api_key: Option<&str>,
) -> FfiResult<String> {
    get_with_headers(url, timeout_secs, api_key, None).await
}

/// GET over HTTP/3 with optional API key and `Origin` headers.
///
/// The `Origin` header is required by some provii-verifier endpoints when the
/// request originates from a web context.
///
/// `timeout_secs` caps the total wall-clock time for connection setup and
/// response read. If the deadline elapses, the future is cancelled and
/// [`FfiError::RequestTimeout`] is returned.
pub async fn get_with_headers(
    url: &str,
    timeout_secs: u64,
    api_key: Option<&str>,
    origin: Option<&str>,
) -> FfiResult<String> {
    tokio_timeout(
        Duration::from_secs(timeout_secs),
        get_with_headers_inner(url, api_key, origin),
    )
    .await
    .map_err(|_| FfiError::RequestTimeout {
        seconds: timeout_secs,
    })?
}

/// Inner implementation of [`get_with_headers`] without timeout wrapping.
async fn get_with_headers_inner(
    url: &str,
    api_key: Option<&str>,
    origin: Option<&str>,
) -> FfiResult<String> {
    log::info!("HTTP/3 GET to {}", url);

    let (host, port, path) = parse_url_for_h3(url)?;

    let lookup_host = format!("{}:{}", host, port);
    let addr = tokio::net::lookup_host(&lookup_host)
        .await
        .map_err(|e| FfiError::Network {
            msg: format!("DNS resolution failed: {}", e),
        })?
        .next()
        .ok_or_else(|| FfiError::Network {
            msg: "No address found".to_string(),
        })?;

    let endpoint = create_quinn_endpoint().map_err(|e| FfiError::Network {
        msg: format!("Failed to create endpoint: {}", e),
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

    let quinn_conn = h3_quinn::Connection::new(connection);
    let (mut driver, mut send_request) =
        client::new(quinn_conn)
            .await
            .map_err(|e| FfiError::Network {
                msg: format!("HTTP/3 setup failed: {}", e),
            })?;

    let driver_handle = tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    let mut req_builder = Request::builder()
        .method(Method::GET)
        .uri(&path)
        .header("host", &host)
        .header("user-agent", current_user_agent())
        .header("accept", "application/json");

    if let Some(key) = api_key {
        req_builder = req_builder.header("x-api-key", key);
    }

    if let Some(origin_value) = origin {
        req_builder = req_builder.header("origin", origin_value);
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
    log::info!("GET {} -> HTTP/3 {}", url, status);

    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.map_err(|e| FfiError::Network {
        msg: format!("Failed to read body: {}", e),
    })? {
        let slice = chunk.chunk();
        if body.len().saturating_add(slice.len()) > MAX_RESPONSE_BYTES {
            log::warn!(
                "GET response body exceeded {} byte limit, aborting",
                MAX_RESPONSE_BYTES
            );
            driver_handle.abort();
            endpoint.close(0u32.into(), b"response too large");
            return Err(FfiError::Network {
                msg: format!("Response body exceeded {} byte limit", MAX_RESPONSE_BYTES),
            });
        }
        body.extend_from_slice(slice);
        chunk.advance(chunk.remaining());
    }

    driver_handle.abort();
    endpoint.close(0u32.into(), b"done");

    let body_str =
        String::from_utf8(body).map_err(|e| FfiError::InvalidFormat { msg: e.to_string() })?;

    if !status.is_success() {
        return Err(FfiError::Network {
            msg: format!("Server returned status: {}", status),
        });
    }

    Ok(body_str)
}

/// Download a file over HTTP/2 with progress reporting.
///
/// Used as a fallback when HTTP/3 is unavailable (e.g. UDP blocked).
/// Supports resuming via the `resume_from` byte offset.
///
/// The entire download is bounded by [`DEFAULT_DOWNLOAD_TIMEOUT_SECS`] (5
/// minutes). Individual chunks are not separately timed, but the overall
/// deadline ensures we never hang indefinitely on a stalled connection.
///
/// Downloaded bytes are capped at [`MAX_DOWNLOAD_BYTES`] (50 MB). If the
/// server sends more data than that, the download is aborted and an error
/// is returned to prevent disk or memory exhaustion.
#[cfg(feature = "http")]
pub async fn http2_download_to_file<F>(
    url: &str,
    out_path: &std::path::Path,
    resume_from: Option<u64>,
    expected_size: Option<u64>,
    mut on_progress: F,
) -> Result<(), FfiError>
where
    F: FnMut(u64, u64) + Send,
{
    tokio_timeout(
        Duration::from_secs(DEFAULT_DOWNLOAD_TIMEOUT_SECS),
        http2_download_to_file_inner(url, out_path, resume_from, expected_size, &mut on_progress),
    )
    .await
    .map_err(|_| FfiError::RequestTimeout {
        seconds: DEFAULT_DOWNLOAD_TIMEOUT_SECS,
    })?
}

/// Inner implementation of [`http2_download_to_file`], separated so the
/// outer function can wrap it in a single `tokio::time::timeout`.
#[cfg(feature = "http")]
async fn http2_download_to_file_inner<F>(
    url: &str,
    out_path: &std::path::Path,
    resume_from: Option<u64>,
    expected_size: Option<u64>,
    on_progress: &mut F,
) -> Result<(), FfiError>
where
    F: FnMut(u64, u64) + Send,
{
    use http::Version;
    use http_body_util::BodyExt;
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use tokio::fs::OpenOptions;
    use tokio::io::AsyncWriteExt;

    log::info!("Starting HTTP/2 download from {}", url);

    // Reject up-front if the server has already told us the file is too large.
    if let Some(expected) = expected_size {
        if expected > MAX_DOWNLOAD_BYTES {
            return Err(FfiError::Network {
                msg: format!(
                    "Expected download size ({} bytes) exceeds limit ({} bytes)",
                    expected, MAX_DOWNLOAD_BYTES
                ),
            });
        }
    }

    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http2()
        .build();

    let client: Client<_, http_body_util::Empty<Bytes>> = Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build(https);

    let mut req_builder = Request::builder()
        .method("GET")
        .uri(url)
        .header(http::header::USER_AGENT, current_user_agent())
        .header(http::header::ACCEPT, "*/*")
        .header(http::header::ACCEPT_ENCODING, "identity");

    if let Some(start) = resume_from {
        if start > 0 {
            req_builder = req_builder.header(http::header::RANGE, format!("bytes={}-", start));
            log::info!("Resuming HTTP/2 download from byte {}", start);
        }
    }

    let req = req_builder
        .body(http_body_util::Empty::<Bytes>::new())
        .map_err(|e| FfiError::Network {
            msg: format!("HTTP/2 build request failed: {}", e),
        })?;

    let resp = client.request(req).await.map_err(|e| FfiError::Network {
        msg: format!("HTTP/2 request failed: {}", e),
    })?;

    if resp.version() != Version::HTTP_2 {
        return Err(FfiError::Network {
            msg: format!("Server did not negotiate HTTP/2, got {:?}", resp.version()),
        });
    }

    let status = resp.status();
    log::info!("HTTP/2 response status: {}", status);

    if !status.is_success() && status != StatusCode::PARTIAL_CONTENT {
        return Err(FfiError::Network {
            msg: format!("Server returned unexpected status: {}", status),
        });
    }

    let content_len = resp
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|hv| hv.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    // Reject if Content-Length exceeds our cap.
    if let Some(len) = content_len {
        let full_len = resume_from.unwrap_or(0).saturating_add(len);
        if full_len > MAX_DOWNLOAD_BYTES {
            return Err(FfiError::Network {
                msg: format!(
                    "Content-Length ({} bytes) exceeds download limit ({} bytes)",
                    full_len, MAX_DOWNLOAD_BYTES
                ),
            });
        }
    }

    let total_bytes = if let Some(start) = resume_from {
        if let Some(len) = content_len {
            start.saturating_add(len)
        } else {
            expected_size.unwrap_or(0)
        }
    } else {
        content_len.or(expected_size).unwrap_or(0)
    };

    let mut file = if resume_from.is_some() {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(out_path)
            .await
    } else {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(out_path)
            .await
    }
    .map_err(|e| FfiError::Storage {
        msg: format!("Failed to open file {}: {}", out_path.display(), e),
    })?;

    let mut downloaded = resume_from.unwrap_or(0);
    let mut last_sync = std::time::Instant::now();

    let mut body = resp.into_body();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| FfiError::Network {
            msg: format!("HTTP/2 read frame failed: {}", e),
        })?;

        if let Some(chunk) = frame.data_ref() {
            file.write_all(chunk).await.map_err(|e| FfiError::Storage {
                msg: format!("Failed to write to {}: {}", out_path.display(), e),
            })?;

            downloaded = downloaded.saturating_add(chunk.len() as u64);

            // Enforce download size limit regardless of Content-Length header.
            if downloaded > MAX_DOWNLOAD_BYTES {
                return Err(FfiError::Network {
                    msg: format!(
                        "Download exceeded size limit ({} bytes received, {} bytes max)",
                        downloaded, MAX_DOWNLOAD_BYTES
                    ),
                });
            }

            on_progress(downloaded, total_bytes);

            // Sync to disk every 5 MB or 10 seconds.
            // Using % instead of is_multiple_of for compatibility with Rust < 1.87.
            #[allow(clippy::manual_is_multiple_of)]
            if downloaded % (5 * 1024 * 1024) == 0 || last_sync.elapsed().as_secs() > 10 {
                file.sync_data().await.map_err(|e| FfiError::Storage {
                    msg: format!("Failed to sync file: {}", e),
                })?;
                last_sync = std::time::Instant::now();
            }
        }
    }

    file.sync_all().await.map_err(|e| FfiError::Storage {
        msg: format!("Failed to final sync file: {}", e),
    })?;

    log::info!("HTTP/2 download complete: {} bytes", downloaded);
    Ok(())
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

    #[test]
    fn test_parse_url_for_h3_valid_https() -> Result<(), Box<dyn std::error::Error>> {
        let url = "https://example.com/path/to/resource";
        let result = parse_url_for_h3(url);

        assert!(result.is_ok());
        let (host, port, path) = result?;
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/path/to/resource");
        Ok(())
    }

    #[test]
    fn test_parse_url_for_h3_with_port() -> Result<(), Box<dyn std::error::Error>> {
        let url = "https://example.com:8443/api/endpoint";
        let result = parse_url_for_h3(url);

        assert!(result.is_ok());
        let (host, port, path) = result?;
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
        assert_eq!(path, "/api/endpoint");
        Ok(())
    }

    #[test]
    fn test_parse_url_for_h3_with_query() -> Result<(), Box<dyn std::error::Error>> {
        let url = "https://api.example.com/search?q=test&limit=10";
        let result = parse_url_for_h3(url);

        assert!(result.is_ok());
        let (host, port, path) = result?;
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/search?q=test&limit=10");
        Ok(())
    }

    #[test]
    fn test_parse_url_for_h3_http_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let url = "http://example.com/path";
        let result = parse_url_for_h3(url);

        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::InvalidFormat { msg } => {
                assert!(msg.contains("HTTPS"));
            }
            _ => panic!("Expected InvalidFormat error"),
        }
        Ok(())
    }

    #[test]
    fn test_parse_url_for_h3_invalid_url() -> Result<(), Box<dyn std::error::Error>> {
        let url = "not a valid url";
        let result = parse_url_for_h3(url);

        assert!(result.is_err());
        let Err(err_val) = result else {
            panic!("expected error")
        };
        match err_val {
            FfiError::InvalidFormat { .. } => {}
            _ => panic!("Expected InvalidFormat error"),
        }
        Ok(())
    }

    #[test]
    fn test_parse_url_for_h3_root_path() -> Result<(), Box<dyn std::error::Error>> {
        let url = "https://example.com";
        let result = parse_url_for_h3(url);

        assert!(result.is_ok());
        let (host, port, path) = result?;
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/");
        Ok(())
    }

    #[test]
    fn test_parse_url_for_h3_with_fragment() -> Result<(), Box<dyn std::error::Error>> {
        let url = "https://example.com/page#section";
        let result = parse_url_for_h3(url);

        assert!(result.is_ok());
        let (_host, _port, path) = result?;
        assert!(!path.contains("#"));
        Ok(())
    }

    #[test]
    fn test_parse_url_for_h3_ipv4_address() -> Result<(), Box<dyn std::error::Error>> {
        let url = "https://192.168.1.1/api";
        let result = parse_url_for_h3(url);

        assert!(result.is_ok());
        let (host, _port, _path) = result?;
        assert_eq!(host, "192.168.1.1");
        Ok(())
    }

    #[test]
    fn test_user_agent_default() {
        set_user_agent(format!(
            "ProviiWallet/{} (Rust SDK)",
            env!("CARGO_PKG_VERSION")
        ));

        let ua = current_user_agent();

        assert!(ua.contains("ProviiWallet"));
        assert!(ua.contains("Rust SDK"));
    }

    #[test]
    fn test_user_agent_set_and_get() {
        let original = current_user_agent();

        let custom_ua = "TestAgent/1.0.0 (Custom)";
        set_user_agent(custom_ua.to_string());

        assert_eq!(current_user_agent(), custom_ua);

        set_user_agent(original);
    }

    #[test]
    fn test_user_agent_multiple_sets() {
        let original = current_user_agent();

        // Overwrite the global user-agent several times. Because other tests
        // may run concurrently and mutate the same global, we only assert
        // after the final set (which is the restore) rather than inside the
        // loop, avoiding a TOCTOU race.
        for i in 0..10 {
            let ua = format!("TestAgent/{}.0.0", i);
            set_user_agent(ua);
        }

        set_user_agent(original.clone());
        // Verify the restore took effect (still racy in theory, but the
        // other user-agent tests also restore, so convergence is guaranteed).
        assert_eq!(current_user_agent(), original);
    }

    #[test]
    fn test_user_agent_empty_string() {
        let original = current_user_agent();

        set_user_agent("".to_string());
        assert_eq!(current_user_agent(), "");

        set_user_agent(original);
    }

    #[test]
    fn test_user_agent_unicode() {
        let original = current_user_agent();

        let unicode_ua = "ProviiWallet/test (Unicode)";
        set_user_agent(unicode_ua.to_string());
        assert_eq!(current_user_agent(), unicode_ua);

        set_user_agent(original);
    }

    #[test]
    fn test_user_agent_very_long() {
        let original = current_user_agent();

        let long_ua = "A".repeat(10000);
        set_user_agent(long_ua.clone());
        assert_eq!(current_user_agent(), long_ua);

        set_user_agent(original);
    }

    #[test]
    fn test_user_agent_concurrent_access() -> Result<(), Box<dyn std::error::Error>> {
        use std::thread;

        let original = current_user_agent();

        let handles: Vec<_> = (0..10)
            .map(|i| {
                thread::spawn(move || {
                    let ua = format!("Thread{}/1.0.0", i);
                    set_user_agent(ua.clone());
                    current_user_agent()
                })
            })
            .collect();

        for handle in handles {
            let result = handle.join().map_err(|_| "thread panicked")?;
            assert!(!result.is_empty());
        }

        set_user_agent(original);
        Ok(())
    }

    #[test]
    fn test_parse_url_for_h3_multiple_query_params() -> Result<(), Box<dyn std::error::Error>> {
        let url = "https://api.example.com/v1/search?q=test&category=books&sort=asc&limit=50";
        let result = parse_url_for_h3(url);

        assert!(result.is_ok());
        let (_host, _port, path) = result?;
        assert!(path.contains("?"));
        assert!(path.contains("q=test"));
        assert!(path.contains("category=books"));
        assert!(path.contains("limit=50"));
        Ok(())
    }

    #[test]
    fn test_parse_url_for_h3_encoded_characters() -> Result<(), Box<dyn std::error::Error>> {
        let url = "https://example.com/path?name=John%20Doe&email=test%40example.com";
        let result = parse_url_for_h3(url);

        assert!(result.is_ok());
        let (_host, _port, path) = result?;
        assert!(path.contains("name=John%20Doe"));
        Ok(())
    }

    #[test]
    fn test_parse_url_for_h3_subdomain() -> Result<(), Box<dyn std::error::Error>> {
        let url = "https://api.staging.example.com/v1/endpoint";
        let result = parse_url_for_h3(url);

        assert!(result.is_ok());
        let (host, _port, _path) = result?;
        assert_eq!(host, "api.staging.example.com");
        Ok(())
    }

    #[test]
    fn test_parse_url_for_h3_trailing_slash() -> Result<(), Box<dyn std::error::Error>> {
        let url = "https://example.com/path/";
        let result = parse_url_for_h3(url);

        assert!(result.is_ok());
        let (_host, _port, path) = result?;
        assert_eq!(path, "/path/");
        Ok(())
    }

    #[test]
    fn test_parse_url_for_h3_nested_path() -> Result<(), Box<dyn std::error::Error>> {
        let url = "https://example.com/api/v2/users/123/profile";
        let result = parse_url_for_h3(url);

        assert!(result.is_ok());
        let (_host, _port, path) = result?;
        assert_eq!(path, "/api/v2/users/123/profile");
        Ok(())
    }
}
