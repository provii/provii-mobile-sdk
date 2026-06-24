// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Operation cache and input validation for the Android Keystore backend.

use super::*;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// SECURITY: CachedOperation may contain sensitive credential data.
/// Implements ZeroizeOnDrop to clear memory when the operation is dropped.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct CachedOperation {
    #[zeroize(skip)] // Key name is not sensitive
    key: String,
    data: Vec<u8>,
    #[zeroize(skip)] // Timestamps are not sensitive
    cached_at: u64,
    #[zeroize(skip)] // TTL is not sensitive
    ttl: u64,
}

impl AndroidSecureStorage {
    pub(crate) fn validate_key(&self, key: &str) -> Result<()> {
        if key.is_empty() {
            return Err(WalletError::Storage {
                msg: "Key cannot be empty".to_string(),
            });
        }
        if key.len() > 255 {
            return Err(WalletError::Storage {
                msg: "Key too long (max 255 characters)".to_string(),
            });
        }
        // Use is_ascii_alphanumeric to match the trait's byte-level ASCII check.
        // is_alphanumeric would accept Unicode letters (e.g. CJK, emoji), which
        // the PlatformSecureStorage::validate_key contract explicitly rejects.
        if !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
        {
            return Err(WalletError::Storage {
                msg: "Key contains invalid characters".to_string(),
            });
        }
        Ok(())
    }

    pub(crate) fn validate_data(&self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Err(WalletError::Storage {
                msg: "Data cannot be empty".to_string(),
            });
        }
        if data.len() > MAX_ITEM_SIZE {
            return Err(WalletError::Storage {
                msg: format!("Data too large (max {} bytes)", MAX_ITEM_SIZE),
            });
        }
        Ok(())
    }

    /* ---------------------------------------------------------------
    Caching Operations
    ------------------------------------------------------------- */

    pub(crate) fn get_from_cache(&self, key: &str) -> Option<Zeroizing<Vec<u8>>> {
        let cache = self
            .operation_cache
            .read()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(cached) = cache.get(key) {
            let now = current_timestamp();
            // VULN-03: cached_at is milliseconds (from current_timestamp), ttl is seconds.
            // Convert ttl to milliseconds before comparison.
            if now.saturating_sub(cached.cached_at) < cached.ttl.saturating_mul(1000) {
                return Some(Zeroizing::new(cached.data.clone()));
            }
        }
        None
    }

    pub(crate) fn add_to_cache(&self, key: &str, data: &[u8]) {
        if !self.config.enable_caching {
            return;
        }

        let mut cache = self
            .operation_cache
            .write()
            .unwrap_or_else(|e| e.into_inner());

        // Implement LRU eviction if cache is getting too large
        if cache.len() >= 100 {
            let oldest_key = cache
                .iter()
                .min_by_key(|(_, op)| op.cached_at)
                .map(|(k, _)| k.clone());

            if let Some(old_key) = oldest_key {
                cache.remove(&old_key);
            }
        }

        cache.insert(
            key.to_string(),
            CachedOperation {
                key: key.to_string(),
                data: data.to_vec(),
                cached_at: current_timestamp(),
                ttl: self.config.cache_ttl,
            },
        );
    }

    pub(crate) fn remove_from_cache(&self, key: &str) {
        let mut cache = self
            .operation_cache
            .write()
            .unwrap_or_else(|e| e.into_inner());
        cache.remove(key);
    }

    /// Clear operation cache
    pub fn clear_cache(&self) {
        let mut cache = self
            .operation_cache
            .write()
            .unwrap_or_else(|e| e.into_inner());
        cache.clear();
    }
}
