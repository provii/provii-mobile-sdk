// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! In-memory item cache and input validation for the iOS Keychain storage
//! backend.

use super::*;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug)]
pub(crate) struct ItemCache {
    pub(crate) items: HashMap<String, CachedItem>,
    pub(crate) max_size: usize,
}

/// SECURITY: ItemCache holds sensitive credential data in its HashMap values.
/// When the cache is dropped, each CachedItem's ZeroizeOnDrop clears its own
/// data field, but the HashMap itself may leave key strings and internal
/// metadata in memory. This Drop impl explicitly clears the map first so that
/// all entries are dropped (and zeroised) deterministically.
impl Drop for ItemCache {
    fn drop(&mut self) {
        self.items.clear();
    }
}

/// SECURITY: CachedItem may contain sensitive credential data.
/// Implements ZeroizeOnDrop to clear memory when the item is dropped.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct CachedItem {
    data: Vec<u8>,
    #[zeroize(skip)] // Timestamps are not sensitive
    cached_at: u64,
    #[zeroize(skip)] // TTL is not sensitive
    ttl_seconds: u64,
}

impl IOSKeychainStorage {
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
    Cache Management
    ------------------------------------------------------------- */

    pub(crate) fn get_from_cache(&self, key: &str) -> Option<Zeroizing<Vec<u8>>> {
        if !self.config.enable_caching {
            return None;
        }

        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(item) = cache.items.get(key) {
            let now = current_timestamp();
            if now.saturating_sub(item.cached_at) < item.ttl_seconds.saturating_mul(1000) {
                return Some(Zeroizing::new(item.data.clone()));
            }
        }
        None
    }

    pub(crate) fn add_to_cache(&self, key: &str, data: &[u8]) {
        if !self.config.enable_caching {
            return;
        }

        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());

        // Evict oldest items if cache is full
        if cache.items.len() >= cache.max_size && cache.max_size > 0 {
            if let Some(oldest_key) = cache
                .items
                .keys()
                .min_by_key(|k| cache.items[*k].cached_at)
                .cloned()
            {
                cache.items.remove(&oldest_key);
            }
        }

        if cache.max_size > 0 {
            cache.items.insert(
                key.to_string(),
                CachedItem {
                    data: data.to_vec(),
                    cached_at: current_timestamp(),
                    ttl_seconds: self.config.cache_ttl_seconds,
                },
            );
        }
    }

    pub(crate) fn remove_from_cache(&self, key: &str) {
        if self.config.enable_caching {
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.items.remove(key);
        }
    }

    /// Clear cache
    pub fn clear_cache(&self) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.items.clear();
    }
}
