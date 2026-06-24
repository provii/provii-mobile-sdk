// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Security event logging and storage metrics for the iOS Keychain backend.

use super::*;

#[derive(Debug, Clone)]
pub(crate) struct SecurityEvent {
    event_type: SecurityEventType,
    timestamp: u64,
    details: String,
    risk_level: RiskLevel,
}

#[derive(Debug, Clone)]
pub(crate) enum SecurityEventType {
    KeychainAccess,
    BiometricAuth,
    FailedOperation,
    KeyRotation,
    ConfigChange,
}

#[derive(Debug, Clone)]
pub(crate) enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct StorageMetrics {
    pub(crate) operations_count: u64,
    pub(crate) cache_hits: u64,
    pub(crate) cache_misses: u64,
    pub(crate) biometric_prompts: u64,
    pub(crate) errors_count: u64,
    pub(crate) last_error: Option<String>,
}

impl IOSKeychainStorage {
    /* ---------------------------------------------------------------
    Security Event Logging
    ------------------------------------------------------------- */

    pub(crate) fn log_security_event(
        &self,
        event_type: SecurityEventType,
        details: &str,
        risk_level: RiskLevel,
    ) {
        if !self.config.enable_audit_logging {
            return;
        }

        let event = SecurityEvent {
            event_type,
            timestamp: current_timestamp(),
            details: details.to_string(),
            risk_level,
        };

        let mut audit_log = self.audit_log.lock().unwrap_or_else(|e| e.into_inner());
        audit_log.push_back(event);

        // Keep log size manageable
        if audit_log.len() > 1000 {
            audit_log.pop_front();
        }
    }

    /// Get storage metrics
    pub fn get_metrics(&self) -> StorageMetrics {
        let metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        metrics.clone()
    }

    /// Get security audit log
    pub fn get_audit_log(&self) -> Vec<SecurityEvent> {
        let audit_log = self.audit_log.lock().unwrap_or_else(|e| e.into_inner());
        audit_log.iter().cloned().collect()
    }
}
