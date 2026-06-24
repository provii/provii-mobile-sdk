// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Operation statistics, device security profile, security-event types, and
//! the metric/audit impl methods for the Android Keystore backend.

use super::*;

#[derive(Debug, Clone)]
pub(crate) struct OperationStatistics {
    total_operations: u64,
    successful_operations: u64,
    failed_operations: u64,
    biometric_authentications: u64,
    hardware_operations: u64,
    last_operation_time: u64,
}

impl OperationStatistics {
    pub(crate) const fn new() -> Self {
        Self {
            total_operations: 0,
            successful_operations: 0,
            failed_operations: 0,
            biometric_authentications: 0,
            hardware_operations: 0,
            last_operation_time: 0,
        }
    }

    fn record_operation(&mut self, success: bool, used_biometrics: bool, used_hardware: bool) {
        self.total_operations += 1;
        if success {
            self.successful_operations += 1;
        } else {
            self.failed_operations += 1;
        }
        if used_biometrics {
            self.biometric_authentications += 1;
        }
        if used_hardware {
            self.hardware_operations += 1;
        }
        self.last_operation_time = current_timestamp();
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DeviceSecurityProfile {
    pub(crate) has_strongbox: bool,
    pub(crate) has_hardware_keystore: bool,
    pub(crate) has_biometric_hardware: bool,
    pub(crate) security_patch_level: String,
    pub(crate) api_level: i32,
    pub(crate) last_assessed: u64,
}

impl Default for DeviceSecurityProfile {
    fn default() -> Self {
        Self {
            has_strongbox: false,
            has_hardware_keystore: false,
            has_biometric_hardware: false,
            security_patch_level: "unknown".to_string(),
            api_level: 0,
            last_assessed: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SecurityEvent {
    event_type: SecurityEventType,
    timestamp: u64,
    details: String,
    risk_level: RiskLevel,
}

#[derive(Debug, Clone)]
pub(crate) enum SecurityEventType {
    KeystoreAccess,
    BiometricAuth,
    HardwareFeatureCheck,
    FailedOperation,
    ConfigurationChange,
}

#[derive(Debug, Clone)]
pub(crate) enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct StorageMetrics {
    operations_count: u64,
    cache_hits: u64,
    cache_misses: u64,
    biometric_prompts: u64,
    strongbox_operations: u64,
    errors_count: u64,
    average_operation_time_ms: u64,
    last_error: Option<String>,
}

impl AndroidSecureStorage {
    /* ---------------------------------------------------------------
    Metrics and Monitoring
    ------------------------------------------------------------- */

    pub(crate) fn update_metrics(
        &self,
        success: bool,
        used_biometrics: bool,
        used_strongbox: bool,
        operation_time_ms: u64,
    ) {
        let mut metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        metrics.operations_count += 1;

        if !success {
            metrics.errors_count += 1;
        }

        if used_biometrics {
            metrics.biometric_prompts += 1;
        }

        if used_strongbox {
            metrics.strongbox_operations += 1;
        }

        // Update rolling average of operation time
        metrics.average_operation_time_ms =
            (metrics.average_operation_time_ms + operation_time_ms) / 2;

        // Update global stats
        let mut stats = OPERATION_STATS.lock().unwrap_or_else(|e| e.into_inner());
        stats.record_operation(success, used_biometrics, used_strongbox);
    }

    pub(crate) fn update_cache_metrics(&self, cache_hit: bool) {
        let mut metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        if cache_hit {
            metrics.cache_hits += 1;
        } else {
            metrics.cache_misses += 1;
        }
    }

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
        audit_log.push_back(event.clone());

        // SEC-09: Evict oldest entry with O(1) pop_front instead of O(n) remove(0)
        if audit_log.len() > 1000 {
            audit_log.pop_front();
        }
    }

    /* ---------------------------------------------------------------
    Public Diagnostic Methods
    ------------------------------------------------------------- */

    /// Get storage metrics for monitoring and debugging
    pub fn get_metrics(&self) -> StorageMetrics {
        self.metrics
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Get security audit log
    pub fn get_audit_log(&self) -> Vec<SecurityEvent> {
        self.audit_log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    /// Get device security profile
    pub fn get_device_profile(&self) -> Option<DeviceSecurityProfile> {
        self.device_profile
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}
