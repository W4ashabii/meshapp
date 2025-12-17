//! Optimization module (Phase 9)
//!
//! Provides optimizations for:
//! - Packet batching (reduce transport overhead)
//! - Scanning intervals (BLE power management)
//! - Battery usage hints

use crate::transport::Packet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Batched packet sender for efficient transport usage
/// 
/// Collects packets and sends them in batches to reduce overhead
/// 
/// Will be used when BLE transport is implemented
#[allow(dead_code)] // Will be used in Phase 10+ (BLE transport)
pub struct PacketBatcher {
    batch: Arc<Mutex<Vec<Packet>>>,
    max_batch_size: usize,
    max_batch_age: Duration,
    last_flush: Arc<Mutex<Instant>>,
}

#[allow(dead_code)] // Will be used in Phase 10+ (BLE transport)
impl PacketBatcher {
    /// Create a new batcher with specified limits
    pub fn new(max_batch_size: usize, max_batch_age_secs: u64) -> Self {
        Self {
            batch: Arc::new(Mutex::new(Vec::new())),
            max_batch_size,
            max_batch_age: Duration::from_secs(max_batch_age_secs),
            last_flush: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Add a packet to the batch
    /// Returns true if batch should be flushed immediately
    pub fn add(&self, packet: Packet) -> bool {
        let mut batch = self.batch.lock().unwrap();
        batch.push(packet);
        
        // Flush if batch is full
        if batch.len() >= self.max_batch_size {
            true
        } else {
            false
        }
    }

    /// Check if batch should be flushed due to age
    pub fn should_flush(&self) -> bool {
        let last_flush = self.last_flush.lock().unwrap();
        last_flush.elapsed() >= self.max_batch_age
    }

    /// Take all packets from the batch (clears batch)
    pub fn take_batch(&self) -> Vec<Packet> {
        let mut batch = self.batch.lock().unwrap();
        let packets = batch.clone();
        batch.clear();
        *self.last_flush.lock().unwrap() = Instant::now();
        packets
    }

    /// Get current batch size
    pub fn len(&self) -> usize {
        self.batch.lock().unwrap().len()
    }
}

/// Scanning interval configuration for BLE
#[derive(Clone, Copy, Debug)]
pub enum ScanInterval {
    /// Aggressive scanning (high power, fast discovery)
    Aggressive, // ~100ms
    /// Normal scanning (balanced)
    Normal,     // ~1s
    /// Power-saving scanning (low power, slower discovery)
    PowerSaving, // ~5s
    /// Custom interval in milliseconds
    #[allow(dead_code)] // Will be used when custom intervals are needed
    Custom(u64),
}

impl ScanInterval {
    /// Get the interval duration in milliseconds
    pub fn as_millis(&self) -> u64 {
        match self {
            ScanInterval::Aggressive => 100,
            ScanInterval::Normal => 1000,
            ScanInterval::PowerSaving => 5000,
            ScanInterval::Custom(ms) => *ms,
        }
    }

    /// Get the scan window duration (typically 50% of interval for power saving)
    pub fn scan_window_ms(&self) -> u64 {
        self.as_millis() / 2
    }
}

/// Battery optimization mode
#[derive(Clone, Copy, Debug)]
pub enum BatteryMode {
    /// Performance mode (higher power usage, faster mesh)
    Performance,
    /// Balanced mode (default)
    Balanced,
    /// Power saving mode (lower power, slower mesh)
    PowerSaving,
}

impl BatteryMode {
    /// Get recommended scan interval for this battery mode
    pub fn recommended_scan_interval(&self) -> ScanInterval {
        match self {
            BatteryMode::Performance => ScanInterval::Aggressive,
            BatteryMode::Balanced => ScanInterval::Normal,
            BatteryMode::PowerSaving => ScanInterval::PowerSaving,
        }
    }

    /// Get recommended batch size for this battery mode
    pub fn recommended_batch_size(&self) -> usize {
        match self {
            BatteryMode::Performance => 5,  // Smaller batches, faster delivery
            BatteryMode::Balanced => 10,     // Default
            BatteryMode::PowerSaving => 20, // Larger batches, less frequent sends
        }
    }

    /// Get recommended batch age in seconds
    pub fn recommended_batch_age_secs(&self) -> u64 {
        match self {
            BatteryMode::Performance => 1,  // Flush quickly
            BatteryMode::Balanced => 2,     // Default
            BatteryMode::PowerSaving => 5,  // Wait longer to batch more
        }
    }
}

/// Optimization configuration
pub struct OptimizationConfig {
    #[allow(dead_code)] // Will be used when full config is needed
    pub battery_mode: BatteryMode,
    pub scan_interval: ScanInterval,
    pub batch_size: usize,
    pub batch_age_secs: u64,
}

impl OptimizationConfig {
    /// Create config from battery mode (uses recommended values)
    pub fn from_battery_mode(mode: BatteryMode) -> Self {
        Self {
            battery_mode: mode,
            scan_interval: mode.recommended_scan_interval(),
            batch_size: mode.recommended_batch_size(),
            batch_age_secs: mode.recommended_batch_age_secs(),
        }
    }

    /// Create default balanced config
    #[allow(dead_code)] // Will be used when default config is needed
    pub fn default() -> Self {
        Self::from_battery_mode(BatteryMode::Balanced)
    }
}

