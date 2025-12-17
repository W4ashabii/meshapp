//! Transport layer (Phase 5)
//!
//! Transport-agnostic packet routing with TTL and deduplication.
//! Implements:
//! - `Packet` struct
//! - `Transport` trait
//! - `LoopbackTransport` for local testing
//! - `Router` with TTL + dedup logic
//!
//! BLE and other real transports will plug into this trait in later phases.

#![allow(dead_code)] // Many items will be fully used in later phases

use rand::RngCore;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// Mesh packet as seen by transports and router.
#[derive(Clone, Debug)]
pub struct Packet {
    pub packet_id: [u8; 32],
    pub channel_id: [u8; 32],
    pub ttl: u8,
    pub payload: Vec<u8>, // encrypted bytes
}

/// Abstract transport (BLE, Wi‑Fi Direct, Loopback, etc.).
pub trait Transport: Send + Sync {
    fn send(&self, packet: &Packet) -> Result<(), String>;
    fn is_available(&self) -> bool;
    fn name(&self) -> &'static str {
        "transport"
    }
}

/// Simple in-process transport used for tests and local development.
#[derive(Clone)]
pub struct LoopbackTransport {
    inner: Arc<Mutex<Vec<Packet>>>,
}

impl LoopbackTransport {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Drain all packets that have been \"sent\" through this transport.
    pub fn drain(&self) -> Vec<Packet> {
        let mut guard = self.inner.lock().unwrap();
        let out = guard.clone();
        guard.clear();
        out
    }
}

impl Transport for LoopbackTransport {
    fn send(&self, packet: &Packet) -> Result<(), String> {
        let mut guard = self.inner.lock().unwrap();
        guard.push(packet.clone());
        Ok(())
    }

    fn is_available(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "loopback"
    }
}

/// Router implementing TTL and deduplication across transports.
pub struct Router {
    transports: Vec<Arc<dyn Transport>>,
    seen: Mutex<HashSet<[u8; 32]>>,
}

impl Router {
    pub fn new(transports: Vec<Arc<dyn Transport>>) -> Self {
        Self {
            transports,
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// Generate a random packet_id.
    pub fn generate_packet_id() -> [u8; 32] {
        let mut id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut id);
        id
    }

    /// Route a packet:
    /// - Drops if already seen (dedup).
    /// - Calls `on_new` callback exactly once for new packets (for storage, UI, etc.).
    /// - Forwards to all available transports while `ttl > 0`, decrementing TTL.
    pub fn route<F>(&self, mut packet: Packet, on_new: F)
    where
        F: Fn(&Packet),
    {
        {
            let mut seen = self.seen.lock().unwrap();
            if !seen.insert(packet.packet_id) {
                // Already seen, drop silently.
                return;
            }
        }

        // New packet: inform caller (e.g., store in DB).
        on_new(&packet);

        if packet.ttl == 0 {
            return;
        }

        packet.ttl -= 1;
        for transport in &self.transports {
            if transport.is_available() {
                let _ = transport.send(&packet);
            }
        }
    }
}



