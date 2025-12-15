//! Geohash-based group channels (Phase 7)
//!
//! geo_channel_id = SHA256(geohash + topic)

use sha2::{Digest, Sha256};

/// Derive a geohash channel id from geohash + topic.
pub fn derive_geo_channel_id(geohash: &str, topic: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(geohash.as_bytes());
    hasher.update(topic.as_bytes());
    hasher.finalize().into()
}

/// Hex utilities reused from identity/dm modules.
pub fn channel_id_to_hex(id: &[u8; 32]) -> String {
    hex::encode(id)
}


