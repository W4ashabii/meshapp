//! Storage module (Phase 4)
//!
//! SQLite-backed offline-first storage for messages and channels.
//! Tables:
//! - messages(message_id BLOB PRIMARY KEY, channel_id BLOB, ciphertext BLOB, timestamp INTEGER, ttl INTEGER)
//! - channels(channel_id BLOB PRIMARY KEY, type TEXT)

use rusqlite::{params, Connection};
use std::path::PathBuf;

pub struct Storage {
    conn: Connection,
}

#[derive(Debug)]
pub struct MessageRow {
    pub message_id: [u8; 32],
    pub channel_id: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub timestamp: i64,
    pub ttl: u8,
}

#[derive(Debug)]
pub struct ChannelRow {
    pub channel_id: [u8; 32],
    pub channel_type: String,
}

impl Storage {
    /// Initialize storage and create tables if they don't exist.
    pub fn init(db_path: &PathBuf) -> Result<Self, String> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create storage directory: {}", e))?;
        }

        let conn = Connection::open(db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        // Enable WAL for better concurrency on mobile/desktop
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| format!("Failed to set WAL mode: {}", e))?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS messages (
                message_id BLOB PRIMARY KEY,
                channel_id BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                timestamp INTEGER NOT NULL,
                ttl INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS channels (
                channel_id BLOB PRIMARY KEY,
                type TEXT NOT NULL
            );
            ",
        )
        .map_err(|e| format!("Failed to create tables: {}", e))?;

        Ok(Self { conn })
    }

    /// Store a message (idempotent on message_id).
    pub fn store_message(
        &self,
        message_id: [u8; 32],
        channel_id: [u8; 32],
        ciphertext: Vec<u8>,
        timestamp: i64,
        ttl: u8,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO messages (message_id, channel_id, ciphertext, timestamp, ttl)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![&message_id, &channel_id, &ciphertext, timestamp, ttl as i64],
            )
            .map_err(|e| format!("Failed to insert message: {}", e))?;
        Ok(())
    }

    /// Fetch messages for a channel ordered by timestamp ascending.
    pub fn fetch_messages(
        &self,
        channel_id: [u8; 32],
        limit: u32,
        offset: u32,
    ) -> Result<Vec<MessageRow>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT message_id, channel_id, ciphertext, timestamp, ttl
                 FROM messages
                 WHERE channel_id = ?1
                 ORDER BY timestamp ASC
                 LIMIT ?2 OFFSET ?3",
            )
            .map_err(|e| format!("Failed to prepare fetch: {}", e))?;

        let rows = stmt
            .query_map(params![&channel_id, limit as i64, offset as i64], |row| {
                Ok(MessageRow {
                    message_id: {
                        let blob: Vec<u8> = row.get(0)?;
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&blob);
                        arr
                    },
                    channel_id: {
                        let blob: Vec<u8> = row.get(1)?;
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&blob);
                        arr
                    },
                    ciphertext: row.get(2)?,
                    timestamp: row.get(3)?,
                    ttl: {
                        let v: i64 = row.get(4)?;
                        v as u8
                    },
                })
            })
            .map_err(|e| format!("Failed to query messages: {}", e))?;

        let mut results = Vec::new();
        for r in rows {
            results.push(r.map_err(|e| format!("Row error: {}", e))?);
        }
        Ok(results)
    }

    /// Upsert a channel (idempotent on channel_id).
    pub fn upsert_channel(&self, channel_id: [u8; 32], channel_type: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO channels (channel_id, type)
                 VALUES (?1, ?2)",
                params![&channel_id, &channel_type],
            )
            .map_err(|e| format!("Failed to upsert channel: {}", e))?;
        Ok(())
    }

    /// List channels by type.
    pub fn list_channels_by_type(&self, channel_type: &str) -> Result<Vec<ChannelRow>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT channel_id, type
                 FROM channels
                 WHERE type = ?1",
            )
            .map_err(|e| format!("Failed to prepare channel query: {}", e))?;

        let rows = stmt
            .query_map(params![channel_type], |row| {
                Ok(ChannelRow {
                    channel_id: {
                        let blob: Vec<u8> = row.get(0)?;
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&blob);
                        arr
                    },
                    channel_type: row.get(1)?,
                })
            })
            .map_err(|e| format!("Failed to query channels: {}", e))?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| format!("Channel row error: {}", e))?);
        }
        Ok(out)
    }
}

/// Get the storage path for the SQLite database.
pub fn db_path() -> Result<PathBuf, String> {
    let data_dir = dirs::data_local_dir().ok_or("Failed to get data directory")?;
    Ok(data_dir.join("meshapp").join("mesh.db"))
}

