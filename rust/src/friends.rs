//! Friend Management
//!
//! Friends represent verified public keys that can be used for direct messaging.
//! - user_id: SHA256 of Ed25519 public key
//! - ed25519_public: Public key for verification
//! - nickname: Local-only display name

use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::io::Write;

/// Friend data structure
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Friend {
    pub user_id: [u8; 32],
    pub ed25519_public: [u8; 32],
    pub nickname: String,
}

/// Friend storage (in-memory representation)
#[derive(Serialize, Deserialize, Default)]
struct FriendsStorage {
    friends: HashMap<String, Friend>, // Keyed by user_id (hex string)
}

impl FriendsStorage {
    /// Load friends from storage
    fn load(path: &PathBuf) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let data = fs::read(path)
            .map_err(|e| format!("Failed to read friends file: {}", e))?;

        serde_json::from_slice(&data)
            .map_err(|e| format!("Failed to parse friends file: {}", e))
    }

    /// Save friends to storage
    fn save(&self, path: &PathBuf) -> Result<(), String> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create storage directory: {}", e))?;
        }

        let data = serde_json::to_vec_pretty(&self)
            .map_err(|e| format!("Failed to serialize friends: {}", e))?;

        // Write to temporary file first, then rename (atomic operation)
        let temp_path = path.with_extension("tmp");
        let mut file = fs::File::create(&temp_path)
            .map_err(|e| format!("Failed to create friends file: {}", e))?;
        
        file.write_all(&data)
            .map_err(|e| format!("Failed to write friends file: {}", e))?;
        
        file.sync_all()
            .map_err(|e| format!("Failed to sync friends file: {}", e))?;
        drop(file);

        // Rename temp file to final location (atomic)
        fs::rename(&temp_path, path)
            .map_err(|e| format!("Failed to rename friends file: {}", e))?;

        // Set restrictive permissions (Unix-like systems)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)
                .map_err(|e| format!("Failed to get file metadata: {}", e))?
                .permissions();
            perms.set_mode(0o600); // rw------- only
            fs::set_permissions(path, perms)
                .map_err(|e| format!("Failed to set file permissions: {}", e))?;
        }

        Ok(())
    }

    /// Add a friend
    fn add_friend(&mut self, friend: Friend) -> Result<(), String> {
        let user_id_hex = hex::encode(friend.user_id);
        
        // Verify user_id matches public key
        let mut hasher = Sha256::new();
        hasher.update(&friend.ed25519_public);
        let computed_user_id: [u8; 32] = hasher.finalize().into();
        
        if computed_user_id != friend.user_id {
            return Err("user_id does not match Ed25519 public key".to_string());
        }

        self.friends.insert(user_id_hex, friend);
        Ok(())
    }

    /// Remove a friend by user_id
    fn remove_friend(&mut self, user_id: &[u8; 32]) -> bool {
        let user_id_hex = hex::encode(user_id);
        self.friends.remove(&user_id_hex).is_some()
    }

    /// Get a friend by user_id
    #[allow(dead_code)] // Will be used in future phases
    fn get_friend(&self, user_id: &[u8; 32]) -> Option<&Friend> {
        let user_id_hex = hex::encode(user_id);
        self.friends.get(&user_id_hex)
    }

    /// Get all friends
    fn get_all_friends(&self) -> Vec<&Friend> {
        self.friends.values().collect()
    }

    /// Update friend nickname
    #[allow(dead_code)] // Will be used in future phases
    fn update_nickname(&mut self, user_id: &[u8; 32], nickname: String) -> Result<(), String> {
        let user_id_hex = hex::encode(user_id);
        if let Some(friend) = self.friends.get_mut(&user_id_hex) {
            friend.nickname = nickname;
            Ok(())
        } else {
            Err("Friend not found".to_string())
        }
    }
}

/// Get the storage path for friends file
fn get_storage_path() -> Result<PathBuf, String> {
    let data_dir = dirs::data_local_dir()
        .ok_or("Failed to get data directory")?;
    
    Ok(data_dir.join("meshapp").join("friends.json"))
}

/// Friend manager (handles loading/saving)
pub struct FriendManager {
    storage: FriendsStorage,
    storage_path: PathBuf,
}

impl FriendManager {
    /// Create a new friend manager
    pub fn new() -> Result<Self, String> {
        let storage_path = get_storage_path()?;
        let storage = FriendsStorage::load(&storage_path)?;
        
        Ok(Self {
            storage,
            storage_path,
        })
    }

    /// Add a friend from public key and nickname
    pub fn add_friend(&mut self, ed25519_public: [u8; 32], nickname: String) -> Result<[u8; 32], String> {
        // Compute user_id
        let mut hasher = Sha256::new();
        hasher.update(&ed25519_public);
        let user_id: [u8; 32] = hasher.finalize().into();

        let friend = Friend {
            user_id,
            ed25519_public,
            nickname,
        };

        self.storage.add_friend(friend)?;
        self.storage.save(&self.storage_path)?;
        
        Ok(user_id)
    }

    /// Remove a friend
    pub fn remove_friend(&mut self, user_id: &[u8; 32]) -> Result<bool, String> {
        let removed = self.storage.remove_friend(user_id);
        if removed {
            self.storage.save(&self.storage_path)?;
        }
        Ok(removed)
    }

    /// Get a friend by user_id
    #[allow(dead_code)] // Will be used in future phases
    pub fn get_friend(&self, user_id: &[u8; 32]) -> Option<&Friend> {
        self.storage.get_friend(user_id)
    }

    /// Get all friends
    pub fn get_all_friends(&self) -> Vec<&Friend> {
        self.storage.get_all_friends()
    }

    /// Update friend nickname
    #[allow(dead_code)] // Will be used in future phases
    pub fn update_nickname(&mut self, user_id: &[u8; 32], nickname: String) -> Result<(), String> {
        self.storage.update_nickname(user_id, nickname)?;
        self.storage.save(&self.storage_path)?;
        Ok(())
    }
}

/// Friend data for export (public information only)
#[derive(Serialize, Deserialize)]
pub struct FriendExport {
    pub user_id: String, // hex
    pub ed25519_public: String, // hex
}

impl From<&Friend> for FriendExport {
    fn from(friend: &Friend) -> Self {
        Self {
            user_id: hex::encode(friend.user_id),
            ed25519_public: hex::encode(friend.ed25519_public),
        }
    }
}

/// Parse friend from JSON string (for QR import)
pub fn parse_friend_from_json(json: &str) -> Result<(String, [u8; 32]), String> {
    let export: FriendExport = serde_json::from_str(json)
        .map_err(|e| format!("Invalid friend data: {}", e))?;

    let ed25519_public = hex::decode(&export.ed25519_public)
        .map_err(|e| format!("Invalid hex encoding: {}", e))?;

    if ed25519_public.len() != 32 {
        return Err("Ed25519 public key must be 32 bytes".to_string());
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&ed25519_public);

    Ok((export.user_id, key_bytes))
}

