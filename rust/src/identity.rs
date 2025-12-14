//! Identity Management
//!
//! Each device generates a permanent identity on first launch:
//! - Ed25519 keypair for identity signing
//! - X25519 keypair for key exchange
//! - user_id = SHA256(identity_public_key)

use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{StaticSecret, PublicKey};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::PathBuf;
use std::io::Write;

/// Identity keys stored securely on device
#[derive(Serialize, Deserialize, Clone)]
struct IdentityKeys {
    ed25519_secret: [u8; 32],
    x25519_secret: [u8; 32],
}

/// Public identity information
#[derive(Clone)]
pub struct PublicIdentity {
    pub ed25519_public: VerifyingKey,
    pub x25519_public: PublicKey,
    pub user_id: [u8; 32],
}

/// Full identity with private keys
pub struct Identity {
    ed25519_signing: SigningKey,
    x25519_secret: StaticSecret,
    public: PublicIdentity,
}

impl Identity {
    /// Generate a new identity
    pub fn generate() -> Self {
        // Generate Ed25519 keypair for signing
        let ed25519_signing = SigningKey::generate(&mut rand::thread_rng());
        let ed25519_public = ed25519_signing.verifying_key();

        // Generate X25519 keypair for key exchange
        let x25519_secret = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let x25519_public = PublicKey::from(&x25519_secret);

        // Compute user_id = SHA256(ed25519_public_key)
        let mut hasher = Sha256::new();
        hasher.update(ed25519_public.as_bytes());
        let user_id = hasher.finalize().into();

        let public = PublicIdentity {
            ed25519_public,
            x25519_public,
            user_id,
        };

        Self {
            ed25519_signing,
            x25519_secret,
            public,
        }
    }

    /// Load identity from storage, or generate if it doesn't exist
    pub fn load_or_generate() -> Result<Self, String> {
        let storage_path = get_storage_path()?;

        if storage_path.exists() {
            Self::load_from_storage(&storage_path)
        } else {
            let identity = Self::generate();
            identity.save_to_storage(&storage_path)?;
            Ok(identity)
        }
    }

    /// Load identity from storage file
    fn load_from_storage(path: &PathBuf) -> Result<Self, String> {
        let data = fs::read(path)
            .map_err(|e| format!("Failed to read identity file: {}", e))?;

        let keys: IdentityKeys = serde_json::from_slice(&data)
            .map_err(|e| format!("Failed to parse identity file: {}", e))?;

        // Reconstruct Ed25519 signing key
        let ed25519_signing = SigningKey::from_bytes(&keys.ed25519_secret);
        let ed25519_public = ed25519_signing.verifying_key();

        // Reconstruct X25519 secret
        let x25519_secret = StaticSecret::from(keys.x25519_secret);
        let x25519_public = PublicKey::from(&x25519_secret);

        // Compute user_id
        let mut hasher = Sha256::new();
        hasher.update(ed25519_public.as_bytes());
        let user_id = hasher.finalize().into();

        let public = PublicIdentity {
            ed25519_public,
            x25519_public,
            user_id,
        };

        Ok(Self {
            ed25519_signing,
            x25519_secret,
            public,
        })
    }

    /// Save identity to storage file with restricted permissions
    fn save_to_storage(&self, path: &PathBuf) -> Result<(), String> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create storage directory: {}", e))?;
        }

        let keys = IdentityKeys {
            ed25519_secret: self.ed25519_signing.to_bytes(),
            x25519_secret: self.x25519_secret.to_bytes(),
        };

        let data = serde_json::to_vec(&keys)
            .map_err(|e| format!("Failed to serialize identity: {}", e))?;

        // Write to temporary file first, then rename (atomic operation)
        let temp_path = path.with_extension("tmp");
        let mut file = fs::File::create(&temp_path)
            .map_err(|e| format!("Failed to create identity file: {}", e))?;
        
        file.write_all(&data)
            .map_err(|e| format!("Failed to write identity file: {}", e))?;
        
        file.sync_all()
            .map_err(|e| format!("Failed to sync identity file: {}", e))?;
        drop(file);

        // Rename temp file to final location (atomic)
        fs::rename(&temp_path, path)
            .map_err(|e| format!("Failed to rename identity file: {}", e))?;

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

    /// Get public identity (safe to expose)
    pub fn public(&self) -> &PublicIdentity {
        &self.public
    }

    /// Get Ed25519 signing key (for future use in Noise Protocol)
    #[allow(dead_code)] // Will be used in Phase 3 (DM Cryptography)
    pub fn ed25519_signing_key(&self) -> &SigningKey {
        &self.ed25519_signing
    }

    /// Get X25519 secret (for future use in Noise Protocol)
    #[allow(dead_code)] // Will be used in Phase 3 (DM Cryptography)
    pub fn x25519_secret(&self) -> &StaticSecret {
        &self.x25519_secret
    }
}

/// Get the storage path for identity file
fn get_storage_path() -> Result<PathBuf, String> {
    let data_dir = dirs::data_local_dir()
        .ok_or("Failed to get data directory")?;
    
    Ok(data_dir.join("meshapp").join("identity.json"))
}

/// Get user_id as hex string
pub fn user_id_to_hex(user_id: &[u8; 32]) -> String {
    hex::encode(user_id)
}

/// Get public key as hex string
pub fn public_key_to_hex(key: &[u8]) -> String {
    hex::encode(key)
}

