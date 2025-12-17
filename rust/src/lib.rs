//! Mesh Messenger Core Library
//! 
//! This is the core Rust library that will handle:
//! - Cryptography (Noise Protocol)
//! - Storage (SQLite)
//! - Transport abstraction (BLE, etc.)
//! - Routing logic
//!
//! Phase 1: Identity generation and secure storage

mod identity;
mod friends;
mod dm_crypto;
mod storage;
mod transport;
mod geo;
mod mentions;
mod optimization;

use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::Mutex;
use once_cell::sync::Lazy;
use std::time::{SystemTime, UNIX_EPOCH};

// Global identity instance (lazy-loaded, thread-safe)
static IDENTITY: Lazy<Mutex<Option<identity::Identity>>> = Lazy::new(|| Mutex::new(None));

// Global friends manager (lazy-loaded, thread-safe)
static FRIENDS: Lazy<Mutex<Option<friends::FriendManager>>> = Lazy::new(|| Mutex::new(None));

// Global storage (lazy-loaded, thread-safe)
static STORAGE: Lazy<Mutex<Option<storage::Storage>>> = Lazy::new(|| Mutex::new(None));

// Global router and loopback transport (Phase 6 store-and-forward)
static ROUTER: Lazy<Mutex<Option<transport::Router>>> = Lazy::new(|| Mutex::new(None));
static LOOPBACK: Lazy<Mutex<Option<std::sync::Arc<transport::LoopbackTransport>>>> =
    Lazy::new(|| Mutex::new(None));

/// Initialize identity (loads from storage or generates new one)
/// Returns 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn init_identity() -> i32 {
    match identity::Identity::load_or_generate() {
        Ok(id) => {
            *IDENTITY.lock().unwrap() = Some(id);
            0
        }
        Err(e) => {
            eprintln!("Failed to initialize identity: {}", e);
            -1
        }
    }
}

/// Get user ID (SHA256 of Ed25519 public key) as hex string
/// Returns null on error
#[no_mangle]
pub extern "C" fn get_user_id() -> *mut c_char {
    let identity_guard = IDENTITY.lock().unwrap();
    if let Some(ref id) = *identity_guard {
        let user_id_hex = identity::user_id_to_hex(&id.public().user_id);
        CString::new(user_id_hex)
            .ok()
            .map(|s| s.into_raw())
            .unwrap_or(std::ptr::null_mut())
    } else {
        std::ptr::null_mut()
    }
}

/// Get Ed25519 public key as hex string
/// Returns null on error
#[no_mangle]
pub extern "C" fn get_ed25519_public_key() -> *mut c_char {
    let identity_guard = IDENTITY.lock().unwrap();
    if let Some(ref id) = *identity_guard {
        let key_hex = identity::public_key_to_hex(id.public().ed25519_public.as_bytes());
        CString::new(key_hex)
            .ok()
            .map(|s| s.into_raw())
            .unwrap_or(std::ptr::null_mut())
    } else {
        std::ptr::null_mut()
    }
}

/// Get X25519 public key as hex string
/// Returns null on error
#[no_mangle]
pub extern "C" fn get_x25519_public_key() -> *mut c_char {
    let identity_guard = IDENTITY.lock().unwrap();
    if let Some(ref id) = *identity_guard {
        let key_hex = identity::public_key_to_hex(id.public().x25519_public.as_bytes());
        CString::new(key_hex)
            .ok()
            .map(|s| s.into_raw())
            .unwrap_or(std::ptr::null_mut())
    } else {
        std::ptr::null_mut()
    }
}

/// Get identity fingerprint (first 16 chars of user_id for display)
/// Returns null on error
#[no_mangle]
pub extern "C" fn get_fingerprint() -> *mut c_char {
    let identity_guard = IDENTITY.lock().unwrap();
    if let Some(ref id) = *identity_guard {
        let user_id_hex = identity::user_id_to_hex(&id.public().user_id);
        let fingerprint = user_id_hex.chars().take(16).collect::<String>();
        CString::new(fingerprint)
            .ok()
            .map(|s| s.into_raw())
            .unwrap_or(std::ptr::null_mut())
    } else {
        std::ptr::null_mut()
    }
}

// ========== Friends Management ==========

/// Initialize friends manager
/// Returns 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn init_friends() -> i32 {
    match friends::FriendManager::new() {
        Ok(fm) => {
            *FRIENDS.lock().unwrap() = Some(fm);
            0
        }
        Err(e) => {
            eprintln!("Failed to initialize friends: {}", e);
            -1
        }
    }
}

/// Add a friend from Ed25519 public key (hex) and nickname
/// Returns user_id (hex) on success, null on error
#[no_mangle]
pub extern "C" fn add_friend(ed25519_public_hex: *const c_char, nickname: *const c_char) -> *mut c_char {
    let public_key_str = unsafe {
        if ed25519_public_hex.is_null() {
            return std::ptr::null_mut();
        }
        match std::ffi::CStr::from_ptr(ed25519_public_hex).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };

    let nickname_str = unsafe {
        if nickname.is_null() {
            return std::ptr::null_mut();
        }
        match std::ffi::CStr::from_ptr(nickname).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return std::ptr::null_mut(),
        }
    };

    let public_key_bytes = match hex::decode(public_key_str) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    if public_key_bytes.len() != 32 {
        return std::ptr::null_mut();
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&public_key_bytes);

    let mut friends_guard = FRIENDS.lock().unwrap();
    if let Some(ref mut fm) = *friends_guard {
        match fm.add_friend(key, nickname_str) {
            Ok(user_id) => {
                let user_id_hex = hex::encode(user_id);
                CString::new(user_id_hex)
                    .ok()
                    .map(|s| s.into_raw())
                    .unwrap_or(std::ptr::null_mut())
            }
            Err(_) => std::ptr::null_mut(),
        }
    } else {
        std::ptr::null_mut()
    }
}

/// Remove a friend by user_id (hex)
/// Returns 1 if removed, 0 if not found, -1 on error
#[no_mangle]
pub extern "C" fn remove_friend(user_id_hex: *const c_char) -> i32 {
    let user_id_str = unsafe {
        if user_id_hex.is_null() {
            return -1;
        }
        match std::ffi::CStr::from_ptr(user_id_hex).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    let user_id_bytes = match hex::decode(user_id_str) {
        Ok(bytes) => bytes,
        Err(_) => return -1,
    };

    if user_id_bytes.len() != 32 {
        return -1;
    }

    let mut user_id = [0u8; 32];
    user_id.copy_from_slice(&user_id_bytes);

    let mut friends_guard = FRIENDS.lock().unwrap();
    if let Some(ref mut fm) = *friends_guard {
        match fm.remove_friend(&user_id) {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(_) => -1,
        }
    } else {
        -1
    }
}

/// Get all friends as JSON array
/// Returns JSON string, null on error
#[no_mangle]
pub extern "C" fn get_all_friends() -> *mut c_char {
    let friends_guard = FRIENDS.lock().unwrap();
    if let Some(ref fm) = *friends_guard {
        let friends_list: Vec<serde_json::Value> = fm.get_all_friends()
            .iter()
            .map(|f| {
                let display_name = f.custom_display_name.as_ref()
                    .unwrap_or(&f.nickname);
                serde_json::json!({
                    "user_id": hex::encode(f.user_id),
                    "ed25519_public": hex::encode(f.ed25519_public),
                    "nickname": f.nickname,
                    "display_name": display_name,
                    "notes": f.notes,
                    "tags": f.tags,
                })
            })
            .collect();

        match serde_json::to_string(&friends_list) {
            Ok(json) => CString::new(json)
                .ok()
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut()),
            Err(_) => std::ptr::null_mut(),
        }
    } else {
        std::ptr::null_mut()
    }
}

/// Update friend nickname
/// Returns 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn update_friend_nickname(user_id_hex: *const c_char, nickname: *const c_char) -> i32 {
    let user_id_str = unsafe {
        if user_id_hex.is_null() {
            return -1;
        }
        match std::ffi::CStr::from_ptr(user_id_hex).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    let nickname_str = unsafe {
        if nickname.is_null() {
            return -1;
        }
        match std::ffi::CStr::from_ptr(nickname).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        }
    };

    let user_id_bytes = match hex::decode(user_id_str) {
        Ok(bytes) => bytes,
        Err(_) => return -1,
    };

    if user_id_bytes.len() != 32 {
        return -1;
    }

    let mut user_id = [0u8; 32];
    user_id.copy_from_slice(&user_id_bytes);

    let mut friends_guard = FRIENDS.lock().unwrap();
    if let Some(ref mut fm) = *friends_guard {
        match fm.update_nickname(&user_id, nickname_str) {
            Ok(_) => 0,
            Err(_) => -1,
        }
    } else {
        -1
    }
}

/// Update friend profile (all customizable fields)
/// Parameters: user_id_hex, nickname (null = no change), notes (null = no change), 
///             tags_json (null = no change, JSON array of strings), custom_display_name (null = no change, empty string = clear)
/// Returns 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn update_friend_profile(
    user_id_hex: *const c_char,
    nickname: *const c_char,
    notes: *const c_char,
    tags_json: *const c_char,
    custom_display_name: *const c_char,
) -> i32 {
    let user_id_str = unsafe {
        if user_id_hex.is_null() {
            return -1;
        }
        match std::ffi::CStr::from_ptr(user_id_hex).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    let user_id_bytes = match hex::decode(user_id_str) {
        Ok(bytes) => bytes,
        Err(_) => return -1,
    };

    if user_id_bytes.len() != 32 {
        return -1;
    }

    let mut user_id = [0u8; 32];
    user_id.copy_from_slice(&user_id_bytes);

    let nickname_opt = if nickname.is_null() {
        None
    } else {
        unsafe {
            match std::ffi::CStr::from_ptr(nickname).to_str() {
                Ok(s) if !s.is_empty() => Some(s.to_string()),
                _ => None,
            }
        }
    };

    let notes_opt = if notes.is_null() {
        None
    } else {
        unsafe {
            match std::ffi::CStr::from_ptr(notes).to_str() {
                Ok(s) => Some(s.to_string()),
                Err(_) => None,
            }
        }
    };

    let tags_opt = if tags_json.is_null() {
        None
    } else {
        unsafe {
            match std::ffi::CStr::from_ptr(tags_json).to_str() {
                Ok(s) => {
                    match serde_json::from_str::<Vec<String>>(s) {
                        Ok(tags) => Some(tags),
                        Err(_) => None,
                    }
                }
                Err(_) => None,
            }
        }
    };

    let custom_display_name_opt = if custom_display_name.is_null() {
        None
    } else {
        unsafe {
            match std::ffi::CStr::from_ptr(custom_display_name).to_str() {
                Ok(s) if s.is_empty() => Some(None), // Clear custom display name
                Ok(s) => Some(Some(s.to_string())),
                Err(_) => None,
            }
        }
    };

    let mut friends_guard = FRIENDS.lock().unwrap();
    if let Some(ref mut fm) = *friends_guard {
        match fm.update_profile(&user_id, nickname_opt, notes_opt, tags_opt, custom_display_name_opt) {
            Ok(_) => 0,
            Err(_) => -1,
        }
    } else {
        -1
    }
}

/// Get own public identity as JSON for QR export
/// Returns JSON string, null on error
#[no_mangle]
pub extern "C" fn export_own_identity() -> *mut c_char {
    let identity_guard = IDENTITY.lock().unwrap();
    if let Some(ref id) = *identity_guard {
        let export = serde_json::json!({
            "user_id": identity::user_id_to_hex(&id.public().user_id),
            "ed25519_public": identity::public_key_to_hex(id.public().ed25519_public.as_bytes()),
        });

        match serde_json::to_string(&export) {
            Ok(json) => CString::new(json)
                .ok()
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut()),
            Err(_) => std::ptr::null_mut(),
        }
    } else {
        std::ptr::null_mut()
    }
}

/// Import friend from JSON (for QR scanning)
/// Returns user_id (hex) on success, null on error
#[no_mangle]
pub extern "C" fn import_friend_from_json(json: *const c_char, nickname: *const c_char) -> *mut c_char {
    let json_str = unsafe {
        if json.is_null() {
            return std::ptr::null_mut();
        }
        match std::ffi::CStr::from_ptr(json).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };

    let nickname_str = unsafe {
        if nickname.is_null() {
            return std::ptr::null_mut();
        }
        match std::ffi::CStr::from_ptr(nickname).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return std::ptr::null_mut(),
        }
    };

    match friends::parse_friend_from_json(json_str) {
        Ok((_, ed25519_public)) => {
            let mut friends_guard = FRIENDS.lock().unwrap();
            if let Some(ref mut fm) = *friends_guard {
                match fm.add_friend(ed25519_public, nickname_str) {
                    Ok(user_id) => {
                        let user_id_hex = hex::encode(user_id);
                        CString::new(user_id_hex)
                            .ok()
                            .map(|s| s.into_raw())
                            .unwrap_or(std::ptr::null_mut())
                    }
                    Err(_) => std::ptr::null_mut(),
                }
            } else {
                std::ptr::null_mut()
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

// ========== Storage (Phase 4) ==========

/// Initialize SQLite storage
/// Returns 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn init_storage() -> i32 {
    let db_path = match storage::db_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to get db path: {}", e);
            return -1;
        }
    };

    match storage::Storage::init(&db_path) {
        Ok(s) => {
            *STORAGE.lock().unwrap() = Some(s);
            0
        }
        Err(e) => {
            eprintln!("Failed to initialize storage: {}", e);
            -1
        }
    }
}

/// Store a message
/// Returns 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn store_message(
    message_id_hex: *const c_char,
    channel_id_hex: *const c_char,
    ciphertext_hex: *const c_char,
    timestamp: i64,
    ttl: u8,
) -> i32 {
    let message_id = match parse_hex_32(message_id_hex) {
        Some(v) => v,
        None => return -1,
    };
    let channel_id = match parse_hex_32(channel_id_hex) {
        Some(v) => v,
        None => return -1,
    };
    let ciphertext = match parse_hex_vec(ciphertext_hex) {
        Some(v) => v,
        None => return -1,
    };

    let storage_guard = STORAGE.lock().unwrap();
    if let Some(ref storage) = *storage_guard {
        match storage.store_message(message_id, channel_id, ciphertext, timestamp, ttl) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("store_message failed: {}", e);
                -1
            }
        }
    } else {
        -1
    }
}

/// Get messages for a channel as JSON
/// Returns JSON string or null on error
#[no_mangle]
pub extern "C" fn get_messages(
    channel_id_hex: *const c_char,
    limit: u32,
    offset: u32,
) -> *mut c_char {
    let channel_id = match parse_hex_32(channel_id_hex) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };

    let storage_guard = STORAGE.lock().unwrap();
    if let Some(ref storage) = *storage_guard {
        match storage.fetch_messages(channel_id, limit, offset) {
            Ok(rows) => {
                let json_rows: Vec<serde_json::Value> = rows
                    .into_iter()
                    .map(|r| {
                        serde_json::json!({
                            "message_id": hex::encode(r.message_id),
                            "channel_id": hex::encode(r.channel_id),
                            "ciphertext": hex::encode(r.ciphertext),
                            "timestamp": r.timestamp,
                            "ttl": r.ttl,
                        })
                    })
                    .collect();
                match serde_json::to_string(&json_rows) {
                    Ok(s) => CString::new(s)
                        .ok()
                        .map(|s| s.into_raw())
                        .unwrap_or(std::ptr::null_mut()),
                    Err(_) => std::ptr::null_mut(),
                }
            }
            Err(e) => {
                eprintln!("get_messages failed: {}", e);
                std::ptr::null_mut()
            }
        }
    } else {
        std::ptr::null_mut()
    }
}

// ========== DM Cryptography ==========

/// Derive DM channel ID from two user IDs (Ed25519 public keys as hex)
/// Returns channel_id (hex) on success, null on error
#[no_mangle]
pub extern "C" fn derive_dm_channel_id(user_id_a_hex: *const c_char, user_id_b_hex: *const c_char) -> *mut c_char {
    let user_id_a_str = unsafe {
        if user_id_a_hex.is_null() {
            return std::ptr::null_mut();
        }
        match std::ffi::CStr::from_ptr(user_id_a_hex).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };

    let user_id_b_str = unsafe {
        if user_id_b_hex.is_null() {
            return std::ptr::null_mut();
        }
        match std::ffi::CStr::from_ptr(user_id_b_hex).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };

    let user_id_a_bytes = match hex::decode(user_id_a_str) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let user_id_b_bytes = match hex::decode(user_id_b_str) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    if user_id_a_bytes.len() != 32 || user_id_b_bytes.len() != 32 {
        return std::ptr::null_mut();
    }

    let mut pub_a = [0u8; 32];
    let mut pub_b = [0u8; 32];
    pub_a.copy_from_slice(&user_id_a_bytes);
    pub_b.copy_from_slice(&user_id_b_bytes);

    let channel_id = dm_crypto::derive_dm_channel_id(&pub_a, &pub_b);
    let channel_id_hex = dm_crypto::dm_channel_id_to_hex(&channel_id);

    CString::new(channel_id_hex)
        .ok()
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Helper to parse hex string to [u8; 32]
fn parse_hex_32(hex_ptr: *const c_char) -> Option<[u8; 32]> {
    if hex_ptr.is_null() {
        return None;
    }
    
    let hex_str = unsafe {
        match std::ffi::CStr::from_ptr(hex_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return None,
        }
    };

    let bytes = match hex::decode(hex_str) {
        Ok(b) => b,
        Err(_) => return None,
    };
    
    if bytes.len() != 32 {
        return None;
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Some(result)
}

/// Helper to parse hex string to Vec<u8>
fn parse_hex_vec(hex_ptr: *const c_char) -> Option<Vec<u8>> {
    if hex_ptr.is_null() {
        return None;
    }

    let hex_str = unsafe {
        match std::ffi::CStr::from_ptr(hex_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return None,
        }
    };

    hex::decode(hex_str).ok()
}

/// Send a DM message (encrypt and store)
/// Parameters: friend_user_id_hex, plaintext message
/// Returns message_id (hex) on success, null on error
#[no_mangle]
pub extern "C" fn send_dm_message(friend_user_id_hex: *const c_char, plaintext: *const c_char) -> *mut c_char {
    let friend_user_id = match parse_hex_32(friend_user_id_hex) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };

    let plaintext_str = unsafe {
        if plaintext.is_null() {
            return std::ptr::null_mut();
        }
        match std::ffi::CStr::from_ptr(plaintext).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };

    // Get our identity
    let identity_guard = IDENTITY.lock().unwrap();
    let identity = match identity_guard.as_ref() {
        Some(id) => id,
        None => return std::ptr::null_mut(),
    };

    let our_user_id = identity.public().user_id;
    let local_ed25519 = identity.public().ed25519_public.as_bytes();
    let local_x25519_secret = identity.x25519_secret().as_bytes();
    let local_x25519_public = identity.public().x25519_public.as_bytes();

    // Check if messaging yourself - use deterministic encryption
    let is_self = friend_user_id == our_user_id;
    
    let (remote_ed25519, remote_x25519_public, remote_x25519_secret, is_initiator) = 
        if is_self {
            // For self-messaging, we'll use deterministic encryption
            // These values won't be used, but we need them for the type
            let remote_ed25519 = *local_ed25519;
            let remote_x25519_public = *local_x25519_public;
            let remote_x25519_secret = *local_x25519_secret;
            (remote_ed25519, remote_x25519_public, remote_x25519_secret, true)
        } else {
            // Get friend's public key (clone to avoid borrow issues)
            let friend_ed25519_public = {
                let friends_guard = FRIENDS.lock().unwrap();
                match friends_guard.as_ref() {
                    Some(fm) => {
                        match fm.get_friend(&friend_user_id) {
                            Some(f) => f.ed25519_public,
                            None => return std::ptr::null_mut(),
                        }
                    }
                    None => return std::ptr::null_mut(),
                }
            };

            let remote_ed25519 = friend_ed25519_public; // Copy the array
            // For now, use placeholder approach: treat Ed25519 bytes as X25519 (not secure, testing only)
            let remote_x25519_public = friend_ed25519_public; // Placeholder
            let remote_x25519_secret = friend_ed25519_public; // Placeholder
            let is_initiator = our_user_id < friend_user_id;
            
            (remote_ed25519, remote_x25519_public, remote_x25519_secret, is_initiator)
        };
    
    // Derive channel ID
    let channel_id = if is_self {
        dm_crypto::derive_dm_channel_id(local_ed25519, local_ed25519)
    } else {
        dm_crypto::derive_dm_channel_id(local_ed25519, &remote_ed25519)
    };
    
    // Generate message ID (hash of channel_id + timestamp + plaintext)
    let timestamp = now_ts();
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(&channel_id);
    hasher.update(timestamp.to_be_bytes());
    hasher.update(plaintext_str.as_bytes());
    let message_id: [u8; 32] = hasher.finalize().into();
    
    // Encrypt message
    let ciphertext = if is_self {
        // Use deterministic encryption for self-messaging
        match dm_crypto::encrypt_self_message(&channel_id, &message_id, plaintext_str.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to encrypt self-message: {}", e);
                return std::ptr::null_mut();
            }
        }
    } else {
        // Use Noise Protocol for friend messaging
        let mut session = match dm_crypto::create_test_session(
            local_ed25519,
            local_x25519_secret,
            local_x25519_public,
            &remote_ed25519,
            &remote_x25519_secret,
            &remote_x25519_public,
            is_initiator,
        ) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to create session: {}", e);
                return std::ptr::null_mut();
            }
        };
        
        match session.encrypt(plaintext_str.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to encrypt message: {}", e);
                return std::ptr::null_mut();
            }
        }
    };

    // Store message
    let storage_guard = STORAGE.lock().unwrap();
    if let Some(ref storage) = *storage_guard {
        if let Err(_) = storage.store_message(message_id, channel_id, ciphertext, timestamp, 10) {
            return std::ptr::null_mut();
        }
    } else {
        return std::ptr::null_mut();
    }

    // Return message_id
    let message_id_hex = hex::encode(message_id);
    CString::new(message_id_hex)
        .ok()
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Get and decrypt messages for a DM channel
/// Parameters: friend_user_id_hex, limit, offset
/// Returns JSON array of decrypted messages, null on error
#[no_mangle]
pub extern "C" fn get_dm_messages(friend_user_id_hex: *const c_char, limit: u32, offset: u32) -> *mut c_char {
    let friend_user_id = match parse_hex_32(friend_user_id_hex) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };

    // Get our identity
    let identity_guard = IDENTITY.lock().unwrap();
    let identity = match identity_guard.as_ref() {
        Some(id) => id,
        None => return std::ptr::null_mut(),
    };

    let our_user_id = identity.public().user_id;
    let our_ed25519 = identity.public().ed25519_public.as_bytes();
    let local_x25519_secret = identity.x25519_secret().as_bytes();
    let local_x25519_public = identity.public().x25519_public.as_bytes();

    // Check if messaging yourself and get remote keys
    let (remote_ed25519, remote_x25519_public, remote_x25519_secret, encrypt_role, channel_id) = 
        if friend_user_id == our_user_id {
            // Messaging yourself - use your own keys (proper X25519 keys)
            let channel_id = dm_crypto::derive_dm_channel_id(our_ed25519, our_ed25519);
            let remote_ed25519 = *our_ed25519; // Copy the array
            let remote_x25519_public = *local_x25519_public; // Our own X25519 public
            let remote_x25519_secret = *local_x25519_secret; // Our own X25519 secret
            (remote_ed25519, remote_x25519_public, remote_x25519_secret, true, channel_id) // Always initiator for self
        } else {
            // Get friend's public key (clone to avoid borrow issues)
            let friend_ed25519_public = {
                let friends_guard = FRIENDS.lock().unwrap();
                match friends_guard.as_ref() {
                    Some(fm) => {
                        match fm.get_friend(&friend_user_id) {
                            Some(f) => f.ed25519_public,
                            None => return std::ptr::null_mut(),
                        }
                    }
                    None => return std::ptr::null_mut(),
                }
            };

            let channel_id = dm_crypto::derive_dm_channel_id(our_ed25519, &friend_ed25519_public);
            let remote_ed25519 = friend_ed25519_public; // Copy the array
            // TODO: In production, we'd store X25519 public keys for friends
            // For now, use placeholder approach: treat Ed25519 bytes as X25519 (not secure, testing only)
            let remote_x25519_public = friend_ed25519_public; // Placeholder - should be friend's X25519 public
            let remote_x25519_secret = friend_ed25519_public; // Placeholder - we don't have friend's X25519 secret
            let is_initiator = our_user_id < friend_user_id;
            
            (remote_ed25519, remote_x25519_public, remote_x25519_secret, is_initiator, channel_id)
        };

    // Get messages from storage
    let storage_guard = STORAGE.lock().unwrap();
    let messages = match storage_guard.as_ref() {
        Some(storage) => {
            match storage.fetch_messages(channel_id, limit, offset) {
                Ok(rows) => rows,
                Err(e) => {
                    eprintln!("Failed to fetch messages: {}", e);
                    return std::ptr::null_mut();
                }
            }
        }
        None => {
            eprintln!("Storage not initialized");
            return std::ptr::null_mut();
        }
    };

    eprintln!("Found {} messages for channel_id: {}", messages.len(), hex::encode(channel_id));

    // Keys for decryption
    let local_ed25519 = our_ed25519;

    // Decrypt messages
    let mut decrypted_messages = Vec::new();
    let is_self = friend_user_id == our_user_id;
    
    for msg in messages {
        let plaintext_result: Result<Vec<u8>, String> = if is_self {
            // Try deterministic decryption first (new method)
            let mut result = dm_crypto::decrypt_self_message(&channel_id, &msg.message_id, &msg.ciphertext);
            
            // If deterministic decryption fails, try Noise Protocol (old method for backwards compatibility)
            if result.is_err() {
                eprintln!("Deterministic decryption failed, trying Noise Protocol for message {}", hex::encode(msg.message_id));
                let decrypt_role = !encrypt_role; // Try opposite role
                
                // Try to create session with opposite role
                let mut session_opt = dm_crypto::create_test_session(
                    local_ed25519,
                    local_x25519_secret,
                    local_x25519_public,
                    &remote_ed25519,
                    &remote_x25519_secret,
                    &remote_x25519_public,
                    decrypt_role,
                ).ok();
                
                // If that failed, try same role as fallback
                if session_opt.is_none() {
                    session_opt = dm_crypto::create_test_session(
                        local_ed25519,
                        local_x25519_secret,
                        local_x25519_public,
                        &remote_ed25519,
                        &remote_x25519_secret,
                        &remote_x25519_public,
                        encrypt_role,
                    ).ok();
                }
                
                // Try to decrypt with Noise session if we have one
                if let Some(mut session) = session_opt {
                    result = session.decrypt(&msg.ciphertext);
                } else {
                    eprintln!("Failed to create Noise session with either role for message {}", hex::encode(msg.message_id));
                }
            }
            result
        } else {
            // Use Noise Protocol for friend messaging
            // In Noise IK pattern:
            // - Initiator encrypts with write_message, responder decrypts with read_message
            // - Responder encrypts with write_message, initiator decrypts with read_message
            // So if we encrypted as initiator, we must decrypt as responder (and vice versa)
            let decrypt_role = !encrypt_role;
            
            // Try decrypting with the opposite role first (correct approach)
            let mut session = match dm_crypto::create_test_session(
                local_ed25519,
                local_x25519_secret,
                local_x25519_public,
                &remote_ed25519,
                &remote_x25519_secret,
                &remote_x25519_public,
                decrypt_role,
            ) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to create decrypt session (role {}): {}", decrypt_role, e);
                    continue;
                }
            };
            
            match session.decrypt(&msg.ciphertext) {
                Ok(bytes) => Ok(bytes),
                Err(e) => {
                    eprintln!("Failed to decrypt message {} with role {}: {}", hex::encode(msg.message_id), decrypt_role, e);
                    // Try same role as fallback
                    let mut fallback_session = match dm_crypto::create_test_session(
                        local_ed25519,
                        local_x25519_secret,
                        local_x25519_public,
                        &remote_ed25519,
                        &remote_x25519_secret,
                        &remote_x25519_public,
                        encrypt_role,
                    ) {
                        Ok(s) => s,
                        Err(_) => {
                            eprintln!("Could not decrypt message {} with either role", hex::encode(msg.message_id));
                            continue;
                        }
                    };
                    fallback_session.decrypt(&msg.ciphertext)
                }
            }
        };
        
        match plaintext_result {
            Ok(plaintext_bytes) => {
                match String::from_utf8(plaintext_bytes) {
                    Ok(plaintext) => {
                        decrypted_messages.push(serde_json::json!({
                            "message_id": hex::encode(msg.message_id),
                            "plaintext": plaintext,
                            "timestamp": msg.timestamp,
                            "is_sent": is_self || encrypt_role, // Self-messages are always sent by us
                        }));
                    }
                    Err(e) => {
                        eprintln!("Failed to decode plaintext as UTF-8: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to decrypt message {}: {}", hex::encode(msg.message_id), e);
            }
        }
    }

    match serde_json::to_string(&decrypted_messages) {
        Ok(s) => CString::new(s)
            .ok()
            .map(|s| s.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Clear all messages for a DM channel
/// Parameters: friend_user_id_hex
/// Returns 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn clear_dm_messages(friend_user_id_hex: *const c_char) -> i32 {
    let friend_user_id = match parse_hex_32(friend_user_id_hex) {
        Some(v) => v,
        None => return -1,
    };

    // Get our identity
    let identity_guard = IDENTITY.lock().unwrap();
    let identity = match identity_guard.as_ref() {
        Some(id) => id,
        None => return -1,
    };

    let our_ed25519 = identity.public().ed25519_public.as_bytes();
    
    // Derive channel ID
    let channel_id = if friend_user_id == identity.public().user_id {
        // Self-messaging
        dm_crypto::derive_dm_channel_id(our_ed25519, our_ed25519)
    } else {
        // Get friend's public key
        let friends_guard = FRIENDS.lock().unwrap();
        let friend_ed25519_public = match friends_guard.as_ref() {
            Some(fm) => {
                match fm.get_friend(&friend_user_id) {
                    Some(f) => f.ed25519_public,
                    None => return -1,
                }
            }
            None => return -1,
        };
        dm_crypto::derive_dm_channel_id(our_ed25519, &friend_ed25519_public)
    };

    // Delete messages
    let storage_guard = STORAGE.lock().unwrap();
    match storage_guard.as_ref() {
        Some(storage) => {
            match storage.delete_channel_messages(channel_id) {
                Ok(_) => 0,
                Err(_) => -1,
            }
        }
        None => -1,
    }
}

/// Helper: current timestamp seconds since UNIX_EPOCH
fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Test encrypt/decrypt roundtrip (Phase 3 testing)
/// 
/// This function demonstrates the encryption/decryption APIs work correctly.
/// It requires both peers' keys to simulate the handshake.
/// 
/// Returns: "OK" on success, error message on failure
#[no_mangle]
pub extern "C" fn test_dm_encrypt_decrypt(
    local_ed25519_hex: *const c_char,
    local_x25519_secret_hex: *const c_char,
    local_x25519_public_hex: *const c_char,
    remote_ed25519_hex: *const c_char,
    remote_x25519_secret_hex: *const c_char,
    remote_x25519_public_hex: *const c_char,
    test_message_hex: *const c_char,
) -> *mut c_char {
    // Parse all inputs
    let local_ed25519 = match parse_hex_32(local_ed25519_hex) {
        Some(k) => k,
        None => {
            return CString::new("Error: Invalid local_ed25519_hex").ok()
                .map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
        }
    };
    
    let local_x25519_secret = match parse_hex_32(local_x25519_secret_hex) {
        Some(k) => k,
        None => {
            return CString::new("Error: Invalid local_x25519_secret_hex").ok()
                .map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
        }
    };
    
    let local_x25519_public = match parse_hex_32(local_x25519_public_hex) {
        Some(k) => k,
        None => {
            return CString::new("Error: Invalid local_x25519_public_hex").ok()
                .map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
        }
    };
    
    let remote_ed25519 = match parse_hex_32(remote_ed25519_hex) {
        Some(k) => k,
        None => {
            return CString::new("Error: Invalid remote_ed25519_hex").ok()
                .map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
        }
    };
    
    let remote_x25519_secret = match parse_hex_32(remote_x25519_secret_hex) {
        Some(k) => k,
        None => {
            return CString::new("Error: Invalid remote_x25519_secret_hex").ok()
                .map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
        }
    };
    
    let remote_x25519_public = match parse_hex_32(remote_x25519_public_hex) {
        Some(k) => k,
        None => {
            return CString::new("Error: Invalid remote_x25519_public_hex").ok()
                .map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
        }
    };
    
    let test_message_str = unsafe {
        if test_message_hex.is_null() {
            return CString::new("Error: test_message_hex is null").ok()
                .map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
        }
        match std::ffi::CStr::from_ptr(test_message_hex).to_str() {
            Ok(s) => s,
            Err(_) => {
                return CString::new("Error: Invalid test_message_hex").ok()
                    .map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
            }
        }
    };
    
    let test_message = match hex::decode(test_message_str) {
        Ok(b) => b,
        Err(_) => {
            return CString::new("Error: Failed to decode test_message_hex").ok()
                .map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
        }
    };

    // Create test sessions (both sides)
    let mut init_session = match dm_crypto::create_test_session(
        &local_ed25519,
        &local_x25519_secret,
        &local_x25519_public,
        &remote_ed25519,
        &remote_x25519_secret,
        &remote_x25519_public,
        true, // is_initiator
    ) {
        Ok(s) => s,
        Err(e) => {
            return CString::new(format!("Error creating initiator session: {}", e)).ok()
                .map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
        }
    };

    let mut resp_session = match dm_crypto::create_test_session(
        &local_ed25519,
        &local_x25519_secret,
        &local_x25519_public,
        &remote_ed25519,
        &remote_x25519_secret,
        &remote_x25519_public,
        false, // is_initiator
    ) {
        Ok(s) => s,
        Err(e) => {
            return CString::new(format!("Error creating responder session: {}", e)).ok()
                .map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
        }
    };

    // Encrypt on initiator side
    let ciphertext = match init_session.encrypt(&test_message) {
        Ok(c) => c,
        Err(e) => {
            return CString::new(format!("Error encrypting: {}", e)).ok()
                .map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
        }
    };

    // Decrypt on responder side
    let decrypted = match resp_session.decrypt(&ciphertext) {
        Ok(d) => d,
        Err(e) => {
            return CString::new(format!("Error decrypting: {}", e)).ok()
                .map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
        }
    };

    // Verify roundtrip
    if decrypted != test_message {
        return CString::new("Error: Decrypted message doesn't match original").ok()
            .map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut());
    }

    CString::new("OK: Encrypt/decrypt roundtrip successful").ok()
        .map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

// ========== Geohash Channels (Phase 7) ==========

/// Derive a geohash channel id from geohash + topic.
/// Returns channel_id hex on success, null on error.
#[no_mangle]
pub extern "C" fn derive_geo_channel_id(
    geohash_ptr: *const c_char,
    topic_ptr: *const c_char,
) -> *mut c_char {
    let geohash = unsafe {
        if geohash_ptr.is_null() {
            return std::ptr::null_mut();
        }
        match std::ffi::CStr::from_ptr(geohash_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };

    let topic = unsafe {
        if topic_ptr.is_null() {
            return std::ptr::null_mut();
        }
        match std::ffi::CStr::from_ptr(topic_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };

    let id = geo::derive_geo_channel_id(geohash, topic);
    let hex_str = geo::channel_id_to_hex(&id);
    CString::new(hex_str)
        .ok()
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Register a geohash channel in local storage.
/// channel_id_hex must be 32 bytes hex; returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn register_geo_channel(channel_id_hex: *const c_char) -> i32 {
    let channel_id = match parse_hex_32(channel_id_hex) {
        Some(v) => v,
        None => return -1,
    };

    let storage_guard = STORAGE.lock().unwrap();
    if let Some(ref storage) = *storage_guard {
        match storage.upsert_channel(channel_id, "geo") {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("register_geo_channel failed: {}", e);
                -1
            }
        }
    } else {
        -1
    }
}

/// List registered geohash channels.
/// Returns JSON array [{ channel_id, type }] or null on error.
#[no_mangle]
pub extern "C" fn get_geo_channels() -> *mut c_char {
    let storage_guard = STORAGE.lock().unwrap();
    if let Some(ref storage) = *storage_guard {
        match storage.list_channels_by_type("geo") {
            Ok(channels) => {
                let json: Vec<serde_json::Value> = channels
                    .into_iter()
                    .map(|c| {
                        serde_json::json!({
                            "channel_id": hex::encode(c.channel_id),
                            "type": c.channel_type,
                        })
                    })
                    .collect();
                match serde_json::to_string(&json) {
                    Ok(s) => CString::new(s)
                        .ok()
                        .map(|s| s.into_raw())
                        .unwrap_or(std::ptr::null_mut()),
                    Err(_) => std::ptr::null_mut(),
                }
            }
            Err(e) => {
                eprintln!("get_geo_channels failed: {}", e);
                std::ptr::null_mut()
            }
        }
    } else {
        std::ptr::null_mut()
    }
}

// ========== Mentions (Phase 8) ==========

/// Extract mentions from message text.
/// 
/// friends_json: JSON array of friends, e.g.:
///   [{ "user_id": "...", "nickname": "Alice" }, ...]
/// Returns JSON array of mentions:
///   [{ "user_id": "...", "nickname": "Alice" }, ...]
#[no_mangle]
pub extern "C" fn extract_mentions_from_text(
    text_ptr: *const c_char,
    friends_json_ptr: *const c_char,
) -> *mut c_char {
    let text = unsafe {
        if text_ptr.is_null() {
            return std::ptr::null_mut();
        }
        match std::ffi::CStr::from_ptr(text_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };

    let friends_json = unsafe {
        if friends_json_ptr.is_null() {
            return std::ptr::null_mut();
        }
        match std::ffi::CStr::from_ptr(friends_json_ptr).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };

    let friends: Vec<mentions::FriendInfo> = match serde_json::from_str(friends_json) {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };

    let mentions = mentions::extract_mentions(text, &friends);
    match serde_json::to_string(&mentions) {
        Ok(s) => CString::new(s)
            .ok()
            .map(|s| s.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Test function to verify FFI connectivity
/// 
/// Returns a test string to confirm Rust ↔ Flutter communication works
#[no_mangle]
pub extern "C" fn test_ffi() -> *mut c_char {
    let test_message = CString::new("FFI connection successful! Rust ↔ Flutter is working.")
        .expect("Failed to create CString");
    test_message.into_raw()
}

/// Free a CString allocated by Rust
/// 
/// Call this from Dart after reading the string to prevent memory leaks
#[no_mangle]
pub extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

// ========== Transport / Router (Phase 6) ==========

/// Initialize router with loopback transport (for testing / local dev).
/// Requires storage to be initialized for on_new persistence.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn init_router_with_loopback() -> i32 {
    let loopback = std::sync::Arc::new(transport::LoopbackTransport::new());
    let router = transport::Router::new(vec![loopback.clone()]);

    {
        let mut lb_guard = LOOPBACK.lock().unwrap();
        *lb_guard = Some(loopback);
    }
    {
        let mut r_guard = ROUTER.lock().unwrap();
        *r_guard = Some(router);
    }
    0
}

/// Send a packet (builds packet_id if not provided) via router.
/// packet_id_hex: optional (null pointer -> auto-generate)
/// channel_id_hex, payload_hex: required
/// ttl: hop limit
/// Returns packet_id_hex on success, null on error.
#[no_mangle]
pub extern "C" fn send_packet(
    packet_id_hex: *const c_char,
    channel_id_hex: *const c_char,
    payload_hex: *const c_char,
    ttl: u8,
) -> *mut c_char {
    let channel_id = match parse_hex_32(channel_id_hex) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };
    let payload = match parse_hex_vec(payload_hex) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };

    let packet_id = if packet_id_hex.is_null() {
        transport::Router::generate_packet_id()
    } else {
        match parse_hex_32(packet_id_hex) {
            Some(v) => v,
            None => return std::ptr::null_mut(),
        }
    };

    let packet = transport::Packet {
        packet_id,
        channel_id,
        ttl,
        payload,
    };

    // Route and store on new.
    {
        let r_guard = ROUTER.lock().unwrap();
        if let Some(ref router) = *r_guard {
            let storage_guard = STORAGE.lock().unwrap();
            let storage_opt = storage_guard.as_ref().map(|s| s as *const _);
            router.route(packet.clone(), |p| {
                // On new: persist message (ciphertext) for offline-first
                if let Some(storage_ptr) = storage_opt {
                    // Safety: storage_ptr derived from &storage; read-only here.
                    let storage: &storage::Storage = unsafe { &*storage_ptr };
                    let _ = storage.store_message(
                        p.packet_id,
                        p.channel_id,
                        p.payload.clone(),
                        now_ts(),
                        p.ttl,
                    );
                }
            });
        } else {
            return std::ptr::null_mut();
        }
    }

    CString::new(hex::encode(packet_id))
        .ok()
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Inject a received packet (e.g., from BLE) into the router.
/// packet_id_hex, channel_id_hex, payload_hex required; ttl as received.
#[no_mangle]
pub extern "C" fn ingest_packet(
    packet_id_hex: *const c_char,
    channel_id_hex: *const c_char,
    payload_hex: *const c_char,
    ttl: u8,
) -> i32 {
    let packet_id = match parse_hex_32(packet_id_hex) {
        Some(v) => v,
        None => return -1,
    };
    let channel_id = match parse_hex_32(channel_id_hex) {
        Some(v) => v,
        None => return -1,
    };
    let payload = match parse_hex_vec(payload_hex) {
        Some(v) => v,
        None => return -1,
    };

    let packet = transport::Packet {
        packet_id,
        channel_id,
        ttl,
        payload,
    };

    let r_guard = ROUTER.lock().unwrap();
    if let Some(ref router) = *r_guard {
        let storage_guard = STORAGE.lock().unwrap();
        let storage_opt = storage_guard.as_ref().map(|s| s as *const _);
        router.route(packet, |p| {
            if let Some(storage_ptr) = storage_opt {
                let storage: &storage::Storage = unsafe { &*storage_ptr };
                let _ = storage.store_message(
                    p.packet_id,
                    p.channel_id,
                    p.payload.clone(),
                    now_ts(),
                    p.ttl,
                );
            }
        });
        0
    } else {
        -1
    }
}

/// Drain loopback transport packets (testing helper).
/// Returns JSON array of packets {packet_id, channel_id, ttl, payload} hex-encoded.
#[no_mangle]
pub extern "C" fn drain_loopback_packets() -> *mut c_char {
    let lb_guard = LOOPBACK.lock().unwrap();
    if let Some(ref lb) = *lb_guard {
        let packets = lb.drain();
        let json: Vec<serde_json::Value> = packets
            .into_iter()
            .map(|p| {
                serde_json::json!({
                    "packet_id": hex::encode(p.packet_id),
                    "channel_id": hex::encode(p.channel_id),
                    "ttl": p.ttl,
                    "payload": hex::encode(p.payload),
                })
            })
            .collect();
        match serde_json::to_string(&json) {
            Ok(s) => CString::new(s).ok().map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut()),
            Err(_) => std::ptr::null_mut(),
        }
    } else {
        std::ptr::null_mut()
    }
}

// ========== Optimization (Phase 9) ==========

/// Get recommended optimization config as JSON
/// 
/// Returns JSON: {
///   "battery_mode": "Performance" | "Balanced" | "PowerSaving",
///   "scan_interval_ms": <number>,
///   "scan_window_ms": <number>,
///   "batch_size": <number>,
///   "batch_age_secs": <number>
/// }
#[no_mangle]
pub extern "C" fn get_optimization_config(battery_mode_str: *const c_char) -> *mut c_char {
    let mode_str = unsafe {
        if battery_mode_str.is_null() {
            return std::ptr::null_mut();
        }
        match std::ffi::CStr::from_ptr(battery_mode_str).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        }
    };

    let battery_mode = match mode_str.to_lowercase().as_str() {
        "performance" => optimization::BatteryMode::Performance,
        "balanced" => optimization::BatteryMode::Balanced,
        "powersaving" | "power_saving" => optimization::BatteryMode::PowerSaving,
        _ => optimization::BatteryMode::Balanced,
    };

    let config = optimization::OptimizationConfig::from_battery_mode(battery_mode);
    let mode_name = match battery_mode {
        optimization::BatteryMode::Performance => "Performance",
        optimization::BatteryMode::Balanced => "Balanced",
        optimization::BatteryMode::PowerSaving => "PowerSaving",
    };

    let json = serde_json::json!({
        "battery_mode": mode_name,
        "scan_interval_ms": config.scan_interval.as_millis(),
        "scan_window_ms": config.scan_interval.scan_window_ms(),
        "batch_size": config.batch_size,
        "batch_age_secs": config.batch_age_secs,
    });

    match serde_json::to_string(&json) {
        Ok(s) => CString::new(s).ok().map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(_) => std::ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn test_ffi_function() {
        let result = test_ffi();
        assert!(!result.is_null());
        
        let c_str = unsafe { CStr::from_ptr(result) };
        let message = c_str.to_str().unwrap();
        assert!(message.contains("FFI connection successful"));
        
        free_string(result);
    }
}

