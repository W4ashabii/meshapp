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

use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::Mutex;
use once_cell::sync::Lazy;

// Global identity instance (lazy-loaded, thread-safe)
static IDENTITY: Lazy<Mutex<Option<identity::Identity>>> = Lazy::new(|| Mutex::new(None));

// Global friends manager (lazy-loaded, thread-safe)
static FRIENDS: Lazy<Mutex<Option<friends::FriendManager>>> = Lazy::new(|| Mutex::new(None));

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
                serde_json::json!({
                    "user_id": hex::encode(f.user_id),
                    "ed25519_public": hex::encode(f.ed25519_public),
                    "nickname": f.nickname,
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

