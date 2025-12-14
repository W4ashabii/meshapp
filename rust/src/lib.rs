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

use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::Mutex;
use once_cell::sync::Lazy;

// Global identity instance (lazy-loaded, thread-safe)
static IDENTITY: Lazy<Mutex<Option<identity::Identity>>> = Lazy::new(|| Mutex::new(None));

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

