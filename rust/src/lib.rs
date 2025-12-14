//! Mesh Messenger Core Library
//! 
//! This is the core Rust library that will handle:
//! - Cryptography (Noise Protocol)
//! - Storage (SQLite)
//! - Transport abstraction (BLE, etc.)
//! - Routing logic
//!
//! Phase 0: Basic FFI skeleton only

use std::ffi::CString;
use std::os::raw::c_char;

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

