//! C FFI interface for LCP decryption library
//!
//! This module provides C-compatible functions for use from Lua/LuaJIT via FFI.

#![allow(clippy::needless_return)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::Mutex;

use lcp_core::crypto::key::{UserEncryptionKey, UserPassphrase};
use lcp_core::epub::Epub;

// Global error storage (using Mutex instead of thread_local to avoid TLS init issues on old ARM)
static LAST_ERROR: Mutex<Option<CString>> = Mutex::new(None);

fn set_error(msg: String) {
    if let Ok(mut guard) = LAST_ERROR.lock() {
        *guard = CString::new(msg).ok();
    }
}

fn clear_error() {
    if let Ok(mut guard) = LAST_ERROR.lock() {
        *guard = None;
    }
}

fn log(msg: &str) {
    eprintln!("[lcp-rs] {}", msg);
}

/// Initialize the library and verify it's functional.
///
/// # Returns
/// * `0` on success
#[unsafe(no_mangle)]
pub extern "C" fn lcp_init() -> i32 {
    log("lcp_init called - library loaded successfully");
    0
}

/// Check if an EPUB file is LCP encrypted.
///
/// # Returns
/// * `1` if the file is LCP encrypted
/// * `0` if the file is not LCP encrypted
/// * `-1` on error (call lcp_get_error for details)
/// # Safety
///
/// This is an ffi function that is called from C.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcp_is_encrypted(epub_path: *const c_char) -> i32 {
    clear_error();
    log("lcp_is_encrypted called");

    if epub_path.is_null() {
        set_error("epub_path is null".to_string());
        log("ERROR: epub_path is null");
        return -1;
    }

    let path = match unsafe { CStr::from_ptr(epub_path) }.to_str() {
        Ok(s) => {
            log(&format!("checking: {}", s));
            PathBuf::from(s)
        }
        Err(e) => {
            set_error(format!("Invalid UTF-8 in path: {}", e));
            log(&format!("ERROR: invalid UTF-8 in path: {}", e));
            return -1;
        }
    };

    match Epub::new(path) {
        Ok(epub) => {
            let encrypted = epub.license().is_some();
            log(&format!("encrypted: {}", encrypted));
            if encrypted { 1 } else { 0 }
        }
        Err(e) => {
            set_error(format!("Failed to open EPUB: {}", e));
            log(&format!("ERROR: failed to open EPUB: {}", e));
            -1
        }
    }
}

/// Decrypt an LCP-encrypted EPUB to a new file.
///
/// # Returns
/// * `0` on success
/// * `1` if the passphrase is incorrect
/// * `2` if the file is not LCP encrypted
/// * `-1` on other errors (call lcp_get_error for details)
/// # Safety
///
/// This is an ffi function that is called from C.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lcp_decrypt_epub(
    epub_path: *const c_char,
    output_path: *const c_char,
    passphrase: *const c_char,
) -> i32 {
    clear_error();
    log("lcp_decrypt_epub called");

    if epub_path.is_null() {
        set_error("epub_path is null".to_string());
        log("ERROR: epub_path is null");
        return -1;
    }
    if output_path.is_null() {
        set_error("output_path is null".to_string());
        log("ERROR: output_path is null");
        return -1;
    }
    if passphrase.is_null() {
        set_error("passphrase is null".to_string());
        log("ERROR: passphrase is null");
        return -1;
    }

    let input_path = match unsafe { CStr::from_ptr(epub_path) }.to_str() {
        Ok(s) => {
            log(&format!("input: {}", s));
            PathBuf::from(s)
        }
        Err(e) => {
            set_error(format!("Invalid UTF-8 in input path: {}", e));
            log(&format!("ERROR: invalid UTF-8 in input path: {}", e));
            return -1;
        }
    };

    let output = match unsafe { CStr::from_ptr(output_path) }.to_str() {
        Ok(s) => {
            log(&format!("output: {}", s));
            PathBuf::from(s)
        }
        Err(e) => {
            set_error(format!("Invalid UTF-8 in output path: {}", e));
            return -1;
        }
    };

    let pass = match unsafe { CStr::from_ptr(passphrase) }.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_error(format!("Invalid UTF-8 in passphrase: {}", e));
            return -1;
        }
    };

    // Open the EPUB
    let mut epub = match Epub::new(input_path.clone()) {
        Ok(e) => e,
        Err(e) => {
            set_error(format!("Failed to open EPUB: {}", e));
            log(&format!("ERROR: failed to open EPUB: {}", e));
            return -1;
        }
    };

    // Check if it's LCP encrypted
    let license = match epub.license() {
        Some(l) => l,
        None => {
            set_error("EPUB is not LCP encrypted".to_string());
            log("not LCP encrypted");
            return 2;
        }
    };

    let profile = match license.profile() {
        Ok(profile) => profile,
        Err(e) => {
            set_error(e.to_string());
            log(&e.to_string());
            return 2;
        }
    };
    // Verify passphrase and get user key
    log("verifying passphrase...");
    let user_encryption_key = UserEncryptionKey::new(
        UserPassphrase(pass.to_string()),
        lcp_core::crypto::key::HashAlgorithm::Sha256,
        profile,
    );
    if license.key_check(&user_encryption_key).is_err() {
        set_error("Incorrect passphrase".to_string());
        log("incorrect passphrase");
        return 1;
    };

    // Decrypt the content key
    log("decrypting content key...");
    let content_key = match license.decrypt_content_key(&user_encryption_key) {
        Ok(k) => k,
        Err(e) => {
            set_error(format!("Failed to decrypt content key: {}", e));
            log(&format!("ERROR: failed to decrypt content key: {}", e));
            return -1;
        }
    };

    log("creating decrypted EPUB...");
    match epub.create_decrypted_epub(output, &content_key) {
        Ok(writer) => {
            if let Err(e) = writer.finish() {
                set_error(format!("Failed to finalize EPUB: {}", e));
                log(&format!("ERROR: failed to finalize EPUB: {}", e));
                return -1;
            }
            log("decryption successful");
            return 0;
        }
        Err(e) => {
            set_error(e.to_string());
            log(&format!("ERROR: {}", e));
            return -1;
        }
    }
}

/// Get the last error message.
///
/// # Returns
/// A pointer to a null-terminated error string, or NULL if no error occurred.
/// The string is valid until the next call to any lcp_* function.
#[unsafe(no_mangle)]
pub extern "C" fn lcp_get_error() -> *const c_char {
    match LAST_ERROR.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(cstr) => cstr.as_ptr(),
            None => std::ptr::null(),
        },
        Err(_) => std::ptr::null(),
    }
}
