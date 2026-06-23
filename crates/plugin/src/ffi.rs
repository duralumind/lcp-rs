//! C FFI interface for LCP decryption library
//!
//! This module provides C-compatible functions for use from Lua/LuaJIT via FFI.

#![allow(clippy::needless_return)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::Mutex;

use lcp_core::epub::Epub;
use lcp_core::{BasicResolver, EpubError, Error, LicenseError, OpenedPublication};

// Global error storage (using Mutex instead of thread_local to avoid TLS init issues on old ARM)
static LAST_ERROR: Mutex<Option<CString>> = Mutex::new(None);
const ROOT_CA_DER: &[u8] = include_bytes!("../../../certs/root_ca.der");

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

    log("opening LCP session...");
    let resolver = BasicResolver;
    match OpenedPublication::open_path(input_path, None, ROOT_CA_DER, &resolver)
        .and_then(|opened| opened.unlock_with_passphrase(pass))
        .and_then(|unlocked| unlocked.export_decrypted_epub(output))
    {
        Ok(()) => {
            log("decryption successful");
            0
        }
        Err(Error::License(LicenseError::KeyCheckFailed)) => {
            set_error("Incorrect passphrase".to_string());
            log("incorrect passphrase");
            1
        }
        Err(Error::Epub(EpubError::MissingRequiredFile(file))) if file == "license.lcpl" => {
            set_error("EPUB is not LCP encrypted".to_string());
            log("not LCP encrypted");
            2
        }
        Err(Error::License(LicenseError::UnsupportedEncryptionProfile(e))) => {
            set_error(e.clone());
            log(&e);
            2
        }
        Err(e) => {
            set_error(e.to_string());
            log(&format!("ERROR: {}", e));
            -1
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
