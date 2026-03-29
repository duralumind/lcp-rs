//! C FFI interface for LCP decryption library
//!
//! This module provides C-compatible functions for use from Lua/LuaJIT via FFI.

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;

use lcp_core::crypto::key::{UserEncryptionKey, UserPassphrase};
use lcp_core::epub::Epub;
use lcp_core::license::EncryptionProfile;

// Thread-local storage for the last error message
thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = RefCell::new(None);
}

fn set_error(msg: String) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = CString::new(msg).ok();
    });
}

fn clear_error() {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
}

/// Check if an EPUB file is LCP encrypted.
///
/// # Arguments
/// * `epub_path` - Path to the EPUB file (null-terminated C string)
///
/// # Returns
/// * `1` if the file is LCP encrypted
/// * `0` if the file is not LCP encrypted
/// * `-1` on error (call lcp_get_error for details)
#[unsafe(no_mangle)]
pub extern "C" fn lcp_is_encrypted(epub_path: *const c_char) -> i32 {
    clear_error();

    let path = match unsafe { CStr::from_ptr(epub_path) }.to_str() {
        Ok(s) => PathBuf::from(s),
        Err(e) => {
            set_error(format!("Invalid UTF-8 in path: {}", e));
            return -1;
        }
    };

    match Epub::new(path) {
        Ok(epub) => {
            if epub.license().is_some() {
                1
            } else {
                0
            }
        }
        Err(e) => {
            // If we can't open the file, it's not a valid encrypted EPUB
            set_error(format!("Failed to open EPUB: {}", e));
            -1
        }
    }
}

/// Decrypt an LCP-encrypted EPUB to a new file.
///
/// # Arguments
/// * `epub_path` - Path to the encrypted EPUB file (null-terminated C string)
/// * `output_path` - Path where the decrypted EPUB will be written (null-terminated C string)
/// * `passphrase` - The user's passphrase (null-terminated C string)
///
/// # Returns
/// * `0` on success
/// * `1` if the passphrase is incorrect
/// * `2` if the file is not LCP encrypted
/// * `-1` on other errors (call lcp_get_error for details)
#[unsafe(no_mangle)]
pub extern "C" fn lcp_decrypt_epub(
    epub_path: *const c_char,
    output_path: *const c_char,
    passphrase: *const c_char,
) -> i32 {
    clear_error();

    // Parse input paths
    let input_path = match unsafe { CStr::from_ptr(epub_path) }.to_str() {
        Ok(s) => PathBuf::from(s),
        Err(e) => {
            set_error(format!("Invalid UTF-8 in input path: {}", e));
            return -1;
        }
    };

    let output = match unsafe { CStr::from_ptr(output_path) }.to_str() {
        Ok(s) => PathBuf::from(s),
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
            return -1;
        }
    };

    // Check if it's LCP encrypted
    let license = match epub.license() {
        Some(l) => l,
        None => {
            set_error("EPUB is not LCP encrypted".to_string());
            return 2;
        }
    };

    // Verify passphrase and get user key
    let user_encryption_key = UserEncryptionKey::new(
        UserPassphrase(pass.to_string()),
        lcp_core::crypto::key::HashAlgorithm::Sha256,
        EncryptionProfile::Basic,
    );
    if let Err(_) = license.key_check(&user_encryption_key) {
        set_error("Incorrect passphrase".to_string());
        return 1;
    };

    // Decrypt the content key
    let content_key = match license.decrypt_content_key(&user_encryption_key) {
        Ok(k) => k,
        Err(e) => {
            set_error(format!("Failed to decrypt content key: {}", e));
            return -1;
        }
    };

    match epub.create_decrypted_epub(output, &content_key) {
        Ok(writer) => {
            if let Err(e) = writer.finish() {
                set_error(format!("Failed to finalize EPUB: {}", e));
                return -1;
            }
            return 0;
        }
        Err(e) => {
            set_error(e.to_string());
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
    LAST_ERROR.with(|e| match e.borrow().as_ref() {
        Some(cstr) => cstr.as_ptr(),
        None => std::ptr::null(),
    })
}
