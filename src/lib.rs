pub mod crypto;
pub mod epub;
pub mod license;

use crate::{
    crypto::{
        key::{ContentKey, EncryptedContentKey, UserEncryptionKey, UserPassphrase},
        signature::{load_certificate_from_der, load_private_key_from_der},
    },
    epub::Epub,
    license::{License, LicenseBuilder},
};
use thiserror::Error;

/// This is the trait that needs to be implemented to support additional
/// production profiles. See docs for details.
pub use crypto::transform::Transform;

// Re-export module-specific error types
pub use crypto::cipher::CipherError;
pub use crypto::key::KeyError;
pub use crypto::signature::SignatureError;
pub use epub::EpubError;
pub use license::LicenseError;

use license::EncryptionProfile;
use std::path::{Path, PathBuf};

const ROOT_CA_DER: &[u8] = include_bytes!("../certs/root_ca.der");

/// Input source for decryption - either an encrypted EPUB with embedded license,
/// or a standalone LCPL license file that references the publication URL.
pub enum DecryptionInput {
    /// Decrypt from an epub file that contains the license file
    /// embedded in the metadata.
    EmbeddedEpub(PathBuf),
    /// Decrypt from a plain lcpl license file which contains the link to the publication.
    Lcpl(PathBuf),
}

impl DecryptionInput {
    pub fn path(&self) -> &Path {
        match self {
            Self::EmbeddedEpub(p) => p,
            Self::Lcpl(p) => p,
        }
    }
}

/// Unified error type for the readium-rs library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error from EPUB operations
    #[error(transparent)]
    Epub(#[from] EpubError),
    /// Error from license operations
    #[error(transparent)]
    License(#[from] LicenseError),
    /// Error from signature operations
    #[error(transparent)]
    Signature(#[from] SignatureError),
    /// Error from cipher operations
    #[error(transparent)]
    Cipher(#[from] CipherError),
    /// Error from key operations
    #[error(transparent)]
    Key(#[from] KeyError),
}

const PROVIDER_CERT_DER: &[u8] = include_bytes!("../certs/provider.der");
const PROVIDER_PRIVATE_KEY_DER: &[u8] = include_bytes!("../certs/provider_private.der");

pub fn encrypt_epub(
    input: PathBuf,
    password: String,
    password_hint: String,
    profile: EncryptionProfile,
    output: Option<PathBuf>,
) -> Result<(), Error> {
    let output_path = output.unwrap_or_else(|| {
        let stem = input.file_stem().unwrap_or_default().to_string_lossy();
        input.with_file_name(format!("{}.encrypted.epub", stem))
    });

    println!("Encrypting EPUB:");
    println!("  Input:    {:?}", input.canonicalize());
    println!("  Output:   {}", output_path.display());
    println!("  Profile:  {:?}", profile);

    // step 1: parse the epub file
    let mut epub = Epub::new(input)?;
    // step 2: generate aes key with user passphrase
    let passphrase = UserPassphrase(password);
    let user_key = UserEncryptionKey::new(
        passphrase.clone(),
        crypto::key::HashAlgorithm::Sha256,
        profile,
    );
    let content_key = ContentKey::generate();
    let encrypted_content_key = EncryptedContentKey::new(content_key.clone(), passphrase, profile);
    // step 3: encrypt all required content and return a new epub
    let encrypted_epub = epub.create_encrypted_epub(output_path, &content_key)?;
    // step 4: generate lcpl file, embed in encrypted epub
    let private_key =
        load_private_key_from_der(PROVIDER_PRIVATE_KEY_DER).map_err(Error::Signature)?;
    let provider_certificate =
        load_certificate_from_der(PROVIDER_CERT_DER).map_err(Error::Signature)?;
    let license = LicenseBuilder::new()
        .encryption(&encrypted_content_key, &user_key, password_hint)
        .sign(&private_key, &provider_certificate)?
        .build()?;

    Epub::embed_license_and_write(encrypted_epub, &license)?;

    Ok(())
}

pub fn decrypt_epub(
    input: DecryptionInput,
    password: String,
    profile: EncryptionProfile,
    output: Option<PathBuf>,
) -> Result<(), Error> {
    let output_path = output.unwrap_or_else(|| {
        let stem = input
            .path()
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy();
        input
            .path()
            .with_file_name(format!("{}.decrypted.epub", stem))
    });

    println!("Decrypting EPUB:");
    println!("  Input:    {}", input.path().display());
    println!("  Output:   {}", output_path.display());
    println!("  Profile:  {:?}", profile);

    // step 1: parse the epub file and get the license
    let (epub_path, license_opt) = match input {
        DecryptionInput::EmbeddedEpub(path) => (path, None),
        DecryptionInput::Lcpl(path) => {
            // 1. Read and parse the LCPL file
            let lcpl_contents = std::fs::read_to_string(&path).map_err(|e| {
                EpubError::MissingRequiredFile(format!("Failed to read LCPL file: {}", e))
            })?;
            let license: License = serde_json::from_str(&lcpl_contents).map_err(|e| {
                LicenseError::SerializationFailed(format!("Failed to parse LCPL: {}", e))
            })?;

            // 2. Get the publication download URL
            let publication_url = license.publication_link().ok_or_else(|| {
                LicenseError::SerializationFailed("LCPL missing publication link".to_string())
            })?;

            // 3. Download the encrypted EPUB to temp directory
            let temp_dir = std::env::temp_dir();
            let epub_filename = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
                + ".epub";
            let epub_path = temp_dir.join(&epub_filename);

            println!("  Downloading publication from: {}", publication_url);
            let response = reqwest::blocking::get(&publication_url)
                .map_err(|e| EpubError::DownloadFailed(format!("HTTP request failed: {}", e)))?;
            let bytes = response.bytes().map_err(|e| {
                EpubError::DownloadFailed(format!("Failed to read response body: {}", e))
            })?;
            std::fs::write(&epub_path, &bytes).map_err(|e| {
                EpubError::WriteFailed(format!("Failed to write downloaded EPUB: {}", e))
            })?;
            println!("  Downloaded to: {}", epub_path.display());

            (epub_path, Some(license))
        }
    };
    let mut epub = Epub::new(epub_path)?;
    let license = match license_opt.as_ref() {
        Some(l) => l,
        None => epub
            .license()
            .ok_or(EpubError::MissingRequiredFile("license.lcpl".to_string()))?,
    };
    // step 2: do the key check and decrypt the content key
    let passphrase = UserPassphrase(password);
    let root_cert =
        load_certificate_from_der(ROOT_CA_DER).expect("Failed to load root certificate");
    let user_encryption_key =
        UserEncryptionKey::new(passphrase, crypto::key::HashAlgorithm::Sha256, profile);
    license.key_check(&user_encryption_key)?;
    license.verify_signature_and_provider(&root_cert)?;
    let content_key = license.decrypt_content_key(&user_encryption_key)?;
    // step 3: create and write decrypted epub
    let decrypted_epub = epub.create_decrypted_epub(output_path, &content_key)?;
    decrypted_epub
        .finish()
        .map_err(|e| EpubError::WriteFailed(format!("Failed to write decrypted epub: {}", e)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_roundtrip() {
        let _ = encrypt_epub(
            PathBuf::from("samples/moby-dick.epub"),
            "test123".to_string(),
            "password is test123".to_string(),
            EncryptionProfile::Basic,
            Some(PathBuf::from("/tmp/moby-dick-encrypted.epub")),
        )
        .unwrap();
        let _ = decrypt_epub(
            DecryptionInput::EmbeddedEpub(PathBuf::from("/tmp/moby-dick-encrypted.epub")),
            "test123".to_string(),
            EncryptionProfile::Basic,
            Some(PathBuf::from("/tmp/moby-dick-decrypted.epub")),
        )
        .unwrap();
    }
}
