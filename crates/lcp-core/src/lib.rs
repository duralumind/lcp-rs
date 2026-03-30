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
use std::path::PathBuf;

/// Unified error type for the lcp-core library.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Epub(#[from] EpubError),
    #[error(transparent)]
    License(#[from] LicenseError),
    #[error(transparent)]
    Signature(#[from] SignatureError),
    #[error(transparent)]
    Cipher(#[from] CipherError),
    #[error(transparent)]
    Key(#[from] KeyError),
}

/// Encrypt an EPUB file with LCP DRM.
///
/// Accepts provider certificate and private key as parameters so that callers
/// (CLI, server) can supply their own credentials.
pub fn encrypt_epub(
    input: PathBuf,
    password: String,
    password_hint: String,
    profile: EncryptionProfile,
    output: Option<PathBuf>,
    provider_cert_der: &[u8],
    provider_private_key_der: &[u8],
) -> Result<(), Error> {
    let output_path = output.unwrap_or_else(|| {
        let stem = input.file_stem().unwrap_or_default().to_string_lossy();
        input.with_file_name(format!("{}.encrypted.epub", stem))
    });

    println!("Encrypting EPUB:");
    println!("  Input:    {:?}", input.canonicalize());
    println!("  Output:   {}", output_path.display());
    println!("  Profile:  {:?}", profile);

    let mut epub = Epub::new(input)?;
    let passphrase = UserPassphrase(password);
    let user_key = UserEncryptionKey::new(
        passphrase.clone(),
        crypto::key::HashAlgorithm::Sha256,
        profile,
    );
    let content_key = ContentKey::generate();
    let encrypted_content_key = EncryptedContentKey::new(content_key.clone(), passphrase, profile);
    let encrypted_epub = epub.create_encrypted_epub(output_path, &content_key)?;

    let private_key =
        load_private_key_from_der(provider_private_key_der).map_err(Error::Signature)?;
    let provider_certificate =
        load_certificate_from_der(provider_cert_der).map_err(Error::Signature)?;
    let license = LicenseBuilder::new()
        .encryption(&encrypted_content_key, &user_key, password_hint)
        .sign(&private_key, &provider_certificate)?
        .build()?;

    Epub::embed_license_and_write(encrypted_epub, &license)?;

    Ok(())
}

/// Encrypt an EPUB from raw bytes in memory. Returns the encrypted epub bytes.
///
/// Used by the server for server-side encryption on upload.
pub fn encrypt_epub_from_bytes(
    epub_bytes: &[u8],
    content_key: &ContentKey,
) -> Result<(Vec<u8>, Vec<epub::xml_utils::EncryptedFileInfo>), Error> {
    use std::io::{Cursor, Write};
    use zip::ZipArchive;
    use zip::write::{SimpleFileOptions, ZipWriter};

    // Read source epub from bytes
    let reader = Cursor::new(epub_bytes);
    let mut archive =
        ZipArchive::new(reader).map_err(|e| EpubError::ArchiveReadFailed(format!("{}", e)))?;

    // Read container.xml
    let container = {
        let mut zipfile = archive
            .by_path(epub::CONTAINER_FILE)
            .map_err(|_| EpubError::MissingRequiredFile(epub::CONTAINER_FILE.to_string()))?;
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut zipfile, &mut buf)
            .map_err(|e| EpubError::ArchiveReadFailed(format!("{}", e)))?;
        buf
    };

    let opf_path =
        epub::xml_utils::parse_container_xml(&container).map_err(EpubError::XmlParseFailed)?;
    let base_path = epub::xml_utils::get_opf_base_path(&opf_path);

    // Read OPF manifest
    let manifest_items = {
        let mut opf_file = archive
            .by_path(&opf_path)
            .map_err(|_| EpubError::MissingRequiredFile(opf_path.clone()))?;
        let mut opf_content = String::new();
        std::io::Read::read_to_string(&mut opf_file, &mut opf_content)
            .map_err(|e| EpubError::ArchiveReadFailed(format!("{}", e)))?;
        epub::xml_utils::parse_opf_manifest(&opf_content).map_err(EpubError::XmlParseFailed)?
    };

    let items_to_encrypt: Vec<_> = manifest_items
        .iter()
        .filter(|m| !m.is_encryption_exempt())
        .collect();

    let files_to_encrypt: std::collections::HashSet<String> = items_to_encrypt
        .iter()
        .map(|m| format!("{}{}", base_path, m.href))
        .collect();

    // Create output zip in memory
    let output_buf = Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(output_buf);

    // Copy mimetype first
    if let Ok(mimetype_file) = archive.by_name("mimetype") {
        writer
            .raw_copy_file(mimetype_file)
            .map_err(|e| EpubError::WriteFailed(format!("Failed to copy mimetype: {}", e)))?;
    }

    // Copy non-encrypted files
    for i in 0..archive.len() {
        let file = archive
            .by_index(i)
            .map_err(|e| EpubError::ArchiveReadFailed(format!("{}", e)))?;
        let name = file.name().to_string();
        if name == "mimetype" || name == epub::ENCRYPTION_FILE || name == epub::LICENSE_FILE {
            continue;
        }
        if files_to_encrypt.contains(&name) {
            continue;
        }
        writer
            .raw_copy_file(file)
            .map_err(|e| EpubError::WriteFailed(format!("Failed to copy {}: {}", name, e)))?;
    }

    // Encrypt files
    let mut encrypted_files = Vec::new();
    for manifest in &items_to_encrypt {
        let path = format!("{}{}", base_path, manifest.href);
        let data = {
            let mut zipfile = archive
                .by_path(&path)
                .map_err(|_| EpubError::InvalidManifest(format!("{:?}", &manifest)))?;
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut zipfile, &mut buf)
                .map_err(|e| EpubError::ArchiveReadFailed(format!("{}", e)))?;
            buf
        };
        let len = data.len();
        let compressed_data = if manifest.is_codec() {
            data
        } else {
            epub::deflate_compress(&data)
                .map_err(|e| EpubError::CompressionFailed(format!("{:?}", e)))?
        };
        let encrypted_data = crypto::cipher::aes_cbc256::encrypt_aes_256_cbc_with_random_iv(
            &compressed_data,
            content_key.key(),
        );
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        writer
            .start_file(&path, options)
            .map_err(|e| EpubError::WriteFailed(format!("{}", e)))?;
        writer
            .write_all(&encrypted_data)
            .map_err(|e| EpubError::WriteFailed(format!("{}", e)))?;

        encrypted_files.push(epub::xml_utils::EncryptedFileInfo {
            uri: path,
            is_compressed: !manifest.is_codec(),
            original_length: len,
        });
    }

    // Write encryption.xml
    let encryption_xml = epub::xml_utils::write_encryption_xml(&encrypted_files);
    writer
        .start_file(epub::ENCRYPTION_FILE, SimpleFileOptions::default())
        .map_err(|e| EpubError::WriteFailed(format!("{}", e)))?;
    writer
        .write_all(encryption_xml.as_bytes())
        .map_err(|e| EpubError::WriteFailed(format!("{}", e)))?;

    let result = writer
        .finish()
        .map_err(|e| EpubError::WriteFailed(format!("{}", e)))?;

    Ok((result.into_inner(), encrypted_files))
}

/// Decrypt an EPUB file with LCP DRM.
///
/// Takes the path to the encrypted epub, an optional externally-provided license,
/// and the root CA certificate for signature verification.
pub fn decrypt_epub(
    epub_path: PathBuf,
    external_license: Option<License>,
    password: String,
    profile: EncryptionProfile,
    output: Option<PathBuf>,
    root_ca_der: &[u8],
) -> Result<(), Error> {
    let output_path = output.unwrap_or_else(|| {
        let stem = epub_path.file_stem().unwrap_or_default().to_string_lossy();
        epub_path.with_file_name(format!("{}.decrypted.epub", stem))
    });

    println!("Decrypting EPUB:");
    println!("  Input:    {}", epub_path.display());
    println!("  Output:   {}", output_path.display());
    println!("  Profile:  {:?}", profile);

    let mut epub = Epub::new(epub_path)?;
    let license = match external_license.as_ref() {
        Some(l) => l,
        None => epub
            .license()
            .ok_or(EpubError::MissingRequiredFile("license.lcpl".to_string()))?,
    };
    let passphrase = UserPassphrase(password);
    let root_cert =
        load_certificate_from_der(root_ca_der).expect("Failed to load root certificate");
    let user_encryption_key =
        UserEncryptionKey::new(passphrase, crypto::key::HashAlgorithm::Sha256, profile);
    license.key_check(&user_encryption_key)?;
    license.verify_signature_and_provider(&root_cert)?;
    let content_key = license.decrypt_content_key(&user_encryption_key)?;
    let decrypted_epub = epub.create_decrypted_epub(output_path, &content_key)?;
    decrypted_epub
        .finish()
        .map_err(|e| EpubError::WriteFailed(format!("Failed to write decrypted epub: {}", e)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_CA_DER: &[u8] = include_bytes!("../../../certs/root_ca.der");
    const PROVIDER_CERT_DER: &[u8] = include_bytes!("../../../certs/provider.der");
    const PROVIDER_PRIVATE_KEY_DER: &[u8] = include_bytes!("../../../certs/provider_private.der");

    #[test]
    fn test_full_roundtrip() {
        encrypt_epub(
            PathBuf::from("../../samples/moby-dick.epub"),
            "test123".to_string(),
            "password is test123".to_string(),
            EncryptionProfile::Basic,
            Some(PathBuf::from("/tmp/moby-dick-encrypted.epub")),
            PROVIDER_CERT_DER,
            PROVIDER_PRIVATE_KEY_DER,
        )
        .unwrap();
        decrypt_epub(
            PathBuf::from("/tmp/moby-dick-encrypted.epub"),
            None,
            "test123".to_string(),
            EncryptionProfile::Basic,
            Some(PathBuf::from("/tmp/moby-dick-decrypted.epub")),
            ROOT_CA_DER,
        )
        .unwrap();
    }
}
