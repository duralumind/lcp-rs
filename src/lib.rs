pub mod crypto;
pub mod epub;
pub mod license;

use crate::{
    crypto::{
        key::{ContentKey, EncryptedContentKey, UserEncryptionKey, UserPassphrase},
        signature::{load_certificate_from_der, load_private_key_from_der},
    },
    epub::Epub,
    license::LicenseBuilder,
};

/// This is the trait that needs to be implemented to support additional
/// production profiles. See docs for details.
pub use crypto::transform::Transform;

use license::EncryptionProfile;
use std::path::PathBuf;

const PROVIDER_CERT_DER: &[u8] = include_bytes!("../certs/provider.der");
const PROVIDER_PRIVATE_KEY_DER: &[u8] = include_bytes!("../certs/provider_private.der");

pub fn encrypt_epub(
    input: PathBuf,
    password: String,
    password_hint: String,
    profile: EncryptionProfile,
    output: Option<PathBuf>,
) -> Result<(), String> {
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
    let encrypted_epub = epub
        .create_encrypted_epub(output_path, &content_key)
        .unwrap();
    // step 4: generate lcpl file, embed in encrypted epub
    let private_key =
        load_private_key_from_der(PROVIDER_PRIVATE_KEY_DER).expect("Failed to load private key");
    let provider_certificate =
        load_certificate_from_der(PROVIDER_CERT_DER).expect("Failed to load provider certificate");
    let license = LicenseBuilder::new()
        .encryption(&encrypted_content_key, &user_key, password_hint)
        .sign(&private_key, &provider_certificate)
        .map_err(|e| format!("Failed to sign license {}", e))?
        .build()
        .map_err(|e| format!("Failed to build license {}", e))?;

    Epub::embed_license_and_write(encrypted_epub, &license)?;

    Ok(())
}

pub fn decrypt_epub(
    input: PathBuf,
    password: String,
    profile: EncryptionProfile,
    output: Option<PathBuf>,
) -> Result<(), String> {
    let output_path = output.unwrap_or_else(|| {
        let stem = input.file_stem().unwrap_or_default().to_string_lossy();
        input.with_file_name(format!("{}.decrypted.epub", stem))
    });

    println!("Decrypting EPUB:");
    println!("  Input:    {}", input.display());
    println!("  Output:   {}", output_path.display());
    println!("  Profile:  {:?}", profile);

    // step 1: parse the epub file and get the license
    let mut epub = Epub::new(input)?;
    let license = epub
        .license()
        .ok_or("Encrypted epub must contain license file".to_string())?;
    // step 2: do the key check and decrypt the content key
    let passphrase = UserPassphrase(password);
    let user_encryption_key =
        UserEncryptionKey::new(passphrase, crypto::key::HashAlgorithm::Sha256, profile);
    license.key_check(&user_encryption_key)?;
    let content_key = license.decrypt_content_key(&user_encryption_key)?;
    // step 3: create and write decrypted epub
    let decrypted_epub = epub.create_decrypted_epub(output_path, &content_key)?;
    decrypted_epub
        .finish()
        .map_err(|e| format!("Failed to write decrypted epub: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testing_encryption_full() {
        let _ = encrypt_epub(
            PathBuf::from("samples/way_of_kings.epub"),
            "test123".to_string(),
            "password is test123".to_string(),
            EncryptionProfile::Basic,
            Some(PathBuf::from("samples/way_of_kings_encrypted.epub")),
        )
        .unwrap();
        let _ = decrypt_epub(
            PathBuf::from("samples/way_of_kings_encrypted.epub"),
            "test123".to_string(),
            EncryptionProfile::Basic,
            Some(PathBuf::from("samples/way_of_kings_decrypted.epub")),
        )
        .unwrap();
    }
}
