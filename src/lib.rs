pub mod crypto;
pub mod epub;
pub mod license;

use crate::{
    crypto::key::{ContentKey, EncryptedContentKey, UserPassphrase},
    epub::Epub,
};

/// This is the trait that needs to be implemented to support additional
/// production profiles. See docs for details.
pub use crypto::transform::Transform;

use license::EncryptionProfile;
use std::path::PathBuf;

pub fn encrypt_epub(
    input: PathBuf,
    password: String,
    profile: EncryptionProfile,
    output: Option<PathBuf>,
) -> Result<(), String> {
    let output_path = output.unwrap_or_else(|| {
        let stem = input.file_stem().unwrap_or_default().to_string_lossy();
        input.with_file_name(format!("{}.encrypted.epub", stem))
    });

    println!("Encrypting EPUB:");
    println!("  Input:    {}", input.display());
    println!("  Output:   {}", output_path.display());
    println!("  Profile:  {:?}", profile);

    // step 1: parse the epub file
    let mut epub = Epub::new(input)?;
    // step 2: generate aes key with user passphrase
    let passphrase = UserPassphrase(password);
    let content_key = ContentKey::generate();
    let _encrypted_content_key = EncryptedContentKey::new(content_key.clone(), passphrase, profile);
    // let manifest_items = epub.manifest_items()?;

    epub.write_encrypted_epub(output_path, &content_key)
        .unwrap();

    Ok(())
    // step 3: encrypt all required content
    // step 3: generate a new epub with the encrypted content, embed lcpl file
    // step 4: generate output epub
    // unimplemented!()
}

pub fn decrypt_epub(
    input: PathBuf,
    _password: String,
    profile: EncryptionProfile,
    output: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let output_path = output.unwrap_or_else(|| {
        let stem = input.file_stem().unwrap_or_default().to_string_lossy();
        input.with_file_name(format!("{}.decrypted.epub", stem))
    });

    println!("Decrypting EPUB:");
    println!("  Input:    {}", input.display());
    println!("  Output:   {}", output_path.display());
    println!("  Profile:  {:?}", profile);

    todo!("Implement EPUB decryption")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testing_encryption_full() {
        encrypt_epub(
            PathBuf::from("/Users/work/company/lcp_stuff/readium-rs/samples/way_of_kings.epub"),
            "test123".to_string(),
            EncryptionProfile::Basic,
            None,
        );
    }
}
