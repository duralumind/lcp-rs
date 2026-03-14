pub mod crypto;
pub mod epub;
pub mod license;

use license::EncryptionProfile;
use std::path::PathBuf;


pub fn encrypt_epub(
    input: PathBuf,
    _password: String,
    profile: EncryptionProfile,
    output: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let output_path = output.unwrap_or_else(|| {
        let stem = input.file_stem().unwrap_or_default().to_string_lossy();
        input.with_file_name(format!("{}.encrypted.epub", stem))
    });

    println!("Encrypting EPUB:");
    println!("  Input:    {}", input.display());
    println!("  Output:   {}", output_path.display());
    println!("  Profile:  {:?}", profile);

    todo!("Implement EPUB encryption")
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
