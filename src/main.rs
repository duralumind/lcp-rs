use clap::{Parser, Subcommand};
use readium_rs::{decrypt_epub, encrypt_epub, license::EncryptionProfile};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "readium-rs")]
#[command(about = "LCP DRM encryption/decryption for EPUB files")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Encrypt an EPUB file using LCP DRM
    Encrypt {
        /// Path to the input EPUB file
        input: PathBuf,

        /// User password for encryption
        #[arg(long)]
        password: String,

        /// Encryption profile to use
        #[arg(long)]
        profile: EncryptionProfile,

        /// Output path (optional, defaults to <input>.encrypted.epub)
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Decrypt an LCP-protected EPUB file
    Decrypt {
        /// Path to the encrypted EPUB (with embedded .lcpl)
        input: PathBuf,

        /// User password for decryption
        #[arg(long)]
        password: String,

        /// Encryption profile used
        #[arg(long)]
        profile: EncryptionProfile,

        /// Output path (optional, defaults to <input>.decrypted.epub)
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            input,
            password,
            profile,
            output,
        } => encrypt_epub(input, password, profile, output),
        Commands::Decrypt {
            input,
            password,
            profile,
            output,
        } => decrypt_epub(input, password, profile, output),
    }
}
