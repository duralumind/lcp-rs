use clap::{Parser, Subcommand};
use lcp_core::{decrypt_epub, encrypt_epub, license::EncryptionProfile};
use std::path::PathBuf;

const ROOT_CA_DER: &[u8] = include_bytes!("../../../certs/root_ca.der");
const PROVIDER_CERT_DER: &[u8] = include_bytes!("../../../certs/provider.der");
const PROVIDER_PRIVATE_KEY_DER: &[u8] = include_bytes!("../../../certs/provider_private.der");

#[derive(Parser, Debug)]
#[command(name = "lcp-cli")]
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

        /// User password hint
        #[arg(long)]
        password_hint: String,

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
        #[arg(long, conflicts_with = "lcpl")]
        input: Option<PathBuf>,

        /// Path to the lcpl file which contains the link to the publication
        #[arg(long, conflicts_with = "input")]
        lcpl: Option<PathBuf>,

        /// User password for decryption
        #[arg(long)]
        password: String,

        /// Output path (optional, defaults to <input>.decrypted.epub)
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            input,
            password,
            password_hint,
            profile,
            output,
        } => encrypt_epub(
            input,
            password,
            password_hint,
            profile,
            output,
            PROVIDER_CERT_DER,
            PROVIDER_PRIVATE_KEY_DER,
        )
        .unwrap(),
        Commands::Decrypt {
            input,
            lcpl,
            password,
            output,
        } => {
            let (epub_path, external_license) = match (input, lcpl) {
                (Some(path), None) => (path, None),
                (None, Some(lcpl_path)) => {
                    // Read and parse the LCPL file
                    let lcpl_contents =
                        std::fs::read_to_string(&lcpl_path).expect("Failed to read LCPL file");
                    let license: lcp_core::license::License =
                        serde_json::from_str(&lcpl_contents).expect("Failed to parse LCPL");

                    // Get the publication download URL
                    let publication_url = license
                        .publication_link()
                        .expect("LCPL missing publication link");

                    // Download the encrypted EPUB
                    let temp_dir = std::env::temp_dir();
                    let epub_filename = lcpl_path
                        .file_stem()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string()
                        + ".epub";
                    let epub_path = temp_dir.join(&epub_filename);

                    println!("  Downloading publication from: {}", publication_url);
                    let response =
                        reqwest::blocking::get(&publication_url).expect("HTTP request failed");
                    let bytes = response.bytes().expect("Failed to read response body");
                    std::fs::write(&epub_path, &bytes).expect("Failed to write downloaded EPUB");
                    println!("  Downloaded to: {}", epub_path.display());

                    (epub_path, Some(license))
                }
                (None, None) => {
                    eprintln!("Error: Either --input or --lcpl must be provided");
                    std::process::exit(1);
                }
                (Some(_), Some(_)) => unreachable!("clap conflicts_with prevents this"),
            };
            decrypt_epub(epub_path, external_license, password, output, ROOT_CA_DER).unwrap()
        }
    }
}
