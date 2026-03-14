use clap::ValueEnum;

/// Encryption profiles supported by LCP
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum EncryptionProfile {
    /// Basic LCP profile (http://readium.org/lcp/basic-profile)
    Basic,
}
