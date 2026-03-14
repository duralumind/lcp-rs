use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct UserPassphrase(pub String);

#[derive(Debug)]
pub enum HashAlgorithm {
    Sha256,
}

impl HashAlgorithm {
    pub fn hash_message(&self, data: impl AsRef<[u8]>) -> [u8; 32] {
        match self {
            Self::Sha256 => Sha256::digest(data).into(),
        }
    }
}

#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct UserEncryptionKey {
    key: [u8; 32],
}

impl UserEncryptionKey {
    pub fn new(passphrase: UserPassphrase, algorithm: HashAlgorithm) -> Self {
        Self {
            key: algorithm.hash_message(passphrase.0.as_bytes()),
        }
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
}
