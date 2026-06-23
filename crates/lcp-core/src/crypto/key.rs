use super::cipher;
use base64::{Engine as _, engine::general_purpose};
use rand_core::{OsRng, RngCore};
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::Transform;

/// Errors that can occur during key operations.
#[derive(Debug, Error)]
pub enum KeyError {
    /// Base64 decoding failed
    #[error("Base64 decode failed: {0}")]
    Base64DecodeFailed(String),
    /// Invalid IV length in the encrypted content key blob.
    #[error("Invalid IV length: got {actual} bytes, expected 16")]
    InvalidIvLength { actual: usize },
    /// Invalid encrypted content-key ciphertext length.
    #[error("Invalid encrypted content-key length: got {actual} bytes, expected 48")]
    InvalidEncryptedKeyLength { actual: usize },
    /// Invalid decrypted content-key length.
    #[error("Invalid content key length: got {actual} bytes, expected 32")]
    InvalidContentKeyLength { actual: usize },
    /// Decryption of key material failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
}

const IV_LEN: usize = 16;
const ENCRYPTED_CONTENT_KEY_LEN: usize = 48;
const CONTENT_KEY_LEN: usize = 32;

/// The password chosen by the user to encrypt/decrypt the publication.
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct UserPassphrase(pub String);

/// The hash algorithm for hashing the passphrase to a user key before [`Transform`].
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

/// The user's encryption key. This represents the key after applying the
/// secret [`Transform`].
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct UserEncryptionKey {
    key: [u8; 32],
}

impl UserEncryptionKey {
    pub fn new(
        passphrase: UserPassphrase,
        algorithm: HashAlgorithm,
        transform: impl Transform,
    ) -> Self {
        Self {
            key: transform.transform(algorithm.hash_message(passphrase.0.as_bytes())),
        }
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

/// The content key that is used as a key for the encryption algorithm for actually
/// encrypting the contents of the publication.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct ContentKey([u8; 32]);

impl ContentKey {
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.0
    }

    /// Decrypt the original content key using the user passphrase and the key transform.
    pub fn decrypt_content_key(
        encrypted_key: &EncryptedContentKey,
        user_key: &UserEncryptionKey,
    ) -> Result<Self, KeyError> {
        let decrypted = cipher::aes_cbc256::decrypt_aes_256_cbc(
            encrypted_key.key(),
            user_key.key(),
            encrypted_key.iv(),
        )
        .map_err(|e| KeyError::DecryptionFailed(e.to_string()))?;
        Self::from_decrypted_bytes(&decrypted)
    }

    fn from_decrypted_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != CONTENT_KEY_LEN {
            return Err(KeyError::InvalidContentKeyLength {
                actual: bytes.len(),
            });
        }

        let mut content_key = [0; CONTENT_KEY_LEN];
        content_key.copy_from_slice(bytes);
        Ok(ContentKey(content_key))
    }
}

/// Represents a [`ContentKey`] that has been encrypted using the [`UserEncryptionKey`].
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct EncryptedContentKey {
    /// The key size here is 48 bytes because of additional padding with the PKCS7 padding scheme
    /// for aes cbc.
    key: [u8; 48],
    /// The associated initialization vector for the aes encryption.
    iv: [u8; 16],
}

impl EncryptedContentKey {
    /// Create an [`EncryptedContentKey`] by decoding raw bytes.
    pub fn new_from_raw_bytes(base64_encrypted_key: &str) -> Result<Self, KeyError> {
        let encrypted_key_bytes = general_purpose::STANDARD
            .decode(base64_encrypted_key)
            .map_err(|e| KeyError::Base64DecodeFailed(format!("{:?}", e)))?;

        Self::new_from_bytes(&encrypted_key_bytes)
    }

    fn new_from_bytes(encrypted_key_bytes: &[u8]) -> Result<Self, KeyError> {
        if encrypted_key_bytes.len() < IV_LEN {
            return Err(KeyError::InvalidIvLength {
                actual: encrypted_key_bytes.len(),
            });
        }

        let (iv_slice, key_slice) = encrypted_key_bytes.split_at(IV_LEN);
        if key_slice.len() != ENCRYPTED_CONTENT_KEY_LEN {
            return Err(KeyError::InvalidEncryptedKeyLength {
                actual: key_slice.len(),
            });
        }

        let mut iv = [0; IV_LEN];
        iv.copy_from_slice(iv_slice);
        let mut key = [0; ENCRYPTED_CONTENT_KEY_LEN];
        key.copy_from_slice(key_slice);

        Ok(Self { key, iv })
    }
    /// Create an [`EncryptedContentKey`] by encrypting the [`ContentKey`] with a
    /// [`UserPassphrase`].
    ///
    /// The encryption algorithm used is aes cbc with pkc7 padding.
    /// The resulting `EncryptedContentKey` length is 48 bytes (16 bytes additional padding)
    /// and the iv length is 16 bytes.
    pub fn new(
        content_key: &ContentKey,
        passphrase: UserPassphrase,
        transform: impl Transform,
    ) -> Self {
        let user_key = UserEncryptionKey::new(passphrase, HashAlgorithm::Sha256, transform);
        // Generate a random iv
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);
        let mut key = [0u8; 48];
        // Vec gets dropped right after the scope ends
        {
            let encrypted =
                cipher::aes_cbc256::encrypt_aes_256_cbc(content_key.key(), &user_key.key, &iv);

            key.copy_from_slice(&encrypted);
        }
        Self { key, iv }
    }

    pub fn key(&self) -> &[u8; 48] {
        &self.key
    }

    pub fn iv(&self) -> &[u8; 16] {
        &self.iv
    }

    /// Decrypt the original content key using the user passphrase and the key transform.
    pub fn decrypt_content_key(
        &self,
        passphrase: UserPassphrase,
        transform: impl Transform,
    ) -> Result<ContentKey, KeyError> {
        let user_key = UserEncryptionKey::new(passphrase, HashAlgorithm::Sha256, transform);
        let decrypted =
            cipher::aes_cbc256::decrypt_aes_256_cbc(&self.key, user_key.key(), &self.iv)
                .map_err(|e| KeyError::DecryptionFailed(e.to_string()))?;
        ContentKey::from_decrypted_bytes(&decrypted)
    }

    /// Encodes the encrypted content key in base64 format (IV || ciphertext)
    pub fn to_base64(&self) -> String {
        // Concatenate IV + encrypted key (LCP format)
        let mut data = Vec::with_capacity(16 + self.key.len());
        data.extend_from_slice(&self.iv);
        data.extend_from_slice(&self.key);

        general_purpose::STANDARD.encode(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cipher::aes_cbc256;

    const TEST_IV: [u8; IV_LEN] = [7; IV_LEN];
    const TEST_USER_KEY: [u8; 32] = [3; 32];

    #[test]
    fn roundtrip_no_transform() {
        struct IdentityTransform;

        impl Transform for IdentityTransform {
            fn transform(&self, user_key: [u8; 32]) -> [u8; 32] {
                user_key
            }
        }
        let content_key = ContentKey::generate();

        let encrypted_content_key = EncryptedContentKey::new(
            &content_key,
            UserPassphrase("password123".to_string()),
            IdentityTransform,
        );

        let decrypted_content_key = encrypted_content_key
            .decrypt_content_key(UserPassphrase("password123".to_string()), IdentityTransform)
            .unwrap();
        assert_eq!(decrypted_content_key.key(), content_key.key());
    }

    #[test]
    fn roundtrip_with_transform() {
        // hash the hash
        struct ShaTransform;

        impl Transform for ShaTransform {
            fn transform(&self, user_key: [u8; 32]) -> [u8; 32] {
                Sha256::digest(user_key).into()
            }
        }
        let content_key = ContentKey::generate();

        let encrypted_content_key = EncryptedContentKey::new(
            &content_key,
            UserPassphrase("password123".to_string()),
            ShaTransform,
        );

        let decrypted_content_key = encrypted_content_key
            .decrypt_content_key(UserPassphrase("password123".to_string()), ShaTransform)
            .unwrap();
        assert_eq!(decrypted_content_key.key(), content_key.key());
    }

    #[test]
    fn encrypted_content_key_rejects_short_iv_blob() {
        let result = EncryptedContentKey::new_from_bytes(&[1; 8]);
        assert!(matches!(
            result,
            Err(KeyError::InvalidIvLength { actual: 8 })
        ));
    }

    #[test]
    fn encrypted_content_key_rejects_wrong_ciphertext_length() {
        let mut bytes = vec![0; IV_LEN];
        bytes.extend_from_slice(&[1; ENCRYPTED_CONTENT_KEY_LEN - 1]);

        assert!(matches!(
            EncryptedContentKey::new_from_bytes(&bytes),
            Err(KeyError::InvalidEncryptedKeyLength { actual: 47 })
        ));
    }

    #[test]
    fn encrypted_content_key_rejects_bad_base64() {
        let result = EncryptedContentKey::new_from_raw_bytes("%%%");
        assert!(matches!(result, Err(KeyError::Base64DecodeFailed(_))));
    }

    #[test]
    fn decrypt_content_key_rejects_wrong_plaintext_length() {
        let wrong_length_plaintext = [9; 33];
        let encrypted =
            aes_cbc256::encrypt_aes_256_cbc(&wrong_length_plaintext, &TEST_USER_KEY, &TEST_IV);
        let key: [u8; ENCRYPTED_CONTENT_KEY_LEN] = encrypted.try_into().unwrap();
        let encrypted_content_key = EncryptedContentKey { key, iv: TEST_IV };
        let user_key = UserEncryptionKey { key: TEST_USER_KEY };

        assert!(matches!(
            ContentKey::decrypt_content_key(&encrypted_content_key, &user_key),
            Err(KeyError::InvalidContentKeyLength { actual: 33 })
        ));
    }
}
