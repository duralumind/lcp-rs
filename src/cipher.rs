pub mod aes_cbc256 {
    use aes::{
        Aes256,
        cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit},
    };
    use block_padding::Pkcs7;
    use cbc::{Decryptor, Encryptor};

    type Aes256CbcEnc = Encryptor<Aes256>;
    type Aes256CbcDec = Decryptor<Aes256>;

    pub fn encrypt_aes_256_cbc(
        plaintext: &[u8],
        key: &[u8; 32],
        iv: &[u8; 16],
    ) -> Result<Vec<u8>, String> {
        let encryptor = Aes256CbcEnc::new(key.into(), iv.into());
        Ok(encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
    }

    pub fn decrypt_aes_256_cbc(
        ciphertext: &[u8],
        key: &[u8; 32],
        iv: &[u8; 16],
    ) -> Result<Vec<u8>, String> {
        let decryptor = Aes256CbcDec::new(key.into(), iv.into());

        let mut buf = ciphertext.to_vec();
        let decrypted_data = decryptor
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|e| format!("Decryption failed: {:?}", e))?;

        Ok(decrypted_data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::aes_cbc256::{decrypt_aes_256_cbc, encrypt_aes_256_cbc};

    const KEY: &[u8; 32] = &[42; 32];
    const IV: &[u8; 16] = &[41; 16];
    const PLAINTEXT: &[u8] = b"quickwhitefoxjumpsoverthelazydog";

    #[test]
    fn test_roundtrip() {
        let ciphertext = encrypt_aes_256_cbc(PLAINTEXT, KEY, IV).unwrap();
        let decrypted = decrypt_aes_256_cbc(&ciphertext, KEY, IV).unwrap();
        assert_eq!(decrypted, PLAINTEXT);
    }

    #[test]
    fn test_incorrect_key() {
        let ciphertext = encrypt_aes_256_cbc(PLAINTEXT, KEY, IV).unwrap();

        let wrong_key: &[u8; 32] = &[40; 32];
        // Decryption with the wrong key errors with bad padding
        assert!(decrypt_aes_256_cbc(&ciphertext, wrong_key, IV).is_err());
    }

    #[test]
    fn test_incorrect_iv() {
        let ciphertext = encrypt_aes_256_cbc(PLAINTEXT, KEY, IV).unwrap();

        let wrong_iv: &[u8; 16] = &[40; 16];
        // Decryption with the wrong iv produces incorrect result
        let decrypted = decrypt_aes_256_cbc(&ciphertext, KEY, wrong_iv).unwrap();
        assert_ne!(decrypted, PLAINTEXT);
    }
}
