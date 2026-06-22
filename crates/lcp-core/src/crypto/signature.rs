//! Signature handling for LCP License Documents.
//!
//! Signing and verification dispatch between the supported XML-SIG algorithms
//! based on the typed license model.

use base64::engine::general_purpose;
use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_521_R_1, SHA_256_WITH_RSA_ENCRYPTION,
};
use p521::ecdsa::SigningKey as P521SigningKey;
use rsa::RsaPrivateKey;
use thiserror::Error;
use x509_cert::{
    Certificate,
    der::{Decode, asn1::ObjectIdentifier},
};

use crate::license::SignatureAlgorithm;

/// Errors that can occur during signing or verification.
#[derive(Debug, Error)]
pub enum SignatureError {
    /// Error related to the private/public key
    #[error("Key error: {0}")]
    KeyError(String),
    /// Error related to certificate parsing or validation
    #[error("Certificate error: {0}")]
    CertificateError(String),
    /// The certificate or license references a signature algorithm we do not support
    #[error("Unsupported signature: {0}")]
    UnsupportedSignature(String),
    /// The signature format is invalid
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    /// Signature verification failed (signature doesn't match)
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

#[derive(Clone)]
pub enum ProviderSigningKey {
    /// Based on some of the production LCP profiles I have checked, the `ecdsa_sha256` algorithm explicitly
    /// uses the p521 curve.
    ///
    /// Currently, we only support the p521 curve, but if we see uses of other curves, we should add them in here.
    EcdsaP521(P521SigningKey),
    /// The basic profile signing key.
    RsaSha256(RsaPrivateKey),
}

impl ProviderSigningKey {
    pub fn algorithm(&self) -> SignatureAlgorithm {
        match self {
            Self::EcdsaP521(_) => SignatureAlgorithm::EcdsaSha256,
            Self::RsaSha256(_) => SignatureAlgorithm::RsaSha256,
        }
    }
}

/// Extracts the `SignatureAlgorithm` from the X509 certificate.
fn provider_certificate_key_algorithm(
    provider_certificate: &Certificate,
) -> Result<SignatureAlgorithm, SignatureError> {
    let algorithm = &provider_certificate
        .tbs_certificate
        .subject_public_key_info
        .algorithm;

    if algorithm.oid == RSA_ENCRYPTION {
        return Ok(SignatureAlgorithm::RsaSha256);
    }
    if algorithm.oid == ID_EC_PUBLIC_KEY {
        let curve_oid = algorithm
            .parameters
            .as_ref()
            .ok_or_else(|| {
                SignatureError::CertificateError(
                    "Missing EC curve parameters in provider certificate".to_string(),
                )
            })?
            .decode_as::<ObjectIdentifier>()
            .map_err(|e| {
                SignatureError::CertificateError(format!(
                    "Failed to read EC curve OID from provider certificate: {}",
                    e
                ))
            })?;

        if curve_oid == SECP_521_R_1 {
            return Ok(SignatureAlgorithm::EcdsaSha256);
        } else {
            return Err(SignatureError::UnsupportedSignature(format!(
                "Unsupported provider certificate public-key algorithm OID: {}",
                algorithm.oid
            )));
        }
    }
    Err(SignatureError::UnsupportedSignature(format!(
        "Unsupported provider certificate public-key algorithm OID: {}",
        algorithm.oid
    )))
}

/// Sign the canonical JSON bytes using the selected license signature algorithm.
///
/// # Arguments
/// * `canonical_json` - The canonical form of the license document (as bytes)
/// * `private_key` - The provider's private signing key
///
/// # Returns
/// Base64-encoded signature value
pub fn sign_license(
    canonical_json: &[u8],
    private_key: &ProviderSigningKey,
) -> Result<String, SignatureError> {
    match private_key {
        ProviderSigningKey::EcdsaP521(private_key) => {
            ecdsa_sha256::sign_license(canonical_json, private_key)
        }
        ProviderSigningKey::RsaSha256(private_key) => {
            rsa_sha256::sign_license(canonical_json, private_key)
        }
    }
}

/// Verify a license signature using the provider's certificate.
///
/// # Arguments
/// * `canonical_json` - The canonical form of the license document (as bytes)
/// * `signature_value` - Base64-encoded signature from the license
/// * `certificate` - The provider's X.509 certificate containing the public key
///
/// # Returns
/// `Ok(())` if the signature is valid, `Err` otherwise
pub fn verify_license_signature(
    canonical_json: &[u8],
    signature_value: &str,
    algorithm: SignatureAlgorithm,
    certificate: &Certificate,
) -> Result<(), SignatureError> {
    match algorithm {
        SignatureAlgorithm::RsaSha256 => {
            rsa_sha256::verify_license_signature(canonical_json, signature_value, certificate)
        }
        SignatureAlgorithm::EcdsaSha256 => {
            ecdsa_sha256::verify_license_signature(canonical_json, signature_value, certificate)
        }
    }
}

/// Validate that a provider certificate was signed by the root certificate.
///
/// # Arguments
/// * `provider_cert` - The provider's certificate (from the license)
/// * `root_cert` - The root CA certificate (embedded in the reader)
///
/// # Returns
/// `Ok(())` if the provider certificate is valid, `Err` otherwise
pub fn validate_provider_certificate(
    provider_cert: &Certificate,
    root_cert: &Certificate,
) -> Result<(), SignatureError> {
    let algorithm_oid = provider_cert.signature_algorithm.oid;

    if algorithm_oid == SHA_256_WITH_RSA_ENCRYPTION {
        return rsa_sha256::validate_certificate_signature(provider_cert, root_cert);
    }

    if algorithm_oid == ECDSA_WITH_SHA_256 {
        return ecdsa_sha256::validate_certificate_signature(provider_cert, root_cert);
    }

    Err(SignatureError::UnsupportedSignature(format!(
        "Unsupported certificate signature algorithm OID: {}",
        algorithm_oid
    )))
}

/// Load a provider signing key from DER-encoded PKCS#8 bytes using the
/// provider certificate's public-key algorithm to select the key type.
pub fn load_signing_key_from_der(
    der_bytes: &[u8],
    provider_certificate: &Certificate,
) -> Result<ProviderSigningKey, SignatureError> {
    match provider_certificate_key_algorithm(provider_certificate)? {
        SignatureAlgorithm::RsaSha256 => rsa_sha256::load_signing_key_from_der(der_bytes),
        SignatureAlgorithm::EcdsaSha256 => ecdsa_sha256::load_signing_key_from_der(der_bytes),
    }
}

/// Load an X.509 certificate from DER-encoded bytes.
pub fn load_certificate_from_der(der_bytes: &[u8]) -> Result<Certificate, SignatureError> {
    Certificate::from_der(der_bytes).map_err(|e| {
        SignatureError::CertificateError(format!("Failed to parse certificate: {}", e))
    })
}

mod rsa_sha256 {
    use rsa::{
        RsaPrivateKey, RsaPublicKey,
        pkcs1v15::{SigningKey, VerifyingKey},
        signature::{SignatureEncoding, Signer, Verifier},
    };
    use sha2::Sha256;
    use x509_cert::Certificate;

    use super::{ProviderSigningKey, SignatureError, general_purpose};
    use base64::Engine;

    pub(super) fn sign_license(
        canonical_json: &[u8],
        private_key: &RsaPrivateKey,
    ) -> Result<String, SignatureError> {
        let signing_key = SigningKey::<Sha256>::new(private_key.clone());
        let signature = signing_key.sign(canonical_json);
        let signature_bytes = signature.to_bytes();
        Ok(general_purpose::STANDARD.encode(&signature_bytes))
    }

    pub(super) fn verify_license_signature(
        canonical_json: &[u8],
        signature_value: &str,
        certificate: &Certificate,
    ) -> Result<(), SignatureError> {
        let public_key = extract_public_key_from_certificate(certificate)?;
        let signature_bytes = general_purpose::STANDARD
            .decode(signature_value)
            .map_err(|e| {
                SignatureError::InvalidSignature(format!("Base64 decode failed: {}", e))
            })?;

        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        let signature =
            rsa::pkcs1v15::Signature::try_from(signature_bytes.as_slice()).map_err(|e| {
                SignatureError::InvalidSignature(format!("Invalid signature format: {}", e))
            })?;

        verifying_key
            .verify(canonical_json, &signature)
            .map_err(|e| {
                SignatureError::VerificationFailed(format!("Signature verification failed: {}", e))
            })
    }

    pub(super) fn load_signing_key_from_der(
        der_bytes: &[u8],
    ) -> Result<ProviderSigningKey, SignatureError> {
        use rsa::pkcs8::DecodePrivateKey;

        RsaPrivateKey::from_pkcs8_der(der_bytes)
            .map(ProviderSigningKey::RsaSha256)
            .map_err(|e| SignatureError::KeyError(format!("Failed to load RSA private key: {}", e)))
    }

    pub(super) fn extract_public_key_from_certificate(
        certificate: &Certificate,
    ) -> Result<RsaPublicKey, SignatureError> {
        use rsa::pkcs1::DecodeRsaPublicKey;

        let spki = &certificate.tbs_certificate.subject_public_key_info;
        let public_key_bytes = spki.subject_public_key.raw_bytes();

        RsaPublicKey::from_pkcs1_der(public_key_bytes).map_err(|e| {
            SignatureError::CertificateError(format!("Failed to extract RSA public key: {}", e))
        })
    }

    pub(super) fn validate_certificate_signature(
        signed_certificate: &Certificate,
        issuer_certificate: &Certificate,
    ) -> Result<(), SignatureError> {
        use x509_cert::der::Encode;

        let issuer_public_key = extract_public_key_from_certificate(issuer_certificate)?;
        let signature_bytes = signed_certificate.signature.raw_bytes();
        let tbs_bytes = signed_certificate.tbs_certificate.to_der().map_err(|e| {
            SignatureError::CertificateError(format!("Failed to encode TBS certificate: {}", e))
        })?;

        let verifying_key = VerifyingKey::<Sha256>::new(issuer_public_key);
        let signature = rsa::pkcs1v15::Signature::try_from(signature_bytes).map_err(|e| {
            SignatureError::CertificateError(format!("Invalid certificate signature format: {}", e))
        })?;

        verifying_key.verify(&tbs_bytes, &signature).map_err(|e| {
            SignatureError::CertificateError(format!("Certificate validation failed: {}", e))
        })
    }
}

mod ecdsa_sha256 {
    use p521::{
        FieldBytes,
        ecdsa::SigningKey as P521SigningKey,
        ecdsa::signature::hazmat::PrehashSigner,
        ecdsa::signature::hazmat::PrehashVerifier,
        ecdsa::{Signature as P521Signature, VerifyingKey as P521VerifyingKey},
    };
    use sha2::{Digest, Sha256};
    use x509_cert::Certificate;

    use super::{ProviderSigningKey, SignatureError, general_purpose};
    use base64::Engine;

    const P521_PUBLIC_KEY_LEN: usize = 133;
    const P521_SIGNATURE_LEN: usize = 132;
    const P521_FIELD_BYTES_LEN: usize = 66;

    fn prehash_from_canonical_json(canonical_json: &[u8]) -> FieldBytes {
        prehash_from_sha256_input(canonical_json)
    }

    fn prehash_from_sha256_input(input: &[u8]) -> FieldBytes {
        let digest = Sha256::digest(input);
        let mut prehash = FieldBytes::default();
        prehash[(P521_FIELD_BYTES_LEN - digest.len())..].copy_from_slice(&digest);
        prehash
    }

    pub(super) fn sign_license(
        canonical_json: &[u8],
        private_key: &P521SigningKey,
    ) -> Result<String, SignatureError> {
        let prehash = prehash_from_canonical_json(canonical_json);

        let signature = private_key.sign_prehash(&prehash).map_err(|e| {
            SignatureError::KeyError(format!("Failed to sign with P-521 private key: {}", e))
        })?;

        Ok(general_purpose::STANDARD.encode(signature.to_bytes()))
    }

    pub(super) fn verify_license_signature(
        canonical_json: &[u8],
        signature_value: &str,
        certificate: &Certificate,
    ) -> Result<(), SignatureError> {
        let verifying_key = extract_public_key_from_certificate(certificate)?;
        let signature_bytes = general_purpose::STANDARD
            .decode(signature_value)
            .map_err(|e| {
                SignatureError::InvalidSignature(format!("Base64 decode failed: {}", e))
            })?;

        if signature_bytes.len() != P521_SIGNATURE_LEN {
            return Err(SignatureError::InvalidSignature(format!(
                "Unsupported ECDSA signature size: got {} bytes, expected {} for secp521r1 raw r||s",
                signature_bytes.len(),
                P521_SIGNATURE_LEN
            )));
        }

        let signature = P521Signature::from_slice(&signature_bytes).map_err(|e| {
            SignatureError::InvalidSignature(format!("Invalid P-521 signature format: {}", e))
        })?;

        let prehash = prehash_from_canonical_json(canonical_json);

        verifying_key
            .verify_prehash(&prehash, &signature)
            .map_err(|e| {
                SignatureError::VerificationFailed(format!("Signature verification failed: {}", e))
            })
    }

    pub(super) fn load_signing_key_from_der(
        der_bytes: &[u8],
    ) -> Result<ProviderSigningKey, SignatureError> {
        use p521::SecretKey;
        use p521::pkcs8::DecodePrivateKey;

        let secret_key = SecretKey::from_pkcs8_der(der_bytes).map_err(|e| {
            SignatureError::KeyError(format!("Failed to load P-521 private key: {}", e))
        })?;
        let signing_key = P521SigningKey::from_bytes(&secret_key.to_bytes()).map_err(|e| {
            SignatureError::KeyError(format!("Failed to construct P-521 signing key: {}", e))
        })?;

        Ok(ProviderSigningKey::EcdsaP521(signing_key))
    }

    pub(super) fn extract_public_key_from_certificate(
        certificate: &Certificate,
    ) -> Result<P521VerifyingKey, SignatureError> {
        let public_key_bytes = certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();

        if public_key_bytes.len() != P521_PUBLIC_KEY_LEN {
            return Err(SignatureError::CertificateError(format!(
                "Unsupported ECDSA public key size: got {} bytes, expected {} for secp521r1",
                public_key_bytes.len(),
                P521_PUBLIC_KEY_LEN
            )));
        }

        P521VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|e| {
            SignatureError::CertificateError(format!("Failed to extract P-521 public key: {}", e))
        })
    }

    pub(super) fn validate_certificate_signature(
        signed_certificate: &Certificate,
        issuer_certificate: &Certificate,
    ) -> Result<(), SignatureError> {
        use p521::ecdsa::Signature as P521Signature;
        use x509_cert::der::Encode;

        let issuer_public_key = extract_public_key_from_certificate(issuer_certificate)?;
        let signature =
            P521Signature::from_der(signed_certificate.signature.raw_bytes()).map_err(|e| {
                SignatureError::CertificateError(format!(
                    "Invalid ECDSA certificate signature format: {}",
                    e
                ))
            })?;
        let tbs_bytes = signed_certificate.tbs_certificate.to_der().map_err(|e| {
            SignatureError::CertificateError(format!("Failed to encode TBS certificate: {}", e))
        })?;
        let prehash = prehash_from_sha256_input(&tbs_bytes);

        issuer_public_key
            .verify_prehash(&prehash, &signature)
            .map_err(|e| {
                SignatureError::CertificateError(format!("Certificate validation failed: {}", e))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    // Embed the test certificates
    const ROOT_CA_DER: &[u8] = include_bytes!("../../../../certs/root_ca.der");
    const PROVIDER_CERT_DER: &[u8] = include_bytes!("../../../../certs/provider.der");
    const PROVIDER_PRIVATE_KEY_DER: &[u8] =
        include_bytes!("../../../../certs/provider_private.der");
    const ECDSA_ROOT_CA_DER_B64: &str = "MIICGTCCAXqgAwIBAgIUUm4GgREwIWLkVeuudcnhvdEWsc0wCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwTTENQIFRlc3QgRUNEU0EgUm9vdDAeFw0yNjA2MjIwMDE0MTNaFw0zNjA2MTkwMDE0MTNaMB4xHDAaBgNVBAMME0xDUCBUZXN0IEVDRFNBIFJvb3QwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAHQDo2n02dCvTygb7J94K72bFelpG5SYxBpKZ+ebcdQ6MmTgO+wHbJPc/vevEZtlnmVi/ETbNJSdJRCF16jusOScwE0o4lnrn0pj5FDAy5zzccNvQS/lMfUyu1mZHVyay/waPETtLMzVkAN06dgF5FSxMHPQUPy4aqxif1AyS/vEJwlJKNTMFEwHQYDVR0OBBYEFOqa5Cxs2//DpBDO6eXFFUANO5LZMB8GA1UdIwQYMBaAFOqa5Cxs2//DpBDO6eXFFUANO5LZMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDgYwAMIGIAkIB/JO+erctkgGaU8FPzHFKQyao9l+qYfDjMBfjlrKCZYGZ5MTHnplF5E+D3VIPYjO0hdwJ91zvTZaRk36WTl2NAAoCQgC/cHkCYN9CcO/PRio09FY+D0/djV1O4EJXPmGiNt+cVHY9G3BrhEoYH0hT8kk2nYuJTMyTef2muDnl2vnZ6gk+Qg==";
    const ECDSA_PROVIDER_CERT_DER_B64: &str = "MIICCzCCAW2gAwIBAgIUTDgBmdwwckJiz8DIk1x9yBNAtHcwCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwTTENQIFRlc3QgRUNEU0EgUm9vdDAeFw0yNjA2MjIwMDE0MTNaFw0yNzA2MjIwMDE0MTNaMCIxIDAeBgNVBAMMF0xDUCBUZXN0IEVDRFNBIFByb3ZpZGVyMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBWFy4Ok6FRr8Dz9M0pWRBLmbdFUhfkVXVWu9jjPtvn/nzx1BfhDqqw0wg1GoubwlLTqaaYLLIV/rH0RiAb+ASRxQBiB0eWk9Z7eH8pc6Vo0d7r+O0B+vYXZq7oijWQ2T+NAQMGsZyDcFJ1/BGS63+5k/JuEE2ljmmvsISXnlcP+QZclSjQjBAMB0GA1UdDgQWBBTJWZS4lQTvK4YlFoCQdAzcjtWufzAfBgNVHSMEGDAWgBTqmuQsbNv/w6QQzunlxRVADTuS2TAKBggqhkjOPQQDAgOBiwAwgYcCQgHOOo6TG4NKwuxR+OhB9gaMzxUrUNvUCfAEKZhgNrjWs5EClanJ2sPMvwSYlTQgQn9KAseqS10xeWvJMACXDAJVrQJBY0LNM6k9ZSesVE9+EvohNXTjoAY+Bmsplv3kGOf0NDPxYH17ZeZN6l3FxtLPXQPukhEktcI5GS1cu6YG27m2Xyw=";
    const ECDSA_PROVIDER_PRIVATE_KEY_DER_B64: &str = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAeh6bPZK81a/+76gCft377ucafMwM1JiEY6sgmE87YPdfzjNK4YghQy2E8J++Y9oqoctpn2tEUqhRUQwHJAlMGjKhgYkDgYYABAFYXLg6ToVGvwPP0zSlZEEuZt0VSF+RVdVa72OM+2+f+fPHUF+EOqrDTCDUai5vCUtOpppgsshX+sfRGIBv4BJHFAGIHR5aT1nt4fylzpWjR3uv47QH69hdmruiKNZDZP40BAwaxnINwUnX8EZLrf7mT8m4QTaWOaa+whJeeVw/5BlyVA==";

    fn decode_der_base64(input: &str) -> Vec<u8> {
        general_purpose::STANDARD
            .decode(input)
            .expect("Failed to decode base64 DER fixture")
    }

    #[test]
    fn test_load_certificates() {
        let root_cert = load_certificate_from_der(ROOT_CA_DER);
        assert!(
            root_cert.is_ok(),
            "Failed to load root certificate: {:?}",
            root_cert.err()
        );

        let provider_cert = load_certificate_from_der(PROVIDER_CERT_DER);
        assert!(
            provider_cert.is_ok(),
            "Failed to load provider certificate: {:?}",
            provider_cert.err()
        );
    }

    #[test]
    fn test_load_signing_key() {
        let provider_cert = load_certificate_from_der(PROVIDER_CERT_DER)
            .expect("Failed to load provider certificate");
        let private_key = load_signing_key_from_der(PROVIDER_PRIVATE_KEY_DER, &provider_cert);
        assert!(
            private_key.is_ok(),
            "Failed to load signing key: {:?}",
            private_key.err()
        );
        assert!(matches!(
            private_key.unwrap(),
            ProviderSigningKey::RsaSha256(_)
        ));
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        // Load the provider's private key and certificate
        let provider_cert = load_certificate_from_der(PROVIDER_CERT_DER)
            .expect("Failed to load provider certificate");
        let private_key = load_signing_key_from_der(PROVIDER_PRIVATE_KEY_DER, &provider_cert)
            .expect("Failed to load signing key");

        // Sample canonical JSON (this would normally come from License::canonical_json())
        let canonical_json = r#"{"encryption":{"content_key":{"algorithm":"http://www.w3.org/2001/04/xmlenc#aes256-cbc","encrypted_value":"test"},"profile":"http://readium.org/lcp/basic-profile","user_key":{"algorithm":"http://www.w3.org/2001/04/xmlenc#sha256","key_check":"test","text_hint":"Enter your password"}},"id":"test-license-id","issued":"2024-01-01T00:00:00+00:00","links":[],"provider":"https://example.com","user":{}}"#;

        // Sign the canonical JSON
        let signature =
            sign_license(canonical_json.as_bytes(), &private_key).expect("Signing failed");

        // Verify the signature
        let result = verify_license_signature(
            canonical_json.as_bytes(),
            &signature,
            SignatureAlgorithm::RsaSha256,
            &provider_cert,
        );

        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
    }

    #[test]
    fn test_verify_fails_with_tampered_data() {
        // Load the provider's private key and certificate
        let provider_cert = load_certificate_from_der(PROVIDER_CERT_DER)
            .expect("Failed to load provider certificate");
        let private_key = load_signing_key_from_der(PROVIDER_PRIVATE_KEY_DER, &provider_cert)
            .expect("Failed to load signing key");

        let original_json = r#"{"id":"original-id","provider":"https://example.com"}"#;
        let tampered_json = r#"{"id":"tampered-id","provider":"https://example.com"}"#;

        // Sign the original
        let signature =
            sign_license(original_json.as_bytes(), &private_key).expect("Signing failed");

        // Try to verify with tampered data - should fail
        let result = verify_license_signature(
            tampered_json.as_bytes(),
            &signature,
            SignatureAlgorithm::RsaSha256,
            &provider_cert,
        );

        assert!(
            result.is_err(),
            "Verification should have failed for tampered data"
        );
    }

    #[test]
    fn test_validate_provider_certificate_chain() {
        let root_cert =
            load_certificate_from_der(ROOT_CA_DER).expect("Failed to load root certificate");
        let provider_cert = load_certificate_from_der(PROVIDER_CERT_DER)
            .expect("Failed to load provider certificate");

        let result = validate_provider_certificate(&provider_cert, &root_cert);
        assert!(
            result.is_ok(),
            "Certificate chain validation failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_validate_provider_certificate_chain_ecdsa() {
        let root_cert = load_certificate_from_der(&decode_der_base64(ECDSA_ROOT_CA_DER_B64))
            .expect("Failed to load ECDSA root certificate");
        let provider_cert =
            load_certificate_from_der(&decode_der_base64(ECDSA_PROVIDER_CERT_DER_B64))
                .expect("Failed to load ECDSA provider certificate");

        let result = validate_provider_certificate(&provider_cert, &root_cert);
        assert!(
            result.is_ok(),
            "ECDSA certificate chain validation failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_extract_public_key() {
        let provider_cert = load_certificate_from_der(PROVIDER_CERT_DER)
            .expect("Failed to load provider certificate");

        let public_key = rsa_sha256::extract_public_key_from_certificate(&provider_cert);
        assert!(
            public_key.is_ok(),
            "Failed to extract public key: {:?}",
            public_key.err()
        );
    }

    #[test]
    fn test_load_signing_key_ecdsa() {
        let provider_cert =
            load_certificate_from_der(&decode_der_base64(ECDSA_PROVIDER_CERT_DER_B64))
                .expect("Failed to load ECDSA provider certificate");
        let private_key = load_signing_key_from_der(
            &decode_der_base64(ECDSA_PROVIDER_PRIVATE_KEY_DER_B64),
            &provider_cert,
        );

        assert!(
            private_key.is_ok(),
            "Failed to load ECDSA signing key: {:?}",
            private_key.err()
        );
        assert!(matches!(
            private_key.unwrap(),
            ProviderSigningKey::EcdsaP521(_)
        ));
    }

    #[test]
    fn test_verify_ecdsa_sample_license() {
        let license_json = include_str!("../../../../samples/moby-dick.lcpl");
        let license: crate::license::License =
            serde_json::from_str(license_json).expect("Failed to parse sample license");
        let signature = license
            .signature
            .as_ref()
            .expect("Sample license is unsigned");
        let canonical = license.canonical_json().expect("Failed to canonicalize");

        let result = verify_license_signature(
            canonical.as_bytes(),
            signature.value(),
            signature.algorithm(),
            signature.certificate(),
        );

        assert!(
            result.is_ok(),
            "ECDSA sample verification failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_verify_ecdsa_sample_fails_with_tampered_data() {
        let license_json = include_str!("../../../../samples/moby-dick.lcpl");
        let mut license: crate::license::License =
            serde_json::from_str(license_json).expect("Failed to parse sample license");
        license.id = "tampered-license".to_string();
        let signature = license
            .signature
            .as_ref()
            .expect("Sample license is unsigned");
        let tampered_json = license
            .canonical_json()
            .expect("Failed to canonicalize tampered license");

        let result = verify_license_signature(
            tampered_json.as_bytes(),
            signature.value(),
            signature.algorithm(),
            signature.certificate(),
        );

        assert!(
            result.is_err(),
            "Verification should have failed for tampered ECDSA data"
        );
    }

    #[test]
    fn test_sign_and_verify_roundtrip_ecdsa_p521() {
        use p521::ecdsa::VerifyingKey as P521VerifyingKey;
        use p521::ecdsa::signature::hazmat::PrehashVerifier;
        use p521::elliptic_curve::rand_core::OsRng;
        use sha2::{Digest, Sha256};
        const P521_FIELD_BYTES_LEN: usize = 66;

        let private_key = P521SigningKey::random(&mut OsRng);
        let verifying_key = P521VerifyingKey::from(&private_key);
        let provider_key = ProviderSigningKey::EcdsaP521(private_key);
        let canonical_json = br#"{"id":"test-license-id","provider":"https://example.com"}"#;

        let signature_b64 = sign_license(canonical_json, &provider_key).expect("Signing failed");
        let signature_bytes = general_purpose::STANDARD
            .decode(signature_b64)
            .expect("Failed to decode generated signature");
        let signature =
            p521::ecdsa::Signature::from_slice(&signature_bytes).expect("Invalid signature bytes");

        let digest = Sha256::digest(canonical_json);
        let mut prehash = p521::FieldBytes::default();
        prehash[(P521_FIELD_BYTES_LEN - digest.len())..].copy_from_slice(&digest);

        let result = verifying_key.verify_prehash(&prehash, &signature);
        assert!(
            result.is_ok(),
            "ECDSA verification failed: {:?}",
            result.err()
        );
    }
}
