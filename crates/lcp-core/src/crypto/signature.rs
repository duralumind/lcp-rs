//! RSA-SHA256 signing and verification for LCP License Documents.
//!
//! This module implements the signature scheme required by the LCP Basic Profile:
//! - Algorithm: `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`
//! - The canonical JSON of the license (minus signature) is signed using PKCS#1 v1.5 with SHA-256

use base64::{Engine, engine::general_purpose};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{SigningKey, VerifyingKey},
    signature::{SignatureEncoding, Signer, Verifier},
};
use sha2::Sha256;
use thiserror::Error;
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};

/// The algorithm URI for RSA-SHA256 as defined in XML-SIG
pub const RSA_SHA256_ALGORITHM: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

/// Sign the canonical JSON bytes using RSA-SHA256 (PKCS#1 v1.5).
///
/// # Arguments
/// * `canonical_json` - The canonical form of the license document (as bytes)
/// * `private_key` - The provider's RSA private key
///
/// # Returns
/// Base64-encoded signature value
pub fn sign_license(
    canonical_json: &[u8],
    private_key: &RsaPrivateKey,
) -> Result<String, SignatureError> {
    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let signature = signing_key.sign(canonical_json);
    let signature_bytes = signature.to_bytes();
    Ok(general_purpose::STANDARD.encode(&signature_bytes))
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
    certificate: &Certificate,
) -> Result<(), SignatureError> {
    // Extract the public key from the certificate
    let public_key = extract_public_key_from_certificate(certificate)?;

    // Decode the base64 signature
    let signature_bytes = general_purpose::STANDARD
        .decode(signature_value)
        .map_err(|e| SignatureError::InvalidSignature(format!("Base64 decode failed: {}", e)))?;

    // Create the verifying key and verify
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
    // Extract the root's public key for verification
    let root_public_key = extract_public_key_from_certificate(root_cert)?;

    // Get the signature from the provider certificate
    let cert_signature_bytes = provider_cert.signature.raw_bytes();

    // Get the TBS (To Be Signed) certificate data - this is what was signed
    let tbs_bytes = provider_cert.tbs_certificate.to_der().map_err(|e| {
        SignatureError::CertificateError(format!("Failed to encode TBS certificate: {}", e))
    })?;

    // Verify the certificate signature
    // Note: We assume SHA-256 with RSA here (matching the basic profile)
    let verifying_key = VerifyingKey::<Sha256>::new(root_public_key);
    let signature = rsa::pkcs1v15::Signature::try_from(cert_signature_bytes).map_err(|e| {
        SignatureError::CertificateError(format!("Invalid certificate signature format: {}", e))
    })?;

    verifying_key.verify(&tbs_bytes, &signature).map_err(|e| {
        SignatureError::CertificateError(format!("Certificate validation failed: {}", e))
    })?;

    Ok(())
}

/// Extract an RSA public key from an X.509 certificate.
fn extract_public_key_from_certificate(
    certificate: &Certificate,
) -> Result<RsaPublicKey, SignatureError> {
    use rsa::pkcs1::DecodeRsaPublicKey;

    let spki = &certificate.tbs_certificate.subject_public_key_info;
    let public_key_bytes = spki.subject_public_key.raw_bytes();

    RsaPublicKey::from_pkcs1_der(public_key_bytes).map_err(|e| {
        SignatureError::CertificateError(format!("Failed to extract RSA public key: {}", e))
    })
}

/// Load an RSA private key from DER-encoded PKCS#8 bytes.
pub fn load_private_key_from_der(der_bytes: &[u8]) -> Result<RsaPrivateKey, SignatureError> {
    use rsa::pkcs8::DecodePrivateKey;

    RsaPrivateKey::from_pkcs8_der(der_bytes)
        .map_err(|e| SignatureError::KeyError(format!("Failed to load private key: {}", e)))
}

/// Load an X.509 certificate from DER-encoded bytes.
pub fn load_certificate_from_der(der_bytes: &[u8]) -> Result<Certificate, SignatureError> {
    Certificate::from_der(der_bytes).map_err(|e| {
        SignatureError::CertificateError(format!("Failed to parse certificate: {}", e))
    })
}

/// Errors that can occur during signing or verification.
#[derive(Debug, Error)]
pub enum SignatureError {
    /// Error related to the private/public key
    #[error("Key error: {0}")]
    KeyError(String),
    /// Error related to certificate parsing or validation
    #[error("Certificate error: {0}")]
    CertificateError(String),
    /// The signature format is invalid
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    /// Signature verification failed (signature doesn't match)
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    // Embed the test certificates
    const ROOT_CA_DER: &[u8] = include_bytes!("../../../../certs/root_ca.der");
    const PROVIDER_CERT_DER: &[u8] = include_bytes!("../../../../certs/provider.der");
    const PROVIDER_PRIVATE_KEY_DER: &[u8] =
        include_bytes!("../../../../certs/provider_private.der");

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
    fn test_load_private_key() {
        let private_key = load_private_key_from_der(PROVIDER_PRIVATE_KEY_DER);
        assert!(
            private_key.is_ok(),
            "Failed to load private key: {:?}",
            private_key.err()
        );
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        // Load the provider's private key and certificate
        let private_key = load_private_key_from_der(PROVIDER_PRIVATE_KEY_DER)
            .expect("Failed to load private key");
        let provider_cert = load_certificate_from_der(PROVIDER_CERT_DER)
            .expect("Failed to load provider certificate");

        // Sample canonical JSON (this would normally come from License::canonical_json())
        let canonical_json = r#"{"encryption":{"content_key":{"algorithm":"http://www.w3.org/2001/04/xmlenc#aes256-cbc","encrypted_value":"test"},"profile":"http://readium.org/lcp/basic-profile","user_key":{"algorithm":"http://www.w3.org/2001/04/xmlenc#sha256","key_check":"test","text_hint":"Enter your password"}},"id":"test-license-id","issued":"2024-01-01T00:00:00+00:00","links":[],"provider":"https://example.com","user":{}}"#;

        // Sign the canonical JSON
        let signature =
            sign_license(canonical_json.as_bytes(), &private_key).expect("Signing failed");

        // Verify the signature
        let result =
            verify_license_signature(canonical_json.as_bytes(), &signature, &provider_cert);

        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
    }

    #[test]
    fn test_verify_fails_with_tampered_data() {
        // Load the provider's private key and certificate
        let private_key = load_private_key_from_der(PROVIDER_PRIVATE_KEY_DER)
            .expect("Failed to load private key");
        let provider_cert = load_certificate_from_der(PROVIDER_CERT_DER)
            .expect("Failed to load provider certificate");

        let original_json = r#"{"id":"original-id","provider":"https://example.com"}"#;
        let tampered_json = r#"{"id":"tampered-id","provider":"https://example.com"}"#;

        // Sign the original
        let signature =
            sign_license(original_json.as_bytes(), &private_key).expect("Signing failed");

        // Try to verify with tampered data - should fail
        let result = verify_license_signature(tampered_json.as_bytes(), &signature, &provider_cert);

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
    fn test_extract_public_key() {
        let provider_cert = load_certificate_from_der(PROVIDER_CERT_DER)
            .expect("Failed to load provider certificate");

        let public_key = extract_public_key_from_certificate(&provider_cert);
        assert!(
            public_key.is_ok(),
            "Failed to extract public key: {:?}",
            public_key.err()
        );
    }
}
