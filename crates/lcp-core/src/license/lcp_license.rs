use rsa::RsaPrivateKey;
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

use super::encoding::{certificate_format, date_format, optional_date_format};
use crate::crypto::cipher::aes_cbc256;
use crate::crypto::key::{ContentKey, EncryptedContentKey, UserEncryptionKey};
use crate::crypto::signature::{RSA_SHA256_ALGORITHM, sign_license};
use crate::{crypto, epub};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, FixedOffset, Utc};
use serde_derive::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::ops::Not;
use x509_cert::Certificate;

/// Errors that can occur during license operations.
#[derive(Debug, Error)]
pub enum LicenseError {
    /// Serialization/deserialization failed
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
    /// Key check verification failed
    #[error("Key check failed: user key does not match license")]
    KeyCheckFailed,
    /// Base64 decoding failed
    #[error("Base64 decode failed: {0}")]
    Base64DecodeFailed(String),
    /// License signing failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    /// License must be signed before building
    #[error("License must be signed before building")]
    MissingSignature,
    /// Content key decryption failed
    #[error("Content key decryption failed: {0}")]
    ContentKeyDecryptionFailed(String),
    /// Cipher operation failed
    #[error("Cipher operation failed: {0}")]
    CipherFailed(String),
    /// Cipher operation failed
    #[error("Signature validation failed: {0}")]
    SignatureValidationError(String),
    #[error("Unsupported encryption profile: {0}")]
    UnsupportedEncryptionProfile(String),
}

pub const DEFAULT_PROVIDER: &str = "https://www.duralumind.com";
pub const DEFAULT_HASH_ALGORITHM: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub const DEFAULT_ENCRYPTION_ALGORITHM: &str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
pub const DEFAULT_ENCRYPTION_PROFILE: &str = "http://readium.org/lcp/basic-profile";

#[derive(Debug, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    AesCbc,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct LicenseContentKey {
    /// Encrypted Content Key. Base 64 encoded octet sequence
    encrypted_value: String,
    /// Algorithm used to encrypt the Content Key, identified using the URIs defined in
    ///  [XML-ENC]. This must match the Content Key encryption
    /// algorithm named in the Encryption Profile identified in encryption/profile.
    algorithm: String,
}

impl Default for LicenseContentKey {
    fn default() -> Self {
        Self {
            algorithm: DEFAULT_ENCRYPTION_ALGORITHM.to_string(),
            encrypted_value: Default::default(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct UserKey {
    /// A hint to be displayed to the User to help them remember the User Passphrase
    text_hint: String,
    /// Algorithm used to generate the User Key from the User Passphrase,
    /// identified using the URIs defined in [XML-ENC]. This must match
    /// the User Key hash algorithm named in the Encryption Profile
    /// identified in encryption/profile.
    algorithm: String,
    /// The value of the License Document’s id field, encrypted using the
    /// User Key and the same algorithm identified for Content Key encryption
    /// in encryption/content_key/algorithm. This is used to verify that
    /// the Reading System has the correct User Key.
    ///
    /// Base 64 encoded octet sequence.
    key_check: String,
}

impl Default for UserKey {
    fn default() -> Self {
        Self {
            algorithm: DEFAULT_HASH_ALGORITHM.to_string(),
            text_hint: Default::default(),
            key_check: Default::default(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Encryption {
    /// Identifies the Encryption Profile used by this LCP-protected
    /// Publication. Type: URI
    profile: String,
    /// contains the Content Key (encrypted using the User Key)
    /// used to encrypt the Publication Resources.
    content_key: LicenseContentKey,
    /// contains information regarding the User Key used to encrypt the Content Key.
    user_key: UserKey,
}

impl Default for Encryption {
    fn default() -> Self {
        Self {
            profile: DEFAULT_ENCRYPTION_PROFILE.to_string(),
            content_key: Default::default(),
            user_key: Default::default(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct Link {
    /// Location of the linked resource
    href: String,
    /// Link relationship to the document
    rel: String,
    /// Title of the link
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    /// Expected MIME media type value for the external resources.
    /// MIME media type
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    media_type: Option<String>,
    /// Indicates that the href is a URI Template. False by default.
    #[serde(default)]
    #[serde(skip_serializing_if = "<&bool>::not")]
    templated: bool,
    /// Expected profile used to identify the external resource.
    /// URI type
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
    /// Content length in octets.
    #[serde(skip_serializing_if = "Option::is_none")]
    length: Option<usize>,
    /// SHA-256 hash of the resource.
    /// Base 64 encoded octet sequence
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct Rights {
    /// Maximum number of pages that can be printed over the lifetime of the license.
    print: usize,
    /// Maximum number of characters that can be copied to the clipboard over the lifetime of the license.
    copy: usize,
    /// Date and time when the license begins.
    #[serde(with = "optional_date_format")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    start: Option<DateTime<FixedOffset>>,
    /// Date and time when the license ends.
    #[serde(with = "optional_date_format")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    end: Option<DateTime<FixedOffset>>,
    /// Additional optional entries
    #[serde(flatten)]
    additional_fields: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct User {
    /// Unique identifier for the User at a specific Provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    /// A list of which user object values are encrypted in this License Document.
    #[serde(skip_serializing_if = "Option::is_none")]
    encrypted: Option<Vec<String>>,
    #[serde(flatten)]
    additional_fields: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Signature {
    /// Algorithm used to calculate the signature, identified using the URIs
    /// given in [XML-SIG]. This must match the signature algorithm named in
    /// the Encryption Profile identified in encryption/profile.
    algorithm: String,
    /// The Provider Certificate: an X509 certificate used by the Content Provider.
    /// Base 64 encoded DER certificate.
    #[serde(with = "certificate_format")]
    certificate: Certificate,
    /// Base 64 encoded signature
    value: String,
}

impl Signature {
    pub fn decode_certificate(&self) -> Result<Certificate, String> {
        Ok(self.certificate.clone())
    }
}

#[derive(Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct License {
    /// Unique identifier for the License
    pub id: String,
    /// Date and time when the license was first issued
    /// in ISO 8601 format
    #[serde(with = "date_format")]
    pub issued: DateTime<FixedOffset>,
    /// Date and time when the license was last updated in
    /// ISO 8601 format
    #[serde(with = "optional_date_format")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub updated: Option<DateTime<FixedOffset>>,
    /// Unique identifier for the Provider URI
    pub provider: String,
    /// Contains all encryption related info for the licensed publication.
    pub encryption: Encryption,
    pub links: Vec<Link>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rights: Option<Rights>,
    pub user: User,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

impl License {
    /// Returns a `Builder` for creating a license object.
    pub fn builder() -> LicenseBuilder {
        LicenseBuilder::new()
    }

    pub fn canonical_json(&self) -> Result<String, LicenseError> {
        // First, serialize to JSON Value to manipulate the structure
        let mut value = serde_json::to_value(self)
            .map_err(|e| LicenseError::SerializationFailed(format!("{}", e)))?;

        // Remove the signature field as per rule 1
        if let Value::Object(ref mut map) = value {
            map.remove("signature");
        }

        // Apply canonicalization rules
        let canonical_value = canonicalize_value(value);

        // Serialize without pretty printing (removes non-significant whitespace)
        serde_json::to_string(&canonical_value)
            .map_err(|e| LicenseError::SerializationFailed(format!("{}", e)))
    }

    pub fn publication_link(&self) -> Option<String> {
        self.links.iter().find_map(|link| {
            if link.rel == "publication"
                && link.media_type == Some(epub::CONTENT_TYPE_EPUB.to_string())
            {
                Some(link.href.clone())
            } else {
                None
            }
        })
    }

    /// Returns the raw profile URI string from the license document.
    pub fn profile_uri(&self) -> &str {
        &self.encryption.profile
    }

    /// Check that the `key_check` bytes decrypted with the user encryption key is
    /// the license id.
    ///
    /// This check is part of the validity conditions for a License document.
    pub fn key_check(&self, user_key: &UserEncryptionKey) -> Result<(), LicenseError> {
        let key_check_bytes = general_purpose::STANDARD
            .decode(&self.encryption.user_key.key_check)
            .map_err(|e| LicenseError::Base64DecodeFailed(format!("{:?}", e)))?;

        let decrypted_bytes =
            crate::crypto::cipher::aes_cbc256::decrypt_aes_256_cbc_with_prepended_iv(
                &key_check_bytes,
                user_key.key(),
            )
            .map_err(|e| LicenseError::CipherFailed(e.to_string()))?;

        if decrypted_bytes.as_slice() == self.id.as_bytes() {
            Ok(())
        } else {
            Err(LicenseError::KeyCheckFailed)
        }
    }

    /// Decrypt the content key from the `encrypted_value` in the license to decrypt the actual
    /// content of the epub publication.
    pub fn decrypt_content_key(
        &self,
        user_key: &UserEncryptionKey,
    ) -> Result<ContentKey, LicenseError> {
        // Base64-decode the encrypted content key
        let encrypted_content_key =
            EncryptedContentKey::new_from_raw_bytes(&self.encryption.content_key.encrypted_value)
                .map_err(|e| LicenseError::ContentKeyDecryptionFailed(e.to_string()))?;
        let content_key = ContentKey::decrypt_content_key(&encrypted_content_key, user_key)
            .map_err(|e| LicenseError::ContentKeyDecryptionFailed(e.to_string()))?;
        Ok(content_key)
    }

    /// Verify that the signature against the provider certificate in the license
    /// file. Also verifies that the provider certificate is signed by the root certificate.
    pub fn verify_signature_and_provider(
        &self,
        root_certificate: &Certificate,
    ) -> Result<(), LicenseError> {
        let Some(signature) = &self.signature else {
            return Err(LicenseError::MissingSignature);
        };

        crypto::signature::validate_provider_certificate(&signature.certificate, root_certificate)
            .map_err(|e| {
                LicenseError::SignatureValidationError(format!(
                    "Failed to validate provider signature: {}",
                    e
                ))
            })?;
        crypto::signature::verify_license_signature(
            self.canonical_json()?.as_bytes(),
            &signature.value,
            &signature.certificate,
        )
        .map_err(|e| {
            LicenseError::SignatureValidationError(format!(
                "Failed to validate license signature: {}",
                e
            ))
        })?;
        Ok(())
    }
}

/// Recursively canonicalize a JSON Value according to the rules
fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            // Sort object properties lexicographically
            let mut btree: BTreeMap<String, Value> = BTreeMap::new();
            for (k, v) in map {
                btree.insert(k, canonicalize_value(v));
            }
            let sorted_map: Map<String, Value> = btree.into_iter().collect();
            Value::Object(sorted_map)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(canonicalize_value).collect()),
        // value @ Value::Number(num) => value,
        // value @ Value::String(s) => {
        //     // TODO(pawan): escapre required characters
        //     value
        // }
        other => other,
    }
}

pub struct LicenseBuilder(License);

impl Default for LicenseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl LicenseBuilder {
    /// Creates a builder object with default values.
    pub fn new() -> Self {
        let now: DateTime<FixedOffset> = Utc::now().fixed_offset();
        Self(License {
            id: Uuid::new_v4().to_string(),
            issued: now,
            updated: Some(now),
            provider: DEFAULT_PROVIDER.to_string(),
            ..Default::default()
        })
    }

    /// Sets the encryption related fields on the license.
    pub fn encryption(
        mut self,
        encrypted_key: &EncryptedContentKey,
        user_key: &UserEncryptionKey,
        hint: String,
        profile_uri: &str,
    ) -> Self {
        self.0.encryption.profile = profile_uri.to_string();
        self.0.encryption.content_key.encrypted_value = encrypted_key.to_base64();
        let key_check =
            aes_cbc256::encrypt_aes_256_cbc_with_random_iv(self.0.id.as_bytes(), user_key.key());
        self.0.encryption.user_key.text_hint = hint;
        use base64::{Engine as _, engine::general_purpose};
        self.0.encryption.user_key.key_check = general_purpose::STANDARD.encode(&key_check);
        self
    }

    /// Sets the `signature` on the license with the provider private key.
    pub fn sign(
        mut self,
        private_key: &RsaPrivateKey,
        provider_certificate: &Certificate,
    ) -> Result<Self, LicenseError> {
        let signature = sign_license(self.0.canonical_json()?.as_bytes(), private_key)
            .map_err(|e| LicenseError::SigningFailed(e.to_string()))?;
        let sig = Signature {
            algorithm: RSA_SHA256_ALGORITHM.to_string(),
            certificate: provider_certificate.clone(),
            value: signature,
        };
        self.0.signature = Some(sig);
        Ok(self)
    }

    // Add other optional stuff
    // pub fn links(&mut self, links: Links) -> &mut self {
    //   self
    //  }

    pub fn build(self) -> Result<License, LicenseError> {
        if self.0.signature.is_none() {
            return Err(LicenseError::MissingSignature);
        }
        Ok(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_decode() {
        let json = json!(
            {
              "id": "ef15e740-697f-11e3-949a-0800200c9a66",
              "issued": "2013-11-04T01:08:15+01:00",
              "updated": "2014-02-21T09:44:17+01:00",
              "provider": "https://www.imaginaryebookretailer.com",
              "encryption": {
                "profile": "http://readium.org/lcp/basic-profile",
                "content_key": {
                  "encrypted_value": "/k8RpXqf4E2WEunCp76E8PjhS051NXwAXeTD1ioazYxCRGvHLAck/KQ3cCh5JxDmCK0nRLyAxs1X0aA3z55boQ==",
                  "algorithm": "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
                },
                "user_key": {
                  "text_hint": "Enter your email address",
                    "algorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
                    "key_check": "jJEjUDipHK3OjGt6kFq7dcOLZuicQFUYwQ+TYkAIWKm6Xv6kpHFhF7LOkUK/Owww"
                }
              },
              "links": [
                  { "rel": "publication",
                    "href": "https://www.example.com/file.epub",
                    "type": "application/epub+zip",
                    "length": 264929,
                    "hash": "8b752f93e5e73a3efff1c706c1c2e267dffc6ec01c382cbe2a6ca9bd57cc8378"
                  },
                  { "rel": "hint",
                    "href": "https://www.example.com/passphraseHint?user_id=1234",
                    "type": "text/html"
                  },
                  { "rel": "support",
                    "href": "mailto:support@example.org"
                  },
                  { "rel": "support",
                    "href": "tel:1800836482"
                  },
                  { "rel": "support",
                    "href": "https://example.com/support",
                    "type": "text/html"
                  },
                  { "rel": "https://mylcpextension.com/authentication",
                    "href": "https://www.example.com/authenticateMe",
                    "title": "Authentication service",
                    "type": "application/vnd.myextension.authentication+json"
                  },
                  { "rel": "https://mylcpextension.com/book_recommendations",
                    "href": "https://www.example.com/recommended/1",
                    "type": "text/html"
                  },
                  { "rel": "https://mylcpextension.com/book_recommendations",
                    "href": "https://www.example.com/recommended/1.opds",
                    "type": "application/atom+xml; profile=opds-catalog; kind=acquisition"}
                ],
            "rights": {
                "print": 10,
                "copy": 10000,
                "start": "2013-11-04T01:08:15+01:00",
                "end": "2013-11-25T01:08:15+01:00",
                "https://www.imaginaryebookretailer.com/lcp/rights/tweet": true
              },
            "user": {
                  "id": "d9f298a7-7f34-49e7-8aae-4378ecb1d597",
                  "email": "EnCt2b8c6d2afd94ae4ed201b27049d8ce1afe31a90ceb8c6d2afd94ae4ed201b2704RjkaXRveAAarHwdlID1KCIwEmS",
                  "encrypted": ["email"],
                    "https://www.imaginaryebookretailer.com/lcp/user/language": "tlh"
            },
            "signature": {
              "algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
              "certificate": "MIIDEjCCAfoCCQDwMOjkYYOjPjANBgkqhkiG9w0BAQUFADBLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTETMBEGA1UEBxMKRXZlcnl3aGVyZTESMBAGA1UEAxMJbG9jYWxob3N0MB4XDTE0MDEwMjIxMjYxNloXDTE1MDEwMjIxMjYxNlowSzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEzARBgNVBAcTCkV2ZXJ5d2hlcmUxEjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOpCRECG7icpf0H37kuAM7s42oqggBoikoTpo5yapy+s5eFSp8HSqwhIYgZ4SghNLkj3e652SALav7chyZ2vWvitZycY+aq50n5UTTxDvdwsC5ZNeTycuzVWZALKGhV7VUPEhtWZNm0gruntronNa8l2WS0aF7P5SbhJ65SDQGprFFaYOSyN6550P3kqaAO7tDddcA1cmuIIDRf8tOIIeMkBFk1Qf+lh+3uRP2wztOTECSMRxX/hIkCe5DRFDK2MuDUyc/iY8IbY0hMFFGw5J7MWOwZLBOaZHX+Lf5lOYByPbMH78O0dda6T+tLYAVzsmJdHJFtaRguCaJVtSXKQUAMCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAi9HIM+FMfqXsRUY0rGxLlw403f3YtAG/ohzt5i8DKiKUG3YAnwRbL/VzXLZaHru7XBC40wmKefKqoA0RHyNEddXgtY/aXzOlfTvp+xirop+D4DwJIbaj8/wHKWYGBucA/VgGY7JeSYYTUSuz2RoYtjPNRELIXN8A+D+nkJ3dxdFQ6jFfVfahN3nCIgRqRIOt1KaNI39CShccCaWJ5DeSASLXLPcEjrTi/pyDzC4kLF0VjHYlKT7lq5RkMO6GeC+7YFvJtAyssM2nqunA2lUgyQHb1q4Ih/dcYOACubtBwW0ITpHz8N7eO+r1dtH/BF4yxeWl6p5kGLvuPXNU21ThgA==",
              "value": "q/3IInic9c/EaJHyG1Kkqk5v1zlJNsiQBmxz4lykhyD3dA2jg2ZzrOenYU9GxP/xhe5H5Kt2WaJ/hnt8+GWrEx1QOwnNEij5CmIpZ63yRNKnFS5rSRnDMYmQT/fkUYco7BUi7MPPU6OFf4+kaToNWl8m/ZlMxDcS3BZnVhSEKzUNQn1f2y3sUcXjes7wHbImDc6dRthbL/E+assh5HEqakrDuA4lM8XNfukEYQJnivqhqMLOGM33RnS5nZKrPPK/c2F/vGjJffSrlX3W3Jlds0/MZ6wtVeKIugR06c56V6+qKsnMLAQJaeOxxBXmbFdAEyplP9irn4D9tQZKqbbMIw=="
            }
        }
        );

        let license: License = serde_json::from_value(json).unwrap();
        dbg!(license);
    }

    #[test]
    fn round_trip() {
        let a = License::default();
        let serialized = serde_json::to_value(&a).unwrap();
        let b = serde_json::from_value(serialized).unwrap();

        assert_eq!(a, b);
    }

    #[test]
    fn canonical_json() {
        let json = json!(
            {
              "id": "ef15e740-697f-11e3-949a-0800200c9a66",
              "issued": "2013-11-04T01:08:15+01:00",
              "updated": "2014-02-21T09:44:17+01:00",
              "provider": "https://www.imaginaryebookretailer.com",
              "encryption": {
                "profile": "http://readium.org/lcp/basic-profile",
                "content_key": {
                  "encrypted_value": "/k8RpXqf4E2WEunCp76E8PjhS051NXwAXeTD1ioazYxCRGvHLAck/KQ3cCh5JxDmCK0nRLyAxs1X0aA3z55boQ==",
                  "algorithm": "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
                },
                "user_key": {
                  "text_hint": "Enter your email address",
                    "algorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
                    "key_check": "jJEjUDipHK3OjGt6kFq7dcOLZuicQFUYwQ+TYkAIWKm6Xv6kpHFhF7LOkUK/Owww"
                }
              },
              "links": [
                { "rel": "hint", "href": "https://www.imaginaryebookretailer.com/lcp/hint", "type": "text/html"}
              ],
              "user": { "id": "d9f298a7-7f34-49e7-8aae-4378ecb1d597"}
            }
        );

        let license: License = serde_json::from_value(json).unwrap();
        // Note(pawan): the links array in the spec example isn't sorted.
        // seems like a spec bug, but might be our bug too
        // https://readium.org/lcp-specs/releases/lcp/latest#53-canonical-form-of-the-license-document
        let json_data = r#"{"encryption":{"content_key":{"algorithm":"http://www.w3.org/2001/04/xmlenc#aes256-cbc","encrypted_value":"/k8RpXqf4E2WEunCp76E8PjhS051NXwAXeTD1ioazYxCRGvHLAck/KQ3cCh5JxDmCK0nRLyAxs1X0aA3z55boQ=="},"profile":"http://readium.org/lcp/basic-profile","user_key":{"algorithm":"http://www.w3.org/2001/04/xmlenc#sha256","key_check":"jJEjUDipHK3OjGt6kFq7dcOLZuicQFUYwQ+TYkAIWKm6Xv6kpHFhF7LOkUK/Owww","text_hint":"Enter your email address"}},"id":"ef15e740-697f-11e3-949a-0800200c9a66","issued":"2013-11-04T01:08:15+01:00","links":[{"href":"https://www.imaginaryebookretailer.com/lcp/hint","rel":"hint","type":"text/html"}],"provider":"https://www.imaginaryebookretailer.com","updated":"2014-02-21T09:44:17+01:00","user":{"id":"d9f298a7-7f34-49e7-8aae-4378ecb1d597"}}"#;

        assert_eq!(json_data, license.canonical_json().unwrap());
    }

    #[test]
    fn test_certificate_decode() {
        let signature_json = json!({
          "algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
          "certificate": "MIIDEjCCAfoCCQDwMOjkYYOjPjANBgkqhkiG9w0BAQUFADBLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTETMBEGA1UEBxMKRXZlcnl3aGVyZTESMBAGA1UEAxMJbG9jYWxob3N0MB4XDTE0MDEwMjIxMjYxNloXDTE1MDEwMjIxMjYxNlowSzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEzARBgNVBAcTCkV2ZXJ5d2hlcmUxEjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOpCRECG7icpf0H37kuAM7s42oqggBoikoTpo5yapy+s5eFSp8HSqwhIYgZ4SghNLkj3e652SALav7chyZ2vWvitZycY+aq50n5UTTxDvdwsC5ZNeTycuzVWZALKGhV7VUPEhtWZNm0gruntronNa8l2WS0aF7P5SbhJ65SDQGprFFaYOSyN6550P3kqaAO7tDddcA1cmuIIDRf8tOIIeMkBFk1Qf+lh+3uRP2wztOTECSMRxX/hIkCe5DRFDK2MuDUyc/iY8IbY0hMFFGw5J7MWOwZLBOaZHX+Lf5lOYByPbMH78O0dda6T+tLYAVzsmJdHJFtaRguCaJVtSXKQUAMCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAi9HIM+FMfqXsRUY0rGxLlw403f3YtAG/ohzt5i8DKiKUG3YAnwRbL/VzXLZaHru7XBC40wmKefKqoA0RHyNEddXgtY/aXzOlfTvp+xirop+D4DwJIbaj8/wHKWYGBucA/VgGY7JeSYYTUSuz2RoYtjPNRELIXN8A+D+nkJ3dxdFQ6jFfVfahN3nCIgRqRIOt1KaNI39CShccCaWJ5DeSASLXLPcEjrTi/pyDzC4kLF0VjHYlKT7lq5RkMO6GeC+7YFvJtAyssM2nqunA2lUgyQHb1q4Ih/dcYOACubtBwW0ITpHz8N7eO+r1dtH/BF4yxeWl6p5kGLvuPXNU21ThgA==",
          "value": "q/3IInic9c/EaJHyG1Kkqk5v1zlJNsiQBmxz4lykhyD3dA2jg2ZzrOenYU9GxP/xhe5H5Kt2WaJ/hnt8+GWrEx1QOwnNEij5CmIpZ63yRNKnFS5rSRnDMYmQT/fkUYco7BUi7MPPU6OFf4+kaToNWl8m/ZlMxDcS3BZnVhSEKzUNQn1f2y3sUcXjes7wHbImDc6dRthbL/E+assh5HEqakrDuA4lM8XNfukEYQJnivqhqMLOGM33RnS5nZKrPPK/c2F/vGjJffSrlX3W3Jlds0/MZ6wtVeKIugR06c56V6+qKsnMLAQJaeOxxBXmbFdAEyplP9irn4D9tQZKqbbMIw=="
        });
        let signature: Result<Signature, _> = serde_json::from_value(signature_json);
        assert!(signature.is_ok());
    }
}
