use std::path::{Path, PathBuf};

use crate::{
    Error, TransformResolver,
    crypto::{
        key::{ContentKey, HashAlgorithm, UserEncryptionKey, UserPassphrase},
        signature::load_certificate_from_der,
    },
    epub::{ENCRYPTION_FILE, EncryptedFileInfo, Epub, EpubError},
    license::{License, LicenseError},
};
use x509_cert::Certificate;

/// A parsed LCP-protected publication before the user key has been verified.
pub struct OpenedPublication<'a> {
    epub: Epub,
    license: License,
    encrypted_resources: Vec<EncryptedFileInfo>,
    root_certificate: Certificate,
    resolver: &'a dyn TransformResolver,
}

impl<'a> OpenedPublication<'a> {
    /// Opens an EPUB and loads either an external license or the embedded license.
    pub fn open_path(
        path: impl Into<PathBuf>,
        external_license: Option<License>,
        root_ca_der: &[u8],
        resolver: &'a dyn TransformResolver,
    ) -> Result<Self, Error> {
        let epub_path = path.into();
        let epub = Epub::new(epub_path)?;
        Self::from_epub(epub, external_license, root_ca_der, resolver)
    }

    fn from_epub(
        epub: Epub,
        external_license: Option<License>,
        root_ca_der: &[u8],
        resolver: &'a dyn TransformResolver,
    ) -> Result<Self, Error> {
        let license = match external_license {
            Some(license) => license,
            None => epub
                .license()
                .cloned()
                .ok_or_else(|| EpubError::MissingRequiredFile("license.lcpl".to_string()))?,
        };
        let encrypted_resources = epub.encrypted_resources().map_err(|e| match e {
            EpubError::MissingRequiredFile(_) => {
                EpubError::MissingRequiredFile(ENCRYPTION_FILE.to_string())
            }
            other => other,
        })?;
        let root_certificate = load_certificate_from_der(root_ca_der).map_err(Error::Signature)?;

        Ok(Self {
            epub,
            license,
            encrypted_resources,
            root_certificate,
            resolver,
        })
    }

    pub fn license(&self) -> &License {
        &self.license
    }

    pub fn profile_uri(&self) -> &str {
        self.license.profile_uri()
    }

    pub fn user_key_hint(&self) -> &str {
        self.license.user_key_hint()
    }

    pub fn encrypted_resources(&self) -> &[EncryptedFileInfo] {
        &self.encrypted_resources
    }

    /// Verifies the passphrase, validates the license signature, and derives the content key.
    ///
    /// Returns a `UnlockedPublication` which can decrypt resources on demand.
    pub fn unlock_with_passphrase(
        self,
        passphrase: &str,
    ) -> Result<UnlockedPublication<'a>, Error> {
        let transform = self
            .resolver
            .resolve(self.license.profile_uri())
            .map_err(|e| Error::License(LicenseError::UnsupportedEncryptionProfile(e)))?;
        let user_encryption_key = UserEncryptionKey::new(
            UserPassphrase(passphrase.to_string()),
            HashAlgorithm::Sha256,
            &*transform,
        );

        self.license.key_check(&user_encryption_key)?;
        self.license
            .verify_signature_and_provider(&self.root_certificate)?;
        let content_key = self.license.decrypt_content_key(&user_encryption_key)?;

        Ok(UnlockedPublication {
            opened: self,
            content_key,
        })
    }
}

/// A publication whose LCP license has been verified and unlocked.
pub struct UnlockedPublication<'a> {
    opened: OpenedPublication<'a>,
    content_key: ContentKey,
}

impl UnlockedPublication<'_> {
    pub fn license(&self) -> &License {
        &self.opened.license
    }

    /// Returns a list of encrypted resources contained within the unlocked
    /// publication.
    pub fn encrypted_resources(&self) -> &[EncryptedFileInfo] {
        &self.opened.encrypted_resources
    }

    /// Decrypts and returns the decrypted bytes for resource in the path.
    ///
    /// Returns an error if the path doesn't exist or if the decryption fails.
    pub fn decrypt_resource(&mut self, path: &str) -> Result<Vec<u8>, Error> {
        let encrypted_resource = self
            .encrypted_resource_info(path)
            .cloned()
            .ok_or_else(|| EpubError::MissingRequiredFile(path.to_string()))?;
        self.opened
            .epub
            .decrypt_resource_with_info(&encrypted_resource, &self.content_key)
            .map_err(Error::from)
    }

    /// Writes the decrypted epub to the provided path.
    pub fn export_decrypted_epub(mut self, output: impl AsRef<Path>) -> Result<(), Error> {
        let writer = self.opened.epub.create_decrypted_epub_with_resources(
            output.as_ref().to_path_buf(),
            &self.content_key,
            &self.opened.encrypted_resources,
        )?;
        writer.finish().map_err(|e| {
            EpubError::WriteFailed(format!("Failed to write decrypted epub: {}", e))
        })?;
        Ok(())
    }

    fn encrypted_resource_info(&self, path: &str) -> Option<&EncryptedFileInfo> {
        self.opened
            .encrypted_resources
            .iter()
            .find(|resource| resource.uri == path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BasicResolver, encrypt_epub, license::lcp_license::DEFAULT_ENCRYPTION_PROFILE};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const ROOT_CA_DER: &[u8] = include_bytes!("../../../certs/root_ca.der");
    const PROVIDER_CERT_DER: &[u8] = include_bytes!("../../../certs/provider.der");
    const PROVIDER_PRIVATE_KEY_DER: &[u8] = include_bytes!("../../../certs/provider_private.der");
    static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_path(name: &str) -> PathBuf {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "lcp-rs-session-{}-{}-{}",
            std::process::id(),
            counter,
            name
        ))
    }

    fn encrypted_fixture() -> PathBuf {
        let resolver = BasicResolver;
        let encrypted = temp_path("encrypted.epub");
        encrypt_epub(
            PathBuf::from("../../samples/moby-dick.epub"),
            "test123".to_string(),
            "password is test123".to_string(),
            DEFAULT_ENCRYPTION_PROFILE,
            &resolver,
            Some(encrypted.clone()),
            PROVIDER_CERT_DER,
            PROVIDER_PRIVATE_KEY_DER,
        )
        .unwrap();
        encrypted
    }

    #[test]
    fn session_unlocks_and_decrypts_single_resource() {
        let resolver = BasicResolver;
        let encrypted = encrypted_fixture();
        let opened = OpenedPublication::open_path(encrypted, None, ROOT_CA_DER, &resolver).unwrap();

        assert!(!opened.encrypted_resources().is_empty());

        let encrypted_resource = opened.encrypted_resources()[0].clone();
        let mut unlocked = opened.unlock_with_passphrase("test123").unwrap();
        let decrypted = unlocked.decrypt_resource(&encrypted_resource.uri).unwrap();

        assert_eq!(decrypted.len(), encrypted_resource.original_length);
    }

    #[test]
    fn session_exports_decrypted_epub() {
        let resolver = BasicResolver;
        let encrypted = encrypted_fixture();
        let decrypted = temp_path("decrypted.epub");

        OpenedPublication::open_path(encrypted, None, ROOT_CA_DER, &resolver)
            .unwrap()
            .unlock_with_passphrase("test123")
            .unwrap()
            .export_decrypted_epub(&decrypted)
            .unwrap();

        assert!(decrypted.exists());
    }
}
