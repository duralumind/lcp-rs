use std::collections::HashSet;
use std::io::Seek;
use std::{fs::File, io::Read, path::PathBuf};
use thiserror::Error;
use zip::ZipArchive;
use zip::write::{SimpleFileOptions, ZipWriter};

use crate::{
    crypto::{cipher::aes_cbc256::*, key::ContentKey},
    license::License,
};

pub mod xml_utils;

pub use xml_utils::{
    EncryptedFileInfo, ManifestItem, find_element_attr, get_opf_base_path, parse_container_xml,
    parse_encryption_xml, parse_opf_manifest, write_encryption_xml,
};

use flate2::Compression;
use flate2::write::{DeflateDecoder, DeflateEncoder};
use std::io::Write;

/// Errors that can occur during EPUB operations.
#[derive(Debug, Error)]
pub enum EpubError {
    /// Failed to open file
    #[error("Failed to open file: {0}")]
    FileOpenFailed(String),
    /// Failed to read archive
    #[error("Failed to read archive: {0}")]
    ArchiveReadFailed(String),
    /// Missing required file in archive
    #[error("Missing required file: {0}")]
    MissingRequiredFile(String),
    /// XML parsing error
    #[error("XML parse error: {0}")]
    XmlParseFailed(String),
    /// Invalid manifest entry
    #[error("Invalid manifest: {0}")]
    InvalidManifest(String),
    /// Compression operation failed
    #[error("Compression failed: {0}")]
    CompressionFailed(String),
    /// Decompression operation failed
    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),
    /// Decryption operation failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    /// Write operation failed
    #[error("Write failed: {0}")]
    WriteFailed(String),
    /// License parsing failed
    #[error("License parse failed: {0}")]
    LicenseParseFailed(String),
    /// Decrypted length doesn't match original
    #[error("Invalid decrypted length: original={original}, decrypted={decrypted}")]
    InvalidDecryptedLength { original: usize, decrypted: usize },
    /// Invalid string data
    #[error("Invalid string data: {0}")]
    InvalidStringData(String),
    /// Download operation failed
    #[error("Download failed: {0}")]
    DownloadFailed(String),
}

/// Compress data using the Deflate algorithm.
pub fn deflate_compress(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

/// Compress data using the Deflate algorithm.
pub fn deflate_uncompress(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut decoder = DeflateDecoder::new(Vec::new());
    decoder.write_all(data)?;
    decoder.finish()
}

/// Filenames for specific metadata files
pub const CONTAINER_FILE: &str = "META-INF/container.xml";
pub const ENCRYPTION_FILE: &str = "META-INF/encryption.xml";
pub const LICENSE_FILE: &str = "META-INF/license.lcpl";

/// Content types for files used within epubs.
pub const CONTENT_TYPE_XHTML: &str = "application/xhtml+xml";
pub const CONTENT_TYPE_HTML: &str = "text/html";
pub const CONTENT_TYPE_NCX: &str = "application/x-dtbncx+xml";
pub const CONTENT_TYPE_EPUB: &str = "application/epub+zip";

fn read_file_from_archive(
    archive: &mut ZipArchive<File>,
    filename: &str,
) -> Result<Option<String>, EpubError> {
    let Ok(mut zipfile) = archive.by_path(filename) else {
        return Ok(None);
    };
    let mut target = Vec::with_capacity(zipfile.size() as usize);
    zipfile
        .read_to_end(&mut target)
        .map_err(|e| EpubError::ArchiveReadFailed(format!("Failed to read {}: {}", filename, e)))?;
    String::from_utf8(target)
        .map(Some)
        .map_err(|e| EpubError::InvalidStringData(format!("Invalid UTF-8 in {}: {}", filename, e)))
}

fn read_binary_from_archive(
    archive: &mut ZipArchive<File>,
    filename: &str,
) -> Result<Option<Vec<u8>>, EpubError> {
    let Ok(mut zipfile) = archive.by_path(filename) else {
        return Ok(None);
    };
    let mut buffer = Vec::with_capacity(zipfile.size() as usize);
    zipfile
        .read_to_end(&mut buffer)
        .map_err(|e| EpubError::ArchiveReadFailed(format!("Failed to read {}: {}", filename, e)))?;
    Ok(Some(buffer))
}

/// Internal representation of an epub file with all required elements for
/// 1. encrypting a epub publication to a lcp encrypted epub.
/// 2. decrypting a lcp encrypted epub to a regular epub.
#[derive(Debug)]
pub struct Epub {
    archive: ZipArchive<File>,
    container: String,
    #[allow(unused)]
    encryption: Option<String>,
    license: Option<License>,
}

impl Epub {
    /// Load a type `Self` from the given path.
    pub fn new(path: PathBuf) -> Result<Self, EpubError> {
        let epub_file =
            File::open(&path).map_err(|e| EpubError::FileOpenFailed(format!("{}", e)))?;
        let mut zip = zip::ZipArchive::new(epub_file)
            .map_err(|e| EpubError::ArchiveReadFailed(format!("{}", e)))?;
        let container = read_file_from_archive(&mut zip, CONTAINER_FILE)?
            .ok_or_else(|| EpubError::MissingRequiredFile(CONTAINER_FILE.to_string()))?;
        let encryption = read_file_from_archive(&mut zip, ENCRYPTION_FILE)?;
        let license: Option<License> = read_file_from_archive(&mut zip, LICENSE_FILE)?
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .map_err(|e| EpubError::LicenseParseFailed(format!("{}", e)))?;

        Ok(Self {
            archive: zip,
            container,
            encryption,
            license,
        })
    }

    /// Returns the license file.
    pub fn license(&self) -> Option<&License> {
        self.license.as_ref()
    }

    /// Creates and returns a new zip archive in the given output path with the metadata files from the
    /// orginal archive and the encrypted content files.
    pub fn create_encrypted_epub(
        &mut self,
        output: PathBuf,
        content_key: &ContentKey,
    ) -> Result<ZipWriter<File>, EpubError> {
        // Create the writer
        let output =
            File::create(output).map_err(|e| EpubError::FileOpenFailed(format!("{}", e)))?;
        let mut writer = ZipWriter::new(output);

        // Clone the reader
        let manifest_items_to_encrypt = self.clone_reader(&mut writer)?;
        let mut encrypted_files = Vec::new();
        let opf_path = self.opf_path()?;
        let base_path = get_opf_base_path(&opf_path);
        // Encrypt and write
        for manifest in manifest_items_to_encrypt {
            let path = format!("{}{}", base_path, manifest.href);
            let data = read_binary_from_archive(&mut self.archive, &path)?
                .ok_or_else(|| EpubError::InvalidManifest(format!("{:?}", &manifest)))?;
            let len = data.len();
            let compressed_data = if manifest.is_codec() {
                data
            } else {
                deflate_compress(&data)
                    .map_err(|e| EpubError::CompressionFailed(format!("{:?}", e)))?
            };
            let encrypted_data =
                encrypt_aes_256_cbc_with_random_iv(&compressed_data, content_key.key());
            // no need to compress already compressed files
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            writer
                .start_file(&path, options)
                .map_err(|e| EpubError::WriteFailed(format!("Failed to start file: {}", e)))?;

            writer
                .write_all(&encrypted_data)
                .map_err(|e| EpubError::WriteFailed(format!("Failed to write to file: {}", e)))?;

            // Track for encryption.xml
            encrypted_files.push(EncryptedFileInfo {
                uri: path,
                is_compressed: !manifest.is_codec(),
                original_length: len,
            });
        }

        // Write encryption.xml
        let encryption_xml = write_encryption_xml(&encrypted_files);
        writer
            .start_file(ENCRYPTION_FILE, SimpleFileOptions::default())
            .map_err(|e| EpubError::WriteFailed(format!("Failed to start file: {}", e)))?;
        writer
            .write_all(encryption_xml.as_bytes())
            .map_err(|e| EpubError::WriteFailed(format!("Failed to write to file: {}", e)))?;

        Ok(writer)
    }

    /// Embed lcpl license file into the epub metadata and write to the output path.
    pub fn embed_license_and_write(
        mut encrypted_epub: ZipWriter<File>,
        license: &License,
    ) -> Result<(), EpubError> {
        let license_json = serde_json::to_string(&license)
            .map_err(|e| EpubError::LicenseParseFailed(format!("{}", e)))?;
        encrypted_epub
            .start_file(LICENSE_FILE, SimpleFileOptions::default())
            .map_err(|e| EpubError::WriteFailed(format!("Failed to start file: {}", e)))?;
        encrypted_epub
            .write_all(license_json.as_bytes())
            .map_err(|e| EpubError::WriteFailed(format!("Failed to write to file: {}", e)))?;

        encrypted_epub
            .finish()
            .map_err(|e| EpubError::WriteFailed(format!("Failed to finish writing: {}", e)))?;

        Ok(())
    }

    /// Returns the path to the OPF file from container.xml.
    pub fn opf_path(&self) -> Result<String, EpubError> {
        xml_utils::parse_container_xml(&self.container).map_err(EpubError::XmlParseFailed)
    }

    /// Returns a list of manifest items from the opf file.
    pub fn manifest_items(&mut self) -> Result<Vec<ManifestItem>, EpubError> {
        let opf_path = self.opf_path()?;
        let manifest = read_file_from_archive(&mut self.archive, &opf_path)?
            .ok_or_else(|| EpubError::MissingRequiredFile(opf_path.clone()))?;
        let manifest_items = parse_opf_manifest(&manifest).map_err(EpubError::XmlParseFailed)?;

        Ok(manifest_items)
    }

    /// Clone all files that should NOT be encrypted from this EPUB to a ZipWriter.
    ///
    /// Returns the list of ManifestItems that need to be encrypted (were not copied).
    ///
    /// This function is AI generated:
    /// - Copies `mimetype` first (required by EPUB spec)
    /// - Skips files that need encryption (based on manifest analysis)
    /// - Skips `META-INF/encryption.xml` and `META-INF/license.lcpl` (will be regenerated)
    /// - Copies all other files using raw_copy_file (preserves compression)
    pub fn clone_reader<W: Write + Seek>(
        &mut self,
        writer: &mut ZipWriter<W>,
    ) -> Result<Vec<ManifestItem>, EpubError> {
        let opf_path = self.opf_path()?;
        let base_path = xml_utils::get_opf_base_path(&opf_path);
        let manifest_items = self.manifest_items()?;

        // Build set of full paths for files to encrypt
        let files_to_encrypt: HashSet<String> = manifest_items
            .iter()
            .filter(|m| !m.is_encryption_exempt())
            .map(|m| format!("{}{}", base_path, m.href))
            .collect();

        // Items that need encryption (to return)
        let items_to_encrypt: Vec<ManifestItem> = manifest_items
            .into_iter()
            .filter(|m| !m.is_encryption_exempt())
            .collect();

        // Copy mimetype first (EPUB requirement)
        if let Ok(mimetype_file) = self.archive.by_name("mimetype") {
            writer
                .raw_copy_file(mimetype_file)
                .map_err(|e| EpubError::WriteFailed(format!("Failed to copy mimetype: {}", e)))?;
        }

        // Copy all other files that don't need encryption
        for i in 0..self.archive.len() {
            let file = self.archive.by_index(i).map_err(|e| {
                EpubError::ArchiveReadFailed(format!("Failed to read entry {}: {}", i, e))
            })?;
            let name = file.name().to_string();

            // Skip mimetype (already copied)
            if name == "mimetype" {
                continue;
            }

            // Skip files we'll regenerate
            if name == ENCRYPTION_FILE || name == LICENSE_FILE {
                continue;
            }

            // Skip files that need encryption
            if files_to_encrypt.contains(&name) {
                continue;
            }

            // Copy everything else
            writer
                .raw_copy_file(file)
                .map_err(|e| EpubError::WriteFailed(format!("Failed to copy {}: {}", name, e)))?;
        }

        Ok(items_to_encrypt)
    }

    /// Creates and returns a new zip archive in the given output path with the encrypted data decrypted
    /// and then written into the same path as the original.
    pub fn create_decrypted_epub(
        &mut self,
        output: PathBuf,
        content_key: &ContentKey,
    ) -> Result<ZipWriter<File>, EpubError> {
        // Create the writer
        let output =
            File::create(output).map_err(|e| EpubError::FileOpenFailed(format!("{}", e)))?;
        let mut writer = ZipWriter::new(output);
        let mut decrypted_files = HashSet::new();

        // Decrypt and write decrypted files
        for encrypted_file in self.encrypted_resources()?.iter() {
            let data = read_binary_from_archive(&mut self.archive, &encrypted_file.uri)?
                .ok_or_else(|| {
                    EpubError::MissingRequiredFile(format!(
                        "Invalid path in encryption.xml: {:?}",
                        &encrypted_file
                    ))
                })?;

            let decrypted_data = decrypt_aes_256_cbc_with_prepended_iv(&data, content_key.key())
                .map_err(|e| EpubError::DecryptionFailed(e.to_string()))?;

            let uncompressed_decrypted_data = if !encrypted_file.is_compressed {
                decrypted_data
            } else {
                deflate_uncompress(&decrypted_data)
                    .map_err(|e| EpubError::DecompressionFailed(format!("{:?}", e)))?
            };
            if uncompressed_decrypted_data.len() != encrypted_file.original_length {
                return Err(EpubError::InvalidDecryptedLength {
                    original: encrypted_file.original_length,
                    decrypted: uncompressed_decrypted_data.len(),
                });
            }
            // no need to compress already compressed files
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            let path = &encrypted_file.uri;
            decrypted_files.insert(path.clone());
            writer
                .start_file(&path, options)
                .map_err(|e| EpubError::WriteFailed(format!("Failed to start file: {}", e)))?;

            writer
                .write_all(&uncompressed_decrypted_data)
                .map_err(|e| EpubError::WriteFailed(format!("Failed to write to file: {}", e)))?;
        }
        // Copy all remaining non encrypted files from reader to writer
        // Copy all other files that don't need encryption
        for i in 0..self.archive.len() {
            let file = self.archive.by_index(i).map_err(|e| {
                EpubError::ArchiveReadFailed(format!("Failed to read entry {}: {}", i, e))
            })?;
            let name = file.name().to_string();
            // Skip files that we don't need in decrypted epub
            if name == ENCRYPTION_FILE || name == LICENSE_FILE {
                continue;
            }
            // Skip files that we decrypted already
            if decrypted_files.contains(&name) {
                continue;
            }
            // Copy everything else
            writer
                .raw_copy_file(file)
                .map_err(|e| EpubError::WriteFailed(format!("Failed to copy {}: {}", name, e)))?;
        }

        Ok(writer)
    }

    /// Returns a list of encrypted resources from encryption.xml.
    ///
    /// This parses the `META-INF/encryption.xml` file and returns information
    /// about each encrypted file, including its path, compression status,
    /// and original length.
    ///
    /// Returns an error if the EPUB doesn't have an encryption.xml file
    /// or if the file cannot be parsed.
    pub fn encrypted_resources(&self) -> Result<Vec<EncryptedFileInfo>, EpubError> {
        let encryption_xml = self
            .encryption
            .as_ref()
            .ok_or_else(|| EpubError::MissingRequiredFile(ENCRYPTION_FILE.to_string()))?;

        parse_encryption_xml(encryption_xml).map_err(EpubError::XmlParseFailed)
    }
}

#[cfg(test)]
mod tests {}
