use std::collections::HashSet;
use std::io::Seek;
use std::{fs::File, io::Read, path::PathBuf};
use zip::ZipArchive;
use zip::write::{SimpleFileOptions, ZipWriter};

use crate::{
    crypto::{cipher::aes_cbc256::*, key::ContentKey},
    license::License,
};

pub mod xml_utils;

pub use xml_utils::{
    EncryptedFileInfo, ManifestItem, find_element_attr, get_opf_base_path, parse_container_xml,
    parse_opf_manifest, write_encryption_xml,
};

use flate2::Compression;
use flate2::write::DeflateEncoder;
use std::io::Write;

/// Compress data using the Deflate algorithm.
pub fn deflate_compress(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
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
) -> Result<Option<String>, String> {
    let Ok(mut zipfile) = archive.by_path(filename) else {
        return Ok(None);
    };
    let mut target = Vec::with_capacity(zipfile.size() as usize);
    zipfile
        .read_to_end(&mut target)
        .map_err(|e| format!("Failed to read container.xml file, err: {}", e))?;
    String::from_utf8(target)
        .map(Some)
        .map_err(|e| format!("Invalid string data in container.xml, err: {}", e))
}

fn read_binary_from_archive(
    archive: &mut ZipArchive<File>,
    filename: &str,
) -> Result<Option<Vec<u8>>, String> {
    let Ok(mut zipfile) = archive.by_path(filename) else {
        return Ok(None);
    };
    let mut buffer = Vec::with_capacity(zipfile.size() as usize);
    zipfile
        .read_to_end(&mut buffer)
        .map_err(|e| format!("Failed to read {}, err: {}", filename, e))?;
    Ok(Some(buffer))
}

/// Internal representation of an epub file with all required elements for
/// 1. encrypting a epub publication to a lcp encrypted epub.
/// 2. decrypting a lcp encrypted epub to a regular epub.
#[derive(Debug)]
pub struct Epub {
    archive: ZipArchive<File>,
    container: String,
    encryption: Option<String>,
    license: Option<License>,
}

impl Epub {
    /// Load a type `Self` from the given path.
    pub fn new(path: PathBuf) -> Result<Self, String> {
        let epub_file = File::open(&path).map_err(|e| format!("Unable to open file {}", e))?;
        let mut zip = zip::ZipArchive::new(epub_file)
            .map_err(|e| format!("Unable to read epub archive {}", e))?;
        let container = read_file_from_archive(&mut zip, CONTAINER_FILE)?
            .ok_or_else(|| "metadata must container container.xml".to_string())?;
        let encryption = read_file_from_archive(&mut zip, ENCRYPTION_FILE)?;
        let license: Option<License> = read_file_from_archive(&mut zip, LICENSE_FILE)?
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .map_err(|e| format!("failed to parse lcpl json: {}", e))?;

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

    /// Writes a new zip archive in the given output path with the metadata files from the
    /// orginal archive and the encrypted content files
    pub fn write_encrypted_epub(
        &mut self,
        output: PathBuf,
        content_key: &ContentKey,
    ) -> Result<(), String> {
        // Create the writer
        let output = File::create(output).map_err(|e| format!("Unable to open file {}", e))?;
        let mut writer = ZipWriter::new(output);

        // Clone the reader
        let manifest_items_to_encrypt = self
            .clone_reader(&mut writer)
            .map_err(|e| format!("Failed to clone reader {}", e))?;
        let mut encrypted_files = Vec::new();
        let opf_path = self.opf_path()?;
        let base_path = get_opf_base_path(&opf_path);
        // Encrypt and write
        for manifest in manifest_items_to_encrypt {
            let data = read_binary_from_archive(&mut self.archive, &manifest.href)?
                .ok_or(format!("Invalid path in opf manifest: {:?}", &manifest))?;
            let len = data.len();
            let compressed_data = if manifest.is_codec() {
                data
            } else {
                deflate_compress(&data).map_err(|e| format!("Deflate write error: {:?}", e))?
            };
            let encrypted_data =
                encrypt_aes_256_cbc_with_random_iv(&compressed_data, content_key.key());
            // no need to compress already compressed files
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            let path = format!("{}{}", base_path, manifest.href);
            writer
                .start_file(&path, options)
                .map_err(|e| format!("Failed to start file {}", e))?;

            writer
                .write_all(&encrypted_data)
                .map_err(|e| format!("Failed to write to file {}", e))?;

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
            .map_err(|e| format!("Failed to start file {}", e))?;
        writer
            .write_all(encryption_xml.as_bytes())
            .map_err(|e| format!("Failed to write to file {}", e))?;

        // TODO(write license)
        // let license_json = serde_json::to_string(&license)?;
        // writer
        //     .start_file(LICENSE_FILE, SimpleFileOptions::default())
        //     .map_err(|e| format!("Failed to start file {}", e))?;
        // writer
        //     .write_all(license_json.as_bytes())
        //     .map_err(|e| format!("Failed to write to file {}", e))?;

        // Finalize
        writer.finish().map_err(|e| format!("Failed to finish writing file {}", e))?;

        Ok(())
    }

    /// Returns the path to the OPF file from container.xml.
    pub fn opf_path(&self) -> Result<String, String> {
        xml_utils::parse_container_xml(&self.container)
    }

    /// Returns a list of manifest items from the opf file.
    pub fn manifest_items(&mut self) -> Result<Vec<ManifestItem>, String> {
        let opf_path = self.opf_path()?;
        let manifest = read_file_from_archive(&mut self.archive, &opf_path)?
            .ok_or("manifest file should be in the path pointed by container.xml".to_string())?;
        let manifest_items = parse_opf_manifest(&manifest)?;

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
    ) -> Result<Vec<ManifestItem>, String> {
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
                .map_err(|e| format!("Failed to copy mimetype: {}", e))?;
        }

        // Copy all other files that don't need encryption
        for i in 0..self.archive.len() {
            let file = self
                .archive
                .by_index(i)
                .map_err(|e| format!("Failed to read archive entry {}: {}", i, e))?;
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
            dbg!(&file.name());
            writer
                .raw_copy_file(file)
                .map_err(|e| format!("Failed to copy {}: {}", name, e))?;
        }

        Ok(items_to_encrypt)
    }
}

#[cfg(test)]
mod tests {}
