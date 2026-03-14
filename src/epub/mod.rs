use std::{fs::File, io::Read, path::PathBuf};
use zip::ZipArchive;

use crate::license::License;

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

/// Given an ebpub file, unzip it and view list all internal resources
#[derive(Debug)]
pub struct Epub {
    archive: ZipArchive<File>,
    #[allow(unused)]
    container: String,
    encryption: Option<String>,
    license: Option<License>,
}

impl Epub {
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

    pub fn license(&self) -> Option<&License> {
        self.license.as_ref()
    }

    pub fn decrypt_encrypted_content(&mut self, user_key: &[u8; 32]) -> Result<(), String> {
        use super::crypto::cipher::aes_cbc256::decrypt_aes_256_cbc;
        use flate2::read::DeflateDecoder;
        use std::io::Read as _;

        let Some(encrypted_metadata_str) = &self.encryption else {
            return Err("No encrypted metadata file".to_string());
        };
        let Ok(encrypted_metadata) = roxmltree::Document::parse(encrypted_metadata_str) else {
            return Err("Not valid xml encryption metadata".to_string());
        };

        // Decrypt the content key using the user key
        let license = self.license.as_ref().ok_or("No license found in EPUB")?;
        let content_key = license.decrypt_content_key(user_key)?;

        // Parse XML to extract encrypted file paths and compression info
        // Each EncryptedData block contains one encrypted file
        for encrypted_data_node in encrypted_metadata.descendants() {
            if encrypted_data_node.tag_name().name() != "EncryptedData" {
                continue;
            }

            // Extract URI from CipherReference
            let uri = encrypted_data_node
                .descendants()
                .find(|n| n.tag_name().name() == "CipherReference")
                .and_then(|n| n.attribute("URI"));

            let Some(uri) = uri else {
                continue;
            };

            // Extract compression method if present
            let compression_method = encrypted_data_node
                .descendants()
                .find(|n| n.tag_name().name() == "Compression")
                .and_then(|n| n.attribute("Method"));

            // Read the encrypted file from the archive
            let Some(encrypted_data) = read_binary_from_archive(&mut self.archive, uri)? else {
                println!("Warning: Could not find encrypted file: {}", uri);
                continue;
            };

            // Extract IV from first 16 bytes
            if encrypted_data.len() < 16 {
                println!("Warning: File {} is too small to contain IV", uri);
                continue;
            }

            let iv: [u8; 16] = encrypted_data[0..16]
                .try_into()
                .map_err(|_| format!("Invalid IV length for {}", uri))?;

            // Ciphertext is everything after the IV
            let ciphertext = &encrypted_data[16..];

            // Decrypt using content key
            let mut decrypted = decrypt_aes_256_cbc(ciphertext, &content_key, &iv)
                .map_err(|e| format!("Failed to decrypt {}: {}", uri, e))?;

            // Decompress if compression method indicates compression
            // Method="8" is deflate compression (standard ZIP compression method)
            // Method="0" is "stored" (no compression)
            if let Some(method) = compression_method {
                if method == "8" || method.to_lowercase() == "deflate" {
                    let mut decoder = DeflateDecoder::new(&decrypted[..]);
                    let mut decompressed = Vec::new();
                    match decoder.read_to_end(&mut decompressed) {
                        Ok(_) if !decompressed.is_empty() => {
                            decrypted = decompressed;
                        }
                        _ => {
                            println!("Warning: Failed to decompress {} (method={})", uri, method);
                        }
                    }
                }
            }

            // Print file info
            println!("\nDecrypted: {} ({} bytes)", uri, decrypted.len());

            // For text files, print content preview
            if uri.ends_with(".html") || uri.ends_with(".xhtml") || uri.ends_with(".xml") {
                if let Ok(text) = String::from_utf8(decrypted.clone()) {
                    let preview_len = text.len().min(300);
                    println!("Preview: {}", &text[..preview_len]);
                    if text.len() > 300 {
                        println!("...");
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {}
