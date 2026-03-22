//! XML parsing utilities for EPUB metadata files.
//!
//! Provides helper functions for working with `roxmltree` and string-based
//! XML generation for `encryption.xml`.
//!
//! Note: this file is completely AI generated. I did not have the patience to parse xml.

use roxmltree::{Document, Node};

// =============================================================================
// roxmltree Helper Functions
// =============================================================================

/// Find the first descendant element with the given local name.
pub fn find_element<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    node.descendants()
        .find(|n| n.is_element() && n.tag_name().name() == name)
}

/// Find all descendant elements with the given local name.
pub fn find_all_elements<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Vec<Node<'a, 'input>> {
    node.descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == name)
        .collect()
}

/// Find element and get its attribute in one call.
pub fn find_element_attr<'a, 'input>(
    node: Node<'a, 'input>,
    element: &str,
    attr: &str,
) -> Option<&'a str> {
    find_element(node, element).and_then(|n| n.attribute(attr))
}

/// Find element and get its text content.
#[allow(dead_code)]
pub fn find_element_text<'a, 'input>(node: Node<'a, 'input>, element: &str) -> Option<&'a str> {
    find_element(node, element).and_then(|n| n.text())
}

// =============================================================================
// Data Structures
// =============================================================================

/// Represents an item from the OPF manifest.
#[derive(Debug, Clone)]
pub struct ManifestItem {
    /// The unique identifier for this item within the manifest.
    pub id: String,
    /// The relative path to the resource.
    pub href: String,
    /// The MIME type of the resource.
    pub media_type: String,
    /// Optional properties (e.g., "nav", "cover-image").
    pub properties: Option<String>,
    /// Whether this item is the cover image (detected via EPUB 2 or EPUB 3 metadata).
    pub is_cover: bool,
}

impl ManifestItem {
    /// Returns true if this item should NOT be encrypted per LCP spec.
    ///
    /// The following are exempt from encryption:
    /// - Navigation documents (properties contains "nav")
    /// - Cover images (properties contains "cover-image" OR identified via EPUB 2 metadata)
    /// - NCX documents (media-type is "application/x-dtbncx+xml")
    pub fn is_encryption_exempt(&self) -> bool {
        // Navigation documents
        if self.properties.as_ref().is_some_and(|p| p.contains("nav")) {
            return true;
        }
        // Cover images (EPUB 3 style via properties)
        if self
            .properties
            .as_ref()
            .is_some_and(|p| p.contains("cover-image"))
        {
            return true;
        }
        // Cover images (EPUB 2 style via <meta name="cover"> or EPUB 3)
        if self.is_cover {
            return true;
        }
        // NCX documents
        if self.media_type == "application/x-dtbncx+xml" {
            return true;
        }
        false
    }

    /// Returns true if this is a codec type (should NOT be compressed before encryption).
    ///
    /// Codec types include:
    /// - Images (except SVG)
    /// - Audio
    /// - Video
    /// - PDF
    pub fn is_codec(&self) -> bool {
        (self.media_type.starts_with("image/") && self.media_type != "image/svg+xml")
            || self.media_type.starts_with("audio/")
            || self.media_type.starts_with("video/")
            || self.media_type == "application/pdf"
    }
}

/// Information about an encrypted file.
///
/// Used both for generating encryption.xml during encryption and for
/// parsing encryption.xml during decryption.
#[derive(Debug, Clone)]
pub struct EncryptedFileInfo {
    /// The relative URI path within the EPUB.
    pub uri: String,
    /// Whether the file was compressed (deflated) before encryption.
    pub is_compressed: bool,
    /// The original length of the file before compression/encryption.
    pub original_length: usize,
}

// =============================================================================
// Container.xml Parsing
// =============================================================================

/// Parse container.xml to extract the path to the OPF (Package Document).
///
/// The container.xml file contains a `<rootfile>` element with a `full-path`
/// attribute pointing to the OPF file.
pub fn parse_container_xml(xml: &str) -> Result<String, String> {
    let doc = Document::parse(xml).map_err(|e| format!("Failed to parse container.xml: {}", e))?;

    find_element_attr(doc.root_element(), "rootfile", "full-path")
        .map(|s| s.to_string())
        .ok_or_else(|| "No rootfile found in container.xml".to_string())
}

// =============================================================================
// OPF Manifest Parsing
// =============================================================================

/// Parse the OPF Package Document to extract manifest items.
///
/// Returns a list of all `<item>` elements from the `<manifest>` section.
/// Also detects the cover image using both EPUB 2 (`<meta name="cover">`) and
/// EPUB 3 (`properties="cover-image"`) methods.
pub fn parse_opf_manifest(xml: &str) -> Result<Vec<ManifestItem>, String> {
    let doc = Document::parse(xml).map_err(|e| format!("Failed to parse OPF: {}", e))?;

    // Look for EPUB 2 style cover: <meta name="cover" content="cover-id"/>
    // The content attribute contains the manifest item ID of the cover image
    let epub2_cover_id: Option<String> =
        find_element(doc.root_element(), "metadata").and_then(|metadata| {
            find_all_elements(metadata, "meta")
                .into_iter()
                .find(|meta| meta.attribute("name") == Some("cover"))
                .and_then(|meta| meta.attribute("content").map(|s| s.to_string()))
        });

    let manifest = find_element(doc.root_element(), "manifest")
        .ok_or_else(|| "No manifest found in OPF".to_string())?;

    let items = find_all_elements(manifest, "item")
        .into_iter()
        .filter_map(|node| {
            let id = node.attribute("id")?.to_string();
            let properties = node.attribute("properties").map(|s| s.to_string());

            // Check if this is the cover image (EPUB 2 or EPUB 3)
            let is_cover = epub2_cover_id.as_ref() == Some(&id)
                || properties
                    .as_ref()
                    .is_some_and(|p| p.contains("cover-image"));

            Some(ManifestItem {
                id,
                href: node.attribute("href")?.to_string(),
                media_type: node.attribute("media-type")?.to_string(),
                properties,
                is_cover,
            })
        })
        .collect();

    Ok(items)
}

/// Get the directory containing the OPF file (for resolving relative paths).
///
/// For example, if the OPF path is "OEBPS/content.opf", this returns "OEBPS/".
/// If the OPF is at the root, this returns an empty string.
pub fn get_opf_base_path(opf_path: &str) -> &str {
    match opf_path.rfind('/') {
        Some(idx) => &opf_path[..=idx],
        None => "",
    }
}

// =============================================================================
// Encryption.xml Writing
// =============================================================================

/// Escape special XML characters in a string.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Generate the encryption.xml content for a list of encrypted files.
///
/// This creates the XML structure required by the LCP specification,
/// with each encrypted file represented as an `<enc:EncryptedData>` element.
pub fn write_encryption_xml(encrypted_files: &[EncryptedFileInfo]) -> String {
    let mut entries = String::new();

    for file in encrypted_files {
        entries.push_str(&format!(
            r#"
    <enc:EncryptedData>
        <enc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
        <ds:KeyInfo>
            <ds:RetrievalMethod URI="license.lcpl#/encryption/content_key"
                Type="http://readium.org/2014/01/lcp#EncryptedContentKey"/>
        </ds:KeyInfo>
        <enc:CipherData>
            <enc:CipherReference URI="{}"/>
        </enc:CipherData>
        <enc:EncryptionProperties>
            <enc:EncryptionProperty xmlns:ns="http://www.idpf.org/2016/encryption#compression">
                <ns:Compression Method="{}" OriginalLength="{}"/>
            </enc:EncryptionProperty>
        </enc:EncryptionProperties>
    </enc:EncryptedData>"#,
            xml_escape(&file.uri),
            if file.is_compressed { "8" } else { "0" },
            file.original_length
        ));
    }

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<encryption
    xmlns="urn:oasis:names:tc:opendocument:xmlns:container"
    xmlns:enc="http://www.w3.org/2001/04/xmlenc#"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{entries}
</encryption>"#
    )
}

// =============================================================================
// Encryption.xml Parsing
// =============================================================================

/// Parse encryption.xml to extract the list of encrypted resources.
///
/// Returns a list of `EncryptedFileInfo` with paths and compression info
/// needed for decryption.
///
/// # Arguments
/// * `xml` - The contents of the encryption.xml file as a string
///
/// # Returns
/// A vector of `EncryptedFileInfo` structs, one for each encrypted file in the EPUB.
pub fn parse_encryption_xml(xml: &str) -> Result<Vec<EncryptedFileInfo>, String> {
    let doc = Document::parse(xml).map_err(|e| format!("Failed to parse encryption.xml: {}", e))?;

    let encrypted_data_elements = find_all_elements(doc.root_element(), "EncryptedData");

    let mut resources = Vec::with_capacity(encrypted_data_elements.len());

    for encrypted_data in encrypted_data_elements {
        // Extract the URI from CipherData/CipherReference
        let uri = find_element(encrypted_data, "CipherReference")
            .and_then(|node| node.attribute("URI"))
            .map(|s| s.to_string())
            .ok_or_else(|| "EncryptedData missing CipherReference URI".to_string())?;

        // Extract compression info from EncryptionProperties/EncryptionProperty/Compression
        // Method="8" means deflate compression, Method="0" means no compression
        let (is_compressed, original_length) =
            if let Some(compression) = find_element(encrypted_data, "Compression") {
                let method = compression.attribute("Method").unwrap_or("0");
                let is_compressed = method == "8";

                let original_length = compression
                    .attribute("OriginalLength")
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(0);

                (is_compressed, original_length)
            } else {
                // Default: assume not compressed, unknown length
                (false, 0)
            };

        resources.push(EncryptedFileInfo {
            uri,
            is_compressed,
            original_length,
        });
    }

    Ok(resources)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_container_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
    <rootfiles>
        <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
    </rootfiles>
</container>"#;

        let result = parse_container_xml(xml).unwrap();
        assert_eq!(result, "OEBPS/content.opf");
    }

    #[test]
    fn test_parse_opf_manifest() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0">
    <manifest>
        <item id="nav" href="nav.xhtml" media-type="application/xhtml+xml" properties="nav"/>
        <item id="cover" href="cover.jpg" media-type="image/jpeg" properties="cover-image"/>
        <item id="chapter1" href="chapter1.xhtml" media-type="application/xhtml+xml"/>
        <item id="ncx" href="toc.ncx" media-type="application/x-dtbncx+xml"/>
        <item id="style" href="style.css" media-type="text/css"/>
    </manifest>
</package>"#;

        let items = parse_opf_manifest(xml).unwrap();
        assert_eq!(items.len(), 5);

        // Check nav is exempt
        let nav = items.iter().find(|i| i.id == "nav").unwrap();
        assert!(nav.is_encryption_exempt());

        // Check cover is exempt
        let cover = items.iter().find(|i| i.id == "cover").unwrap();
        assert!(cover.is_encryption_exempt());
        assert!(cover.is_codec());

        // Check ncx is exempt
        let ncx = items.iter().find(|i| i.id == "ncx").unwrap();
        assert!(ncx.is_encryption_exempt());

        // Check chapter is NOT exempt
        let chapter = items.iter().find(|i| i.id == "chapter1").unwrap();
        assert!(!chapter.is_encryption_exempt());
        assert!(!chapter.is_codec());

        // Check CSS is NOT exempt and NOT codec
        let style = items.iter().find(|i| i.id == "style").unwrap();
        assert!(!style.is_encryption_exempt());
        assert!(!style.is_codec());
    }

    #[test]
    fn test_write_encryption_xml() {
        let files = vec![
            EncryptedFileInfo {
                uri: "OEBPS/chapter1.xhtml".to_string(),
                is_compressed: true,
                original_length: 12345,
            },
            EncryptedFileInfo {
                uri: "OEBPS/image.jpg".to_string(),
                is_compressed: false,
                original_length: 67890,
            },
        ];

        let xml = write_encryption_xml(&files);

        // Verify basic structure
        assert!(xml.contains(r#"<?xml version="1.0" encoding="UTF-8"?>"#));
        assert!(xml.contains(r#"xmlns:enc="http://www.w3.org/2001/04/xmlenc#""#));
        assert!(xml.contains(r#"URI="OEBPS/chapter1.xhtml""#));
        assert!(xml.contains(r#"Method="8" OriginalLength="12345""#));
        assert!(xml.contains(r#"URI="OEBPS/image.jpg""#));
        assert!(xml.contains(r#"Method="0" OriginalLength="67890""#));
    }

    #[test]
    fn test_xml_escape() {
        assert_eq!(xml_escape("hello"), "hello");
        assert_eq!(xml_escape("a & b"), "a &amp; b");
        assert_eq!(xml_escape("<tag>"), "&lt;tag&gt;");
        assert_eq!(xml_escape(r#"say "hi""#), "say &quot;hi&quot;");
    }

    #[test]
    fn test_manifest_item_is_codec() {
        let jpeg = ManifestItem {
            id: "img".to_string(),
            href: "image.jpg".to_string(),
            media_type: "image/jpeg".to_string(),
            properties: None,
            is_cover: false,
        };
        assert!(jpeg.is_codec());

        let svg = ManifestItem {
            id: "img".to_string(),
            href: "image.svg".to_string(),
            media_type: "image/svg+xml".to_string(),
            properties: None,
            is_cover: false,
        };
        assert!(!svg.is_codec()); // SVG is NOT codec (it's text-based)

        let audio = ManifestItem {
            id: "audio".to_string(),
            href: "sound.mp3".to_string(),
            media_type: "audio/mpeg".to_string(),
            properties: None,
            is_cover: false,
        };
        assert!(audio.is_codec());

        let html = ManifestItem {
            id: "ch1".to_string(),
            href: "chapter1.xhtml".to_string(),
            media_type: "application/xhtml+xml".to_string(),
            properties: None,
            is_cover: false,
        };
        assert!(!html.is_codec());
    }

    #[test]
    fn test_epub2_cover_detection() {
        // EPUB 2 style: cover identified via <meta name="cover" content="cover-id"/>
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<package xmlns="http://www.idpf.org/2007/opf" version="2.0">
    <metadata xmlns:opf="http://www.idpf.org/2007/opf">
        <meta name="cover" content="cover-img"/>
    </metadata>
    <manifest>
        <item id="cover-img" href="cover.jpeg" media-type="image/jpeg"/>
        <item id="chapter1" href="chapter1.xhtml" media-type="application/xhtml+xml"/>
        <item id="other-img" href="image.png" media-type="image/png"/>
    </manifest>
</package>"#;

        let items = parse_opf_manifest(xml).unwrap();
        assert_eq!(items.len(), 3);

        // Cover should be detected and exempt
        let cover = items.iter().find(|i| i.id == "cover-img").unwrap();
        assert!(cover.is_cover);
        assert!(cover.is_encryption_exempt());

        // Other image should NOT be marked as cover
        let other = items.iter().find(|i| i.id == "other-img").unwrap();
        assert!(!other.is_cover);
        assert!(!other.is_encryption_exempt());

        // Chapter should NOT be marked as cover
        let chapter = items.iter().find(|i| i.id == "chapter1").unwrap();
        assert!(!chapter.is_cover);
        assert!(!chapter.is_encryption_exempt());
    }

    #[test]
    fn test_epub3_cover_detection() {
        // EPUB 3 style: cover identified via properties="cover-image"
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0">
    <metadata>
    </metadata>
    <manifest>
        <item id="cover" href="cover.jpg" media-type="image/jpeg" properties="cover-image"/>
        <item id="chapter1" href="chapter1.xhtml" media-type="application/xhtml+xml"/>
    </manifest>
</package>"#;

        let items = parse_opf_manifest(xml).unwrap();
        assert_eq!(items.len(), 2);

        // Cover should be detected via properties and is_cover flag
        let cover = items.iter().find(|i| i.id == "cover").unwrap();
        assert!(cover.is_cover);
        assert!(cover.is_encryption_exempt());

        // Chapter should NOT be marked as cover
        let chapter = items.iter().find(|i| i.id == "chapter1").unwrap();
        assert!(!chapter.is_cover);
        assert!(!chapter.is_encryption_exempt());
    }

    #[test]
    fn test_parse_encryption_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<encryption
    xmlns="urn:oasis:names:tc:opendocument:xmlns:container"
    xmlns:enc="http://www.w3.org/2001/04/xmlenc#"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <enc:EncryptedData>
        <enc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
        <ds:KeyInfo>
            <ds:RetrievalMethod URI="license.lcpl#/encryption/content_key"
                Type="http://readium.org/2014/01/lcp#EncryptedContentKey"/>
        </ds:KeyInfo>
        <enc:CipherData>
            <enc:CipherReference URI="OEBPS/chapter1.xhtml"/>
        </enc:CipherData>
        <enc:EncryptionProperties>
            <enc:EncryptionProperty xmlns:ns="http://www.idpf.org/2016/encryption#compression">
                <ns:Compression Method="8" OriginalLength="12345"/>
            </enc:EncryptionProperty>
        </enc:EncryptionProperties>
    </enc:EncryptedData>
    <enc:EncryptedData>
        <enc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
        <ds:KeyInfo>
            <ds:RetrievalMethod URI="license.lcpl#/encryption/content_key"
                Type="http://readium.org/2014/01/lcp#EncryptedContentKey"/>
        </ds:KeyInfo>
        <enc:CipherData>
            <enc:CipherReference URI="OEBPS/image.jpg"/>
        </enc:CipherData>
        <enc:EncryptionProperties>
            <enc:EncryptionProperty xmlns:ns="http://www.idpf.org/2016/encryption#compression">
                <ns:Compression Method="0" OriginalLength="67890"/>
            </enc:EncryptionProperty>
        </enc:EncryptionProperties>
    </enc:EncryptedData>
</encryption>"#;

        let resources = parse_encryption_xml(xml).unwrap();
        assert_eq!(resources.len(), 2);

        // First resource: compressed chapter
        let chapter = &resources[0];
        assert_eq!(chapter.uri, "OEBPS/chapter1.xhtml");
        assert!(chapter.is_compressed);
        assert_eq!(chapter.original_length, 12345);

        // Second resource: uncompressed image
        let image = &resources[1];
        assert_eq!(image.uri, "OEBPS/image.jpg");
        assert!(!image.is_compressed);
        assert_eq!(image.original_length, 67890);
    }

    #[test]
    fn test_parse_encryption_xml_missing_compression() {
        // Test that missing compression info uses defaults
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<encryption
    xmlns="urn:oasis:names:tc:opendocument:xmlns:container"
    xmlns:enc="http://www.w3.org/2001/04/xmlenc#"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <enc:EncryptedData>
        <enc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
        <enc:CipherData>
            <enc:CipherReference URI="OEBPS/chapter1.xhtml"/>
        </enc:CipherData>
    </enc:EncryptedData>
</encryption>"#;

        let resources = parse_encryption_xml(xml).unwrap();
        assert_eq!(resources.len(), 1);

        let chapter = &resources[0];
        assert_eq!(chapter.uri, "OEBPS/chapter1.xhtml");
        // Defaults when compression info is missing
        assert!(!chapter.is_compressed);
        assert_eq!(chapter.original_length, 0);
    }

    #[test]
    fn test_parse_encryption_xml_roundtrip() {
        // Test that write_encryption_xml output can be parsed by parse_encryption_xml
        let files = vec![
            EncryptedFileInfo {
                uri: "OEBPS/chapter1.xhtml".to_string(),
                is_compressed: true,
                original_length: 12345,
            },
            EncryptedFileInfo {
                uri: "OEBPS/image.jpg".to_string(),
                is_compressed: false,
                original_length: 67890,
            },
        ];

        let xml = write_encryption_xml(&files);
        let resources = parse_encryption_xml(&xml).unwrap();

        assert_eq!(resources.len(), 2);

        assert_eq!(resources[0].uri, "OEBPS/chapter1.xhtml");
        assert!(resources[0].is_compressed);
        assert_eq!(resources[0].original_length, 12345);

        assert_eq!(resources[1].uri, "OEBPS/image.jpg");
        assert!(!resources[1].is_compressed);
        assert_eq!(resources[1].original_length, 67890);
    }
}
