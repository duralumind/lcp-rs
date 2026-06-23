# lcp-rs

A Rust implementation of the Readium LCP (Licensed Content Protection) [specification](https://readium.org/lcp-specs/). Implements the **basic profile** with extension traits for custom encryption profiles.

## Features

- EPUB encryption/decryption for the [basic profile](https://readium.org/lcp-specs/releases/lcp/latest.html#63-basic-encryption-profile-10)
- Session API for reader apps to unlock once and decrypt individual EPUB resources
- License Status Document (LSD) parsing
- Extensible `Transform` and `TransformResolver` trait for proprietary profiles
- KOReader plugin for Kobo e-readers

## KOReader Plugin

Plugin for reading LCP-protected EPUBs on KOReader.
The plugin crate wraps the session engine in the core crate to create a shared library that is used by the `lcpreader.koplugin` Lua plugin to decrypt on device.
The plugin intercepts the FileManager on KOReader when it detects a LCP encrypted epub and prompts the user for a password, decrypts it and then caches the password on device.

### Installation

Copy `lcpreader.koplugin/` to `/mnt/onboard/.adds/koreader/plugins/` on your Kobo.
The plugin directory already contains the compiled shared library files for the Kobo Libra Color.

For other devices, you may need to manually compile the plugin and copy it to the `lcpreader.koplugin/libs` folder.

I have tested this on the Kobo Libra Color.

### Building for Kobo

**macOS (Apple Silicon):**

```bash
rustup target add armv7-unknown-linux-gnueabihf
brew tap messense/macos-cross-toolchains
brew install arm-unknown-linux-gnueabihf

make install
```

**Docker (any platform):**

```bash
docker build -f Dockerfile.kobo -t lcp-kobo .
docker run --rm -v $(pwd)/out:/out lcp-kobo
cp out/libreadium_lcp.so lcpreader.koplugin/libs/
```

See [KOBO_BUILD.md](KOBO_BUILD.md) for additional details.

## CLI Usage

```bash
# Encrypt
cargo run -p lcp-cli -- encrypt input.epub --password "secret" --password-hint "hint"

# Decrypt
cargo run -p lcp-cli -- decrypt --input encrypted.epub --password "secret"
```

## Library Usage

Reader apps should use the session API. Open the publication, unlock it with the passphrase selected by the app, then decrypt resources by the exact URI listed in `META-INF/encryption.xml`.

```rust
use lcp_core::{BasicResolver, OpenedPublication};

let resolver = BasicResolver;
let opened = OpenedPublication::open_path(
    "encrypted.epub",
    None,
    root_ca_der,
    &resolver,
)?;

let encrypted_resource_uri = opened.encrypted_resources()[0].uri.clone();
let mut publication = opened.unlock_with_passphrase("secret")?;
let plaintext = publication.decrypt_resource(&encrypted_resource_uri)?;
```

For integrations that still need a fully decrypted EPUB, export from the unlocked session:

```rust
publication.export_decrypted_epub("decrypted.epub")?;
```

## Implementing Custom Encryption Profiles

LCP uses a secret transform on the passphrase hash to derive the encryption key. Implement `Transform` and `TransformResolver` to support custom profiles.

This would allow EDRLabs or any provider with access to the production profiles to import the core crate, implement the transforms in Rust, and create a production resolver.

### 1. Implement `Transform`

```rust
use lcp_core::Transform;

enum ProductionTransforms {
    Production1_0,
    Production1_1,
}

impl Transform for ProductionTransforms {
    fn transform(&self, user_key: [u8; 32]) -> [u8; 32] {
        match self {
            Self::Production1_0 => my_v1_secret_algorithm(user_key),
            Self::Production1_1 => my_v1_1_secret_algorithm(user_key),
        }
    }
}
```

### 2. Implement `TransformResolver`

```rust
use lcp_core::{TransformResolver, Transform, BasicTransform};

struct ProductionResolver;

impl TransformResolver for ProductionResolver {
    fn resolve(&self, profile_uri: &str) -> Result<Box<dyn Transform>, String> {
        match profile_uri {
            "http://readium.org/lcp/basic-profile" => Ok(Box::new(BasicTransform)),
            "http://example.com/lcp/production-1.0" => Ok(Box::new(ProductionTransform::Production1_0)),
            "http://example.com/lcp/production-1.1" => Ok(Box::new(ProductionTransform::Production1_1)),
            other => Err(format!("Unsupported profile: {}", other)),
        }
    }
}
```

### 3. Use the resolver

```rust
use lcp_core::{encrypt_epub, OpenedPublication};

let resolver = ProductionResolver;

// Encrypt
encrypt_epub(source_epub, password, hint, "http://example.com/lcp/production-1.0", &resolver, ...)?;

// Reader-style decrypt (transform selected automatically from license)
let opened = OpenedPublication::open_path(encrypted_epub, None, root_ca, &resolver)?;
let encrypted_resource_uri = opened.encrypted_resources()[0].uri.clone();
let mut publication = opened.unlock_with_passphrase(&password)?;
let plaintext = publication.decrypt_resource(&encrypted_resource_uri)?;

// Full-EPUB export, if needed
publication.export_decrypted_epub(decrypted_epub)?;
```

## License

MIT
