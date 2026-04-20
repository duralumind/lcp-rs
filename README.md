# lcp-rs

A Rust implementation of the Readium LCP (Licensed Content Protection) [specification](https://readium.org/lcp-specs/). Implements the **basic profile** with extension traits for custom encryption profiles.

## Features

- EPUB encryption/decryption for the [basic profile](https://readium.org/lcp-specs/releases/lcp/latest.html#63-basic-encryption-profile-10)
- License Status Document (LSD) parsing
- Extensible `Transform` and `TransformResolver` trait for proprietary profiles
- KOReader plugin for Kobo e-readers

## Workspace Structure

│   ├── lcp-core/       # Core library: encryption, decryption, license/LSD handling
│   ├── lcp-cli/        # Command-line tool
│   └── plugin/         # FFI library for KOReader
└── lcpreader.koplugin/ # KOReader Lua plugin

## KOReader Plugin

Plugin for reading LCP-protected EPUBs on KOReader.
The plugin crate basically wraps the decryption functions in the core crate to create a shared library that is used by `lcpreader.koplugin` lua plugin to do the actual decryption on device.
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

## Implementing Custom Encryption Profiles

LCP uses a secret transform on the passphrase hash to derive the encryption key. Implement `Transform` and `TransformResolver` to support custom profiles.

This would allow EDRLabs or any provider with access to the production profiles to simply import the core crate, implement the transforms in rust and create a `Production` resolver to 

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
            "http://example.com/lcp/production-1.0" => Ok(Box::new(MyTransform::Production1_0)),
            "http://example.com/lcp/production-1.1" => Ok(Box::new(MyTransform::Production1_1)),
            other => Err(format!("Unsupported profile: {}", other)),
        }
    }
}
```

### 3. Use the resolver

```rust
let resolver = ProductionResolver;

// Encrypt
encrypt_epub(input, password, hint, "http://example.com/lcp/production-1.0", &resolver, ...)?;

// Decrypt (transform selected automatically from license)
decrypt_epub(input, None, password, output, root_ca, &resolver)?;
```

## License

MIT
