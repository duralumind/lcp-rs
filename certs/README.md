# Generating Test Certificates with OpenSSL

## Step 1: Generate the Root Certificate (Self-Signed)

This is your "License Authority" - the trust anchor that will be embedded in your library.

```bash
# 1a. Generate the Root CA private key (keep this secret!)
openssl genrsa -out root_ca.key 2048

# 1b. Create a self-signed Root Certificate (valid for 10 years)
openssl req -x509 -new -nodes -key root_ca.key \
    -sha256 -days 3650 \
    -subj "/C=US/ST=California/L=SanFrancisco/O=TestLicenseAuthority/CN=Test LCP Root CA" \
    -out root_ca.crt
```

This gives you:
- `root_ca.key` - Root CA private key (you'll use this to sign Provider Certificates)
- `root_ca.crt` - Root CA certificate in PEM format (this gets embedded in your binary)

## Step 2: Generate the Provider Certificate (Signed by Root)

This is what a Content Provider (bookstore) would have. It gets included in every License Document.

```bash
# 2a. Generate the Provider's private key
openssl genrsa -out provider.key 2048

# 2b. Create a Certificate Signing Request (CSR)
openssl req -new -key provider.key \
    -subj "/C=US/ST=California/L=SanFrancisco/O=TestDuralumind/CN=Test Content Provider" \
    -out provider.csr

# 2c. Sign the CSR with the Root CA to create the Provider Certificate
openssl x509 -req -in provider.csr \
    -CA root_ca.crt -CAkey root_ca.key -CAcreateserial \
    -days 365 -sha256 \
    -out provider.crt
```

This gives you:
- `provider.key` - Provider's private key (used to sign License Documents)
- `provider.crt` - Provider Certificate in PEM format (embedded in `signature.certificate`)

## Step 3: Convert to DER Format (What LCP Uses)

LCP uses DER (binary) format, base64-encoded. The PEM files above are already base64, but with headers. Here's how to get raw DER:

```bash
# Convert Root CA to DER (for embedding in binary)
openssl x509 -in root_ca.crt -outform DER -out root_ca.der

# Convert Provider cert to DER (for embedding in license)
openssl x509 -in provider.crt -outform DER -out provider.der

# Convert Provider private key to DER/PKCS#8 (for signing)
openssl pkcs8 -topk8 -inform PEM -outform DER -nocrypt \
    -in provider.key -out provider_private.der
```

## Step 4: Verify the Chain (Optional Sanity Check)

```bash
# Verify that the provider cert was signed by the root
openssl verify -CAfile root_ca.crt provider.crt
# Should output: provider.crt: OK
```

## File Reference

| File | Format | Contains | Used For |
|------|--------|----------|----------|
| `root_ca.key` | PEM | Root private key | Signing new Provider Certificates |
| `root_ca.der` | DER | Root certificate | Embedded in readers for verification |
| `provider.key` | PEM | Provider private key | Signing License Documents |
| `provider.der` | DER | Provider certificate | Embedded in `signature.certificate` |
