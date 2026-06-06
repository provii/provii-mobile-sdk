# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: security@provii.app

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Coordinated Disclosure

Vulnerabilities will be publicly disclosed within 90 days of a fix being available. If no fix is forthcoming, we may disclose earlier to protect users. We follow a coordinated disclosure model: the reporter is credited (unless they prefer anonymity) and given reasonable advance notice before public disclosure.

## Supply Chain Security

This project implements SLSA Level 3 supply chain security:

All releases are signed with Sigstore keyless signing. SLSA provenance attestations accompany every artifact. Dependencies are locked via `Cargo.lock` for reproducible builds. Automated `cargo audit` runs on every build.

### Verifying Releases

```bash
# 1. Download release artifacts
gh release download v0.1.0 --repo provii/provii-mobile-sdk

# 2. Verify checksum
sha256sum -c provii-mobile-sdk-bundle.tar.gz.sha256

# 3. Verify Sigstore signature
cosign verify-blob \
  --bundle provii-mobile-sdk-bundle.cosign-bundle \
  --certificate-identity-regexp="https://github.com/provii/provii-mobile-sdk/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  provii-mobile-sdk-bundle.tar.gz

# 4. Verify SLSA provenance (optional)
slsa-verifier verify-artifact \
  provii-mobile-sdk-bundle.tar.gz \
  --provenance-path provii-mobile-sdk.intoto.jsonl \
  --source-uri github.com/provii/provii-mobile-sdk
```

## Security Features

### Memory Safety

All sensitive data is zeroised on drop using the `zeroize` crate. No plaintext credential storage occurs; all credentials reside in platform secure storage. The FFI boundary uses safe error propagation (no panics across FFI).

### Cryptographic Security

BLS12-381 curve for zero knowledge proofs. Groth16 proving system via bellman. Constant-time operations for cryptographic primitives. RedJubjub signatures for credential authentication.

### Platform Security

On iOS, the Keychain with Secure Enclave support provides hardware-backed protection. On Android, the hardware-backed Keystore (API 29+) serves the same role. Credentials never leave secure hardware when available.

### Build Security

All builds use the `--locked` flag ensuring exact dependency versions. `Cargo.lock` is committed to the repository. Dependencies are audited via `cargo-audit`, and CI builds are hermetic (no network access during build).
