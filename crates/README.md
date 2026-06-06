# Provii Mobile SDK FFI Bindings

This crate provides Foreign Function Interface (FFI) bindings for the Provii SDK using Mozilla's [UniFFI](https://mozilla.github.io/uniffi-rs/).

## Overview

The FFI layer allows the Rust-based Provii Mobile SDK to be used from:
- **Swift** (iOS/macOS)
- **Kotlin** (Android)

## Architecture

```
┌─────────────────┐     ┌──────────────────┐
│   Swift/iOS     │     │   Kotlin/Android │
└────────┬────────┘     └────────┬─────────┘
         │                       │
         └───────────┬───────────┘
                                 │
                          ┌──────▼──────┐
                          │   UniFFI    │
                          │  Bindings   │
                          └──────┬──────┘
                                 │
                          ┌──────▼──────┐
                          │  FFI Layer  │
                          │ (this crate)│
                          └──────┬──────┘
                                 │
                          ┌──────▼──────┐
                          │provii-mobile│
                          │    core     │
                          └─────────────┘
```

## Building

### Prerequisites

1. Rust toolchain
2. Platform-specific requirements:
   - **iOS**: Xcode and iOS SDK
   - **Android**: Android NDK

### Build Commands

```bash
# Build for current platform
cargo build --release

# Build for iOS (on macOS)
cargo build --release --target aarch64-apple-ios
cargo build --release --target x86_64-apple-ios

# Build for Android
cargo build --release --target aarch64-linux-android
cargo build --release --target armv7-linux-androideabi
cargo build --release --target x86_64-linux-android
```

## Generating Language Bindings

### Using the included script:

```bash
chmod +x generate_bindings.sh
./generate_bindings.sh
```

### Manual generation:

```bash
# Generate Swift bindings
cargo run --bin uniffi-bindgen generate \
    --library target/release/libprovii_mobile_sdk_ffi.dylib \
    --language swift \
    --out-dir ../../bindings/swift

# Generate Kotlin bindings
cargo run --bin uniffi-bindgen generate \
    --library target/release/libprovii_mobile_sdk_ffi.so \
    --language kotlin \
    --out-dir ../../bindings/kotlin
```

## API Overview

### Main Interface: `ProviiWallet`

The primary interface exposed through FFI:

```swift
// Swift example
import ProviiSDK

let appInfo = AppInfo(
    version: "1.0.0",
    buildNumber: "42",
    platform: "iOS",
    deviceModel: nil,
    osVersion: nil
)
let wallet = ProviiWallet(appInfo: appInfo)

// Initialise platform storage
let store = try createDefaultSecureStore()
try wallet.setStorageHandle(handle: store)

// Process a QR challenge and generate an age proof
let challengeId = try wallet.processQrChallenge(qrContent: scannedString)
let proofJson = try wallet.createAgeProofAuto(challengeId: challengeId)
let accepted = try wallet.submitProof(proofJson: proofJson)
```

### Key Features

1. **Credential Issuance**
   - Create blinded credential requests via Pedersen commitments
   - Finalise credentials after blind signing by the issuer

2. **Age Proof Generation**
   - Generate Groth16 zero knowledge proofs over BLS12-381
   - Parallelised proving via Rayon thread pool

3. **Storage**
   - Platform secure storage (iOS Keychain, Android Keystore) by default
   - Import, list, and delete credentials

4. **Verification**
   - Parse QR challenge payloads
   - Submit proofs to the verifier API

## Error Handling

All methods that can fail return a `Result` type that gets translated to:

- **Swift**: `throws` with proper error types
- **Kotlin**: Exceptions

## Security Considerations

1. **Memory Safety**: All sensitive data is zeroised on drop
2. **Platform Secure Storage**: Credentials are persisted in the platform keychain (iOS Keychain, Android Keystore) by default
3. **Constant-Time Operations**: Cryptographic comparisons use the `subtle` crate to prevent timing side channels
4. **FFI Safety**: Safe error propagation across the FFI boundary (no panics)

## Integration Examples

### iOS (Swift)

```swift
import ProviiSDK

class WalletManager {
    private let wallet = ProviiWallet()
    
    func setupWallet() throws {
        // Generate identity if needed
        if !wallet.hasIdentity() {
            wallet.generateIdentity(walletId: UUID().uuidString)
        }
    }
    
    func requestAgeCredential(birthYear: UInt32) throws -> CredentialRequest {
        // In practice, fetch issuer's public key from server
        let issuerKey = try fetchIssuerPublicKey()
        
        return try wallet.requestCredential(
            birthYear: birthYear,
            issuerModulus: issuerKey.modulus,
            issuerExponent: issuerKey.exponent
        )
    }
}
```

### Android (Kotlin)

```kotlin
import app.provii.wallet.*

class WalletManager {
    private val wallet = ProviiWallet()
    
    fun setupWallet() {
        if (!wallet.hasIdentity()) {
            wallet.generateIdentity(UUID.randomUUID().toString())
        }
    }
    
    suspend fun createAgeProof(
        credentialId: ByteArray,
        challenge: Challenge
    ): AgeProof {
        return wallet.createAgeProof(credentialId, challenge)
    }
}
```

## Testing

The FFI layer includes comprehensive tests:

```bash
# Run Rust tests
cargo test
```

## Troubleshooting

### Common Issues

1. **Library not found**: Ensure the native library is in the correct location
2. **Symbol not found**: Rebuild with the correct target architecture
3. **Version mismatch**: Regenerate bindings after updating the FFI interface

### Debug Builds

For debugging, build without optimizations:
```bash
cargo build --features debug
```

## License

Apache License 2.0. See [LICENSE](../LICENSE) for details.

