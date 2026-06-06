# Provii Mobile SDK Integration Guide

This guide explains how to consume the Provii Mobile SDK artifacts in your mobile application, with a focus on supply chain security and SLSA compliance.

## Table of Contents

- [Overview](#overview)
- [Artifact Types](#artifact-types)
- [Security & Verification](#security--verification)
- [Integration Methods](#integration-methods)
  - [Option 1: CI/CD with GitHub Actions](#option-1-cicd-with-github-actions-recommended)
  - [Option 2: Manual Download](#option-2-manual-download)
  - [Option 3: Local Development](#option-3-local-development)
- [Platform-Specific Setup](#platform-specific-setup)
- [Version Management](#version-management)
- [Troubleshooting](#troubleshooting)

## Overview

The Provii Mobile SDK is built with **SLSA Level 3** supply chain security practices, ensuring:

- ✅ **Hermetic, reproducible builds** in ephemeral environments
- ✅ **Cryptographic signing** of all artifacts with Sigstore
- ✅ **Non-falsifiable provenance** generation
- ✅ **Security audits** before every build
- ✅ **Checksum verification** for all binaries

Every release is **signed, attested, and verifiable** using open-source tools.

## Artifact Types

Each release contains:

| Artifact | Description | Size (approx) |
|----------|-------------|---------------|
| `provii-mobile-sdk-bundle.tar.gz` | Complete bundle with all platforms | ~50-100 MB |
| `provii-mobile-sdk-bundle.tar.gz.sha256` | SHA256 checksum | <1 KB |
| `provii-mobile-sdk-bundle.cosign-bundle` | Sigstore signature bundle | ~5 KB |
| `provii-mobile-sdk.intoto.jsonl` | SLSA provenance attestation | ~10 KB |

Inside the tarball:

```
release-artifacts/
├── android/
│   ├── arm64-v8a/
│   │   ├── libprovii_mobile_sdk_ffi.so
│   │   └── libprovii_mobile_sdk_ffi.so.sha256
│   ├── armeabi-v7a/
│   │   ├── libprovii_mobile_sdk_ffi.so
│   │   └── libprovii_mobile_sdk_ffi.so.sha256
│   └── x86_64/
│       ├── libprovii_mobile_sdk_ffi.so
│       └── libprovii_mobile_sdk_ffi.so.sha256
├── ios/
│   └── ProviiSDK.xcframework/
│       ├── ios-arm64/
│       ├── ios-arm64_x86_64-simulator/
│       └── Info.plist
├── bindings/
│   ├── kotlin/
│   │   └── app/provii/wallet/sdk/
│   │       └── provii_mobile_sdk_ffi.kt
│   └── swift/
│       ├── provii_mobile_sdk_ffi.swift
│       └── provii_mobile_sdk_ffiFFI.h
└── CHECKSUMS.txt
```

## Security & Verification

### Prerequisites

Install verification tools:

```bash
# Cosign (for signature verification)
curl -LO https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-amd64
sudo install cosign-linux-amd64 /usr/local/bin/cosign

# SLSA Verifier (for provenance)
curl -LO https://github.com/slsa-framework/slsa-verifier/releases/download/v2.5.1/slsa-verifier-linux-amd64
sudo install slsa-verifier-linux-amd64 /usr/local/bin/slsa-verifier
```

### Step 1: Download Artifacts

```bash
VERSION="v0.1.0"  # or "latest"
BASE_URL="https://github.com/provii/provii-mobile-sdk/releases/download/${VERSION}"

mkdir -p sdk-artifacts
cd sdk-artifacts

# Download bundle + verification files
curl -LO "${BASE_URL}/provii-mobile-sdk-bundle.tar.gz"
curl -LO "${BASE_URL}/provii-mobile-sdk-bundle.tar.gz.sha256"
curl -LO "${BASE_URL}/provii-mobile-sdk-bundle.cosign-bundle"
curl -LO "${BASE_URL}/provii-mobile-sdk.intoto.jsonl"
```

### Step 2: Verify Checksum

```bash
sha256sum -c provii-mobile-sdk-bundle.tar.gz.sha256
# Expected output: provii-mobile-sdk-bundle.tar.gz: OK
```

### Step 3: Verify Signature

```bash
export COSIGN_EXPERIMENTAL=1

cosign verify-blob \
  --bundle provii-mobile-sdk-bundle.cosign-bundle \
  --certificate-identity-regexp="https://github.com/provii/provii-mobile-sdk/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  provii-mobile-sdk-bundle.tar.gz
```

Expected output:
```
Verified OK
```

### Step 4: Verify SLSA Provenance

```bash
slsa-verifier verify-artifact \
  provii-mobile-sdk-bundle.tar.gz \
  --provenance-path provii-mobile-sdk.intoto.jsonl \
  --source-uri github.com/provii/provii-mobile-sdk
```

Expected output:
```
PASSED: Verified SLSA provenance
```

### Step 5: Extract and Use

```bash
tar -xzf provii-mobile-sdk-bundle.tar.gz
ls -lhR release-artifacts/
```

## Integration Methods

### Option 1: CI/CD with GitHub Actions (Recommended)

This is the most secure approach for production builds.

**Benefits:**
- ✅ Automated verification on every build
- ✅ No local toolchain dependencies (Rust, NDK, etc.)
- ✅ Consistent, reproducible builds
- ✅ Full audit trail

**Setup:**

1. Create a new workflow file in your `provii-mobile` repository at `.github/workflows/sdk-integration.yml`:

   ```yaml
   name: Build with SDK

   on:
     push:
       branches: [main]
     workflow_dispatch:
       inputs:
         sdk_version:
           description: 'SDK version (e.g., v0.1.0)'
           required: false
           default: 'latest'

   env:
     SDK_REPO: provii/provii-mobile-sdk
     SDK_VERSION: ${{ github.event.inputs.sdk_version || 'v0.1.0' }}

   jobs:
     build:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4

         - name: Download SDK bundle
           run: |
             if [[ "$SDK_VERSION" == "latest" ]]; then
               DOWNLOAD_URL=$(gh release view --repo $SDK_REPO --json assets -q '.assets[] | select(.name=="provii-mobile-sdk-bundle.tar.gz") | .url')
             else
               DOWNLOAD_URL="https://github.com/$SDK_REPO/releases/download/$SDK_VERSION/provii-mobile-sdk-bundle.tar.gz"
             fi
             curl -LO "$DOWNLOAD_URL"
             curl -LO "${DOWNLOAD_URL}.sha256"
           env:
             GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}

         - name: Verify checksum
           run: sha256sum -c provii-mobile-sdk-bundle.tar.gz.sha256

         - name: Extract SDK artifacts
           run: |
             tar -xzf provii-mobile-sdk-bundle.tar.gz
             # Copy Android native libraries
             cp -R release-artifacts/android/* android/app/src/main/jniLibs/
             # Copy Kotlin bindings
             cp -R release-artifacts/bindings/kotlin/* android/walletsdk/src/main/java/
             # Copy iOS framework and Swift bindings (adjust paths as needed)
             cp -R release-artifacts/ios/ProviiSDK.xcframework ios/Frameworks/
             cp release-artifacts/bindings/swift/*.swift ios/ProviiSDK/Sources/

         # Add your build steps here (e.g., ./gradlew assembleRelease, xcodebuild)
   ```

   For reference, see the SDK's [release.yml](../.github/workflows/release.yml) to understand how artifacts are structured and signed.

2. Customise the workflow for your project:
   - Update `SDK_VERSION` to pin to a specific release version
   - Adjust the artifact destination paths to match your project structure
   - Add signature verification steps (see [Security & Verification](#security--verification))

3. Commit and push:
   ```bash
   cd provii-mobile
   git add .github/workflows/sdk-integration.yml
   git commit -m "Add SDK artifact integration workflow"
   git push
   ```

4. The workflow will:
   - Download the latest SDK release
   - Verify checksums and signatures
   - Extract artifacts into your project
   - Build Android/iOS apps with verified SDK

**Version pinning:**

For production, pin to a specific version:
```yaml
env:
  SDK_VERSION: v0.1.0  # Don't use 'latest' in prod
```

### Option 2: Manual Download

For one-off builds or testing.

```bash
# Download and verify (see Security & Verification above)
VERSION="v0.1.0"
cd /tmp
wget https://github.com/provii/provii-mobile-sdk/releases/download/${VERSION}/provii-mobile-sdk-bundle.tar.gz
wget https://github.com/provii/provii-mobile-sdk/releases/download/${VERSION}/provii-mobile-sdk-bundle.tar.gz.sha256

# Verify
sha256sum -c provii-mobile-sdk-bundle.tar.gz.sha256

# Extract
tar -xzf provii-mobile-sdk-bundle.tar.gz

# Copy to your project
cd release-artifacts

# Android
cp -R android/* /path/to/provii-mobile/android/app/src/main/jniLibs/
cp -R bindings/kotlin/* /path/to/provii-mobile/android/walletsdk/src/main/java/

# iOS
cp -R ios/ProviiSDK.xcframework /path/to/provii-mobile/ios/Frameworks/
cp bindings/swift/*.swift /path/to/provii-mobile/ios/ProviiSDK/Sources/
```

### Option 3: Local Development

For SDK developers who need to modify the SDK.

**Use the build script:**
```bash
cd /path/to/provii-mobile-sdk

# Build all platforms + bindings
./generate_bindings.sh

# Or build specific platforms
./generate_bindings.sh --android-only
./generate_bindings.sh --ios-only
```

The script stages artifacts to `release-artifacts/` for local testing or manual integration.

**Note:** This requires:
- Rust toolchain
- Android NDK (for Android)
- Xcode (for iOS, macOS only)
- `cargo-ndk` (for Android)

## Platform-Specific Setup

### Android

**Project Structure:**
```
provii-mobile/android/
├── app/
│   └── src/main/jniLibs/
│       ├── arm64-v8a/
│       │   └── libprovii_mobile_sdk_ffi.so
│       ├── armeabi-v7a/
│       │   └── libprovii_mobile_sdk_ffi.so
│       └── x86_64/
│           └── libprovii_mobile_sdk_ffi.so
└── walletsdk/
    └── src/main/java/
        └── app/provii/wallet/sdk/
            └── provii_mobile_sdk_ffi.kt
```

**Gradle Configuration:**

In `android/walletsdk/build.gradle`:
```gradle
android {
    namespace 'app.provii.wallet.sdk'

    defaultConfig {
        // Ensure ABIs match available .so files
        ndk {
            abiFilters 'arm64-v8a', 'armeabi-v7a', 'x86_64'
        }
    }
}

dependencies {
    implementation 'net.java.dev.jna:jna:5.13.0@aar'
}
```

**Usage in Kotlin:**
```kotlin
import app.provii.wallet.sdk.*

val appInfo = AppInfo(
    version = "1.0.0",
    buildNumber = "1",
    platform = "Android",
    deviceModel = null,
    osVersion = null
)
initAndroidLogging()
val wallet = ProviiWallet(appInfo)
```

### iOS

**Project Structure:**
```
provii-mobile/ios/
├── Frameworks/
│   └── ProviiSDK.xcframework/
└── ProviiSDK/
    └── Sources/
        ├── provii_mobile_sdk_ffi.swift
        └── provii_mobile_sdk_ffiFFI.h
```

**Xcode Configuration:**

1. **Add XCFramework to project:**
   - Drag `Frameworks/ProviiSDK.xcframework` into Xcode
   - Target → General → Frameworks, Libraries, and Embedded Content
   - Set to **Embed & Sign**

2. **Add Swift sources:**
   - Add `ProviiSDK/Sources/*.swift` to your target

3. **Configure Swift Bridging Header** (if needed):
   ```objective-c
   #import <ProviiSDK/provii_mobile_sdk_ffiFFI.h>
   ```

4. **Build Settings:**
   - Framework Search Paths: `$(PROJECT_DIR)/Frameworks`
   - Swift Compiler - Code Generation: **-O** (for release)

**Usage in Swift:**
```swift
import ProviiSDK

let appInfo = AppInfo(
    version: "1.0.0",
    buildNumber: "1",
    platform: "iOS",
    deviceModel: nil,
    osVersion: nil
)
let wallet = ProviiWallet(appInfo: appInfo)
```

## Version Management

### Recommended Strategy

| Environment | Strategy | Rationale |
|-------------|----------|-----------|
| **Production** | Pin to specific version (e.g., `v0.1.0`) | Stability, reproducibility |
| **Staging** | Use `latest` from main branch | Early testing of new features |
| **Development** | Local builds with `./generate_bindings.sh` | Fast iteration |

### Updating Versions

**In CI/CD workflow:**
```yaml
env:
  SDK_VERSION: v0.2.0  # Update this
```

**In manual builds:**
```bash
VERSION="v0.2.0"  # Update this
curl -LO "https://github.com/provii/provii-mobile-sdk/releases/download/${VERSION}/..."
```

### Version Compatibility

The SDK follows [Semantic Versioning](https://semver.org/):

- **Major version** (`v0.1.0` to `v1.0.0`): Breaking API changes, requires mobile app updates
- **Minor version** (`v0.1.0` to `v0.2.0`): New features, backward-compatible
- **Patch version** (`v0.1.0` to `v0.1.1`): Bug fixes, backward-compatible

## Troubleshooting

### "Library not found" errors

**Android:**
```
java.lang.UnsatisfiedLinkError: dlopen failed: library "libprovii_mobile_sdk_ffi.so" not found
```

**Solution:**
- Verify `.so` files are in `android/app/src/main/jniLibs/{abi}/`
- Check `abiFilters` in `build.gradle` matches available ABIs
- Clean and rebuild: `./gradlew clean assembleDebug`

**iOS:**
```
dyld: Library not loaded: @rpath/ProviiSDK.framework/ProviiSDK
```

**Solution:**
- Verify XCFramework is added to project with **Embed & Sign**
- Check Framework Search Paths in Build Settings
- Clean build folder: Xcode → Product → Clean Build Folder

### Signature verification fails

```
Error: signature verification failed
```

**Possible causes:**
1. **Artifact was tampered with** - DO NOT USE, report to security team
2. **Wrong certificate identity** - Check `--certificate-identity-regexp`
3. **Expired certificate** - Update cosign tool

**Debug:**
```bash
# Inspect signature bundle
cat provii-mobile-sdk-bundle.cosign-bundle | jq '.'

# Verify certificate matches expected identity
cosign verify-blob --bundle provii-mobile-sdk-bundle.cosign-bundle provii-mobile-sdk-bundle.tar.gz | \
  jq '.payload | @base64d | fromjson'
```

### Checksum mismatch

```
provii-mobile-sdk-bundle.tar.gz: FAILED
```

**Cause:** File was corrupted or tampered with during download.

**Solution:**
1. Re-download the artifact
2. If problem persists, check network/proxy issues
3. If still failing, verify artifact integrity on GitHub releases page

### Wrong SDK version loaded

**Android:**
```kotlin
// Check version
val version = getSdkVersion()
println("SDK version: $version")
```

**iOS:**
```swift
// Check version
let version = getSdkVersion()
print("SDK version: \(version)")
```

If version is unexpected:
- Clean and rebuild
- Verify artifact installation step in CI
- Check Gradle/Xcode cache

### Performance issues

If proof generation is slow:
- **Check thread pool initialization:**
  Look for log: `"✔ Rayon global thread pool initialised with N threads"`
- **Verify parallel feature is enabled:**
  Check built artifacts were built with `--features parallel`
- **Profile with debug logging:**
  Set `RUST_LOG=debug` (Android: logcat, iOS: Xcode console)

## Additional Resources

- [Provii Mobile SDK README](../README.md)
- [SLSA Framework](https://slsa.dev/)
- [Sigstore Documentation](https://docs.sigstore.dev/)
- [UniFFI Documentation](https://mozilla.github.io/uniffi-rs/)

## Support

For integration issues:
1. Check this guide's [Troubleshooting](#troubleshooting) section
2. Review [GitHub Issues](https://github.com/provii/provii-mobile-sdk/issues)
3. Open a new issue with:
   - SDK version used
   - Platform (Android/iOS)
   - Error logs
   - Steps to reproduce
