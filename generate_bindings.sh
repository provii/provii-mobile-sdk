#!/usr/bin/env bash
# provii-mobile-sdk/generate_bindings.sh
#
# Builds the Rust FFI crate, generates UniFFI Swift & Kotlin bindings,
# cross-compiles Android .so libraries with cargo-ndk and iOS libraries,
# creates XCFramework for iOS, and places everything where the provii-mobile 
# Android and iOS projects expect it.
#
# Usage (from repo root):  ./generate_bindings.sh
set -euo pipefail

################################################################################
# 0. Locate repo root and common paths
################################################################################
REPO_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "${REPO_ROOT}"

# Parse command line arguments
BUILD_ANDROID=true
BUILD_IOS=true
while [[ $# -gt 0 ]]; do
  case $1 in
    --android-only)
      BUILD_IOS=false
      shift
      ;;
    --ios-only)
      BUILD_ANDROID=false
      shift
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--android-only | --ios-only]"
      exit 1
      ;;
  esac
done

# Check for required tools based on platform
if [[ "$BUILD_ANDROID" == true ]]; then
  command -v cargo-ndk >/dev/null 2>&1 || { 
    echo "❌ cargo-ndk is required but not installed."
    echo "Install with: cargo install cargo-ndk"
    exit 1
  }
  
  # Check for Android NDK (required by cargo-ndk)
  if [[ -z "${ANDROID_NDK_HOME:-}" ]] && [[ -z "${NDK_HOME:-}" ]] && [[ -z "${ANDROID_HOME:-}" ]]; then
    echo "⚠️  Warning: Android NDK environment not detected."
    echo "   cargo-ndk will try to find it automatically."
    echo "   If the build fails, set one of: ANDROID_NDK_HOME, NDK_HOME, or ANDROID_HOME"
  fi
fi

if [[ "$BUILD_IOS" == true ]]; then
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "❌ iOS builds require macOS"
    exit 1
  fi
  
  command -v xcodebuild >/dev/null 2>&1 || {
    echo "❌ xcodebuild is required for iOS builds but not found."
    echo "Install Xcode from the Mac App Store."
    exit 1
  }
fi

# Host shared-library extension
case "$(uname -s)" in
  Darwin*) LIB_EXT="dylib" ;;
  Linux*)  LIB_EXT="so"    ;;
  *) echo "Unsupported host OS: $(uname -s)"; exit 1 ;;
esac

LIB_NAME="libprovii_mobile_sdk_ffi"
HOST_LIB_PATH="${REPO_ROOT}/target/release/${LIB_NAME}.${LIB_EXT}"
BINDGEN_BIN="${REPO_ROOT}/target/release/uniffi-bindgen"
UNIFFI_CONFIG="${REPO_ROOT}/uniffi.toml"

################################################################################
# 1. Build uniffi-bindgen for the host platform first
################################################################################
echo "▶️ Building uniffi-bindgen helper binary for host…"
cargo build --release --bin uniffi-bindgen -p provii-mobile-sdk-ffi --features "uniffi/cli"

if [[ ! -x "${BINDGEN_BIN}" ]]; then
  echo "❌  Failed to build uniffi-bindgen"
  exit 1
fi

################################################################################
# 2. Build host library first (needed for binding generation)
################################################################################
echo "▶️ Building host library for binding generation…"
cargo build --release -p provii-mobile-sdk-ffi

################################################################################
# 3. Build Android libraries (with ALL required features for multi-threading)
################################################################################
if [[ "$BUILD_ANDROID" == true ]]; then
  echo "▶️ Building Android native libraries with multi-threading and HTTP/3 support…"
  echo "   Features enabled: android, parallel, debug-threading, http"
  ANDROID_LIB_DIR="${REPO_ROOT}/android-libs"
  rm -rf "${ANDROID_LIB_DIR}"

  # Build with all features needed for multi-threaded proof generation and HTTP/3
  cargo ndk \
    -t aarch64-linux-android \
    -t armv7-linux-androideabi \
    -t x86_64-linux-android \
    -o "${ANDROID_LIB_DIR}" \
    build --release -p provii-mobile-sdk-ffi \
    --features "android,parallel,debug-threading,http"

  # Verify the build completed successfully
  if [[ ! -d "${ANDROID_LIB_DIR}" ]]; then
    echo "❌  Android library build failed - output directory not created"
    exit 1
  fi

  # Check that libraries were actually built for all architectures
  EXPECTED_ARCHS=("arm64-v8a" "armeabi-v7a" "x86_64")
  for arch in "${EXPECTED_ARCHS[@]}"; do
    if [[ ! -f "${ANDROID_LIB_DIR}/${arch}/${LIB_NAME}.so" ]]; then
      echo "⚠️  Warning: ${arch} library not found at ${ANDROID_LIB_DIR}/${arch}/${LIB_NAME}.so"
    else
      echo "✅  Built ${arch} library ($(du -h "${ANDROID_LIB_DIR}/${arch}/${LIB_NAME}.so" | cut -f1))"
    fi
  done
fi

################################################################################
# 4. Build iOS libraries
################################################################################
if [[ "$BUILD_IOS" == true ]]; then
  echo "▶️ Building iOS native libraries…"
  echo "   Features enabled: ios, parallel, debug-threading, http"

  # Set minimum iOS deployment target to match the app's target
  # This prevents "built for newer iOS version" linker warnings
  export IPHONEOS_DEPLOYMENT_TARGET=17.6
  echo "   iOS deployment target: ${IPHONEOS_DEPLOYMENT_TARGET}"

  # Add iOS targets if not already added
  echo "   Adding iOS rust targets if needed…"
  rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim 2>/dev/null || true

  # Build for iOS device (ARM64)
  echo "   Building for iOS devices (arm64)…"
  cargo build --release \
    --target aarch64-apple-ios \
    -p provii-mobile-sdk-ffi \
    --features "ios,parallel,debug-threading,http"
  
  # Build for iOS Simulator (Intel)
  echo "   Building for iOS Simulator (x86_64)…"
  cargo build --release \
    --target x86_64-apple-ios \
    -p provii-mobile-sdk-ffi \
    --features "ios,parallel,debug-threading,http"
  
  # Build for iOS Simulator (Apple Silicon)
  echo "   Building for iOS Simulator (arm64)…"
  cargo build --release \
    --target aarch64-apple-ios-sim \
    -p provii-mobile-sdk-ffi \
    --features "ios,parallel,debug-threading,http"
  
  # Verify iOS builds
  IOS_TARGETS=(
    "aarch64-apple-ios"
    "x86_64-apple-ios"
    "aarch64-apple-ios-sim"
  )
  
  for target in "${IOS_TARGETS[@]}"; do
    if [[ ! -f "${REPO_ROOT}/target/${target}/release/${LIB_NAME}.a" ]]; then
      echo "❌  Failed to build iOS library for ${target}"
      exit 1
    else
      echo "✅  Built ${target} library ($(du -h "${REPO_ROOT}/target/${target}/release/${LIB_NAME}.a" | cut -f1))"
    fi
  done
fi

################################################################################
# 5. Generate Kotlin bindings from HOST library
################################################################################
if [[ "$BUILD_ANDROID" == true ]]; then
  KOTLIN_OUT="${REPO_ROOT}/crates/bindings/kotlin"
  rm -rf "${KOTLIN_OUT}"
  mkdir -p "${KOTLIN_OUT}"

  echo "▶️ Generating Kotlin bindings from host library…"
  "${BINDGEN_BIN}" generate \
    --library "${HOST_LIB_PATH}" \
    --language kotlin \
    --config "${UNIFFI_CONFIG}" \
    --out-dir "${KOTLIN_OUT}"

  # The Kotlin file will be in a package directory structure
  KOTLIN_PACKAGE_PATH="app/provii/wallet/sdk"
  KOTLIN_FILE="${KOTLIN_OUT}/${KOTLIN_PACKAGE_PATH}/provii_mobile_sdk_ffi.kt"

  ################################################################################
  # 5.1. Post-process Kotlin to fix the missing-newline bug in UniFFI 0.29
  ################################################################################
  if [[ -f "${KOTLIN_FILE}" ]]; then
    echo "▶️ Patching newline bug in ${KOTLIN_FILE}"
    if [[ "$(uname -s)" == "Darwin" ]]; then
      sed -E -i '' 's/(uniffi::Enum)([[:alnum:]_]+)/\1\
\2/' "${KOTLIN_FILE}"
    else
      sed -E -i 's/(uniffi::Enum)([[:alnum:]_]+)/\1\
\2/' "${KOTLIN_FILE}"
    fi
    echo "✅  Kotlin newline bug patched"
  else
    echo "⚠️  Warning: ${KOTLIN_FILE} not found, skipping newline patch"
  fi

  ################################################################################
  # 5.2. Patch Kotlin to force JNA cleaner for Android API < 33 compatibility
  # UniFFI 0.29 generates runtime-selection code that tries java.lang.ref.Cleaner
  # first. On Android, this class exists on API 33+ but crashes on earlier APIs.
  # With android_cleaner=false, we want to ALWAYS use UniffiJnaCleaner.
  ################################################################################
  if [[ -f "${KOTLIN_FILE}" ]]; then
    echo "▶️ Patching cleaner selection for Android API < 33 compatibility"

    # Use Python for reliable multi-line text replacement
    python3 - "${KOTLIN_FILE}" << 'PYSCRIPT'
import re
import sys

kotlin_file = sys.argv[1]
with open(kotlin_file, 'r') as f:
    content = f.read()

# Pattern to match the entire UniffiCleaner.Companion.create() function
# Matches from the comments before the function to the closing brace
pattern = r'''// We decide at uniffi binding generation time whether we were
// using Android or not\.
// There are further runtime checks to chose the correct implementation
// of the cleaner\.
private fun UniffiCleaner\.Companion\.create\(\): UniffiCleaner =
    try \{
        // For safety's sake: if the library hasn't been run in android_cleaner = true
        // mode, but is being run on Android, then we still need to think about
        // Android API versions\.
        // So we check if java\.lang\.ref\.Cleaner is there, and use that…
        java\.lang\.Class\.forName\("java\.lang\.ref\.Cleaner"\)
        JavaLangRefCleaner\(\)
    \} catch \(e: ClassNotFoundException\) \{
        // … otherwise, fallback to the JNA cleaner\.
        UniffiJnaCleaner\(\)
    \}'''

replacement = '''// Force JNA cleaner for Android API < 33 compatibility
// (patched by generate_bindings.sh - see uniffi.toml android_cleaner = false)
private fun UniffiCleaner.Companion.create(): UniffiCleaner = UniffiJnaCleaner()'''

# Perform the replacement
new_content = re.sub(pattern, replacement, content)

# Also remove JavaLangRefCleaner and JavaLangRefCleanable classes if they exist
new_content = re.sub(r'private class JavaLangRefCleaner : UniffiCleaner \{[^}]+\}\n*', '', new_content)
new_content = re.sub(r'private class JavaLangRefCleanable\([^)]+\)[^}]+\}\n*', '', new_content)

with open(kotlin_file, 'w') as f:
    f.write(new_content)

print("Python patch applied successfully")
PYSCRIPT

    # Verify the patch worked
    if grep -q "Force JNA cleaner for Android API < 33 compatibility" "${KOTLIN_FILE}"; then
      echo "✅  Cleaner patched to always use JNA cleaner"
    else
      echo "⚠️  Warning: Cleaner patch may not have applied correctly"
    fi

    # Verify no java.lang.ref.Cleaner references remain
    if grep -q "java.lang.ref.Cleaner" "${KOTLIN_FILE}"; then
      echo "⚠️  Warning: java.lang.ref.Cleaner references still exist"
    else
      echo "✅  No java.lang.ref.Cleaner references in generated code"
    fi
  fi
fi

################################################################################
# 6. Generate Swift bindings
################################################################################
SWIFT_OUT="${REPO_ROOT}/crates/bindings/swift"
rm -rf "${SWIFT_OUT}"
mkdir -p "${SWIFT_OUT}"

echo "▶️ Generating Swift bindings…"
"${BINDGEN_BIN}" generate \
  --library "${HOST_LIB_PATH}" \
  --language swift \
  --config "${UNIFFI_CONFIG}" \
  --out-dir "${SWIFT_OUT}"

################################################################################
# 6.1. Post-process Swift to replace fatalError with thrown error
#       UniFFI generates fatalError("Cancellation not supported yet") in
#       uniffiCheckCallStatus. This crashes the app instead of propagating
#       a recoverable error. Replace it with a thrown UniffiInternalError.
################################################################################
SWIFT_FILE="${SWIFT_OUT}/ProviiSDK.swift"
if [[ -f "${SWIFT_FILE}" ]]; then
  echo "▶️ Patching fatalError in Swift bindings…"
  sed -i '' 's/fatalError("Cancellation not supported yet")/throw UniffiInternalError.rustPanic("FFI call cancelled")/' "${SWIFT_FILE}"

  # Verify the patch applied
  if grep -q 'throw UniffiInternalError.rustPanic("FFI call cancelled")' "${SWIFT_FILE}"; then
    echo "✅  Swift fatalError replaced with thrown error"
  else
    echo "❌  Swift fatalError patch failed"
    exit 1
  fi

  # Verify no fatalError("Cancellation not supported yet") remains
  if grep -q 'fatalError("Cancellation not supported yet")' "${SWIFT_FILE}"; then
    echo "❌  fatalError still present after patching"
    exit 1
  fi
fi

################################################################################
# 6.2. Replace try! force-unwraps in Swift bindings
#
# UniFFI generates try! for all FFI calls. Most of these are in non-throwing
# contexts where a Rust panic would crash the app. This post-generation script
# applies category-specific replacements to prevent app crashes.
#
# Category 1 (deinit/dealloc): try! -> try? (accept leak over crash)
# Category 2 (clone/lower/buffer): keep try! (in throwing contexts already)
# Category 3 (constructors): try! -> do/catch with fatalError
# Category 4 (getters/properties): try! -> do/catch with safe defaults
# Category 5 (void methods/functions): try! -> do/catch with no-op + log
################################################################################
SWIFT_FILE=$(find "${SWIFT_OUT}" -name "*.swift" | head -n1)
if [[ -n "${SWIFT_FILE}" ]]; then
  echo "▶️ Patching try! force-unwraps in Swift bindings…"

  python3 - "${SWIFT_FILE}" << 'PYFIX060'
import re
import sys

swift_file = sys.argv[1]
with open(swift_file, 'r') as f:
    content = f.read()

patched = 0

# ---------------------------------------------------------------------------
# Category 1: deinit / dealloc  (try! -> try?)
# Matches lines containing fn_free_ or rustbuffer_free inside deinit blocks.
# These are simple single-line try! calls that we convert to try?.
# ---------------------------------------------------------------------------
# Pattern for deinit free calls (fn_free_ and rustbuffer_free)
content, n = re.subn(
    r'try! rustCall\s*\{[^}]*(?:fn_free_|rustbuffer_free)[^}]*\}',
    lambda m: m.group(0).replace('try!', 'try?'),
    content
)
patched += n
print(f"  Category 1 (deinit/dealloc): {n} sites patched (try! -> try?)")

# ---------------------------------------------------------------------------
# Category 2: clone / rustbuffer_from_bytes  (KEEP try!)
# These are used inside uniffiClonePointer() and RustBuffer.from() which are
# called from throwing contexts. No changes needed.
# ---------------------------------------------------------------------------
cat2_count = len(re.findall(r'try! rustCall\s*\{[^}]*(?:fn_clone_|rustbuffer_from_bytes)[^}]*\}', content))
print(f"  Category 2 (clone/buffer): {cat2_count} sites kept as try! (throwing context)")

# ---------------------------------------------------------------------------
# Category 3: constructors  (try! -> do/catch with fatalError)
#
# Pattern A: convenience init with try! rustCall() { ... }
#   let pointer =
#       try! rustCall() {
#   uniffi_..._fn_constructor_...(...)
#   }
#   self.init(unsafeFromRawPointer: pointer)
#
# Pattern B: static factory with return try! Lift(try! rustCall() { ... })
# ---------------------------------------------------------------------------

# Pattern A: convenience init constructors
def patch_constructor_init(m):
    global patched
    patched += 1
    body = m.group(1)
    return (
        'let pointer: UnsafeMutableRawPointer\n'
        '    do {\n'
        '        pointer = try rustCall() {\n'
        f'    {body}'
        '    }\n'
        '    } catch {\n'
        '        fatalError("Constructor failed: \\(error)")\n'
        '    }\n'
        '    self.init(unsafeFromRawPointer: pointer)'
    )

content, n = re.subn(
    r'let pointer =\s*\n\s*try! rustCall\(\) \{\n(.*?)\}\n\s*self\.init\(unsafeFromRawPointer: pointer\)',
    patch_constructor_init,
    content,
    flags=re.DOTALL
)
print(f"  Category 3a (convenience init constructors): {n} sites patched")

# Pattern B: static factory (withConfig pattern)
# return try!  FfiConverterTypeX_lift(try! rustCall() { ... })
def patch_static_factory(m):
    global patched
    patched += 1
    converter = m.group(1)
    body = m.group(2)
    return (
        f'do {{\n'
        f'        return try {converter}(try rustCall() {{\n'
        f'{body})\n'
        f'}})\n'
        f'    }} catch {{\n'
        f'        fatalError("Constructor failed: \\(error)")\n'
        f'    }}'
    )

content, n = re.subn(
    r'return try!\s+(FfiConverterType\w+_lift)\(try! rustCall\(\) \{\n(\s*uniffi_\w+_fn_constructor_\w+\([^}]*?)\)\n\}\)',
    patch_static_factory,
    content,
    flags=re.DOTALL
)
print(f"  Category 3b (static factory constructors): {n} sites patched")

# ---------------------------------------------------------------------------
# Category 5: void methods and free functions (try! rustCall() { ... } as
# the entire method body, NOT in deinit, NOT clone, NOT constructor)
#
# These are methods like reportProgress, addListener, markCompleted, etc.
# and free functions like initAndroidLogging, sdkSetUserAgent.
#
# We process these BEFORE Category 4 so the more specific void pattern
# does not get caught by the general getter pattern.
# ---------------------------------------------------------------------------

# Void methods on objects: open func foo(...)  {try! rustCall() { ... }}
# Void free functions: public func foo(...)  {try! rustCall() { ... }}
def patch_void_method(m):
    global patched
    patched += 1
    prefix = m.group(1)  # the func declaration
    body = m.group(2)    # the rustCall body (including trailing ")")
    indent = '    '
    # Detect if this is a top-level function (public func) vs method (open func)
    if prefix.strip().startswith('public func'):
        indent = ''
    return (
        f'{prefix} {{\n'
        f'{indent}do {{ try rustCall() {{\n'
        f'{body}\n'
        f'{indent}}}\n'
        f'{indent}}} catch {{\n'
        f'{indent}    print("[ProviiSDK] FFI void call failed: \\(error)")\n'
        f'{indent}}}\n'
        f'}}'
    )

# Void methods: funcDecl  {try! rustCall() { ... }\n}
# The body includes everything up to the \n before the closing }\n}
content, n = re.subn(
    r'((?:open|public) func \w+\([^)]*\))\s+\{try! rustCall\(\) \{\n(.*?)\n\}\n\}',
    patch_void_method,
    content,
    flags=re.DOTALL
)
print(f"  Category 5 (void methods/functions): {n} sites patched (try! -> do/catch no-op)")

# ---------------------------------------------------------------------------
# Category 4: getters and computed properties (return try! Lift(try! rustCall()))
#
# These return values. We wrap in do/catch and return type-appropriate defaults.
# Pattern: return try!  FfiConverterXxx.lift(try! rustCall() { ... })
# ---------------------------------------------------------------------------

# Map converter names to default values
DEFAULTS = {
    'FfiConverterBool': 'false',
    'FfiConverterString': '""',
    'FfiConverterUInt8': '0',
    'FfiConverterUInt16': '0',
    'FfiConverterUInt32': '0',
    'FfiConverterUInt64': '0',
    'FfiConverterInt8': '0',
    'FfiConverterInt16': '0',
    'FfiConverterInt32': '0',
    'FfiConverterInt64': '0',
    'FfiConverterFloat': '0.0',
    'FfiConverterDouble': '0.0',
    'FfiConverterOptionUInt8': 'nil',
    'FfiConverterOptionUInt16': 'nil',
    'FfiConverterOptionUInt32': 'nil',
    'FfiConverterOptionUInt64': 'nil',
    'FfiConverterOptionString': 'nil',
    'FfiConverterTypeNetworkStatus': 'NetworkStatus(connected: false)',
    'FfiConverterTypeStorageCheckResult': '.error(message: "FFI call failed")',
    'FfiConverterTypeVerificationStatus': '.notStarted',
    'FfiConverterTypeProgressStage': '.failed',
    'FfiConverterTypeWalletConfig': (
        'WalletConfig(autoSelect: false, networkTimeout: 30, '
        'cacheProvingKeys: false, issuerApiUrl: "", verifierApiUrl: "", '
        'verifierApiKey: nil, verifierOrigin: nil, environment: "unknown", '
        'enableParallelProver: false, maxProverThreads: 0)'
    ),
    'FfiConverterTypeDiagnosticInfo': (
        'DiagnosticInfo(sdkVersion: "", appVersion: "", platform: "", '
        'proverInitialized: false, credentialCount: 0, storageAvailable: false, '
        'configEnvironment: "unknown", lastProofGenerated: nil)'
    ),
    'FfiConverterTypeProgressTracker': 'ProgressTracker()',
}

def get_default_for_converter(conv_name):
    """Return a safe default value for a given FfiConverter type."""
    # Try exact match first
    if conv_name in DEFAULTS:
        return DEFAULTS[conv_name]
    # Try the _lift suffix variant (free-standing functions use FfiConverterTypeX_lift)
    base = conv_name.replace('_lift', '')
    if base in DEFAULTS:
        return DEFAULTS[base]
    # Fallback: if it looks like an optional, return nil
    if 'Option' in conv_name:
        return 'nil'
    # Unknown type: use a comment so it fails to compile rather than silently breaking
    return f'/* unknown default for {conv_name} */'

def patch_getter(m):
    global patched
    patched += 1
    converter = m.group(1)  # e.g. FfiConverterBool.lift or FfiConverterTypeX_lift
    body = m.group(2)       # the rustCall body

    # Extract the converter name (before .lift or _lift)
    if '.lift' in converter:
        conv_name = converter.split('.lift')[0].strip()
    else:
        conv_name = converter.split('_lift')[0].strip()
        # For free-standing functions like FfiConverterTypeStorageCheckResult_lift
        # the conv_name already has the right form

    default_val = get_default_for_converter(conv_name)

    return (
        f'do {{\n'
        f'        return try {converter}(try rustCall() {{\n'
        f'{body})\n'
        f'}})\n'
        f'    }} catch {{\n'
        f'        print("[ProviiSDK] FFI getter failed: \\(error)")\n'
        f'        return {default_val}\n'
        f'    }}'
    )

# Use [^}]* instead of .*? to prevent cross-method matching
content, n = re.subn(
    r'return try!\s+((?:FfiConverter\w+)(?:\.lift|_lift))\(try! rustCall\(\) \{\n([^}]*?)\)\n\}\)',
    patch_getter,
    content,
    flags=re.DOTALL
)
print(f"  Category 4 (getters/properties): {n} sites patched (try! -> do/catch with defaults)")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
remaining = len(re.findall(r'try!', content))
print(f"\n  Total try! remaining after patching: {remaining}")
print(f"  Expected remaining (Category 2 clone/buffer): {cat2_count}")

if remaining != cat2_count:
    print(f"  WARNING: {remaining - cat2_count} unexpected try! sites remain!")
    # Print the lines that still have try! for debugging
    for i, line in enumerate(content.split('\n'), 1):
        if 'try!' in line:
            # Skip known Category 2 lines
            if 'fn_clone_' in line or 'rustbuffer_from_bytes' in line:
                continue
            print(f"    Line {i}: {line.strip()}")

with open(swift_file, 'w') as f:
    f.write(content)

print(f"\nFIX-060 patch applied successfully to {swift_file}")
PYFIX060

  # Verify the patch
  REMAINING_TRY_BANG=$(grep -c 'try!' "${SWIFT_FILE}" || true)
  EXPECTED_CAT2=$(grep -c 'fn_clone_\|rustbuffer_from_bytes' "${SWIFT_FILE}" || true)

  if [[ "${REMAINING_TRY_BANG}" -eq "${EXPECTED_CAT2}" ]]; then
    echo "✅  All non-Category-2 try! sites patched (${EXPECTED_CAT2} clone/buffer sites retained)"
  else
    echo "❌  ${REMAINING_TRY_BANG} try! remain but expected ${EXPECTED_CAT2} (Category 2 only)"
    echo "   Listing unexpected try! sites:"
    grep -n 'try!' "${SWIFT_FILE}" | grep -v 'fn_clone_\|rustbuffer_from_bytes' || true
    exit 1
  fi
else
  echo "⚠️  Warning: No Swift file found in ${SWIFT_OUT}, skipping the try! patch"
fi

################################################################################
# 7. Create XCFramework for iOS
################################################################################
if [[ "$BUILD_IOS" == true ]]; then
  echo "▶️ Creating XCFramework for iOS…"
  
  XCFRAMEWORK_DIR="${REPO_ROOT}/ios-framework"
  rm -rf "${XCFRAMEWORK_DIR}"
  mkdir -p "${XCFRAMEWORK_DIR}"
  
  # Create directories for each platform
  mkdir -p "${XCFRAMEWORK_DIR}/ios-device"
  mkdir -p "${XCFRAMEWORK_DIR}/ios-simulator"
  
  # Copy device library
  cp "${REPO_ROOT}/target/aarch64-apple-ios/release/${LIB_NAME}.a" \
     "${XCFRAMEWORK_DIR}/ios-device/${LIB_NAME}.a"
  
  # Create universal binary for simulators (Intel + Apple Silicon)
  echo "   Creating universal simulator library…"
  lipo -create \
    "${REPO_ROOT}/target/x86_64-apple-ios/release/${LIB_NAME}.a" \
    "${REPO_ROOT}/target/aarch64-apple-ios-sim/release/${LIB_NAME}.a" \
    -output "${XCFRAMEWORK_DIR}/ios-simulator/${LIB_NAME}.a"
  
  # Verify lipo worked
  echo "   Verifying universal binary architectures…"
  lipo -info "${XCFRAMEWORK_DIR}/ios-simulator/${LIB_NAME}.a"
  
  # Copy headers (from Swift bindings output)
  SWIFT_HEADER=$(find "${SWIFT_OUT}" -name "*.h" | head -n1)
  if [[ -n "$SWIFT_HEADER" ]]; then
    cp "$SWIFT_HEADER" "${XCFRAMEWORK_DIR}/ios-device/provii_mobile_sdk_ffiFFI.h"
    cp "$SWIFT_HEADER" "${XCFRAMEWORK_DIR}/ios-simulator/provii_mobile_sdk_ffiFFI.h"
  fi
  
  # Create modulemaps for each platform
  for platform in "ios-device" "ios-simulator"; do
    mkdir -p "${XCFRAMEWORK_DIR}/${platform}/Headers"
    if [[ -f "${XCFRAMEWORK_DIR}/${platform}/provii_mobile_sdk_ffiFFI.h" ]]; then
      mv "${XCFRAMEWORK_DIR}/${platform}/provii_mobile_sdk_ffiFFI.h" "${XCFRAMEWORK_DIR}/${platform}/Headers/"
    fi
    
    cat > "${XCFRAMEWORK_DIR}/${platform}/module.modulemap" << EOF
module ProviiSDKFFI {
    umbrella header "Headers/provii_mobile_sdk_ffiFFI.h"
    export *
}
EOF
  done
  
  # Create XCFramework
  echo "   Building XCFramework…"
  xcodebuild -create-xcframework \
    -library "${XCFRAMEWORK_DIR}/ios-device/${LIB_NAME}.a" \
    -headers "${XCFRAMEWORK_DIR}/ios-device/Headers" \
    -library "${XCFRAMEWORK_DIR}/ios-simulator/${LIB_NAME}.a" \
    -headers "${XCFRAMEWORK_DIR}/ios-simulator/Headers" \
    -output "${XCFRAMEWORK_DIR}/ProviiSDK.xcframework"
  
  if [[ ! -d "${XCFRAMEWORK_DIR}/ProviiSDK.xcframework" ]]; then
    echo "❌  Failed to create XCFramework"
    exit 1
  fi
  echo "✅  XCFramework created successfully"
fi

################################################################################
# 8. Stage artifacts for release (used by CI and local development)
################################################################################
RELEASE_DIR="${REPO_ROOT}/release-artifacts"
rm -rf "${RELEASE_DIR}"
mkdir -p "${RELEASE_DIR}"

if [[ "$BUILD_ANDROID" == true ]]; then
  echo "▶️ Staging Android artifacts for release..."
  mkdir -p "${RELEASE_DIR}/android"
  cp -R "${ANDROID_LIB_DIR}/"* "${RELEASE_DIR}/android/"

  mkdir -p "${RELEASE_DIR}/bindings/kotlin"
  cp -R "${KOTLIN_OUT}/"* "${RELEASE_DIR}/bindings/kotlin/"
fi

if [[ "$BUILD_IOS" == true ]]; then
  echo "▶️ Staging iOS artifacts for release..."
  mkdir -p "${RELEASE_DIR}/ios"
  cp -R "${XCFRAMEWORK_DIR}/ProviiSDK.xcframework" "${RELEASE_DIR}/ios/"

  mkdir -p "${RELEASE_DIR}/bindings/swift"
  cp "${SWIFT_OUT}/"*.swift "${RELEASE_DIR}/bindings/swift/" 2>/dev/null || true
  cp "${SWIFT_OUT}/"*.h "${RELEASE_DIR}/bindings/swift/" 2>/dev/null || true
fi

# Generate checksums for all artifacts
echo "▶️ Generating checksums..."
cd "${RELEASE_DIR}"
find . -type f \( -name "*.so" -o -name "*.a" -o -name "*.kt" -o -name "*.swift" -o -name "*.h" \) \
  -exec shasum -a 256 {} \; > CHECKSUMS.txt 2>/dev/null || \
find . -type f \( -name "*.so" -o -name "*.a" -o -name "*.kt" -o -name "*.swift" -o -name "*.h" \) \
  -exec sha256sum {} \; > CHECKSUMS.txt
cd "${REPO_ROOT}"

echo "✅  Artifacts staged in: ${RELEASE_DIR}"

################################################################################
# 9. Print build summary and verification steps
################################################################################
echo
echo "🎉  All bindings and native libraries are up-to-date."
echo

echo "📦 Release Artifacts staged in: ${RELEASE_DIR}/"
echo

if [[ "$BUILD_ANDROID" == true ]]; then
  echo "📱 Android:"
  echo "    • Native libs     ➜  ${RELEASE_DIR}/android/"
  echo "    • Kotlin bindings ➜  ${RELEASE_DIR}/bindings/kotlin/"
  echo
fi

if [[ "$BUILD_IOS" == true ]]; then
  echo "🍎 iOS:"
  echo "    • XCFramework     ➜  ${RELEASE_DIR}/ios/ProviiSDK.xcframework"
  echo "    • Swift bindings  ➜  ${RELEASE_DIR}/bindings/swift/"
  echo
fi

echo "📋 Checksums: ${RELEASE_DIR}/CHECKSUMS.txt"
echo

echo "🔧  Multi-threading features enabled:"
echo "    • android/ios     - Platform-specific support with Rayon thread pool"
echo "    • parallel        - Multi-threaded proof generation (n-2 threads)"  
echo "    • debug-threading - Thread diagnostics and performance logging"
echo "    • http3           - HTTP/3 support (with HTTP/2 fallback)"
echo
echo "📊  Expected performance on 8-core device:"
echo "    • Threads for proving: 6 (n-2 strategy)"
echo "    • Expected proof time: 8-15 seconds (vs 40+ seconds single-threaded)"
echo
echo "🌐  Network protocol support:"
echo "    • HTTP/3 with QUIC (when available)"
echo "    • Automatic fallback to HTTP/2"
echo "    • HTTPS enforced for all connections"
echo
echo "🔍  To verify multi-threading is working, look for these logs:"
echo '    "✔ Rayon global thread pool initialized with 6 threads"'
echo '    "Performance suggests: MULTI-THREADED execution"'
echo
echo "🔍  To verify HTTP/3 is working, look for these logs:"
echo '    "HTTP/3 support enabled"'
echo '    "POST https://verify.provii.app/v1/verify -> HTTP/3 200 OK"'

# Optional: Run basic validation
if command -v file >/dev/null 2>&1; then
  echo
  echo "🔍  Library architecture verification:"
  if [[ "$BUILD_ANDROID" == true ]] && [[ -f "${RELEASE_DIR}/android/arm64-v8a/${LIB_NAME}.so" ]]; then
    echo -n "    • Android arm64:  "
    file "${RELEASE_DIR}/android/arm64-v8a/${LIB_NAME}.so" | grep -o "ARM aarch64" || echo "verification failed"
  fi
  if [[ "$BUILD_IOS" == true ]] && [[ -d "${RELEASE_DIR}/ios/ProviiSDK.xcframework" ]]; then
    echo -n "    • iOS device:     "
    # Use lipo for iOS static libraries
    IOS_LIB="${RELEASE_DIR}/ios/ProviiSDK.xcframework/ios-arm64/libprovii_mobile_sdk_ffi.a"
    if [[ -f "$IOS_LIB" ]] && command -v lipo >/dev/null 2>&1 && lipo -info "$IOS_LIB" 2>&1 | grep -q "arm64"; then
      echo "ARM arm64"
    elif command -v lipo >/dev/null 2>&1; then
      echo "verification failed"
    else
      echo "lipo not found"
    fi
  fi
fi