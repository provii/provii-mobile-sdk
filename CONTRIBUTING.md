# Contributing to Provii Mobile SDK

Thank you for your interest in contributing to the Provii Mobile SDK.

## Getting Started

1. Fork the repository
2. Clone your fork
3. Create a feature branch from `main`
4. Make your changes
5. Submit a pull request

## Development Setup

### Prerequisites

- **Rust 1.75+**: Install via [rustup](https://rustup.rs/)
- **For Android builds**:
  - Android NDK r26d or later
  - `cargo-ndk`: `cargo install cargo-ndk`
- **For iOS builds**:
  - macOS with Xcode 15+
  - iOS simulator targets: `rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim`

### Building

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/provii-mobile-sdk.git
cd provii-mobile-sdk

# Build
cargo build --release

# Run tests
cargo test --workspace --all-features

# Lint
cargo fmt --check
cargo clippy --workspace --all-features -- -D warnings

# Security audit
cargo audit
```

### Generating Bindings (Local Development)

```bash
# Full build (Android + iOS)
./generate_bindings.sh

# Android only
./generate_bindings.sh --android-only

# iOS only
./generate_bindings.sh --ios-only
```

## Pull Request Process

### 1. Branch Naming

Use descriptive branch names:
- `feat/add-new-proof-type`
- `fix/memory-leak-callback`
- `docs/update-integration-guide`

### 2. Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(core): add parallel proof generation
fix(ffi): correct memory cleanup in callbacks
docs: update README with new badges
ci: add security scanning workflow
```


### 3. PR Title

Use the same conventional commit format for PR titles:
```
feat(core): add new credential type support
```

### 4. PR Description

Include:
- **What**: Brief description of the change
- **Why**: Motivation for the change
- **How**: High-level approach (if not obvious)
- **Testing**: How you tested the changes

### 5. Checklist

Before submitting:

- [ ] Code compiles without warnings (`cargo build --release`)
- [ ] Tests pass (`cargo test --workspace --all-features`)
- [ ] Code is formatted (`cargo fmt`)
- [ ] No clippy warnings (`cargo clippy --workspace --all-features -- -D warnings`)
- [ ] Documentation updated if needed
- [ ] Commit messages follow conventional commits

## Code Style

### Rust Guidelines

- Follow standard Rust idioms
- Use `thiserror` for error types in library code
- Document all public APIs with doc comments
- Use `zeroize` for sensitive data
- Prefer `#[must_use]` on functions returning important values

### FFI Guidelines

- Never panic across FFI boundary - use `FfiResult<T>`
- All complex types serialized as JSON
- Thread safety via `Arc` for shared state
- Document any platform-specific behavior

## Testing

### Unit Tests

```bash
cargo test --workspace --all-features
```

### Integration Tests

Integration tests require platform-specific setup:

```bash
# Android (requires emulator or device)
./generate_bindings.sh --android-only
# Then run Android tests via Gradle

# iOS (requires simulator)
./generate_bindings.sh --ios-only
# Then run iOS tests via Xcode
```

## Contributor Licence Agreement (CLA)

All contributors must sign the project's [Contributor Licence Agreement](CLA.md) before their pull request can be merged. The CLA bot will comment on your PR with instructions when you open it. You only need to sign once; the signature applies to all future contributions to this repository.

If you are contributing on behalf of your employer, please ensure you have authorisation to sign the CLA.

## Questions?

- Open a [Discussion](https://github.com/provii/provii-mobile-sdk/discussions) for questions
- Check existing issues before opening new ones
