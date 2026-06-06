// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

/// Entry point for the UniFFI binding generator.
///
/// Running `cargo run --bin uniffi-bindgen` invokes this binary, which
/// delegates to [`uniffi::uniffi_bindgen_main`] to produce Swift and
/// Kotlin source files from the UDL and proc-macro metadata in this crate.
fn main() {
    uniffi::uniffi_bindgen_main()
}
