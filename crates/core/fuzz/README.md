# Fuzzing for provii-mobile-sdk-core

This directory contains fuzzing infrastructure for provii-mobile-sdk-core using cargo-fuzz and libFuzzer.

## Fuzz Targets

### High Priority
- **fuzz_credential_json** - Tests `CredentialV2::from_json()` parsing for credential JSON deserialization
- **fuzz_base64_utils** - Tests `encode_base64url()` and `decode_base64url()` for URL-safe base64 encoding

### Medium Priority
- **fuzz_qr_parsing** - Tests `parse_qr_json<QrChallengePayload>()` for QR code payload parsing
- **fuzz_date_parsing** - Tests `parse_dob_iso()` and `days_to_iso()` for ISO date parsing

## Quick Start

### Prerequisites
```bash
# Install nightly Rust (required for fuzzing)
rustup install nightly

# Install cargo-fuzz
cargo install cargo-fuzz
```

### Running Individual Fuzz Tests

```bash
# List all available targets
cargo +nightly fuzz list

# Run a specific target for 60 seconds
cargo +nightly fuzz run fuzz_credential_json -- -max_total_time=60

# Run with multiple jobs (parallel fuzzing)
cargo +nightly fuzz run fuzz_base64_utils -- -max_total_time=300 -jobs=4
```

## 12-Hour Fuzzing Campaigns

Three scripts are provided for extended fuzzing campaigns:

### 1. Parallel Execution (Recommended for multi-core systems)

Run all 4 targets in parallel for 12 hours:

```bash
./fuzz_12h_parallel.sh
```

- **Runtime**: ~12 hours (all targets run simultaneously)
- **Requirements**: 8+ CPU cores recommended
- **Best for**: Finding bugs quickly across all targets

### 2. Sequential Execution

Run all 4 targets sequentially for 12 hours each:

```bash
./fuzz_12h_all.sh
```

- **Runtime**: ~48 hours (2 days total)
- **Best for**: Deep testing of each target with full CPU resources
- **Tip**: Run in tmux/screen session

### 3. Individual Target

Run a single target for 12 hours:

```bash
./fuzz_12h_individual.sh fuzz_credential_json
```

- **Runtime**: ~12 hours
- **Best for**: Focused testing on a specific area

## Monitoring

### View Real-time Progress

```bash
# Watch all fuzz targets (parallel mode)
tail -f fuzz_results_*.log

# Watch completion status
tail -f fuzz_completion.log

# View specific target
tail -f fuzz_results_fuzz_credential_json_*.log
```

### Stop Running Fuzzers

```bash
# Stop all parallel fuzzers
cat fuzz_pids.txt | xargs kill

# Or use Ctrl+C for individual runs
```

## Analyzing Results

### Check for Crashes

```bash
# List all crash artifacts
ls -la artifacts/*/crash-*

# Reproduce a specific crash
cargo +nightly fuzz run fuzz_credential_json artifacts/fuzz_credential_json/crash-abc123

# Minimize a crash case
cargo +nightly fuzz tmin fuzz_credential_json artifacts/fuzz_credential_json/crash-abc123
```

### View Coverage

```bash
# Generate coverage report
cargo +nightly fuzz coverage fuzz_credential_json

# View corpus statistics
ls -lh corpus/fuzz_credential_json/
```

## Continuous Integration

For CI/CD pipelines, run fuzzers for a shorter duration:

```bash
# 5-minute smoke test per target
for target in $(cargo +nightly fuzz list); do
    cargo +nightly fuzz run $target -- -max_total_time=300 -jobs=2
done
```

## Advanced Options

### Libfuzzer Options

```bash
cargo +nightly fuzz run TARGET -- [libfuzzer options]

# Common options:
#   -max_total_time=SECONDS    Stop after N seconds
#   -jobs=N                    Run N parallel jobs
#   -rss_limit_mb=MB          Memory limit per job
#   -dict=FILE                Use dictionary file
#   -print_final_stats=1      Show final statistics
#   -max_len=N                Maximum input length
```

### Using Dictionaries

If you create a dictionary file (e.g., `json.dict`):

```bash
cargo +nightly fuzz run fuzz_credential_json -- -dict=json.dict
```

## Target Details

### fuzz_credential_json
- **Function**: `CredentialV2::from_json()`
- **Tests**: 15 categories including malformed JSON, wrong types, nulls, truncation
- **Priority**: HIGH - Parses untrusted credential data

### fuzz_base64_utils
- **Functions**: `encode_base64url()`, `decode_base64url()`
- **Tests**: 25 categories with assertions for URL-safe alphabet, no padding, roundtrip
- **Priority**: HIGH - Used for QR codes and URLs

### fuzz_qr_parsing
- **Function**: `parse_qr_json<QrChallengePayload>()`
- **Tests**: 25 categories covering QR payload edge cases
- **Priority**: MEDIUM - Parses QR code JSON data

### fuzz_date_parsing
- **Functions**: `parse_dob_iso()`, `days_to_iso()`
- **Tests**: 25 categories including leap years, epoch boundaries, validation
- **Priority**: MEDIUM - Date parsing for date of birth

## Troubleshooting

### "error: the option Z is only accepted on the nightly compiler"

Use `cargo +nightly` instead of `cargo`:

```bash
cargo +nightly fuzz run TARGET
```

### Out of Memory

Reduce memory limit or job count:

```bash
cargo +nightly fuzz run TARGET -- -rss_limit_mb=1024 -jobs=1
```

### Crash in Fuzz Target Harness

This is different from a crash in the code under test. Check if the issue is in the test harness itself.

## Resources

- [cargo-fuzz documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer options](https://llvm.org/docs/LibFuzzer.html#options)
- [Rust Fuzz Book](https://rust-fuzz.github.io/book/)
