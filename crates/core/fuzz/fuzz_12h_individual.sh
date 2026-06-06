#!/bin/bash
# 12-Hour Fuzzing Campaign - Single Target
# Run a single fuzz target for 12 hours
#
# Usage:
#   chmod +x fuzz_12h_individual.sh
#   ./fuzz_12h_individual.sh <target_name>
#
# Examples:
#   ./fuzz_12h_individual.sh fuzz_credential_json
#   ./fuzz_12h_individual.sh fuzz_base64_utils

set -e

cd "$(dirname "$0")"

if [ $# -eq 0 ]; then
    echo "ERROR: No target specified"
    echo ""
    echo "Usage: $0 <target_name>"
    echo ""
    echo "Available targets:"
    cargo +nightly fuzz list
    exit 1
fi

TARGET="$1"
DURATION=$((12 * 3600))  # 12 hours in seconds
JOBS=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)

echo "========================================"
echo "12-Hour Fuzzing Campaign"
echo "provii-mobile-sdk-core"
echo "========================================"
echo "Target: $TARGET"
echo "Duration: 12 hours"
echo "CPU cores: $JOBS"
echo "Start time: $(date)"
echo "========================================"
echo ""

LOG_FILE="fuzz_results_${TARGET}_$(date +%Y%m%d_%H%M%S).log"

cargo +nightly fuzz run "$TARGET" -- \
    -max_total_time="$DURATION" \
    -jobs="$JOBS" \
    -rss_limit_mb=4096 \
    -print_final_stats=1 \
    2>&1 | tee "$LOG_FILE"

EXIT_CODE=$?

echo ""
echo "========================================"
echo "FUZZING CAMPAIGN COMPLETED"
echo "========================================"
echo "Target: $TARGET"
echo "Exit code: $EXIT_CODE"
echo "Finished: $(date)"
echo "Log file: $LOG_FILE"
echo "========================================"

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "WARNING: Fuzzer exited with non-zero code $EXIT_CODE"
    echo "This may indicate a crash was found!"
    echo "Check artifacts/$TARGET/ for crash files"
fi

echo ""
echo "Corpus files: $(ls corpus/$TARGET 2>/dev/null | wc -l | xargs)"
echo "Artifacts: $(ls artifacts/$TARGET 2>/dev/null | wc -l | xargs)"
