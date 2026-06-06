#!/bin/bash
# 12-Hour Fuzzing Campaign - All Targets
# Run all 4 production fuzz targets sequentially for 12 hours each
#
# Total runtime: ~48 hours (2 days)
# Recommended: Run in tmux/screen session or use nohup
#
# Usage:
#   chmod +x fuzz_12h_all.sh
#   ./fuzz_12h_all.sh

set -e

cd "$(dirname "$0")"

DURATION=$((12 * 3600))  # 12 hours in seconds
JOBS=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)  # Auto-detect CPU count

echo "========================================"
echo "12-Hour Fuzzing Campaign"
echo "provii-mobile-sdk-core"
echo "========================================"
echo "Duration per target: 12 hours"
echo "Total estimated time: ~48 hours (2 days)"
echo "CPU cores: $JOBS"
echo "Start time: $(date)"
echo "========================================"
echo ""

TARGETS=(
    "fuzz_credential_json"
    "fuzz_base64_utils"
    "fuzz_qr_parsing"
    "fuzz_date_parsing"
)

for TARGET in "${TARGETS[@]}"; do
    echo ""
    echo "========================================"
    echo "Running: $TARGET"
    echo "Started: $(date)"
    echo "========================================"

    cargo +nightly fuzz run "$TARGET" -- \
        -max_total_time="$DURATION" \
        -jobs="$JOBS" \
        -rss_limit_mb=4096 \
        -print_final_stats=1 \
        2>&1 | tee "fuzz_results_${TARGET}_$(date +%Y%m%d_%H%M%S).log"

    EXIT_CODE=$?

    echo ""
    echo "========================================"
    echo "Completed: $TARGET"
    echo "Exit code: $EXIT_CODE"
    echo "Finished: $(date)"
    echo "========================================"

    if [ $EXIT_CODE -ne 0 ]; then
        echo "WARNING: $TARGET exited with non-zero code $EXIT_CODE"
        echo "This may indicate a crash was found!"
        echo "Check artifacts/$TARGET/ for crash files"
    fi

    # Brief pause between targets
    sleep 5
done

echo ""
echo "========================================"
echo "ALL FUZZING CAMPAIGNS COMPLETED"
echo "Finished: $(date)"
echo "========================================"
echo ""
echo "Results summary:"
for TARGET in "${TARGETS[@]}"; do
    CORPUS_COUNT=$(ls "corpus/$TARGET" 2>/dev/null | wc -l | xargs)
    ARTIFACTS=$(ls "artifacts/$TARGET" 2>/dev/null | wc -l | xargs)
    echo "  $TARGET: $CORPUS_COUNT corpus files, $ARTIFACTS artifacts"
done
