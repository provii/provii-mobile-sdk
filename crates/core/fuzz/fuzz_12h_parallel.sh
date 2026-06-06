#!/bin/bash
# 12-Hour Fuzzing Campaign - Parallel Execution
# Run all 4 targets in parallel for 12 hours simultaneously
#
# Total runtime: ~12 hours (all targets run concurrently)
# Requires: Enough CPU cores to run all targets (recommended: 8+ cores)
#
# Usage:
#   chmod +x fuzz_12h_parallel.sh
#   ./fuzz_12h_parallel.sh

set -e

cd "$(dirname "$0")"

DURATION=$((12 * 3600))  # 12 hours in seconds
TOTAL_CORES=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 8)
JOBS_PER_TARGET=$((TOTAL_CORES / 4))  # Divide cores among 4 targets

if [ "$JOBS_PER_TARGET" -lt 1 ]; then
    JOBS_PER_TARGET=1
fi

echo "========================================"
echo "12-Hour PARALLEL Fuzzing Campaign"
echo "provii-mobile-sdk-core"
echo "========================================"
echo "Duration: 12 hours (all targets run simultaneously)"
echo "Total CPU cores: $TOTAL_CORES"
echo "Cores per target: $JOBS_PER_TARGET"
echo "Start time: $(date)"
echo "========================================"
echo ""

TARGETS=(
    "fuzz_credential_json"
    "fuzz_base64_utils"
    "fuzz_qr_parsing"
    "fuzz_date_parsing"
)

# Clean up any previous PID file
rm -f fuzz_pids.txt

# Launch all targets in background
for TARGET in "${TARGETS[@]}"; do
    echo "Launching $TARGET in background..."

    (
        cargo +nightly fuzz run "$TARGET" -- \
            -max_total_time="$DURATION" \
            -jobs="$JOBS_PER_TARGET" \
            -rss_limit_mb=2048 \
            -print_final_stats=1 \
            2>&1 | tee "fuzz_results_${TARGET}_$(date +%Y%m%d_%H%M%S).log"

        EXIT_CODE=$?
        echo "$TARGET finished with exit code $EXIT_CODE at $(date)" >> fuzz_completion.log

        if [ $EXIT_CODE -ne 0 ]; then
            echo "CRASH FOUND in $TARGET!" >> fuzz_completion.log
        fi
    ) &

    # Store the PID
    echo $! >> fuzz_pids.txt
done

echo ""
echo "All targets launched in background"
echo "PIDs saved to fuzz_pids.txt"
echo ""
echo "Monitor progress:"
echo "  tail -f fuzz_results_*.log"
echo "  tail -f fuzz_completion.log"
echo ""
echo "Stop all fuzzers:"
echo "  cat fuzz_pids.txt | xargs kill"
echo ""

# Wait for all background jobs
wait

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

# Clean up
rm -f fuzz_pids.txt
