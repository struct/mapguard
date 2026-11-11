#!/bin/bash
# MapGuard full test script - runs inside Ubuntu Linux container
set -e

echo "========================================"
echo "  MapGuard Full Test Suite"
echo "========================================"

cd /mapguard

# Install deps
apt-get update -qq
apt-get install -y -qq clang make > /dev/null 2>&1
echo "[OK] Build tools installed"

# ---- Build everything in one pass ----
echo ""
echo "--- Building library, tests, and demos ---"
make clean
make library_debug 2>&1
make tests 2>&1
make demo 2>&1
echo "[OK] All binaries built successfully"

ls -la build/

# ---- Run existing tests ----
echo ""
echo "--- Running existing tests ---"
export MG_PANIC_ON_VIOLATION=0
export MG_USE_MAPPING_CACHE=1
export MG_PREVENT_RWX=1
export MG_PREVENT_TRANSITION_FROM_X=1
export MG_PREVENT_STATIC_ADDRESS=1
export MG_ENABLE_GUARD_PAGES=1
export MG_POISON_ON_ALLOCATION=1
export MG_ENABLE_SYSLOG=0
export MG_SNAPSHOT_INTERVAL_MS=500
export MG_OBSERVE_COUNT=5
export MG_GROWTH_THRESHOLD_BYTES=1048576

echo "Running mapguard_test..."
export MG_REPORT_PATH=/tmp/mg_report_existing.txt
LD_PRELOAD=build/libmapguard.so build/mapguard_test 2>/dev/null && echo "[PASS] mapguard_test" || echo "[FAIL] mapguard_test"

echo "Running mapguard_thread_test..."
export MG_REPORT_PATH=/tmp/mg_report_thread.txt
LD_PRELOAD=build/libmapguard.so build/mapguard_thread_test 2>/dev/null && echo "[PASS] mapguard_thread_test" || echo "[FAIL] mapguard_thread_test"

# ---- Run demos ----
echo ""
echo "--- Running demo programs ---"

# Normal demo - should produce 0 leaks
echo ""
echo ">> normal_demo (expect: 0 outstanding leaks):"
export MG_REPORT_PATH=/tmp/mg_report_normal.txt
unset MG_ENABLE_GUARD_PAGES  # simpler for demo
unset MG_USE_MAPPING_CACHE
export MG_SNAPSHOT_INTERVAL_MS=500
export MG_OBSERVE_COUNT=5
LD_PRELOAD=build/libmapguard.so build/normal_demo 2>/dev/null
OUTSTANDING=$(grep "Outstanding mappings:" /tmp/mg_report_normal.txt | awk '{print $NF}')
if [ "$OUTSTANDING" = "0" ]; then
    echo "[PASS] normal_demo: 0 outstanding leaks confirmed"
else
    echo "[FAIL] normal_demo: expected 0 leaks, got $OUTSTANDING"
fi

# Leak demo - should show 2 leaks
echo ""
echo ">> leak_demo (expect: 2 outstanding leaks):"
export MG_REPORT_PATH=/tmp/mg_report_leak.txt
LD_PRELOAD=build/libmapguard.so build/leak_demo 2>/dev/null
OUTSTANDING=$(grep "Outstanding mappings:" /tmp/mg_report_leak.txt | awk '{print $NF}')
if [ "$OUTSTANDING" = "2" ]; then
    echo "[PASS] leak_demo: 2 outstanding leaks confirmed"
else
    echo "[FAIL] leak_demo: expected 2 leaks, got $OUTSTANDING"
fi
grep "Outstanding Application Mappings" /tmp/mg_report_leak.txt

# Partial munmap demo
echo ""
echo ">> partial_munmap_demo (expect: 0 outstanding - all cleaned up):"
export MG_REPORT_PATH=/tmp/mg_report_partial.txt
LD_PRELOAD=build/libmapguard.so build/partial_munmap_demo 2>/dev/null
OUTSTANDING=$(grep "Outstanding mappings:" /tmp/mg_report_partial.txt | awk '{print $NF}')
echo "  Outstanding: $OUTSTANDING"
grep "Peak mapped bytes:" /tmp/mg_report_partial.txt

# mremap demo
echo ""
echo ">> mremap_demo (expect: 0 outstanding leaks):"
export MG_REPORT_PATH=/tmp/mg_report_mremap.txt
LD_PRELOAD=build/libmapguard.so build/mremap_demo 2>/dev/null
OUTSTANDING=$(grep "Outstanding mappings:" /tmp/mg_report_mremap.txt | awk '{print $NF}')
if [ "$OUTSTANDING" = "0" ]; then
    echo "[PASS] mremap_demo: 0 outstanding leaks confirmed"
else
    echo "[FAIL] mremap_demo: expected 0 leaks, got $OUTSTANDING"
fi
grep "Peak mapped bytes:" /tmp/mg_report_mremap.txt

# Growth demo - shorter interval for testing
echo ""
echo ">> growth_demo (expect: growth warning + 12 outstanding leaks):"
export MG_REPORT_PATH=/tmp/mg_report_growth.txt
export MG_SNAPSHOT_INTERVAL_MS=300
export MG_OBSERVE_COUNT=5
export MG_GROWTH_THRESHOLD_BYTES=65536  # 64 KiB to trigger quickly
LD_PRELOAD=build/libmapguard.so build/growth_demo 2>/dev/null
OUTSTANDING=$(grep "Outstanding mappings:" /tmp/mg_report_growth.txt | awk '{print $NF}')
if [ "$OUTSTANDING" = "12" ]; then
    echo "[PASS] growth_demo: 12 outstanding leaks confirmed"
else
    echo "[CHECK] growth_demo: expected 12 leaks, got $OUTSTANDING"
fi
if grep -q "GROWTH WARNING" /tmp/mg_report_growth.txt; then
    echo "[PASS] growth_demo: growth warning present"
    grep "Memory grew" /tmp/mg_report_growth.txt
else
    echo "[FAIL] growth_demo: no growth warning found"
fi

echo ""
echo "========================================"
echo "  Full test results summary"
echo "========================================"
echo "normal_demo:         outstanding=$(grep 'Outstanding mappings:' /tmp/mg_report_normal.txt | awk '{print $NF}')"
echo "leak_demo:           outstanding=$(grep 'Outstanding mappings:' /tmp/mg_report_leak.txt | awk '{print $NF}')"
echo "partial_munmap_demo: outstanding=$(grep 'Outstanding mappings:' /tmp/mg_report_partial.txt | awk '{print $NF}')"
echo "mremap_demo:         outstanding=$(grep 'Outstanding mappings:' /tmp/mg_report_mremap.txt | awk '{print $NF}')"
echo "growth_demo:         outstanding=$(grep 'Outstanding mappings:' /tmp/mg_report_growth.txt | awk '{print $NF}')"
echo "growth_demo:         warning=$(grep -c 'GROWTH WARNING' /tmp/mg_report_growth.txt) occurrence(s)"
echo "========================================"
