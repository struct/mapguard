#!/usr/bin/env bash

set -e

echo "Building performance test..."
make perf_tests

echo "================================================================"
echo "Running baseline performance (no MapGuard)..."
echo "================================================================"
./build/mapguard_perf_test > /tmp/baseline_perf.csv
cat /tmp/baseline_perf.csv

echo ""
echo "================================================================"
echo "Running with MapGuard (no config)..."
echo "================================================================"
LD_PRELOAD=build/libmapguard.so ./build/mapguard_perf_test > /tmp/minimal_perf.csv
cat /tmp/minimal_perf.csv

echo ""
echo "================================================================"
echo "Running with MapGuard (cache enabled)..."
echo "================================================================"
MG_USE_MAPPING_CACHE=1 LD_PRELOAD=build/libmapguard.so ./build/mapguard_perf_test > /tmp/cache_perf.csv
cat /tmp/cache_perf.csv

echo ""
echo "================================================================"
echo "Running with MapGuard (full protection)..."
echo "================================================================"
MG_USE_MAPPING_CACHE=1 MG_ENABLE_GUARD_PAGES=1 \
MG_PREVENT_RWX=1 MG_PREVENT_TRANSITION_TO_X=1 \
MG_PREVENT_TRANSITION_FROM_X=1 MG_POISON_ON_ALLOCATION=1 \
LD_PRELOAD=build/libmapguard.so ./build/mapguard_perf_test > /tmp/full_perf.csv
cat /tmp/full_perf.csv

echo ""
echo "================================================================"
echo "Performance Summary"
echo "================================================================"

python3 - <<'EOF'
import csv

configs = [
    ("Baseline", "/tmp/baseline_perf.csv"),
    ("Minimal", "/tmp/minimal_perf.csv"),
    ("Cache", "/tmp/cache_perf.csv"),
    ("Full", "/tmp/full_perf.csv")
]

def iter_perf_rows(filepath):
    with open(filepath, 'r') as f:
        lines = f.readlines()

    header_idx = next((i for i, line in enumerate(lines)
                       if line.strip().lower().startswith('test_name,')), None)
    if header_idx is None:
        return

    for row in csv.DictReader(lines[header_idx:]):
        test = row.get('test_name')
        ops = row.get('ops_per_sec')
        if not test or ops is None:
            continue
        try:
            yield test, float(ops)
        except ValueError:
            continue

results = {}
for config_name, filepath in configs:
    for test, ops in iter_perf_rows(filepath):
        results.setdefault(test, {})[config_name] = ops

print(f"{'Test':<30} {'Baseline':<11} {'Minimal':<9} {'Cache':<12} {'Full':<11} {'Overhead %':<12}")
print("=" * 100)

for test in results:
    baseline = results[test].get('Baseline')
    if baseline is None:
        continue
    print(f"{test:<25} {baseline:>11.0f}", end='')
    for config in ['Minimal', 'Cache', 'Full']:
        ops = results[test].get(config)
        print(f" {ops:>11.0f}" if ops is not None else f" {'N/A':>11}", end='')
    full_ops = results[test].get('Full')
    if full_ops is None:
        print(f" {'N/A':>11}")
    else:
        overhead = ((baseline - full_ops) / baseline) * 100
        print(f" {overhead:>11.1f}%")
EOF

echo ""
echo "Raw CSV files saved in /tmp/*_perf.csv"
