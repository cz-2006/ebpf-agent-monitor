#!/usr/bin/env bash
# 固定 FILE_OPEN N=100，增加配对次数以观察测量波动和稳定性。
set -euo pipefail

PERF_RUNS=15
PERF_BASELINE="/tmp/ebpf-agent-monitor-stability-baseline.txt"
PERF_MONITORED="/tmp/ebpf-agent-monitor-stability-monitored.txt"

: > "$PERF_BASELINE"
: > "$PERF_MONITORED"

echo "warming up workload..."
/usr/bin/python3 experiments/performance_workload.py > /dev/null
sudo -v

echo "running $PERF_RUNS pairs for file_sample_every=100..."
for ((run = 1; run <= PERF_RUNS; run++)); do
    /usr/bin/python3 experiments/performance_workload.py \
        --result "$PERF_BASELINE" > /dev/null
    sudo ./build/monitor --quiet-events --events file \
        --file-open-sample-every 100 \
        --agent 1 -- \
        /usr/bin/python3 experiments/performance_workload.py \
        --result "$PERF_MONITORED" > /dev/null
    echo "completed pair $run/$PERF_RUNS"
done

echo "file_sample_every=100 stability_run=1"
exec /usr/bin/python3 experiments/performance_report.py \
    "$PERF_BASELINE" "$PERF_MONITORED"
