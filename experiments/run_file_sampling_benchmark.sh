#!/usr/bin/env bash
# 比较 FILE_OPEN 每 1/10/100 次采样时的端到端微基准开销。
set -euo pipefail

PERF_RUNS=5
PERF_ROOT="/tmp/ebpf-agent-monitor-file-sampling"

echo "warming up workload..."
/usr/bin/python3 experiments/performance_workload.py > /dev/null
sudo -v

for sample_every in 1 10 100; do
    baseline="$PERF_ROOT-$sample_every-baseline.txt"
    monitored="$PERF_ROOT-$sample_every-monitored.txt"
    : > "$baseline"
    : > "$monitored"

    echo "running $PERF_RUNS pairs for file_sample_every=$sample_every..."
    for ((run = 1; run <= PERF_RUNS; run++)); do
        /usr/bin/python3 experiments/performance_workload.py \
            --result "$baseline" > /dev/null
        sudo ./build/monitor --quiet-events --events file \
            --file-open-sample-every "$sample_every" \
            --agent 1 -- \
            /usr/bin/python3 experiments/performance_workload.py \
            --result "$monitored" > /dev/null
        echo "completed sample_every=$sample_every pair $run/$PERF_RUNS"
    done

    echo "file_sample_every=$sample_every"
    /usr/bin/python3 experiments/performance_report.py \
        "$baseline" "$monitored"
done
