#!/usr/bin/env bash
set -euo pipefail

PERF_RUNS=5
PERF_ROOT="/tmp/ebpf-agent-monitor-perf"

echo "warming up workload..."
/usr/bin/python3 experiments/performance_workload.py > /dev/null

sudo -v
for category in process file network all; do
    baseline="$PERF_ROOT-$category-baseline.txt"
    monitored="$PERF_ROOT-$category-monitored.txt"
    : > "$baseline"
    : > "$monitored"

    if [[ "$category" == "all" ]]; then
        event_list="process,file,network"
    else
        event_list="$category"
    fi

    echo "running $PERF_RUNS pairs for events=$category..."
    for ((run = 1; run <= PERF_RUNS; run++)); do
        /usr/bin/python3 experiments/performance_workload.py \
            --result "$baseline" > /dev/null
        sudo ./build/monitor --quiet-events --events "$event_list" \
            --agent 1 -- \
            /usr/bin/python3 experiments/performance_workload.py \
            --result "$monitored" > /dev/null
        echo "completed events=$category pair $run/$PERF_RUNS"
    done

    echo "configuration=$category"
    /usr/bin/python3 experiments/performance_report.py \
        "$baseline" "$monitored"
done
