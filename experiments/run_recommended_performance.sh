#!/usr/bin/env bash
# 测量推荐运行配置：三类事件、FILE_OPEN N=100、关闭普通事件展示。
# 每对交替基线/监控顺序，并由 performance_report.py 汇总分位数。
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "$script_dir/.." && pwd)"
monitor="$project_dir/build/monitor"
workload="$script_dir/performance_workload.py"
report="$script_dir/performance_report.py"
runs="${PERF_RUNS:-15}"
result_root="${PERF_ROOT:-/tmp/ebpf-agent-monitor-recommended}"
baseline="$result_root-baseline.txt"
monitored="$result_root-monitored.txt"

if [[ $EUID -eq 0 ]]; then
    echo "run this script as the normal user; it invokes sudo itself" >&2
    exit 2
fi
if [[ ! -x "$monitor" ]]; then
    echo "missing $monitor; run make first" >&2
    exit 2
fi
if [[ ! "$runs" =~ ^[1-9][0-9]*$ ]]; then
    echo "PERF_RUNS must be a positive integer" >&2
    exit 2
fi

: > "$baseline"
: > "$monitored"

run_baseline() {
    /usr/bin/python3 "$workload" --result "$baseline" > /dev/null
}

run_monitored() {
    sudo "$monitor" --quiet-events --events process,file,network \
      --file-open-sample-every 100 \
      --agent 1 -- /usr/bin/python3 "$workload" \
      --result "$monitored" > /dev/null
}

echo "configuration=recommended events=process,file,network file_sample_every=100 quiet_events=1"
echo "warming up baseline workload..."
/usr/bin/python3 "$workload" > /dev/null
sudo -v

echo "running $runs paired samples..."
for ((run = 1; run <= runs; run++)); do
    if ((run % 2 == 1)); then
        run_baseline
        run_monitored
        order="baseline-first"
    else
        run_monitored
        run_baseline
        order="monitored-first"
    fi
    echo "completed pair $run/$runs order=$order"
done

echo "configuration=recommended"
echo "events=process,file,network"
echo "file_sample_every=100"
echo "quiet_events=1"
exec /usr/bin/python3 "$report" "$baseline" "$monitored"
