#!/usr/bin/env bash
# 一键启动两个确定性工作负载，收集日志并核对基础验收项。
# 脚本自身以普通用户运行，仅在加载 monitor 时调用 sudo。
set -uo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "$script_dir/.." && pwd)"
monitor="$project_dir/build/monitor"
workload="$script_dir/acceptance_demo_agent.py"
log_path="${DEMO_LOG:-/tmp/ebpf-agent-monitor-acceptance-demo.log}"

if [[ $EUID -eq 0 ]]; then
    echo "run this script as the normal user; it invokes sudo itself" >&2
    exit 2
fi
if [[ ! -x "$monitor" ]]; then
    echo "missing $monitor; run make first" >&2
    exit 2
fi
if ! command -v rg >/dev/null 2>&1; then
    echo "rg is required to summarize the demo" >&2
    exit 2
fi

demo_root="$(mktemp -d /tmp/ebpf-agent-monitor-demo.XXXXXX)" || exit 1
workspace="$demo_root/workspace"
sensitive_dir="$demo_root/sensitive"
outside_dir="$demo_root/outside"
mkdir -p "$workspace" "$sensitive_dir" "$outside_dir"
printf 'DEMO_SENSITIVE_MARKER\n' > "$sensitive_dir/secret.txt"
printf 'DEMO_ALLOWED_DELETE\n' > "$workspace/allowed.txt"
printf 'DEMO_OUTSIDE_DELETE\n' > "$outside_dir/victim.txt"

cleanup() {
    rm -rf -- "$demo_root"
}
trap cleanup EXIT

echo "demo_root=$demo_root"
echo "log=$log_path"

sudo "$monitor" --hide-runtime-noise --events process,file,network \
  --agent 1 \
  --sensitive-path "$sensitive_dir" \
  --workspace "$workspace" \
  --failed-open-threshold 5 \
  --failed-open-window-ms 2000 \
  --cpu-sample-ms 200 \
  --cpu-threshold-percent 50 \
  -- /usr/bin/python3 "$workload" security \
    --sensitive-file "$sensitive_dir/secret.txt" \
    --allowed-file "$workspace/allowed.txt" \
    --outside-file "$outside_dir/victim.txt" \
    --missing-file "$workspace/missing.txt" \
  --next \
  --agent 2 --shell-policy deny \
  -- /usr/bin/python3 "$workload" process-network \
  > "$log_path" 2>&1
monitor_status=$?

failures=0
check() {
    local label="$1"
    local pattern="$2"
    if rg -q -- "$pattern" "$log_path"; then
        printf 'PASS %s\n' "$label"
    else
        printf 'FAIL %s\n' "$label"
        failures=$((failures + 1))
    fi
}

printf 'monitor_exit=%d\n' "$monitor_status"
check "agent_1_registration" 'event=agent_register agent_id=1'
check "agent_2_registration" 'event=agent_register agent_id=2'
check "process_fork" 'event=PROCESS_FORK.*agent_id=2'
check "network_connect" 'event=CONNECT_RESULT.*agent_id=2.*ret=0'
check "unexpected_shell" 'event=security_alert.*rule=unexpected_shell.*agent_id=2'
check "sensitive_read" 'event=security_alert.*rule=sensitive_file_access.*agent_id=1'
check "outside_delete" 'event=security_alert.*rule=outside_workspace_delete.*agent_id=1'
check "repeated_failed_open" 'event=security_alert.*rule=repeated_failed_open.*agent_id=1'
check "resource_logic_anomaly" 'event=anomaly_alert.*rule=resource_logic_anomaly.*agent_id=1'
check "agent_1_exit" 'event=agent_exit agent_id=1.*exit_code=0'
check "agent_2_exit" 'event=agent_exit agent_id=2.*exit_code=0'

echo "key evidence:"
rg -n 'agent_register|security_alert|anomaly_alert|CONNECT_RESULT.*ret=0|agent_exit' \
  "$log_path"

if ((monitor_status != 0)); then
    failures=$((failures + 1))
fi
if ((failures)); then
    printf 'DEMO_RESULT=FAIL failures=%d\n' "$failures"
    exit 1
fi
echo 'DEMO_RESULT=PASS'
