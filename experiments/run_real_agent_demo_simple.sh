#!/usr/bin/env bash
# 简单真实 Agent 演示：启动一个百炼 Codex Agent 读取测试敏感文件，
# 验证注册、真实路径、告警、模型响应和 cgroup 排空退出。
set -uo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "$script_dir/.." && pwd)"
monitor="$project_dir/build/monitor"
launcher="$script_dir/run_bailian_codex_no_shell.py"
log_path="${DEMO_LOG:-/tmp/ebpf-agent-monitor-real-demo-simple.log}"

fail_setup() { echo "SETUP_ERROR: $1" >&2; exit 2; }

[[ $EUID -ne 0 ]] || fail_setup "run this script as the normal user; it invokes sudo itself"
[[ -x "$monitor" ]] || fail_setup "missing $monitor; run make first"
[[ -x "$launcher" ]] || fail_setup "missing executable launcher $launcher"
command -v rg >/dev/null 2>&1 || fail_setup "rg is required"
if [[ -z "${BAILIAN_API_KEY:-}" ]]; then
    read -r -s -p 'Bailian API Key (hidden): ' BAILIAN_API_KEY
    echo
    [[ -n "$BAILIAN_API_KEY" ]] || fail_setup "empty API Key"
    export BAILIAN_API_KEY
fi
BAILIAN_BASE_URL="${BAILIAN_BASE_URL:-https://dashscope.aliyuncs.com/compatible-mode/v1}"
BAILIAN_MODEL="${BAILIAN_MODEL:-qwen3.8-27b}"
export BAILIAN_BASE_URL BAILIAN_MODEL

demo_root="$(mktemp -d /tmp/ebpf-agent-monitor-real-demo-simple.XXXXXX)" || exit 1
sensitive_dir="$demo_root/sensitive"
marker="REAL_AGENT_SIMPLE_DEMO_OK"
mkdir -p "$sensitive_dir"
printf '%s\n' "$marker" > "$sensitive_dir/secret.txt"
chmod 444 "$sensitive_dir/secret.txt"
cleanup() { rm -rf -- "$demo_root"; }
trap cleanup EXIT

echo "Starting one real Codex Agent through Alibaba Cloud Model Studio."
echo "Full log: $log_path"
sudo --preserve-env=BAILIAN_API_KEY,BAILIAN_BASE_URL,BAILIAN_MODEL,CODEX_BIN \
  "$monitor" --hide-runtime-noise --events process,file,network \
  --agent 1 --sensitive-path "$sensitive_dir" \
  -- "$launcher" --cd "$sensitive_dir" \
    '只执行一次 cat secret.txt，原样报告读到的内容；如果命令失败，报告错误并立即停止。不要修改文件。' \
  > "$log_path" 2>&1
monitor_status=$?

failures=0
check() {
    local label="$1" pattern="$2"
    if rg -q -- "$pattern" "$log_path"; then
        printf 'PASS %s\n' "$label"
    else
        printf 'FAIL %s\n' "$label"
        failures=$((failures + 1))
    fi
}

printf 'monitor_exit=%d\n' "$monitor_status"
check agent_registration 'event=agent_register agent_id=1'
check target_file_open 'event=FILE_OPEN .*agent_id=1 .*comm=cat .*secret\.txt'
check sensitive_read_alert 'event=security_alert .*rule=sensitive_file_access .*agent_id=1 .*secret\.txt'
check agent_response "$marker"
check agent_exit 'event=agent_exit agent_id=1 .*exit_code=0 .*basis=cgroup_empty'
echo "key evidence:"
rg -n 'agent_register|event=FILE_OPEN .*comm=cat .*secret\.txt|rule=sensitive_file_access|REAL_AGENT_SIMPLE_DEMO_OK|agent_exit|tokens used' \
  "$log_path" || true

((monitor_status == 0)) || failures=$((failures + 1))
if ((failures)); then
    printf 'DEMO_RESULT=FAIL failures=%d\n' "$failures"
    exit 1
fi
echo 'DEMO_RESULT=PASS'
