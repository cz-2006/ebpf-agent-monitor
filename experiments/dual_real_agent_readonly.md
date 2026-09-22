# 双真实 Codex Agent 只读归属实验

状态：2026-09-22 用户已完成 sudo 端到端实测，结果见文末。

目标是让一个监控器同时启动两个 Codex CLI Agent。每组使用独立工作目录，
只读取自己的 `marker.txt`，核对进程、文件和网络事件的 `agent_id`/`cgroup_id`。
这验证受控双真实 Agent 的归属，不测试协作、竞争或高并发压力。

## 夹具

本机已在 `/tmp/ebpf-agent-monitor-qwen-dual/agent1` 和 `agent2` 准备好
权限为 444 的 `marker.txt`，内容分别为 `AGENT_ONE_20260922` 与
`AGENT_TWO_20260922`。若临时目录在重启后消失，可重新执行：

```bash
mkdir -p /tmp/ebpf-agent-monitor-qwen-dual/agent1 \
  /tmp/ebpf-agent-monitor-qwen-dual/agent2
printf 'AGENT_ONE_20260922\n' > /tmp/ebpf-agent-monitor-qwen-dual/agent1/marker.txt
printf 'AGENT_TWO_20260922\n' > /tmp/ebpf-agent-monitor-qwen-dual/agent2/marker.txt
chmod 444 /tmp/ebpf-agent-monitor-qwen-dual/agent{1,2}/marker.txt
```

## 运行

在已配置 `BAILIAN_API_KEY` 和 `BAILIAN_BASE_URL` 的同一终端，从项目根目录执行。
这会发起两次真实模型会话；不需要把密钥或完整日志发给他人。

```bash
sudo --preserve-env=BAILIAN_API_KEY,BAILIAN_BASE_URL \
  ./build/monitor --hide-runtime-noise --events process,file,network \
  --agent 1 -- ./experiments/run_bailian_codex.sh \
    --cd /tmp/ebpf-agent-monitor-qwen-dual/agent1 \
    '只执行一次 cat marker.txt，原样报告读到的内容；如果命令失败，报告错误并立即停止。不要修改文件。' \
  --next \
  --agent 2 -- ./experiments/run_bailian_codex.sh \
    --cd /tmp/ebpf-agent-monitor-qwen-dual/agent2 \
    '只执行一次 cat marker.txt，原样报告读到的内容；如果命令失败，报告错误并立即停止。不要修改文件。' \
  > /tmp/ebpf-agent-monitor-qwen-dual.log 2>&1
monitor_exit=$?
echo "monitor_exit=$monitor_exit"
rg -n 'agent_register|agent_exit|marker\.txt|AGENT_ONE|AGENT_TWO|CONNECT_RESULT|tokens used' \
  /tmp/ebpf-agent-monitor-qwen-dual.log
```

`--hide-runtime-noise` 只隐藏部分沙箱文件事件的展示，仍采集并交给 detector。
不能加 `--quiet-events`，否则目标文件事件也会被隐藏。无需启用文件抽样。

## 核对标准

1. 两条 `agent_register` 的 `agent_id` 分别为 1、2，`cgroup_id` 不同，
   `run_uid/run_gid` 为普通用户；两条 `agent_exit` 均为 0，`monitor_exit=0`。
2. Agent 1 的 `cat` 对 `agent1/marker.txt` 产生 FILE_OPEN，Agent 2 的 `cat`
   对 `agent2/marker.txt` 产生 FILE_OPEN；两条事件各自匹配注册时的
   `agent_id`/`cgroup_id`，没有交叉归属。
3. 两个 Codex 分别报告对应标记内容。各自的 CONNECT_RESULT 也归于对应
   cgroup；非阻塞 `ret=-115` 仅代表 EINPROGRESS，不能单独判断连接结果。
4. 若要称为“生命周期重叠”，需检查一组退出前另一组已有业务事件；
   即使符合，也不是压力测试。记录两组 `tokens used`，不预设具体额度。

复核后只分享上述摘要行及必要的目标 FILE_OPEN，避免传出可能包含其他环境路径
的完整日志。失败时先保留日志与退出码，不重复调用模型，分析原因后再决定是否重跑。

## 用户实测结果（2026-09-22）

`monitor_exit=0`。Agent 1 注册为 cgroup_id=10074、根 PID 24056；
Agent 2 为 cgroup_id=10093、根 PID 24057；两组 run_uid/run_gid 均为 1000。
两组都有归属正确的 CONNECT_RESULT 到 443 端口，连接事件在时间上交错；
其中 `ret=-115` 仅表示非阻塞 EINPROGRESS。两组最终均报告对应标记内容并以 0 退出。

| Agent | 目标 FILE_OPEN | `cat` PID | 退出码 | Codex 报告的 tokens used |
| --- | --- | ---: | ---: | ---: |
| 1 / cgroup 10074 | `agent1/marker.txt`，path_ret=52，flags=32768 | 24929 | 0 | 2,070 |
| 2 / cgroup 10093 | `agent2/marker.txt`，path_ret=52，flags=32768 | 24887 | 0 | 72,777 |

两条目标 FILE_OPEN 分别是 timestamp_ns=16690479204251 和 16687080630668，
没有交叉归属。标记文件实验后仍为 444 权限、19 字节，内容未变。Agent 1
退出后 Agent 2 才退出，且二者在退出前已有交错的网络事件，证实生命周期重叠；
不据此宣称高并发压力能力。Codex CLI 报告的用量合计 74,847 tokens，
其中 Agent 2 的 72,777 明显高于短任务预期；这只是 CLI 报告值，不推断百炼
实际计费或剩余额度，也不为验证同一结论自动重跑。目标日志约 16,196 行，
说明当前展示过滤并不覆盖 Codex 初始化产生的全部普通文件/进程事件。
